// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// netns_linux.go builds the agent's network namespace and runs code inside it.
//
// A Linux namespace belongs to a THREAD, not a process. Every function here that touches
// the agent's namespace does so on a goroutine that locks its OS thread, enters the
// namespace, does its work and returns WITHOUT unlocking. The Go runtime then destroys that
// thread instead of returning it to the pool, so no other goroutine can ever be scheduled on
// a thread inside the agent's namespace. That matters in the other direction too: the
// WireGuard socket, every control-plane request and every name lookup run on ordinary
// threads, which never left the host's namespace, so the tunnel's own underlay can never be
// routed into the tunnel.

// IfName is the name of the namespace's one non-loopback interface.
const IfName = "wsp0"

// v4MTU keeps a v4 packet inside one translated IPv6 packet: the v6 header is 20 bytes
// longer than the v4 one, and the TUN carries the IPv6 minimum MTU.
const v4MTU = minMTU - 20

// Namespace is an agent's network namespace and the TUN device inside it.
type Namespace struct {
	fd        int    // the namespace, held open by this handle
	Inode     uint64 // the namespace's inode, which init checks itself against
	HostInode uint64 // the host namespace's, which init checks it is NOT in
	Dev       tun.Device
}

// nsInode returns the inode of the calling thread's network namespace.
func nsInode() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// CreateNamespace makes a new network namespace holding loopback and a TUN device that
// carries self (the /128) and 192.0.0.2, with a default route of each family through it.
// On any error everything it made is gone again.
func CreateNamespace(self netip.Addr) (*Namespace, error) {
	if !self.Is6() || self.Is4In6() {
		return nil, errors.New("enforce: the agent address must be an IPv6 /128")
	}
	type result struct {
		ns  *Namespace
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: this thread ends with this goroutine
		ns, err := buildNamespace(self)
		ch <- result{ns, err}
	}()
	r := <-ch
	return r.ns, r.err
}

func buildNamespace(self netip.Addr) (*Namespace, error) {
	host, err := nsInode()
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot read this host's network namespace: %w", err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, errors.New("enforce: creating a network namespace needs root (run it with sudo)")
		}
		return nil, fmt.Errorf("enforce: cannot create a network namespace: %w", err)
	}
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot hold the new namespace: %w", err)
	}
	ino, err := nsInode()
	if err != nil || ino == host {
		unix.Close(fd)
		return nil, errors.New("enforce: the new network namespace could not be confirmed")
	}
	dev, err := openTUN(IfName)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := configure(self); err != nil {
		dev.Close()
		unix.Close(fd)
		return nil, err
	}
	// Unprivileged ICMP echo sockets, so `ping` works for an agent that holds no capability.
	// Namespace-local, best effort: a kernel without it simply has no unprivileged ping.
	_ = os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 2147483647"), 0)
	return &Namespace{fd: fd, Inode: ino, HostInode: host, Dev: dev}, nil
}

// openTUN creates the TUN device in the calling thread's namespace. It is opened without
// IFF_VNET_HDR, so every read is one whole packet with its checksums computed: the filter in
// front of it sees exactly what will be encrypted, never a segmentation offload it would
// have to reason about.
func openTUN(name string) (tun.Device, error) {
	nfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot open /dev/net/tun (is the tun module loaded?): %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(nfd)
		return nil, fmt.Errorf("enforce: cannot create the tunnel interface: %w", err)
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	dev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(nfd), "/dev/net/tun"), minMTU)
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot start the tunnel interface: %w", err)
	}
	return dev, nil
}

func configure(self netip.Addr) error {
	r, err := openRTNL()
	if err != nil {
		return fmt.Errorf("enforce: %w", err)
	}
	defer r.close()
	lo, err := ifIndex("lo")
	if err != nil {
		return fmt.Errorf("enforce: no loopback in the namespace: %w", err)
	}
	idx, err := ifIndex(IfName)
	if err != nil {
		return fmt.Errorf("enforce: the tunnel interface is missing: %w", err)
	}
	steps := []struct {
		what string
		do   func() error
	}{
		{"bring loopback up", func() error { return r.setUp(lo) }},
		{"turn off link-local addressing", func() error { return r.noLinkLocal(idx) }},
		{"assign the agent address", func() error { return r.addAddr(idx, self) }},
		{"assign the IPv4 translator address", func() error { return r.addAddr(idx, CLATv4) }},
		{"bring the tunnel interface up", func() error { return r.setUp(idx) }},
		{"route IPv6 into the tunnel", func() error { return r.addDefaultRoute(idx, true, minMTU) }},
		{"route IPv4 into the translator", func() error { return r.addDefaultRoute(idx, false, v4MTU) }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("enforce: could not %s: %w", s.what, err)
		}
	}
	return nil
}

// run executes fn on a fresh thread inside the namespace. The thread is discarded afterwards.
func (n *Namespace) run(fn func() error) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: this thread ends with this goroutine
		if err := unix.Setns(n.fd, unix.CLONE_NEWNET); err != nil {
			ch <- fmt.Errorf("enforce: cannot enter the agent's namespace: %w", err)
			return
		}
		if ino, err := nsInode(); err != nil || ino != n.Inode {
			ch <- errors.New("enforce: entered the wrong network namespace")
			return
		}
		ch <- fn()
	}()
	return <-ch
}

// DialContext opens a connection from inside the namespace, so it leaves exactly as the
// agent's would. addr must be an IP literal: a name would be resolved inside the namespace,
// and the host's resolver configuration means nothing there.
func (n *Namespace) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if _, perr := netip.ParseAddr(host); perr != nil {
		return nil, errors.New("enforce: dial inside the namespace needs an IP literal")
	}
	var c net.Conn
	err = n.run(func() error {
		var d net.Dialer
		var derr error
		c, derr = d.DialContext(ctx, network, addr)
		return derr
	})
	return c, err
}

// Interfaces lists the interfaces the namespace holds.
func (n *Namespace) Interfaces() ([]string, error) {
	var names []string
	err := n.run(func() error {
		ifs, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, i := range ifs {
			names = append(names, i.Name)
		}
		return nil
	})
	return names, err
}

// Close releases the device and the handle. With both gone the kernel removes the namespace
// once the last process inside it has exited.
func (n *Namespace) Close() {
	if n == nil {
		return
	}
	if n.Dev != nil {
		n.Dev.Close()
	}
	if n.fd >= 0 {
		unix.Close(n.fd)
		n.fd = -1
	}
}
