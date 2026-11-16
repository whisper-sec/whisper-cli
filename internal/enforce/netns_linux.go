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
	"sync"

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
	Inode     uint64 // the namespace's inode, which init checks itself against
	HostInode uint64 // the host namespace's, which init checks it is NOT in
	Dev       tun.Device
	// host is set when the device lives in the HOST namespace instead (hostroute_linux.go): there
	// is no namespace to enter, fd is -1, and a socket reaches the device only by carrying the
	// route's mark.
	host *HostRoute

	// mu orders every way in against Close. A thread entering the namespace takes a descriptor of
	// its own under it, and Close marks the handle closed and releases fd under it, so nothing ever
	// enters through a number Close has already freed, which the next open in this process could
	// have been handed for some other file. A host device's dial pins its socket under it too.
	mu       sync.Mutex
	fd       int  // the namespace, held open by this handle; -1 for a host device and after Close
	closed   bool // set by seal (and so by Close); from then on every way in is refused
	released bool // set by Close once the device and fd are let go

	// beforeEnter, when set, runs on the entering thread between taking its descriptor and setns.
	// Tests set it on a handle of their own to land a Close at exactly that moment; it is a field
	// and not a package variable so that no other handle's threads ever read it.
	beforeEnter func()
}

// errNamespaceClosed is the answer to any way into a namespace after Close.
var errNamespaceClosed = errors.New("enforce: the agent's namespace is already closed")

// HostRoute returns the routing of a host-namespace device, or nil for an agent namespace.
func (n *Namespace) HostRoute() *HostRoute { return n.host }

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
	dev, err := openTUN(IfName, 0)
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
// have to reason about. A non-zero admit attaches the admission program for that mark before the
// device has an address or a route, so not one packet reaches it unfiltered (hostroute_linux.go).
// The namespace's own device needs none: nothing but the agent lives in its namespace.
func openTUN(name string, admit uint32) (tun.Device, error) {
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
	if admit != 0 {
		if err := attachAdmission(nfd, admit); err != nil {
			unix.Close(nfd)
			return nil, err
		}
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

// whileOpen runs fn under the lock Close takes, or refuses once Close has run. Whatever fn does
// therefore happens wholly before Close or not at all.
func (n *Namespace) whileOpen(fn func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return errNamespaceClosed
	}
	return fn()
}

// enterHandle returns a duplicate of the namespace descriptor that belongs to the caller alone.
// It refers to the namespace itself, not to a number in this process's table, so Close can
// release its own at any moment and the caller still enters exactly this namespace.
func (n *Namespace) enterHandle() (int, error) {
	fd := -1
	err := n.whileOpen(func() error {
		if n.fd < 0 {
			return errors.New("enforce: this tunnel's device is in the host namespace; there is no agent namespace to enter")
		}
		var derr error
		if fd, derr = unix.FcntlInt(uintptr(n.fd), unix.F_DUPFD_CLOEXEC, 0); derr != nil {
			return fmt.Errorf("enforce: cannot hold the agent's namespace: %w", derr)
		}
		return nil
	})
	return fd, err
}

// run executes fn on a fresh thread inside the namespace. The thread is discarded afterwards.
// The thread enters through a descriptor of its own (enterHandle) and closes it once it is in;
// the inode check stays as the last word on where it landed.
func (n *Namespace) run(fn func() error) error {
	fd, err := n.enterHandle()
	if err != nil {
		return err
	}
	hook := n.beforeEnter
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: this thread ends with this goroutine
		answered := false
		answer := func(err error) { answered = true; ch <- err }
		// A goroutine that ends without answering (runtime.Goexit) must not leave run waiting.
		defer func() {
			if !answered {
				ch <- errors.New("enforce: the thread inside the agent's namespace ended without an answer")
			}
		}()
		if err := enterThrough(fd, hook); err != nil {
			answer(fmt.Errorf("enforce: cannot enter the agent's namespace: %w", err))
			return
		}
		if ino, err := nsInode(); err != nil || ino != n.Inode {
			answer(errors.New("enforce: entered the wrong network namespace"))
			return
		}
		answer(fn())
	}()
	return <-ch
}

// enterThrough moves the calling thread into the namespace fd names and closes fd, whatever
// happens on the way.
func enterThrough(fd int, hook func()) error {
	defer unix.Close(fd)
	if hook != nil {
		hook()
	}
	return unix.Setns(fd, unix.CLONE_NEWNET)
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
	if n.host != nil {
		return n.host.dial(ctx, network, addr, host, n.whileOpen)
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

// seal refuses every way in from now on and, for a host device, removes the rules that route its
// mark, while the device still holds its name. Whoever closes the TUN first must seal first: a
// closed TUN frees its name, and with it the slot, mark and table, for the next containment on
// the host, and neither a late dial of this one nor this one's rule removal may land on that.
// It is safe to call more than once and from any goroutine.
func (n *Namespace) seal() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sealLocked()
}

func (n *Namespace) sealLocked() {
	if n.closed {
		return
	}
	n.closed = true
	if n.host != nil {
		n.host.removeRules()
	}
}

// Close seals the handle, then releases the device and the namespace descriptor. With both gone
// the kernel removes the namespace once the last process inside it has exited. It is safe to call
// more than once and from any goroutine, also while another is entering the namespace: a thread
// already on its way in holds its own descriptor, and every way in that starts after Close (or
// seal) is refused.
func (n *Namespace) Close() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sealLocked()
	if n.released {
		return
	}
	n.released = true
	if n.Dev != nil {
		n.Dev.Close()
	}
	if n.fd >= 0 {
		unix.Close(n.fd)
		n.fd = -1
	}
	// A host device's gate on the root cgroup goes last, once nothing can enter the device: until
	// then it is what keeps a socket that carries the mark, and is not the containment's, out.
	if n.host != nil {
		n.host.gate.detach()
		n.host.afterStop(n.HostInode)
	}
}
