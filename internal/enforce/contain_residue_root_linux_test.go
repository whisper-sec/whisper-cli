// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// contain_residue_root_linux_test.go proves, as root against real containments, that what a
// containment makes goes with it: its rules, its routes, its gate, its cgroup, its records and the
// mark on every socket it made, and that the one thing it leaves on purpose, the refusal of the
// agent's address, stays exactly while a socket could still send from that address. It also proves
// that a contained process reaches nothing outside the tunnel at any step of the way: while another
// agent's device prunes, through a takeover that fails, through a wait for descriptors in flight, and
// through the end itself while it keeps opening sockets.

// Agents of these tests alone, so no other test's refusal is mistaken for theirs. tSelf5 and tSelf6
// carry the TIME_WAIT tests' connections, which on a kernel that cannot end them outlive the test by
// a minute, and rightly keep their agents' refusals that long.
var (
	tSelf3 = netip.MustParseAddr("2a04:2a01:0:1::44")
	tSelf4 = netip.MustParseAddr("2a04:2a01:0:1::45")
	tSelf5 = netip.MustParseAddr("2a04:2a01:0:1::46")
	tSelf6 = netip.MustParseAddr("2a04:2a01:0:1::47")
)

// The helper's state for these tests. It lives in the helper process only.
var (
	insideSocks []int // sockets made on request, kept open
	sprayStop   chan struct{}
	sprayDone   chan struct{}
	sprayN      atomic.Int64
	parkedIn    = -1 // the receiving end of a socket pair a socket made inside is in flight on
	spawnStop   chan struct{}
	spawnDone   chan struct{}
	spawned     []*exec.Cmd
	revivable   = -1 // a TCP socket from the agent's address the release ends, connected again after it
)

// residueCommand runs one of the helper's commands for these tests.
func residueCommand(f []string) error {
	switch f[0] {
	case "newsock": // a fresh unconnected datagram socket of each family, kept
		for _, fam := range []int{unix.AF_INET6, unix.AF_INET} {
			fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			insideSocks = append(insideSocks, fd)
		}
		return nil
	case "selfconn": // selfconn <self> <addr:port>: a datagram socket connected now, which must leave from self
		self, err := netip.ParseAddr(f[1])
		if err != nil {
			return err
		}
		ap, err := netip.ParseAddrPort(f[2])
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Connect(fd, sockaddr(ap)); err != nil {
			return err
		}
		insideSocks = append(insideSocks, fd)
		sa, _ := unix.Getsockname(fd)
		if a := saAddr(sa); a != self {
			return fmt.Errorf("the connected socket's source is %s, not %s", a, self)
		}
		return nil
	case "parkrecv": // parkrecv <ms>: a fresh socket put in flight on a socket pair, received back after ms
		ms, err := strconv.Atoi(f[1])
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Sendmsg(sp[0], []byte("p"), unix.UnixRights(fd), nil, 0); err != nil {
			return err
		}
		unix.Close(fd)
		go func() {
			time.Sleep(time.Duration(ms) * time.Millisecond)
			b, oob := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
			if _, oobn, _, _, err := unix.Recvmsg(sp[1], b, oob, unix.MSG_CMSG_CLOEXEC); err == nil {
				if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) > 0 {
					if fds, err := unix.ParseUnixRights(&msgs[0]); err == nil {
						insideSocks = append(insideSocks, fds...)
					}
				}
			}
		}()
		return nil
	case "spray": // spray <v6 addr:port> <v4 addr:port>: open and send from new sockets in a loop until stopspray
		v6, err1 := netip.ParseAddrPort(f[1])
		v4, err2 := netip.ParseAddrPort(f[2])
		if err1 != nil || err2 != nil {
			return errors.New("spray <v6> <v4>")
		}
		sprayStop, sprayDone = make(chan struct{}), make(chan struct{})
		go spray(v6, v4)
		return nil
	case "parkinside": // a datagram socket made now, put in flight on a socket pair and closed here
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Sendmsg(sp[0], []byte("p"), unix.UnixRights(fd), nil, 0); err != nil {
			return err
		}
		unix.Close(fd)
		unix.Close(sp[0])
		parkedIn = sp[1]
		return nil
	case "unparksend": // unparksend <addr:port>: take the parked socket back and send from it
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		b, oob := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
		_, oobn, _, _, err := unix.Recvmsg(parkedIn, b, oob, unix.MSG_CMSG_CLOEXEC)
		if err != nil {
			return err
		}
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(msgs) == 0 {
			return errors.New("no descriptor came back")
		}
		fds, err := unix.ParseUnixRights(&msgs[0])
		if err != nil || len(fds) == 0 {
			return errors.New("no descriptor came back")
		}
		if m, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_MARK); err == nil && m == 0 {
			return errors.New("control: the parked socket carries no mark, so nothing is tested")
		}
		return unix.Sendto(fds[0], []byte("u"), 0, sockaddr(ap))
	case "spawnloop": // start a child (sleep) every few milliseconds until stopspawn
		spawnStop, spawnDone = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(spawnDone)
			for len(spawned) < 64 {
				select {
				case <-spawnStop:
					return
				default:
				}
				c := exec.Command(sleepBin(), "600") // the helper has no PATH
				if c.Start() == nil {
					spawned = append(spawned, c)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		return nil
	case "stopspawn":
		if spawnStop == nil {
			return errors.New("no spawn loop")
		}
		close(spawnStop)
		<-spawnDone
		return nil
	case "killspawned":
		for _, c := range spawned {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
		spawned = nil
		return nil
	case "tcpfrom": // tcpfrom <self> <addr:port>: a TCP socket bound to self, connecting now (it never completes)
		self, err := netip.ParseAddr(f[1])
		if err != nil {
			return err
		}
		ap, err := netip.ParseAddrPort(f[2])
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: self.As16()}); err != nil {
			return err
		}
		if err := unix.Connect(fd, sockaddr(ap)); err != nil && !errors.Is(err, unix.EINPROGRESS) {
			return err
		}
		revivable = fd
		return nil
	case "tcprevive": // tcprevive <addr:port>: disconnect that socket and connect it again
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		if revivable < 0 {
			return errors.New("no socket (tcpfrom first)")
		}
		_ = disconnect(revivable)
		return unix.Connect(revivable, sockaddr(ap))
	case "parkkept": // the kept IPv6 datagram socket (udpopen), put in flight on a socket pair and closed here
		if keptU6 < 0 {
			return errors.New("no kept socket (udpopen first)")
		}
		sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Sendmsg(sp[0], []byte("p"), unix.UnixRights(keptU6), nil, 0); err != nil {
			return err
		}
		unix.Close(keptU6)
		keptU6 = -1
		unix.Close(sp[0])
		parkedIn = sp[1]
		return nil
	case "stopspray":
		if sprayStop == nil {
			return errors.New("no spray")
		}
		close(sprayStop)
		<-sprayDone
		if sprayN.Load() == 0 {
			return errors.New("the spray never ran")
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", f[0])
}

// sleepBin is sleep(1), by its full path.
func sleepBin() string {
	for _, p := range []string{"/bin/sleep", "/usr/bin/sleep"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sleep"
}

// spray opens new sockets and sends from them until told to stop: unbound IPv6 and IPv4 datagrams,
// an IPv6 datagram from a socket bound to the agent's address (which only works while the address is
// on this host), and an IPv6 TCP connect. Every socket is closed at once.
func spray(v6, v4 netip.AddrPort) {
	defer close(sprayDone)
	for {
		select {
		case <-sprayStop:
			return
		default:
		}
		if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
			_ = unix.Sendto(fd, []byte("s"), 0, sockaddr(v6))
			unix.Close(fd)
		}
		if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
			if unix.Bind(fd, &unix.SockaddrInet6{Addr: tSelf4.As16()}) == nil {
				_ = unix.Sendto(fd, []byte("b"), 0, sockaddr(v6))
			}
			unix.Close(fd)
		}
		if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
			_ = unix.Sendto(fd, []byte("4"), 0, sockaddr(v4))
			unix.Close(fd)
		}
		if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0); err == nil {
			_ = unix.Connect(fd, sockaddr(v6))
			time.Sleep(time.Millisecond)
			unix.Close(fd)
		}
		sprayN.Add(1)
		time.Sleep(2 * time.Millisecond)
	}
}

// The far IPv6 network a leak by the host's own routes would reach: the peer is its next hop.
var (
	farNet6  = netip.MustParsePrefix("2001:db8:77::/48")
	farAddr6 = netip.MustParseAddrPort("[2001:db8:77::5]:9")
	hostV6   = netip.MustParseAddr("fd77:203::1")
	peerV6   = netip.MustParseAddr("fd77:203::2")
	farAddr4 = netip.MustParseAddrPort("10.203.77.2:9")
)

// peerCapture counts what arrives at the peer's end of the veth, read with AF_PACKET before anything
// in the peer's stack can drop it.
type peerCapture struct {
	fromSelf  atomic.Int64 // anything from the agent's address (or the translator's), by the host's routes
	toFar     atomic.Int64 // anything for the spray's targets, from any source
	fromHost  atomic.Int64 // anything for the spray's targets from the host's own addresses
	lastFrom  atomic.Value // the last source counted in fromSelf, for the message
	stopped   chan struct{}
	closeOnce sync.Once
	fd        int
}

// routeToPeer gives the host an IPv6 path by its main table to farNet6 through the peer, so that a
// packet leaving by the host's own routes is seen at the peer.
func routeToPeer(t *testing.T, p *peerNS) {
	t.Helper()
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("-6", "addr", "add", hostV6.String()+"/64", "dev", p.hostIf, "nodad")
	run("-n", p.ns, "-6", "addr", "add", peerV6.String()+"/64", "dev", p.peerIf, "nodad")
	run("-6", "route", "add", farNet6.String(), "via", peerV6.String(), "dev", p.hostIf)
	t.Cleanup(func() { _ = exec.Command("ip", "-6", "route", "del", farNet6.String()).Run() })
}

func capturePeer(t *testing.T, p *peerNS, self netip.Addr) *peerCapture {
	t.Helper()
	c := &peerCapture{stopped: make(chan struct{}), fd: -1}
	ready := make(chan error, 1)
	go func() {
		defer close(c.stopped)
		runtime.LockOSThread() // never unlocked: the thread ends inside the peer namespace
		nfd, err := unix.Open("/run/netns/"+p.ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ready <- err
			return
		}
		err = unix.Setns(nfd, unix.CLONE_NEWNET)
		unix.Close(nfd)
		if err != nil {
			ready <- err
			return
		}
		ifc, err := net.InterfaceByName(p.peerIf)
		if err != nil {
			ready <- err
			return
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons16(unix.ETH_P_ALL)))
		if err != nil {
			ready <- err
			return
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
			unix.Close(fd)
			ready <- err
			return
		}
		c.fd = fd
		ready <- nil
		buf := make([]byte, 2048)
		for {
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
				continue // the peer's own packets
			}
			c.count(buf[:n], self)
		}
	}()
	if err := <-ready; err != nil {
		t.Fatalf("cannot capture at the peer: %v", err)
	}
	t.Cleanup(func() { c.stop() })
	return c
}

func htons16(v uint16) uint16 { return v<<8 | v>>8 }

func (c *peerCapture) stop() {
	c.closeOnce.Do(func() {
		if c.fd >= 0 {
			_ = unix.Shutdown(c.fd, unix.SHUT_RDWR)
			unix.Close(c.fd)
		}
	})
}

func (c *peerCapture) count(p []byte, self netip.Addr) {
	if len(p) < 20 {
		return
	}
	switch p[0] >> 4 {
	case 6:
		if len(p) < 40 {
			return
		}
		src, dst := addr16(p[8:24]), addr16(p[24:40])
		if src == self {
			c.fromSelf.Add(1)
			c.lastFrom.Store(fmt.Sprintf("%s -> %s", src, dst))
		}
		if farNet6.Contains(dst) {
			c.toFar.Add(1)
			if src == hostV6 {
				c.fromHost.Add(1)
			}
		}
	case 4:
		src, dst := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		if src == CLATv4 {
			c.fromSelf.Add(1)
			c.lastFrom.Store(fmt.Sprintf("%s -> %s", src, dst))
		}
		if dst == farAddr4.Addr() && p[9] == protoUDP && len(p) >= 24 && binary.BigEndian.Uint16(p[22:24]) == farAddr4.Port() {
			c.toFar.Add(1)
			if src == netip.MustParseAddr("10.203.77.1") {
				c.fromHost.Add(1)
			}
		}
	}
}

// noneFromSelf fails the test if anything from the agent's address reached the peer.
func (c *peerCapture) noneFromSelf(t *testing.T, when string) {
	t.Helper()
	if n := c.fromSelf.Load(); n > 0 {
		t.Fatalf("%s: %d packet(s) from the agent's address left by the host's own routes (last: %v)", when, n, c.lastFrom.Load())
	}
}

// heldStill fails the test if the peer sees anything for the spray's targets for d: the contained
// process reaches nothing outside the tunnel. It lets what was sent before settle first.
func (c *peerCapture) heldStill(t *testing.T, d time.Duration, when string) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	before := c.toFar.Load()
	time.Sleep(d)
	if n := c.toFar.Load() - before; n > 0 {
		t.Fatalf("%s: %d packet(s) of the contained process reached the peer outside the tunnel", when, n)
	}
}

var lookupRe = regexp.MustCompile(`lookup (\d+)`)

// hostRules is every policy rule line of both families, the host's own before a test begins: a rule
// the host had already (at a slot's priority, looking up a slot's table) is not a containment's
// leftover.
func hostRules(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, fam := range []string{"-6", "-4"} {
		b, err := exec.Command("ip", fam, "rule", "show").CombinedOutput()
		if err != nil {
			t.Skipf("needs iproute2: %v %s", err, b)
		}
		for _, line := range strings.Split(string(b), "\n") {
			out[fam+strings.TrimSpace(line)] = true
		}
	}
	return out
}

// residue lists what is left of the containment that held route for self: rules naming its address,
// its table or its mark in either family that the host did not have before (before, from hostRules),
// routes in its table, its gate on the root cgroup, its cgroup, its records, its device, the mark on
// any socket of pids, and anything of ours in the nftables ruleset.
func residue(t *testing.T, before map[string]bool, hr HostRoute, self netip.Addr, pids ...int) []string {
	t.Helper()
	var left []string
	mark := fmt.Sprintf("fwmark %#x", hr.Mark)
	for _, fam := range []string{"-6", "-4"} {
		out, err := exec.Command("ip", fam, "rule", "show").CombinedOutput()
		if err != nil {
			t.Skipf("needs iproute2: %v %s", err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if before[fam+strings.TrimSpace(line)] {
				continue
			}
			table := false
			if m := lookupRe.FindStringSubmatch(line); m != nil && m[1] == strconv.Itoa(int(hr.Table)) {
				table = true
			}
			if strings.Contains(line, "from "+self.String()+" ") || table || strings.Contains(line, mark) {
				left = append(left, "rule "+strings.TrimSpace(line))
			}
		}
		if fam == "-6" && len(left) > 0 {
			// Why a refusal stayed: what sock_diag still lists from the address, or why it cannot say.
			socks, complete, why := agentSockets([]netip.Addr{self})
			ifs, _ := liveIfindexes()
			for _, k := range socks {
				left = append(left, fmt.Sprintf("  from %s: state %d port %d -> [%s]:%d dev %d inert %v", k.src, k.state,
					k.sport, k.dst, k.dport, k.ifidx, k.inert(ifs)))
			}
			if !complete {
				left = append(left, "  the socket answer is incomplete: "+why)
			}
		}
		out, _ = exec.Command("ip", fam, "route", "show", "table", strconv.Itoa(int(hr.Table))).CombinedOutput()
		if s := strings.TrimSpace(string(out)); s != "" && !strings.Contains(s, "does not exist") {
			left = append(left, "routes in table "+strconv.Itoa(int(hr.Table))+": "+s)
		}
	}
	for _, g := range rootGateGenerations(cgroupRoot()) {
		if g == hr.Gen {
			left = append(left, "gate "+rootGateName(g)+" on the root cgroup")
		}
	}
	if _, err := os.Stat(filepath.Join(cgroupRoot(), ContainParent, containCgroupName(self))); err == nil {
		left = append(left, "the containment's cgroup")
	}
	for _, p := range []string{filepath.Join(containState, containCgroupName(self)+".json"), devRecordPath(hr.Gen)} {
		if _, err := os.Stat(p); err == nil {
			left = append(left, "record "+p)
		}
	}
	if idx, err := ifIndex(hr.Name); err == nil && idx == hr.Index {
		left = append(left, "device "+hr.Name)
	}
	socks, _, _ := tableSockets(pids)
	for _, r := range socks {
		dup, err := getfdAt(r.pid, r.tid, r.fd)
		if err != nil {
			continue
		}
		if m, err := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK); err == nil && uint32(m)&hostMarkMask == hr.Mark {
			left = append(left, fmt.Sprintf("pid %d fd %d still carries the mark %#x", r.pid, r.fd, m))
		}
		unix.Close(dup)
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.Command("nft", "list", "ruleset").CombinedOutput(); err == nil {
			low := strings.ToLower(string(out))
			if strings.Contains(low, "whisper") || strings.Contains(low, "wsc") {
				left = append(left, "nftables: "+strings.TrimSpace(string(out)))
			}
		}
	}
	return left
}

// refused reports whether a packet from self is refused by the host's rules (and so never routed by
// main), read the way an operator would.
func refused(t *testing.T, self netip.Addr) bool {
	t.Helper()
	out, _ := exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", self.String()).CombinedOutput()
	s := strings.ToLower(string(out))
	return strings.Contains(s, "permission denied") || strings.Contains(s, "prohibit")
}

// pruneWhy says what a prune would see of self: each of the conditions it checks, so a refusal that
// stayed explains itself.
func pruneWhy(self netip.Addr) string {
	live, ok := liveDeviceAgents()
	addrs, _ := hostAddrs()
	on := false
	for _, a := range addrs {
		on = on || a == self
	}
	protos, perr := ipv6Protocols()
	var busy []string
	for name, n := range protos {
		if n > 0 {
			busy = append(busy, fmt.Sprintf("%s=%d", name, n))
		}
	}
	socks, complete, why := agentSockets([]netip.Addr{self})
	return fmt.Sprintf("[prune view of %s: live %v (records readable %v), contained %v, on an interface %v, IPv6 "+
		"protocols in use %v (%v), sockets %d, complete %v %q]", self, live[self], ok, containedAgents()[self], on, busy, perr,
		len(socks), complete, why)
}

// hasAddrRules reports whether any rule a containment made for self's address is left.
func hasAddrRules(self netip.Addr) bool {
	_, ok := agentRulesOnHost()[self]
	return ok
}

// tcpFrom holds a TCP connection from self to a listener on self (both ends local, so it runs over
// loopback) and returns a function that ends both ends with a reset, which leaves no TIME_WAIT.
func tcpFrom(t *testing.T, self netip.Addr) (end func()) {
	t.Helper()
	ln, err := net.Listen("tcp6", "["+self.String()+"]:0")
	if err != nil {
		t.Fatalf("listen on %s: %v", self, err)
	}
	c, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	ln.Close()
	if err != nil {
		t.Fatal(err)
	}
	done := false
	end = func() {
		if done {
			return
		}
		done = true
		for _, x := range []net.Conn{c, s} {
			_ = x.(*net.TCPConn).SetLinger(0)
			x.Close()
		}
	}
	t.Cleanup(end)
	return end
}

// withoutDestroy makes this test's kernel one built without CONFIG_INET_DIAG_DESTROY (the CI
// kernel), which ends no socket: what still sends from an agent's address then keeps its refusal.
func withoutDestroy(t *testing.T) {
	t.Helper()
	old := endSocket
	endSocket = func(*sockDiag, diagSock) error { return unix.EOPNOTSUPP }
	t.Cleanup(func() { endSocket = old })
}

// plantRefusal puts the refusal a stopped tunnel leaves for self at slot, as if a containment of it had
// ended there earlier.
func plantRefusal(t *testing.T, self netip.Addr, slot uint32) {
	t.Helper()
	touchLock(t, self) // a containment of self ran here, so it has its lock file
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, tagged(ruleBodyProhibit(unix.AF_INET6, hostRulePrio+slot, self))); err != nil {
		t.Fatalf("plant a refusal for %s: %v", self, err)
	}
	t.Cleanup(func() { removeAgentAddrRules(self) })
}

// A containment that ends leaves nothing behind: not its rules or routes in either family, its gate,
// its cgroup, its records or its device, and not its mark on any socket of the process it held, those
// it swept from before, made inside, or ended at the release. Nothing of it was ever in nftables.
func TestATeardownLeavesNothingBehind(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	before := hostRules(t)
	peer := startPeer(t)
	ns, _ := hostTUNAs(t, tSelf4)
	hr := *ns.HostRoute()
	h := startHelper(t, peer.addr)
	pid := h.cmd.Process.Pid
	if got := h.do(t, "udpopen"); got != "ok" { // from before: swept, marked and pinned, given back
		t.Fatalf("udpopen: %s", got)
	}
	c, err := Contain(pid, tSelf4, hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	// Made inside: marked by the cgroup, the second from the /128. And the swept socket connected now, from
	// the /128: the release ends it too, and it was adopted by the sweep.
	for _, cmd := range []string{"newsock", "selfconn " + tSelf4.String() + " [2606:4700:4700::1111]:443",
		"udpconnect [2606:4700:4700::1111]:443"} {
		if got := h.do(t, cmd); got != "ok" {
			c.Release()
			t.Fatalf("%s: %s", cmd, got)
		}
	}
	if left := residue(t, before, hr, tSelf4, pid); len(left) == 0 {
		t.Fatal("control: a live containment shows nothing for the residue check to find")
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	// Released, with the tunnel still up: only the sockets the release ended still carry the mark, and
	// none of them is adopted any more (their goodbye left as they were ended); everything else the
	// process holds speaks as itself already.
	ended := 0
	socks, _, _ := tableSockets([]int{pid})
	for _, r := range socks {
		dup, err := getfdAt(r.pid, r.tid, r.fd)
		if err != nil {
			continue
		}
		local, _, _ := sockAddrs(dup)
		m, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK)
		var tag uint32
		adopted := hr.gate.tags.Lookup(int32(dup), &tag) == nil
		unix.Close(dup)
		switch {
		case local == tSelf4:
			ended++
			if adopted {
				t.Fatalf("pid %d fd %d, ended by the release, is still adopted: connected again, it would enter the tunnel", r.pid, r.fd)
			}
		case uint32(m)&hostMarkMask == hr.Mark:
			t.Fatalf("pid %d fd %d still carries the containment's mark after the release, so it leaves as the agent", r.pid, r.fd)
		}
	}
	if ended == 0 {
		t.Fatal("control: no socket from the agent's address was there to end")
	}
	ns.Close()
	c.Finish()
	if left := residue(t, before, hr, tSelf4, pid); len(left) > 0 {
		t.Fatalf("the containment left:\n  %s", strings.Join(left, "\n  "))
	}
}

// The refusal of the agent's address stays while the kernel could still send from it for a TCP
// connection, and goes with the first prune after it no longer could: here, another agent's device.
func TestTheRefusalStaysExactlyWhileASocketCouldSendFromTheAgent(t *testing.T) {
	needRoot(t)
	withoutDestroy(t)
	ns, _ := hostTUNAs(t, tSelf4)
	end := tcpFrom(t, tSelf4)
	ns.Close()
	if !refused(t, tSelf4) {
		t.Fatal("with a connection still open from the agent's address, the tunnel's stop let the address take the host's routes")
	}
	end()
	other, _ := hostTUNAs(t, tSelf3) // another agent's device prunes what nothing needs
	defer other.Close()
	if hasAddrRules(tSelf4) {
		t.Fatalf("no connection is left from the agent's address, and another device left its refusal:\n%s%s", ipRules(t), pruneWhy(tSelf4))
	}
}

// sockDestroyWorks reports whether this kernel ends a TIME_WAIT socket with SOCK_DESTROY.
func sockDestroyWorks(t *testing.T, self netip.Addr) bool {
	t.Helper()
	tw := timeWaitFrom(t, self)
	d, err := openSockDiag()
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	return d.destroy(tw) == nil
}

// timeWaitFrom makes a TCP connection from self to itself, closes the client first, and returns the
// client's TIME_WAIT socket. self must be on this host.
func timeWaitFrom(t *testing.T, self netip.Addr) diagSock {
	t.Helper()
	ln, err := net.Listen("tcp6", "["+self.String()+"]:0")
	if err != nil {
		t.Fatalf("listen on %s: %v", self, err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	cport := c.LocalAddr().(*net.TCPAddr).Port
	c.Close()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		socks, _, _ := agentSockets([]netip.Addr{self})
		for _, k := range socks {
			if k.state == tcpTimeWait && int(k.sport) == cport {
				return k
			}
		}
	}
	t.Fatal("no TIME_WAIT socket from the agent's address appeared")
	return diagSock{}
}

// A TIME_WAIT from the agent's address answers a retransmitted FIN with an ACK the kernel routes for it
// with no strict output device, so it holds the refusal. The tunnel's stop ends it where the kernel
// has SOCK_DESTROY, and then nothing is left; where it does not, the refusal stays with it.
func TestATimeWaitFromTheAgentIsEndedAtTheStopOrKeepsTheRefusal(t *testing.T) {
	needRoot(t)
	probe, _ := hostTUNAs(t, tSelf6)
	destroys := sockDestroyWorks(t, tSelf6)
	probe.Close()
	t.Logf("this kernel ends a TIME_WAIT with SOCK_DESTROY: %v", destroys)
	ns, _ := hostTUNAs(t, tSelf5)
	tw := timeWaitFrom(t, tSelf5)
	ns.Close()
	socks, _, _ := agentSockets([]netip.Addr{tSelf5})
	still := false
	for _, k := range socks {
		if k.state == tcpTimeWait && k.sport == tw.sport {
			still = true
		}
	}
	switch {
	case destroys && still:
		t.Fatal("the kernel can end a TIME_WAIT, and the tunnel's stop left one from the agent's address")
	case destroys && hasAddrRules(tSelf5):
		t.Fatalf("nothing could send from the agent's address after the stop, and its refusal stayed:\n%s%s", ipRules(t), pruneWhy(tSelf5))
	case !destroys && (!still || !refused(t, tSelf5)):
		t.Fatalf("a TIME_WAIT from the agent's address outlived the stop (%v) without its refusal (%v)", still, refused(t, tSelf5))
	}
}

// A live containment's rules survive every prune: another agent's device made beside it, on a slot of
// its own, and a prune called outright, though nothing sends from the live agent's address.
func TestAPruneNeverTakesALiveContainmentsRules(t *testing.T) {
	needRoot(t)
	live, _ := hostTUNAs(t, tSelf4)
	hl := live.HostRoute()
	other, _ := hostTUNAs(t, tSelf3)
	other.Close() // its stop prunes too
	pruneAgentRefusals(netip.Addr{}, 0)
	rules := ipRules(t)
	for _, want := range []string{"from " + tSelf4.String() + " lookup", "from " + tSelf4.String() + " prohibit", fmt.Sprintf("fwmark %#x", hl.Mark)} {
		if !strings.Contains(rules, want) {
			t.Fatalf("a prune took the live containment's %q:\n%s", want, rules)
		}
	}
	out, _ := exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", tSelf4.String()).CombinedOutput()
	if !strings.Contains(string(out), "dev "+hl.Name) {
		t.Fatalf("after the prunes the live agent's address is not routed to its tunnel: %s", out)
	}
}

// An agent whose lock is held exclusively (its containment is starting, or running) keeps its rules
// through a prune; the prune after the lock is let go takes them.
func TestAPruneLeavesAnAgentWhoseLockIsHeld(t *testing.T) {
	needRoot(t)
	plantRefusal(t, tSelf3, 7)
	l, err := LockExclusive(tSelf3)
	if err != nil {
		t.Fatalf("LockExclusive: %v", err)
	}
	pruneAgentRefusals(netip.Addr{}, 0)
	if !hasAddrRules(tSelf3) {
		l.Release()
		t.Fatal("a prune took the rules of an agent whose lock another command holds")
	}
	l.Release()
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("with the lock free and nothing on the address, the refusal stayed:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
}

// A killed containment keeps its refusal while its record is there: `whisper contain --release` or the
// agent's next containment clears it, not a prune by another agent.
func TestAPruneLeavesAKilledContainmentsRules(t *testing.T) {
	needRoot(t)
	plantRefusal(t, tSelf3, 7)
	if err := secureDir(containState); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(containState, containCgroupName(tSelf3)+".json")
	if err := os.WriteFile(path, []byte(`{"pid":1,"slot":7,"origin":{},"pinned":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	pruneAgentRefusals(netip.Addr{}, 0)
	if !hasAddrRules(tSelf3) {
		t.Fatal("a prune took the refusal of a killed containment whose record is still there")
	}
	os.Remove(path)
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("with the record gone and nothing on the address, the refusal stayed:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
}

// A full TCP socket bound to a device that is gone can never send, so it does not hold a refusal; the
// same socket while its device lives does. Here it is still connecting (SYN_SENT), which the kernel
// retransmits on its own.
func TestAnInertSocketDoesNotHoldARefusal(t *testing.T) {
	needRoot(t)
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("link", "add", "resdummy", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "resdummy").Run() })
	run("-6", "addr", "add", tSelf3.String()+"/128", "dev", "resdummy", "nodad")
	run("link", "set", "resdummy", "up")
	run("-6", "route", "add", "2001:db8:99::/64", "dev", "resdummy")
	idx, err := ifIndex("resdummy")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: tSelf3.As16()}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, idx); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, &unix.SockaddrInet6{Port: 9, Addr: netip.MustParseAddr("2001:db8:99::1").As16()}); !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("connect: %v", err)
	}
	plantRefusal(t, tSelf3, 7)
	pruneAgentRefusals(netip.Addr{}, 0)
	if !hasAddrRules(tSelf3) {
		t.Fatal("control: a connection bound to a live device from the agent's address must hold its refusal")
	}
	run("link", "del", "resdummy")
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("a connection bound to a device that is gone held the refusal:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
}

// A prune deletes only a rule a containment made: one tagged as its own. The same shapes written by
// anybody else stay, at a slot's priority too, where a rule added without a priority lands.
func TestAPruneDeletesOnlyRulesAContainmentMade(t *testing.T) {
	needRoot(t)
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	other := netip.MustParseAddr("2001:db8:77::5")
	theirs := [][]byte{
		ruleBodyProhibit(unix.AF_INET6, 100, tSelf3),
		ruleBodyProhibit(unix.AF_INET6, hostRulePrio+9, tSelf3),
		ruleBodyFrom(unix.AF_INET6, hostRulePrio, other, hostTableBase),
	}
	for _, b := range theirs {
		if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, b); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, b := range theirs {
			deleteRuleBodies(func(fam uint8) []byte {
				if fam == unix.AF_INET6 {
					return b
				}
				return nil
			})
		}
	})
	plantRefusal(t, tSelf3, 7)
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("the containment's own refusal was not pruned:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
	rules := ipRules(t)
	for _, want := range []string{
		"100:\tfrom " + tSelf3.String() + " prohibit",
		fmt.Sprintf("%d:\tfrom %s prohibit", hostRulePrio+9, tSelf3),
		fmt.Sprintf("%d:\tfrom %s lookup %d", hostRulePrio, other, hostTableBase),
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("a prune took a rule no containment made (%q):\n%s", want, rules)
		}
	}
}

// A prune that cannot see a live device's records (another /run, or one removed under it) still
// never takes its rules: the device holds its agent's address, which the kernel shows whoever's /run
// is read.
func TestAPruneNeverTakesTheRulesOfADeviceWhoseRecordsItCannotSee(t *testing.T) {
	needRoot(t)
	live, _ := hostTUNAs(t, tSelf4)
	hl := live.HostRoute()
	oldState, oldLocks := containState, LockDir
	containState, LockDir = t.TempDir(), filepath.Join(t.TempDir(), "locks")
	pruneAgentRefusals(netip.Addr{}, 0)
	containState, LockDir = oldState, oldLocks
	rules := ipRules(t)
	for _, want := range []string{"from " + tSelf4.String() + " lookup", "from " + tSelf4.String() + " prohibit"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("a prune blind to the device's records took its %q:\n%s", want, rules)
		}
	}
	out, _ := exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", tSelf4.String()).CombinedOutput()
	if !strings.Contains(string(out), "dev "+hl.Name) {
		t.Fatalf("the live agent's address is no longer routed to its tunnel: %s", out)
	}
}

// A containment of an agent that starts while a prune holds that agent's lock waits the prune out and
// then goes ahead; the prune never sees half of it.
func TestAContainmentStartingDuringAPruneWaitsItOut(t *testing.T) {
	needRoot(t)
	plantRefusal(t, tSelf3, 7)
	var got time.Time
	var lerr error
	done := make(chan struct{})
	old := pruneHeld
	pruneHeld = func() {
		go func() {
			defer close(done)
			l, err := LockExclusive(tSelf3)
			got, lerr = time.Now(), err
			if err == nil {
				l.Release()
			}
		}()
		time.Sleep(150 * time.Millisecond)
	}
	t.Cleanup(func() { pruneHeld = old })
	pruneAgentRefusals(netip.Addr{}, 0)
	ended := time.Now()
	<-done
	if lerr != nil {
		t.Fatalf("a containment starting during a prune refused: %v", lerr)
	}
	if got.Before(ended) {
		t.Fatal("a containment took its agent's lock while a prune held it")
	}
	if hasAddrRules(tSelf3) {
		t.Fatalf("control: the prune must have taken the agent's refusal:\n%s", ipRules(t))
	}
}

// A guard a command killed in the middle of making a device left goes with the next prune; a device
// made normally leaves none.
func TestAGuardLeftByAKilledCommandIsPruned(t *testing.T) {
	needRoot(t)
	ns, _ := hostTUNAs(t, tSelf3)
	for _, ar := range agentRulesOnHost()[tSelf3] {
		if ar.prio == hostGuardPrio {
			t.Fatalf("a device made normally left its guard:\n%s", ipRules(t))
		}
	}
	ns.Close()
	touchLock(t, tSelf4) // the killed command had made it, as every one does before its device
	addGuard(tSelf4)
	t.Cleanup(func() { removeGuard(tSelf4) })
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf4) {
		t.Fatalf("a guard nothing needs survived a prune:\n%s%s", ipRules(t), pruneWhy(tSelf4))
	}
}

// While a process is contained it reaches nothing outside the tunnel, also while another agent's device
// is made and stopped beside it (each prunes); and through the end, while it goes on opening new sockets
// and sending from them as fast as it can, nothing from the agent's address ever leaves by the host's
// own routes. Afterwards the released process's traffic leaves as the host's own.
func TestNewSocketsThroughTheEndNeverSpeakAsTheAgentOutsideTheTunnel(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	before := hostRules(t)
	peer := startPeer(t)
	routeToPeer(t, peer)
	pc := capturePeer(t, peer, tSelf4)
	ns, sent, raw := hostTUNRaw(t, tSelf4)
	go func() {
		for range sent { // what passed the filter; the test reads what entered the device (raw)
		}
	}()
	hr := *ns.HostRoute()
	h := startHelper(t, peer.addr)
	pid := h.cmd.Process.Pid
	if got := h.do(t, "spray "+farAddr6.String()+" "+farAddr4.String()); got != "ok" {
		t.Fatalf("spray: %s", got)
	}
	time.Sleep(200 * time.Millisecond)
	if pc.toFar.Load() == 0 {
		t.Fatal("control: before the containment the helper's spray must reach the peer by the host's routes")
	}
	c, err := Contain(pid, tSelf4, hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	pc.heldStill(t, 300*time.Millisecond, "contained")
	other, _ := hostTUNAs(t, tSelf3) // another agent's device, made and stopped: both prune
	other.Close()
	pc.heldStill(t, 200*time.Millisecond, "contained, after another agent's device pruned")
	inTunnel := 0
	for drained := false; !drained; {
		select {
		case p := <-raw:
			if p[0]>>4 == 6 && addr16(p[8:24]) == tSelf4 {
				inTunnel++
			}
		default:
			drained = true
		}
	}
	if inTunnel == 0 {
		t.Fatal("control: the contained spray never reached the tunnel, so nothing here was tested")
	}
	pc.noneFromSelf(t, "contained")
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	pc.noneFromSelf(t, "released, tunnel up")
	ns.Close()
	c.Finish()
	pc.noneFromSelf(t, "tunnel stopped")
	host := pc.fromHost.Load()
	time.Sleep(300 * time.Millisecond)
	if got := h.do(t, "stopspray"); got != "ok" {
		t.Fatalf("stopspray: %s", got)
	}
	time.Sleep(100 * time.Millisecond)
	pc.noneFromSelf(t, "after the end")
	if pc.fromHost.Load() == host {
		t.Fatal("control: after the end the released process's spray must leave as the host's own")
	}
	if left := residue(t, before, hr, tSelf4, pid); len(left) > 0 {
		t.Fatalf("the containment left:\n  %s", strings.Join(left, "\n  "))
	}
}

// killDevice does to a device what a killed command does: the kernel lets its record's lock go, closes
// its TUN and the links that hold its address checks; nothing else is detached and no rule is removed.
func killDevice(ns *Namespace) {
	hr := ns.HostRoute()
	hr.gate.rec.drop()
	hr.gate.rec = nil
	if hr.gate.src != nil {
		hr.gate.src.Close()
		hr.gate.src = nil
	}
	if hr.gate.nf != nil {
		hr.gate.nf.close()
		hr.gate.nf = nil
	}
	ns.Dev.Close()
}

// A takeover of a killed containment that fails leaves that containment's process held, as it was: in
// its cgroup, under its own programs again (its new sockets carry its own mark), reaching nothing
// outside, with its record as it was. The process the takeover tried to add goes back where it was.
func TestAFailedTakeoverKeepsTheKilledContainmentsProcessHeld(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	nsA, _ := hostTUNAs(t, tSelf4)
	ha := *nsA.HostRoute()
	h1 := startHelper(t, peer.addr)
	if _, err := Contain(h1.cmd.Process.Pid, tSelf4, ha, t.Logf); err != nil {
		t.Fatalf("Contain: %v", err)
	}
	t.Cleanup(func() {
		if _, notes, err := ReleaseStale(h1.cmd.Process.Pid, netip.Addr{}); err != nil || len(notes) > 0 {
			t.Errorf("releasing the killed containment: %v %v", err, notes)
		}
	})
	killDevice(nsA)
	nsB, _ := hostTUNAs(t, tSelf4) // the agent's next device
	h2 := startHelper(t, peer.addr)
	if got := h2.do(t, "park"); got != "ok" { // a descriptor in flight nobody receives: the takeover refuses
		t.Fatalf("park: %s", got)
	}
	origin2 := cgroupOf(t, h2.cmd.Process.Pid)
	_, err := Contain(h2.cmd.Process.Pid, tSelf4, *nsB.HostRoute(), t.Logf)
	var ce *ContainError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("the takeover must refuse over the descriptor in flight, got %v", err)
	}
	want := "/" + ContainParent + "/" + containCgroupName(tSelf4)
	if got := cgroupOf(t, h1.cmd.Process.Pid); got != want {
		t.Fatalf("the killed containment's process was let go by a failed takeover: it is in %s, not %s", got, want)
	}
	if got := cgroupOf(t, h2.cmd.Process.Pid); got != origin2 {
		t.Fatalf("the process the takeover tried to add is in %s, not back in %s", got, origin2)
	}
	rec, rerr := readRecord(filepath.Join(containState, containCgroupName(tSelf4)+".json"))
	if rerr != nil || rec.Gen != ha.Gen || rec.Pid != h1.cmd.Process.Pid {
		t.Fatalf("the killed containment's record was not given back as it was: %+v %v", rec, rerr)
	}
	if got := h1.do(t, "dial "+peer.addr); got == "ok" {
		t.Fatal("after the failed takeover the killed containment's process reached the peer")
	}
	if got := h1.do(t, "newsock"); got != "ok" {
		t.Fatalf("newsock: %s", got)
	}
	marks := map[uint32]int{}
	socks, _, _ := tableSockets([]int{h1.cmd.Process.Pid})
	for _, r := range socks {
		if dup, err := getfdAt(r.pid, r.tid, r.fd); err == nil {
			if m, err := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK); err == nil {
				marks[uint32(m)]++
			}
			unix.Close(dup)
		}
	}
	if marks[nsB.HostRoute().Mark] > 0 || marks[ha.Mark] < 2 {
		t.Fatalf("the killed containment's own mark program is not back on its cgroup: marks %v (its %#x, the takeover's %#x)",
			marks, ha.Mark, nsB.HostRoute().Mark)
	}
	if got := h2.do(t, "dial "+peer.addr); got != "ok" {
		t.Fatalf("control: the process the takeover gave back must be free again, got %s", got)
	}
}

// Descriptors in flight for a moment are waited out: the containment lets the process run until they
// are received, sweeps again, and holds what came back like any other socket.
func TestDescriptorsInFlightForAMomentAreWaitedOut(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	routeToPeer(t, peer)
	pc := capturePeer(t, peer, tSelf4)
	ns, _ := hostTUNAs(t, tSelf4)
	h := startHelper(t, peer.addr)
	old := beforeMove
	beforeMove = func() { h.do(t, "parkrecv 120") }
	t.Cleanup(func() { beforeMove = old })
	var logged []string
	var mu sync.Mutex
	logf := func(format string, args ...any) {
		mu.Lock()
		logged = append(logged, fmt.Sprintf(format, args...))
		mu.Unlock()
		t.Logf(format, args...)
	}
	c, err := Contain(h.cmd.Process.Pid, tSelf4, *ns.HostRoute(), logf)
	if err != nil {
		t.Fatalf("a descriptor in flight for a moment refused the containment: %v", err)
	}
	defer c.Release()
	mu.Lock()
	waited := strings.Contains(strings.Join(logged, "\n"), "in flight")
	mu.Unlock()
	if !waited {
		t.Fatal("control: the containment never saw the descriptor in flight, so nothing was waited out")
	}
	if got := h.do(t, "spray "+farAddr6.String()+" "+farAddr4.String()); got != "ok" {
		t.Fatalf("spray: %s", got)
	}
	pc.heldStill(t, 300*time.Millisecond, "contained after a wait for descriptors in flight")
	_ = h.do(t, "stopspray")
	pc.noneFromSelf(t, "contained after a wait for descriptors in flight")
}

// The attribution probe reads back the mark its cgroup's program gives a new socket, and leaves
// nothing behind; a program that marks nothing is refused.
func TestTheAttributionProbeProvesTheMechanismAndRefusesWithoutIt(t *testing.T) {
	needRoot(t)
	root := needCgroup2(t)
	attributionProven.Store(false)
	t.Cleanup(func() { attributionProven.Store(false) })
	if err := probeSocketAttribution(root); err != nil {
		t.Fatalf("the probe refused a kernel that attributes sockets: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ContainParent, fmt.Sprintf("probe-%d", os.Getpid()))); err == nil {
		t.Fatal("the probe left its cgroup")
	}
	attributionProven.Store(false)
	old := probeSpec
	probeSpec = func() *ebpf.ProgramSpec {
		return &ebpf.ProgramSpec{Name: "whisper_nomark", Type: ebpf.CGroupSock, AttachType: ebpf.AttachCGroupInetSockCreate,
			License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}}
	}
	t.Cleanup(func() { probeSpec = old })
	err := probeSocketAttribution(root)
	if err == nil || !strings.Contains(err.Error(), "does not tell a cgroup's programs") {
		t.Fatalf("a cgroup whose new sockets carry no mark must refuse, got %v", err)
	}
}

// `whisper contain --release` of a killed containment clears its rules, but its agent's refusal only
// once nothing could still send from the address: it used to delete that refusal whatever still did.
func TestReleasingAKilledContainmentKeepsTheRefusalWhileNeeded(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	withoutDestroy(t)
	peer := startPeer(t)
	ns, _ := hostTUNAs(t, tSelf4)
	h := startHelper(t, peer.addr)
	if _, err := Contain(h.cmd.Process.Pid, tSelf4, *ns.HostRoute(), t.Logf); err != nil {
		t.Fatalf("Contain: %v", err)
	}
	end := tcpFrom(t, tSelf4)
	killDevice(ns)
	if _, notes, err := ReleaseStale(h.cmd.Process.Pid, netip.Addr{}); err != nil || len(notes) > 0 {
		t.Fatalf("ReleaseStale: %v %v", err, notes)
	}
	if !refused(t, tSelf4) {
		t.Fatalf("with a connection still open from the agent's address, the release let the address take the host's routes:\n%s", ipRules(t))
	}
	end()
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf4) {
		t.Fatalf("with nothing on the address any more, the refusal stayed:\n%s%s", ipRules(t), pruneWhy(tSelf4))
	}
}

// A socket made inside that is in flight on a unix socket at the release is out of every table the
// release reads, so it keeps the containment's mark. Received and used after the release, while the
// tunnel still runs, it must not enter the tunnel: the released process speaks as itself.
func TestASocketInFlightAtTheReleaseNeverLeavesAsTheAgent(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, sent, raw := hostTUNRaw(t, tSelf4)
	go func() {
		for range sent {
		}
	}()
	h := startHelper(t, peer.addr)
	c, err := Contain(h.cmd.Process.Pid, tSelf4, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if got := h.do(t, "parkinside"); got != "ok" {
		c.Release()
		t.Fatalf("parkinside: %s", got)
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	for drained := false; !drained; {
		select {
		case <-raw:
		default:
			drained = true
		}
	}
	t.Logf("released, the parked socket used: %s", h.do(t, "unparksend [2606:4700:4700::1111]:443"))
	noDatagramWithin(t, raw, 500*time.Millisecond, "a datagram of a socket made inside and received after the release")
	ns.Close()
	c.Finish()
}

// A failed takeover gives back only what it moved in itself: whatever the killed containment's process
// forks meanwhile (the takeover lets the tree run while it waits for descriptors in flight) stays held
// with it.
func TestAFailedTakeoverHoldsWhatTheKilledContainmentsProcessForks(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	if sleepBin() == "sleep" {
		t.Skip("needs sleep(1) at /bin or /usr/bin")
	}
	peer := startPeer(t)
	nsA, _ := hostTUNAs(t, tSelf4)
	h1 := startHelper(t, peer.addr)
	t.Cleanup(func() { h1.do(t, "killspawned") })
	if _, err := Contain(h1.cmd.Process.Pid, tSelf4, *nsA.HostRoute(), t.Logf); err != nil {
		t.Fatalf("Contain: %v", err)
	}
	t.Cleanup(func() {
		if _, notes, err := ReleaseStale(h1.cmd.Process.Pid, netip.Addr{}); err != nil || len(notes) > 0 {
			t.Errorf("releasing the killed containment: %v %v", err, notes)
		}
	})
	killDevice(nsA)
	nsB, _ := hostTUNAs(t, tSelf4)
	h2 := startHelper(t, peer.addr)
	if got := h2.do(t, "park"); got != "ok" {
		t.Fatalf("park: %s", got)
	}
	if got := h1.do(t, "spawnloop"); got != "ok" {
		t.Fatalf("spawnloop: %s", got)
	}
	_, err := Contain(h2.cmd.Process.Pid, tSelf4, *nsB.HostRoute(), t.Logf)
	if err == nil || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("the takeover must refuse over the descriptor in flight, got %v", err)
	}
	if got := h1.do(t, "stopspawn"); got != "ok" {
		t.Fatalf("stopspawn: %s", got)
	}
	want := "/" + ContainParent + "/" + containCgroupName(tSelf4)
	kids := descendants(parentMap(), h1.cmd.Process.Pid)
	if len(kids) == 0 {
		t.Fatal("control: the killed containment's process forked nothing, so nothing was tested")
	}
	for _, k := range kids {
		if exited(k) {
			continue
		}
		if got := cgroupOf(t, k); got != want {
			t.Fatalf("pid %d, forked by the killed containment's process, was let out by the failed takeover into %s", k, got)
		}
	}
	if got := cgroupOf(t, h1.cmd.Process.Pid); got != want {
		t.Fatalf("the killed containment's process was let out into %s", got)
	}
	if got := cgroupOf(t, h2.cmd.Process.Pid); got == want {
		t.Fatal("the process the takeover tried to add was kept")
	}
	t.Logf("%d children of the killed containment's process, all still held", len(kids))
}

// A TCP socket from the agent's address that the release ended can be connected again (TCP clears
// the shutdown on a disconnect). It still carries the mark and the pin until the tunnel stops, but it
// is no longer the containment's: its new connection never enters the tunnel.
func TestAConnectionTheReleaseEndedNeverEntersTheTunnelAgain(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, sent, raw := hostTUNRaw(t, tSelf4)
	go func() {
		for range sent {
		}
	}()
	h := startHelper(t, peer.addr)
	c, err := Contain(h.cmd.Process.Pid, tSelf4, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	far := "[2606:4700:4700::1111]:443"
	if got := h.do(t, "tcpfrom "+tSelf4.String()+" "+far); got != "ok" {
		c.Release()
		t.Fatalf("tcpfrom: %s", got)
	}
	synFromSelf := func(d time.Duration) bool {
		deadline := time.After(d)
		for {
			select {
			case p := <-raw:
				if p[0]>>4 == 6 && len(p) >= 54 && p[6] == protoTCP && addr16(p[8:24]) == tSelf4 && p[53]&0x02 != 0 {
					return true
				}
			case <-deadline:
				return false
			}
		}
	}
	if !synFromSelf(time.Second) {
		c.Release()
		t.Fatal("control: the contained connection's SYN never reached the tunnel")
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	for drained := false; !drained; {
		select {
		case <-raw:
		default:
			drained = true
		}
	}
	t.Logf("released, the ended connection connected again: %s", h.do(t, "tcprevive "+far))
	if synFromSelf(700 * time.Millisecond) {
		t.Fatal("a connection the release ended was connected again and entered the tunnel as the agent")
	}
	ns.Close()
	c.Finish()
}

// A failed takeover gives back only what it moved in itself. A process the killed containment held
// stays held even when the takeover's target is its parent, which the takeover moved in.
func TestAFailedTakeoverNeverGivesBackAProcessTheKilledContainmentHeld(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	if sleepBin() == "sleep" {
		t.Skip("needs sleep(1) at /bin or /usr/bin")
	}
	peer := startPeer(t)
	h2 := startHelper(t, peer.addr)
	t.Cleanup(func() { h2.do(t, "killspawned") })
	if got := h2.do(t, "spawnloop"); got != "ok" {
		t.Fatalf("spawnloop: %s", got)
	}
	time.Sleep(30 * time.Millisecond)
	if got := h2.do(t, "stopspawn"); got != "ok" {
		t.Fatalf("stopspawn: %s", got)
	}
	kids := descendants(parentMap(), h2.cmd.Process.Pid)
	if len(kids) == 0 {
		t.Fatal("control: the parent has no child to contain")
	}
	k := kids[0]
	nsA, _ := hostTUNAs(t, tSelf4)
	if _, err := Contain(k, tSelf4, *nsA.HostRoute(), t.Logf); err != nil {
		t.Fatalf("Contain the child: %v", err)
	}
	t.Cleanup(func() {
		if _, notes, err := ReleaseStale(k, netip.Addr{}); err != nil || len(notes) > 0 {
			t.Errorf("releasing the killed containment: %v %v", err, notes)
		}
	})
	killDevice(nsA)
	nsB, _ := hostTUNAs(t, tSelf4)
	if got := h2.do(t, "park"); got != "ok" {
		t.Fatalf("park: %s", got)
	}
	_, err := Contain(h2.cmd.Process.Pid, tSelf4, *nsB.HostRoute(), t.Logf)
	if err == nil || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("the takeover of the parent must refuse over its descriptor in flight, got %v", err)
	}
	want := "/" + ContainParent + "/" + containCgroupName(tSelf4)
	if got := cgroupOf(t, k); got != want {
		t.Fatalf("the child the killed containment held was given back by the failed takeover of its parent: it is in %s", got)
	}
	if got := cgroupOf(t, h2.cmd.Process.Pid); got == want {
		t.Fatal("the parent the takeover tried to add was kept")
	}
}

// A process held by another agent's containment is never pulled into this one: its sockets would be
// marked as this agent's, and it would speak as this agent.
func TestATreeReachingAnotherAgentsContainmentIsRefused(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	if sleepBin() == "sleep" {
		t.Skip("needs sleep(1) at /bin or /usr/bin")
	}
	peer := startPeer(t)
	h := startHelper(t, peer.addr)
	t.Cleanup(func() { h.do(t, "killspawned") })
	if got := h.do(t, "spawnloop"); got != "ok" {
		t.Fatalf("spawnloop: %s", got)
	}
	time.Sleep(30 * time.Millisecond)
	_ = h.do(t, "stopspawn")
	kids := descendants(parentMap(), h.cmd.Process.Pid)
	if len(kids) == 0 {
		t.Fatal("control: no child to contain")
	}
	nsA, _ := hostTUNAs(t, tSelf4)
	cA, err := Contain(kids[0], tSelf4, *nsA.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain the child as one agent: %v", err)
	}
	defer cA.Release()
	nsB, _ := hostTUNAs(t, tSelf3)
	_, err = Contain(h.cmd.Process.Pid, tSelf3, *nsB.HostRoute(), t.Logf)
	if err == nil || !strings.Contains(err.Error(), "another agent's containment") {
		t.Fatalf("containing the parent as another agent must refuse over the child, got %v", err)
	}
	if got, want := cgroupOf(t, kids[0]), "/"+ContainParent+"/"+containCgroupName(tSelf4); got != want {
		t.Fatalf("the refusal moved the other agent's process: it is in %s", got)
	}
}

// A device clears what a killed holder of its slot left there, and only that: a host's own rule at the
// slot's priority (a rule added without a priority lands there) stays.
func TestANewDeviceLeavesTheHostsOwnRulesAtItsSlot(t *testing.T) {
	needRoot(t)
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	theirs := []struct {
		fam  uint8
		body []byte
	}{
		{unix.AF_INET, ruleBodyFrom(unix.AF_INET, hostRulePrio, netip.MustParseAddr("10.9.9.8"), hostTableBase)},
		{unix.AF_INET6, ruleBodyAnyFrom(unix.AF_INET6, hostRulePrio, netip.MustParsePrefix("2001:db8:5::/64"), hostTableBase)},
		{unix.AF_INET6, ruleBodyFrom(unix.AF_INET6, hostRulePrio, netip.MustParseAddr("2001:db8:5::1"), 200)},
	}
	for _, x := range theirs {
		if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, x.body); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, x := range theirs {
			b, fam := x.body, x.fam
			deleteRuleBodies(func(f uint8) []byte {
				if f == fam {
					return b
				}
				return nil
			})
		}
	})
	ns, _ := hostTUNAs(t, tSelf3)
	if ns.HostRoute().Slot != 0 {
		t.Skipf("the device took slot %d; this host already holds slot 0", ns.HostRoute().Slot)
	}
	v4, _ := exec.Command("ip", "-4", "rule", "show").CombinedOutput()
	v6 := ipRules(t)
	for _, want := range []string{"from 10.9.9.8 lookup 4300"} {
		if !strings.Contains(string(v4), want) {
			t.Fatalf("a new device took the host's own IPv4 rule %q:\n%s", want, v4)
		}
	}
	for _, want := range []string{"from 2001:db8:5::/64 lookup 4300", "from 2001:db8:5::1 lookup 200"} {
		if !strings.Contains(v6, want) {
			t.Fatalf("a new device took the host's own rule %q:\n%s", want, v6)
		}
	}
}

// ruleBodyAnyFrom encodes "priority prio from prefix lookup table", a host's rule for a whole prefix.
func ruleBodyAnyFrom(fam uint8, prio uint32, p netip.Prefix, table uint32) []byte {
	b := ruleBodyFrom(fam, prio, p.Addr(), table)
	b[2] = uint8(p.Bits())
	return b
}

// A socket from before the containment, which the sweep adopted, that is in flight on a unix socket at
// the release is out of every table the release reads, so it keeps the sweep's tag, mark and pin.
// Received and used after the release, while the tunnel still runs, it must not enter the tunnel: the
// release voids every tag the sweep gave, wherever its socket is.
func TestASweptSocketInFlightAtTheReleaseNeverLeavesAsTheAgent(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, sent, raw := hostTUNRaw(t, tSelf4)
	go func() {
		for range sent {
		}
	}()
	h := startHelper(t, peer.addr)
	if got := h.do(t, "udpopen"); got != "ok" { // before the containment: swept, adopted, marked, pinned
		t.Fatalf("udpopen: %s", got)
	}
	c, err := Contain(h.cmd.Process.Pid, tSelf4, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if got := h.do(t, "parkkept"); got != "ok" {
		c.Release()
		t.Fatalf("parkkept: %s", got)
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	for drained := false; !drained; {
		select {
		case <-raw:
		default:
			drained = true
		}
	}
	t.Logf("released, the swept socket used: %s", h.do(t, "unparksend [2606:4700:4700::1111]:443"))
	noDatagramWithin(t, raw, 500*time.Millisecond, "a datagram of a socket the sweep adopted, received after the release")
	ns.Close()
	c.Finish()
}

// needSCTP skips unless the sctp module is loaded. A test may load it (creating an SCTP socket does,
// as root) only when WHISPER_TEST_LOAD_SCTP=1 says so: it stays loaded on the host afterwards.
func needSCTP(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/sys/module/sctp"); err == nil {
		return
	}
	if os.Getenv("WHISPER_TEST_LOAD_SCTP") != "1" {
		t.Skip("needs the sctp module loaded (WHISPER_TEST_LOAD_SCTP=1 lets the test load it, and it stays loaded)")
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("this kernel has no SCTP: %v", err)
	}
	unix.Close(fd)
}

// Once the sctp module is loaded, the kernel keeps an SCTP control socket in every namespace, so the
// protocol table counts SCTPv6 in a namespace nobody has used. It sends for no address and is in no
// association: a prune still decides, and takes a refusal nothing needs.
func TestTheKernelsSCTPControlSocketDoesNotStopAPrune(t *testing.T) {
	needRoot(t)
	needSCTP(t)
	protos, err := ipv6Protocols()
	if err != nil {
		t.Fatal(err)
	}
	if protos["SCTPv6"] < 1 {
		t.Fatalf("control: with the sctp module loaded this namespace must count SCTPv6, got %v", protos)
	}
	socks, complete, why := agentSockets([]netip.Addr{tSelf3})
	if !complete || len(socks) != 0 {
		t.Fatalf("the kernel's SCTP control socket left the answer incomplete or counted (%v %q %v); a prune would never decide on this host",
			complete, why, socks)
	}
	plantRefusal(t, tSelf3, 7)
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("with only the kernel's SCTP control socket in use, the prune kept a refusal nothing needs:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
}

// An SCTP association from the agent's address keeps its refusal: the kernel drives it on its own
// (heartbeats, retransmissions, the shutdown). Once it has ended, the refusal goes.
func TestAnSCTPAssociationFromTheAgentHoldsItsRefusal(t *testing.T) {
	needRoot(t)
	needSCTP(t)
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("link", "add", "ressctp", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "ressctp").Run() })
	run("-6", "addr", "add", tSelf3.String()+"/128", "dev", "ressctp", "nodad")
	run("link", "set", "ressctp", "up")
	sock := func() int {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_SCTP)
		if err != nil {
			t.Fatalf("an SCTP socket: %v", err)
		}
		if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: tSelf3.As16()}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		return fd
	}
	srv, cli := sock(), sock()
	if err := unix.Listen(srv, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(cli, sa); err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn, _, err := unix.Accept(srv)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	ended := false
	end := func() {
		if !ended {
			ended = true
			unix.Close(cli)
			unix.Close(conn)
			unix.Close(srv)
		}
	}
	t.Cleanup(end)
	socks, complete, why := agentSockets([]netip.Addr{tSelf3})
	n := 0
	for _, k := range socks {
		if k.sctp && k.src == tSelf3 {
			n++
		}
	}
	if !complete || n == 0 {
		t.Fatalf("an SCTP association from the agent's address was not counted: %v %q %v", complete, why, socks)
	}
	plantRefusal(t, tSelf3, 7)
	pruneAgentRefusals(netip.Addr{}, 0)
	if !hasAddrRules(tSelf3) {
		t.Fatal("a prune took the refusal of an address an SCTP association still speaks from")
	}
	end()
	waitFor(t, func() bool {
		socks, complete, _ := agentSockets([]netip.Addr{tSelf3})
		return complete && len(socks) == 0
	}, "the SCTP association to end")
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("with the association ended, the refusal stayed:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
}
