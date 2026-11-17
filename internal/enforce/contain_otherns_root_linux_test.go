// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// contain_otherns_root_linux_test.go holds a containment to the network namespace each of its comparisons belongs
// to. A device's index is unique only within its own namespace, and a contained process may have a member in a
// namespace of its own: a sandboxed child, in a namespace that holds only loopback. These tests build that second
// namespace and put a device in it at the tunnel's own index, so that anything compared across the two is seen.
//
// Unprivileged, or without cgroup v2, it skips and says why.

const (
	otherNSSpawnerArg = "__whisper-otherns-spawner"
	otherNSChildArg   = "__whisper-otherns-child"
	otherNSOwnerArg   = "__whisper-otherns-owner"
	nobodyID          = 65534
	vethInfoPeer      = 1 // VETH_INFO_PEER, from include/uapi/linux/veth.h
)

// otherNSSpawner is the process the tests contain. It starts as root, starts its one child in a network namespace
// of its own as nobody, then drops to nobody itself, so that both are processes a containment takes, and says the
// child's pid. The child answers the test on the stdin and stdout the spawner hands it. Its options:
//
//   - "bind6=<addr>": the spawner keeps a datagram socket of the host's namespace bound to addr (IPV6_FREEBIND, no
//     capability needed), made before it drops, which a release must cut.
func otherNSSpawner() {
	for _, a := range os.Args[2:] {
		switch {
		case strings.HasPrefix(a, "bind6="):
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
			}
			if err == nil {
				err = unix.Bind(fd, &unix.SockaddrInet6{Addr: netip.MustParseAddr(strings.TrimPrefix(a, "bind6=")).As16()})
			}
			if err != nil {
				fmt.Printf("err cannot hold the host socket: %v\n", err)
				os.Exit(1)
			}
		}
	}
	child := exec.Command("/proc/self/exe", otherNSChildArg)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET,
		Credential: &syscall.Credential{Uid: nobodyID, Gid: nobodyID}}
	if err := child.Start(); err != nil {
		fmt.Printf("err cannot start the child: %v\n", err)
		os.Exit(1)
	}
	err := syscall.Setgroups(nil)
	if err == nil {
		err = syscall.Setresgid(nobodyID, nobodyID, nobodyID)
	}
	if err == nil {
		err = syscall.Setresuid(nobodyID, nobodyID, nobodyID)
	}
	if err != nil {
		_ = child.Process.Kill()
		fmt.Printf("err cannot become nobody: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("child %d\n", child.Process.Pid)
	_ = child.Wait()
	os.Exit(0)
}

// otherNSChild is the member in a namespace of its own. One command per line, one answer per command, "ok ..." or
// "err <reason>".
func otherNSChild() {
	out := bufio.NewWriter(os.Stdout)
	say := func(s string) { fmt.Fprintln(out, s); out.Flush() }
	answer := func(err error) {
		if err != nil {
			say("err " + errName(err))
			return
		}
		say("ok")
	}
	kept := -1
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		switch {
		case len(f) == 2 && f[0] == "bind6": // bind6 <addr>: a datagram socket bound to addr with IPV6_FREEBIND, kept
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
				if err == nil {
					err = unix.Bind(fd, &unix.SockaddrInet6{Addr: netip.MustParseAddr(f[1]).As16()})
				}
				if err != nil {
					unix.Close(fd)
				} else {
					kept = fd
				}
			}
			answer(err)
		case len(f) == 1 && f[0] == "state": // the kept socket's device binding, and whether it was shut down
			idx, err := unix.GetsockoptInt(kept, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
			if err != nil {
				answer(err)
				continue
			}
			pfd := []unix.PollFd{{Fd: int32(kept), Events: unix.POLLIN}}
			_, _ = unix.Poll(pfd, 0)
			say(fmt.Sprintf("ok bound=%d shut=%v", idx, pfd[0].Revents&unix.POLLHUP != 0))
		case len(f) == 2 && f[0] == "udp": // udp <addr:port>: one datagram from a new socket
			ap, err := netip.ParseAddrPort(f[1])
			if err == nil {
				err = sendOne(ap)
			}
			answer(err)
		case len(f) == 1 && f[0] == "loopback": // a datagram to itself over this namespace's loopback
			answer(loopbackRoundTrip())
		case len(f) == 2 && f[0] == "newlink": // newlink <index>: a veth pair here, its first end at index
			idx, _ := strconv.Atoi(f[1])
			answer(addVeth("wcm0", idx, "wcm1", idx+1, -1))
		case len(f) == 1 && f[0] == "exit":
			os.Exit(0)
		default:
			say("err unknown command")
		}
	}
	os.Exit(0)
}

// otherNSOwner is root of a user namespace of its own, which owns its network namespace. Fd 3 is the test's own
// network namespace, and fd 4 a datagram socket made there. It says, for each way it has to give its namespace a
// device in the test's or to bring one up there, what the kernel answered, and then waits for its stdin to close,
// so the far end of a veth it placed is still there for the test to look at.
func otherNSOwner() {
	idx, _ := strconv.Atoi(os.Args[2])
	const host = 3
	var res []string
	try := func(what string, err error) { res = append(res, what+"="+errName(err)) }
	// The control: it can put a device at the tunnel's index where it is, so each refusal below is the kernel's rule
	// about the other namespace, not a capability it lacks.
	try("own", addVeth("wco0", idx, "wco1", idx+1, -1))
	if r, err := openRTNL(); err != nil {
		try("create", err)
		try("move", err)
	} else {
		create := append(ifinfo(0, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte("wcq0\x00"))...)
		create = append(create, nlAttr(unix.IFLA_NET_NS_FD, u32(host))...)
		create = append(create, nlAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, nlAttr(unix.IFLA_INFO_KIND, []byte("dummy")))...)
		try("create", r.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, create))
		if own, err := ifIndex("wco1"); err != nil {
			try("move", err)
		} else {
			try("move", r.do(unix.RTM_NEWLINK, 0, append(ifinfo(own, 0, 0), nlAttr(unix.IFLA_NET_NS_FD, u32(host))...)))
		}
		r.close()
	}
	// A veth whose far end is placed in the test's namespace, down as the request leaves it.
	try("peer", addVeth("wcp0", 0, "wcp1", 0, host))
	// The same with the far end's own IFF_UP: the kernel opens the far end before it is joined to this end, so the
	// request fails (ENOTCONN on Linux 6.8) rather than placing a device that arrives up.
	try("peerup", addVethPeerUp("wcu0", "wcu1", host))
	ifr, err := unix.NewIfreq("wcp1")
	if err == nil {
		ifr.SetUint16(unix.IFF_UP)
		err = unix.IoctlIfreq(4, unix.SIOCSIFFLAGS, ifr) // asked through a socket of the test's namespace
	}
	try("up", err)
	enter := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: if setns took, the thread must never run anything else
		enter <- unix.Setns(host, unix.CLONE_NEWNET)
	}()
	try("enter", <-enter)
	fmt.Println(strings.Join(res, " "))
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// sendOne sends one datagram to ap from a new socket.
func sendOne(ap netip.AddrPort) error {
	fam := unix.AF_INET6
	if ap.Addr().Is4() {
		fam = unix.AF_INET
	}
	fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, []byte("x"), 0, sockaddr(ap))
}

// loopbackRoundTrip sends one datagram over loopback to a socket of its own and reads it back.
func loopbackRoundTrip() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	if err := unix.Sendto(fd, []byte("x"), 0, sa); err != nil {
		return err
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	b := make([]byte, 8)
	if n, _, err := unix.Recvfrom(fd, b, 0); err != nil || n != 1 {
		return fmt.Errorf("the datagram did not come back (%d, %v)", n, err)
	}
	return nil
}

// addVeth makes a veth pair in the calling thread's namespace: name at index (0: the kernel's choice), and its peer
// at peerIndex in the namespace peerNS names (-1: this one). The kernel makes the peer first, so a peer in the same
// namespace is given an index of its own when name has one, or it would take the one name asks for.
func addVeth(name string, index int, peer string, peerIndex, peerNS int) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	peerMsg := append(ifinfo(peerIndex, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte(peer+"\x00"))...)
	if peerNS >= 0 {
		peerMsg = append(peerMsg, nlAttr(unix.IFLA_NET_NS_FD, u32(uint32(peerNS)))...)
	}
	info := append(nlAttr(unix.IFLA_INFO_KIND, []byte("veth")),
		nlAttr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, nlAttr(vethInfoPeer, peerMsg))...)
	body := append(ifinfo(index, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte(name+"\x00"))...)
	body = append(body, nlAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	return r.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// addVethPeerUp is addVeth with the far end, in the namespace peerNS holds, asked to be up as it is made.
func addVethPeerUp(name, peer string, peerNS int) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	peerMsg := append(ifinfo(0, unix.IFF_UP, unix.IFF_UP), nlAttr(unix.IFLA_IFNAME, []byte(peer+"\x00"))...)
	peerMsg = append(peerMsg, nlAttr(unix.IFLA_NET_NS_FD, u32(uint32(peerNS)))...)
	info := append(nlAttr(unix.IFLA_INFO_KIND, []byte("veth")),
		nlAttr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, nlAttr(vethInfoPeer, peerMsg))...)
	body := append(ifinfo(0, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte(name+"\x00"))...)
	body = append(body, nlAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	return r.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// otherNS is a running spawner and its child.
type otherNS struct {
	pid, child int
	in         io.WriteCloser
	out        *bufio.Scanner
}

func (o *otherNS) do(t *testing.T, line string) string {
	t.Helper()
	fmt.Fprintln(o.in, line)
	ch := make(chan string, 1)
	go func() {
		if o.out.Scan() {
			ch <- o.out.Text()
		} else {
			ch <- "err the child is gone"
		}
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("the child did not answer %q", line)
		return ""
	}
}

// startOtherNS starts the spawner, with opts (otherNSSpawner's), which starts its child in a namespace of its own,
// and waits for the child's pid.
func startOtherNS(t *testing.T, opts ...string) *otherNS {
	t.Helper()
	if err := closeOnExecAboveStderr(); err != nil {
		t.Fatalf("cannot keep the test's descriptors out of the spawner: %v", err)
	}
	cmd := exec.Command(agentBinary(t), append([]string{otherNSSpawnerArg}, opts...)...)
	cmd.Env = []string{testsLockedEnv + "=1"}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outp, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the spawner: %v", err)
	}
	o := &otherNS{pid: cmd.Process.Pid, in: in, out: bufio.NewScanner(outp)}
	t.Cleanup(func() {
		// The child first, while its stdin is still open: it cannot have exited on its own yet, so its pid is still
		// its own and a signal by number cannot reach a process that took the number after it.
		if o.child > 0 {
			_ = syscall.Kill(o.child, syscall.SIGKILL)
		}
		in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	line := make(chan string, 1)
	go func() {
		if o.out.Scan() {
			line <- o.out.Text()
		} else {
			line <- "err the spawner said nothing"
		}
	}()
	select {
	case l := <-line:
		if _, err := fmt.Sscanf(l, "child %d", &o.child); err != nil {
			t.Fatalf("the spawner said %q", l)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the spawner never said its child's pid")
	}
	if sameNamespace(strconv.Itoa(o.child), "thread-self", "net") {
		t.Fatal("control: the child is in the test's own namespace")
	}
	return o
}

// nsFD opens a process's network namespace, closed when the test ends.
func nsFD(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("cannot open pid %d's network namespace: %v", pid, err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// ownNSFD opens the test's own network namespace (this thread's), closed when the test ends.
func ownNSFD(t *testing.T) int {
	t.Helper()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// giveDevice puts a veth end named name+"b" at index in pid's namespace, with its peer, name+"a", in the test's
// own, as a privileged program could at any time. It returns the index the device has there.
func giveDevice(t *testing.T, pid int, name string, index int) int {
	t.Helper()
	host := ownNSFD(t)
	got := 0
	err := onThreadIn(nsFD(t, pid), func() error {
		if err := addVeth(name+"b", index, name+"a", 0, host); err != nil {
			return fmt.Errorf("a veth at index %d in pid %d's namespace: %w", index, pid, err)
		}
		var err error
		got, err = ifIndex(name + "b")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name+"a").Run() })
	return got
}

// A release ends what a member sends from the agent's address only in the namespace the tunnel is in: a socket of
// a member's own namespace, bound to the agent's address there, never left the host, and is not pinned to the
// device that holds the tunnel's index in that namespace, which is another device entirely, nor shut down. The same
// release still ends the host-namespace socket another member holds bound to the agent's address.
func TestReleaseLeavesASocketOfAMembersOwnNamespaceAlone(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	ns, _ := hostTUN(t)
	hr := ns.HostRoute()
	o := startOtherNS(t, "bind6="+tSelf.String())
	c, err := Contain(o.pid, tSelf, *hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	released := false
	defer func() {
		if !released {
			c.Release()
		}
	}()
	if _, ok := c.isolated[o.child]; !ok {
		t.Fatalf("control: the child's namespace must be taken as one that reaches nothing past loopback (%v)", c.isolated)
	}
	// A sandbox's loopback is up, as a browser's renderer's is; a new namespace's starts down.
	if err := onThreadIn(nsFD(t, o.child), func() error {
		r, err := openRTNL()
		if err != nil {
			return err
		}
		defer r.close()
		return r.setUp(1)
	}); err != nil {
		t.Fatalf("cannot bring the member's loopback up: %v", err)
	}
	// Loopback is the one way out a member's own namespace has, and it stays open: lo is index 1 in every namespace.
	if got := o.do(t, "loopback"); got != "ok" {
		t.Fatalf("the member's own loopback must keep working: %s", got)
	}
	if got := o.do(t, "bind6 "+tSelf.String()); got != "ok" {
		t.Fatalf("control: a socket bound to the agent's address in the member's namespace: %s", got)
	}
	if got := giveDevice(t, o.child, "wcr", hr.Index); got != hr.Index {
		t.Fatalf("control: the device in the member's namespace has index %d, not the tunnel's %d", got, hr.Index)
	}
	hostFd := -1
	for _, l := range socketsOf(t, o.pid) {
		if n, err := fmt.Sscanf(l, "%d ->", &hostFd); n != 1 || err != nil {
			hostFd = -1
		}
	}
	if hostFd < 0 {
		t.Fatalf("control: the spawner must hold its host socket bound to the agent's address (%v)", socketsOf(t, o.pid))
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	released = true
	if got := o.do(t, "state"); got != "ok bound=0 shut=false" {
		t.Fatalf("the member's socket was touched by the release (%s): the tunnel's index %d names another device "+
			"in the member's namespace", got, hr.Index)
	}
	dup, err := getfd(o.pid, hostFd)
	if err != nil {
		t.Fatalf("cannot reach the spawner's host socket: %v", err)
	}
	defer unix.Close(dup)
	bound, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
	pfd := []unix.PollFd{{Fd: int32(dup), Events: unix.POLLIN}}
	_, _ = unix.Poll(pfd, 0)
	if bound != hr.Index || pfd[0].Revents&unix.POLLHUP == 0 {
		t.Fatalf("the release must end the host-namespace socket bound to the agent's address (bound=%d, want %d; "+
			"shut=%v)", bound, hr.Index, pfd[0].Revents&unix.POLLHUP != 0)
	}
}

// The gate on the containment's cgroup compares a packet's device index with the tunnel's, which is the host
// namespace's, whatever namespace the packet's socket is in. It is never asked to judge a socket in a namespace
// where that number names a device that reaches anywhere: a member in a namespace holding anything but loopback and
// the kernel's idle fallback devices refuses the containment, and nothing is changed.
func TestAMemberWhoseNamespaceHoldsTheTunnelsIndexRefusesTheContainment(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	ns, _ := hostTUN(t)
	hr := ns.HostRoute()
	o := startOtherNS(t)
	if got := giveDevice(t, o.child, "wcs", hr.Index); got != hr.Index {
		t.Fatalf("control: the device in the member's namespace has index %d, not the tunnel's %d", got, hr.Index)
	}
	before := cgroupOf(t, o.pid)
	c, err := Contain(o.pid, tSelf, *hr, t.Logf)
	if err == nil {
		c.Release()
		t.Fatal("a member in a namespace holding a device at the tunnel's index, linked to another namespace, was contained")
	}
	var ce *ContainError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "reaches past loopback") {
		t.Fatalf("the refusal must say the member's namespace reaches past loopback: %v", err)
	}
	if got := cgroupOf(t, o.pid); got != before {
		t.Fatalf("a refused containment moved the process: it is in %s, was in %s", got, before)
	}
}

// socketInode is the inode of the one IP socket a process holds, or 0.
func socketInode(t *testing.T, pid int) uint64 {
	t.Helper()
	for _, s := range socketsOf(t, pid) {
		var ino uint64
		if _, err := fmt.Sscanf(s[strings.Index(s, "socket:[")+len("socket:["):], "%d]", &ino); err == nil {
			return ino
		}
	}
	return 0
}

// The release judges a socket by the namespace the sweep found it isolated in, never by the namespace of the thread
// it runs on: run from inside the member's own namespace, it still cuts the host's socket bound to the agent's
// address and still leaves the member's own one alone. A version that compared each socket with the running thread's
// namespace would do both the other way round.
func TestTheCutIsJudgedByTheSweepNotByTheCallersNamespace(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	ns, _ := hostTUN(t)
	hr := ns.HostRoute()
	o := startOtherNS(t, "bind6="+tSelf.String())
	c, err := Contain(o.pid, tSelf, *hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	if got := o.do(t, "bind6 "+tSelf.String()); got != "ok" {
		t.Fatalf("control: a socket bound to the agent's address in the member's namespace: %s", got)
	}
	host, own := socketInode(t, o.pid), socketInode(t, o.child)
	if host == 0 || own == 0 {
		t.Fatalf("control: the host's socket (%d) and the member's (%d) must both be there", host, own)
	}
	var cut map[uint64]bool
	if err := onThreadIn(nsFD(t, o.child), func() error { cut = c.cutAgentSockets(); return nil }); err != nil {
		t.Fatal(err)
	}
	if !cut[host] {
		t.Fatalf("the release, run from the member's namespace, left the host's socket bound to the agent's address (%v)", cut)
	}
	if cut[own] {
		t.Fatalf("the release, run from the member's namespace, cut the member's own socket (%v)", cut)
	}
}

// What a process that is root in a user namespace of its own can do to a namespace it holds a descriptor for, the
// facts the containment's design records as measured. The control: it can put a device at the tunnel's index in its own namespace.
// It can make no device in the other one, move none there, bring none up there through a socket of that namespace it
// kept, or enter it. A veth's far end it may place there (Linux 6.8 lets it; a kernel that refuses is accepted too),
// and that end is down, with no address: nothing it did brought it up.
func TestAUserNamespacesRootPlacesAVethEndDownItCannotBringUp(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	ns, _ := hostTUN(t)
	hr := ns.HostRoute()
	host, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostSock := os.NewFile(uintptr(sock), "a socket of the test's namespace")
	defer hostSock.Close()
	cmd := exec.Command(agentBinary(t), otherNSOwnerArg, strconv.Itoa(hr.Index))
	cmd.Env = []string{testsLockedEnv + "=1"}
	cmd.ExtraFiles = []*os.File{host, hostSock}
	// Root of its own user namespace, mapped to root, as startSandbox's is: a host that keeps capabilities out of
	// user namespaces made by unprivileged users (Ubuntu's AppArmor restriction) still lets this one use them, so the
	// control proves something. Its capabilities stop at the namespaces it owns whatever it is mapped to.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outp, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the user namespace's root: %v", err)
	}
	defer func() { in.Close(); _ = cmd.Wait() }()
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(outp).ReadString('\n')
		line <- strings.TrimSpace(l)
	}()
	var out string
	select {
	case out = <-line:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the user namespace's root never answered")
	}
	t.Logf("as root of a user namespace of its own: %s", out)
	got := map[string]string{}
	for _, kv := range strings.Fields(out) {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["own"] != "ok" {
		t.Fatalf("control: the user namespace's root could not make a device at the tunnel's index in its own namespace: %s", out)
	}
	for _, k := range []string{"create", "move", "up", "enter"} {
		if got[k] != "EPERM" {
			t.Errorf("%s: the kernel answered %q, where only a program privileged over the other namespace may", k, got[k])
		}
	}
	if got["create"] == "ok" {
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "wcq0").Run() })
	}
	if got["peerup"] == "ok" {
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "wcu1").Run() })
		t.Fatal("a veth's far end placed with its own IFF_UP was made: a device can arrive up in a namespace its maker " +
			"holds no capability over")
	}
	switch got["peer"] {
	case "EPERM":
	case "ok":
		// Looked at while the owner still lives: its end goes, and this one with it, once its namespace is gone.
		ifc, err := net.InterfaceByName("wcp1")
		if err != nil {
			t.Fatalf("the veth's far end is not in this namespace: %v", err)
		}
		if ifc.Flags&net.FlagUp != 0 {
			t.Fatal("the veth's far end the user namespace's root placed here is up")
		}
		if as, _ := ifc.Addrs(); len(as) > 0 {
			t.Fatalf("the veth's far end the user namespace's root placed here has addresses %v", as)
		}
	default:
		t.Fatalf("a veth's far end in another namespace: the kernel answered %q", got["peer"])
	}
}
