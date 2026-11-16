// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// contain_root_linux_test.go runs a real containment as root: a real process, running as nobody,
// holding a real connection out of the host, is contained, and the test proves what it can and
// cannot do afterwards. "The outside" is a second network namespace on a veth pair, so nothing
// leaves the machine running the test; the tunnel device is read directly, as in netns_linux_test.go.
//
// Unprivileged, or without cgroup v2, iproute2 or a writable cgroup hierarchy, it skips and says why.

const containHelperArg = "__whisper-contain-helper"

// containHelper is the contained process: it dials CONTAIN_PEER, says "ready", then obeys one
// command per line and answers "ok" or "err <reason>".
func containHelper() {
	out := bufio.NewWriter(os.Stdout)
	say := func(s string) { fmt.Fprintln(out, s); out.Flush() }
	conn, err := net.DialTimeout("tcp", os.Getenv("CONTAIN_PEER"), 3*time.Second)
	if err != nil {
		say("err " + err.Error())
		os.Exit(1)
	}
	say("ready")
	answer := func(err error) {
		if err != nil {
			say("err " + err.Error())
			return
		}
		say("ok")
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "write":
			_, err := conn.Write([]byte("x"))
			answer(err)
		case "dial":
			c, err := net.DialTimeout("tcp", f[1], 2*time.Second)
			if c != nil {
				c.Close()
			}
			answer(err)
		case "binddial":
			d := net.Dialer{Timeout: 2 * time.Second, Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				_ = rc.Control(func(fd uintptr) {
					serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, f[1])
				})
				return serr
			}}
			c, err := d.Dial("tcp", f[2])
			if c != nil {
				c.Close()
			}
			answer(err)
		case "bindudp":
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				err = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, f[1])
				if err == nil {
					ap := netip.MustParseAddrPort(f[2])
					err = unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()})
				}
				unix.Close(fd)
			}
			answer(err)
		case "listenaddr": // the escape tests' listener, read back with the port the kernel gave it
			addr, err := listenerAddr()
			if err != nil {
				answer(err)
			} else {
				say("ok " + addr)
			}
		case "exit":
			os.Exit(0)
		default:
			// The escape attempts (contain_escape_root_linux_test.go).
			answer(escapeCommand(f))
		}
	}
	os.Exit(0)
}

type helper struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
}

func (h *helper) do(t *testing.T, line string) string {
	t.Helper()
	fmt.Fprintln(h.in, line)
	ch := make(chan string, 1)
	go func() {
		if h.out.Scan() {
			ch <- h.out.Text()
		} else {
			ch <- "err helper gone"
		}
	}()
	select {
	case s := <-ch:
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("the helper did not answer %q", line)
		return ""
	}
}

// async sends one command and answers on the channel, for a command that blocks.
func (h *helper) async(line string) chan string {
	ch := make(chan string, 1)
	go func() {
		fmt.Fprintln(h.in, line)
		if h.out.Scan() {
			ch <- h.out.Text()
		} else {
			ch <- "err helper gone"
		}
	}()
	return ch
}

// socketsOf lists the sockets in pid's descriptor table, as "fd -> socket:[inode]".
func socketsOf(t *testing.T, pid int) []string {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot list pid %d's descriptors: %v", pid, err)
	}
	var out []string
	for _, e := range ents {
		if target, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && strings.HasPrefix(target, "socket:[") {
			out = append(out, e.Name()+" -> "+target)
		}
	}
	return out
}

// startHelper starts the process the containment tests contain, holding exactly the sockets the
// test gives it. The test process's descriptors are made close-on-exec first, as init makes its
// own before the agent starts: a runner that hands the test binary a socket without the flag (a
// VM runner's vsock to its host, for one) would hand it to the helper too, and Contain would
// then rightly refuse the helper over a family no route reaches, or cut an IP socket that is the
// runner's and not the helper's.
func startHelper(t *testing.T, peer string) *helper {
	t.Helper()
	if err := closeOnExecAboveStderr(); err != nil {
		t.Fatalf("cannot keep the test's descriptors out of the helper: %v", err)
	}
	cmd := exec.Command("/proc/self/exe", containHelperArg)
	cmd.Env = []string{"CONTAIN_PEER=" + peer}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	in, _ := cmd.StdinPipe()
	outp, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	h := &helper{cmd: cmd, in: in, out: bufio.NewScanner(outp)}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if !h.out.Scan() || h.out.Text() != "ready" {
		t.Fatalf("helper did not come up: %q", h.out.Text())
	}
	return h
}

// peerNS is the outside world: a namespace on a veth pair with a listener that counts what it gets.
type peerNS struct {
	ns        string // the namespace's name under /run/netns
	addr      string
	hostIf    string
	peerIf    string // the veth end inside the namespace
	accepted  atomic.Int32
	bytes     atomic.Int32
	datagrams atomic.Int32 // what reached the UDP socket on the same address and port
}

func startPeer(t *testing.T) *peerNS {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 (ip) to build the peer namespace")
	}
	name := fmt.Sprintf("wct%d", os.Getpid())
	p := &peerNS{ns: name, hostIf: "wctA" + fmt.Sprint(os.Getpid()%1000), peerIf: "wctB" + fmt.Sprint(os.Getpid()%1000)}
	peerIf := p.peerIf
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	run("link", "add", p.hostIf, "type", "veth", "peer", "name", peerIf)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", p.hostIf).Run() })
	run("link", "set", peerIf, "netns", name)
	run("addr", "add", "10.203.77.1/30", "dev", p.hostIf)
	run("link", "set", p.hostIf, "up")
	run("-n", name, "addr", "add", "10.203.77.2/30", "dev", peerIf)
	run("-n", name, "link", "set", peerIf, "up")
	run("-n", name, "link", "set", "lo", "up")

	lnCh := make(chan net.Listener, 1)
	pcCh := make(chan net.PacketConn, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies inside the peer namespace
		fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			lnCh <- nil
			return
		}
		// Closed once entered, so `ip netns del` in the cleanup really ends the namespace.
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			lnCh <- nil
			return
		}
		ln, err := net.Listen("tcp4", "10.203.77.2:0")
		if err != nil {
			lnCh <- nil
			pcCh <- nil
			return
		}
		pc, err := net.ListenPacket("udp4", ln.Addr().String())
		if err != nil {
			pc = nil
		}
		lnCh <- ln
		pcCh <- pc
	}()
	ln, pc := <-lnCh, <-pcCh
	if ln == nil || pc == nil {
		if ln != nil {
			ln.Close()
		}
		t.Fatal("could not listen in the peer namespace")
	}
	p.addr = ln.Addr().String()
	var mu sync.Mutex
	var conns []net.Conn
	ended := false
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		b := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
			p.datagrams.Add(1)
		}
	}()
	go func() {
		defer readers.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.accepted.Add(1)
			mu.Lock()
			if ended { // accepted as the test ended: nobody would close it
				mu.Unlock()
				c.Close()
				return
			}
			conns = append(conns, c)
			mu.Unlock()
			readers.Add(1)
			go func() {
				defer readers.Done()
				b := make([]byte, 64)
				for {
					n, err := c.Read(b)
					p.bytes.Add(int32(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	// The listener and every accepted connection are closed, and their goroutines waited for,
	// when the test ends: nothing of the peer outlives it.
	t.Cleanup(func() {
		ln.Close()
		pc.Close()
		mu.Lock()
		ended = true
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		readers.Wait()
	})
	return p
}

func needCgroup2(t *testing.T) string {
	t.Helper()
	mi, err := os.ReadFile(mountinfoPath)
	if err != nil {
		t.Skip("no mountinfo")
	}
	root, err := cgroup2Mount(string(mi))
	if err != nil {
		t.Skip("needs a cgroup v2 hierarchy")
	}
	probe := filepath.Join(root, "whisper-contain-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Skipf("the cgroup v2 hierarchy is not writable here: %v", err)
	}
	_ = os.Remove(probe)
	return root
}

// hostTUN brings up the containment's device and reads what passes its filter.
func hostTUN(t *testing.T) (*Namespace, chan []byte) {
	t.Helper()
	return hostTUNAs(t, tSelf)
}

// hostTUNAs is hostTUN for the agent self: what it reads is what would be encrypted to Whisper as
// that agent's traffic.
func hostTUNAs(t *testing.T, self netip.Addr) (*Namespace, chan []byte) {
	t.Helper()
	ns, sent, _ := hostTUNRaw(t, self)
	return ns, sent
}

// tapTUN hands a copy of every packet the device delivers to raw, before any filter sees it.
type tapTUN struct {
	tun.Device
	raw chan []byte
}

func (d *tapTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] > 0 {
			select {
			case d.raw <- append([]byte(nil), bufs[i][offset:offset+sizes[i]]...):
			default:
			}
		}
	}
	return n, err
}

// hostTUNRaw is hostTUNAs that also returns everything that entered the device at all (raw), which
// is what the kernel let in, before the tunnel's own filter.
func hostTUNRaw(t *testing.T, self netip.Addr) (*Namespace, chan []byte, chan []byte) {
	t.Helper()
	ns, err := CreateHostDevice(self)
	if err != nil {
		t.Fatalf("CreateHostDevice: %v", err)
	}
	t.Cleanup(ns.Close)
	t.Logf("tunnel device %s for %s: slot %d, generation %d, mark %#x, IPv4 carried %v %s", ns.host.Name, self,
		ns.host.Slot, ns.host.Gen, ns.host.Mark, ns.host.CarryV4, ns.host.V4Note)
	f := NewFilter(Policy{Self: self, Resolvers: []netip.Addr{tResolver}, NAT64: tPrefix})
	f.SetLive(true)
	raw := make(chan []byte, 64)
	ft := FilterTUN(&tapTUN{Device: ns.Dev, raw: raw}, f).(*filteredTUN)
	sent := make(chan []byte, 64)
	go func() {
		bufs := [][]byte{make([]byte, 4096)}
		sizes := []int{0}
		for {
			n, err := ft.Read(bufs, sizes, replyHeadroom)
			if err != nil {
				close(sent)
				return
			}
			if n == 1 && sizes[0] > 0 {
				sent <- append([]byte(nil), bufs[0][replyHeadroom:replyHeadroom+sizes[0]]...)
			}
		}
	}()
	return ns, sent, raw
}

func waitTCP6(t *testing.T, sent chan []byte, dst netip.Addr) []byte {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case p := <-sent:
			if p[0]>>4 == 6 && p[6] == protoTCP && addr16(p[24:40]) == dst {
				return p
			}
		case <-deadline:
			t.Fatalf("no TCP packet to %s reached the tunnel", dst)
		}
	}
}

func cgroupOf(t *testing.T, pid int) string {
	t.Helper()
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	p, _ := cgroupPath(string(b))
	return p
}

func TestContainARunningProcess(t *testing.T) {
	needRoot(t)
	root := needCgroup2(t)
	peer := startPeer(t)
	ns, sent := hostTUN(t)
	hr := ns.HostRoute()

	lo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lo.Close()
	go func() {
		for {
			c, err := lo.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// A descriptor of the runner's, as the test binary may inherit one: a socket of a family no
	// route reaches, open without close-on-exec. The helper must not get it.
	stray, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("cannot open the stray packet socket: %v", err)
	}
	defer unix.Close(stray)

	h := startHelper(t, peer.addr)
	pid := h.cmd.Process.Pid
	if socks := socketsOf(t, pid); len(socks) != 1 {
		t.Fatalf("the helper must hold only its connection to the peer, it holds %v", socks)
	}
	before := cgroupOf(t, pid)
	if got := h.do(t, "write"); got != "ok" {
		t.Fatalf("before containment the existing connection must work: %s", got)
	}
	waitFor(t, func() bool { return peer.bytes.Load() == 1 }, "the peer to get the first byte")

	c, err := Contain(pid, tSelf, *hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	released := false
	defer func() {
		if !released {
			c.Release()
		}
	}()
	t.Logf("contained %v: %s", c.Members, c.Sockets)
	if c.Sockets != (SocketReport{Cut: 1}) {
		t.Fatalf("the helper's one connection, to the peer, must be cut and nothing else touched, report %s", c.Sockets)
	}
	if cg := cgroupOf(t, pid); !strings.HasPrefix(cg, "/"+ContainParent+"/") {
		t.Fatalf("the process is in %s, not in the containment", cg)
	}

	// The existing connection is gone, and nothing more reaches the peer through it.
	if got := h.do(t, "write"); !strings.HasPrefix(got, "err") {
		t.Fatalf("a write on the cut connection must fail, got %s", got)
	}
	time.Sleep(300 * time.Millisecond)
	if n := peer.bytes.Load(); n != 1 {
		t.Fatalf("the peer received %d bytes; only the one sent before containment may arrive", n)
	}

	// A new connection leaves through the tunnel, from the /128.
	far := netip.MustParseAddr("2606:4700:4700::1111")
	pending := h.async("dial [" + far.String() + "]:443")
	syn := waitTCP6(t, sent, far)
	if src := addr16(syn[8:24]); src != tSelf {
		t.Fatalf("a new connection left from %s, not the /128 %s", src, tSelf)
	}
	<-pending // nothing answers the SYN here, so the helper's dial times out

	// The way out that is not Whisper's: the host route to the peer, and the same with the socket
	// bound to the host's interface. Neither reaches it.
	accepted := peer.accepted.Load()
	if got := h.do(t, "dial "+peer.addr); !strings.HasPrefix(got, "err") {
		t.Fatalf("a dial to the peer over the host route must be refused, got %s", got)
	}
	// The gate drops the SYN before it leaves; TCP does not report that to connect() and
	// retransmits until the dial times out, so the proof is that it fails and the peer saw nothing.
	if got := h.do(t, "binddial "+peer.hostIf+" "+peer.addr); !strings.HasPrefix(got, "err") {
		t.Fatalf("a socket bound to the host interface must not get through, got %s", got)
	}
	// A datagram sent the same way is refused at the socket, which shows it is the gate.
	if got := h.do(t, "bindudp "+peer.hostIf+" "+peer.addr); !strings.Contains(got, "operation not permitted") {
		t.Fatalf("a datagram bound to the host interface must be refused at egress (EPERM), got %s", got)
	}
	if n := peer.accepted.Load(); n != accepted {
		t.Fatalf("the peer accepted %d connections during containment", n-accepted)
	}

	// Loopback is not egress, and keeps working.
	if got := h.do(t, "dial "+lo.Addr().String()); got != "ok" {
		t.Fatalf("loopback must keep working, got %s", got)
	}

	// Release puts the process back exactly as it was.
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	released = true
	if cg := cgroupOf(t, pid); cg != before {
		t.Fatalf("after release the process is in %s, want %s", cg, before)
	}
	if _, err := os.Stat(filepath.Join(root, ContainParent, containCgroupName(tSelf))); !os.IsNotExist(err) {
		t.Fatalf("the containment's cgroup is still there: %v", err)
	}
	if got := h.do(t, "dial "+peer.addr); got != "ok" {
		t.Fatalf("after release the host route works again, got %s", got)
	}
}

func TestContainRefusesAPidThatExitsMidMove(t *testing.T) {
	needRoot(t)
	root := needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	pid := h.cmd.Process.Pid
	old := beforeMove
	beforeMove = func() { _ = h.cmd.Process.Kill(); _ = h.cmd.Wait() }
	defer func() { beforeMove = old }()
	_, err := Contain(pid, tSelf, *ns.HostRoute(), t.Logf)
	refusal(t, err, "exited before it could be contained")
	if _, serr := os.Stat(filepath.Join(root, ContainParent, containCgroupName(tSelf))); !os.IsNotExist(serr) {
		t.Fatalf("a refused containment left its cgroup behind: %v", serr)
	}
}

func TestContainRefusesAPrivilegedProcess(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	ns, _ := hostTUN(t)
	cmd := exec.Command("sleep", "30") // runs as root: it could move itself out
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep binary")
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_, err := Contain(cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	refusal(t, err, "uid 0")
}

func TestHostDeviceDialUsesTheContainedRoute(t *testing.T) {
	needRoot(t)
	ns, sent := hostTUN(t)
	far := netip.MustParseAddr("2606:4700:4700::1001")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := ns.DialContext(ctx, "tcp", "["+far.String()+"]:443"); err == nil {
			c.Close()
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	syn := waitTCP6(t, sent, far)
	if src := addr16(syn[8:24]); src != tSelf {
		t.Fatalf("the marked dial left from %s, not %s", src, tSelf)
	}
	// Closed, the device's way out is refused at once, with the dial above still in flight.
	ns.Close()
	if _, err := ns.DialContext(context.Background(), "tcp", "["+far.String()+"]:443"); !errors.Is(err, errNamespaceClosed) {
		t.Fatalf("a dial through a closed host device must be refused, got %v", err)
	}
}

// The host dial binds the device's index, not its name: with the name of a device that exists and
// an index nothing holds, the dial reaches nothing, and with that device's own index the same
// dial connects (the control, so the failure is the index and nothing else).
func TestHostDialBindsTheIndexNotTheName(t *testing.T) {
	needRoot(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface here")
	}
	open := func(fn func() error) error { return fn() }
	gate, err := attachRootGate(markFor(1), lo.Index, 1)
	if err != nil {
		t.Skipf("no gate on the root cgroup here: %v", err)
	}
	defer gate.detach()
	dial := func(index int) error {
		hr := HostRoute{Name: "lo", Index: index, Gen: 1, Mark: markFor(1), CarryV4: true, gate: gate}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := hr.dial(ctx, "tcp", ln.Addr().String(), "127.0.0.1", open)
		if c != nil {
			c.Close()
		}
		return err
	}
	if err := dial(lo.Index); err != nil {
		t.Fatalf("control: bound to lo's own index the dial must connect, got %v", err)
	}
	if err := dial(1 << 30); err == nil {
		t.Fatal("bound to an index nothing holds, the dial connected: it was bound by name")
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
