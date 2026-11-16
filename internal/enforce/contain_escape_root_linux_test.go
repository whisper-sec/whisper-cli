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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// contain_escape_root_linux_test.go is the escape review's attempts, each run as a real process
// against a real containment as root: a process that tries to speak as another agent, or to get
// a socket past the sweep, or a process outside any containment that tries to use its tunnel.
// Each test fails while the way out is open.

// tSelf2 is a second agent, for a containment that follows another one on the same host.
var tSelf2 = netip.MustParseAddr("2a04:2a01:0:1::43")

// The helper's escape state. It lives in the helper process only.
var (
	keptU4, keptU6 = -1, -1   // datagram sockets made on request (inside a containment, if there is one)
	loHeld         []loSocket // sockets connected to loopback before the containment
	parkedEnd      = -1       // the receiving end of a socket pair a socket is parked in
	agentU         = -1       // a datagram socket made inside the containment, connected from the /128
	listener       = -1       // a TCP listener made on request
	privCmd        chan chan error
	uring          *uringState
)

type loSocket struct {
	fd    int
	proto string
}

// listenerAddr is the address the helper's listener holds, its port included: the helper binds
// port 0 and the kernel's choice is read back here, so the number is never let go between a pick
// and the bind.
func listenerAddr() (string, error) {
	if listener < 0 {
		return "", errors.New("no listener (listen first)")
	}
	sa, err := unix.Getsockname(listener)
	if err != nil {
		return "", err
	}
	in4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return "", fmt.Errorf("the listener is not IPv4: %T", sa)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(in4.Addr), uint16(in4.Port)).String(), nil
}

// helperListen has the helper listen on the host's tunnel address at a port the kernel picks
// ("defer" holds a connection as a request until its first data) and returns that address.
func helperListen(t *testing.T, h *helper, mode string) string {
	t.Helper()
	cmd := "listen 10.203.77.1:0"
	if mode != "" {
		cmd += " " + mode
	}
	if got := h.do(t, cmd); got != "ok" {
		t.Fatalf("listen: %s", got)
	}
	got := h.do(t, "listenaddr")
	addr, ok := strings.CutPrefix(got, "ok ")
	if !ok {
		t.Fatalf("listenaddr: %s", got)
	}
	return addr
}

// escapeCommand runs one of the helper's escape commands and returns its outcome.
func escapeCommand(f []string) error {
	switch f[0] {
	case "udpopen":
		var err error
		if keptU6 < 0 {
			keptU6, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				keptU6 = -1
				return err
			}
		}
		if keptU4 < 0 {
			keptU4, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				keptU4 = -1
				return err
			}
		}
		return nil
	case "udpsend": // udpsend <addr:port> [ifindex]
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		ifx := 0
		if len(f) > 2 {
			ifx, _ = strconv.Atoi(f[2])
		}
		fd := keptU6
		if ap.Addr().Is4() {
			fd = keptU4
		}
		if fd < 0 {
			return errors.New("no kept socket (udpopen first)")
		}
		return sendDatagram(fd, ap, ifx)
	case "udpunbind": // udpunbind <addr:port>: disconnect the kept socket of that family, which drops a device binding, and send
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		fd := keptU6
		if ap.Addr().Is4() {
			fd = keptU4
		}
		if err := disconnect(fd); err != nil {
			return fmt.Errorf("disconnect: %w", err)
		}
		return unix.Sendto(fd, []byte("x"), 0, sockaddr(ap))
	case "listen": // listen <addr:port>: a TCP listener, made now, that accepts nothing until asked
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if len(f) > 2 && f[2] == "defer" {
			// A connection waits as a request (SYN_RECV) until its first data, not in the accept queue.
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 30); err != nil {
				return err
			}
		}
		if err := unix.Bind(fd, sockaddr(ap)); err != nil {
			return err
		}
		if err := unix.Listen(fd, 8); err != nil {
			return err
		}
		listener = fd
		return nil
	case "acceptwrite": // take a waiting connection, if there is one within a second, and write to it
		pfd := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		if n, err := unix.Poll(pfd, 1000); err != nil || n == 0 {
			return errors.New("no connection waiting")
		}
		c, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
		if err != nil {
			return err
		}
		_, err = unix.Write(c, []byte("x"))
		return err
	case "udpconnect": // udpconnect <addr:port>: connect the kept datagram socket of that family
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		fd := keptU6
		if ap.Addr().Is4() {
			fd = keptU4
		}
		return unix.Connect(fd, sockaddr(ap))
	case "agentconn": // agentconn <addr:port>: a datagram socket connected now (inside the containment: from the /128)
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		fam := unix.AF_INET6
		if ap.Addr().Is4() {
			fam = unix.AF_INET
		}
		fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Connect(fd, sockaddr(ap)); err != nil {
			return err
		}
		agentU = fd
		sa, _ := unix.Getsockname(fd)
		if a := saAddr(sa); a != tSelf {
			return fmt.Errorf("the connected socket's source is %s, not the /128", a)
		}
		return nil
	case "agentwrite":
		if agentU < 0 {
			return errors.New("no agent socket (agentconn first)")
		}
		_, err := unix.Write(agentU, []byte("x"))
		return err
	case "lohold": // lohold <tcp loopback addr> <udp loopback addr>
		tap, err1 := netip.ParseAddrPort(f[1])
		uap, err2 := netip.ParseAddrPort(f[2])
		if err1 != nil || err2 != nil {
			return errors.New("lohold <tcp> <udp>")
		}
		tfd, err := rawDialTCP(tap, 2*time.Second)
		if err != nil {
			return fmt.Errorf("tcp: %w", err)
		}
		ufd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		if err := unix.Connect(ufd, sockaddr(uap)); err != nil {
			return fmt.Errorf("udp: %w", err)
		}
		loHeld = append(loHeld, loSocket{tfd, "tcp"}, loSocket{ufd, "udp"})
		return nil
	case "loredial": // loredial <addr:port>: disconnect every loopback socket and point it outward
		ap, err := netip.ParseAddrPort(f[1])
		if err != nil {
			return err
		}
		var out []string
		for _, s := range loHeld {
			if err := disconnect(s.fd); err != nil {
				out = append(out, s.proto+" disconnect: "+err.Error())
				continue
			}
			if s.proto == "tcp" {
				err = connectWithin(s.fd, ap, 2*time.Second)
			} else if err = unix.Connect(s.fd, sockaddr(ap)); err == nil {
				_, err = unix.Write(s.fd, []byte("x"))
			}
			out = append(out, fmt.Sprintf("%s: %v", s.proto, err))
		}
		return errors.New(strings.Join(out, "; ")) // always "err ...": the peer's counters are the verdict
	case "park": // a second connection to the peer, put in flight on a socket pair of the helper's own and closed
		ap := netip.MustParseAddrPort(os.Getenv("CONTAIN_PEER"))
		fd, err := rawDialTCP(ap, 2*time.Second)
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
		parkedEnd = sp[1]
		return nil
	case "unpark": // take the parked socket back and write through it
		if parkedEnd < 0 {
			return errors.New("nothing parked")
		}
		b, oob := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
		_, oobn, _, _, err := unix.Recvmsg(parkedEnd, b, oob, unix.MSG_CMSG_CLOEXEC)
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
		_, err = unix.Write(fds[0], []byte("x"))
		return err
	case "privconn": // a second connection to the peer, held only in one thread's own descriptor table
		ready := make(chan error, 1)
		privCmd = make(chan chan error)
		go privateTableThread(netip.MustParseAddrPort(os.Getenv("CONTAIN_PEER")), ready, privCmd)
		return <-ready
	case "privwrite":
		if privCmd == nil {
			return errors.New("no private table (privconn first)")
		}
		res := make(chan error, 1)
		privCmd <- res
		return <-res
	case "uringpark": // a second connection to the peer, registered with io_uring and then closed
		ap := netip.MustParseAddrPort(os.Getenv("CONTAIN_PEER"))
		fd, err := rawDialTCP(ap, 2*time.Second)
		if err != nil {
			return err
		}
		u, err := newUring(fd)
		unix.Close(fd)
		if err != nil {
			return err
		}
		uring = u
		return nil
	case "uringsend":
		if uring == nil {
			return errors.New("no ring (uringpark first)")
		}
		return uring.sendFixed0([]byte("x"))
	}
	return residueCommand(f) // contain_residue_root_linux_test.go
}

func sockaddr(ap netip.AddrPort) unix.Sockaddr {
	if ap.Addr().Is4() {
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
}

// sendDatagram sends one datagram; with ifx it names that device in the packet-info option, which
// an unprivileged process may set on any datagram it sends.
func sendDatagram(fd int, ap netip.AddrPort, ifx int) error {
	if ifx == 0 {
		return unix.Sendto(fd, []byte("x"), 0, sockaddr(ap))
	}
	var oob []byte
	if ap.Addr().Is4() {
		pi := unix.Inet4Pktinfo{Ifindex: int32(ifx)}
		oob = cmsg(unix.IPPROTO_IP, unix.IP_PKTINFO, unsafe.Slice((*byte)(unsafe.Pointer(&pi)), unsafe.Sizeof(pi)))
	} else {
		pi := unix.Inet6Pktinfo{Ifindex: uint32(ifx)}
		oob = cmsg(unix.IPPROTO_IPV6, unix.IPV6_PKTINFO, unsafe.Slice((*byte)(unsafe.Pointer(&pi)), unsafe.Sizeof(pi)))
	}
	return unix.Sendmsg(fd, []byte("x"), oob, sockaddr(ap), 0)
}

func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

// rawDialTCP connects a TCP socket the runtime knows nothing about, so it stays in whichever
// descriptor table made it.
func rawDialTCP(ap netip.AddrPort, within time.Duration) (int, error) {
	fam := unix.AF_INET6
	if ap.Addr().Is4() {
		fam = unix.AF_INET
	}
	fd, err := unix.Socket(fam, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := connectWithin(fd, ap, within); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// connectWithin connects fd to ap, giving up after within, and leaves fd blocking.
func connectWithin(fd int, ap netip.AddrPort, within time.Duration) error {
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	defer unix.SetNonblock(fd, false)
	err := unix.Connect(fd, sockaddr(ap))
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EINPROGRESS) {
		return err
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	n, err := unix.Poll(pfd, int(within/time.Millisecond))
	if err != nil {
		return err
	}
	if n == 0 {
		return unix.ETIMEDOUT
	}
	soerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return err
	}
	if soerr != 0 {
		return unix.Errno(soerr)
	}
	return nil
}

// disconnect is connect(AF_UNSPEC): TCP and UDP both return the socket to unconnected, and both
// forget a source address the program never bound.
func disconnect(fd int) error {
	var sa [16]byte // a sockaddr whose family is AF_UNSPEC (0)
	_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
	if e != 0 {
		return e
	}
	return nil
}

// privateTableThread gives its thread a descriptor table of its own, opens a connection in it and
// writes on request. Nothing else in the process can see that descriptor.
func privateTableThread(ap netip.AddrPort, ready chan error, cmds chan chan error) {
	runtime.LockOSThread() // never unlocked: the thread and its table end with this goroutine
	if err := unix.Unshare(unix.CLONE_FILES); err != nil {
		ready <- err
		return
	}
	fd, err := rawDialTCP(ap, 2*time.Second)
	if err != nil {
		ready <- err
		return
	}
	ready <- nil
	for res := range cmds {
		_, err := unix.Write(fd, []byte("x"))
		res <- err
	}
}

// uringState is a minimal io_uring: one fixed file (index 0) and one send at a time.
type uringState struct {
	fd                int
	sq, sqes          []byte
	sqHead, sqTail    *uint32
	sqMask            uint32
	sqArray           []uint32
	cqHead, cqTail    *uint32
	cqMask            uint32
	cqes              []byte
	sqEntries, cqOffs uint32
}

type uringParams struct {
	SqEntries, CqEntries, Flags, SqThreadCPU, SqThreadIdle, Features, WqFd uint32
	Resv                                                                   [3]uint32
	SqOff                                                                  struct {
		Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
		UserAddr                                                        uint64
	}
	CqOff struct {
		Head, Tail, RingMask, RingEntries, Overflow, Cqes, Flags, Resv1 uint32
		UserAddr                                                        uint64
	}
}

func newUring(sock int) (*uringState, error) {
	var p uringParams
	rfd, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 4, uintptr(unsafe.Pointer(&p)), 0)
	if e != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", e)
	}
	u := &uringState{fd: int(rfd), sqEntries: p.SqEntries}
	fds := []int32{int32(sock)}
	if _, _, e := unix.Syscall6(unix.SYS_IO_URING_REGISTER, rfd, 2 /* IORING_REGISTER_FILES */, uintptr(unsafe.Pointer(&fds[0])), 1, 0, 0); e != 0 {
		unix.Close(int(rfd))
		return nil, fmt.Errorf("io_uring_register: %w", e)
	}
	sqSize := int(p.SqOff.Array + p.SqEntries*4)
	cqSize := int(p.CqOff.Cqes + p.CqEntries*16)
	if cqSize > sqSize {
		sqSize = cqSize // IORING_FEAT_SINGLE_MMAP: one mapping holds both rings
	}
	var err error
	if u.sq, err = unix.Mmap(int(rfd), 0, sqSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		return nil, err
	}
	if u.sqes, err = unix.Mmap(int(rfd), 0x10000000, int(p.SqEntries*64), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE); err != nil {
		return nil, err
	}
	u.sqHead = (*uint32)(unsafe.Pointer(&u.sq[p.SqOff.Head]))
	u.sqTail = (*uint32)(unsafe.Pointer(&u.sq[p.SqOff.Tail]))
	u.sqMask = *(*uint32)(unsafe.Pointer(&u.sq[p.SqOff.RingMask]))
	u.sqArray = unsafe.Slice((*uint32)(unsafe.Pointer(&u.sq[p.SqOff.Array])), p.SqEntries)
	u.cqHead = (*uint32)(unsafe.Pointer(&u.sq[p.CqOff.Head]))
	u.cqTail = (*uint32)(unsafe.Pointer(&u.sq[p.CqOff.Tail]))
	u.cqMask = *(*uint32)(unsafe.Pointer(&u.sq[p.CqOff.RingMask]))
	u.cqes = u.sq[p.CqOff.Cqes:]
	return u, nil
}

// sendFixed0 sends b on fixed file 0 and waits for the answer.
func (u *uringState) sendFixed0(b []byte) error {
	tail := atomic.LoadUint32(u.sqTail)
	idx := tail & u.sqMask
	sqe := u.sqes[idx*64 : idx*64+64]
	clear(sqe)
	sqe[0] = 26 // IORING_OP_SEND
	sqe[1] = 1  // IOSQE_FIXED_FILE
	*(*int32)(unsafe.Pointer(&sqe[4])) = 0
	*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(&b[0])))
	*(*uint32)(unsafe.Pointer(&sqe[24])) = uint32(len(b))
	u.sqArray[idx] = idx
	atomic.StoreUint32(u.sqTail, tail+1)
	_, _, e := unix.Syscall6(unix.SYS_IO_URING_ENTER, uintptr(u.fd), 1, 1, 1 /* IORING_ENTER_GETEVENTS */, 0, 0)
	runtime.KeepAlive(b)
	if e != 0 {
		return fmt.Errorf("io_uring_enter: %w", e)
	}
	head := atomic.LoadUint32(u.cqHead)
	if head == atomic.LoadUint32(u.cqTail) {
		return errors.New("no completion")
	}
	cqe := u.cqes[(head&u.cqMask)*16:]
	res := *(*int32)(unsafe.Pointer(&cqe[8]))
	atomic.StoreUint32(u.cqHead, head+1)
	if res < 0 {
		return unix.Errno(-res)
	}
	return nil
}

// asNobody runs fn on a thread of its own that has given up root for uid and gid 65534, and so
// every capability. The thread is discarded afterwards.
func asNobody(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends unprivileged and is discarded
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, 65534, 65534, 65534); e != 0 {
			t.Errorf("setresgid: %v", e)
			return
		}
		if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, 65534, 65534, 65534); e != 0 {
			t.Errorf("setresuid: %v", e)
			return
		}
		fn()
	}()
	<-done
}

// describe is a packet's family, addresses and protocol, for a failure message.
func describe(p []byte) string {
	switch {
	case len(p) >= 20 && p[0]>>4 == 4:
		return fmt.Sprintf("IPv4 %s -> %s proto %d", netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), p[9])
	case len(p) >= 40 && p[0]>>4 == 6:
		return fmt.Sprintf("IPv6 %s -> %s next header %d", addr16(p[8:24]), addr16(p[24:40]), p[6])
	}
	return fmt.Sprintf("% x", p)
}

// noDatagramWithin fails the test if a UDP packet reaches the tunnel within d (sent, or raw when
// the question is what the device let in at all). The tunnel's own TCP (a control dial's
// retransmissions) is not what is being watched.
func noDatagramWithin(t *testing.T, sent chan []byte, d time.Duration, who string) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case p, ok := <-sent:
			if !ok {
				return
			}
			if (p[0]>>4 == 6 && len(p) >= 40 && p[6] == 17) || (p[0]>>4 == 4 && len(p) >= 20 && p[9] == 17) {
				t.Fatalf("%s entered the tunnel device: %s", who, describe(p))
			}
		case <-deadline:
			return
		}
	}
}

// controlDial proves a tunnel's reader is alive: a dial of the device's own reaches it from self.
func controlDial(t *testing.T, ns *Namespace, sent chan []byte, self netip.Addr) {
	t.Helper()
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
	if syn := waitTCP6(t, sent, far); addr16(syn[8:24]) != self {
		t.Fatalf("the control dial left from %s, not %s", addr16(syn[8:24]), self)
	}
}

// A process that was contained and then released keeps the sockets it made inside. When the next
// containment on the host takes the same slot, none of them may reach its tunnel: not plainly, and
// not by naming its device in the packet-info option. Unconnected UDP is the case that leaked.
func TestAReleasedProcessNeverSpeaksAsTheNextAgentOnItsSlot(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	nsA, _ := hostTUN(t)
	hrA := *nsA.HostRoute()
	h := startHelper(t, peer.addr)
	c, err := Contain(h.cmd.Process.Pid, tSelf, hrA, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if got := h.do(t, "udpopen"); got != "ok" {
		c.Release()
		t.Fatalf("the helper could not open its datagram sockets inside the containment: %s", got)
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	nsA.Close() // A's tunnel goes, as the CLI's does once it has released the process

	nsB, sentB, rawB := hostTUNRaw(t, tSelf2)
	hrB := nsB.HostRoute()
	if hrB.Slot != hrA.Slot {
		t.Fatalf("containment B took slot %d, not A's %d, so this host cannot show the reuse", hrB.Slot, hrA.Slot)
	}
	controlDial(t, nsB, sentB, tSelf2)

	idx := strconv.Itoa(hrB.Index)
	for _, cmd := range []string{
		"udpsend [2606:4700:4700::1111]:443", "udpsend 198.51.100.7:443",
		"udpsend [2606:4700:4700::1111]:443 " + idx, "udpsend 198.51.100.7:443 " + idx,
	} {
		t.Logf("released process, %s: %s", cmd, h.do(t, cmd))
	}
	noDatagramWithin(t, rawB, time.Second, "a datagram the released process sent from a socket it made in containment A")
}

// A process that was never contained, unprivileged, may bind an unbound socket to any device and
// name any device in the packet-info option. Neither may put its traffic into a containment's
// tunnel: only the containment's own sockets enter it.
func TestOnlyTheContainmentsOwnSocketsEnterItsTunnel(t *testing.T) {
	needRoot(t)
	ns, sent, raw := hostTUNRaw(t, tSelf)
	hr := ns.HostRoute()
	controlDial(t, ns, sent, tSelf)
	far4 := netip.MustParseAddrPort("198.51.100.7:443")
	far6 := netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	asNobody(t, func() {
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			dst := far4
			if fam == unix.AF_INET6 {
				dst = far6
			}
			if fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
				berr := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, hr.Name)
				t.Logf("unprivileged, family %d, bound to %s (%v): %v", fam, hr.Name, berr, sendDatagram(fd, dst, 0))
				unix.Close(fd)
			}
			if fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
				t.Logf("unprivileged, family %d, naming %s in packet info: %v", fam, hr.Name, sendDatagram(fd, dst, hr.Index))
				unix.Close(fd)
			}
		}
	})
	noDatagramWithin(t, raw, time.Second, "a datagram of an unprivileged process outside the containment")
}

// A socket connected to loopback is kept working through a containment, and it was made before it,
// so neither of the containment's programs sees it. Disconnected and pointed outward, it must
// reach nothing.
func TestAKeptLoopbackSocketCannotBeTurnedOutward(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	lt, lu := loopbackHolders(t)
	h := startHelper(t, peer.addr)
	if got := h.do(t, "lohold "+lt+" "+lu); got != "ok" {
		t.Fatalf("the helper could not connect to loopback: %s", got)
	}
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	if c.Sockets.Kept != 2 {
		t.Fatalf("the two loopback sockets must be kept, report %s", c.Sockets)
	}
	acc, dg := peer.accepted.Load(), peer.datagrams.Load()
	t.Logf("the helper turned its loopback sockets outward: %s", h.do(t, "loredial "+peer.addr))
	time.Sleep(300 * time.Millisecond)
	if n := peer.accepted.Load() - acc; n != 0 {
		t.Fatalf("a kept loopback TCP socket reconnected to the peer outside the tunnel (%d connection)", n)
	}
	if n := peer.datagrams.Load() - dg; n != 0 {
		t.Fatalf("a kept loopback UDP socket sent %d datagram to the peer outside the tunnel", n)
	}
}

// loopbackHolders listens on loopback for a TCP connection it keeps open and for datagrams, and
// returns both addresses.
func loopbackHolders(t *testing.T) (tcp, udp string) {
	t.Helper()
	tfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(tfd) })
	ufd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(ufd) })
	lo := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Bind(tfd, lo); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(tfd, 4); err != nil { // the kernel completes the handshake; nobody accepts
		t.Fatal(err)
	}
	if err := unix.Bind(ufd, lo); err != nil {
		t.Fatal(err)
	}
	name := func(fd int) string {
		sa, _ := unix.Getsockname(fd)
		return fmt.Sprintf("127.0.0.1:%d", sa.(*unix.SockaddrInet4).Port)
	}
	return name(tfd), name(ufd)
}

// A socket parked in flight (sent over a socket pair the process owns, then closed) is in no
// descriptor table, so the sweep cannot reach it. Received back after the thaw, it is a socket
// from before the containment that neither program sees. The containment must refuse.
func TestASocketParkedInFlightRefusesTheContainment(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	if got := h.do(t, "park"); got != "ok" {
		t.Fatalf("the helper could not park a socket: %s", got)
	}
	waitFor(t, func() bool { return peer.accepted.Load() == 2 }, "the parked connection")
	before := cgroupOf(t, h.cmd.Process.Pid)
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err == nil {
		defer c.Release()
		b := peer.bytes.Load()
		got := h.do(t, "unpark")
		time.Sleep(300 * time.Millisecond)
		t.Fatalf("the containment did not see the socket in flight (report %s); after the thaw it came back (%s) "+
			"and the peer received %d byte through it", c.Sockets, got, peer.bytes.Load()-b)
	}
	refusal(t, err, "in flight")
	if cg := cgroupOf(t, h.cmd.Process.Pid); cg != before {
		t.Fatalf("a refused containment moved the process to %s", cg)
	}
}

// A thread that keeps a descriptor table of its own holds a socket that the process's table does
// not show. The containment must reach it, or refuse.
func TestASocketInAThreadsOwnTableIsReachedOrRefused(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	if got := h.do(t, "privconn"); got != "ok" {
		t.Fatalf("the helper could not open a connection in a table of its own: %s", got)
	}
	waitFor(t, func() bool { return peer.accepted.Load() == 2 }, "the private connection")
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		refusal(t, err, "descriptor table of its own")
		t.Logf("refused, as this kernel cannot reach another thread's table: %v", err)
		return
	}
	defer c.Release()
	b := peer.bytes.Load()
	got := h.do(t, "privwrite")
	time.Sleep(300 * time.Millisecond)
	if n := peer.bytes.Load() - b; n != 0 || c.Sockets != (SocketReport{Cut: 2}) {
		t.Fatalf("the socket in the thread's own table was not cut (report %s); a write through it (%s) brought the peer %d byte",
			c.Sockets, got, n)
	}
}

// A socket registered with io_uring and closed lives on as a fixed file, outside every descriptor
// table, and the ring can still send through it. The containment must refuse.
func TestASocketRegisteredWithIoUringRefusesTheContainment(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	if got := h.do(t, "uringpark"); got != "ok" {
		if strings.Contains(got, "io_uring_setup") {
			t.Skipf("io_uring is not available here: %s", got)
		}
		t.Fatalf("the helper could not register a socket with io_uring: %s", got)
	}
	waitFor(t, func() bool { return peer.accepted.Load() == 2 }, "the registered connection")
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err == nil {
		defer c.Release()
		b := peer.bytes.Load()
		got := h.do(t, "uringsend")
		time.Sleep(300 * time.Millisecond)
		t.Fatalf("the containment did not see the socket registered with io_uring (report %s); after the thaw the ring "+
			"sent through it (%s) and the peer received %d byte", c.Sockets, got, peer.bytes.Load()-b)
	}
	refusal(t, err, "io_uring")
}

// The sweep pins a socket to the route's device by its index, never by whichever device holds the
// route's name: here the name is loopback's and the index the tunnel's.
func TestTheSweepPinsByIndexNotByName(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	hr := *ns.HostRoute()
	h := startHelper(t, peer.addr)
	if got := h.do(t, "udpopen"); got != "ok" { // made before the containment: unconnected, so pinned
		t.Fatalf("udpopen: %s", got)
	}
	misnamed := hr
	misnamed.Name = "lo"
	c, err := Contain(h.cmd.Process.Pid, tSelf, misnamed, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	if c.Sockets.Pinned != 2 {
		t.Fatalf("the two unconnected sockets must be pinned, report %s", c.Sockets)
	}
	for _, s := range socketsOf(t, h.cmd.Process.Pid) {
		fd, _ := strconv.Atoi(strings.Fields(s)[0])
		dup, err := getfd(h.cmd.Process.Pid, fd)
		if err != nil {
			t.Fatalf("getfd: %v", err)
		}
		dom, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_DOMAIN)
		typ, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_TYPE)
		bound, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
		unix.Close(dup)
		if typ == unix.SOCK_DGRAM && (dom == unix.AF_INET || dom == unix.AF_INET6) && bound != hr.Index {
			t.Fatalf("a pinned socket is bound to index %d, not the route's %d", bound, hr.Index)
		}
	}
}

// A datagram socket made before the containment is pinned to the tunnel, and pinning is not enough
// for UDP: connect(AF_UNSPEC) drops the binding without privilege, and for IPv4 the packet-info
// option overrides it. Marked, the socket is held by the gate on the root cgroup instead, whatever
// is done to it: neither way reaches the peer outside the tunnel.
func TestAPinnedDatagramSocketStaysHeldWhateverItDoes(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	veth, err := net.InterfaceByName(peer.hostIf)
	if err != nil {
		t.Fatal(err)
	}
	h := startHelper(t, peer.addr)
	if got := h.do(t, "udpopen"); got != "ok" { // before the containment: unconnected, so pinned
		t.Fatalf("udpopen: %s", got)
	}
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	if c.Sockets.Pinned != 2 {
		t.Fatalf("the two unconnected sockets must be pinned, report %s", c.Sockets)
	}
	dg := peer.datagrams.Load()
	t.Logf("packet info naming %s: %s", peer.hostIf, h.do(t, "udpsend "+peer.addr+" "+strconv.Itoa(veth.Index)))
	t.Logf("disconnected, then sent: %s", h.do(t, "udpunbind "+peer.addr))
	time.Sleep(300 * time.Millisecond)
	if n := peer.datagrams.Load() - dg; n != 0 {
		t.Fatalf("a pinned datagram socket reached the peer outside the tunnel (%d datagram)", n)
	}
}

// Release gives a socket the containment touched back its mark and binding, exactly as they were.
func TestReleaseGivesBackTheMarkAndTheBinding(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	hr := *ns.HostRoute()
	h := startHelper(t, peer.addr)
	if got := h.do(t, "udpopen"); got != "ok" {
		t.Fatalf("udpopen: %s", got)
	}
	pid := h.cmd.Process.Pid
	opts := func() (marks, binds []int) {
		for _, s := range socketsOf(t, pid) {
			fd, _ := strconv.Atoi(strings.Fields(s)[0])
			dup, err := getfd(pid, fd)
			if err != nil {
				t.Fatalf("getfd: %v", err)
			}
			if typ, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_TYPE); typ == unix.SOCK_DGRAM {
				m, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK)
				b, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
				marks, binds = append(marks, m), append(binds, b)
			}
			unix.Close(dup)
		}
		return marks, binds
	}
	c, err := Contain(pid, tSelf, hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	marks, binds := opts()
	for i := range marks {
		if uint32(marks[i]) != hr.Mark || binds[i] != hr.Index {
			c.Release()
			t.Fatalf("contained, a pinned socket carries mark %#x bound to %d, want %#x on %d", marks[i], binds[i], hr.Mark, hr.Index)
		}
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	marks, binds = opts()
	for i := range marks {
		if marks[i] != 0 || binds[i] != 0 {
			t.Fatalf("released, a socket still carries mark %#x bound to %d", marks[i], binds[i])
		}
	}
}

// A socket the process made inside the containment and connected from the /128 cannot outlive it:
// release ends it, so it never later leaves the host's own uplink with the agent's address.
func TestReleaseEndsTheAgentsOwnConnections(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if got := h.do(t, "agentconn [2606:4700:4700::1111]:443"); got != "ok" {
		c.Release()
		t.Fatalf("agentconn: %s", got)
	}
	if got := h.do(t, "agentwrite"); got != "ok" {
		c.Release()
		t.Fatalf("contained, the agent's own socket must work: %s", got)
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	if got := h.do(t, "agentwrite"); !strings.Contains(got, "broken pipe") {
		t.Fatalf("released, a socket sourced from the /128 must be ended (EPIPE), got %s", got)
	}
}

// RemoveStaleRules takes only the dead containment's own rules: never the rule of the live one that
// holds the slot now, with or without a device on it.
func TestStaleRuleRemovalTakesOnlyTheDeadContainmentsRules(t *testing.T) {
	needRoot(t)
	ns, _ := hostTUNAs(t, tSelf2)
	hr := ns.HostRoute()
	// Generation 1 is long gone on any host that has made a device since its counter started, and is
	// never past the counter, which a live generation above it would be (another counter).
	dead := markFor(1)
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.rule(unix.RTM_NEWRULE, unix.AF_INET6, hr.Prio, dead, hr.Table); err != nil {
		t.Fatalf("plant a stale rule: %v", err)
	}
	RemoveStaleRules(hr.Slot, dead, netip.MustParseAddr("2a04:2a01:0:1::99"))
	rules := ipRules(t)
	if strings.Contains(rules, fmt.Sprintf("fwmark %#x", dead)) {
		t.Fatalf("the dead containment's rule survived:\n%s", rules)
	}
	if !strings.Contains(rules, fmt.Sprintf("fwmark %#x", hr.Mark)) {
		t.Fatalf("removing a dead containment's rules took the live one's (slot %d, mark %#x):\n%s", hr.Slot, hr.Mark, rules)
	}
}

// A new device clears whatever a killed holder of its slot left at its priority and table.
func TestANewDeviceClearsItsSlotsLeftovers(t *testing.T) {
	needRoot(t)
	dead := markFor(1)
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	t.Cleanup(func() { deleteRules(hostRulePrio, hostTableBase, dead, hostMarkMask) })
	// slot 0 is the lowest free name on a host with no containment, as this test's namespace has
	if err := r.rule(unix.RTM_NEWRULE, unix.AF_INET6, hostRulePrio, dead, hostTableBase); err != nil {
		t.Fatalf("plant a leftover: %v", err)
	}
	// A killed containment of the same agent on slot 9 left its address rules: from the /128 they
	// would look up an empty table and refuse, ahead of anything this one installs on a higher slot.
	far := uint32(9)
	t.Cleanup(func() { removeAgentAddrRulesAt(tSelf, hostRulePrio+far) })
	if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ruleBodyFrom(unix.AF_INET6, hostRulePrio+far, tSelf, hostTableBase+far)); err != nil {
		t.Fatalf("plant an address leftover: %v", err)
	}
	if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ruleBodyProhibit(unix.AF_INET6, hostRulePrio+far, tSelf)); err != nil {
		t.Fatalf("plant a prohibit leftover: %v", err)
	}
	ns, _ := hostTUN(t)
	if ns.HostRoute().Slot != 0 {
		t.Skipf("the device took slot %d; this host already holds slot 0", ns.HostRoute().Slot)
	}
	rules := ipRules(t)
	if strings.Contains(rules, fmt.Sprintf("fwmark %#x", dead)) {
		t.Fatalf("the leftover of slot 0 survived a new device on it:\n%s", rules)
	}
	if strings.Contains(rules, fmt.Sprintf("%d:", hostRulePrio+far)) {
		t.Fatalf("a killed containment's address rules for this agent survived a new device for it:\n%s", rules)
	}
}

func ipRules(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("ip", "-6", "rule", "show").CombinedOutput()
	if err != nil {
		t.Skipf("needs iproute2 to read the rules: %v %s", err, out)
	}
	return string(out)
}

// The mark is no secret (`ip rule` shows it to anybody) and, since Linux 5.17, CAP_NET_RAW may set
// it: on a stock distribution mtr-packet holds that for every user. A socket that is neither in the
// containment's cgroup nor adopted by it never enters the tunnel, whatever mark it carries and
// however it is bound. Root runs it here, which can set the mark directly, as such a program would.
func TestAMarkSetByAnotherSocketNeverEntersTheTunnel(t *testing.T) {
	needRoot(t)
	ns, sent, raw := hostTUNRaw(t, tSelf)
	hr := ns.HostRoute()
	controlDial(t, ns, sent, tSelf) // this command's own dial is adopted, and goes through
	for _, dst := range []string{"[2606:4700:4700::1111]:443", "198.51.100.7:443"} {
		ap := netip.MustParseAddrPort(dst)
		fam := unix.AF_INET6
		if ap.Addr().Is4() {
			fam = unix.AF_INET
		}
		fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			continue
		}
		merr := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(hr.Mark))
		berr := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, hr.Index)
		t.Logf("a socket outside the containment, marked (%v) and bound to %s (%v), to %s: %v", merr, hr.Name, berr, dst,
			unix.Sendto(fd, []byte("x"), 0, sockaddr(ap)))
		unix.Close(fd)
	}
	noDatagramWithin(t, raw, time.Second, "a datagram of a socket outside the containment that carries its mark")
}

// A packet from the agent's address that carries no mark (a reply the kernel makes for the /128, or
// a socket outside the containment bound to the address) is routed to the tunnel, where admission
// refuses it, and never by the host's own routes, out of its uplink with the agent's address.
func TestTheAgentsAddressNeverTakesTheHostsRoutes(t *testing.T) {
	needRoot(t)
	ns, _ := hostTUN(t)
	hr := ns.HostRoute()
	route := func(args ...string) string {
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil && len(out) == 0 {
			t.Skipf("needs iproute2: %v", err)
		}
		return string(out)
	}
	if got := route("-6", "route", "get", "2606:4700:4700::1111", "from", tSelf.String()); !strings.Contains(got, "dev "+hr.Name) {
		t.Fatalf("from the /128 the route is not the tunnel's: %s", got)
	}
	if hr.CarryV4 {
		if got := route("-4", "route", "get", "198.51.100.7", "from", CLATv4.String()); !strings.Contains(got, "dev "+hr.Name) {
			t.Fatalf("from 192.0.0.2 the route is not the tunnel's: %s", got)
		}
	}
	// With the device's route gone (a killed command takes it with its TUN), the address is refused.
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	var m unix.RtMsg
	m.Family, m.Table, m.Type, m.Scope = unix.AF_INET6, unix.RT_TABLE_UNSPEC, unix.RTN_UNICAST, unix.RT_SCOPE_UNIVERSE
	body := append([]byte(nil), (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.RTA_TABLE, u32(hr.Table))...)
	if err := r.do(unix.RTM_DELROUTE, 0, body); err != nil {
		t.Fatalf("drop the tunnel's IPv6 route: %v", err)
	}
	if got := route("-6", "route", "get", "2606:4700:4700::1111", "from", tSelf.String()); !strings.Contains(strings.ToLower(got), "permission denied") &&
		!strings.Contains(got, "prohibit") {
		t.Fatalf("with the tunnel's table empty the /128 must be refused, not routed by main: %s", got)
	}
}

// A socket made before the containment and pinned by it, which then connects through the tunnel
// from the /128, is ended at release and keeps its pin: given back its old binding, what it still
// sends (a TCP connection's closing exchange and retransmissions) would leave by the host's routes.
// A datagram socket shows it, because ending it leaves its addresses in place, where ending a TCP
// socket that never got an answer resets it.
func TestReleaseKeepsAnEndedSocketPinned(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	hr := *ns.HostRoute()
	h := startHelper(t, peer.addr)
	pid := h.cmd.Process.Pid
	if got := h.do(t, "udpopen"); got != "ok" { // before the containment: touched by it, marked and pinned
		t.Fatalf("udpopen: %s", got)
	}
	c, err := Contain(pid, tSelf, hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	if got := h.do(t, "udpconnect [2606:4700:4700::1111]:443"); got != "ok" {
		c.Release()
		t.Fatalf("udpconnect: %s", got)
	}
	if notes := c.Release(); len(notes) > 0 {
		t.Fatalf("release notes: %v", notes)
	}
	seen := false
	for _, sk := range socketsOf(t, pid) {
		fd, _ := strconv.Atoi(strings.Fields(sk)[0])
		dup, err := getfd(pid, fd)
		if err != nil {
			t.Fatalf("getfd: %v", err)
		}
		local, _, _ := sockAddrs(dup)
		bound, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
		fromSelf := local == tSelf
		unix.Close(dup) // our copy only: the agent's own descriptor, and its socket, stay as they were
		if fromSelf {
			seen = true
			if bound != hr.Index {
				t.Fatalf("released, a socket sourced from the /128 is bound to %d, not the tunnel's %d: release gave its pin back", bound, hr.Index)
			}
		}
	}
	if !seen {
		t.Fatal("control: the connected socket's source is not the /128")
	}
}

// Taking over a killed containment of the same agent clears what that one left, and never the
// address rules the new device has just put in at the same slot.
func TestATakeoverKeepsTheNewDevicesAddressRules(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	hr := *ns.HostRoute()
	// The record a killed containment of this agent left, on this device's slot.
	path := filepath.Join(containState, containCgroupName(tSelf)+".json")
	rec := fmt.Sprintf(`{"pid":1,"slot":%d,"gen":1,"mark":%d,"index":%d,"origin":{},"pinned":[]}`, hr.Slot, markFor(1), hr.Index)
	if err := secureDir(containState); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	h := startHelper(t, peer.addr)
	c, err := Contain(h.cmd.Process.Pid, tSelf, hr, t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	rules := ipRules(t)
	if !strings.Contains(rules, "from "+tSelf.String()+" lookup") || !strings.Contains(rules, "from "+tSelf.String()+" prohibit") {
		t.Fatalf("the takeover removed the new device's address rules:\n%s", rules)
	}
	out, _ := exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", tSelf.String()).CombinedOutput()
	if !strings.Contains(string(out), "dev "+hr.Name) {
		t.Fatalf("after the takeover the /128 is not routed to the tunnel: %s", out)
	}
}

// The translator's 192.0.0.2 is not one agent's: a second device, for another agent, on another
// slot, and the removal of a dead containment's rules on the first one's slot leave the rule of the
// containment that carries IPv4 in place.
func TestAnotherAgentNeverTakesTheTranslatorsRule(t *testing.T) {
	needRoot(t)
	b, _ := hostTUNAs(t, tSelf2)
	hb := b.HostRoute()
	if !hb.CarryV4 {
		t.Skipf("IPv4 is not carried here (%s)", hb.V4Note)
	}
	route := func() string {
		out, _ := exec.Command("ip", "-4", "route", "get", "198.51.100.7", "from", CLATv4.String()).CombinedOutput()
		return string(out)
	}
	if got := route(); !strings.Contains(got, "dev "+hb.Name) {
		t.Fatalf("control: from 192.0.0.2 the route is not B's tunnel: %s", got)
	}
	a, _ := hostTUNAs(t, tSelf)
	t.Logf("A on %s, IPv4 carried %v", a.HostRoute().Name, a.HostRoute().CarryV4)
	if got := route(); !strings.Contains(got, "dev "+hb.Name) {
		t.Fatalf("another agent's device took B's translator rule: %s", got)
	}
	RemoveStaleRules(hb.Slot, markFor(1), netip.MustParseAddr("2a04:2a01:0:1::99"))
	if got := route(); !strings.Contains(got, "dev "+hb.Name) {
		t.Fatalf("removing a dead containment's rules on B's slot took B's translator rule: %s", got)
	}
}

// A device whose command was killed (its record no longer held) loses its gate when the next device
// on the host is made: no gate stays on the root cgroup with nothing that names it. A device that
// closes normally leaves no record behind.
func TestADeadDevicesGateIsReaped(t *testing.T) {
	needRoot(t)
	a, _ := hostTUN(t)
	ha := a.HostRoute()
	root := cgroupRoot()
	has := func(gen uint32) bool {
		for _, g := range rootGateGenerations(root) {
			if g == gen {
				return true
			}
		}
		return false
	}
	if !has(ha.Gen) {
		t.Fatalf("control: A's gate %s is not on the root cgroup", rootGateName(ha.Gen))
	}
	// Killed: the kernel drops the record's lock and closes the TUN; nothing is detached.
	ha.gate.rec.drop()
	ha.gate.rec = nil
	a.Dev.Close()
	b, _ := hostTUNAs(t, tSelf2)
	if has(ha.Gen) {
		t.Fatalf("the gate %s of a device whose command is gone was not reaped", rootGateName(ha.Gen))
	}
	if _, err := os.Stat(devRecordPath(ha.Gen)); !os.IsNotExist(err) {
		t.Fatalf("the dead device's record is still there: %v", err)
	}
	gb := b.HostRoute().Gen
	b.Close()
	if has(gb) {
		t.Fatalf("a closed device left its gate %s", rootGateName(gb))
	}
	if _, err := os.Stat(devRecordPath(gb)); !os.IsNotExist(err) {
		t.Fatalf("a closed device left its record: %v", err)
	}
}

// A reaper of a dead device runs under another agent's lock. If the dead device's agent has
// meanwhile come up again on the same slot, the reaper must not take that live containment's
// address rules, which have the same shape as the dead one's.
func TestALateReapNeverTakesALiveContainmentsAddressRules(t *testing.T) {
	needRoot(t)
	if err := secureDir(containState); err != nil {
		t.Fatal(err)
	}
	// The record a device of this agent left when its command was killed, on slot 0, held for now by
	// another command that is reaping it.
	path := devRecordPath(1)
	rec := fmt.Sprintf(`{"gen":1,"slot":0,"mark":%d,"index":99999,"self":%q}`, markFor(1), tSelf.String())
	if err := os.WriteFile(path, []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ns, _ := hostTUN(t) // the agent comes up again, on slot 0, while the record is held
	hr := ns.HostRoute()
	if hr.Slot != 0 {
		other.Close()
		t.Skipf("the device took slot %d; this host already holds slot 0", hr.Slot)
	}
	other.Close() // the other reaper gives way, and this one reaps late
	reapDeadDevices()
	rules := ipRules(t)
	if !strings.Contains(rules, "from "+tSelf.String()+" lookup") || !strings.Contains(rules, "from "+tSelf.String()+" prohibit") {
		t.Fatalf("a late reap of a dead device took the live containment's address rules:\n%s", rules)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the dead device's record was not reaped: %v", err)
	}
}

// A listener made before the containment is pinned, but the connections already waiting in its
// accept queue finished their handshake before that, from the host's own address: in no descriptor
// table, unmarked, unpinned, in the old cgroup. Accepted after the thaw they would talk outside the
// tunnel, so the containment ends them while the process is frozen.
func TestConnectionsWaitingInAPinnedListenersQueueAreEnded(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	addr := helperListen(t, h, "")
	// The peer connects; the kernel completes the handshake; nobody accepts yet.
	conn := dialFromPeer(t, peer, addr)
	defer conn.Close()
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	t.Logf("contained: %s", c.Sockets)
	got := h.do(t, "acceptwrite")
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	b := make([]byte, 8)
	if n, _ := conn.Read(b); n > 0 {
		t.Fatalf("a connection that waited in the listener's queue was accepted after the thaw (%s) and reached the "+
			"peer outside the tunnel with %q", got, b[:n])
	}
}

// dialFromPeer connects from inside the peer namespace.
func dialFromPeer(t *testing.T, p *peerNS, addr string) net.Conn {
	t.Helper()
	ch := make(chan net.Conn, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends inside the peer namespace
		fd, err := unix.Open("/run/netns/"+p.ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ch <- nil
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			ch <- nil
			return
		}
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			c = nil
		}
		ch <- c
	}()
	c := <-ch
	if c == nil {
		t.Fatal("could not connect from the peer namespace")
	}
	return c
}

// A connection still in the middle of its handshake when the listener is pinned completes after the
// sweep. The kernel gives it the binding and mark of its request, both from before the pin, so it
// carries neither; it does carry the listener's tag, copied when it is made, and the gate holds it by
// that: accepted after the thaw, it reaches nothing outside the tunnel. The listener defers accept,
// so the connection waits as a request until its first data, which the peer sends after the sweep.
func TestAConnectionMidHandshakeAtTheSweepIsHeldByTheTag(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	ns, _ := hostTUN(t)
	h := startHelper(t, peer.addr)
	addr := helperListen(t, h, "defer")
	port, _ := strconv.Atoi(addr[strings.LastIndexByte(addr, ':')+1:])
	conn := dialFromPeer(t, peer, addr)
	defer conn.Close()
	waitFor(t, func() bool { return synRecvOn(port) }, "a request in SYN_RECV on the listener (the precondition)")
	c, err := Contain(h.cmd.Process.Pid, tSelf, *ns.HostRoute(), t.Logf)
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	defer c.Release()
	if !synRecvOn(port) {
		t.Fatal("the request was not in SYN_RECV across the sweep, so this would prove nothing")
	}
	if _, err := conn.Write([]byte("y")); err != nil { // its data completes the connection now
		t.Fatalf("peer write: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	got := h.do(t, "acceptwrite")
	if got != "ok" {
		t.Fatalf("control: the completed connection must be there to accept, got %s", got)
	}
	_ = conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	b := make([]byte, 8)
	if n, _ := conn.Read(b); n > 0 {
		t.Fatalf("a connection mid-handshake at the sweep was accepted after the thaw and reached the peer outside "+
			"the tunnel with %q", b[:n])
	}
}

// synRecvOn reports whether a request on local port port is in SYN_RECV. It reads the calling
// thread's namespace's table: /proc/net follows the main thread, which an earlier test may have left
// inside an agent's namespace.
func synRecvOn(port int) bool {
	b, err := os.ReadFile("/proc/thread-self/net/tcp")
	if err != nil {
		return false
	}
	want := fmt.Sprintf(":%04X", port)
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 3 && strings.HasSuffix(f[1], want) && f[3] == "03" {
			return true
		}
	}
	return false
}

// Once the tunnel stops, a connection of the containment still ending (FIN_WAIT1, LAST_ACK) would
// retransmit from the /128 by the host's main table: while a socket could still send from it, the
// address stays refused on the host, and the agent's next device clears that refusal and routes the
// address through its own tunnel.
func TestTheAgentsAddressStaysRefusedAfterTheTunnelStops(t *testing.T) {
	needRoot(t)
	withoutDestroy(t) // a kernel that can end the connection leaves nothing that needs the refusal
	ns, _ := hostTUN(t)
	tcpFrom(t, tSelf) // a connection the kernel could still send from the /128 for (contain_residue_root_linux_test.go)
	ns.Close()
	out, _ := exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", tSelf.String()).CombinedOutput()
	if !strings.Contains(strings.ToLower(string(out)), "permission denied") && !strings.Contains(string(out), "prohibit") {
		t.Fatalf("after the tunnel stopped, the /128 is routed by the host: %s", out)
	}
	again, _ := hostTUN(t) // the agent's next device clears it and routes it through its own tunnel
	out, _ = exec.Command("ip", "-6", "route", "get", "2606:4700:4700::1111", "from", tSelf.String()).CombinedOutput()
	if !strings.Contains(string(out), "dev "+again.HostRoute().Name) {
		t.Fatalf("the agent's next device did not take its address back: %s", out)
	}
	if rules := ipRules(t); strings.Count(rules, "from "+tSelf.String()+" prohibit") != 1 {
		t.Fatalf("the agent's next device left the old refusal beside its own:\n%s", rules)
	}
}
