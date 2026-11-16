// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// sockdiag_linux.go asks the kernel which TCP sockets of this network namespace could still send
// from an agent's address, through NETLINK_SOCK_DIAG (the interface `ss` reads), and ends them with
// SOCK_DESTROY where the kernel was built with it.
//
// A containment leaves one thing behind on purpose, the agent's "from <the /128> prohibit" rule, and
// only so that a connection of the containment that is still ending never retransmits from the /128
// by the host's own routes. What it asks here is whether any such connection is left, so the rule
// goes as soon as nothing needs it.
//
// TCP is asked about, and SCTP's associations are read from their own table. The tunnel's filter
// passes TCP, UDP and ICMPv6 and nothing else, so a containment never has an association of another
// protocol from the /128 (SCTP and DCCP keep sending for one in the background), though one made
// another way is still counted; and of those three only the kernel's TCP sends from a socket nobody is
// driving: a retransmission, a keepalive, a FIN, a request socket's SYN-ACK, a TIME_WAIT's ACK. A
// datagram, raw or ping socket, a listener and a TCP socket that is only bound send nothing unless
// their holder makes them, and a holder can send from the /128 anyway once nothing refuses it: any
// unprivileged process may bind it with IPV6_FREEBIND. So the refusal is for the connections the
// kernel drives, and those are what the answer covers (an MPTCP connection's subflows are TCP
// sockets of their own). A filter that let another protocol through would have to revisit this.

// The sock_diag wire constants, from linux/sock_diag.h and linux/inet_diag.h.
const (
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY, the request and every answer
	sockDestroyMsg   = 21 // SOCK_DESTROY

	inetDiagReqBytecode = 1 // INET_DIAG_REQ_BYTECODE
	inetDiagBcJmp       = 1 // INET_DIAG_BC_JMP: always takes its "no" jump
	inetDiagBcSCond     = 7 // INET_DIAG_BC_S_COND: the local address matches a prefix

	inetDiagReqLen = 56 // sizeof(struct inet_diag_req_v2)
	inetDiagMsgLen = 72 // sizeof(struct inet_diag_msg)

	tcpTimeWait      = 6  // TCP_TIME_WAIT
	tcpListen        = 10 // TCP_LISTEN
	tcpNewSynRecv    = 12 // TCP_NEW_SYN_RECV, a request socket
	tcpBoundInactive = 13 // TCP_BOUND_INACTIVE (Linux 6.5): bound, neither connected nor listening
)

// diagStates asks for every TCP state in which the kernel may send for the socket on its own: not a
// listener, which only answers what arrives (its request sockets, which it does answer on a timer,
// are asked for), and not a socket that is only bound (Linux 6.5 lists those; older kernels cannot).
const diagStates = ^uint32(0) &^ (1<<tcpListen | 1<<tcpBoundInactive)

// diagSock is one TCP socket a dump returned, or an SCTP association (sctp, with its address and
// inode only).
type diagSock struct {
	sctp   bool
	state  uint8
	src    netip.Addr
	sport  uint16
	dst    netip.Addr
	dport  uint16
	ifidx  uint32 // the device the socket is bound to; for a request socket, its listener's binding
	cookie [2]uint32
	inode  uint32
}

// inert reports whether s can never send again: a full socket (not a TIME_WAIT or a request socket,
// which the kernel answers for with the device only as a preference) bound to a device that is gone.
// A full socket's binding is strict, so nothing is routed for it; an unprivileged process cannot
// rebind a bound socket (SO_BINDTODEVICE needs CAP_NET_RAW then), and a TCP socket keeps its binding
// through connect(AF_UNSPEC); and a device index is not handed out twice in a boot in practice (only
// root can place one).
func (s diagSock) inert(live map[int]bool) bool {
	if s.sctp || s.state == tcpTimeWait || s.state == tcpNewSynRecv || s.ifidx == 0 {
		return false
	}
	return !live[int(s.ifidx)]
}

// liveIfindexes is every device index of the calling thread's network namespace.
func liveIfindexes() (map[int]bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(ifs))
	for _, i := range ifs {
		out[i.Index] = true
	}
	return out, nil
}

// bcSourceIn encodes a sock_diag filter that passes a socket whose local address is one of addrs, in
// the shape `ss` builds for an "or" and the kernel's audit accepts (every jump lands on the chain of
// "yes" steps): a condition that matches falls through to a JMP that skips everything after it to
// the end (pass); one that does not skips the JMP to the next condition, and the last one past the
// end (drop).
func bcSourceIn(addrs []netip.Addr) []byte {
	const condLen = 4 + 8 + 16 // inet_diag_bc_op, inet_diag_hostcond, an IPv6 address
	const jmpLen = 4
	total := len(addrs)*condLen + (len(addrs)-1)*jmpLen
	out := make([]byte, 0, total)
	for i, a := range addrs {
		op := make([]byte, condLen)
		op[0] = inetDiagBcSCond
		op[1] = condLen
		binary.NativeEndian.PutUint16(op[2:4], condLen+jmpLen)
		op[4] = unix.AF_INET6
		op[5] = 128
		binary.NativeEndian.PutUint32(op[8:12], 0xffffffff) // port -1: any port
		b := a.As16()
		copy(op[12:28], b[:])
		out = append(out, op...)
		if i < len(addrs)-1 {
			rest := total - len(out) - jmpLen // what follows the JMP
			jmp := make([]byte, jmpLen)
			jmp[0] = inetDiagBcJmp
			jmp[1] = jmpLen
			binary.NativeEndian.PutUint16(jmp[2:4], uint16(rest+jmpLen))
			out = append(out, jmp...)
		}
	}
	return out
}

// maxBcAddrs keeps a filter within one netlink attribute (32 bytes an address, under 64 KiB).
const maxBcAddrs = 1024

// diagReq encodes struct inet_diag_req_v2 for AF_INET6 TCP.
func diagReq(states uint32, id []byte) []byte {
	b := make([]byte, inetDiagReqLen)
	b[0] = unix.AF_INET6
	b[1] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(b[4:8], states)
	if id != nil {
		copy(b[8:56], id)
	}
	return b
}

// sockDiag is a NETLINK_SOCK_DIAG socket of the calling thread's network namespace.
type sockDiag struct{ fd int }

func openSockDiag() (*sockDiag, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("sock_diag bind: %w", err)
	}
	return &sockDiag{fd: fd}, nil
}

func (d *sockDiag) close() { unix.Close(d.fd) }

// send writes one request and returns its sequence number.
func (d *sockDiag) send(typ, flags uint16, body []byte) (uint32, error) {
	seq := nlSeq.Add(1)
	msg := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], typ)
	binary.NativeEndian.PutUint16(msg[6:8], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	copy(msg[unix.SizeofNlMsghdr:], body)
	return seq, unix.Sendto(d.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// dump lists the AF_INET6 TCP sockets in diagStates whose local address is one of addrs.
func (d *sockDiag) dump(addrs []netip.Addr) ([]diagSock, error) {
	var out []diagSock
	for start := 0; start < len(addrs); start += maxBcAddrs {
		end := min(start+maxBcAddrs, len(addrs))
		body := diagReq(diagStates, nil)
		body = append(body, nlAttr(inetDiagReqBytecode, bcSourceIn(addrs[start:end]))...)
		seq, err := d.send(sockDiagByFamily, unix.NLM_F_DUMP, body)
		if err != nil {
			return nil, err
		}
		if err := d.read(seq, func(data []byte) {
			if s, ok := parseDiagMsg(data); ok {
				out = append(out, s)
			}
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// read hands each answer to seq to each, until the kernel says it is done (or acknowledges).
func (d *sockDiag) read(seq uint32, each func([]byte)) error {
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(d.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code < 0 {
						return unix.Errno(-code)
					}
				}
				return nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code != 0 {
						return unix.Errno(-code)
					}
				}
				return nil
			case sockDiagByFamily:
				each(m.Data)
			}
		}
	}
}

// parseDiagMsg reads one struct inet_diag_msg.
func parseDiagMsg(b []byte) (diagSock, bool) {
	if len(b) < inetDiagMsgLen || b[0] != unix.AF_INET6 {
		return diagSock{}, false
	}
	var s diagSock
	s.state = b[1]
	s.sport = binary.BigEndian.Uint16(b[4:6])
	s.dport = binary.BigEndian.Uint16(b[6:8])
	s.src = netip.AddrFrom16([16]byte(b[8:24]))
	s.dst = netip.AddrFrom16([16]byte(b[24:40]))
	s.ifidx = binary.NativeEndian.Uint32(b[40:44])
	s.cookie[0] = binary.NativeEndian.Uint32(b[44:48])
	s.cookie[1] = binary.NativeEndian.Uint32(b[48:52])
	s.inode = binary.NativeEndian.Uint32(b[68:72])
	return s, true
}

// sockID encodes s's struct inet_diag_sockid back, as a destroy names it.
func (s diagSock) sockID() []byte {
	id := make([]byte, 48)
	binary.BigEndian.PutUint16(id[0:2], s.sport)
	binary.BigEndian.PutUint16(id[2:4], s.dport)
	src, dst := s.src.As16(), s.dst.As16()
	copy(id[4:20], src[:])
	copy(id[20:36], dst[:])
	binary.NativeEndian.PutUint32(id[36:40], s.ifidx)
	binary.NativeEndian.PutUint32(id[40:44], s.cookie[0])
	binary.NativeEndian.PutUint32(id[44:48], s.cookie[1])
	return id
}

// destroy ends s (SOCK_DESTROY). A kernel built without CONFIG_INET_DIAG_DESTROY answers EOPNOTSUPP,
// and a socket already gone ENOENT.
func (d *sockDiag) destroy(s diagSock) error {
	body := diagReq(diagStates, s.sockID())
	seq, err := d.send(sockDestroyMsg, unix.NLM_F_ACK, body)
	if err != nil {
		return err
	}
	return d.read(seq, func([]byte) {})
}

// ipv6Protocols reads the calling thread's namespace's protocol table (/proc/net/protocols): each
// IPv6 protocol and how many of its sockets are in use, which counts what is hashed (bound,
// connected or listening). A TIME_WAIT or request socket is not counted, so TCP is always dumped.
func ipv6Protocols() (map[string]int, error) {
	f, err := os.Open(filepath.Join(procRoot, "thread-self", "net", "protocols"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[0] == "protocol" || !strings.HasSuffix(fs[0], "6") {
			continue // the header, and the protocols that are not IPv6 (their names end v6, IPv6 or 6)
		}
		n, err := strconv.Atoi(fs[2])
		if err != nil {
			return nil, fmt.Errorf("%s: unreadable socket count %q", fs[0], fs[2])
		}
		out[fs[0]] = n
	}
	return out, sc.Err()
}

// quietProtocols are the IPv6 protocols whose sockets the kernel never sends from on its own, or (an
// MPTCP connection) does only through TCP sockets the TCP dump lists. SCTP is read from its own table
// (sctpAssociations). Any other IPv6 protocol in use (DCCP: its kernel keeps connections alive) is one
// the answer cannot cover.
var quietProtocols = map[string]bool{"TCPv6": true, "UDPv6": true, "UDPLITEv6": true, "RAWv6": true, "PINGv6": true, "MPTCPv6": true}

// sctpAssociations lists the SCTP associations of the calling thread's namespace that have one of
// want among their local addresses, from its association table (/proc/net/sctp/assocs).
//
// SCTP is counted from there, not from the protocol table: once the sctp module is loaded, the kernel
// keeps a control socket of its own in every namespace (SCTPv6 counts one in a namespace nobody has
// used), which no table of associations or endpoints lists and which sends nothing for any address.
// And an SCTP socket sends only within an association: one that is still shutting down after its
// socket was closed stays in this table while it does, where the protocol table has stopped counting
// it. A line lists the association's local addresses between its ports and "<->", each in full
// form, the primary one marked with "*".
func sctpAssociations(want map[netip.Addr]bool) ([]diagSock, error) {
	f, err := os.Open(filepath.Join(procRoot, "thread-self", "net", "sctp", "assocs"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []diagSock
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	header := true
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if header {
			// " ASSOC SOCK STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> ..."
			if len(fs) < 14 || fs[0] != "ASSOC" || fs[10] != "INODE" || fs[13] != "LADDRS" {
				return nil, fmt.Errorf("an association table in a form this does not read: %q", sc.Text())
			}
			header = false
			continue
		}
		arrow := -1
		for i, f := range fs {
			if f == "<->" {
				arrow = i
				break
			}
		}
		if arrow < 13 {
			return nil, fmt.Errorf("an association line this does not read: %q", sc.Text())
		}
		ino, _ := strconv.ParseUint(fs[10], 10, 32)
		for _, l := range fs[13:arrow] {
			a, err := netip.ParseAddr(strings.TrimPrefix(l, "*"))
			if err == nil && want[a.Unmap()] {
				out = append(out, diagSock{src: a.Unmap(), inode: uint32(ino), sctp: true})
				break
			}
		}
	}
	if header {
		return nil, errors.New("an empty association table")
	}
	return out, sc.Err()
}

// agentSockets lists every TCP socket of the calling thread's network namespace that could still send
// from one of addrs, in the states diagStates names, and every SCTP association with one of addrs
// among its local addresses. complete is false, with the reason, when the answer may be missing one:
// an IPv6 protocol in use that the kernel keeps sending for and nothing here reads, a protocol table
// or an SCTP association table that cannot be read, or a dump the kernel refused. A caller deciding that
// nothing sends from an address may decide so only on a complete answer. The caller keeps one thread
// for the whole question (runtime.LockOSThread), so every part of it reads the same namespace.
func agentSockets(addrs []netip.Addr) (socks []diagSock, complete bool, why string) {
	if len(addrs) == 0 {
		return nil, true, ""
	}
	protos, err := ipv6Protocols()
	if err != nil {
		return nil, false, "the protocol table cannot be read: " + err.Error()
	}
	for name, n := range protos {
		if n > 0 && !quietProtocols[name] && name != "SCTPv6" {
			return nil, false, fmt.Sprintf("%d %s socket%s in use, which the kernel keeps sending for and nothing here can "+
				"look into", n, name, plural(n))
		}
	}
	d, err := openSockDiag()
	if err != nil {
		return nil, false, err.Error()
	}
	defer d.close()
	socks, err = d.dump(addrs)
	if err != nil {
		return nil, false, fmt.Sprintf("the kernel would not list its TCP sockets (%v)", err)
	}
	if protos["SCTPv6"] > 0 {
		want := make(map[netip.Addr]bool, len(addrs))
		for _, a := range addrs {
			want[a] = true
		}
		assocs, err := sctpAssociations(want)
		if err != nil {
			return nil, false, fmt.Sprintf("SCTP is in use and its associations cannot be read (%v)", err)
		}
		socks = append(socks, assocs...)
	}
	return socks, true, ""
}
