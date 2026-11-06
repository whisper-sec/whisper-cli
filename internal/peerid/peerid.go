// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package peerid names the local user behind a loopback TCP connection.
//
// The local forwarder accepts a connection on 127.0.0.1:<port> and has to decide, before it
// writes a single byte back, whether the process on the other end belongs to the user holding
// the session. The kernel knows: every connected socket carries the uid of the process that
// opened it. This package asks it, by the EXACT four-tuple of the client's socket (its address
// and port, and the forwarder's), never by port alone, because a client can bind any loopback
// address with a source port equal to the listen port and a port-only match would then find
// the holder's own rows.
//
// The answer is either an ID or UNKNOWN. UNKNOWN is the honest answer to a row that is
// missing, a socket that is already in TIME_WAIT (the kernel keeps uid 0 and inode 0 for it), a
// table that cannot be read, or a platform with no reader. The caller treats UNKNOWN as "not
// the owner": a client that cannot be identified must present the session's credential. Same-
// user clients lose nothing by this, because a process can always see its own user's sockets.
//
// Everything here is pure Go with no cgo and no fork, so the release builds (CGO_ENABLED=0)
// carry it on every OS. The table decoders are OS-free functions so every platform's parser is
// tested on any host.
package peerid

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// ID is a local principal: "u:<uid>" on unix, the user's SID string on Windows. Comparable, so
// a share list is a plain set.
type ID string

// Peer is what a lookup learned about the client socket: its principal, and whether the socket
// belongs to THIS process. Mine is computed only when ID equals Self() and Self() is privileged
// (root, LocalSystem), the one case where the user alone does not say enough: a root holder must
// not admit every root process on the host (a --network=host container, a root daemon told to
// use a proxy), only its own in-process clients.
type Peer struct {
	ID   ID
	Mine bool
}

// Privileged reports whether id is the superuser or the Windows LocalSystem account, for which
// "same user" is not a trust boundary.
func Privileged(id ID) bool { return id == "u:0" || id == "S-1-5-18" }

// Unknown is the zero ID. It never equals a real principal.
const Unknown ID = ""

// overflowUID is the kernel's "nobody": what a uid that does not map into this user namespace
// reads as. Two unrelated principals can both read as it, so it never identifies anyone. 65534
// by default; Linux reads the configured value at start (kernel.overflowuid).
var overflowUID uint32 = 65534

// UID renders a unix uid as an ID. The overflow uid renders as Unknown, so a holder running as
// it has no owner at all and every client must present the credential.
func UID(uid uint32) ID {
	if uid == overflowUID || uid == ^uint32(0) {
		return Unknown
	}
	return ID("u:" + strconv.FormatUint(uint64(uid), 10))
}

// Lookup names the owner of the client socket of an accepted loopback connection. client is
// the accepted conn's RemoteAddr (the client socket's LOCAL side) and server is its LocalAddr
// (the client socket's REMOTE side). known=false is UNKNOWN. A package var so tests pin it.
var Lookup = lookup

// needMine reports whether a lookup that found id must also say whether the socket is ours.
func needMine(id ID) bool { return id != Unknown && id == Self() && Privileged(id) }

// Self is the principal this process runs as: the holder of any proxy it serves.
var Self = self

// canon unmaps a v4-mapped address, so a tuple compares the same whichever table it came from.
func canon(a netip.Addr) netip.Addr { return a.Unmap() }

func sameTuple(aLocal, aRemote, bLocal, bRemote netip.AddrPort) bool {
	return canon(aLocal.Addr()) == canon(bLocal.Addr()) && aLocal.Port() == bLocal.Port() &&
		canon(aRemote.Addr()) == canon(bRemote.Addr()) && aRemote.Port() == bRemote.Port()
}

// --- Linux: /proc/net/tcp{,6} -----------------------------------------------------------

// Linux TCP states as /proc prints them (hex) and inet_diag reports them.
const (
	linuxEstablished = 0x01
	linuxFinWait1    = 0x04
	linuxFinWait2    = 0x05
)

func linuxLiveState(st uint8) bool {
	return st == linuxEstablished || st == linuxFinWait1 || st == linuxFinWait2
}

// procNetTCPOwner scans one /proc/net/tcp or tcp6 table for the row whose local side is client
// and remote side is server, and returns its uid. A row only counts in a live client state
// (ESTABLISHED, FIN_WAIT1, FIN_WAIT2) with a non-zero inode: a TIME_WAIT mini-socket keeps the
// tuple but has uid 0 and inode 0, and must never read as root. Pure and total.
func procNetTCPOwner(table []byte, client, server netip.AddrPort) (uid uint32, inode uint64, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(table))
	sc.Buffer(make([]byte, 0, 512), 4096)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, ok1 := procNetAddrPort(f[1])
		remote, ok2 := procNetAddrPort(f[2])
		if !ok1 || !ok2 || !sameTuple(local, remote, client, server) {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil || !linuxLiveState(uint8(st)) {
			continue
		}
		ino, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || ino == 0 {
			continue
		}
		u, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			continue
		}
		return uint32(u), ino, true
	}
	return 0, 0, false
}

// procNetAddrPort decodes "0100007F:1F90" (8 or 32 hex digits, then a 4-digit port). The kernel
// prints each 32-bit address word as the host-order integer of network-order bytes, so a word
// is decoded back through the native byte order.
func procNetAddrPort(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	ip := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}

// --- Linux: NETLINK_SOCK_DIAG -----------------------------------------------------------

const (
	nlmsgHdrLen       = 16
	inetDiagReqLen    = 56
	inetDiagMsgLen    = 72
	sockDiagByFamily  = 20 // SOCK_DIAG_BY_FAMILY
	nlmsgError        = 2  // NLMSG_ERROR
	nlmFRequest       = 0x1
	afINET            = 2
	afINET6           = 10
	ipprotoTCP        = 6
	inetDiagNoCookie  = ^uint32(0)
	inetDiagAllStates = ^uint32(0)
)

// encodeInetDiagExact builds one netlink request for the kernel's exact socket lookup: no
// NLM_F_DUMP, so the kernel runs inet_diag_find_one_icsk on the id instead of walking every
// socket. In the id, src/sport are the LOCAL side of the socket wanted (the client's address and
// ephemeral port) and dst/dport its REMOTE side (the forwarder), all in network byte order; the
// cookie is INET_DIAG_NOCOOKIE so the kernel does not insist on one. For AF_INET only the first
// address word is used.
func encodeInetDiagExact(family uint8, client, server netip.AddrPort, seq uint32) []byte {
	b := make([]byte, nlmsgHdrLen+inetDiagReqLen)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(b[6:], nlmFRequest)
	binary.NativeEndian.PutUint32(b[8:], seq)
	r := b[nlmsgHdrLen:]
	r[0], r[1] = family, ipprotoTCP
	binary.NativeEndian.PutUint32(r[4:], inetDiagAllStates)
	id := r[8:]
	binary.BigEndian.PutUint16(id[0:], client.Port())
	binary.BigEndian.PutUint16(id[2:], server.Port())
	putDiagAddr(id[4:20], family, client.Addr())
	putDiagAddr(id[20:36], family, server.Addr())
	binary.NativeEndian.PutUint32(id[40:], inetDiagNoCookie)
	binary.NativeEndian.PutUint32(id[44:], inetDiagNoCookie)
	return b
}

func putDiagAddr(dst []byte, family uint8, a netip.Addr) {
	if family == afINET {
		v4 := a.Unmap().As4()
		copy(dst, v4[:])
		return
	}
	v6 := a.As16() // As16 of a v4 address is its v4-mapped form
	copy(dst, v6[:])
}

func diagAddr(src []byte, family uint8) netip.Addr {
	if family == afINET {
		return netip.AddrFrom4([4]byte(src[:4]))
	}
	return netip.AddrFrom16([16]byte(src[:16]))
}

// parseInetDiagReply reads the kernel's answer to encodeInetDiagExact. It returns the uid only
// when the reply is ONE inet_diag_msg whose own id echoes the exact tuple asked for, in a live
// client state, with a non-zero inode. All three checks are load-bearing: on an established-
// table miss the kernel's inet_lookup falls back to the LISTENER table (whose id differs and
// whose state is LISTEN), and it also returns TIME_WAIT mini-sockets (uid 0, inode 0). An NLMSG_ERROR (ENOENT for "no such socket"), a short or garbled message, or
// anything else is not-found. Pure and bounded by len(b).
func parseInetDiagReply(b []byte, client, server netip.AddrPort, seq uint32) (uid uint32, inode uint32, ok bool) {
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:]))
		typ := binary.NativeEndian.Uint16(b[4:])
		mseq := binary.NativeEndian.Uint32(b[8:])
		if l < nlmsgHdrLen || l > len(b) {
			return 0, 0, false
		}
		msg := b[nlmsgHdrLen:l]
		if mseq == seq {
			if typ != sockDiagByFamily || len(msg) < inetDiagMsgLen || (msg[0] != afINET && msg[0] != afINET6) {
				return 0, 0, false
			}
			// Decoded by the REPLY's family: the v4 lookup shares the established hash with
			// dual-stack AF_INET6 sockets connected to a v4-mapped peer, and answers with them.
			fam := msg[0]
			id := msg[4:]
			sport := binary.BigEndian.Uint16(id[0:])
			dport := binary.BigEndian.Uint16(id[2:])
			local := netip.AddrPortFrom(diagAddr(id[4:20], fam), sport)
			remote := netip.AddrPortFrom(diagAddr(id[20:36], fam), dport)
			if !sameTuple(local, remote, client, server) || !linuxLiveState(msg[1]) {
				return 0, 0, false
			}
			ino := binary.NativeEndian.Uint32(msg[68:]) // idiag_inode
			if ino == 0 {
				return 0, 0, false
			}
			return binary.NativeEndian.Uint32(msg[64:]), ino, true // idiag_uid
		}
		next := (l + 3) &^ 3
		if next > len(b) {
			return 0, 0, false
		}
		b = b[next:]
	}
	return 0, 0, false
}

// --- macOS: net.inet.tcp.pcblist_n -------------------------------------------------------

// The pcblist_n records come from xnu's bsd/netinet/in_pcb.h, sys/socketvar.h and
// netinet/tcp_var.h, all under #pragma pack(4), so every offset below is the pack(4) layout.
// A misread layout must fail CLOSED (no match, so the client presents the credential), never
// open: the socket record is checked for protocol TCP and family AF_INET/AF_INET6, bound to its
// pcb by pointer, and the state is range-checked, so stray bytes cannot pass as a uid.
const (
	xsoSocket = 0x001
	xsoInpcb  = 0x010
	xsoTcpcb  = 0x020

	xinpgenLen = 24 // struct xinpgen: len 0, count 4, xig_gen 8 (u64), xig_sogen 16 (u64)
	xinpgenGen = 8

	// xinpcb_n: len 0, kind 4, xi_inpp 8, inp_fport 16, inp_lport 18, inp_ppcb 20,
	// inp_gencnt 28, inp_flags 36, inp_flow 40, inp_vflag 44, ttl 45, ip_p 46,
	// inp_dependfaddr 48 (16), inp_dependladdr 64 (16).
	xinpInpp, xinpFport, xinpLport, xinpVflag, xinpFaddr, xinpLaddr, xinpMin = 8, 16, 18, 44, 48, 64, 80
	// xsocket_n: len 0, kind 4, xso_so 8, so_type 16, so_options 20, so_linger 24, so_state 26,
	// so_pcb 28 (u64), xso_protocol 36, xso_family 40, ..., so_uid 64, so_last_pid 68, so_e_pid 72.
	xsoPcb, xsoProto, xsoFamily, xsoUID, xsoLastPID, xsoEPID, xsoMin = 28, 36, 40, 64, 68, 72, 76
	// xtcpcb_n: len 0, kind 4, t_segq 8, t_dupacks 16, t_timer[4] 20, t_state 36.
	xtcpState, xtcpMin = 36, 40

	inpIPv4 = 0x1
	inpIPv6 = 0x2

	darwinAFInet  = 2
	darwinAFInet6 = 30

	darwinEstablished = 4
	darwinFinWait1    = 6
	darwinFinWait2    = 9
	darwinTimeWait    = 10
)

type darwinPCB struct {
	inpp          uint64
	local, remote netip.AddrPort
	uid           uint32
	pids          [2]int32
	haveSock      bool
	state         int32
	haveState     bool
}

// pcbMatch is what pcblistOwner found: the client socket's uid and the pids the kernel last saw
// using it (so_last_pid, so_e_pid), which say whether it is this process's own socket.
type pcbMatch struct {
	uid  uint32
	pids [2]int32
}

// pcblistOwner walks a pcblist_n buffer record by record, as netstat does: skip the leading
// xinpgen by its own length, then each record is (len, kind, ...) advanced by its length rounded
// up to 8, and a record no longer than an xinpgen ends the list (the trailing xinpgen). A pcb is
// its xinpcb_n plus the xsocket_n and xtcpcb_n that follow it; all three are required, every
// field is read only after the record's length is checked against the minimum its kind needs,
// state is reset at each xinpcb_n, and an unknown kind is skipped by length. When the head and
// tail generation counts differ the list changed while the kernel copied it, and ok is false so
// the caller can read it again. Pure and bounded by len(buf): every step advances by at least 32.
func pcblistOwner(buf []byte, client, server netip.AddrPort) (m pcbMatch, found, consistent bool) {
	if len(buf) < xinpgenLen {
		return pcbMatch{}, false, false
	}
	headLen := int(binary.LittleEndian.Uint32(buf[0:]))
	if headLen < xinpgenLen || headLen > len(buf) {
		return pcbMatch{}, false, false
	}
	headGen := binary.LittleEndian.Uint64(buf[xinpgenGen:])
	var cur *darwinPCB
	check := func(p *darwinPCB) (pcbMatch, bool) {
		if p == nil || !p.haveSock || !p.haveState || !sameTuple(p.local, p.remote, client, server) {
			return pcbMatch{}, false
		}
		if p.state != darwinEstablished && p.state != darwinFinWait1 && p.state != darwinFinWait2 {
			return pcbMatch{}, false
		}
		return pcbMatch{uid: p.uid, pids: p.pids}, true
	}
	var hit pcbMatch
	var hitOK bool
	off := roundUp8(headLen)
	for off+8 <= len(buf) {
		l := int(binary.LittleEndian.Uint32(buf[off:]))
		kind := binary.LittleEndian.Uint32(buf[off+4:])
		if l <= xinpgenLen || l > len(buf)-off {
			// The trailing xinpgen (or a record that lies about its length) ends the walk.
			if !hitOK {
				hit, hitOK = check(cur)
			}
			if l == xinpgenLen && len(buf)-off >= xinpgenLen {
				tailGen := binary.LittleEndian.Uint64(buf[off+xinpgenGen:])
				return hit, hitOK, tailGen == headGen
			}
			return hit, hitOK, false
		}
		rec := buf[off : off+l]
		switch kind {
		case xsoInpcb:
			if !hitOK {
				hit, hitOK = check(cur)
			}
			cur = nil
			if l >= xinpMin {
				cur = parseXinpcb(rec)
			}
		case xsoSocket:
			if cur != nil && l >= xsoMin && binary.LittleEndian.Uint64(rec[xsoPcb:]) == cur.inpp &&
				binary.LittleEndian.Uint32(rec[xsoProto:]) == ipprotoTCP {
				if fam := binary.LittleEndian.Uint32(rec[xsoFamily:]); fam == darwinAFInet || fam == darwinAFInet6 {
					cur.uid = binary.LittleEndian.Uint32(rec[xsoUID:])
					cur.pids = [2]int32{int32(binary.LittleEndian.Uint32(rec[xsoLastPID:])),
						int32(binary.LittleEndian.Uint32(rec[xsoEPID:]))}
					cur.haveSock = true
				}
			}
		case xsoTcpcb:
			if cur != nil && l >= xtcpMin {
				st := int32(binary.LittleEndian.Uint32(rec[xtcpState:]))
				if st >= 0 && st <= darwinTimeWait {
					cur.state, cur.haveState = st, true
				}
			}
		}
		off += roundUp8(l)
	}
	if !hitOK {
		hit, hitOK = check(cur)
	}
	return hit, hitOK, false // no trailer: a truncated copy
}

func parseXinpcb(rec []byte) *darwinPCB {
	fport := binary.BigEndian.Uint16(rec[xinpFport:])
	lport := binary.BigEndian.Uint16(rec[xinpLport:])
	var la, fa netip.Addr
	// INP_IPV4 first, as netstat does: a v6 socket connected to a v4-mapped peer carries
	// INP_IPV4 with the v4 address at the end of the union.
	switch v := rec[xinpVflag]; {
	case v&inpIPv4 != 0:
		// struct in_addr_4in6: three pad words, then the v4 address.
		la = netip.AddrFrom4([4]byte(rec[xinpLaddr+12 : xinpLaddr+16]))
		fa = netip.AddrFrom4([4]byte(rec[xinpFaddr+12 : xinpFaddr+16]))
	case v&inpIPv6 != 0:
		la = netip.AddrFrom16([16]byte(rec[xinpLaddr : xinpLaddr+16]))
		fa = netip.AddrFrom16([16]byte(rec[xinpFaddr : xinpFaddr+16]))
	default:
		return nil
	}
	return &darwinPCB{inpp: binary.LittleEndian.Uint64(rec[xinpInpp:]),
		local: netip.AddrPortFrom(la, lport), remote: netip.AddrPortFrom(fa, fport)}
}

func roundUp8(n int) int { return (n + 7) &^ 7 }

// --- Windows: GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_CONNECTIONS) ---------------------

// MIB_TCP_STATE values for a live client socket.
const (
	winEstab    = 5
	winFinWait1 = 6
	winFinWait2 = 7

	// MIB_TCPROW_OWNER_MODULE: state 0, local addr 4, local port 8, remote addr 12, remote port
	// 16, pid 20, liCreateTimestamp 24 (8-aligned), OwningModuleInfo[16] u64 = 160 bytes.
	winRow4Len = 160
	// MIB_TCP6ROW_OWNER_MODULE: local addr 0 (16), scope 16, local port 20, remote addr 24 (16),
	// scope 40, remote port 44, state 48, pid 52, liCreateTimestamp 56, module info = 192 bytes.
	winRow6Len = 192
	// Both tables are a DWORD count followed by rows that contain a LARGE_INTEGER, so the rows
	// start 8-aligned.
	winTableHdr = 8
)

func winLiveState(st uint32) bool { return st == winEstab || st == winFinWait1 || st == winFinWait2 }

// winConn is one connection row's owner: its pid and the socket's creation time (FILETIME).
type winConn struct {
	pid     uint32
	created int64
}

// tcpTableConnOwner finds the owner of the connection whose local side is client and remote side
// is server, in a MIB_TCPTABLE_OWNER_MODULE (v6=false) or MIB_TCP6TABLE_OWNER_MODULE (v6=true).
// Addresses are in network order as stored; a port's first two bytes are its network-order
// value. pid 0 (Idle) and 4 (System) never own a user's socket and never match. Pure and bounded
// by the buffer: the count is untrusted, and only whole rows inside the buffer are read.
func tcpTableConnOwner(buf []byte, v6 bool, client, server netip.AddrPort) (winConn, bool) {
	if len(buf) < winTableHdr {
		return winConn{}, false
	}
	n := int(binary.LittleEndian.Uint32(buf))
	row := winRow4Len
	if v6 {
		row = winRow6Len
	}
	if max := (len(buf) - winTableHdr) / row; n > max {
		n = max
	}
	for i := 0; i < n; i++ {
		r := buf[winTableHdr+i*row : winTableHdr+(i+1)*row]
		var local, remote netip.AddrPort
		var state, pid uint32
		var created int64
		if v6 {
			local = netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), uint16(r[20])<<8|uint16(r[21]))
			remote = netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), uint16(r[44])<<8|uint16(r[45]))
			state, pid = binary.LittleEndian.Uint32(r[48:]), binary.LittleEndian.Uint32(r[52:])
			created = int64(binary.LittleEndian.Uint64(r[56:]))
		} else {
			state = binary.LittleEndian.Uint32(r[0:])
			local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), uint16(r[8])<<8|uint16(r[9]))
			remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), uint16(r[16])<<8|uint16(r[17]))
			pid = binary.LittleEndian.Uint32(r[20:])
			created = int64(binary.LittleEndian.Uint64(r[24:]))
		}
		if pid == 0 || pid == 4 || !winLiveState(state) || !sameTuple(local, remote, client, server) {
			continue
		}
		return winConn{pid: pid, created: created}, true
	}
	return winConn{}, false
}
