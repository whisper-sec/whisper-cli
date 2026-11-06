// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package peerid

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

var (
	cli = netip.MustParseAddrPort("127.0.0.1:51000")
	srv = netip.MustParseAddrPort("127.0.0.1:1080")
)

func TestUIDOverflowAndAllOnesAreUnknown(t *testing.T) {
	if UID(65534) != Unknown || UID(^uint32(0)) != Unknown {
		t.Fatal("the overflow uid and -1 must never name a principal")
	}
	if UID(0) != "u:0" || UID(1000) != "u:1000" {
		t.Fatalf("got %q %q", UID(0), UID(1000))
	}
}

// procRow renders one /proc/net/tcp row the way the kernel does on a little-endian host.
func procRow(local, remote netip.AddrPort, st uint8, uid uint32, ino uint64) string {
	enc := func(ap netip.AddrPort) string {
		a := ap.Addr().As4()
		return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(a[:]), ap.Port())
	}
	return fmt.Sprintf("   0: %s %s %02X 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 20 4 30 10 -1\n",
		enc(local), enc(remote), st, uid, ino)
}

func TestProcNetTCPExactTuple(t *testing.T) {
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	table := head +
		procRow(srv, cli, 0x01, 1001, 9) + // the forwarder's accepted socket: reversed tuple, holder uid
		procRow(cli, srv, 0x01, 1000, 7) // the client's socket
	uid, _, ok := procNetTCPOwner([]byte(table), cli, srv)
	if !ok || uid != 1000 {
		t.Fatalf("got %d %v, want the client's uid 1000", uid, ok)
	}
}

func TestProcNetTCPRefusesPortOnlyAndDeadStates(t *testing.T) {
	head := "  sl  local_address rem_address   st\n"
	other := netip.MustParseAddrPort("127.0.0.2:1080") // source port equal to the listen port
	cases := map[string]string{
		"source port = listen port on 127.0.0.2": procRow(other, srv, 0x01, 1000, 7),
		"TIME_WAIT mini-socket":                  procRow(cli, srv, 0x06, 0, 0),
		"inode zero":                             procRow(cli, srv, 0x01, 1000, 0),
		"listen row":                             procRow(cli, srv, 0x0A, 1000, 7),
		"garbage":                                "zz zz zz zz zz zz zz zz zz zz\n",
	}
	for name, row := range cases {
		if _, _, ok := procNetTCPOwner([]byte(head+row), cli, srv); ok {
			t.Errorf("%s: matched, want not found", name)
		}
	}
	for _, st := range []uint8{0x01, 0x04, 0x05} {
		if _, _, ok := procNetTCPOwner([]byte(procRow(cli, srv, st, 1000, 7)), cli, srv); !ok {
			t.Errorf("state %02X: a live client state must match", st)
		}
	}
}

func diagReply(family uint8, local, remote netip.AddrPort, state uint8, uid, ino, seq uint32) []byte {
	b := make([]byte, nlmsgHdrLen+inetDiagMsgLen)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint32(b[8:], seq)
	m := b[nlmsgHdrLen:]
	m[0], m[1] = family, state
	binary.BigEndian.PutUint16(m[4:], local.Port())
	binary.BigEndian.PutUint16(m[6:], remote.Port())
	putDiagAddr(m[8:24], family, local.Addr())
	putDiagAddr(m[24:40], family, remote.Addr())
	binary.NativeEndian.PutUint32(m[64:], uid)
	binary.NativeEndian.PutUint32(m[68:], ino)
	return b
}

func TestInetDiagRequestLayout(t *testing.T) {
	b := encodeInetDiagExact(afINET, cli, srv, 7)
	if len(b) != 72 || binary.NativeEndian.Uint16(b[6:])&0x300 != 0 {
		t.Fatal("must be a single non-dump request of 16+56 bytes")
	}
	id := b[16+8:]
	if binary.BigEndian.Uint16(id[0:]) != 51000 || binary.BigEndian.Uint16(id[2:]) != 1080 {
		t.Fatal("sport is the client's port, dport the forwarder's, both network order")
	}
	if id[4] != 127 || id[7] != 1 || id[20] != 127 || binary.NativeEndian.Uint32(id[40:]) != ^uint32(0) {
		t.Fatal("addresses and INET_DIAG_NOCOOKIE")
	}
	b6 := encodeInetDiagExact(afINET6, cli, srv, 8)
	if b6[16+8+4+10] != 0xff || b6[16+8+4+15] != 1 {
		t.Fatal("AF_INET6 carries the v4-mapped form")
	}
}

func TestInetDiagReply(t *testing.T) {
	ok := diagReply(afINET, cli, srv, 1, 1000, 77, 5)
	if uid, _, found := parseInetDiagReply(ok, cli, srv, 5); !found || uid != 1000 {
		t.Fatalf("got %d %v", uid, found)
	}
	bad := map[string][]byte{
		"listener fallback (different id)": diagReply(afINET, netip.MustParseAddrPort("127.0.0.1:51000"), netip.MustParseAddrPort("0.0.0.0:0"), 0x0A, 1000, 1, 5),
		"time wait":                        diagReply(afINET, cli, srv, 6, 0, 0, 5),
		"inode zero":                       diagReply(afINET, cli, srv, 1, 1000, 0, 5),
		"unknown family":                   diagReply(7, cli, srv, 1, 1000, 1, 5),
		"truncated":                        ok[:40],
	}
	for name, b := range bad {
		if _, _, found := parseInetDiagReply(b, cli, srv, 5); found {
			t.Errorf("%s: accepted", name)
		}
	}
	// NLMSG_ERROR (ENOENT) for our seq.
	e := make([]byte, 36)
	binary.NativeEndian.PutUint32(e[0:], 36)
	binary.NativeEndian.PutUint16(e[4:], nlmsgError)
	binary.NativeEndian.PutUint32(e[8:], 5)
	if _, _, found := parseInetDiagReply(e, cli, srv, 5); found {
		t.Error("an error message is not-found")
	}
	// A stale reply for an older seq is skipped, and a lying length never reads past the buffer.
	stale := diagReply(afINET, cli, srv, 1, 0, 1, 4)
	if uid, _, found := parseInetDiagReply(append(stale, ok...), cli, srv, 5); !found || uid != 1000 {
		t.Error("a stale message must be skipped, not answered")
	}
	liar := append([]byte(nil), ok...)
	binary.NativeEndian.PutUint32(liar[0:], 1<<20)
	if _, _, found := parseInetDiagReply(liar, cli, srv, 5); found {
		t.Error("an oversized nlmsg_len must be refused")
	}
}

// pcbSpec is one pcb for pcbRecs.
type pcbSpec struct {
	local, remote netip.AddrPort
	uid           uint32
	state         int32
	inpp, sopcb   uint64 // sopcb 0 means "same as inpp"
	noSocket      bool
	proto, family uint32 // 0 means TCP / AF_INET
}

// pcbRecs builds a pcblist_n buffer: xinpgen, then per pcb xinpcb_n + xsocket_n + a receive
// buffer record + xtcpcb_n, then the trailing xinpgen with tailGen.
func pcbRecs(headGen, tailGen uint64, pcbs ...pcbSpec) []byte {
	var b []byte
	rec := func(kind uint32, size int, fill func(r []byte)) {
		r := make([]byte, roundUp8(size))
		binary.LittleEndian.PutUint32(r[0:], uint32(size))
		binary.LittleEndian.PutUint32(r[4:], kind)
		fill(r)
		b = append(b, r...)
	}
	gen := func(g uint64) []byte {
		x := make([]byte, xinpgenLen)
		binary.LittleEndian.PutUint32(x, xinpgenLen)
		binary.LittleEndian.PutUint64(x[xinpgenGen:], g)
		return x
	}
	b = append(b, gen(headGen)...)
	for i, p := range pcbs {
		inpp := p.inpp
		if inpp == 0 {
			inpp = uint64(0x1000 + i)
		}
		sopcb := p.sopcb
		if sopcb == 0 {
			sopcb = inpp
		}
		rec(xsoInpcb, 104, func(r []byte) {
			binary.LittleEndian.PutUint64(r[xinpInpp:], inpp)
			binary.BigEndian.PutUint16(r[xinpFport:], p.remote.Port())
			binary.BigEndian.PutUint16(r[xinpLport:], p.local.Port())
			if p.local.Addr().Unmap().Is4() {
				r[xinpVflag] = inpIPv4
				l4, f4 := p.local.Addr().Unmap().As4(), p.remote.Addr().Unmap().As4()
				copy(r[xinpLaddr+12:], l4[:])
				copy(r[xinpFaddr+12:], f4[:])
			} else {
				r[xinpVflag] = inpIPv6
				l6, f6 := p.local.Addr().As16(), p.remote.Addr().As16()
				copy(r[xinpLaddr:], l6[:])
				copy(r[xinpFaddr:], f6[:])
			}
		})
		if !p.noSocket {
			rec(xsoSocket, 104, func(r []byte) {
				binary.LittleEndian.PutUint64(r[xsoPcb:], sopcb)
				proto, fam := p.proto, p.family
				if proto == 0 {
					proto = 6
				}
				if fam == 0 {
					fam = darwinAFInet
				}
				binary.LittleEndian.PutUint32(r[xsoProto:], proto)
				binary.LittleEndian.PutUint32(r[xsoFamily:], fam)
				binary.LittleEndian.PutUint32(r[xsoUID:], p.uid)
				binary.LittleEndian.PutUint32(r[xsoLastPID:], 4242)
			})
		}
		rec(0x002, 48, func([]byte) {}) // a receive-buffer record, skipped by length
		rec(xsoTcpcb, 200, func(r []byte) { binary.LittleEndian.PutUint32(r[xtcpState:], uint32(p.state)) })
	}
	b = append(b, gen(tailGen)...)
	return b
}

func TestPCBListOwner(t *testing.T) {
	buf := pcbRecs(9, 9,
		pcbSpec{local: srv, remote: cli, uid: 501, state: 4}, // the accepted side
		pcbSpec{local: cli, remote: srv, uid: 502, state: 4}, // the client
	)
	if m, ok, cons := pcblistOwner(buf, cli, srv); !ok || !cons || m.uid != 502 || m.pids[0] != 4242 {
		t.Fatalf("got %+v %v %v, want 502", m, ok, cons)
	}
	if m, ok, _ := pcblistOwner(buf, srv, cli); !ok || m.uid != 501 {
		t.Fatalf("the reversed tuple is the other socket: got %+v %v", m, ok)
	}
	for _, st := range []int32{1, 10, 5, 99, -1} {
		if _, ok, _ := pcblistOwner(pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 7, state: st}), cli, srv); ok {
			t.Errorf("state %d must not match", st)
		}
	}
	v6c := netip.MustParseAddrPort("[::ffff:127.0.0.1]:51000")
	v6 := pcbRecs(1, 1, pcbSpec{local: v6c, remote: netip.MustParseAddrPort("[::ffff:127.0.0.1]:1080"), uid: 503, state: 6, family: darwinAFInet6})
	if m, ok, _ := pcblistOwner(v6, cli, srv); !ok || m.uid != 503 {
		t.Errorf("a v4-mapped pcb must match the v4 tuple: %+v %v", m, ok)
	}
}

func TestPCBListFailsClosedOnAMisreadLayout(t *testing.T) {
	cases := map[string][]byte{
		// The socket record of the previous pcb must never lend its uid to the next pcb.
		"socket record missing": pcbRecs(1, 1, pcbSpec{local: srv, remote: cli, uid: 0, state: 4},
			pcbSpec{local: cli, remote: srv, uid: 502, state: 4, noSocket: true}),
		"socket bound to another pcb": pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 0, state: 4, sopcb: 0xdead}),
		"socket not TCP":              pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 0, state: 4, proto: 17}),
		"socket family nonsense":      pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 0, state: 4, family: 99}),
	}
	for name, b := range cases {
		if m, ok, _ := pcblistOwner(b, cli, srv); ok {
			t.Errorf("%s: matched uid %d", name, m.uid)
		}
	}
	if _, _, cons := pcblistOwner(pcbRecs(1, 2, pcbSpec{local: cli, remote: srv, uid: 5, state: 4}), cli, srv); cons {
		t.Error("head and tail generations differ: the copy is inconsistent")
	}
}

func TestPCBListHostileLengths(t *testing.T) {
	buf := pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 502, state: 4})
	for cut := 0; cut < len(buf); cut++ {
		_, _, _ = pcblistOwner(buf[:cut], cli, srv) // must never panic
	}
	for _, l := range []uint32{0, 4, 8, 24, 32} { // records too short to hold an inpcb
		short := append([]byte(nil), buf...)
		binary.LittleEndian.PutUint32(short[xinpgenLen:], l)
		if _, ok, _ := pcblistOwner(short, cli, srv); ok {
			t.Errorf("an inpcb of length %d must not be read", l)
		}
	}
	huge := append([]byte(nil), buf...)
	binary.LittleEndian.PutUint32(huge[xinpgenLen:], 1<<30)
	if _, ok, _ := pcblistOwner(huge, cli, srv); ok {
		t.Error("a record longer than the buffer ends the walk")
	}
	neg := append([]byte(nil), buf...)
	binary.LittleEndian.PutUint32(neg[0:], 0xFFFFFFF0)
	if _, ok, _ := pcblistOwner(neg, cli, srv); ok {
		t.Error("a head that lies about its length is refused")
	}
}

func FuzzPCBList(f *testing.F) {
	f.Add(pcbRecs(1, 1, pcbSpec{local: cli, remote: srv, uid: 502, state: 4}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = pcblistOwner(b, cli, srv) })
}

func FuzzInetDiagReply(f *testing.F) {
	f.Add(diagReply(afINET, cli, srv, 1, 1000, 77, 5))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = parseInetDiagReply(b, cli, srv, 5) })
}

func FuzzProcNetTCP(f *testing.F) {
	f.Add([]byte(procRow(cli, srv, 1, 1000, 7)))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = procNetTCPOwner(b, cli, srv) })
}

func FuzzWindowsConnTable(f *testing.F) {
	f.Add(winTable(false, winRow4(5, cli, srv, 42, 100)), false)
	f.Fuzz(func(t *testing.T, b []byte, v6 bool) { _, _ = tcpTableConnOwner(b, v6, cli, srv) })
}

func winRow4(state uint32, local, remote netip.AddrPort, pid uint32, created int64) []byte {
	r := make([]byte, winRow4Len)
	binary.LittleEndian.PutUint32(r[0:], state)
	l, f := local.Addr().As4(), remote.Addr().As4()
	copy(r[4:], l[:])
	r[8], r[9] = byte(local.Port()>>8), byte(local.Port())
	copy(r[12:], f[:])
	r[16], r[17] = byte(remote.Port()>>8), byte(remote.Port())
	binary.LittleEndian.PutUint32(r[20:], pid)
	binary.LittleEndian.PutUint64(r[24:], uint64(created))
	return r
}

func winTable(_ bool, rows ...[]byte) []byte {
	buf := make([]byte, winTableHdr)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

func TestWindowsConnTable(t *testing.T) {
	buf := winTable(false,
		winRow4(5, srv, cli, 10, 1), // the accepted side
		winRow4(11, cli, srv, 9, 1), // TIME_WAIT
		winRow4(5, cli, srv, 4, 1),  // System never owns a user's socket
		winRow4(5, cli, srv, 42, 777))
	if c, ok := tcpTableConnOwner(buf, false, cli, srv); !ok || c.pid != 42 || c.created != 777 {
		t.Fatalf("got %+v %v", c, ok)
	}
	binary.LittleEndian.PutUint32(buf, 1000) // a count larger than the buffer reads only what fits
	if c, ok := tcpTableConnOwner(buf, false, cli, srv); !ok || c.pid != 42 {
		t.Fatal("an inflated count must still read only whole rows")
	}
	r6 := make([]byte, winRow6Len)
	l6, f6 := cli.Addr().As16(), srv.Addr().As16()
	copy(r6[0:], l6[:])
	r6[20], r6[21] = byte(cli.Port()>>8), byte(cli.Port())
	copy(r6[24:], f6[:])
	r6[44], r6[45] = byte(srv.Port()>>8), byte(srv.Port())
	binary.LittleEndian.PutUint32(r6[48:], 6)
	binary.LittleEndian.PutUint32(r6[52:], 77)
	buf6 := winTable(true, r6)
	if c, ok := tcpTableConnOwner(buf6, true, cli, srv); !ok || c.pid != 77 {
		t.Fatalf("v6 row: %+v %v", c, ok)
	}
	if _, ok := tcpTableConnOwner(buf6[:30], true, cli, srv); ok {
		t.Fatal("a short table yields nothing")
	}
}
