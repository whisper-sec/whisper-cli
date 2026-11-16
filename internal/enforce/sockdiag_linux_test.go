// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// sockdiag_linux_test.go holds the sock_diag layer to the kernel without privilege: a dump needs none,
// so the filter is proved against the kernel's own audit and matching, not against a reading of it.

// inodeOf reads the inode of a connection's socket.
func inodeOf(t *testing.T, c syscall.Conn) uint32 {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ino uint32
	if err := rc.Control(func(fd uintptr) {
		var st unix.Stat_t
		if unix.Fstat(int(fd), &st) == nil {
			ino = uint32(st.Ino)
		}
	}); err != nil {
		t.Fatal(err)
	}
	return ino
}

// connectedOnLoopback opens a TCP connection over ::1 and returns its client socket's inode and the
// listener's, or skips where ::1 is not on loopback.
func connectedOnLoopback(t *testing.T) (client, listener uint32) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("::1 is not on loopback here: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	c, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return inodeOf(t, c.(*net.TCPConn)), inodeOf(t, ln.(*net.TCPListener))
}

func dumped(t *testing.T, addrs []netip.Addr, ino uint32) bool {
	t.Helper()
	d, err := openSockDiag()
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	socks, err := d.dump(addrs)
	if err != nil {
		t.Fatalf("the kernel refused the dump (its audit refuses a filter it cannot walk): %v", err)
	}
	for _, s := range socks {
		if s.inode == ino {
			return true
		}
	}
	return false
}

// The filter passes a socket whose address is any of the asked ones, wherever it sits in the list
// (alone, first, middle, last, past a batch boundary), and no other. A listener is never listed: it
// sends nothing of its own.
func TestTheFilterFindsExactlyTheAskedAddresses(t *testing.T) {
	ino, lino := connectedOnLoopback(t)
	lo := netip.IPv6Loopback()
	other := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
	}
	if !dumped(t, []netip.Addr{lo}, ino) {
		t.Fatal("a filter on ::1 alone missed the connection from it")
	}
	if dumped(t, []netip.Addr{lo}, lino) {
		t.Fatal("a listener was listed, though the kernel sends nothing of its own for one")
	}
	for _, at := range []int{0, 1, 5} {
		addrs := []netip.Addr{other(1), other(2), other(3), other(4), other(5)}
		addrs = append(addrs[:at], append([]netip.Addr{lo}, addrs[at:]...)...)
		if !dumped(t, addrs, ino) {
			t.Fatalf("a filter with ::1 at %d of %d missed the connection", at, len(addrs))
		}
	}
	if dumped(t, []netip.Addr{other(1), other(2)}, ino) {
		t.Fatal("a filter without ::1 passed a connection from it")
	}
	var many []netip.Addr
	for i := 0; i < maxBcAddrs+300; i++ {
		many = append(many, other(i+10))
	}
	if !dumped(t, append(many, lo), ino) {
		t.Fatal("a filter over more addresses than one batch missed the connection in the last batch")
	}
}

// agentSockets says when its answer may be missing a socket: an IPv6 protocol in use that the kernel
// keeps sending for and nothing here reads, or a protocol table that cannot be read. A prune decides
// nothing on such an answer. Datagram, raw and ping sockets, and MPTCP (whose subflows are TCP
// sockets), leave it complete.
func TestAgentSocketsIsCompleteOnlyWhenEverythingWasRead(t *testing.T) {
	ino, _ := connectedOnLoopback(t)
	socks, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()})
	found := false
	for _, s := range socks {
		found = found || s.inode == ino
	}
	if !found {
		t.Fatalf("agentSockets missed the connection from ::1 (complete %v %s)", complete, why)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "thread-self", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
	if _, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()}); complete || !strings.Contains(why, "protocol table") {
		t.Fatalf("an unreadable protocol table must leave the answer incomplete: %v %q", complete, why)
	}
	table := func(sctp string) string {
		return "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n" +
			"MPTCPv6   2128      1      -1   NI       0   yes  kernel      y  n  y  y  y  y  y  y  y  y  y  y  y  n  n  n  y  y  n\n" +
			"PINGv6    1176      2      -1   NI       0   yes  kernel      y  y  y  n  n  y  n  n  y  y  y  y  n  y  y  y  y  y  n\n" +
			"RAWv6     1176      2      -1   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  n  y  y  y  y  n  n\n" +
			"UDPv6     1344      5       1   NI       0   yes  kernel      y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  y  n\n" +
			"SCTPv6    1376    " + sctp + "      -1   NI       0   yes  sctp        y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n" +
			"TCPv6     2560     20      12   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n" +
			"SCTP      1360      9      -1   NI       0   yes  sctp        y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y\n"
	}
	write := func(s string) {
		if err := os.WriteFile(filepath.Join(dir, "thread-self", "net", "protocols"), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(table("0"))
	if _, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()}); !complete {
		t.Fatalf("datagram, raw, ping and MPTCP sockets and an idle SCTPv6 must leave the answer complete: %q", why)
	}
	// SCTP in use is read from its association table: the kernel's own control socket, which counts
	// one in every namespace once the module is loaded, is in no association, and a real association
	// names its local addresses there.
	write(table("1"))
	if _, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()}); complete || !strings.Contains(why, "associations cannot be read") {
		t.Fatalf("SCTP in use with no association table to read must leave the answer incomplete: %v %q", complete, why)
	}
	if err := os.MkdirAll(filepath.Join(dir, "thread-self", "net", "sctp"), 0o755); err != nil {
		t.Fatal(err)
	}
	assocs := func(lines ...string) {
		head := " ASSOC     SOCK   STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> RADDRS HBINT INS OUTS MAXRT T1X T2X RTXC wmema wmemq sndbuf rcvbuf\n"
		if err := os.WriteFile(filepath.Join(dir, "thread-self", "net", "sctp", "assocs"), []byte(head+strings.Join(lines, "\n")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sctpOf := func(socks []diagSock) (n int) {
		for _, k := range socks {
			if k.sctp {
				n++
			}
		}
		return n
	}
	assocs()
	if socks, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()}); !complete || sctpOf(socks) != 0 {
		t.Fatalf("the kernel's SCTP control socket alone (no association) must leave the answer complete, counting no SCTP: %v %q %v", complete, why, socks)
	}
	line := func(laddrs string) string {
		return "ffff000714637000 ffff0008c420a400 2   1   3  0       4        0        0       0 9502737 59754 40652  " + laddrs +
			" <-> *2a04:2a01:0000:0001:0000:0000:0000:0045 \t   30000    10    10   10    0    0        0        "
	}
	assocs(line("2001:0db8:0000:0000:0000:0000:0000:0009"), line("*0000:0000:0000:0000:0000:0000:0000:0001 2001:0db8:0000:0000:0000:0000:0000:0007"))
	socks, complete, why = agentSockets([]netip.Addr{netip.IPv6Loopback()})
	sctp := 0
	for _, k := range socks {
		if k.sctp && k.src == netip.IPv6Loopback() && k.inode == 9502737 {
			sctp++
		}
	}
	if !complete || sctp != 1 {
		t.Fatalf("an SCTP association with the address among its local ones (primary or not) must be counted once, and only it: %v %q %+v", complete, why, socks)
	}
	assocs("not an association line")
	if _, complete, _ := agentSockets([]netip.Addr{netip.IPv6Loopback()}); complete {
		t.Fatal("an association line that cannot be read must leave the answer incomplete")
	}
	if err := os.WriteFile(filepath.Join(dir, "thread-self", "net", "sctp", "assocs"), []byte("ASSOC SOCK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, complete, _ := agentSockets([]netip.Addr{netip.IPv6Loopback()}); complete {
		t.Fatal("an association table in another form must leave the answer incomplete")
	}
	write(strings.Replace(table("0"), "SCTPv6    1376    0", "DCCPv6    1376    2", 1))
	if _, complete, why := agentSockets([]netip.Addr{netip.IPv6Loopback()}); complete || !strings.Contains(why, "DCCPv6") {
		t.Fatalf("an IPv6 protocol in use that the kernel keeps sending for and nothing reads must leave the answer incomplete: %v %q", complete, why)
	}
}

// A dump's message reads back into the fields a destroy names again, byte for byte.
func TestADiagMessageReadsBackIntoTheSocketIDADestroyNames(t *testing.T) {
	msg := make([]byte, inetDiagMsgLen+8)
	msg[0], msg[1] = unix.AF_INET6, tcpTimeWait
	id := msg[4:52]
	binary.BigEndian.PutUint16(id[0:2], 40000)
	binary.BigEndian.PutUint16(id[2:4], 443)
	src, dst := tSelf3.As16(), netip.MustParseAddr("2606:4700:4700::1111").As16()
	copy(id[4:20], src[:])
	copy(id[20:36], dst[:])
	binary.NativeEndian.PutUint32(id[36:40], 7)
	binary.NativeEndian.PutUint32(id[40:44], 0xdeadbeef)
	binary.NativeEndian.PutUint32(id[44:48], 0x01020304)
	binary.NativeEndian.PutUint32(msg[68:72], 4242)
	s, ok := parseDiagMsg(msg)
	if !ok || s.src != tSelf3 || s.sport != 40000 || s.dport != 443 || s.ifidx != 7 || s.state != tcpTimeWait || s.inode != 4242 {
		t.Fatalf("parsed %+v", s)
	}
	if got := s.sockID(); string(got) != string(id) {
		t.Fatalf("the socket id did not survive the round trip:\n got %x\nwant %x", got, id)
	}
	if _, ok := parseDiagMsg(msg[:20]); ok {
		t.Fatal("a short message parsed")
	}
	msg[0] = unix.AF_INET
	if _, ok := parseDiagMsg(msg); ok {
		t.Fatal("an IPv4 message parsed as IPv6")
	}
}

// Only a full socket bound to a device that is gone can never send. A TIME_WAIT or request socket's
// replies are routed for it with the device only as a preference, and an unbound socket follows the
// routes, so they always hold the address.
func TestInertIsOnlyAFullSocketOnAGoneDevice(t *testing.T) {
	live := map[int]bool{1: true, 9: true}
	for _, c := range []struct {
		s    diagSock
		want bool
	}{
		{diagSock{state: 1, ifidx: 77}, true},
		{diagSock{state: 4, ifidx: 77}, true},
		{diagSock{state: 1, ifidx: 9}, false},
		{diagSock{state: 1, ifidx: 0}, false},
		{diagSock{state: tcpTimeWait, ifidx: 77}, false},
		{diagSock{state: tcpNewSynRecv, ifidx: 77}, false},
	} {
		if got := c.s.inert(live); got != c.want {
			t.Fatalf("state %d on device %d: inert %v, want %v", c.s.state, c.s.ifidx, got, c.want)
		}
	}
}
