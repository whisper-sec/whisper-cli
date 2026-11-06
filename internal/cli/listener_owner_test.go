// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

// procHex encodes ip the way /proc/net/tcp{,6} prints it on this host: each 32-bit word of the
// network-order address read as a host-order integer, printed %08X.
func procHex(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil && !strings.Contains(ip.String(), ":") {
		ip = v4
	}
	var b strings.Builder
	for i := 0; i < len(ip); i += 4 {
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], binary.NativeEndian.Uint32(ip[i:]))
		b.WriteString(strings.ToUpper(hex.EncodeToString(w[:])))
	}
	return b.String()
}

func procRow(ip net.IP, port int, st string, ino string) string {
	return "   0: " + procHex(ip) + ":" + strings.ToUpper(hex.EncodeToString([]byte{byte(port >> 8), byte(port)})) +
		" 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000  1000        0 " + ino + " 1 0000000000000000 100 0 0 10 0\n"
}

const procHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestProcNetListenInodesSplitsExactFromWildcardAndIgnoresTheRest(t *testing.T) {
	table := procHeader +
		procRow(net.IPv4(127, 0, 0, 1), 1080, "0A", "111") + // the forwarder
		procRow(net.IPv4zero, 1080, "0A", "222") + // a wildcard on the same port
		procRow(net.IPv4(127, 0, 0, 1), 1081, "0A", "333") + // another port
		procRow(net.IPv4(127, 0, 0, 1), 1080, "01", "444") + // ESTABLISHED, not a listener
		procRow(net.IPv4(10, 0, 0, 1), 1080, "0A", "555") + // some other address
		"garbage line\n"
	exact, wild := procNetListenInodes([]byte(table), 1080)
	if len(exact) != 1 || exact[0] != 111 || len(wild) != 1 || wild[0] != 222 {
		t.Fatalf("exact=%v wildcard=%v; want [111] [222]", exact, wild)
	}
	v6 := procHeader + procRow(net.ParseIP("::ffff:127.0.0.1"), 1080, "0A", "666") + procRow(net.IPv6unspecified, 1080, "0A", "777") +
		procRow(net.IPv6loopback, 1080, "0A", "888")
	exact, wild = procNetListenInodes([]byte(v6), 1080)
	if len(exact) != 1 || exact[0] != 666 || len(wild) != 1 || wild[0] != 777 {
		t.Fatalf("tcp6: exact=%v wildcard=%v; want the mapped 127.0.0.1 [666] and :: [777]", exact, wild)
	}
}

// TestProcNetAddrReadsTheKernelsLiteralSpelling pins the decode against the literal a
// little-endian kernel prints, so procHex above cannot be agreeing with a shared mistake.
func TestProcNetAddrReadsTheKernelsLiteralSpelling(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the literal below is a little-endian kernel's spelling")
	}
	for lit, want := range map[string]string{
		"0100007F":                         "127.0.0.1",
		"0000000000000000FFFF00000100007F": "127.0.0.1",
		"00000000000000000000000001000000": "::1",
	} {
		ip, ok := procNetAddr(lit)
		if !ok || ip.String() != want {
			t.Errorf("procNetAddr(%s) = %v, %v; want %s", lit, ip, ok, want)
		}
	}
	for _, bad := range []string{"", "0100007", "zz00007F", "0100"} {
		if _, ok := procNetAddr(bad); ok {
			t.Errorf("procNetAddr(%q) must refuse", bad)
		}
	}
}

func TestTcpTableListenOwnersReadsTheWindowsRowLayout(t *testing.T) {
	row := func(addr net.IP, port, pid int) []byte {
		r := make([]byte, 24)
		binary.LittleEndian.PutUint32(r[0:], 2) // MIB_TCP_STATE_LISTEN
		copy(r[4:8], addr.To4())
		r[8], r[9] = byte(port>>8), byte(port)
		binary.LittleEndian.PutUint32(r[20:], uint32(pid))
		return r
	}
	buf := binary.LittleEndian.AppendUint32(nil, 4)
	buf = append(buf, row(net.IPv4(127, 0, 0, 1), 1080, 4242)...)
	buf = append(buf, row(net.IPv4zero, 1080, 99)...)
	buf = append(buf, row(net.IPv4(127, 0, 0, 1), 1081, 7)...)
	buf = append(buf, row(net.IPv4(127, 0, 0, 1), 1080, 5)[:10]...) // a truncated last row is not read
	exact, wild := tcpTableListenOwners(buf, 1080)
	if len(exact) != 1 || exact[0] != 4242 || len(wild) != 1 || wild[0] != 99 {
		t.Fatalf("exact=%v wildcard=%v; want [4242] [99]", exact, wild)
	}
	if e, w := tcpTableListenOwners([]byte{1}, 1080); e != nil || w != nil {
		t.Fatal("a short buffer yields nothing")
	}
}

func TestLsofAndOwnerDecision(t *testing.T) {
	pids := lsofListenPIDs([]byte("p4242\nf3\np17\nnot\np0\n"))
	if len(pids) != 2 || pids[0] != 4242 || pids[1] != 17 {
		t.Fatalf("lsof pids = %v", pids)
	}
	if o, k := ownedFromPIDs(nil, 1); o || k {
		t.Fatal("no visible owner is unknown, never a mismatch")
	}
	if o, k := ownedFromPIDs([]int{17, 4242}, 4242); !o || !k {
		t.Fatal("the record's pid among the owners is owned")
	}
	if o, k := ownedFromPIDs([]int{17}, 4242); o || !k {
		t.Fatal("a visible other owner is a known mismatch")
	}
}

func TestAKnownStrangerOnThePortSweepsTheRecordWhenTheEchoIsDown(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return "", errors.New("echo unreachable") })
	plantPID = os.Getpid()
	defer func() { plantPID = 0 }()
	path := plantRecord(t, dir, proofTarget, 1080)
	listenerOwnedByFn = func(port, pid int) (bool, bool) { return false, true } // someone else holds it
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if sess != nil || err != nil {
		t.Fatalf("a record whose port a stranger holds is never reused: sess=%+v err=%v", sess, err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("the stale record must be swept, stat err=%v", serr)
	}
}

func TestAProvenOwnerIsReusedWithTheWarningWhenTheEchoIsDown(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return "", errors.New("echo unreachable") })
	plantPID = os.Getpid()
	defer func() { plantPID = 0 }()
	plantRecord(t, dir, proofTarget, 1080)
	var asked [2]int
	listenerOwnedByFn = func(port, pid int) (bool, bool) { asked = [2]int{port, pid}; return true, true }
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if err != nil || sess == nil || sess.verified {
		t.Fatalf("the holder that owns its port is reused, unverified: sess=%+v err=%v", sess, err)
	}
	if asked != [2]int{1080, os.Getpid()} {
		t.Fatalf("the check must ask about the record's own port and pid, asked %v", asked)
	}
}
