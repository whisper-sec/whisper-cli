// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// whale_v4_probe_test.go covers the measurement half.
//
// The property under test is not "the probe returns a value". It is that the probe cannot
// report a NEGATIVE it has not earned. A tunnel that is down and a NAT64 that is missing
// fail identically at the socket, and the only thing separating them is the IPv6 control -
// so every test here is written around what happens to the control.

// --- the anchor and the two targets ---------------------------------------------------

const (
	testAnchorV4 = "203.0.113.7"
	testAnchorV6 = "2001:db8:beef::7"
	// The RFC 6052 wrap of testAnchorV4 under the well-known prefix: 203.0.113.7 is
	// cb00:7107 in hex, so this is the exact address the subject dial must use.
	testAnchorWrapped = "64:ff9b::cb00:7107"
)

// stubAnchor pins DNS so the probe resolves a known dual-stack anchor with no network.
func stubAnchor(t *testing.T, addrs ...string) {
	t.Helper()
	saved := resolveAnchorAddrs
	resolveAnchorAddrs = func(_ context.Context, _ string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	t.Cleanup(func() { resolveAnchorAddrs = saved })
}

// dialLog records what the probe actually dialed, which is how we prove the control and the
// subject are the same host and port and differ only in family.
type dialLog struct {
	addrs []netip.Addr
	ports []int
}

// stubDial pins the SOCKS5 dial to a scripted answer per target address.
func stubDial(t *testing.T, log *dialLog, answer func(netip.Addr) (byte, error)) {
	t.Helper()
	saved := socks5Dial
	socks5Dial = func(_ context.Context, _ int, addr netip.Addr, port int) (byte, error) {
		log.addrs = append(log.addrs, addr)
		log.ports = append(log.ports, port)
		return answer(addr)
	}
	t.Cleanup(func() { socks5Dial = saved })
}

func allGood(netip.Addr) (byte, error) { return 0x00, nil }

// --- the verdicts ---------------------------------------------------------------------

func TestV4ProbeReachableWhenBothCompleted(t *testing.T) {
	stubAnchor(t, testAnchorV4, testAnchorV6)
	var log dialLog
	stubDial(t, &log, allGood)

	p := probeV4Through(context.Background(), 1080, []string{"ns1.whisper.online"})
	if p.State != v4Reachable {
		t.Fatalf("state = %q (%s), want reachable", p.State, p.Detail)
	}
	if !p.ControlOK {
		t.Fatal("control_ok is false on a run where the control completed")
	}
	if len(log.addrs) != 2 {
		t.Fatalf("dialed %d targets, want exactly the control and the subject", len(log.addrs))
	}
	if log.addrs[0].String() != testAnchorV6 {
		t.Fatalf("control dialed %s, want the anchor's IPv6 %s", log.addrs[0], testAnchorV6)
	}
	if log.addrs[1].String() != testAnchorWrapped {
		t.Fatalf("subject dialed %s, want the anchor's IPv4 wrapped into the NAT64 prefix (%s)",
			log.addrs[1], testAnchorWrapped)
	}
	if log.ports[0] != log.ports[1] {
		t.Fatalf("control port %d != subject port %d: the two must differ only in address family",
			log.ports[0], log.ports[1])
	}
}

// THE test. A missing NAT64 must be reported as unreachable, and the detail must name the
// SOCKS5 code so an operator can tell a routing hole from a refusal.
func TestV4ProbeUnreachableWhenOnlyTheV4HalfFails(t *testing.T) {
	stubAnchor(t, testAnchorV4, testAnchorV6)
	var log dialLog
	stubDial(t, &log, func(a netip.Addr) (byte, error) {
		if a.String() == testAnchorWrapped {
			return 0x03, nil // network unreachable, exactly what a missing NAT64 route yields
		}
		return 0x00, nil
	})

	p := probeV4Through(context.Background(), 1080, []string{"ns1.whisper.online"})
	if p.State != v4Unreachable {
		t.Fatalf("state = %q (%s), want unreachable", p.State, p.Detail)
	}
	if !p.ControlOK {
		t.Fatal("control_ok must be true: it is the whole basis for calling this a v4 failure")
	}
	for _, want := range []string{"0x03", "64:ff9b::/96", testAnchorWrapped} {
		if !strings.Contains(p.Detail, want) {
			t.Fatalf("detail %q does not name %q", p.Detail, want)
		}
	}
}

// A dead tunnel must NEVER be reported as an IPv4 fault. This is the failure this file
// exists to prevent.
func TestV4ProbeUnknownWhenTheControlFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		rep  byte
		err  error
	}{
		{"transport error", 0, errors.New("connection refused")},
		{"socks refusal", 0x01, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubAnchor(t, testAnchorV4, testAnchorV6)
			var log dialLog
			stubDial(t, &log, func(a netip.Addr) (byte, error) {
				if a.Is4() || a.String() == testAnchorWrapped {
					return 0x00, nil // the v4 half would have "worked": it must not be believed
				}
				return tc.rep, tc.err
			})

			p := probeV4Through(context.Background(), 1080, []string{"ns1.whisper.online"})
			if p.State != v4Unknown {
				t.Fatalf("state = %q, want unknown when the control did not complete", p.State)
			}
			if p.ControlOK {
				t.Fatal("control_ok is true on a run where the control failed")
			}
			if len(log.addrs) != 1 {
				t.Fatalf("dialed %d targets: a failed control must end the run, not be followed by a "+
					"subject whose result cannot be interpreted", len(log.addrs))
			}
			if strings.Contains(strings.ToLower(p.Detail), "not being carried") {
				t.Fatalf("detail %q reads as an IPv4 verdict on a run that could not reach a verdict", p.Detail)
			}
		})
	}
}

func TestV4ProbeUnknownWithNoListener(t *testing.T) {
	stubAnchor(t, testAnchorV4, testAnchorV6)
	var log dialLog
	stubDial(t, &log, allGood)
	p := probeV4Through(context.Background(), 0, []string{"ns1.whisper.online"})
	if p.State != v4Unknown {
		t.Fatalf("state = %q, want unknown with nothing connected", p.State)
	}
	if len(log.addrs) != 0 {
		t.Fatal("dialed something with no listener port")
	}
	if !strings.Contains(p.Detail, "nothing is connected") {
		t.Fatalf("detail = %q, want the reason named", p.Detail)
	}
}

// A single-stack anchor cannot be both the control and the subject, and pretending
// otherwise would compare two different hosts and call the difference IPv4.
func TestV4ProbeUnknownWhenTheAnchorIsNotDualStack(t *testing.T) {
	for _, only := range [][]string{{testAnchorV6}, {testAnchorV4}} {
		stubAnchor(t, only...)
		var log dialLog
		stubDial(t, &log, allGood)
		p := probeV4Through(context.Background(), 1080, []string{"ns1.whisper.online"})
		if p.State != v4Unknown {
			t.Fatalf("state = %q for a single-stack anchor %v, want unknown", p.State, only)
		}
		if len(log.addrs) != 0 {
			t.Fatalf("dialed %v with no usable anchor", log.addrs)
		}
	}
}

func TestV4ProbeUnknownWithNoAnchors(t *testing.T) {
	var log dialLog
	stubDial(t, &log, allGood)
	p := probeV4Through(context.Background(), 1080, nil)
	if p.State != v4Unknown {
		t.Fatalf("state = %q, want unknown with no anchor to measure against", p.State)
	}
}

// resolveDualStackAnchor must fall through a broken anchor to a working one rather than
// giving up on the first name.
func TestResolveDualStackAnchorFallsThrough(t *testing.T) {
	saved := resolveAnchorAddrs
	defer func() { resolveAnchorAddrs = saved }()
	resolveAnchorAddrs = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "broken":
			return nil, errors.New("no such host")
		case "v6only":
			return []netip.Addr{netip.MustParseAddr(testAnchorV6)}, nil
		default:
			return []netip.Addr{netip.MustParseAddr(testAnchorV4), netip.MustParseAddr(testAnchorV6)}, nil
		}
	}
	name, v4, v6, err := resolveDualStackAnchor(context.Background(), []string{"broken", "v6only", "good"})
	if err != nil {
		t.Fatalf("err = %v, want the third anchor to be used", err)
	}
	if name != "good" || v4.String() != testAnchorV4 || v6.String() != testAnchorV6 {
		t.Fatalf("got %s %s %s, want the dual-stack anchor", name, v4, v6)
	}
}

// --- the wire form --------------------------------------------------------------------

// socks5Dial writes a real SOCKS5 CONNECT. This proves the bytes against a server that
// checks them, rather than asserting the same layout twice.
func TestSocks5DialSpeaksRealSOCKS5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer ln.Close()

	type got struct {
		atyp byte
		addr netip.Addr
		port int
	}
	seen := make(chan got, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 3)
		if _, rerr := readFull(conn, greeting); rerr != nil {
			return
		}
		if _, werr := conn.Write([]byte{0x05, 0x00}); werr != nil {
			return
		}
		head := make([]byte, 4)
		if _, rerr := readFull(conn, head); rerr != nil {
			return
		}
		n := 4
		if head[3] == 0x04 {
			n = 16
		}
		body := make([]byte, n+2)
		if _, rerr := readFull(conn, body); rerr != nil {
			return
		}
		a, _ := netip.AddrFromSlice(body[:n])
		seen <- got{atyp: head[3], addr: a, port: int(binary.BigEndian.Uint16(body[n:]))}
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	rep, derr := socks5Dial(context.Background(), port, netip.MustParseAddr(testAnchorWrapped), v4ProbePort)
	if derr != nil {
		t.Fatalf("socks5Dial: %v", derr)
	}
	if rep != 0x00 {
		t.Fatalf("rep = 0x%02x, want success", rep)
	}
	select {
	case g := <-seen:
		if g.atyp != 0x04 {
			t.Fatalf("atyp = 0x%02x, want IPv6 (0x04) for a NAT64-wrapped target", g.atyp)
		}
		if g.addr.String() != testAnchorWrapped {
			t.Fatalf("server saw %s, want %s", g.addr, testAnchorWrapped)
		}
		if g.port != v4ProbePort {
			t.Fatalf("server saw port %d, want %d", g.port, v4ProbePort)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw a CONNECT")
	}
}

// A listener that is not our proxy must be named as such, not silently reported as an IPv4
// fault. A foreign process on the port is a different problem with a different fix.
func TestSocks5DialRefusesAForeignListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener available: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n"))
		// Stay open until the prober hangs up, and drain what it sent.
		// Closing a socket that still holds unread inbound data (the prober's
		// three-byte SOCKS5 greeting) makes the stack send an RST, and an RST
		// discards whatever we just wrote before the peer reads it. The prober
		// then sees a reset connection instead of the wrong greeting, and the
		// test asserts a sentence that was never produced. Windows does this
		// every time; every other platform does it often enough to be a flake.
		_, _ = io.Copy(io.Discard, conn)
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	_, derr := socks5Dial(context.Background(), port, netip.MustParseAddr(testAnchorV6), v4ProbePort)
	if derr == nil {
		t.Fatal("a non-SOCKS5 listener answered successfully")
	}
	if !strings.Contains(derr.Error(), "not a Whisper proxy") {
		t.Fatalf("err = %v, want it to name the foreign listener", derr)
	}
}

func TestSocks5ReasonNamesEveryRFC1928Code(t *testing.T) {
	for rep := byte(0x00); rep <= 0x08; rep++ {
		s := socks5Reason(rep, nil)
		if strings.HasPrefix(s, "SOCKS5 reply 0x") {
			t.Fatalf("reply 0x%02x has no sentence, only its number", rep)
		}
	}
	if !strings.Contains(socks5Reason(0x99, nil), "0x99") {
		t.Fatal("an unknown code must still be named")
	}
	if socks5Reason(0x00, errors.New("boom")) != "boom" {
		t.Fatal("a transport error must win over the reply code")
	}
}

// --- the anti-unreachable gate ----------------------------------------------------------

// The defect this codebase hits most is a feature that ships and can never execute. This
// EXECUTES the command from the root and asserts the measurement actually ran: without the
// flag the answer must say `not-measured`, with it the answer must carry a real verdict.
// Delete the wiring in whale_ip.go and this fails.
func TestWhaleIPProbeFlagActuallyReachesTheProbe(t *testing.T) {
	whaleTestIsolation(t)
	stubAnchor(t, testAnchorV4, testAnchorV6)

	run := func(args ...string) string {
		out, _ := captureStd(t, func() {
			prev := g.jsonOut
			g.jsonOut = true
			defer func() { g.jsonOut = prev }()
			_ = deepencli_exec(t, newWhaleIPCmd(), args...)
		})
		return out
	}

	plain := run("-4")
	if !strings.Contains(plain, `"state": "`+v4NotMeasured+`"`) {
		t.Fatalf("`whale ip -4` emitted %q; with no --probe the measurement must read %q",
			plain, v4NotMeasured)
	}

	probed := run("-4", "--probe")
	if strings.Contains(probed, `"state": "`+v4NotMeasured+`"`) {
		t.Fatalf("`whale ip -4 --probe` emitted %q: the flag is parsed but never reaches "+
			"probeV4Through, so the measurement can never execute", probed)
	}
	if !strings.Contains(probed, `"state": "`+v4Unknown+`"`) {
		t.Fatalf("`whale ip -4 --probe` emitted %q; with nothing connected the probe must "+
			"report unknown and say why", probed)
	}
	if !strings.Contains(probed, "nothing is connected") {
		t.Fatalf("`whale ip -4 --probe` emitted %q, want the reason the probe could not run", probed)
	}
}

// And the flag is reachable from the real root command, not only from the constructor.
func TestWhaleIPProbeFlagIsRegisteredOnTheRootTree(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"whale", "ip"})
	if err != nil {
		t.Fatalf("`whisper whale ip` is not registered: %v", err)
	}
	if cmd.Flags().Lookup("probe") == nil {
		t.Fatal("`whale ip` has no --probe flag: the measurement is unreachable from the CLI")
	}
}

// The unmeasured answer must not read as a claim, and the measured one must carry the
// verdict into the sentence a person reads.
func TestWhaleV4NoteNeverClaimsWhatWasNotMeasured(t *testing.T) {
	sessions := []statusSession{{Address: "2a04:2a01:1::a", Tier: "wireguard", Port: 1080}}

	un := whaleV4Status(sessions, nil)
	if un.Measured.State != v4NotMeasured {
		t.Fatalf("measured = %q, want not-measured", un.Measured.State)
	}
	if strings.Contains(un.Note, "DESTINATIONS work") {
		t.Fatalf("note %q claims a working path nobody measured", un.Note)
	}
	if !strings.Contains(un.Note, "--probe") {
		t.Fatalf("note %q does not say how to measure it", un.Note)
	}

	bad := whaleV4Status(sessions, &v4Probe{State: v4Unreachable, ControlOK: true,
		Detail: "IPv4 destinations are NOT being carried"})
	if !strings.Contains(bad.Note, "did not work") {
		t.Fatalf("note %q does not carry the measured failure", bad.Note)
	}
	good := whaleV4Status(sessions, &v4Probe{State: v4Reachable, ControlOK: true, Detail: "it completed"})
	if !strings.Contains(good.Note, "Measured just now") {
		t.Fatalf("note %q does not carry the measured success", good.Note)
	}
	unk := whaleV4Status(sessions, &v4Probe{State: v4Unknown, Detail: "the control failed"})
	if !strings.Contains(unk.Note, "could not decide") {
		t.Fatalf("note %q turns an unknown into a verdict", unk.Note)
	}
	if strings.Contains(unk.Note, "did not work") {
		t.Fatalf("note %q reports an unknown as a failure", unk.Note)
	}
}
