// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------------------

// localTarget is a TCP service on loopback standing in for sshd: it reads the caller's whole
// request (to EOF, so it only answers once the caller half-closed), then writes a reply that
// names what it read, and closes.
func localTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b, _ := io.ReadAll(c)
				_, _ = fmt.Fprintf(c, "got %d bytes: %s", len(b), b)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// holdTarget is a local service that accepts and holds every connection open, reading and
// discarding, so a test can keep connections alive while it counts them.
func holdTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) }(c)
		}
	}()
	return ln.Addr().String()
}

// acceptOnLoopback installs an acceptor on a bare Tunnel whose listener is a loopback socket,
// which drives the real admission and splice path with no WireGuard underneath. It returns the
// address callers dial.
func acceptOnLoopback(t *testing.T, target string, opts AcceptOptions) (*Tunnel, string) {
	t.Helper()
	tun := &Tunnel{}
	var bound string
	err := tun.installAcceptor([]AcceptRule{{Port: 22, Target: target}}, opts, func(int) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			bound = ln.Addr().String()
		}
		return ln, err
	})
	if err != nil {
		t.Fatalf("installAcceptor: %v", err)
	}
	t.Cleanup(tun.stopAccept)
	return tun, bound
}

func permitAll(netip.Addr) bool { return true }

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func acceptWait(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requestReply writes req, half-closes, and reads the whole reply.
func requestReply(t *testing.T, addr, req string) (string, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// A refused or limited caller may already be closed by the time it writes, so a write
	// error here is not a test failure: what it READS is the assertion.
	_, _ = io.WriteString(c, req)
	_ = c.(*net.TCPConn).CloseWrite()
	b, _ := io.ReadAll(c)
	return string(b), nil
}

// --- Splice ----------------------------------------------------------------------------

// The half-close is the property a splice most often gets wrong: copy until either side ends,
// close both, and a client that sends a request then shuts its write half never reads the
// reply. The target here answers ONLY after it has seen EOF, so the reply can arrive only if
// the FIN was passed on and the reverse direction was kept open.
func TestAcceptSplicePassesHalfCloseAndKeepsTheReplyOpen(t *testing.T) {
	_, addr := acceptOnLoopback(t, localTarget(t), AcceptOptions{Permit: permitAll})
	got, err := requestReply(t, addr, "uname -a")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if got != "got 8 bytes: uname -a" {
		t.Fatalf("reply = %q, want the target's answer to the whole request", got)
	}
}

func TestSpliceClosesAnIdleConnection(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a1.Close()
	defer b2.Close()
	done := make(chan string, 1)
	go func() {
		_, _, why := Splice(a2, b1, 150*time.Millisecond)
		done <- why
	}()
	select {
	case why := <-done:
		if !strings.Contains(why, "idle") {
			t.Fatalf("reason = %q, want an idle close", why)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an idle splice was never closed")
	}
}

// Traffic resets the idle clock: a connection that keeps talking past the idle window is not
// cut off for being old.
func TestSpliceTrafficKeepsTheConnectionAlive(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a1.Close()
	defer b2.Close()
	go func() { _, _ = io.Copy(io.Discard, b2) }()
	done := make(chan string, 1)
	go func() {
		_, _, why := Splice(a2, b1, time.Second)
		done <- why
	}()
	// 2.5s of steady traffic, two and a half idle windows, with a write every 50ms: a margin
	// of twenty against the window, so a loaded -race run cannot read a scheduling stall as idle.
	for i := 0; i < 50; i++ {
		if _, err := a1.Write([]byte("k")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case why := <-done:
		t.Fatalf("splice ended during steady traffic: %s", why)
	default:
	}
	_ = a1.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("splice did not end after the caller closed")
	}
}

// --- admission -------------------------------------------------------------------------

// A caller the Permit refuses gets a connection that closes with no byte, the local target is
// never dialled, and the refusal is logged with the caller's address.
func TestAcceptRefusesACallerThePermitRejects(t *testing.T) {
	log := &logSink{}
	dialled := false
	tun, addr := acceptOnLoopback(t, "127.0.0.1:1", AcceptOptions{
		Permit: func(a netip.Addr) bool { return a == netip.MustParseAddr("2a04:2a01::77") },
		Logf:   log.logf,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialled = true
			return nil, errors.New("must not be dialled")
		},
	})
	got, err := requestReply(t, addr, "hello")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if got != "" {
		t.Fatalf("a refused caller read %q, want nothing", got)
	}
	acceptWait(t, 2*time.Second, "the refusal to be counted", func() bool { return tun.AcceptStats().Refused == 1 })
	if dialled {
		t.Fatal("the local target was dialled for a refused caller")
	}
	// The counter moves before the line is written, so wait for the line itself.
	acceptWait(t, 2*time.Second, "the refusal to be logged with the caller's address", func() bool { return log.has("refused 127.0.0.1") })
}

// No access decision is no access: an acceptor built without a Permit refuses everyone.
func TestAcceptWithNoPermitFailsClosed(t *testing.T) {
	tun, addr := acceptOnLoopback(t, localTarget(t), AcceptOptions{})
	got, _ := requestReply(t, addr, "hello")
	if got != "" {
		t.Fatalf("a nil Permit let a caller through: read %q", got)
	}
	acceptWait(t, 2*time.Second, "the refusal", func() bool { return tun.AcceptStats().Refused == 1 })
}

func TestAcceptLogsTheCallersAddressOnAdmission(t *testing.T) {
	log := &logSink{}
	_, addr := acceptOnLoopback(t, localTarget(t), AcceptOptions{Permit: permitAll, Logf: log.logf})
	if _, err := requestReply(t, addr, "x"); err != nil {
		t.Fatalf("request: %v", err)
	}
	acceptWait(t, 2*time.Second, "the close line", func() bool { return log.has("closed after") })
	if !log.has(":22 from 127.0.0.1 -> ") {
		t.Fatalf("admission line missing the caller: %q", log.lines)
	}
}

func TestAcceptEnforcesTheConnectionLimit(t *testing.T) {
	log := &logSink{}
	tun, addr := acceptOnLoopback(t, holdTarget(t), AcceptOptions{Permit: permitAll, MaxConns: 2, MaxPerSource: 10, Logf: log.logf})
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	acceptWait(t, 2*time.Second, "two open connections", func() bool { return tun.AcceptStats().Admitted == 2 })
	got, _ := requestReply(t, addr, "third")
	if got != "" {
		t.Fatalf("a connection past the limit was carried: %q", got)
	}
	acceptWait(t, 2*time.Second, "the third to be turned away", func() bool { return tun.AcceptStats().Limited == 1 })
	// The counter moves before the line is written, so wait for the line itself.
	acceptWait(t, 2*time.Second, "the limit to be logged", func() bool { return log.has("the limit") })
}

func TestAcceptEnforcesThePerCallerLimit(t *testing.T) {
	tun, addr := acceptOnLoopback(t, holdTarget(t), AcceptOptions{Permit: permitAll, MaxConns: 10, MaxPerSource: 1})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	acceptWait(t, 2*time.Second, "one open connection", func() bool { return tun.AcceptStats().Admitted == 1 })
	if got, _ := requestReply(t, addr, "second"); got != "" {
		t.Fatalf("a second connection from the same caller was carried: %q", got)
	}
	acceptWait(t, 2*time.Second, "the per-caller refusal", func() bool { return tun.AcceptStats().Limited == 1 })
	// And the slot is given back when the first one closes.
	c.Close()
	acceptWait(t, 2*time.Second, "the slot to be released", func() bool { return tun.AcceptStats().Open == 0 })
}

func TestAcceptReportsALocalTargetThatDoesNotAnswer(t *testing.T) {
	log := &logSink{}
	// A port that was just free on loopback: nothing listens there.
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := probe.Addr().String()
	probe.Close()
	tun, addr := acceptOnLoopback(t, dead, AcceptOptions{Permit: permitAll, Logf: log.logf})
	if got, _ := requestReply(t, addr, "x"); got != "" {
		t.Fatalf("read %q from a target that is not there", got)
	}
	acceptWait(t, 2*time.Second, "the failure", func() bool { return tun.AcceptStats().Failed == 1 })
	// The counter moves before the line is written, so wait for the line itself.
	acceptWait(t, 2*time.Second, "the dead target to be named", func() bool { return log.has("nothing answered on " + dead) })
}

func TestAcceptRefusesDuplicateAndInvalidPortsAndLeavesNothingBound(t *testing.T) {
	for _, rules := range [][]AcceptRule{
		{{Port: 22, Target: "127.0.0.1:22"}, {Port: 22, Target: "127.0.0.1:2222"}},
		{{Port: 0, Target: "127.0.0.1:22"}},
		{{Port: 70000, Target: "127.0.0.1:22"}},
	} {
		var opened []net.Listener
		tun := &Tunnel{}
		err := tun.installAcceptor(rules, AcceptOptions{Permit: permitAll}, func(int) (net.Listener, error) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			opened = append(opened, ln)
			return ln, err
		})
		if err == nil {
			t.Fatalf("rules %v were accepted", rules)
		}
		for _, ln := range opened {
			if c, derr := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); derr == nil {
				c.Close()
				t.Fatalf("a listener for rejected rules %v was left open", rules)
			}
		}
		if len(tun.Accepting()) != 0 {
			t.Fatalf("rejected rules are being reported as accepted")
		}
	}
}

// A port that cannot be bound fails the whole set, naming the port, and releases the ports
// already bound: half an accept set is worse than none, because nobody can reason about it.
func TestAcceptIsAllOrNothing(t *testing.T) {
	var opened []net.Listener
	tun := &Tunnel{}
	err := tun.installAcceptor([]AcceptRule{{Port: 22, Target: "127.0.0.1:22"}, {Port: 2222, Target: "127.0.0.1:22"}},
		AcceptOptions{Permit: permitAll}, func(port int) (net.Listener, error) {
			if port == 2222 {
				return nil, errors.New("address in use")
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			opened = append(opened, ln)
			return ln, err
		})
	if err == nil || !strings.Contains(err.Error(), "port 2222") {
		t.Fatalf("err = %v, want one naming port 2222", err)
	}
	if c, derr := net.DialTimeout("tcp", opened[0].Addr().String(), 200*time.Millisecond); derr == nil {
		c.Close()
		t.Fatal("port 22 was left open after the set failed")
	}
}

// Stop takes the accepted ports and every connection they carry down with the tunnel.
func TestStopClosesAcceptedConnections(t *testing.T) {
	tun, addr := acceptOnLoopback(t, holdTarget(t), AcceptOptions{Permit: permitAll})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	acceptWait(t, 2*time.Second, "the connection", func() bool { return tun.AcceptStats().Open >= 1 })
	if got := tun.Accepting(); len(got) != 1 || got[0].String() != "22 -> "+got[0].Target {
		t.Fatalf("Accepting = %v", got)
	}
	tun.stopAccept()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection survived Stop")
	}
	if len(tun.Accepting()) != 0 {
		t.Fatal("a stopped tunnel still reports accepted ports")
	}
	if c2, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
		c2.Close()
		t.Fatal("the listener survived Stop")
	}
}

// --- through a real tunnel -------------------------------------------------------------

// The whole path, with nothing simulated: a real userspace WireGuard handshake on loopback,
// then the far end of the tunnel opens a TCP connection to the client's own /128 on the
// accepted port, and the client splices it to a service on its loopback. This is the shape of
// `whale ssh` reaching a userspace node, which used to meet a reset.
func TestAcceptThroughARealTunnelReachesTheLocalService(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake e2e in -short")
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::22")
	srv := startServerSide(t, clientPubHex, clientIP, 7001)
	cfg, err := FromWgQuick(srv.pubB64, net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(), srv.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	cfg.Keepalive = 1
	tun, err := Start(cfg, Options{DialTimeout: 5 * time.Second, HealthInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	var callers []netip.Addr
	var mu sync.Mutex
	if err := tun.Accept([]AcceptRule{{Port: 22, Target: localTarget(t)}}, AcceptOptions{
		Permit: func(a netip.Addr) bool {
			mu.Lock()
			callers = append(callers, a)
			mu.Unlock()
			return a == srv.serverIP
		},
	}); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	dst := &net.TCPAddr{IP: clientIP.AsSlice(), Port: 22}
	var reply string
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, derr := srv.tnet.DialTCP(dst)
		if derr == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "SSH-2.0-test")
			_ = c.CloseWrite()
			b, _ := io.ReadAll(c)
			c.Close()
			reply = string(b)
			if reply != "" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("never reached the accepted port through the tunnel (last: %v, %q)", derr, reply)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if reply != "got 12 bytes: SSH-2.0-test" {
		t.Fatalf("reply = %q", reply)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(callers) == 0 || callers[0] != srv.serverIP {
		t.Fatalf("the access decision saw %v, want the far end's address %s", callers, srv.serverIP)
	}

	// The set is fixed for the tunnel's lifetime: a second Accept is refused and the first one
	// keeps serving, rather than closing it and then failing to bind its ports again.
	if err := tun.Accept([]AcceptRule{{Port: 2200, Target: localTarget(t)}}, AcceptOptions{Permit: permitAll}); err == nil {
		t.Fatal("a second Accept was taken")
	}
	if got := tun.Accepting(); len(got) != 1 || got[0].Port != 22 {
		t.Fatalf("after a refused second Accept: %v", got)
	}

	// A port that was NOT accepted is still closed: the netstack resets it.
	if c, derr := srv.tnet.DialTCP(&net.TCPAddr{IP: clientIP.AsSlice(), Port: 2222}); derr == nil {
		c.Close()
		t.Fatal("a port nobody accepted answered")
	}
}

// A fleet changes while a session runs. A caller revoked mid-session loses the connection it
// already has, not only the next one.
func TestRevalidateClosesAConnectionNoLongerPermitted(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	tun, addr := acceptOnLoopback(t, holdTarget(t), AcceptOptions{Permit: func(netip.Addr) bool { return allowed.Load() }})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	acceptWait(t, 2*time.Second, "the connection", func() bool { return tun.AcceptStats().Open == 1 })
	if n := tun.RevalidateAccept(); n != 0 {
		t.Fatalf("revalidation closed %d permitted connection(s)", n)
	}
	allowed.Store(false)
	if n := tun.RevalidateAccept(); n != 1 {
		t.Fatalf("revalidation closed %d, want the one no longer permitted", n)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the revoked caller's connection stayed open")
	}
	acceptWait(t, 2*time.Second, "the slot to be released", func() bool { return tun.AcceptStats().Open == 0 })
}

// Stop must not wait out a dial to a local service that is not answering.
func TestStopDoesNotWaitOutALocalDial(t *testing.T) {
	dialing := make(chan struct{})
	tun, addr := acceptOnLoopback(t, "127.0.0.1:22", AcceptOptions{Permit: permitAll, DialTimeout: time.Minute,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-dialing
	done := make(chan struct{})
	go func() { tun.stopAccept(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop waited on a dial in flight")
	}
}

// One stranger cannot write the operator's log at handshake rate: each source is named once a
// window and the rest are counted into one line.
func TestRefusalsAreNamedOnceAndCounted(t *testing.T) {
	var r refusalLog
	msg := func(a netip.Addr) string { return "whisper: accept :22 refused " + a.String() + ": not permitted" }
	t0 := time.Date(2026, 10, 27, 23, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("2001:db8::1")
	if line := r.note(src, msg(src), t0); !strings.Contains(line, "refused 2001:db8::1") {
		t.Fatalf("first refusal = %q", line)
	}
	for i := 0; i < 1000; i++ {
		if line := r.note(src, msg(src), t0.Add(time.Second)); line != "" {
			t.Fatalf("refusal %d was logged again: %q", i, line)
		}
	}
	for i := 0; i < 2*refusalNamedMax; i++ {
		// Each in its own /64: the log names a /64 once, as the limits count it.
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 7: byte(i + 2), 15: 1})
		_ = r.note(a, msg(a), t0.Add(2*time.Second))
	}
	// 1000 repeats of the first source, plus the 64 new ones less the 31 that still fit the
	// named allowance, are counted rather than named.
	line := r.note(src, msg(src), t0.Add(refusalWindow+time.Second))
	if !strings.Contains(line, "turned away 1033 more connection(s)") || !strings.Contains(line, "refused 2001:db8::1") {
		t.Fatalf("the window turn = %q", line)
	}
}

func TestThePerCallerLimitCountsAWholeSlash64(t *testing.T) {
	a := netip.MustParseAddr("2001:db8:1:2::1")
	b := netip.MustParseAddr("2001:db8:1:2:ffff::9")
	if sourceBucket(a) != sourceBucket(b) {
		t.Fatalf("two addresses in one /64 counted apart: %s %s", sourceBucket(a), sourceBucket(b))
	}
	if sourceBucket(a) == sourceBucket(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("two /64s counted together")
	}
	if got := sourceBucket(netip.MustParseAddr("192.0.2.7")); got.Bits() != 32 {
		t.Fatalf("IPv4 bucket = %s", got)
	}
}

// A caller the operator knows by name is one caller: agents of one owner may share a /64,
// and pooling them would cap the whole fleet at MaxPerSource.
func TestAnIndividualCallerIsCountedAlone(t *testing.T) {
	a := &acceptor{opts: AcceptOptions{Individual: func(x netip.Addr) bool { return x.Is6() && x.As16()[15] < 100 }}.withDefaults()}
	one, two := netip.MustParseAddr("2a04:2a01:1:2::7"), netip.MustParseAddr("2a04:2a01:1:2::8")
	if a.bucket(one) == a.bucket(two) {
		t.Fatalf("two fleet members in one /64 share a bucket: %s", a.bucket(one))
	}
	stranger := netip.MustParseAddr("2a04:2a01:1:2::ff")
	if got := a.bucket(stranger); got.Bits() != 64 {
		t.Fatalf("a stranger is counted by %s, want its /64", got)
	}
}

// The bucket a connection was counted under is the one it is released from, even when the
// caller's standing changed while it was open: otherwise a slot leaks and, after enough of
// them, a whole /64 is locked out until the tunnel renews.
func TestASlotIsReleasedFromTheBucketItWasTakenFrom(t *testing.T) {
	var member atomic.Bool
	member.Store(true)
	// Over IPv6 loopback, where a caller's own /128 and its /64 are different buckets.
	tun := &Tunnel{}
	var addr string
	if err := tun.installAcceptor([]AcceptRule{{Port: 22, Target: holdTarget(t)}}, AcceptOptions{Permit: permitAll,
		Individual: func(netip.Addr) bool { return member.Load() }}, func(int) (net.Listener, error) {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err == nil {
			addr = ln.Addr().String()
		}
		return ln, err
	}); err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	t.Cleanup(tun.stopAccept)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	acceptWait(t, 2*time.Second, "the connection", func() bool { return tun.AcceptStats().Open == 1 })
	member.Store(false) // the caller's standing changes while the connection is open
	c.Close()
	acceptWait(t, 2*time.Second, "the release", func() bool { return tun.AcceptStats().Open == 0 })
	a := tun.currentAcceptor()
	a.mu.Lock()
	left := len(a.perSrc)
	a.mu.Unlock()
	if left != 0 {
		t.Fatalf("a slot leaked: %d bucket(s) still counted after every connection closed", left)
	}
}

// One caller rotating through the addresses of its /64 is one source to the log, as it is to the
// limits, so it cannot use up every named line and hide the other refusals of the window.
func TestARotatingSlash64IsNamedOnce(t *testing.T) {
	var r refusalLog
	t0 := time.Date(2026, 10, 28, 6, 0, 0, 0, time.UTC)
	for i := 0; i < 2*refusalNamedMax; i++ {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i + 1)})
		if line := r.note(a, "rotating "+a.String(), t0); line != "" && i > 0 {
			t.Fatalf("address %d of one /64 was named again: %q", i, line)
		}
	}
	other := netip.MustParseAddr("2001:db8:0:1::1")
	if line := r.note(other, "other "+other.String(), t0); !strings.Contains(line, "other 2001:db8:0:1::1") {
		t.Fatalf("a second caller was not named after one /64 rotated: %q", line)
	}
}

// The count of the last window is told when the acceptor closes, not lost because no refusal
// came after it.
func TestTheLastWindowsCountIsToldOnClose(t *testing.T) {
	var r refusalLog
	t0 := time.Date(2026, 10, 28, 6, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("192.0.2.9")
	_ = r.note(src, "first", t0)
	_ = r.note(src, "again", t0)
	_ = r.note(src, "again", t0)
	if line := r.flush(t0.Add(10 * time.Second)); !strings.Contains(line, "turned away 2 more connection(s)") {
		t.Fatalf("flush = %q", line)
	}
	if line := r.flush(t0.Add(11 * time.Second)); line != "" {
		t.Fatalf("a second flush repeated the count: %q", line)
	}
}

// holdingDial is a local target that answers and stays open until the test ends, so every
// admitted connection stays counted while the test looks.
func holdingDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		c, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		return c, nil
	}
}

// remoteConn is one half of a pipe that says it came from a chosen address.
type remoteConn struct {
	net.Conn
	from net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.from }

// Strangers together hold at most three quarters of MaxConns: a caller with a /48 opening the
// per-caller limit from each of a few /64s cannot fill every slot and turn the fleet away.
func TestStrangersCannotTakeTheFleetsReservedShare(t *testing.T) {
	fleet := netip.MustParseAddr("2a04:2a01:1:2::7")
	a, err := newAcceptor([]AcceptRule{{Port: 22, Target: "127.0.0.1:22"}}, AcceptOptions{
		Permit: permitAll, MaxConns: 8, MaxPerSource: 2,
		Individual: func(x netip.Addr) bool { return x == fleet },
		Dial:       holdingDial(t),
	}, func(int) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	dial := func(from netip.Addr) {
		c, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		a.admit(remoteConn{c, &net.TCPAddr{IP: net.IP(from.AsSlice()), Port: 40000}}, a.rules[0])
	}
	// Four /64s of one /48, two connections each: eight asked, six (8 - 8/4) admitted.
	for n := 0; n < 4; n++ {
		for k := 0; k < 2; k++ {
			dial(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x99, 7: byte(n), 15: byte(k + 1)}))
		}
	}
	if st := a.stats(); st.Open != 6 || st.Limited != 2 {
		t.Fatalf("strangers: open=%d limited=%d, want 6 and 2", st.Open, st.Limited)
	}
	dial(fleet)
	dial(fleet)
	if st := a.stats(); st.Open != 8 {
		t.Fatalf("the fleet member was turned away: open=%d limited=%d", st.Open, st.Limited)
	}
	a.mu.Lock()
	strangers := a.strangers
	a.mu.Unlock()
	if strangers != 6 {
		t.Fatalf("strangers counted %d, want 6", strangers)
	}
}

// With no notion of a fleet (Individual nil) nothing is reserved: every slot is anyone's.
func TestNoReserveWithoutAFleet(t *testing.T) {
	a, err := newAcceptor([]AcceptRule{{Port: 22, Target: "127.0.0.1:22"}}, AcceptOptions{
		Permit: permitAll, MaxConns: 4, MaxPerSource: 4,
		Dial: holdingDial(t),
	}, func(int) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	for k := 0; k < 4; k++ {
		c, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		a.admit(remoteConn{c, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000 + k}}, a.rules[0])
	}
	if st := a.stats(); st.Open != 4 {
		t.Fatalf("open=%d limited=%d, want all 4 admitted", st.Open, st.Limited)
	}
}

// A small MaxConns still keeps one slot for the fleet: a quarter of 3 rounds to nothing.
func TestASmallLimitStillKeepsOneSlotForTheFleet(t *testing.T) {
	for _, c := range []struct{ max, want int }{{1, 1}, {2, 1}, {3, 2}, {4, 3}, {64, 48}} {
		a := &acceptor{opts: AcceptOptions{MaxConns: c.max}}
		if got := a.strangerCap(); got != c.want {
			t.Errorf("MaxConns %d: strangers may hold %d, want %d", c.max, got, c.want)
		}
	}
}
