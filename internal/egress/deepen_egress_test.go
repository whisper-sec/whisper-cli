// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// "deepen-egress" tests: the tier seam (StartWithDialer - how the
// WireGuard tier reuses the hardened front-end), the upstream CONNECT error
// mapping + bearer hygiene, the SOCKS5/HTTP malformed-input branches, dial
// observation, host normalization, and the early-bytes-after-CONNECT
// preservation path. All new helpers are prefixed deepenegress_ so they stay
// clearly apart from the wave 0-7 suite's helpers in this package.

package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// deepenegress_recordingDialer is a same-package Dialer standing in for either
// tier's upstream leg. It records every target exactly as the front-end handed
// it over (the pass-through contract: the NAME/literal the client asked for,
// never rewritten), dials a local backend on success, and fails on demand.
type deepenegress_recordingDialer struct {
	mu      sync.Mutex
	targets []string
	backend string          // host:port to actually dial; "" means always fail
	failFor map[string]bool // targets that fail even with a backend
	wrap    func(net.Conn) net.Conn
}

func (d *deepenegress_recordingDialer) Dial(_ context.Context, target string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, target)
	fail := d.backend == "" || d.failFor[target]
	backend := d.backend
	wrap := d.wrap
	d.mu.Unlock()
	if fail {
		return nil, errors.New("deepenegress: forced dial failure")
	}
	c, err := net.Dial("tcp", backend)
	if err != nil {
		return nil, err
	}
	if wrap != nil {
		return wrap(c), nil
	}
	return c, nil
}

func (d *deepenegress_recordingDialer) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// deepenegress_obsRec is one observed dial: who asked, for what, denied?
type deepenegress_obsRec struct {
	client string
	target string
	denied bool
}

// deepenegress_obsRecorder is a race-safe DialObserver sink.
type deepenegress_obsRecorder struct {
	mu   sync.Mutex
	recs []deepenegress_obsRec
}

func (r *deepenegress_obsRecorder) observe(client net.Addr, target string, denied bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addr := ""
	if client != nil {
		addr = client.String()
	}
	r.recs = append(r.recs, deepenegress_obsRec{client: addr, target: target, denied: denied})
}

func (r *deepenegress_obsRecorder) snapshot() []deepenegress_obsRec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]deepenegress_obsRec(nil), r.recs...)
}

// deepenegress_rawExchange dials the local proxy, writes raw bytes, half-closes
// its write side (FIN), and returns EVERYTHING the proxy sent back until EOF.
// A nil returned error means the proxy closed the conn cleanly; a mutated
// front-end that leaves the conn open (or replies when it must not) surfaces
// here as a deadline error or as unexpected extra bytes.
func deepenegress_rawExchange(t *testing.T, proxyAddr string, raw []byte) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer c.Close()
	if len(raw) > 0 {
		if _, err := c.Write(raw); err != nil {
			t.Fatalf("write raw bytes: %v", err)
		}
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return io.ReadAll(c)
}

// deepenegress_socksRep is the exact 10-byte SOCKS5 reply the proxy must emit
// for the given REP code: a CONCRETE 0.0.0.0:0 IPv4 bind, which some clients require.
func deepenegress_socksRep(rep byte) []byte {
	return []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// deepenegress_closedPort binds an ephemeral loopback port, releases it, and
// returns the now-closed address - a deterministic connection-refused target.
func deepenegress_closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// deepenegress_notTLSServer is an "egress" that speaks no TLS at all: it
// answers every connection with plaintext garbage and closes. The TLS
// handshake on the client leg must fail cleanly against it.
func deepenegress_notTLSServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("not-tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.WriteString(c, "definitely not a TLS server\r\n")
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// deepenegress_muteTLSEgress completes the TLS handshake, reads the CONNECT
// request, then closes WITHOUT ever writing a reply - the "CONNECT reply
// unreadable" shape.
func deepenegress_muteTLSEgress(t *testing.T) string {
	t.Helper()
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("mute egress listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf) // drives the handshake + absorbs the CONNECT, then close
			}()
		}
	}()
	return ln.Addr().String()
}

// deepenegress_earlyByteEgress is a TLS CONNECT egress that flushes the 200
// reply AND some early tunnel bytes in ONE write (one TLS record), then echoes
// everything that follows. A correct client preserves those early bytes
// (prefixedConn) instead of dropping whatever its bufio reader had buffered
// past the reply.
func deepenegress_earlyByteEgress(t *testing.T, early string) string {
	t.Helper()
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("early-byte egress listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				// Reply + early bytes in a single Write: one TLS record, so the
				// client's bufio fill buffers them together behind the reply.
				if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"+early); err != nil {
					return
				}
				_, _ = io.Copy(c, br) // echo the rest of the tunnel
			}()
		}
	}()
	return ln.Addr().String()
}

// deepenegress_noCloseWrite hides the underlying TCP conn's CloseWrite (an
// embedded interface promotes only interface methods), modeling a Dialer whose
// conns cannot half-close - the halfClose full-Close fallback path.
type deepenegress_noCloseWrite struct {
	net.Conn
	closed atomic.Bool
}

func (c *deepenegress_noCloseWrite) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// --- the tests -----------------------------------------------------------------------

// TestDeepenEgress_StartWithDialer_TierSeam: the WG-tier constructor. A custom
// Dialer gets the SAME front-end (SOCKS5 accept, name pass-through, splice), the
// onStop teardown runs EXACTLY once even under concurrent Stop()s, and after
// Stop the listener is gone. Guards the seam every non-egress tier rides.
func TestDeepenEgress_StartWithDialer_TierSeam(t *testing.T) {
	d := &deepenegress_recordingDialer{backend: echoBackend(t)}
	var stops atomic.Int32
	p, err := StartWithDialer(d, func() { stops.Add(1) })
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	if !strings.HasPrefix(p.Endpoint(), "socks5h://127.0.0.1:") {
		t.Fatalf("endpoint = %q, want socks5h://127.0.0.1:<port>", p.Endpoint())
	}

	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial through dialer-backed proxy: %v", err)
	}
	msg := "via-custom-dialer"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	conn.Close()

	// The dialer must have been handed the NAME the client asked for, unchanged.
	if got := d.seen(); len(got) != 1 || got[0] != "example.com:80" {
		t.Fatalf("dialer saw targets %v, want exactly [example.com:80]", got)
	}

	// Concurrent + repeated Stop: idempotent, and onStop runs exactly once,
	// after the drain (the WG-device teardown contract).
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.Stop() }()
	}
	wg.Wait()
	p.Stop()
	if n := stops.Load(); n != 1 {
		t.Fatalf("onStop ran %d times, want exactly 1", n)
	}
	if c, err := net.DialTimeout("tcp", p.Addr(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("after Stop the dialer-backed proxy must no longer accept connections")
	}
}

// TestDeepenEgress_StartWithDialerPort: a nil Dialer is a clean error (never a
// panic later), and a pinned port really pins the local address, so the two
// tiers look the same on the local surface.
func TestDeepenEgress_StartWithDialerPort(t *testing.T) {
	if _, err := StartWithDialerPort(nil, nil, 0); err == nil || !strings.Contains(err.Error(), "nil dialer") {
		t.Fatalf("nil dialer error = %v, want a clear 'nil dialer' error", err)
	}

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pinned := probe.Addr().String()
	_ = probe.Close()
	_, portStr, _ := net.SplitHostPort(pinned)
	var want int
	for _, r := range portStr {
		want = want*10 + int(r-'0')
	}

	d := &deepenegress_recordingDialer{backend: echoBackend(t)}
	p, err := StartWithDialerPort(d, nil, want)
	if err != nil {
		t.Fatalf("StartWithDialerPort(pinned): %v", err)
	}
	t.Cleanup(p.Stop)
	if p.Addr() != pinned {
		t.Fatalf("pinned addr = %q, want %q", p.Addr(), pinned)
	}
	conn, err := socks5Dial(p.Addr(), "pinned.example:443")
	if err != nil {
		t.Fatalf("dial through pinned proxy: %v", err)
	}
	conn.Close()
	if got := d.seen(); len(got) != 1 || got[0] != "pinned.example:443" {
		t.Fatalf("dialer saw %v, want [pinned.example:443]", got)
	}
}

// TestDeepenEgress_DialObserver is the observation contract: an installed
// observer sees every upstream dial (client loopback addr, the EXACT requested
// target, denied on failure), nil clears it, and a replacement takes over.
// Observation must never change tunnel behavior either way.
func TestDeepenEgress_DialObserver(t *testing.T) {
	d := &deepenegress_recordingDialer{
		backend: echoBackend(t),
		failFor: map[string]bool{"deny.example:80": true},
	}
	p, err := StartWithDialer(d, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(p.Stop)

	obs1 := &deepenegress_obsRecorder{}
	p.SetDialObserver(obs1.observe)

	// A successful dial is observed with denied=false and the exact target.
	conn, err := socks5Dial(p.Addr(), "ok.example:80")
	if err != nil {
		t.Fatalf("dial ok.example: %v", err)
	}
	conn.Close()
	// A denied dial is observed with denied=true, and the client sees rep=5.
	if _, err := socks5Dial(p.Addr(), "deny.example:80"); err == nil {
		t.Fatal("a failed upstream dial must reject the SOCKS connect")
	} else if !strings.Contains(err.Error(), "rep=5") {
		t.Fatalf("denied dial error = %v, want the generic rep=5 refusal", err)
	}

	recs := obs1.snapshot()
	if len(recs) != 2 {
		t.Fatalf("observer saw %d dials, want 2: %v", len(recs), recs)
	}
	if recs[0].target != "ok.example:80" || recs[0].denied {
		t.Fatalf("first observation = %+v, want ok.example:80 denied=false", recs[0])
	}
	if recs[1].target != "deny.example:80" || !recs[1].denied {
		t.Fatalf("second observation = %+v, want deny.example:80 denied=true", recs[1])
	}
	for _, r := range recs {
		host, _, err := net.SplitHostPort(r.client)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("observed client addr = %q, want a 127.0.0.1:<port> loopback", r.client)
		}
	}

	// nil clears the observer: further dials are NOT delivered to obs1.
	p.SetDialObserver(nil)
	conn2, err := socks5Dial(p.Addr(), "ok.example:80")
	if err != nil {
		t.Fatalf("dial after clearing observer: %v", err)
	}
	conn2.Close()
	if got := len(obs1.snapshot()); got != 2 {
		t.Fatalf("after SetDialObserver(nil) obs1 grew to %d records, want still 2", got)
	}

	// A replacement observer takes over.
	obs2 := &deepenegress_obsRecorder{}
	p.SetDialObserver(obs2.observe)
	conn3, err := socks5Dial(p.Addr(), "ok.example:80")
	if err != nil {
		t.Fatalf("dial with replacement observer: %v", err)
	}
	conn3.Close()
	if recs2 := obs2.snapshot(); len(recs2) != 1 || recs2[0].target != "ok.example:80" || recs2[0].denied {
		t.Fatalf("replacement observer saw %v, want one ok.example:80 denied=false", recs2)
	}
}

// TestDeepenEgress_SocksMalformedAndLiterals drives the SOCKS5 front-end's
// negative branches byte-by-byte and asserts the EXACT reply stream for each:
// a non-CONNECT command gets rep=7, an unknown/truncated address gets rep=8,
// and a request truncated before the address stage gets NO reply at all - just
// a clean close. Crucially, NO malformed request may ever reach the upstream
// Dialer (asserted via the recording dialer AND the observer), and the
// proxy must stay healthy afterwards. The v4/v6-literal successes also pin the
// pass-through contract: the literal reaches the Dialer byte-identically.
func TestDeepenEgress_SocksMalformedAndLiterals(t *testing.T) {
	d := &deepenegress_recordingDialer{backend: echoBackend(t)}
	p, err := StartWithDialer(d, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(p.Stop)
	obs := &deepenegress_obsRecorder{}
	p.SetDialObserver(obs.observe)

	greet := []byte{0x05, 0x01, 0x00}
	methodOK := []byte{0x05, 0x00}
	malformed := []struct {
		name string
		raw  []byte
		want []byte
	}{
		// Truncated before the request stage: close with NO reply bytes at all.
		{"greeting only a version byte", []byte{0x05}, nil},
		{"greeting claims 2 methods sends 1", []byte{0x05, 0x02, 0x00}, nil},
		{"request header truncated", append(append([]byte{}, greet...), 0x05, 0x01), methodOK},
		// A recognised request with a bad command: rep=7 (command not supported).
		{"BIND command", append(append([]byte{}, greet...), 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x07)...)},
		// Unknown or truncated address stage: rep=8 (address type not supported).
		{"unknown ATYP 0x02", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x02), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
		{"IPv4 address truncated", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x01, 127, 0), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
		{"domain length byte missing", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x03), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
		{"domain name truncated", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x03, 10, 'a', 'b'), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
		{"IPv6 address truncated", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 1), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
		{"port truncated", append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0), append(append([]byte{}, methodOK...), deepenegress_socksRep(0x08)...)},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deepenegress_rawExchange(t, p.Addr(), tc.raw)
			if err != nil {
				t.Fatalf("the proxy did not close the conn cleanly: %v (got %v)", err, got)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("reply bytes = %v, want %v", got, tc.want)
			}
		})
	}
	if got := d.seen(); len(got) != 0 {
		t.Fatalf("a malformed SOCKS request reached the upstream dialer: %v", got)
	}
	if got := obs.snapshot(); len(got) != 0 {
		t.Fatalf("a malformed SOCKS request was observed as a dial: %v", got)
	}

	// IPv4 literal: passed to the Dialer byte-identically, success rep=0, and
	// (with the client's immediate FIN) the tunnel drains to a clean EOF.
	v4 := append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80)
	wantOK := append(append([]byte{}, methodOK...), deepenegress_socksRep(0x00)...)
	got, err := deepenegress_rawExchange(t, p.Addr(), v4)
	if err != nil || !bytes.Equal(got, wantOK) {
		t.Fatalf("IPv4-literal connect: reply=%v err=%v, want %v with clean EOF", got, err, wantOK)
	}
	// IPv6 literal ::1, port 8080.
	v6 := append(append([]byte{}, greet...), 0x05, 0x01, 0x00, 0x04)
	v6 = append(v6, make([]byte, 15)...)
	v6 = append(v6, 1, 0x1f, 0x90)
	got, err = deepenegress_rawExchange(t, p.Addr(), v6)
	if err != nil || !bytes.Equal(got, wantOK) {
		t.Fatalf("IPv6-literal connect: reply=%v err=%v, want %v with clean EOF", got, err, wantOK)
	}
	if targets := d.seen(); len(targets) != 2 || targets[0] != "127.0.0.1:80" || targets[1] != "[::1]:8080" {
		t.Fatalf("literal targets reached the dialer as %v, want [127.0.0.1:80 [::1]:8080] unchanged", targets)
	}

	// And after the whole barrage the proxy still serves a normal client.
	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("proxy unhealthy after malformed barrage: %v", err)
	}
	conn.Close()
}

// TestDeepenEgress_HTTPNegatives drives the HTTP front-end's refusal branches:
// a non-CONNECT method is a clean 405 (we are a tunnel proxy, and we never echo
// the URL), a CONNECT without a host is a 400, an upstream dial failure is a
// 502 observed as denied, and an unparseable request is a bare close. None of
// the refused requests may reach the Dialer.
func TestDeepenEgress_HTTPNegatives(t *testing.T) {
	d := &deepenegress_recordingDialer{
		backend: echoBackend(t),
		failFor: map[string]bool{"refused.example:80": true},
	}
	p, err := StartWithDialer(d, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(p.Stop)
	obs := &deepenegress_obsRecorder{}
	p.SetDialObserver(obs.observe)

	// Plain GET: 405, connection closed.
	got, err := deepenegress_rawExchange(t, p.Addr(), []byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatalf("405 path did not close cleanly: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 405 ") {
		t.Fatalf("non-CONNECT reply = %q, want an HTTP/1.1 405", got)
	}
	if strings.Contains(string(got), "example.com") {
		t.Fatalf("the 405 reply echoed the request URL: %q", got)
	}

	// CONNECT with no authority and no Host header: 400.
	got, err = deepenegress_rawExchange(t, p.Addr(), []byte("CONNECT / HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatalf("400 path did not close cleanly: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 400 ") {
		t.Fatalf("empty-host CONNECT reply = %q, want an HTTP/1.1 400", got)
	}
	if len(d.seen()) != 0 || len(obs.snapshot()) != 0 {
		t.Fatalf("a refused pre-dial request reached the dialer/observer: %v / %v", d.seen(), obs.snapshot())
	}

	// A CONNECT whose upstream dial fails: 502, and observed as denied.
	got, err = deepenegress_rawExchange(t, p.Addr(), []byte("CONNECT refused.example:80 HTTP/1.1\r\nHost: refused.example:80\r\n\r\n"))
	if err != nil {
		t.Fatalf("502 path did not close cleanly: %v", err)
	}
	if !strings.HasPrefix(string(got), "HTTP/1.1 502 ") {
		t.Fatalf("failed-dial CONNECT reply = %q, want an HTTP/1.1 502", got)
	}
	recs := obs.snapshot()
	if len(recs) != 1 || recs[0].target != "refused.example:80" || !recs[0].denied {
		t.Fatalf("failed HTTP dial observation = %v, want one refused.example:80 denied=true", recs)
	}

	// An unparseable request (not SOCKS, not HTTP): bare close, zero reply bytes.
	got, err = deepenegress_rawExchange(t, p.Addr(), []byte("GARBAGE\r\n\r\n"))
	if err != nil {
		t.Fatalf("garbage path did not close cleanly: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("garbage request got a reply %q, want a bare close", got)
	}
}

// TestDeepenEgress_UpstreamErrorMapping exercises the egress tier's four dial
// failure classes against real (local) failure shapes and asserts each maps to
// its fixed, NON-LEAKY message: the bearer (raw or base64-encoded) must never
// appear in any error, whatever went wrong. This is the bearer-hygiene property
// the package header calls THE load-bearing security property.
func TestDeepenEgress_UpstreamErrorMapping(t *testing.T) {
	const bearer = "et_hygiene_canary_7f3"
	b64 := base64.StdEncoding.EncodeToString([]byte("w:" + bearer))

	newUpstream := func(t *testing.T, egressAddr string) *upstream {
		t.Helper()
		p, err := StartLocalProxy(context.Background(), egressAddr, bearer, Options{Insecure: true, DialTimeout: 3 * time.Second})
		if err != nil {
			t.Fatalf("StartLocalProxy: %v", err)
		}
		t.Cleanup(p.Stop)
		u, ok := p.dialer.(*upstream)
		if !ok {
			t.Fatalf("StartLocalProxy dialer is %T, want *upstream", p.dialer)
		}
		return u
	}
	assertClean := func(t *testing.T, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatalf("dial must fail with %q, got nil", want)
		}
		if err.Error() != want {
			t.Fatalf("error = %q, want exactly %q", err.Error(), want)
		}
		if strings.Contains(err.Error(), bearer) || strings.Contains(err.Error(), b64) {
			t.Fatalf("the error leaked the bearer: %q", err.Error())
		}
	}

	t.Run("egress unreachable", func(t *testing.T) {
		u := newUpstream(t, deepenegress_closedPort(t))
		_, err := u.Dial(context.Background(), "example.com:443")
		assertClean(t, err, "cannot reach the Whisper egress")
	})
	t.Run("egress speaks no TLS", func(t *testing.T) {
		u := newUpstream(t, deepenegress_notTLSServer(t))
		_, err := u.Dial(context.Background(), "example.com:443")
		assertClean(t, err, "TLS handshake to the Whisper egress failed")
	})
	t.Run("egress never answers the CONNECT", func(t *testing.T) {
		u := newUpstream(t, deepenegress_muteTLSEgress(t))
		_, err := u.Dial(context.Background(), "example.com:443")
		assertClean(t, err, "egress CONNECT reply unreadable")
	})
	t.Run("egress refuses with a non-407 status", func(t *testing.T) {
		// The fake egress 502s when its backend is unreachable: the generic branch.
		fe := newFakeEgress(t, deepenegress_closedPort(t), nil)
		u := newUpstream(t, fe.addr())
		_, err := u.Dial(context.Background(), "example.com:443")
		assertClean(t, err, "the Whisper egress refused the connection")
	})
	t.Run("egress rejects the bearer with 407", func(t *testing.T) {
		fe := newFakeEgress(t, echoBackend(t), func(string) bool { return true })
		u := newUpstream(t, fe.addr())
		_, err := u.Dial(context.Background(), "example.com:443")
		// The remedy rides on THIS branch and no other: a rejected token is the one cause for
		// which "connect again" is true. It used to be printed for every cause.
		assertClean(t, err, "the Whisper egress rejected this session's token - "+
			"run `whisper connect` again to mint a fresh session")
	})
}

// TestDeepenEgress_HostNormalization pins StartLocalProxy's liberal-accept
// input handling (Postel): a bare hostname defaults to :443, a scheme /
// userinfo / path are stripped, the SNI is the hostname alone, the bearer is
// encoded exactly as Basic w:<bearer>, and the dial timeout defaults to 30s.
// White-box on the same-package upstream, because these values only otherwise
// surface against a live egress.
func TestDeepenEgress_HostNormalization(t *testing.T) {
	start := func(t *testing.T, host string, opts Options) *upstream {
		t.Helper()
		p, err := StartLocalProxy(context.Background(), host, "et_norm", opts)
		if err != nil {
			t.Fatalf("StartLocalProxy(%q): %v", host, err)
		}
		t.Cleanup(p.Stop)
		return p.dialer.(*upstream)
	}

	u := start(t, "egress.whisper.online", Options{})
	if u.host != "egress.whisper.online:443" {
		t.Fatalf("bare hostname normalized to %q, want egress.whisper.online:443", u.host)
	}
	if u.tlsConf.ServerName != "egress.whisper.online" {
		t.Fatalf("SNI = %q, want egress.whisper.online (hostname only, no port)", u.tlsConf.ServerName)
	}
	if u.dialTO != 30*time.Second {
		t.Fatalf("default dial timeout = %v, want 30s", u.dialTO)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("w:et_norm")); u.auth != want {
		t.Fatalf("auth header = %q, want %q", u.auth, want)
	}

	u2 := start(t, "https://w:tok@egress.example:8443/dns-query", Options{})
	if u2.host != "egress.example:8443" {
		t.Fatalf("scheme+userinfo+path normalized to %q, want egress.example:8443", u2.host)
	}
	if u2.tlsConf.ServerName != "egress.example" {
		t.Fatalf("SNI = %q, want egress.example", u2.tlsConf.ServerName)
	}

	// A caller-supplied TLS config is used as-is when Insecure is off...
	conf := &tls.Config{ServerName: "custom.example", MinVersion: tls.VersionTLS12}
	u3 := start(t, "egress.example:443", Options{TLSConfig: conf})
	if u3.tlsConf != conf {
		t.Fatal("a caller TLS config must be used as-is (same pointer) when Insecure is off")
	}
	// ...and Insecure clones it: the flag lands on the clone, NEVER mutates the
	// caller's config (a mutated shared config would silently disable
	// verification for every other user of it).
	u4 := start(t, "egress.example:443", Options{TLSConfig: conf, Insecure: true})
	if u4.tlsConf == conf {
		t.Fatal("Insecure must clone the caller's TLS config, not mutate it in place")
	}
	if !u4.tlsConf.InsecureSkipVerify {
		t.Fatal("Insecure did not set InsecureSkipVerify on the clone")
	}
	if conf.InsecureSkipVerify {
		t.Fatal("Insecure mutated the CALLER's TLS config - the shared-config foot-gun")
	}
	if u4.tlsConf.ServerName != "custom.example" {
		t.Fatalf("the clone lost ServerName: %q", u4.tlsConf.ServerName)
	}

	u5 := start(t, "egress.example:443", Options{DialTimeout: 7 * time.Second})
	if u5.dialTO != 7*time.Second {
		t.Fatalf("explicit dial timeout = %v, want 7s", u5.dialTO)
	}
}

// TestDeepenEgress_StripScheme covers the input-normalization table directly:
// every liberal-accept shape a caller might paste lands on bare host:port.
func TestDeepenEgress_StripScheme(t *testing.T) {
	cases := []struct{ in, want string }{
		{"egress.whisper.online:443", "egress.whisper.online:443"},
		{"https://egress.whisper.online:443", "egress.whisper.online:443"},
		{"https://user:secret@egress.whisper.online:443/path", "egress.whisper.online:443"},
		{"egress.whisper.online:443/dns-query", "egress.whisper.online:443"},
		{"user:secret@egress.whisper.online", "egress.whisper.online"},
		{"socks5://egress.whisper.online", "egress.whisper.online"},
	}
	for _, tc := range cases {
		if got := stripScheme(tc.in); got != tc.want {
			t.Fatalf("stripScheme(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeepenEgress_EarlyBytesAfterConnectPreserved: bytes the egress flushes in
// the SAME record as its 200 CONNECT reply are tunnel payload and MUST reach
// the client (prefixedConn), and the tunnel then continues on the live socket.
// A client that drops its buffered remainder corrupts every protocol where the
// server speaks first (SMTP/IMAP banners, an eager TLS-in-TLS ServerHello).
func TestDeepenEgress_EarlyBytesAfterConnectPreserved(t *testing.T) {
	const early = "EARLY"
	egress := deepenegress_earlyByteEgress(t, early)
	p := startProxy(t, egress, "et_early")

	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	// The early bytes arrive FIRST, before anything we send.
	buf := make([]byte, len(early))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("the early bytes after the CONNECT reply were dropped: %v", err)
	}
	if string(buf) != early {
		t.Fatalf("early bytes = %q, want %q", buf, early)
	}

	// And the tunnel keeps streaming from the live socket after the prefix.
	msg := "ping-after-prefix"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write after prefix: %v", err)
	}
	buf2 := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf2); err != nil {
		t.Fatalf("read echo after prefix: %v", err)
	}
	if string(buf2) != msg {
		t.Fatalf("post-prefix echo = %q, want %q", buf2, msg)
	}
}

// TestDeepenEgress_HalfCloseFallsBackToClose: when a Dialer's conns cannot
// half-close (no CloseWrite - a netstack or wrapped conn), the splice must fall
// back to a FULL close on the client's FIN so the tunnel still terminates
// instead of stranding both copies forever.
func TestDeepenEgress_HalfCloseFallsBackToClose(t *testing.T) {
	var lastWrap atomic.Pointer[deepenegress_noCloseWrite]
	d := &deepenegress_recordingDialer{
		backend: echoBackend(t),
		wrap: func(c net.Conn) net.Conn {
			w := &deepenegress_noCloseWrite{Conn: c}
			lastWrap.Store(w)
			return w
		},
	}
	p, err := StartWithDialer(d, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(p.Stop)

	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	msg := "before-fin"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// FIN the client's write half. With no CloseWrite on the upstream conn the
	// proxy must fully Close it, which ends the tunnel: our read side reaches a
	// clean EOF (bounded by the deadline - a stranded tunnel fails here).
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		t.Fatal("test client conn has no CloseWrite - cannot drive the FIN shape")
	}
	rest, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("tunnel did not terminate after the client FIN (halfClose fallback broken): %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes after FIN: %q", rest)
	}
	w := lastWrap.Load()
	if w == nil {
		t.Fatal("the wrapping dialer was never used")
	}
	if !w.closed.Load() {
		t.Fatal("the no-CloseWrite upstream conn was never fully Closed - the fallback is gone")
	}
}

// TestDeepenEgress_EmptyClientKeepsServing: a client that connects and closes
// without sending a single byte (a port-scan / health-probe shape) must not
// wedge or kill the accept loop - the very next real client still tunnels.
func TestDeepenEgress_EmptyClientKeepsServing(t *testing.T) {
	d := &deepenegress_recordingDialer{backend: echoBackend(t)}
	p, err := StartWithDialer(d, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(p.Stop)

	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", p.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("probe dial %d: %v", i, err)
		}
		_ = c.Close() // no bytes at all
	}

	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("proxy stopped serving after empty probes: %v", err)
	}
	defer conn.Close()
	msg := "still-serving"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}
