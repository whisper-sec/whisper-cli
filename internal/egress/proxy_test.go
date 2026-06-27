// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package egress

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// socks5Dial is a tiny inline SOCKS5 client (RFC 1928, no-auth, CONNECT by DOMAIN) so the
// proxy test needs NO external dependency. It returns the live tunnel conn through the
// local proxy at proxyAddr to target ("host:port").
func socks5Dial(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	// Greeting: VER=5, 1 method, NO-AUTH(0).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 method negotiation failed")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	var pnum int
	fmt.Sscanf(port, "%d", &pnum)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(pnum>>8), byte(pnum&0xff))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT — we expect REP=0 and ATYP=IPv4 (the WB0
	// gotcha #2: a concrete 0.0.0.0:0 bind, NOT a DOMAIN echo, so a client never hangs).
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect rejected (rep=%d)", head[1])
	}
	var bndLen int
	switch head[3] {
	case 0x01:
		bndLen = 4
	case 0x04:
		bndLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		bndLen = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, bndLen+2)); err != nil { // BND.ADDR + BND.PORT
		c.Close()
		return nil, err
	}
	return c, nil
}

// fakeEgress is a self-signed TLS HTTPS-CONNECT proxy standing in for
// egress.whisper.online:443. It records the Proxy-Authorization it received (so a test
// can assert the bearer was sent) and, on a 2xx, splices the tunnel to a real backend.
type fakeEgress struct {
	ln       net.Listener
	conf     *tls.Config
	mu       sync.Mutex
	sawAuth  []string // every Proxy-Authorization header value observed
	backend  string   // host:port the CONNECT target is wired to (the echo backend)
	rejectIf func(auth string) bool
}

func newFakeEgress(t *testing.T, backend string, reject func(string) bool) *fakeEgress {
	t.Helper()
	cert := selfSigned(t)
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatalf("fake egress listen: %v", err)
	}
	f := &fakeEgress{ln: ln, conf: conf, backend: backend, rejectIf: reject}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeEgress) addr() string { return f.ln.Addr().String() }

func (f *fakeEgress) auths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sawAuth...)
}

func (f *fakeEgress) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeEgress) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	auth := req.Header.Get("Proxy-Authorization")
	f.mu.Lock()
	f.sawAuth = append(f.sawAuth, auth)
	f.mu.Unlock()
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	if f.rejectIf != nil && f.rejectIf(auth) {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	}
	// Dial the real backend the CONNECT target is mapped to, then splice.
	up, err := net.Dial("tcp", f.backend)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	// Splice WITH half-close semantics (a correct CONNECT proxy propagates each side's FIN
	// independently and only fully closes once BOTH halves are done) — so this fake faithfully
	// carries the half-closed keep-alive shape the #154 regression test depends on.
	halfCloser := func(w net.Conn) {
		if cw, ok := w.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); halfCloser(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); halfCloser(c); done <- struct{}{} }()
	<-done
	<-done
}

// echoBackend is a tiny TCP server that echoes back whatever it receives (the "target").
func echoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo backend: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// idleBackend accepts + holds the connection open, reading-and-discarding but NEVER
// writing — the keep-alive / idle-upstream shape that hung Stop() before the splice
// close-both fix (an egress→client io.Copy parked reading a peer that never sends EOF).
func idleBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("idle backend: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return ln.Addr().String()
}

// TestProxy_StopDrainsWithIdleTunnel: with a tunnel established to an IDLE upstream (the
// egress→client copy parked reading a peer that never sends), Stop() must STILL return
// promptly — not park on wg.Wait() forever. Guards the live regression where `whisper ip`
// and `whisper run` hung (exit 124) instead of exiting 0 after their work, because the
// splice didn't force both ends shut when one direction ended.
func TestProxy_StopDrainsWithIdleTunnel(t *testing.T) {
	fe := newFakeEgress(t, idleBackend(t), nil)
	p := startProxy(t, fe.addr(), "et_idle")
	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("x")) // establish the tunnel; egress→client copy now parks on the idle upstream
	time.Sleep(100 * time.Millisecond)
	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() hung with an idle tunnel open — the splice close-both regression is back")
	}
}

// halfWriteBackend models the #154 ERR_SOCKET_CLOSED shape: on the accepted tunnel it
// reads the first request, writes ONE response, then CloseWrite()s its OWN write half
// (sends a FIN — an HTTP/1.1 origin that answered and ended that response) while KEEPING
// its READ half open, exactly as a keep-alive origin awaiting the client's next request.
// Any further bytes the client sends after the FIN are delivered on the `got` channel, so
// the test can prove the client→egress→target (WRITE) half SURVIVED the target's FIN —
// i.e. the proxy did NOT force the whole tunnel shut (which is the ERR_SOCKET_CLOSED bug).
func halfWriteBackend(t *testing.T, firstResp string, got chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("halfwrite backend: %v", err)
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
				buf := make([]byte, 256)
				_, _ = c.Read(buf) // first request from the client
				_, _ = io.WriteString(c, firstResp)
				if cw, ok := c.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite() // FIN on the TARGET→client half only
				}
				// Read half stays open: capture the follow-up the client sends so the test can
				// confirm the client→egress→target direction is still alive after the FIN.
				more := make([]byte, 256)
				n, _ := c.Read(more)
				if n > 0 && got != nil {
					got <- string(more[:n])
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startProxy boots the local forward proxy pointed at the fake egress with TLS verify
// disabled (the fake uses a self-signed cert).
func startProxy(t *testing.T, egressAddr, bearer string) *Proxy {
	t.Helper()
	p, err := StartLocalProxy(context.Background(), egressAddr, bearer, Options{Insecure: true, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	t.Cleanup(p.Stop)
	return p
}

// --- the tests ---------------------------------------------------------------------

// TestProxy_SocksTunnelsBytesAndSendsBearer: a SOCKS5 client through the local proxy
// reaches the echo backend (bytes stream), AND the fake egress saw the et_ bearer in the
// CONNECT Proxy-Authorization.
func TestProxy_SocksTunnelsBytesAndSendsBearer(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)
	p := startProxy(t, fe.addr(), "et_secret123")

	// The target host is sent as a NAME up to the egress (socks5h); the fake maps every
	// CONNECT to the echo backend, so "example.com:80" reaches it.
	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	msg := "hello-whisper"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q (bytes must stream end-to-end)", buf, msg)
	}

	// The bearer MUST have been presented to the egress as Basic w:<bearer>.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("w:et_secret123"))
	found := false
	for _, a := range fe.auths() {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("egress did not receive the bearer in Proxy-Authorization; saw %v", fe.auths())
	}
}

// TestProxy_HTTPConnectTunnels: an HTTP CONNECT client through the local proxy reaches the
// backend too (Postel: we accept both SOCKS5 and HTTP-CONNECT from the local client).
func TestProxy_HTTPConnectTunnels(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)
	p := startProxy(t, fe.addr(), "et_http")

	raw, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer raw.Close()
	if _, err := io.WriteString(raw, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("local CONNECT status = %d, want 200", resp.StatusCode)
	}
	msg := "via-http-connect"
	if _, err := io.WriteString(raw, msg); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

// TestProxy_HalfClosedTunnelSurvives is THE #154 regression guard: ERR_SOCKET_CLOSED.
//
// Claude Code's startup connectivity preflight runs through HTTPS_PROXY → our local proxy
// as an HTTP CONNECT (Node/undici). The target answers ONE response and FINs its write
// half (a Connection: close origin, or one keep-alive cycle), which makes the egress→client
// io.Copy reach EOF. The OLD splice slammed BOTH ends shut on that first EOF, RSTing the
// tunnel out from under a request undici still meant to finish/reuse — surfacing as
// ERR_SOCKET_CLOSED. The fix: on a natural one-way EOF we only HALF-close (propagate the
// FIN); the client→target direction stays open. This test drives exactly that shape and
// asserts a follow-up the client sends after the FIN still reaches the target and echoes
// back — i.e. the tunnel was NOT force-closed.
func TestProxy_HalfClosedTunnelSurvives(t *testing.T) {
	got := make(chan string, 1)
	backend := halfWriteBackend(t, "RESP1", got)
	fe := newFakeEgress(t, backend, nil)
	p := startProxy(t, fe.addr(), "et_preflight")

	raw, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer raw.Close()
	if _, err := io.WriteString(raw, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("local CONNECT status = %d, want 200", resp.StatusCode)
	}

	// First tunneled request → the target answers "RESP1" and FINs its write half.
	if _, err := io.WriteString(raw, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write tunneled req 1: %v", err)
	}
	first := make([]byte, len("RESP1"))
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(br, first); err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if string(first) != "RESP1" {
		t.Fatalf("first response = %q, want RESP1", first)
	}

	// Give the egress→client FIN time to propagate through both splices. With the bug, the
	// proxy force-closes the client tunnel HERE; with the fix, the client→target half lives.
	time.Sleep(150 * time.Millisecond)

	// A follow-up the client sends AFTER the target's FIN must still REACH the target. If the
	// proxy force-closed the whole tunnel on that FIN (the old behaviour), this write is RST
	// and the target never sees it — the ERR_SOCKET_CLOSED the preflight saw. With the
	// half-close fix the client→egress→target half is still open and the target receives it.
	const followup = "SECOND-REQUEST"
	_ = raw.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(raw, followup); err != nil {
		t.Fatalf("the tunnel was force-closed after the target's FIN (the #154 ERR_SOCKET_CLOSED bug): write failed: %v", err)
	}
	select {
	case msg := <-got:
		if msg != followup {
			t.Fatalf("target received %q after the FIN, want %q", msg, followup)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client→target half did not survive the target FIN (the #154 ERR_SOCKET_CLOSED bug): the follow-up never reached the target")
	}
}

// TestProxy_RejectedBearerSurfacesCleanFailure: when the egress rejects the bearer (407),
// the local dial fails — and no panic, no leak.
func TestProxy_RejectedBearerSurfacesCleanFailure(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, func(string) bool { return true }) // reject all
	p := startProxy(t, fe.addr(), "et_bad")

	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err == nil {
		conn.Close()
		t.Fatal("a rejected bearer must fail the dial, not connect")
	}
}

// TestProxy_EndpointShapeAndStop: the endpoint is a loopback socks5h URL, and Stop() is
// clean + idempotent (the listener is closed; a second Stop is a no-op).
// TestProxy_PinnedPort verifies the #191 deterministic-port path: Options.Port pins the local
// proxy to an exact loopback port, and a port already in use surfaces a clean, actionable
// "already in use" error (never an opaque stack trace). The interactive default (Port:0) keeps
// picking a free port.
func TestProxy_PinnedPort(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)

	// Grab a known-free port (bind, capture, release) and pin the proxy to it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(probe.Addr().String())
	var want int
	fmt.Sscanf(ps, "%d", &want)
	_ = probe.Close()

	p, err := StartLocalProxy(context.Background(), fe.addr(), "et_pin", Options{Insecure: true, Port: want})
	if err != nil {
		t.Fatalf("StartLocalProxy(pinned): %v", err)
	}
	t.Cleanup(p.Stop)
	if p.Addr() != fmt.Sprintf("127.0.0.1:%d", want) {
		t.Fatalf("pinned proxy addr = %q, want 127.0.0.1:%d", p.Addr(), want)
	}

	// A SECOND proxy pinned to the SAME (now-taken) port must fail with a clear in-use error.
	_, err2 := StartLocalProxy(context.Background(), fe.addr(), "et_pin2", Options{Insecure: true, Port: want})
	if err2 == nil {
		t.Fatal("pinning an already-bound port must error")
	}
	if !strings.Contains(err2.Error(), "already in use") {
		t.Fatalf("port-collision error = %q, want an 'already in use' message", err2.Error())
	}
}

func TestProxy_EndpointShapeAndStop(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)
	p, err := StartLocalProxy(context.Background(), fe.addr(), "et_x", Options{Insecure: true})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	if !strings.HasPrefix(p.Endpoint(), "socks5h://127.0.0.1:") {
		t.Fatalf("endpoint = %q, want socks5h://127.0.0.1:<port>", p.Endpoint())
	}
	if !strings.HasPrefix(p.Addr(), "127.0.0.1:") {
		t.Fatalf("addr = %q, want 127.0.0.1:<port>", p.Addr())
	}
	p.Stop()
	p.Stop() // idempotent — must not panic
	// After Stop the listener is closed: a dial is refused.
	if c, err := net.DialTimeout("tcp", p.Addr(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("after Stop the local proxy must no longer accept connections")
	}
}

// TestProxy_SurvivesControlCtxCancel is THE #172 WB3 lifetime regression guard: the local
// proxy MUST NOT die when the short-lived control-plane ctx (the one used for op:connect +
// verify) is cancelled. We start the proxy on a control ctx, CANCEL that ctx, and then —
// AFTER the cancel — assert the proxy still ACCEPTS a new local client AND streams bytes
// end-to-end through the egress. Only Stop() ends it. (Before the fix, the proxy bound a
// `<-ctx.Done(); Stop()` goroutine to this ctx, so cancel killed it and every persistent
// path — whisper run / connect / the guided hold — got a DEAD proxy.)
func TestProxy_SurvivesControlCtxCancel(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)

	controlCtx, cancelControl := context.WithCancel(context.Background())
	p, err := StartLocalProxy(controlCtx, fe.addr(), "et_lifetime", Options{Insecure: true, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	t.Cleanup(p.Stop)

	// Cancel the CONTROL ctx, exactly as the caller does the instant op:connect + verify
	// return. Give the (now-removed) teardown goroutine a moment to have fired if it existed.
	cancelControl()
	time.Sleep(50 * time.Millisecond)

	// The proxy must STILL accept a new client and stream bytes through to the backend.
	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("after the control ctx was cancelled the proxy refused a NEW connection (it died with the ctx — the WB3 bug): %v", err)
	}
	defer conn.Close()
	msg := "alive-after-cancel"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write through the post-cancel tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo through the post-cancel tunnel: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("post-cancel echo = %q, want %q (bytes must still stream end-to-end)", buf, msg)
	}

	// And the proxy's lifetime ends ONLY at Stop() — not at the control ctx.
	p.Stop()
	if c, err := net.DialTimeout("tcp", p.Addr(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("after Stop the local proxy must no longer accept connections")
	}
}

// TestProxy_InFlightTunnelSurvivesControlCtxCancel: a tunnel OPENED while the control ctx
// is still live must keep streaming AFTER that ctx is cancelled — the per-tunnel upstream
// dial keys off the proxy's OWN context, not the control ctx, so an established splice is
// never severed by the control call returning.
func TestProxy_InFlightTunnelSurvivesControlCtxCancel(t *testing.T) {
	backend := echoBackend(t)
	fe := newFakeEgress(t, backend, nil)

	controlCtx, cancelControl := context.WithCancel(context.Background())
	p, err := StartLocalProxy(controlCtx, fe.addr(), "et_inflight", Options{Insecure: true, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	t.Cleanup(p.Stop)

	// Open the tunnel BEFORE the cancel.
	conn, err := socks5Dial(p.Addr(), "example.com:80")
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	// Now cancel the control ctx — the established splice must keep working.
	cancelControl()
	time.Sleep(50 * time.Millisecond)

	msg := "tunnel-outlives-control-ctx"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write after control-ctx cancel: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("the in-flight tunnel was severed by the control-ctx cancel (the WB3 bug): %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("in-flight echo = %q, want %q", buf, msg)
	}
}

// TestProxy_BadInputs: empty upstream / empty bearer are clean errors, not panics.
func TestProxy_BadInputs(t *testing.T) {
	if _, err := StartLocalProxy(context.Background(), "", "et_x", Options{}); err == nil {
		t.Fatal("empty upstream must error")
	}
	if _, err := StartLocalProxy(context.Background(), "egress.whisper.online:443", "", Options{}); err == nil {
		t.Fatal("empty bearer must error")
	}
}

// selfSigned mints a throwaway self-signed TLS cert for 127.0.0.1, for the fake egress.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
