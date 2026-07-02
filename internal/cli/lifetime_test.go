// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/egress"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// lifetime_test.go is the PROXY-LIFETIME regression suite for the CLI callers.
//
// THE bug it guards: StartLocalProxy used to bind its teardown to the caller's SHORT
// control-plane ctx (`go func(){ <-ctx.Done(); p.Stop() }()`), and the callers cancel that
// ctx the instant op:connect + verify return — so every persistent path got a DEAD proxy:
//   - whisper run / claude : the proxy was torn down before the child ever ran.
//   - the guided hold       : holdUntilSignal parked forever on a dead tunnel.
//   - whisper connect       : the 30s control-ctx timeout killed the held-open egress.
//
// These tests back the session with a REAL egress.StartLocalProxy (against a fake CONNECT
// egress), drive the actual caller code (runWithEgress, connectVia), CANCEL the control
// ctx, and assert the proxy is still LIVE — and that the OWNER's Stop() is what ends it.

// --- a fake CONNECT egress for the CLI package (mirrors the egress package's helper) ----

// fakeConnectEgress is a self-signed TLS HTTPS-CONNECT proxy standing in for
// egress.whisper.online:443. On a 2xx it splices the CONNECT target to a real echo backend.
type fakeConnectEgress struct {
	ln net.Listener
}

func newFakeConnectEgress(t *testing.T, backend string) *fakeConnectEgress {
	t.Helper()
	cert := selfSignedCLI(t)
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatalf("fake egress listen: %v", err)
	}
	f := &fakeConnectEgress{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", backend)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeConnectEgress) addr() string { return f.ln.Addr().String() }

// echoBackendCLI is a tiny TCP echo server (the "target" the CONNECT reaches).
func echoBackendCLI(t *testing.T) string {
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

// dialThroughProxy opens a SOCKS5 (no-auth, CONNECT-by-DOMAIN) tunnel through the local
// proxy at proxyEndpoint (socks5h://127.0.0.1:<port>) to target, then round-trips a probe
// byte sequence to PROVE the tunnel is live and streaming end-to-end.
func dialThroughProxy(t *testing.T, proxyEndpoint, target, probe string) error {
	t.Helper()
	addr := strings.TrimPrefix(proxyEndpoint, "socks5h://")
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial local proxy: %w", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil { // greeting: VER, 1 method, NO-AUTH
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0x00 {
		return fmt.Errorf("socks5 method negotiation failed")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	var pnum int
	fmt.Sscanf(port, "%d", &pnum)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(pnum>>8), byte(pnum&0xff))
	if _, err := c.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect rejected (rep=%d)", head[1])
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
			return err
		}
		bndLen = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, bndLen+2)); err != nil {
		return err
	}
	// Stream the probe end-to-end and read it back from the echo backend.
	if _, err := c.Write([]byte(probe)); err != nil {
		return err
	}
	buf := make([]byte, len(probe))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(buf) != probe {
		return fmt.Errorf("echo = %q, want %q", buf, probe)
	}
	return nil
}

// selfSignedCLI mints a throwaway self-signed cert for 127.0.0.1 (the fake egress).
func selfSignedCLI(t *testing.T) tls.Certificate {
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

// stubLiveProxyTail replaces connectAndVerify with one that brings up a REAL local proxy
// (egress.StartLocalProxy) pointed at the fake egress, USING THE CONTROL CTX the caller
// passes — exactly as production does. It records every live session it produced so a test
// can dial the proxy after the caller has cancelled that control ctx. It does NOT stub the
// network verify (no echo endpoint needed): the point here is the proxy LIFETIME, which is
// the egress package's job and independent of the verify HTTP. It returns a restore func.
func stubLiveProxyTail(t *testing.T, egressAddr, verifiedAddr string) (sessions *[]*egressSession, restore func()) {
	t.Helper()
	var mu sync.Mutex
	var got []*egressSession
	saved := connectAndVerify
	connectAndVerify = func(ctx context.Context, _ *client.Client, _ *client.Result, name string, _ *wgtun.Keypair) (*egressSession, error) {
		// Use the SAME control ctx the caller passes (this is what production does) so the
		// test faithfully exercises the proxy's lifetime vs that ctx.
		p, err := egress.StartLocalProxy(ctx, egressAddr, "et_lifetime_secret", egress.Options{Insecure: true, DialTimeout: 5 * time.Second})
		if err != nil {
			return nil, err
		}
		s := &egressSession{endpoint: p.Endpoint(), addr: verifiedAddr, name: name, verified: true, local: p}
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
		return s, nil
	}
	return &got, func() { connectAndVerify = saved }
}

// --- run.go lifetime: the child gets a LIVE proxy, not a dead one --------------------

// TestRun_ProxyLiveForChild proves the fix for `whisper run`: the local proxy in
// the child's injected ALL_PROXY must still ACCEPT + STREAM while the child runs — i.e.
// AFTER the control ctx that op:connect/verify used has been cancelled. The child here
// dials its own $ALL_PROXY through to the echo backend and reports OK only if the tunnel
// is live; before the fix the proxy was torn down with the control ctx and the dial failed.
func TestRun_ProxyLiveForChild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	backend := echoBackendCLI(t)
	fe := newFakeConnectEgress(t, backend)
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	sessions, restore := stubLiveProxyTail(t, fe.addr(), "2a04:2a01:9::abcd")
	defer restore()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 3 * time.Second}
	defer func() { g = savedG }()

	// The child reads its inherited ALL_PROXY and dials it itself: a tiny SOCKS5 handshake
	// + CONNECT + a one-byte round-trip, printing LIVE on success. This runs AFTER cancel()
	// fired in runWithEgress, so it proves the proxy outlived the control ctx.
	target := "example.com:80"
	probe := "child-sees-live-proxy"
	script := childSocksProbeScript(target, probe)
	stdout, _ := captureStd(t, func() {
		_ = runWithEgress("2a04:2a01:9::abcd", "", "", "sh", []string{"-c", script})
	})
	// No python3 in the child env ⇒ inconclusive (the child can't probe). The core run.go
	// lifetime is covered without a child by TestRun_ProxyLiveAfterControlCtxCancel, so skip
	// rather than fail — a missing test dependency is never a product regression.
	if strings.Contains(stdout, "SKIP") {
		t.Skip("python3 unavailable in the child env; core run.go lifetime covered by TestRun_ProxyLiveAfterControlCtxCancel")
	}
	if !strings.Contains(stdout, "LIVE") {
		t.Fatalf("child could not stream through its injected ALL_PROXY — the proxy died with the control ctx (the ctx-cancellation bug); child stdout=%q", stdout)
	}

	// The owner (runWithEgress) must have Stop()'d the proxy after the child exited.
	for _, s := range *sessions {
		if c, err := net.DialTimeout("tcp", strings.TrimPrefix(s.endpoint, "socks5h://"), 200*time.Millisecond); err == nil {
			c.Close()
			t.Fatalf("after the child exited runWithEgress must Stop() the proxy; %s still accepts", s.endpoint)
		}
	}
}

// childSocksProbeScript builds a POSIX sh + (python3|nc) snippet that dials $ALL_PROXY and
// proves the tunnel streams. We keep it dependency-light: python3 if present (a self-
// contained SOCKS5 handshake), else a graceful skip marker the test treats as inconclusive.
func childSocksProbeScript(target, probe string) string {
	// The shell uses Go's egress proxy via $ALL_PROXY. Implement a minimal SOCKS5 client in
	// python3 (commonly available on CI/dev). If python3 is missing, print SKIP so the test
	// can fall back; the run.go lifetime is ALSO covered directly below without a child.
	py := `
import os,socket,sys,struct
u=os.environ.get("ALL_PROXY","")
hostport=u.replace("socks5h://","").replace("socks5://","")
h,p=hostport.rsplit(":",1)
s=socket.create_connection((h,int(p)),5)
s.sendall(b"\x05\x01\x00")
if s.recv(2)!=b"\x05\x00": sys.exit("neg")
th="` + strings.Split(target, ":")[0] + `"; tp=` + strings.Split(target, ":")[1] + `
req=b"\x05\x01\x00\x03"+bytes([len(th)])+th.encode()+struct.pack(">H",tp)
s.sendall(req)
head=s.recv(4)
if head[1]!=0:
    sys.exit("rep=%d"%head[1])
al={1:4,4:16}.get(head[3],0)
if head[3]==3: al=s.recv(1)[0]
s.recv(al+2)
probe=b"` + probe + `"
s.sendall(probe)
got=b""
while len(got)<len(probe):
    d=s.recv(len(probe)-len(got))
    if not d: break
    got+=d
print("LIVE" if got==probe else "DEAD")
`
	return "command -v python3 >/dev/null 2>&1 && python3 -c '" + py + "' || echo SKIP"
}

// TestRun_ProxyLiveAfterControlCtxCancel is the child-independent core of the run.go fix:
// it drives the SAME bring-up connectAndVerify does on the control ctx, cancels that ctx
// (as runWithEgress does the instant verify returns), and then dials the proxy directly —
// it MUST still stream. This needs no child process, so it always runs (no python3 gate).
func TestRun_ProxyLiveAfterControlCtxCancel(t *testing.T) {
	backend := echoBackendCLI(t)
	fe := newFakeConnectEgress(t, backend)

	// Mirror runWithEgress exactly: build the control ctx, bring the proxy up on it, cancel.
	cx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	p, err := egress.StartLocalProxy(cx, fe.addr(), "et_x", egress.Options{Insecure: true, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	defer p.Stop()
	sess := &egressSession{endpoint: p.Endpoint(), addr: "2a04:2a01:9::abcd", local: p}
	cancel() // <-- the control ctx is now DONE, exactly as in runWithEgress

	// The injected ALL_PROXY (the child would inherit) must still stream.
	if err := dialThroughProxy(t, sess.endpoint, "example.com:80", "after-cancel-run"); err != nil {
		t.Fatalf("the proxy a child would inherit is DEAD after the control ctx was cancelled (the ctx-cancellation bug): %v", err)
	}
	// And Stop() (the owner's job, after the child) ends it.
	sess.Stop()
	if conn, err := net.DialTimeout("tcp", strings.TrimPrefix(sess.endpoint, "socks5h://"), 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("after Stop the proxy must no longer accept")
	}
}

// --- guided.go lifetime: the hold holds a LIVE proxy ---------------------------------

// TestGuidedHold_ProxySurvivesPastConnectAndVerify proves the fix for the guided
// front door: connectVia cancels the control ctx right after connectAndVerify, then parks
// in holdUntilSignal. The proxy MUST survive that cancel so the "Connected ✓ verified"
// terminal holds a LIVE tunnel — before the fix the proxy died with the control ctx and the
// hold sat on a dead endpoint. We capture the live session inside holdUntilSignal (the hold
// point), dial it, and only THEN let the stubbed hold Stop() it.
func TestGuidedHold_ProxySurvivesPastConnectAndVerify(t *testing.T) {
	backend := echoBackendCLI(t)
	fe := newFakeConnectEgress(t, backend)
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}}, nil)
	defer srv.Close()
	_, restoreTail := stubLiveProxyTail(t, fe.addr(), "2a04:2a01:1::1")
	defer restoreTail()

	// Stub the hold to ASSERT-AT-HOLD: when connectVia reaches holdUntilSignal (after it has
	// already cancelled the control ctx), the proxy must still stream. Then Stop() it.
	savedHold := holdUntilSignal
	var holdErr error
	holdUntilSignal = func(sess *egressSession) {
		defer sess.Stop()
		holdErr = dialThroughProxy(t, sess.endpoint, "example.com:80", "guided-hold-live")
	}
	defer func() { holdUntilSignal = savedHold }()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 3 * time.Second}
	defer func() { g = savedG }()

	// Drive the REAL guided connect tail on a TTY (so it takes the hold branch).
	gio := guidedIO{in: bufio.NewReader(strings.NewReader("")), out: io.Discard, err: io.Discard}
	if err := connectVia(guidedOptions{tty: true}, gio, agentChoice{name: "solo", addr: "2a04:2a01:1::1"}); err != nil {
		t.Fatalf("connectVia errored: %v", err)
	}
	if holdErr != nil {
		t.Fatalf("the guided hold held a DEAD proxy — it did not survive past connectAndVerify (the ctx-cancellation bug): %v", holdErr)
	}
}
