// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the production HTTP fetcher and TLS handshaker against
// REAL loopback listeners - genuine sockets and handshakes, nothing faked. GetPinned is the
// security-critical one: it must refuse to speak HTTP over a connection whose served SPKI
// does not equal the DANE pin, and the handshaker must return the leaf with the trailing-dot
// SNI trimmed.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// deepentrustverify_startTLSServer serves handler over TLS on a loopback socket with a fresh
// self-signed leaf (the DANE-EE shape: no WebPKI chain), recording each ClientHello SNI.
// Returns the hostport, the served leaf, and a getter for the last-seen SNI.
func deepentrustverify_startTLSServer(t *testing.T, handler http.Handler) (string, *x509.Certificate, func() string) {
	t.Helper()
	cert, priv := genLeafCert(t, []string{"agent.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	lastSNI := ""
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			lastSNI = hello.ServerName
			mu.Unlock()
			return &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}, nil
		},
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), cert, func() string {
		mu.Lock()
		defer mu.Unlock()
		return lastSNI
	}
}

// deepentrustverify_closedPort returns a loopback hostport that is guaranteed closed (it was
// briefly bound, then released).
func deepentrustverify_closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// deepentrustverify_slammingListener accepts TCP connections and closes them immediately, so
// any TLS handshake against it fails at the transport.
func deepentrustverify_slammingListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// --- httpFetcher.Get ----------------------------------------------------------------------

func TestDeepenTV_HTTPFetcher_GetSendsIdentityHeadersAndReturnsBody(t *testing.T) {
	var mu sync.Mutex
	gotUA, gotAccept := "", ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotUA, gotAccept = r.Header.Get("User-Agent"), r.Header.Get("Accept")
		mu.Unlock()
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	body, status, err := NewHTTPFetcher().Get(context.Background(), srv.URL+"/x")
	if err != nil || status != 200 || string(body) != `{"ok":true}` {
		t.Fatalf("Get: body=%q status=%d err=%v", body, status, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotUA != "whisper-cli/trustverify" || gotAccept != "application/json" {
		t.Fatalf("identity headers must be sent: UA=%q Accept=%q", gotUA, gotAccept)
	}
}

func TestDeepenTV_HTTPFetcher_GetPassesNonOKStatusThrough(t *testing.T) {
	// Get does NOT error on a non-200: callers decide (SKIP vs FAIL). The status must be
	// passed through with the body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte("overloaded"))
	}))
	defer srv.Close()
	body, status, err := NewHTTPFetcher().Get(context.Background(), srv.URL)
	if err != nil || status != 503 || string(body) != "overloaded" {
		t.Fatalf("want (overloaded, 503, nil), got (%q, %d, %v)", body, status, err)
	}
}

func TestDeepenTV_HTTPFetcher_GetBadURLErrors(t *testing.T) {
	if _, _, err := NewHTTPFetcher().Get(context.Background(), "://not-a-url"); err == nil {
		t.Fatal("want an error for an unparseable URL")
	}
}

func TestDeepenTV_HTTPFetcher_GetConnectionRefusedErrors(t *testing.T) {
	url := "http://" + deepentrustverify_closedPort(t) + "/x"
	if _, _, err := NewHTTPFetcher().Get(context.Background(), url); err == nil ||
		!strings.Contains(err.Error(), "fetch") {
		t.Fatalf("want the wrapped fetch error, got: %v", err)
	}
}

func TestDeepenTV_HTTPFetcher_GetTruncatedBodyErrors(t *testing.T) {
	// The server promises 100 bytes and delivers 5: the read must surface an error, never
	// silently return a truncated document as if complete.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
	}))
	defer srv.Close()
	if _, _, err := NewHTTPFetcher().Get(context.Background(), srv.URL); err == nil ||
		!strings.Contains(err.Error(), "reading") {
		t.Fatalf("want the read error, got: %v", err)
	}
}

// --- httpFetcher.GetPinned ---------------------------------------------------------------

func TestDeepenTV_HTTPFetcher_GetPinnedHappyPath(t *testing.T) {
	var mu sync.Mutex
	gotHost, gotPath := "", ""
	hostport, cert, sni := deepentrustverify_startTLSServer(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotHost, gotPath = r.Host, r.URL.Path
			mu.Unlock()
			w.Write([]byte("identity-doc-body"))
		}))
	pin := SPKISHA256(cert)
	body, status, err := NewHTTPFetcher().GetPinned(context.Background(), hostport,
		"agent.test.", "/.well-known/whisper-identity", TLSAPin{SHA256: pin[:]})
	if err != nil || status != 200 || string(body) != "identity-doc-body" {
		t.Fatalf("GetPinned: body=%q status=%d err=%v", body, status, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != "agent.test" || gotPath != "/.well-known/whisper-identity" {
		t.Fatalf("the request must target https://<sni-sans-dot><path>: host=%q path=%q", gotHost, gotPath)
	}
	if sni() != "agent.test" {
		t.Fatalf("the ClientHello SNI must be the trailing-dot-trimmed name, got %q", sni())
	}
}

func TestDeepenTV_HTTPFetcher_GetPinnedRefusesOnPinMismatch(t *testing.T) {
	// The served SPKI differs from the DANE pin: GetPinned must refuse BEFORE any HTTP bytes
	// are exchanged - the request must never reach the handler.
	var mu sync.Mutex
	reached := false
	hostport, _, _ := deepentrustverify_startTLSServer(t,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			reached = true
			mu.Unlock()
		}))
	wrong := make([]byte, 32)
	wrong[0] = 0x5A
	_, _, err := NewHTTPFetcher().GetPinned(context.Background(), hostport,
		"agent.test", "/.well-known/whisper-identity", TLSAPin{SHA256: wrong})
	if err == nil || !strings.Contains(err.Error(), "does not match the DANE pin") {
		t.Fatalf("want the pin-mismatch refusal, got: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reached {
		t.Fatal("no HTTP request may be sent over an unpinned connection")
	}
}

func TestDeepenTV_HTTPFetcher_GetPinnedDialAndHandshakeErrors(t *testing.T) {
	pin := TLSAPin{SHA256: make([]byte, 32)}
	if _, _, err := NewHTTPFetcher().GetPinned(context.Background(),
		deepentrustverify_closedPort(t), "agent.test", "/x", pin); err == nil {
		t.Fatal("want an error dialing a closed port")
	}
	if _, _, err := NewHTTPFetcher().GetPinned(context.Background(),
		deepentrustverify_slammingListener(t), "agent.test", "/x", pin); err == nil {
		t.Fatal("want an error when the TLS handshake is slammed shut")
	}
}

func TestDeepenTV_HTTPFetcher_GetPinnedTruncatedBodyErrors(t *testing.T) {
	// Same contract as Get: a body cut short of its Content-Length must error, never pass a
	// truncated identity document downstream as if complete.
	hostport, cert, _ := deepentrustverify_startTLSServer(t,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("short"))
		}))
	pin := SPKISHA256(cert)
	if _, _, err := NewHTTPFetcher().GetPinned(context.Background(), hostport,
		"agent.test", "/.well-known/whisper-identity", TLSAPin{SHA256: pin[:]}); err == nil ||
		!strings.Contains(err.Error(), "reading identity_doc") {
		t.Fatalf("want the read error, got: %v", err)
	}
}

func TestDeepenTV_HTTPFetcher_GetPinnedBadSNIURLErrors(t *testing.T) {
	pin := TLSAPin{SHA256: make([]byte, 32)}
	if _, _, err := NewHTTPFetcher().GetPinned(context.Background(),
		"127.0.0.1:1", "bad\nhost", "/x", pin); err == nil {
		t.Fatal("want an error for an SNI that cannot form a URL")
	}
}

// --- tlsHandshaker.Leaf ------------------------------------------------------------------

func TestDeepenTV_TLSHandshaker_LeafReturnsServedCertAndTrimsSNI(t *testing.T) {
	hostport, cert, sni := deepentrustverify_startTLSServer(t, http.NewServeMux())
	got, err := NewTLSHandshaker().Leaf(context.Background(), hostport, "agent.test.")
	if err != nil {
		t.Fatalf("Leaf: %v", err)
	}
	if SPKISHA256(got) != SPKISHA256(cert) {
		t.Fatal("Leaf must return the exact served leaf certificate")
	}
	if sni() != "agent.test" {
		t.Fatalf("the SNI must be sent with the trailing dot trimmed, got %q", sni())
	}
}

func TestDeepenTV_TLSHandshaker_NilDialerZeroValueStillWorks(t *testing.T) {
	// The zero-value handshaker (nil dialer) must self-heal, not panic: Postel inside.
	hostport, cert, _ := deepentrustverify_startTLSServer(t, http.NewServeMux())
	got, err := (&tlsHandshaker{}).Leaf(context.Background(), hostport, "agent.test")
	if err != nil {
		t.Fatalf("Leaf with a zero-value handshaker: %v", err)
	}
	if SPKISHA256(got) != SPKISHA256(cert) {
		t.Fatal("the zero-value handshaker must return the served leaf")
	}
}

func TestDeepenTV_TLSHandshaker_DialErrorNamesTheTarget(t *testing.T) {
	_, err := NewTLSHandshaker().Leaf(context.Background(), deepentrustverify_closedPort(t), "agent.test")
	if err == nil || !strings.Contains(err.Error(), "dialing") {
		t.Fatalf("want the dial error, got: %v", err)
	}
}

func TestDeepenTV_TLSHandshaker_HandshakeErrorNamesTheSNI(t *testing.T) {
	_, err := NewTLSHandshaker().Leaf(context.Background(), deepentrustverify_slammingListener(t), "agent.test")
	if err == nil || !strings.Contains(err.Error(), "TLS handshake") ||
		!strings.Contains(err.Error(), "agent.test") {
		t.Fatalf("want the handshake error naming the SNI, got: %v", err)
	}
}

// --- aggregateJWKS ------------------------------------------------------------------------

func TestDeepenTV_AggregateJWKS_ErrorAndStatusAndParseFailuresSurface(t *testing.T) {
	cases := []struct {
		name string
		get  func(string) ([]byte, int, error)
		want string
	}{
		{"transport", func(string) ([]byte, int, error) { return nil, 0, errString("network down") },
			"network down"},
		{"httpStatus", func(string) ([]byte, int, error) { return []byte("x"), 500, nil }, "HTTP 500"},
		{"unparseable", func(string) ([]byte, int, error) { return []byte("garbage"), 200, nil },
			"not a JSON key set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFetcher{get: tc.get}
			set, err := aggregateJWKS(context.Background(), f, []string{"https://x/jwks"}, 2, "")
			if set != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want (nil, ...%s...), got (%v, %v)", tc.want, set, err)
			}
		})
	}
}

func TestDeepenTV_AggregateJWKS_NoURLsIsEmptyNotError(t *testing.T) {
	set, err := aggregateJWKS(context.Background(), &fakeFetcher{}, nil, 3, "")
	if err != nil || len(set) != 0 {
		t.Fatalf("no URLs: want an empty set and no error, got (%v, %v)", set, err)
	}
}

func TestDeepenTV_AggregateJWKS_PartialFailureStillCollects(t *testing.T) {
	// URL 1 is down; URL 2 serves the key: the aggregate succeeds (Postel - collect what is
	// collectable) and the earlier error is forgotten.
	_, jwk, _ := deepentrustverify_signingKey(t)
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) {
		if strings.Contains(url, "one") {
			return nil, 0, errString("down")
		}
		return []byte(`{"keys":[` + jwkJSON(jwk) + `]}`), 200, nil
	}}
	set, err := aggregateJWKS(context.Background(),
		f, []string{"https://one/jwks", "https://two/jwks"}, 1, "")
	if err != nil || len(set) != 1 {
		t.Fatalf("want the one collected key, got (%v, %v)", set, err)
	}
	if _, ok := set[jwk.Kid]; !ok {
		t.Fatalf("the collected key must be indexed by kid, got: %v", set)
	}
}

func TestDeepenTV_AggregateJWKS_StopsEarlyOnWantedKid(t *testing.T) {
	// With wantKid set, the aggregation must stop as soon as the kid is collected instead of
	// burning the full url x rounds fetch budget.
	_, jwk, _ := deepentrustverify_signingKey(t)
	var mu sync.Mutex
	calls := 0
	f := &fakeFetcher{get: func(string) ([]byte, int, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return []byte(`{"keys":[` + jwkJSON(jwk) + `]}`), 200, nil
	}}
	set, err := aggregateJWKS(context.Background(), f,
		[]string{"https://one/jwks", "https://two/jwks"}, 6, jwk.Kid)
	if err != nil || len(set) != 1 {
		t.Fatalf("want the key, got (%v, %v)", set, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("must stop after the kid is found: %d fetches", calls)
	}
}
