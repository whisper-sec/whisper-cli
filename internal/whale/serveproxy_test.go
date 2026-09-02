// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// serveproxy_test.go drives the front end the way a caller does: a real request, over a
// real httptest origin, from a chosen source address. Every rule that decides who is
// answered, and what the origin is told about them, is asserted end to end.

// originEcho is a stand-in origin that reports back exactly what it was sent.
func originEcho(t *testing.T, seen *http.Header, path *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		*path = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "origin ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad test URL %q: %v", raw, err)
	}
	return u
}

// request drives one call through the proxy from a given source address.
func request(p *ServeProxy, from, path string, hdr http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://db-01.acme.agents.whisper.online"+path, nil)
	r.RemoteAddr = "[" + from + "]:51234"
	for k, vals := range hdr {
		for _, v := range vals {
			r.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func provenCache() *IdentityCache {
	return NewIdentityCache(IdentityLookup{
		PTR:    func(context.Context, netip.Addr) (string, string) { return "db-01.acme.agents.whisper.online.", "" },
		Owner:  func(context.Context, netip.Addr) (string, string) { return "ACME B.V.", "" },
		Assess: func(context.Context, netip.Addr) (string, string, string) { return "CLEAN", "0.9", "" },
	}, IdentityCacheOptions{Budget: 2 * time.Second})
}

func TestFleetScopeAnswersMembersAndRefusesEveryoneElse(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)

	member := netip.MustParseAddr("2a04:2a01:1::5")
	p, err := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), MountPath: "/", Scope: ScopeFleet,
		Gate:            func(a netip.Addr) bool { return a == member },
		Identity:        provenCache(),
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatalf("NewServeProxy: %v", err)
	}

	if w := request(p, member.String(), "/", nil); w.Code != http.StatusOK {
		t.Fatalf("a fleet member got %d, want 200", w.Code)
	}
	w := request(p, "2001:db8::666", "/", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a stranger got %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "fleet only") {
		t.Errorf("the refusal does not say why: %q", w.Body.String())
	}
	if strings.Contains(w.Body.String(), member.String()) {
		t.Error("the refusal leaked a fleet member's address to a stranger")
	}
	if st := p.Stats(); st.Refused != 1 || st.Requests != 1 {
		t.Errorf("stats = %+v, want one served and one refused", st)
	}
}

// TestAFleetScopeWithNoGateIsRefusedAtConstruction is the misconfiguration that would
// silently expose an origin. It must be impossible to build, not merely discouraged.
func TestAFleetScopeWithNoGateIsRefusedAtConstruction(t *testing.T) {
	_, err := NewServeProxy(ProxyOptions{Target: mustURL(t, "http://127.0.0.1:1"), Scope: ScopeFleet})
	if err == nil {
		t.Fatal("a fleet-scoped proxy with no gate was built; it would have answered the internet")
	}
	if !strings.Contains(err.Error(), "answer the whole internet") {
		t.Errorf("the refusal does not say what would have happened: %v", err)
	}
	if _, err := NewServeProxy(ProxyOptions{Target: mustURL(t, "http://127.0.0.1:1"), Scope: "sideways"}); err == nil {
		t.Fatal("an unknown scope was accepted")
	}
}

func TestFunnelScopeAnswersAnyone(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)
	p, err := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), Scope: ScopeInternet,
		Identity:        provenCache(),
		IdentityHeaders: true,
	})
	if err != nil {
		t.Fatalf("NewServeProxy: %v", err)
	}
	w := request(p, "185.220.101.1", "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("a public caller got %d from a funnel, want 200", w.Code)
	}
	if w.Header().Get(HeaderServeScope) != "internet" {
		t.Errorf("the response does not declare its scope: %q", w.Header().Get(HeaderServeScope))
	}
	if got := seen.Get(HeaderClientAddress); got != "185.220.101.1" {
		t.Errorf("the origin was told the caller was %q", got)
	}
	if seen.Get(HeaderAgentFQDN) != "" {
		t.Error("a public caller reached the origin carrying a proven agent name")
	}
}

// TestTheOriginNeverSeesAClaimedIdentity drives the forgery end to end, through the real
// proxy, to a real origin.
func TestTheOriginNeverSeesAClaimedIdentity(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)
	p, _ := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), Scope: ScopeInternet,
		Identity: provenCache(), IdentityHeaders: true, CompatHeaders: true,
	})

	claimed := http.Header{}
	claimed.Set("Whisper-Agent-FQDN", "ceo.acme.agents.whisper.online.")
	claimed.Set("Tailscale-User-Login", "root@acme.com")
	claimed.Set("X-Forwarded-For", "10.0.0.1")

	if w := request(p, "185.220.101.1", "/", claimed); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got := seen.Get("Whisper-Agent-FQDN"); got != "" {
		t.Fatalf("the origin was handed a forged identity: %q", got)
	}
	if got := seen.Get("Tailscale-User-Login"); got != "" {
		t.Fatalf("the origin was handed a forged login: %q", got)
	}
	if got := seen.Get("X-Forwarded-For"); got != "185.220.101.1" {
		t.Fatalf("X-Forwarded-For = %q; an inbound claim was appended to rather than replaced", got)
	}
	if seen.Get("X-Forwarded-Proto") != "https" {
		t.Error("X-Forwarded-Proto was not set")
	}
	if st := p.Stats(); st.Spoofed != 1 {
		t.Errorf("the spoof attempt was not counted: %+v", st)
	}
}

func TestAProvenCallerReachesTheOriginWithEveryClaim(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)
	member := netip.MustParseAddr("2a04:2a01:1::5")
	p, _ := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), Scope: ScopeFleet,
		Gate:     func(a netip.Addr) bool { return a == member },
		Identity: provenCache(), IdentityHeaders: true, CompatHeaders: true,
	})
	if w := request(p, member.String(), "/", nil); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	want := map[string]string{
		HeaderAgentAddress:   member.String(),
		HeaderAgentFQDN:      "db-01.acme.agents.whisper.online.",
		HeaderAgentOwner:     "ACME B.V.",
		HeaderAssessBand:     "CLEAN",
		HeaderAssessCoverage: "0.9",
		HeaderCompatLogin:    "db-01.acme.agents.whisper.online.",
		HeaderServeScope:     "fleet",
	}
	for k, v := range want {
		if got := seen.Get(k); got != v {
			t.Errorf("the origin saw %s = %q, want %q", k, got, v)
		}
	}
	if !strings.Contains(seen.Get(HeaderIdentityProof), "fqdn=dnssec-ptr+forward-confirmed") {
		t.Errorf("the proof line did not reach the origin: %q", seen.Get(HeaderIdentityProof))
	}
	if seen.Get("Host") == "" && seen.Get("X-Forwarded-Host") == "" {
		t.Error("the origin lost the name the caller dialled")
	}
	// Logged so `go test -v -run TestAProvenCallerReachesTheOriginWithEveryClaim` prints the
	// real header block an origin receives. The docs quote this capture rather than a
	// hand-written example, so the two can never drift.
	names := make([]string, 0, len(seen))
	for k := range seen {
		if strings.HasPrefix(k, "Whisper-") || strings.HasPrefix(k, "Tailscale-") || strings.HasPrefix(k, "X-Forwarded-") {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		t.Logf("%s: %s", k, seen.Get(k))
	}
}

// TestIdentityHeadersOffStillStripsAtTheProxy: the switch turns OUR headers off, never the
// caller's on.
func TestIdentityHeadersOffStillStripsAtTheProxy(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)
	p, _ := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), Scope: ScopeInternet, IdentityHeaders: false,
	})
	claimed := http.Header{}
	claimed.Set("Whisper-Agent-FQDN", "ceo.acme.agents.whisper.online.")
	request(p, "185.220.101.1", "/", claimed)
	if got := seen.Get("Whisper-Agent-FQDN"); got != "" {
		t.Fatalf("switching our headers off let the caller's through: %q", got)
	}
	if got := seen.Get(HeaderClientAddress); got != "" {
		t.Errorf("our own headers were stamped with --identity-headers=false: %q", got)
	}
}

func TestMountPathIsHonoured(t *testing.T) {
	var seen http.Header
	var path string
	origin := originEcho(t, &seen, &path)
	p, _ := NewServeProxy(ProxyOptions{
		Target: mustURL(t, origin.URL), MountPath: "/api", Scope: ScopeInternet, IdentityHeaders: true,
	})
	if w := request(p, "185.220.101.1", "/api/users", nil); w.Code != http.StatusOK {
		t.Fatalf("a request under the mount got %d", w.Code)
	}
	if path != "/users" {
		t.Errorf("the origin saw %q, want the mount prefix stripped", path)
	}
	w := request(p, "185.220.101.1", "/elsewhere", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("a request outside the mount got %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/api") {
		t.Errorf("the 404 does not say where the origin IS mounted: %q", w.Body.String())
	}
	if w := request(p, "185.220.101.1", "/apifoo", nil); w.Code != http.StatusNotFound {
		t.Errorf("/apifoo was treated as being under the /api mount (%d)", w.Code)
	}
}

// TestADeadOriginIsASentence: the most common failure in daily use (they stopped their
// app) must produce something a person can act on, never an opaque 500.
func TestADeadOriginIsASentence(t *testing.T) {
	p, _ := NewServeProxy(ProxyOptions{
		Target: mustURL(t, "http://127.0.0.1:1"), Scope: ScopeInternet, IdentityHeaders: true,
		DialTimeout: 250 * time.Millisecond,
	})
	w := request(p, "185.220.101.1", "/", nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("a dead origin returned %d, want 502", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "127.0.0.1:1") || !strings.Contains(body, "did not answer") {
		t.Errorf("the 502 does not name the origin or say what happened: %q", body)
	}
	if strings.Contains(body, "goroutine") {
		t.Error("the 502 body carries a stack trace")
	}
}

func TestPeerAddressIsReadFromTheSocketOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "[2a04:2a01:1::5%eth0]:443"
	if got := peerAddr(r); got.String() != "2a04:2a01:1::5" {
		t.Errorf("peerAddr = %q for a zone-scoped literal", got)
	}
	r.RemoteAddr = "garbage"
	if got := peerAddr(r); got.IsValid() {
		t.Errorf("peerAddr returned %q for an unparseable RemoteAddr", got)
	}
}
