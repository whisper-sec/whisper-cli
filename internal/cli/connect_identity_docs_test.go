// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Whisper Security / viaGraph B.V.
package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// the CLI fetches the agent's gateway-signed well-known docs BY ITS FQDN (Host header) so the
// in-tunnel listener can serve them and a trustless verifier gets 4/4. The gateway keys the per-agent
// doc off Host, so every request must carry the (dot-stripped) FQDN as Host while dialing the base host.
func TestFetchIdentityDocsUsesHostFqdnAndReturnsServedDocs(t *testing.T) {
	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		switch r.URL.Path {
		case "/.well-known/whisper-identity":
			w.Header().Set("Content-Type", "application/jose")
			_, _ = w.Write([]byte("JWS"))
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/jwk-set+json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default: // did.json -> 404 (best-effort, skipped)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	docs := fetchIdentityDocs(srv.URL, "a1.t2.agents.whisper.online.", nil)

	if seenHost != "a1.t2.agents.whisper.online" {
		t.Fatalf("Host header = %q, want the dot-stripped agent FQDN", seenHost)
	}
	found := map[string]string{}
	for _, d := range docs {
		found[d.Path] = string(d.Body)
	}
	if found["/.well-known/whisper-identity"] != "JWS" {
		t.Fatalf("identity-doc body = %q", found["/.well-known/whisper-identity"])
	}
	if _, ok := found["/.well-known/jwks.json"]; !ok {
		t.Fatalf("jwks.json should be served")
	}
	if _, ok := found["/.well-known/did.json"]; ok {
		t.Fatalf("did.json (404) should be skipped, not served")
	}
	// content-type is carried through from the response
	for _, d := range docs {
		if d.Path == "/.well-known/whisper-identity" && d.ContentType != "application/jose" {
			t.Fatalf("identity-doc content-type = %q", d.ContentType)
		}
	}
}

// A total fetch miss (dead base) yields no docs and never panics - bring-up continues, DANE leg passes.
func TestFetchIdentityDocsBestEffortOnMiss(t *testing.T) {
	if docs := fetchIdentityDocs("http://127.0.0.1:0", "a1.t2.agents.whisper.online", nil); len(docs) != 0 {
		t.Fatalf("dead base should yield 0 docs, got %d", len(docs))
	}
	if docs := fetchIdentityDocs("", "a1.t2.agents.whisper.online", nil); docs != nil {
		t.Fatalf("empty base should yield nil docs")
	}
	if docs := fetchIdentityDocs("https://x", "", nil); docs != nil {
		t.Fatalf("empty fqdn should yield nil docs")
	}
}

// identityDocBase strips the /api/query control path to a scheme://host base, respects --control-url, and
// defaults to graph.whisper.online (the control front door).
func TestIdentityDocBaseStripsApiQueryAndRespectsOverride(t *testing.T) {
	saved := g.controlURL
	defer func() { g.controlURL = saved }()

	g.controlURL = ""
	if b := identityDocBase(); b != "https://graph.whisper.online" {
		t.Fatalf("default base = %q", b)
	}
	g.controlURL = "https://self-host.example.com/api/query"
	if b := identityDocBase(); b != "https://self-host.example.com" {
		t.Fatalf("override base = %q", b)
	}
}
