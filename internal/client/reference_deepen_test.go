// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- GraphStats: the companion /stats path -------------------------------------------

func TestDeepenClientGraphStatsFetchesTheCompanionStatsPath(t *testing.T) {
	const statsBody = `{"nodes":7400000000,"edges":39000000000,"threat_intel":{"indicators":3860000}}`
	srv, reqs := deepenclient_server(t, 200, statsBody)
	c := New(Config{ControlURL: srv.URL + "/api/query", Cred: Credential{Value: "whisper_live_test"}, HTTPClient: srv.Client()})

	raw, err := c.GraphStats(context.Background())
	if err != nil {
		t.Fatalf("GraphStats: %v", err)
	}
	req := (*reqs)[0]
	if req.method != "GET" || req.path != "/api/query/stats" {
		t.Fatalf("the stats resource sits NEXT to the query endpoint: want GET /api/query/stats, got %s %s", req.method, req.path)
	}
	if req.header.Get("X-API-Key") != "whisper_live_test" {
		t.Fatalf("stats are keyed, got key=%q", req.header.Get("X-API-Key"))
	}
	// Verbatim passthrough: a script sees exactly what the server sent.
	if string(raw) != statsBody {
		t.Fatalf("raw = %s, want the verbatim body", raw)
	}
}

func TestDeepenClientGraphStatsNeedsAKey(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{ControlURL: srv.URL, HTTPClient: srv.Client()})
	_, err := c.GraphStats(context.Background())
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 {
		t.Fatalf("want a helpful 401, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatal("no request may leave the client without a key")
	}
}

func TestDeepenClientGraphStatsSurfacesTheServersOwnWords(t *testing.T) {
	srv, _ := deepenclient_server(t, 503, `{"detail":"stats warming up"}`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.GraphStats(context.Background())
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 503 || pe.Detail != "stats warming up" {
		t.Fatalf("the server's own detail must surface, got %v", err)
	}
}

func TestDeepenClientGraphStatsNonJSON200IsAClearError(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, `<html>lb page</html>`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.GraphStats(context.Background())
	if err == nil || !strings.Contains(err.Error(), "non-JSON") {
		t.Fatalf("a non-JSON 200 must be a clear error, got %v", err)
	}
}

// ---- Text2Cypher ---------------------------------------------------------------------

func TestDeepenClientText2CypherPostsTheQuestion(t *testing.T) {
	const reply = `{"cypher":"MATCH (n) RETURN n LIMIT 1","confidence":0.9}`
	srv, reqs := deepenclient_server(t, 200, reply)
	c := New(Config{Cred: Credential{Value: "whisper_live_test"}, HTTPClient: srv.Client()})

	raw, err := c.Text2Cypher(context.Background(), srv.URL+"/api/v1/text2cypher/generate",
		Text2CypherRequest{Question: "how many hostnames?"})
	if err != nil {
		t.Fatalf("Text2Cypher: %v", err)
	}
	req := (*reqs)[0]
	if req.method != "POST" || req.path != "/api/v1/text2cypher/generate" {
		t.Fatalf("want POST the generate path, got %s %s", req.method, req.path)
	}
	if req.header.Get("X-API-Key") != "whisper_live_test" || req.header.Get("Content-Type") != "application/json" {
		t.Fatalf("keyed JSON POST expected, got key=%q ct=%q", req.header.Get("X-API-Key"), req.header.Get("Content-Type"))
	}
	// Zero-valued optionals are OMITTED (the server defaults them) - the wire body is
	// exactly {"question": ...}.
	if req.body != `{"question":"how many hostnames?"}` {
		t.Fatalf("body = %s", req.body)
	}
	if string(raw) != reply {
		t.Fatalf("raw = %s, want the verbatim body", raw)
	}
}

func TestDeepenClientText2CypherCarriesTheOptionalKnobs(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.Text2Cypher(context.Background(), srv.URL,
		Text2CypherRequest{Question: "q", Execute: true, Provider: "anthropic", Fast: true})
	if err != nil {
		t.Fatal(err)
	}
	var got Text2CypherRequest
	if err := json.Unmarshal([]byte((*reqs)[0].body), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Execute || got.Provider != "anthropic" || !got.Fast {
		t.Fatalf("optional knobs lost on the wire: %+v", got)
	}
}

func TestDeepenClientText2CypherNeedsAKey(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{HTTPClient: srv.Client()})
	_, err := c.Text2Cypher(context.Background(), srv.URL, Text2CypherRequest{Question: "q"})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 {
		t.Fatalf("want a 401 problem, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatal("no request may leave the client without a key")
	}
}

func TestDeepenClientText2CypherSurfacesTheServersOwnWords(t *testing.T) {
	srv, _ := deepenclient_server(t, 400, `{"detail":"question is required"}`)
	c := New(Config{Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.Text2Cypher(context.Background(), srv.URL, Text2CypherRequest{})
	pe, ok := AsProblem(err)
	if !ok || pe.Detail != "question is required" {
		t.Fatalf("the server's own detail must surface, got %v", err)
	}
}

func TestDeepenClientText2CypherNonJSON200IsAClearError(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, `not json`)
	c := New(Config{Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.Text2Cypher(context.Background(), srv.URL, Text2CypherRequest{Question: "q"})
	if err == nil || !strings.Contains(err.Error(), "non-JSON") {
		t.Fatalf("a non-JSON 200 must be a clear error, got %v", err)
	}
}

// ---- FetchDoc: keyless public docs, https-only ---------------------------------------

func TestDeepenClientFetchDocIsKeylessAndReturnsTheMarkdown(t *testing.T) {
	const md = "# Agents\n\nOne call, standard ports.\n"
	var sawKey, sawAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey, sawAuth = r.Header.Get("X-API-Key"), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/markdown")
		_, _ = io.WriteString(w, md)
	}))
	t.Cleanup(srv.Close)

	// A credential IS configured - and must NOT ride the public docs fetch.
	c := New(Config{Cred: Credential{Value: "whisper_live_secret"}, HTTPClient: srv.Client()})
	got, err := c.FetchDoc(context.Background(), srv.URL+"/docs/agents.md")
	if err != nil {
		t.Fatalf("FetchDoc: %v", err)
	}
	if got != md {
		t.Fatalf("doc = %q, want the verbatim markdown", got)
	}
	if sawKey != "" || sawAuth != "" {
		t.Fatalf("the public docs fetch must NEVER carry the key, got key=%q auth=%q", sawKey, sawAuth)
	}
}

func TestDeepenClientFetchDocRefusesNonHTTPS(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, "doc")
	c := New(Config{HTTPClient: srv.Client()})
	_, err := c.FetchDoc(context.Background(), "http://"+strings.TrimPrefix(srv.URL, "http://")+"/docs/x.md")
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 400 || !strings.Contains(pe.Detail, "https") {
		t.Fatalf("a non-https doc URL must be refused locally, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatal("no request may be made for a refused URL")
	}
}

func TestDeepenClientFetchDocMissingPageIsAClearProblem(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "nope")
	}))
	t.Cleanup(srv.Close)
	c := New(Config{HTTPClient: srv.Client()})
	_, err := c.FetchDoc(context.Background(), srv.URL+"/docs/missing.md")
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 404 || !strings.Contains(pe.Detail, "HTTP 404") {
		t.Fatalf("a missing page must be a clear 404 problem, got %v", err)
	}
}
