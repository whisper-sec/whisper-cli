// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
)

// mcp_graph_keyless_test.go pins the two-tier contract asks of `whisper mcp`
// for the GRAPH surface: the catalog's keyless recipes really run with no key,
// and everything else really does not. Both halves are asserted against a fake graph
// endpoint, so "it worked" means bytes actually left the client, not that an error
// happened to be absent.

// fakeGraph is a stand-in for the graph endpoint that records what reached it.
type fakeGraph struct {
	srv *httptest.Server

	mu       sync.Mutex
	hits     int
	lastKey  string
	hadKey   bool
	lastBody map[string]any
}

func newFakeGraph(t *testing.T, reply string) *fakeGraph {
	t.Helper()
	f := &fakeGraph{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		f.lastKey = r.Header.Get("X-API-Key")
		_, f.hadKey = r.Header["X-Api-Key"]
		f.lastBody = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&f.lastBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) snapshot() (hits int, key string, hadKey bool, body map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits, f.lastKey, f.hadKey, f.lastBody
}

// A keyless recipe runs with NO key: the call reaches the endpoint, carries the
// recipe's own Cypher, sends no auth header, and comes back as a normal (non-error)
// tool result. This is the value a key-less MCP user gets, and it is real.
func TestMCP_KeylessGraphToolRunsWithNoKey(t *testing.T) {
	f := newFakeGraph(t, `{"columns":["host","label"],"rows":[{"host":"8.8.8.8","label":"benign-allowlisted"}]}`)
	pinKeyState(t, "", f.srv.URL)

	r := drive(t, callLine(20, "whisper_assess", `{"v":"8.8.8.8"}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("whisper_assess must answer without a key, got the error %q", text)
	}
	if !strings.Contains(text, "benign-allowlisted") {
		t.Fatalf("the endpoint's own reply must come back verbatim, got %q", text)
	}
	hits, _, hadKey, body := f.snapshot()
	if hits != 1 {
		t.Fatalf("the graph endpoint was hit %d times, want exactly 1 (a result with no request is not a result)", hits)
	}
	if hadKey {
		t.Fatal("a keyless call must send no X-API-Key header at all")
	}
	e, ok := catalog.Find("assess")
	if !ok {
		t.Fatal("the assess recipe vanished from the catalog")
	}
	if body["query"] != e.Exec.Cypher {
		t.Fatalf("query sent = %v, want the catalog's own cypher %q", body["query"], e.Exec.Cypher)
	}
	params, _ := body["parameters"].(map[string]any)
	if params["v"] != "8.8.8.8" {
		t.Fatalf("parameters sent = %v, want v=8.8.8.8", body["parameters"])
	}
}

// All three public procedures work keyless, addressed by the catalog input id as well
// as by its wire param name (liberal in what we accept).
func TestMCP_EveryKeylessRecipeAnswersWithoutAKey(t *testing.T) {
	f := newFakeGraph(t, `{"columns":["x"],"rows":[{"x":1}]}`)
	pinKeyState(t, "", f.srv.URL)

	seen := 0
	id := 30
	for _, e := range catalog.All() {
		if !e.IsKeyless() {
			continue
		}
		seen++
		for _, args := range []string{`{"v":"example.com"}`, `{"value":"example.com"}`, `{}`} {
			id++
			r := drive(t, callLine(id, e.ToolName(), args))
			text, isError := toolText(t, r[0])
			if isError {
				t.Fatalf("%s with args %s must answer without a key, got %q", e.ToolName(), args, text)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no keyless recipes in the catalog - this test would pass vacuously")
	}
	hits, _, _, _ := f.snapshot()
	if want := seen * 3; hits != want {
		t.Fatalf("the graph endpoint was hit %d times, want %d (one per keyless call)", hits, want)
	}
}

// The control: the keyed half is still keyed. Raw Cypher and a keyed recipe are
// refused with the message that names the fix, and nothing is sent on the wire.
func TestMCP_KeyedGraphToolsStillRefusedWithoutAKey(t *testing.T) {
	f := newFakeGraph(t, `{"columns":[],"rows":[]}`)
	pinKeyState(t, "", f.srv.URL)

	for i, tc := range []struct{ tool, args string }{
		{"whisper_graph_query", `{"query":"MATCH (n) RETURN count(n)"}`},
		{"whisper_typosquat", `{"v":"paypal.com"}`},
		{"whisper_dbSchema", `{}`},
	} {
		r := drive(t, callLine(50+i, tc.tool, tc.args))
		text, isError := toolText(t, r[0])
		if !isError {
			t.Fatalf("%s without a key must be a tool error, got %q", tc.tool, text)
		}
		if !strings.Contains(text, "WHISPER_API_KEY") {
			t.Fatalf("%s no-key error must name the fix, got %q", tc.tool, text)
		}
		if !strings.Contains(text, "whisper_assess") {
			t.Fatalf("%s no-key error should point at the keyless tools that DO work, got %q", tc.tool, text)
		}
	}
	if hits, _, _, _ := f.snapshot(); hits != 0 {
		t.Fatalf("a refused keyed call must never reach the endpoint, but it was hit %d times", hits)
	}
}

// A key that resolves still rides along on a keyless read: same statement, higher cap.
func TestMCP_KeylessGraphToolCarriesAKeyWhenOneResolves(t *testing.T) {
	f := newFakeGraph(t, `{"columns":["x"],"rows":[{"x":1}]}`)
	pinKeyState(t, "whisper_live_test", f.srv.URL)

	r := drive(t, callLine(60, "whisper_identify", `{"v":"api.openai.com"}`))
	if text, isError := toolText(t, r[0]); isError {
		t.Fatalf("whisper_identify with a key must answer, got %q", text)
	}
	hits, key, _, _ := f.snapshot()
	if hits != 1 {
		t.Fatalf("endpoint hit %d times, want 1", hits)
	}
	if key != "whisper_live_test" {
		t.Fatalf("X-API-Key = %q, want the resolved key to ride along on a keyless read", key)
	}
}
