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
	"time"
)

// ---- helpers (wave-7 deepen-client; prefixed to avoid clashing with older waves) ----

// deepenclient_capture is one recorded control-plane request.
type deepenclient_capture struct {
	method, path, query, body string
	header                    http.Header
}

// deepenclient_server runs an httptest server that records every request and answers
// status+reply (Content-Type: application/json).
func deepenclient_server(t *testing.T, status int, reply string) (*httptest.Server, *[]deepenclient_capture) {
	t.Helper()
	var reqs []deepenclient_capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reqs = append(reqs, deepenclient_capture{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			body:   string(body),
			header: r.Header.Clone(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

// deepenclient_sseServer serves one fixed SSE payload and records the request.
func deepenclient_sseServer(t *testing.T, payload string) (*httptest.Server, *[]deepenclient_capture) {
	t.Helper()
	var reqs []deepenclient_capture
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, deepenclient_capture{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			header: r.Header.Clone(),
		})
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

// ---- New: canonical defaults ---------------------------------------------------------

func TestDeepenClientNewAppliesCanonicalDefaults(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "k", Source: SourceFlag}})
	if c.controlURL != DefaultControlURL {
		t.Fatalf("controlURL = %q, want the canonical default", c.controlURL)
	}
	if got := c.MonitorURL(); got != DefaultMonitorURLs[0] {
		t.Fatalf("first monitor attempt = %q, want %q", got, DefaultMonitorURLs[0])
	}
	if c.rdapURL != DefaultRDAPURL || c.verifyURL != DefaultVerifyURL || c.echoURL != DefaultEchoURL {
		t.Fatalf("rdap/verify/echo defaults not applied: %q %q %q", c.rdapURL, c.verifyURL, c.echoURL)
	}
	// The control client is bounded (30s default); the SSE client must have NO overall
	// timeout - a long-lived stream killed by a client timeout would be a serving bug.
	if c.http.Timeout != 30*time.Second {
		t.Fatalf("control timeout = %v, want the 30s default", c.http.Timeout)
	}
	if c.sse.Timeout != 0 {
		t.Fatalf("the SSE client must have no overall timeout, got %v", c.sse.Timeout)
	}
	if got := c.Credential(); got.Value != "k" || got.Source != SourceFlag {
		t.Fatalf("Credential() must return the resolved principal, got %+v", got)
	}
}

func TestDeepenClientNewHonoursExplicitTimeoutAndMonitorPin(t *testing.T) {
	c := New(Config{Timeout: 5 * time.Second, MonitorURL: "https://pin.example/monitor/stream"})
	if c.http.Timeout != 5*time.Second {
		t.Fatalf("timeout = %v, want 5s", c.http.Timeout)
	}
	// An explicit override PINS the list: even after a simulated failed attempt the
	// next reconnect must stay on the pinned URL (no rotation off an explicit choice).
	if got := c.MonitorURL(); got != "https://pin.example/monitor/stream" {
		t.Fatalf("pinned monitor = %q", got)
	}
	c.monitorIdx.Add(1)
	if got := c.MonitorURL(); got != "https://pin.example/monitor/stream" {
		t.Fatalf("a pinned monitor URL must never rotate away, got %q", got)
	}
}

func TestDeepenClientMonitorURLRotatesAcrossTheActiveActivePair(t *testing.T) {
	c := New(Config{})
	c.monitorURLs = []string{"https://a.example", "https://b.example"}
	if got := c.MonitorURL(); got != "https://a.example" {
		t.Fatalf("start = %q", got)
	}
	c.monitorIdx.Add(1)
	if got := c.MonitorURL(); got != "https://b.example" {
		t.Fatalf("after one failure the OTHER node must be next, got %q", got)
	}
	c.monitorIdx.Add(1)
	if got := c.MonitorURL(); got != "https://a.example" {
		t.Fatalf("the rotation must wrap back to the first node, got %q", got)
	}
}

// ---- Query / Agents: request build + auth + envelope ---------------------------------

func TestDeepenClientAgentsPostsTheDocumentedBodyWithTheOwnerKey(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200,
		`{"ok":true,"status":200,"result":{"columns":["agent"],"rows":[["ag-1"]]}}`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "whisper_live_test"}, HTTPClient: srv.Client()})

	env, err := c.Agents(context.Background(), "list", nil)
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	if !env.Ok || env.Result == nil || len(env.Result.Rows) != 1 || env.Result.Columns[0] != "agent" {
		t.Fatalf("envelope not decoded: %+v", env)
	}
	if len(*reqs) != 1 {
		t.Fatalf("want exactly 1 request, got %d", len(*reqs))
	}
	req := (*reqs)[0]
	if req.method != http.MethodPost {
		t.Fatalf("method = %s, want POST", req.method)
	}
	// The body is EXACTLY the documented {"query": "..."} wire shape.
	var body map[string]string
	if err := json.Unmarshal([]byte(req.body), &body); err != nil {
		t.Fatalf("body is not the documented JSON: %v", err)
	}
	if body["query"] != `CALL whisper.agents({op:'list', args:{}})` {
		t.Fatalf("query = %q", body["query"])
	}
	// Exactly ONE auth header: the owner key as X-API-Key, never a Bearer.
	if req.header.Get("X-API-Key") != "whisper_live_test" || req.header.Get("Authorization") != "" {
		t.Fatalf("owner-key auth wrong: key=%q auth=%q", req.header.Get("X-API-Key"), req.header.Get("Authorization"))
	}
	if req.header.Get("Content-Type") != "application/json" || req.header.Get("User-Agent") != userAgent {
		t.Fatalf("content-type/user-agent wrong: %q %q", req.header.Get("Content-Type"), req.header.Get("User-Agent"))
	}
}

func TestDeepenClientQueryBearerTokenRidesAuthorizationOnly(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{"ok":true,"status":200,"result":{"columns":[],"rows":[]}}`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "et_monitor", Bearer: true}, HTTPClient: srv.Client()})
	if _, err := c.Query(context.Background(), "CALL whisper.agents({op:'logs', args:{}})"); err != nil {
		t.Fatal(err)
	}
	req := (*reqs)[0]
	if req.header.Get("Authorization") != "Bearer et_monitor" || req.header.Get("X-API-Key") != "" {
		t.Fatalf("an et_ token must ride Authorization: Bearer ONLY, got auth=%q key=%q",
			req.header.Get("Authorization"), req.header.Get("X-API-Key"))
	}
}

func TestDeepenClientAgentsEscapesHostileArgsIntoTheQuery(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{"ok":true,"status":200,"result":{"columns":[],"rows":[]}}`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	hostile := `x'}) RETURN 1 //`
	if _, err := c.Agents(context.Background(), "register", map[string]any{"name": hostile}); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte((*reqs)[0].body), &body); err != nil {
		t.Fatal(err)
	}
	// The exact injection-proof form BuildAgentsQuery pins: the quote is backslash-escaped,
	// so the hostile value can never break out of the args map - and, unlike the doubling
	// this replaced, the reader at the far end takes it back apart into the same bytes.
	want := BuildAgentsQuery("register", map[string]any{"name": hostile})
	if body["query"] != want {
		t.Fatalf("query = %q, want %q", body["query"], want)
	}
	if !strings.Contains(body["query"], `'x\'}) RETURN 1 //'`) {
		t.Fatalf("hostile arg not escaped in place: %q", body["query"])
	}
}

func TestDeepenClientQueryWithoutAKeyIsALocal401(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{ControlURL: srv.URL, HTTPClient: srv.Client()})
	_, err := c.Query(context.Background(), "CALL whisper.agents({op:'list', args:{}})")
	if err == nil {
		t.Fatal("no key must be a clean local error")
	}
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 || !strings.Contains(pe.Detail, "whisper login") {
		t.Fatalf("want a helpful 401 problem, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatalf("no request may leave the client without a key; saw %d", len(*reqs))
	}
}

func TestDeepenClientQueryTransportErrorIsWrappedHelpfully(t *testing.T) {
	c := New(Config{ControlURL: deadBase, Cred: Credential{Value: "k"}, HTTPClient: &http.Client{Timeout: 2 * time.Second}})
	_, err := c.Query(context.Background(), "CALL whisper.agents({op:'list', args:{}})")
	if err == nil || !strings.Contains(err.Error(), "control plane unreachable") {
		t.Fatalf("a dial failure must say the control plane is unreachable, got %v", err)
	}
}

func TestDeepenClientQueryNonJSONSuccessBodyIsAClearError(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, `<html>proxy page</html>`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.Query(context.Background(), "CALL whisper.agents({op:'list', args:{}})")
	if err == nil || !strings.Contains(err.Error(), "non-JSON") {
		t.Fatalf("a non-JSON 200 must be a clear decode error, got %v", err)
	}
}

func TestDeepenClientQueryNonJSON5xxBecomesAProblemEnvelope(t *testing.T) {
	srv, _ := deepenclient_server(t, 502, `<html>bad gateway</html>`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	env, err := c.Query(context.Background(), "CALL whisper.agents({op:'list', args:{}})")
	if err != nil {
		t.Fatalf("a non-JSON 5xx must decode into a problem envelope, not an error: %v", err)
	}
	if env.Ok || env.Err == nil || env.Err.Status != 502 {
		t.Fatalf("want ok=false with a 502 problem, got %+v", env)
	}
}

// ---- StreamMonitor: SSE + narrow + active/active failover ----------------------------

func TestDeepenClientStreamMonitorDecodesEventsAndNarrowsByAgent(t *testing.T) {
	payload := "event: dns\n" +
		`data: {"kind":"dns","qname":"example.com.","decision":"allow"}` + "\n\n" +
		": hb\n"
	srv, reqs := deepenclient_sseServer(t, payload)
	c := New(Config{Cred: Credential{Value: "whisper_live_test"}})
	c.monitorURLs = []string{srv.URL + "/monitor/stream"}
	c.sse = srv.Client()

	var events []MonitorEvent
	err := c.StreamMonitor(context.Background(), "2a04:2a01::7", func(ev MonitorEvent) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("a cleanly-closed stream must end without error: %v", err)
	}
	req := (*reqs)[0]
	if req.method != http.MethodGet || req.path != "/monitor/stream" {
		t.Fatalf("want GET /monitor/stream, got %s %s", req.method, req.path)
	}
	if req.query != "agent=2a04%3A2a01%3A%3A7" {
		t.Fatalf("the /128 narrow must ride ?agent=, got query %q", req.query)
	}
	if req.header.Get("Accept") != "text/event-stream" || req.header.Get("X-API-Key") != "whisper_live_test" {
		t.Fatalf("accept/auth wrong: %q %q", req.header.Get("Accept"), req.header.Get("X-API-Key"))
	}
	var dns, hb int
	for _, e := range events {
		switch e.Kind {
		case KindDNS:
			dns++
			if e.QName != "example.com." || e.Decision != "allow" {
				t.Fatalf("dns event decoded wrong: %+v", e)
			}
		case KindHB:
			hb++
		}
	}
	if dns != 1 || hb != 1 {
		t.Fatalf("want 1 dns + 1 hb, got dns=%d hb=%d (%+v)", dns, hb, events)
	}
}

func TestDeepenClientStreamMonitorWholeTenantOmitsTheAgentParam(t *testing.T) {
	srv, reqs := deepenclient_sseServer(t, ": hb\n")
	c := New(Config{Cred: Credential{Value: "k"}})
	c.monitorURLs = []string{srv.URL}
	c.sse = srv.Client()
	if err := c.StreamMonitor(context.Background(), "   ", func(MonitorEvent) {}); err != nil {
		t.Fatal(err)
	}
	if q := (*reqs)[0].query; q != "" {
		t.Fatalf("a whole-tenant stream must carry no ?agent=, got %q", q)
	}
}

func TestDeepenClientStreamMonitor503IsABackOffProblemAndFailsOver(t *testing.T) {
	srv, _ := deepenclient_server(t, 503, "")
	c := New(Config{Cred: Credential{Value: "k"}})
	c.monitorURLs = []string{srv.URL, "https://other.example/monitor/stream"}
	c.sse = srv.Client()

	err := c.StreamMonitor(context.Background(), "", func(MonitorEvent) {})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 503 || !strings.Contains(pe.Detail, "back off") {
		t.Fatalf("a 503 must surface as a back-off problem, got %v", err)
	}
	// The NEXT reconnect must land on the other active/active node.
	if got := c.MonitorURL(); got != "https://other.example/monitor/stream" {
		t.Fatalf("after a 503 the next attempt must be the other node, got %q", got)
	}
}

func TestDeepenClientStreamMonitorTransportErrorFailsOverThenServes(t *testing.T) {
	srv, _ := deepenclient_sseServer(t, ": hb\n")
	c := New(Config{Cred: Credential{Value: "k"}})
	c.monitorURLs = []string{deadBase, srv.URL}
	c.sse = &http.Client{Timeout: 2 * time.Second}

	err := c.StreamMonitor(context.Background(), "", func(MonitorEvent) {})
	if err == nil || !strings.Contains(err.Error(), "monitor stream unreachable") {
		t.Fatalf("a dead node must be a clear unreachable error, got %v", err)
	}
	// The failover index advanced: the SAME client now reaches the healthy node.
	if got := c.MonitorURL(); got != srv.URL {
		t.Fatalf("next attempt must be the healthy node, got %q", got)
	}
	if err := c.StreamMonitor(context.Background(), "", func(MonitorEvent) {}); err != nil {
		t.Fatalf("the reconnect on the healthy node must serve: %v", err)
	}
}

func TestDeepenClientStreamMonitorWithoutAKeyIsA401(t *testing.T) {
	c := New(Config{})
	err := c.StreamMonitor(context.Background(), "", func(MonitorEvent) {})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 {
		t.Fatalf("no key must be a clean 401 problem, got %v", err)
	}
}

func TestDeepenClientStreamMonitorMalformedMonitorURL(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "k"}})
	c.monitorURLs = []string{"http://[::1"} // unclosed bracket: not parseable
	if err := c.StreamMonitor(context.Background(), "", func(MonitorEvent) {}); err == nil {
		t.Fatal("an unparseable monitor URL must error cleanly, never panic")
	}
}
