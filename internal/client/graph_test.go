// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- DecodeGraphResult -------------------------------------------------------------

func TestDecodeGraphResultObjectRows(t *testing.T) {
	body := []byte(`{"columns":["host","category"],"rows":[{"host":"api.openai.com","category":"cdn"}],"statistics":{"rowsReturned":1}}`)
	res, err := DecodeGraphResult(body, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Columns) != 2 || res.Columns[0] != "host" {
		t.Fatalf("columns = %v", res.Columns)
	}
	if len(res.Rows) != 1 || res.Rows[0]["category"] != "cdn" {
		t.Fatalf("rows = %v", res.Rows)
	}
	if res.Statistics["rowsReturned"] != float64(1) {
		t.Fatalf("statistics = %v", res.Statistics)
	}
	if string(res.Raw) != string(body) {
		t.Fatal("Raw must preserve the verbatim reply")
	}
}

// Positional-array rows are zipped against columns (liberal-in).
func TestDecodeGraphResultPositionalRows(t *testing.T) {
	body := []byte(`{"columns":["n","name"],"rows":[[1,"one"],[2,"two"]]}`)
	res, err := DecodeGraphResult(body, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["n"] != float64(1) || res.Rows[1]["name"] != "two" {
		t.Fatalf("rows = %v", res.Rows)
	}
}

func TestDecodeGraphResultErrorStatus(t *testing.T) {
	res, err := DecodeGraphResult([]byte(`{"error":"syntax error near RETRUN"}`), 400)
	if err == nil {
		t.Fatalf("expected an error, got %+v", res)
	}
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 400 || pe.Detail != "syntax error near RETRUN" {
		t.Fatalf("problem = %+v", pe)
	}
}

func TestDecodeGraphResultProblemObject(t *testing.T) {
	_, err := DecodeGraphResult([]byte(`{"title":"unauthorized","detail":"bad key","status":401}`), 401)
	pe, ok := AsProblem(err)
	if !ok || pe.Detail != "bad key" {
		t.Fatalf("problem = %+v (err %v)", pe, err)
	}
}

// A 200 whose body is ONLY an error field is still a failure.
func TestDecodeGraphResultErrorBodyOn200(t *testing.T) {
	if _, err := DecodeGraphResult([]byte(`{"error":"quota exceeded"}`), 200); err == nil {
		t.Fatal("expected an error for a 200 error-only body")
	}
}

func TestDecodeGraphResultNonJSON(t *testing.T) {
	if _, err := DecodeGraphResult([]byte("<html>boom</html>"), 502); err == nil {
		t.Fatal("expected an error for a non-JSON 502")
	}
	if _, err := DecodeGraphResult([]byte("hello"), 200); err == nil {
		t.Fatal("expected an error for a non-JSON 200")
	}
}

// A row that is neither object nor array is dropped, never fatal.
func TestDecodeGraphResultMalformedRowDropped(t *testing.T) {
	res, err := DecodeGraphResult([]byte(`{"columns":["n"],"rows":[{"n":1},"junk",[2]]}`), 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("expected 2 usable rows, got %d", len(res.Rows))
	}
}

// --- GraphQuery over HTTP ----------------------------------------------------------

func TestGraphQuerySendsQueryAndParameters(t *testing.T) {
	var gotBody map[string]any
	var gotKey, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["n"],"rows":[{"n":1}]}`))
	}))
	defer srv.Close()

	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "whisper-test"}, HTTPClient: srv.Client()})
	res, err := c.GraphQuery(context.Background(), "RETURN $v AS n", map[string]any{"v": 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotKey != "whisper-test" || gotCT != "application/json" {
		t.Fatalf("headers: key=%q ct=%q", gotKey, gotCT)
	}
	if gotBody["query"] != "RETURN $v AS n" {
		t.Fatalf("query sent = %v", gotBody["query"])
	}
	params, _ := gotBody["parameters"].(map[string]any)
	if params["v"] != float64(1) {
		t.Fatalf("parameters sent = %v", gotBody["parameters"])
	}
	if len(res.Rows) != 1 || res.Rows[0]["n"] != float64(1) {
		t.Fatalf("rows = %v", res.Rows)
	}
}

// nil params still serialise as an EMPTY parameters object (the documented body).
func TestGraphQueryNilParams(t *testing.T) {
	var raw map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_, _ = w.Write([]byte(`{"columns":[],"rows":[]}`))
	}))
	defer srv.Close()
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	if _, err := c.GraphQuery(context.Background(), "RETURN 1", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(raw["parameters"]) != "{}" {
		t.Fatalf("parameters = %s, want {}", raw["parameters"])
	}
}

func TestGraphQueryNeedsKey(t *testing.T) {
	c := New(Config{ControlURL: "http://127.0.0.1:1", HTTPClient: &http.Client{}})
	_, err := c.GraphQuery(context.Background(), "RETURN 1", nil)
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 {
		t.Fatalf("expected a 401 no-key problem, got %v", err)
	}
}

// --- RunFlow (gallery/run SSE) -----------------------------------------------------

func TestRunFlowStreamsEvents(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/gallery/run" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(
			": keep-alive\n\n" +
				"event: step\ndata: {\"id\":\"overview\",\"rowCount\":3}\n\n" +
				"data: {\"tail\":true}\n\n"))
	}))
	defer srv.Close()

	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	var events []FlowEvent
	err := c.RunFlow(context.Background(), srv.URL, "typosquat",
		"paypal.com", map[string]any{"level": "deep"}, func(ev FlowEvent) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["slug"] != "typosquat" {
		t.Fatalf("slug sent = %v", gotBody["slug"])
	}
	// The console contract is value + paramValues (NOT inputs/params); the primary
	// entity rides top-level `value`, tuning knobs ride `paramValues`.
	if gotBody["value"] != "paypal.com" {
		t.Fatalf("value sent = %v, want paypal.com", gotBody["value"])
	}
	pv, _ := gotBody["paramValues"].(map[string]any)
	if pv["level"] != "deep" {
		t.Fatalf("paramValues sent = %v, want level=deep", gotBody["paramValues"])
	}
	if _, hasInputs := gotBody["inputs"]; hasInputs {
		t.Fatalf("must NOT send an inputs map (console ignores it): %v", gotBody)
	}
	if len(events) != 2 || events[0].Event != "step" || events[1].Event != "" {
		t.Fatalf("events = %+v", events)
	}
	var step map[string]any
	if json.Unmarshal(events[0].Data, &step) != nil || step["rowCount"] != float64(3) {
		t.Fatalf("step data = %s", events[0].Data)
	}
}

func TestRunFlowRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"detail":"key rejected"}`))
	}))
	defer srv.Close()
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "bad"}, HTTPClient: srv.Client()})
	err := c.RunFlow(context.Background(), srv.URL, "typosquat", "", nil, func(FlowEvent) {})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 || pe.Detail != "key rejected" {
		t.Fatalf("problem = %+v (err %v)", pe, err)
	}
}

func TestRunFlowNeedsKey(t *testing.T) {
	c := New(Config{HTTPClient: &http.Client{}})
	err := c.RunFlow(context.Background(), "", "typosquat", "", nil, func(FlowEvent) {})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 401 {
		t.Fatalf("expected a 401 no-key problem, got %v", err)
	}
}

// Cancelling the context ends the stream promptly with the ctx error.
func TestRunFlowCtxCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		<-r.Context().Done() // hold the stream open until the client goes away
	}))
	defer srv.Close()
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	cx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := c.RunFlow(cx, srv.URL, "typosquat", "", nil, func(FlowEvent) {})
	if err == nil {
		t.Fatal("expected a ctx error")
	}
}

// --- Stats() + GraphQueryRows (the interactive TUI surface) ------------------------

// TestGraphResultStats proves the statistics map is parsed into a GraphStats badge,
// accepting both the documented and the shorthand spellings and both JSON number
// forms, and falling back to the decoded row count when rowCount is absent.
func TestGraphResultStats(t *testing.T) {
	res := &GraphResult{
		Rows:       []map[string]any{{"n": 1}, {"n": 2}},
		Statistics: map[string]any{"rowCount": float64(7), "executionTimeMs": float64(22), "dbHits": float64(140)},
	}
	s := res.Stats()
	if s.Rows != 7 || s.MS != 22 || s.DBHits != 140 {
		t.Fatalf("stats parse: got %+v", s)
	}

	// Shorthand spellings + json.Number form.
	res2 := &GraphResult{
		Rows:       []map[string]any{{"n": 1}},
		Statistics: map[string]any{"rows": json.Number("3"), "ms": json.Number("9")},
	}
	if s2 := res2.Stats(); s2.Rows != 3 || s2.MS != 9 {
		t.Fatalf("shorthand stats: got %+v", s2)
	}

	// No statistics at all: Rows falls back to the decoded row count, MS stays 0.
	res3 := &GraphResult{Rows: []map[string]any{{"n": 1}, {"n": 2}, {"n": 3}}}
	if s3 := res3.Stats(); s3.Rows != 3 || s3.MS != 0 {
		t.Fatalf("fallback stats: got %+v", s3)
	}
}

// TestGraphQueryRows proves the convenience wrapper returns the decoded rows plus a
// parsed GraphStats over the full HTTP path.
func TestGraphQueryRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"columns":["l"],"rows":[{"l":"HOSTNAME"}],"statistics":{"rowCount":1,"executionTimeMs":12}}`))
	}))
	defer srv.Close()
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	rows, stats, err := c.GraphQueryRows(context.Background(), "MATCH (n {name:$v}) RETURN labels(n) AS l", map[string]any{"v": "example.com"})
	if err != nil {
		t.Fatalf("GraphQueryRows: %v", err)
	}
	if len(rows) != 1 || rows[0]["l"] != "HOSTNAME" {
		t.Fatalf("rows: %+v", rows)
	}
	if stats.Rows != 1 || stats.MS != 12 {
		t.Fatalf("stats: %+v", stats)
	}
}

// TestGraphQueryRowsNeedsKey asserts the keyed-only contract propagates through the
// wrapper as a 401 problem (never an opaque error).
func TestGraphQueryRowsNeedsKey(t *testing.T) {
	c := New(Config{ControlURL: "https://example.invalid"})
	if _, _, err := c.GraphQueryRows(context.Background(), "RETURN 1", nil); err == nil {
		t.Fatal("keyless GraphQueryRows must be a 401 problem")
	}
}
