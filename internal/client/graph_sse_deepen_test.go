// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- GraphQuery / RunFlow: the remaining failure branches ----------------------------

func TestDeepenClientGraphQueryUnencodableParamsIsAClearError(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	_, err := c.GraphQuery(context.Background(), "RETURN $x", map[string]any{"x": make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "encoding the graph query") {
		t.Fatalf("unencodable params must be one clear error, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatal("no byte may reach the wire on an encode failure")
	}
}

func TestDeepenClientGraphQueryUnreachableIsWrappedHelpfully(t *testing.T) {
	c := New(Config{ControlURL: deadBase, Cred: Credential{Value: "k"}, HTTPClient: &http.Client{Timeout: 2 * time.Second}})
	_, err := c.GraphQuery(context.Background(), "RETURN 1", nil)
	if err == nil || !strings.Contains(err.Error(), "graph endpoint unreachable") {
		t.Fatalf("a dial failure must say the graph is unreachable, got %v", err)
	}
}

func TestDeepenClientRunFlowNon2xxSurfacesTheServersOwnWords(t *testing.T) {
	srv, _ := deepenclient_server(t, 402, `{"detail":"flow quota exhausted"}`)
	c := New(Config{Cred: Credential{Value: "k"}, HTTPClient: srv.Client()})
	c.sse = srv.Client()
	err := c.RunFlow(context.Background(), srv.URL, "lookalike-radar", "example.com", nil, func(FlowEvent) {})
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 402 || pe.Detail != "flow quota exhausted" {
		t.Fatalf("the server's own words must surface, got %v", err)
	}
}

func TestDeepenClientRunFlowUnencodableParamValuesIsAClearError(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "k"}})
	err := c.RunFlow(context.Background(), "https://console.example", "slug", "",
		map[string]any{"x": make(chan int)}, func(FlowEvent) {})
	if err == nil || !strings.Contains(err.Error(), "encoding the flow request") {
		t.Fatalf("unencodable paramValues must be one clear error before any network, got %v", err)
	}
}

func TestDeepenClientRunFlowUnreachableIsWrappedHelpfully(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "k"}})
	c.sse = &http.Client{Timeout: 2 * time.Second}
	err := c.RunFlow(context.Background(), deadBase, "slug", "", nil, func(FlowEvent) {})
	if err == nil || !strings.Contains(err.Error(), "flow endpoint unreachable") {
		t.Fatalf("a dial failure must say the flow endpoint is unreachable, got %v", err)
	}
}

// ---- ReadSSE: the remaining framing branches -----------------------------------------

func TestDeepenClientReadSSELoneHeartbeatEventWithNoData(t *testing.T) {
	// A bare `event: hb` frame with NO data line is the server's idle keep-alive; it
	// must surface as a heartbeat so the TUI shows "connected", not silence.
	stream := "event: hb\n\n"
	var got []MonitorEvent
	if err := ReadSSE(context.Background(), strings.NewReader(stream), func(ev MonitorEvent) {
		got = append(got, ev)
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != KindHB {
		t.Fatalf("want exactly one hb event, got %+v", got)
	}
}

func TestDeepenClientReadSSEOversizedLineIsAnErrorNotAHang(t *testing.T) {
	// A hostile/corrupt stream with a line beyond the 1 MiB scanner budget must end in
	// a clear error - never an unbounded buffer and never a silent success.
	huge := "data: " + strings.Repeat("x", 2*1024*1024) + "\n\n"
	err := ReadSSE(context.Background(), strings.NewReader(huge), func(MonitorEvent) {})
	if err == nil {
		t.Fatal("an oversized SSE line must surface as an error")
	}
}
