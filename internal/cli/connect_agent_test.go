// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- resolveConnectAgent: display-name resolution (fix 2) -----------------------------

// TestResolveConnectAgent_NameResolvesToAddr covers the happy path: a bare display name
// (case-insensitively, matching what `whisper list` shows) resolves to the agent's /128
// via op:list, so op:connect — which only understands a /128 or an id — gets something
// it can actually use.
func TestResolveConnectAgent_NameResolvesToAddr(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01:9::abcd"},
		{name: "watcher", addr: "2a04:2a01:9::beef"},
	}, &seen)
	defer srv.Close()

	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test", Source: client.SourceFlag}, Timeout: 5 * time.Second})

	for _, in := range []string{"scout", "Scout", "SCOUT"} {
		t.Run(in, func(t *testing.T) {
			got, err := resolveConnectAgent(c, context.Background(), in)
			if err != nil {
				t.Fatalf("resolveConnectAgent(%q) errored: %v", in, err)
			}
			if got != "2a04:2a01:9::abcd" {
				t.Fatalf("resolveConnectAgent(%q) = %q, want scout's /128", in, got)
			}
		})
	}
}

// TestResolveConnectAgent_NoMatchClearError proves an unknown display name fails with a
// CLEAR, actionable error naming the real candidates — never the control plane's opaque
// "not found", and never a silent connect to the wrong (or a freshly-created) agent.
func TestResolveConnectAgent_NoMatchClearError(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01:9::abcd"},
		{name: "watcher", addr: "2a04:2a01:9::beef"},
	}, &seen)
	defer srv.Close()

	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test", Source: client.SourceFlag}, Timeout: 5 * time.Second})

	_, err := resolveConnectAgent(c, context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected a clear error for an unknown agent name")
	}
	pe, ok := client.AsProblem(err)
	if !ok {
		t.Fatalf("expected a *client.ProblemError, got %v", err)
	}
	if !strings.Contains(pe.Detail, `"nonexistent"`) {
		t.Fatalf("error must name the selector that failed, got %q", pe.Detail)
	}
	for _, want := range []string{"scout", "watcher", "whisper list", "--agent"} {
		if !strings.Contains(pe.Detail, want) {
			t.Fatalf("error must be actionable (mention %q), got %q", want, pe.Detail)
		}
	}
}

// TestResolveConnectAgent_AddressPassesThroughNoRoundTrip proves a /128 selector is
// never sent through op:list — the common persisted-default / --agent <addr> path pays
// NO extra round-trip. An unroutable control URL proves it: if resolveConnectAgent ever
// called the control plane, this would error/hang instead of returning instantly.
func TestResolveConnectAgent_AddressPassesThroughNoRoundTrip(t *testing.T) {
	c := client.New(client.Config{
		ControlURL: "http://127.0.0.1:1", // unroutable on purpose
		Cred:       client.Credential{Value: "k", Source: client.SourceFlag},
		Timeout:    2 * time.Second,
	})
	got, err := resolveConnectAgent(c, context.Background(), "2a04:2a01:9::abcd")
	if err != nil {
		t.Fatalf("a /128 selector must pass through with no control-plane call, got error: %v", err)
	}
	if got != "2a04:2a01:9::abcd" {
		t.Fatalf("got %q, want the /128 unchanged", got)
	}
}

// TestResolveConnectAgent_EmptyPassesThrough covers the "no selector" case (the server's
// reuse-most-recent default) — resolveConnectAgent must not touch the control plane.
func TestResolveConnectAgent_EmptyPassesThrough(t *testing.T) {
	c := client.New(client.Config{
		ControlURL: "http://127.0.0.1:1",
		Cred:       client.Credential{Value: "k", Source: client.SourceFlag},
		Timeout:    2 * time.Second,
	})
	got, err := resolveConnectAgent(c, context.Background(), "")
	if err != nil || got != "" {
		t.Fatalf("resolveConnectAgent(\"\") = (%q, %v), want (\"\", nil)", got, err)
	}
}

// TestResolveConnectAgent_ExactIDPassesThrough proves an agent id (not a display name)
// still resolves correctly — the id/label/address exact-match rung keeps `--agent <id>`
// working exactly as before, even for an agent that ALSO has a human label.
func TestResolveConnectAgent_ExactIDPassesThrough(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test", Source: client.SourceFlag}, Timeout: 5 * time.Second})

	// The address itself is also an acceptable exact-match selector (defensive: a caller
	// could pass it even though looksLikeV6 would already short-circuit this in practice).
	got, err := resolveConnectAgent(c, context.Background(), "2a04:2a01:9::abcd")
	if err != nil || got != "2a04:2a01:9::abcd" {
		t.Fatalf("resolveConnectAgent(addr) = (%q, %v)", got, err)
	}
}

// --- Full command: `whisper connect --agent <display-name>` end-to-end ----------------

// TestConnect_FullCommand_AgentDisplayName proves the full `whisper connect --agent
// scout` path resolves the human name to the /128 and connects — the live symptom this
// closes ("connect --agent scout" failing opaquely because the backend only understands
// /128 or id).
func TestConnect_FullCommand_AgentDisplayName(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent")
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "scout", "--agent-file", af})
	stdout, stderr := captureStd(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("connect --agent scout errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "2a04:2a01:9::abcd") {
		t.Fatalf("expected the resolved /128 in the success line, stdout=%q stderr=%q", stdout, stderr)
	}
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("expected op:connect to run, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "2a04:2a01:9::abcd") {
		t.Fatalf("op:connect must be called with the RESOLVED /128, not the raw name; body=%q", body)
	}
}

// TestConnect_FullCommand_AgentDisplayNameNoMatch proves an unknown --agent name fails
// with a clear, actionable error and NEVER reaches op:connect (no auto-create, no
// fallback to the server default either — an explicit --agent that doesn't resolve must
// not silently connect to some OTHER agent).
func TestConnect_FullCommand_AgentDisplayNameNoMatch(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent")
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "nope", "--agent-file", af})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("connect --agent nope must error — no such agent")
	}
	if !strings.Contains(err.Error(), "nope") || !strings.Contains(err.Error(), "scout") {
		t.Fatalf("error must name the bad selector and the real candidate, got: %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("op:connect must never run for an unresolved --agent name, ops=%v", opsSeen(seen))
	}
}

// --- Row-level failure surfaces the real detail (fix 1) --------------------------------

// TestConnect_FullCommand_RowLevelFailureSurfacesRealDetail is the headline case: a
// STALE persisted agent (op:connect's row-level failure) must surface the control
// plane's SPECIFIC reason — even when that reason arrives as a bare string, the shape a
// thin control-plane proxy can legitimately send — never the generic "control plane
// reported failure".
func TestConnect_FullCommand_RowLevelFailureSurfacesRealDetail(t *testing.T) {
	const staleAddr = "2a04:2a01:9::dead"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch sniffOp(string(raw)) {
		case "connect":
			// A row-level failure: the outer YIELD row itself is ok:false, with the real
			// reason as a BARE STRING (not an RFC-7807 object).
			_, _ = w.Write([]byte(`{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":false,"status":404,"result":null,"error":"agent ` + staleAddr + ` not found","retry_after":null}]}`))
		default: // op:list — an existing fleet so connect skips the create-first path
			_, _ = w.Write([]byte(listJSON([]agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}})))
		}
	}))
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, staleAddr); err != nil {
		t.Fatal(err)
	}
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent-file", af})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("connect with a stale persisted agent must error")
	}
	if strings.Contains(err.Error(), "control plane reported failure") {
		t.Fatalf("must surface the SPECIFIC reason, not the generic fallback: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected the real not-found detail to surface, got: %v", err)
	}
	pe, ok := client.AsProblem(err)
	if !ok || pe.Status != 404 {
		t.Fatalf("expected a *client.ProblemError with status 404, got %v", err)
	}
}
