// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// lifecyclePlane answers op:list and op:agent with canned bodies, recording each request body.
type lifecyclePlane struct {
	mu     sync.Mutex
	bodies []string
	list   func(body string) string
	agent  string
}

func (p *lifecyclePlane) serve(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		p.mu.Lock()
		p.bodies = append(p.bodies, body)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body, "agent") && !strings.Contains(body, "kind") && p.agent != "" {
			_, _ = w.Write([]byte(p.agent))
			return
		}
		_, _ = w.Write([]byte(p.list(body)))
	}))
	t.Cleanup(srv.Close)
	saved := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = saved })
}

func listPage(rows ...string) string {
	return `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` + strings.Join(rows, ",") + `]}}`
}

const liveRow = `["agents",{"agent":"agent-alive","address":"2a04:2a01:9::1","state":"active","created":"1700000000"}]`

func goneRow(id, addr, state, actor, reason string) string {
	return `["agents",{"agent":"` + id + `","address":"` + addr + `","state":"` + state +
		`","state_at":1700000500000,"state_actor":"` + actor + `","state_reason":"` + reason + `"}]`
}

func runCmd(t *testing.T, args ...string) (error, string, string) {
	t.Helper()
	var cmd = newListCmd()
	if len(args) > 0 && args[0] == "agent" {
		cmd = newAgentCmd()
		args = args[1:]
	}
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	var err error
	stdout, stderr := captureStd(t, func() { err = cmd.Execute() })
	return err, stdout, stderr
}

func TestListTombstones_FollowsEveryPage_AndShowsWhatBecameOfEachAgent(t *testing.T) {
	p := &lifecyclePlane{list: func(body string) string {
		if strings.Contains(body, "cursor") {
			return listPage(goneRow("agent-b", "2a04:2a01:9::b", "reaped", "system", "ephemeral_reap"),
				`["page",{"include":"tombstones","cursor":"","tombstones":1,"complete":true}]`)
		}
		return listPage(liveRow, goneRow("agent-a", "2a04:2a01:9::a", "revoked", "owner", "owner_request"),
			`["page",{"include":"tombstones","cursor":"2a04:2a01:9::a|5","tombstones":1,"complete":false}]`)
	}}
	p.serve(t)
	err, out, errOut := runCmd(t, "--tombstones")
	if err != nil {
		t.Fatalf("list --tombstones: %v %s", err, errOut)
	}
	for _, want := range []string{"agent-alive", "GONE", "agent-a", "revoked", "owner_request", "agent-b", "reaped",
		"ephemeral_reap"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if len(p.bodies) != 2 || !strings.Contains(p.bodies[0], "tombstones") || !strings.Contains(p.bodies[1], "cursor") {
		t.Fatalf("expected two pages, the second with the cursor, got %v", p.bodies)
	}
}

func TestListTombstones_AReplyWithoutTheWitnessIsNeverReadAsNoTombstones(t *testing.T) {
	p := &lifecyclePlane{list: func(string) string { return listPage(liveRow) }} // an older control plane
	p.serve(t)
	err, out, _ := runCmd(t, "--tombstones")
	if err == nil || !strings.Contains(friendly(err), "being updated") {
		t.Fatalf("a reply with no page witness must say the plane is being updated, got %v", err)
	}
	if strings.Contains(out, "GONE") {
		t.Fatalf("nothing about tombstones may be rendered, got %s", out)
	}
}

func TestListTombstones_OnlyGoesWithAgents(t *testing.T) {
	p := &lifecyclePlane{list: func(string) string { return listPage() }}
	p.serve(t)
	if err, _, _ := runCmd(t, "--tombstones", "--kind", "records"); err == nil {
		t.Fatal("--tombstones with another kind must be refused")
	}
}

func agentReply(cols []string, vals []string) string {
	return `{"ok":true,"status":200,"result":{"columns":["` + strings.Join(cols, `","`) + `"],"rows":[[` +
		strings.Join(vals, ",") + `]]}}`
}

func TestAgentDetail_AGoneAgentSaysWhatHappened_AndAContainmentOffersNoFix(t *testing.T) {
	cols := []string{"agent", "address", "state", "state_at", "state_actor", "state_reason"}
	p := &lifecyclePlane{agent: agentReply(cols, []string{`"agent-x"`, `"2a04:2a01:9::x"`, `"revoked"`,
		`1700000500000`, `"operator"`, `"containment"`})}
	p.serve(t)
	err, out, errOut := runCmd(t, "agent", "agent-x")
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	if !strings.Contains(out, "containment") || !strings.Contains(errOut, "administrator") {
		t.Fatalf("the containment must be named and the administrator pointed to, got\n%s\n%s", out, errOut)
	}
	if strings.Contains(errOut, "whisper create") {
		t.Fatalf("a containment offers no one-click fix, got %s", errOut)
	}
	if !strings.Contains(p.bodies[0], "tombstones") {
		t.Fatalf("the agent read asks for the lifecycle, got %s", p.bodies[0])
	}
}

func TestAgentDetail_AReversibleRevokeIsNeverCalledPermanent(t *testing.T) {
	cols := []string{"agent", "address", "state", "state_at", "state_actor", "state_reason", "reversible"}
	p := &lifecyclePlane{agent: agentReply(cols, []string{`"a77"`, `"2a04:2a01:9::77"`, `"revoked"`,
		`1700000500000`, `"owner"`, `"owner_request"`, `true`})}
	p.serve(t)
	_, _, errOut := runCmd(t, "agent", "a77")
	if strings.Contains(errOut, "does not come back") || !strings.Contains(errOut, "reverse:true") {
		t.Fatalf("a reversible revoke says how to undo it, got %s", errOut)
	}
}

func TestListTombstones_AListingThatStopsShortIsAnError_NeverAShorterList(t *testing.T) {
	cases := map[string]func(body string) string{
		"complete false, no cursor": func(string) string {
			return listPage(goneRow("agent-a", "2a04:2a01:9::a", "revoked", "owner", "owner_request"),
				`["page",{"include":"tombstones","cursor":"","tombstones":1,"complete":false}]`)
		},
		"cursor not a string": func(string) string {
			return listPage(`["page",{"include":"tombstones","cursor":5,"tombstones":0,"complete":false}]`)
		},
		"a repeated page": func(string) string {
			return listPage(`["page",{"include":"tombstones","cursor":"c1","tombstones":0,"complete":false}]`)
		},
		"page two without the witness": func(body string) string {
			if strings.Contains(body, "cursor") {
				return listPage(liveRow)
			}
			return listPage(`["page",{"include":"tombstones","cursor":"c1","tombstones":0,"complete":false}]`)
		},
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			p := &lifecyclePlane{list: list}
			p.serve(t)
			err, out, errOut := runCmd(t, "--tombstones")
			if err == nil {
				t.Fatalf("must fail, got\n%s\n%s", out, errOut)
			}
			if strings.Contains(out+errOut, "no agents gone") {
				t.Fatalf("an incomplete listing never reads as nothing gone: %s %s", out, errOut)
			}
		})
	}
}

func TestListTombstones_JSONIsOneFinishedPage(t *testing.T) {
	p := &lifecyclePlane{list: func(body string) string {
		if strings.Contains(body, "cursor") {
			return listPage(goneRow("agent-b", "2a04:2a01:9::b", "reaped", "system", "ephemeral_reap"),
				`["page",{"include":"tombstones","cursor":"","tombstones":1,"complete":true}]`)
		}
		return listPage(liveRow, `["page",{"include":"tombstones","cursor":"c1","tombstones":0,"complete":false}]`)
	}}
	p.serve(t)
	saved := g.jsonOut
	g.jsonOut = true
	defer func() { g.jsonOut = saved }()
	err, out, _ := runCmd(t, "--tombstones")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, `"page"`) != 1 || strings.Contains(out, `"c1"`) || !strings.Contains(out, `"complete": true`) {
		t.Fatalf("one final page row and no intermediate cursor, got %s", out)
	}
}

func TestTables_NeverPrintAServersEscapeSequences(t *testing.T) {
	evil := `x\u001b]0;owned\u0007\u202econtainment\nfake`
	p := &lifecyclePlane{list: func(string) string {
		return listPage(`["agents",{"agent":"agent-e","address":"2a04:2a01:9::e","label":"`+evil+
			`","state":"revoked","state_at":1,"state_actor":"owner","state_reason":"`+evil+`"}]`,
			`["page",{"include":"tombstones","cursor":"","tombstones":1,"complete":true}]`)
	}}
	p.serve(t)
	_, out, _ := runCmd(t, "--tombstones")
	if strings.ContainsAny(out, "\u001b\u0007\u202e") || strings.Contains(out, "\nfake") {
		t.Fatalf("control and format characters must not reach the terminal: %q", out)
	}
}

func TestTables_TimeCellsAreSanitisedToo(t *testing.T) {
	osc := `\u001b]0;owned\u0007`
	p := &lifecyclePlane{list: func(string) string {
		return listPage(`["agents",{"agent":"agent-l","address":"2a04:2a01:9::1","state":"active","created":"`+osc+`"}]`,
			`["agents",{"agent":"agent-g","address":"2a04:2a01:9::2","state":"revoked","state_at":"`+osc+
				`","state_actor":"owner","state_reason":"owner_request"}]`,
			`["page",{"include":"tombstones","cursor":"","tombstones":1,"complete":true}]`)
	}}
	p.serve(t)
	_, out, _ := runCmd(t, "--tombstones")
	if strings.ContainsAny(out, "\u001b\u0007") {
		t.Fatalf("a time cell must not carry an escape: %q", out)
	}
}

func TestAgentDetail_TheReverseHintQuotesAndFallsBackToTheAddress(t *testing.T) {
	if got := lifecycleNote("revoked", "owner", "owner_request", true, true, "", "2a04:2a01:9::5"); !strings.Contains(got, "address:'2a04:2a01:9::5'") {
		t.Fatalf("no agent id: the hint selects by address, got %s", got)
	}
	if got := lifecycleNote("revoked", "owner", "owner_request", true, true, "o'bad", ""); !strings.Contains(got, `agent:'o\'bad'`) {
		t.Fatalf("a quote in the id is escaped, got %s", got)
	}
}

func TestAgentDetail_AnEmpty200IsNotNotFound(t *testing.T) {
	p := &lifecyclePlane{agent: `{"ok":true,"status":200,"result":{"columns":[],"rows":[]}}`}
	p.serve(t)
	err, _, errOut := runCmd(t, "agent", "agent-e")
	if err == nil || strings.Contains(errOut, "not found in your account") {
		t.Fatalf("an empty 200 is an unanswered question, never a not-found with exit 0: %v %s", err, errOut)
	}
}

func TestAgentDetail_RetriesARowStillBeingWritten(t *testing.T) {
	calls := 0
	pending := `{"ok":false,"status":503,"result":null,"error":{"code":"STORE_UNAVAILABLE","message":"the record` +
		` of what happened to this agent is still being written. Nothing was changed; retry shortly",` +
		`"retryable":true,"reason":"lifecycle_pending"}}`
	cols := []string{"agent", "address", "state", "state_at", "state_actor", "state_reason"}
	ok := agentReply(cols, []string{`"agent-p"`, `"2a04:2a01:9::p"`, `"reaped"`, `1700000500000`, `"system"`,
		`"ephemeral_reap"`})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write([]byte(pending))
			return
		}
		_, _ = w.Write([]byte(ok))
	}))
	t.Cleanup(srv.Close)
	saved := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 10 * time.Second, quiet: true}
	t.Cleanup(func() { g = saved })
	err, out, _ := runCmd(t, "agent", "agent-p")
	if err != nil || calls != 2 || !strings.Contains(out, "reaped") {
		t.Fatalf("one retry after lifecycle_pending, then the row: %v calls=%d %s", err, calls, out)
	}
}

func TestAgentDetail_ARevokedAgentPointsAtCreate(t *testing.T) {
	cols := []string{"agent", "address", "state", "state_at", "state_actor", "state_reason"}
	p := &lifecyclePlane{agent: agentReply(cols, []string{`"agent-y"`, `"2a04:2a01:9::y"`, `"revoked"`,
		`1700000500000`, `"owner"`, `"owner_request"`})}
	p.serve(t)
	_, _, errOut := runCmd(t, "agent", "agent-y")
	if !strings.Contains(errOut, "whisper create") {
		t.Fatalf("a revoked agent names the way forward, got %s", errOut)
	}
}

func TestAgentDetail_WithoutTheWitness_SaysTheLifecycleIsNotAvailable(t *testing.T) {
	p := &lifecyclePlane{agent: agentReply([]string{"agent", "address", "state"},
		[]string{`"agent-z"`, `"2a04:2a01:9::z"`, `"active"`})}
	p.serve(t)
	err, out, errOut := runCmd(t, "agent", "agent-z")
	if err != nil || !strings.Contains(out, "agent-z") || !strings.Contains(errOut, "being updated") {
		t.Fatalf("an older plane still shows the agent and says the lifecycle is not available, got %v\n%s\n%s",
			err, out, errOut)
	}
}

func TestAgentNotFound_TheWitnessedOneIsPlain_TheUnwitnessedOneSaysTheCaveat(t *testing.T) {
	notFound := func(reason string) string {
		r := ""
		if reason != "" {
			r = `,"reason":"` + reason + `"`
		}
		return `{"ok":false,"status":404,"result":null,"error":{"code":"NOT_FOUND","message":"agent not found",` +
			`"retryable":false` + r + `}}`
	}
	p := &lifecyclePlane{agent: notFound("no_record")}
	p.serve(t)
	err, _, _ := runCmd(t, "agent", "agent-q")
	if err == nil || strings.Contains(friendly(err), "being updated") {
		t.Fatalf("a witnessed 404 is the plain answer, got %v", err)
	}
	p2 := &lifecyclePlane{agent: notFound("")}
	p2.serve(t)
	err, _, _ = runCmd(t, "agent", "agent-q")
	if err == nil || !strings.Contains(friendly(err), "being updated") {
		t.Fatalf("an unwitnessed 404 carries the caveat, got %v", err)
	}
}

// --- whisper create --idempotency-key -------------------------------------------------------------

func runCreate(t *testing.T, args ...string) (error, string, string) {
	t.Helper()
	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	var err error
	stdout, stderr := captureStd(t, func() { err = cmd.Execute() })
	return err, stdout, stderr
}

// idemServer returns a reader for the request bodies the server saw. The reader takes the server's lock:
// the handler runs on the server's goroutine, and the race detector sees no ordering through the socket
// between its append and the test's read, even when the client has already returned.
func idemServer(t *testing.T, handle func(n int, body string, w http.ResponseWriter, r *http.Request)) func() []string {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		n := len(bodies)
		mu.Unlock()
		handle(n, string(raw), w, r)
	}))
	t.Cleanup(srv.Close)
	saved := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = saved })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

const registeredReply = `{"ok":true,"status":200,"result":{"columns":["agent","address","fqdn","api_key"],"rows":[["agent-a1",` +
	`"2a04:2a01:9::a1","a1.agents.whisper.online.","whisper_live_REDACTED"]]}}`

func refusal(code, agent, address string) string {
	return `{"ok":false,"status":409,"result":null,"error":{"code":"` + code + `","message":"m","retryable":false,` +
		`"agent":"` + agent + `","address":"` + address + `"}}`
}

func TestCreate_TheIdempotencyKeyRidesTheRegister_AndImpliesIt(t *testing.T) {
	bodies := idemServer(t, func(_ int, _ string, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(registeredReply))
	})
	if err, _, errOut := runCreate(t, "--name", "bot", "--idempotency-key", "job-17"); err != nil {
		t.Fatalf("create: %v %s", err, errOut)
	}
	if len(bodies()) != 1 || !strings.Contains(bodies()[0], "register") || !strings.Contains(bodies()[0], "job-17") {
		t.Fatalf("one op:register carrying the key, got %v", bodies())
	}
}

func TestCreate_TheIdempotencyRefusalsNameTheAgent(t *testing.T) {
	cases := map[string]string{
		"IDEMPOTENCY_MISMATCH": "for a different request",
		"ATTEMPT_CONSUMED":     "which is gone",
		"ALREADY_REGISTERED":   "already produced agent agent-a1",
	}
	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			idemServer(t, func(_ int, _ string, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(refusal(code, "agent-a1", "2a04:2a01:9::a1")))
			})
			err, _, _ := runCreate(t, "--name", "bot", "--idempotency-key", "job-18")
			if err == nil {
				t.Fatal("a refusal is an error")
			}
			msg := friendly(err)
			if !strings.Contains(msg, want) || !strings.Contains(msg, "agent-a1") || !strings.Contains(msg, "2a04:2a01:9::a1") {
				t.Fatalf("%s must name the agent and say what happened, got %s", code, msg)
			}
		})
	}
}

func TestCreate_ALostReplyIsAskedForOnceMore_OnlyWithAKey(t *testing.T) {
	drop := func(n int, _ string, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close() // the reply is lost after the request was sent
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(registeredReply))
	}
	bodies := idemServer(t, drop)
	if err, _, errOut := runCreate(t, "--name", "bot", "--idempotency-key", "job-19"); err != nil {
		t.Fatalf("with a key the lost reply is asked for again: %v %s", err, errOut)
	}
	if len(bodies()) != 2 {
		t.Fatalf("exactly one retry, got %d calls", len(bodies()))
	}
	bodies2 := idemServer(t, drop)
	if err, _, _ := runCreate(t, "--name", "bot", "--register"); err == nil {
		t.Fatal("without a key a lost reply is an error, never a second register")
	}
	if len(bodies2()) != 1 {
		t.Fatalf("no retry without a key, got %d calls", len(bodies2()))
	}
}

func TestCreate_AKeyedRegisterStillInFlight_IsAskedForOnceMore(t *testing.T) {
	saved := registerRetryWait
	registerRetryWait = 10 * time.Millisecond
	defer func() { registerRetryWait = saved }()
	inProgress := `{"ok":false,"status":409,"result":null,"error":{"code":"REGISTER_IN_PROGRESS","message":"an identical` +
		` registration is already in progress","retryable":true}}`
	bodies := idemServer(t, func(n int, _ string, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(inProgress))
			return
		}
		_, _ = w.Write([]byte(registeredReply))
	})
	if err, _, errOut := runCreate(t, "--name", "bot", "--idempotency-key", "job-21"); err != nil {
		t.Fatalf("a keyed register in flight is asked for again: %v %s", err, errOut)
	}
	if len(bodies()) != 2 {
		t.Fatalf("exactly one retry, got %d", len(bodies()))
	}
}

func TestCreate_AnOverlongKeyIsRefusedBeforeAnythingIsSent(t *testing.T) {
	bodies := idemServer(t, func(int, string, http.ResponseWriter, *http.Request) {})
	err, _, _ := runCreate(t, "--name", "bot", "--idempotency-key", strings.Repeat("k", 129))
	if err == nil || len(bodies()) != 0 {
		t.Fatalf("a 129-byte key is a usage error with nothing sent, got %v and %d calls", err, len(bodies()))
	}
}

func TestCreate_AHostileAgentFieldNeverReachesTheTerminal(t *testing.T) {
	idemServer(t, func(_ int, _ string, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(refusal("ATTEMPT_CONSUMED", `a\u001b[2J‮`, `2a04:2a01:9::1`)))
	})
	err, _, _ := runCreate(t, "--name", "bot", "--idempotency-key", "job-22")
	if err == nil || strings.ContainsAny(friendly(err), "\u001b‮") {
		t.Fatalf("the agent field is sanitised, got %q", friendly(err))
	}
}

// TestAgentDetail_AContainmentNoteNamesTheEDRConsole pins where an administrator's
// suspension sends the reader: the EDR console's own host, not the old name that now
// only redirects there.
func TestAgentDetail_AContainmentNoteNamesTheEDRConsole(t *testing.T) {
	got := lifecycleNote("suspended", "operator", "containment", false, false, "agent-c", "")
	if !strings.Contains(got, "https://edr.whisper.security.") {
		t.Fatalf("a containment note names the EDR console, got %s", got)
	}
	if strings.Contains(got, "console.whisper.online") {
		t.Fatalf("a containment note must not print the retired console host, got %s", got)
	}
}
