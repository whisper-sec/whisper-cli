// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// guidedTestServer stubs the control plane: it replies to op:list with the given agent
// rows and records every op it saw (so a test can assert e.g. that op:identity ran for a
// create). Each row is {"label":..,"address":..}. The op is sniffed from the query body.
func guidedTestServer(t *testing.T, agents []agentChoice, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		op := sniffOp(string(raw))
		if seen != nil {
			*seen = append(*seen, op)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch op {
		case "identity":
			// A create echoes back the new agent's label+address.
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["label","address"],"rows":[["created-name","2a04:2a01:9::abcd"]]}}`))
		default: // list
			_, _ = w.Write([]byte(listJSON(agents)))
		}
	}))
}

// sniffOp pulls the op token out of the Cypher body whisper.agents({op:'...'}).
func sniffOp(body string) string {
	for _, op := range []string{"identity", "register", "connect", "list", "logs", "policy", "agent", "revoke"} {
		if strings.Contains(body, "'"+op+"'") || strings.Contains(body, `"`+op+`"`) {
			return op
		}
	}
	return "list"
}

func listJSON(agents []agentChoice) string {
	var rows []string
	for _, a := range agents {
		rows = append(rows, `["agent",{"label":"`+a.name+`","address":"`+a.addr+`"}]`)
	}
	return `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` + strings.Join(rows, ",") + `]}}`
}

// guidedHarness wires the package globals at a stub server + a scripted stdin, returning
// the stdout/stderr buffers and a restore func. It mirrors withGlobals (login_test.go).
//
// It also stubs connectVia (the WB3 shared connect+verify tail) so the BRANCH/selection
// logic is tested with no network egress: the stub emits the legacy-style "selected
// <name>" line (the existing assertions key on it) and, under --quiet, the chosen agent's
// address on stdout — exactly the surface a verified connect yields, minus the live proxy.
// The real connect+verify (local proxy, echo, bearer hygiene) is covered by the egress +
// connect_core tests; here we isolate the front-door routing.
func guidedHarness(t *testing.T, controlURL, agentFile, stdin string) (gio guidedIO, out, errb *bytes.Buffer, restore func()) {
	t.Helper()
	savedG := g
	savedLogin := guidedLogin
	savedConnect := connectVia
	g = globalFlags{controlURL: controlURL, timeout: 5 * time.Second}
	// The guided flow must never invoke the real login in these tests.
	guidedLogin = func() error { t.Fatal("guidedLogin must not run when a key is present"); return nil }
	out = &bytes.Buffer{}
	errb = &bytes.Buffer{}
	connectVia = func(opts guidedOptions, gio guidedIO, choice agentChoice) error {
		if opts.quiet {
			v := choice.addr
			if v == "" {
				v = choice.name
			}
			fmt.Fprintln(gio.out, v)
			return nil
		}
		label := choice.name
		if label == "" {
			label = choice.addr
		}
		fmt.Fprintf(gio.err, "Connected as %s — %s  ✓ verified\n", label, choice.addr)
		// Keep the legacy keyword the older assertions look for ("selected <name>").
		fmt.Fprintf(gio.err, "whisper: selected %s\n", label)
		return nil
	}
	gio = guidedIO{in: bufio.NewReader(strings.NewReader(stdin)), out: out, err: errb}
	return gio, out, errb, func() { g = savedG; guidedLogin = savedLogin; connectVia = savedConnect }
}

// --- 0 / 1 / N branch selection ---------------------------------------------------

func TestGuided_ZeroAgents_HeadlessCreatesNamed(t *testing.T) {
	var seen []string
	srv := guidedTestServer(t, nil, &seen)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	gio, out, errb, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"

	opts := guidedOptions{name: "scout", tty: false, agentFile: af}
	if err := runGuided(opts, gio); err != nil {
		t.Fatalf("0-agent headless create errored: %v", err)
	}
	if !containsOp(seen, "identity") {
		t.Fatalf("expected an op:identity (create), saw %v", seen)
	}
	if !strings.Contains(errb.String(), "selected") {
		t.Fatalf("expected a selected line, stderr=%q", errb.String())
	}
	_ = out
}

func TestGuided_ZeroAgents_HeadlessNoNameErrors(t *testing.T) {
	srv := guidedTestServer(t, nil, nil)
	defer srv.Close()
	gio, _, _, restore := guidedHarness(t, srv.URL, "", "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{tty: false}, gio)
	if err == nil {
		t.Fatal("0 agents + no name + no TTY must be a usage error")
	}
	if !isUsageError(err) {
		t.Fatalf("expected a usage error, got %v", err)
	}
}

func TestGuided_OneAgent_HeadlessUsesIt(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"

	if err := runGuided(guidedOptions{tty: false, agentFile: af}, gio); err != nil {
		t.Fatalf("1-agent headless errored: %v", err)
	}
	if !strings.Contains(errb.String(), "solo") {
		t.Fatalf("expected the only agent to be selected, stderr=%q", errb.String())
	}
	if got := client.ReadAgentFile(af); got != "2a04:2a01:1::1" {
		t.Fatalf("expected the agent persisted, got %q", got)
	}
}

func TestGuided_OneAgent_TTYConfirmYes(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	// Enter (empty line) = yes.
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "\n")
	defer restore()
	g.key = "whisper_live_test"

	if err := runGuided(guidedOptions{tty: true, agentFile: af}, gio); err != nil {
		t.Fatalf("1-agent TTY confirm errored: %v", err)
	}
	if !strings.Contains(errb.String(), "Use solo?") {
		t.Fatalf("expected the quick-confirm prompt, stderr=%q", errb.String())
	}
	if !strings.Contains(errb.String(), "selected solo") {
		t.Fatalf("expected solo selected after Enter=yes, stderr=%q", errb.String())
	}
}

func TestGuided_ManyAgents_HeadlessNoSelectorErrors(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	gio, _, _, restore := guidedHarness(t, srv.URL, "", "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{tty: false}, gio)
	if err == nil {
		t.Fatal("N agents + no --agent + no TTY must be a usage error")
	}
	if !isUsageError(err) || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("expected a 'pass --agent' usage error, got %v", err)
	}
}

func TestGuided_ManyAgents_SelectorPicks(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"

	if err := runGuided(guidedOptions{tty: false, agent: "runner", agentFile: af}, gio); err != nil {
		t.Fatalf("selector pick errored: %v", err)
	}
	if !strings.Contains(errb.String(), "runner") {
		t.Fatalf("expected runner selected, stderr=%q", errb.String())
	}
	if got := client.ReadAgentFile(af); got != "2a04:2a01::8" {
		t.Fatalf("expected runner's /128 persisted, got %q", got)
	}
}

func TestGuided_ManyAgents_TTYMenuPicksByNumber(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	// Pick "2" = the second agent (runner).
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "2\n")
	defer restore()
	g.key = "whisper_live_test"

	if err := runGuided(guidedOptions{tty: true, agentFile: af}, gio); err != nil {
		t.Fatalf("menu pick errored: %v", err)
	}
	if !strings.Contains(errb.String(), "Which agent?") {
		t.Fatalf("expected the numbered menu, stderr=%q", errb.String())
	}
	if got := client.ReadAgentFile(af); got != "2a04:2a01::8" {
		t.Fatalf("expected runner picked, got %q", got)
	}
}

func TestGuided_SelectorMiss_FriendlyNotFound(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01::7"}}, nil)
	defer srv.Close()
	gio, _, _, restore := guidedHarness(t, srv.URL, "", "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{tty: false, agent: "ghost"}, gio)
	if err == nil {
		t.Fatal("a --agent that isn't in the fleet must error")
	}
	if pe, ok := client.AsProblem(err); !ok || pe.Status != 404 {
		t.Fatalf("expected a 404 not-found, got %v", err)
	}
}

// --- headless force-create --------------------------------------------------------

func TestGuided_ForceCreate_QuietPrintsOnlyValue(t *testing.T) {
	var seen []string
	srv := guidedTestServer(t, nil, &seen)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	gio, out, errb, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{create: true, name: "scout", quiet: true, tty: false, agentFile: af}, gio)
	if err != nil {
		t.Fatalf("force-create --quiet errored: %v", err)
	}
	if !containsOp(seen, "identity") {
		t.Fatalf("expected op:identity, saw %v", seen)
	}
	// --quiet ⇒ stdout is EXACTLY the address, no chrome.
	if got := strings.TrimSpace(out.String()); got != "2a04:2a01:9::abcd" {
		t.Fatalf("quiet stdout = %q, want only the address", got)
	}
	if errb.Len() != 0 {
		t.Fatalf("quiet must suppress all chrome, stderr=%q", errb.String())
	}
}

func TestGuided_ForceCreate_NoNameErrors(t *testing.T) {
	srv := guidedTestServer(t, nil, nil)
	defer srv.Close()
	gio, _, _, restore := guidedHarness(t, srv.URL, "", "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{create: true, tty: false}, gio)
	if err == nil || !isUsageError(err) {
		t.Fatalf("--create with no --name must be a usage error, got %v", err)
	}
}

// --- Fix #1: a non-interactive run (e.g. `whisper </dev/null`) must NEVER silently
// auto-select + persist agent #1. The corrected TTY gate (isInteractive() && stdoutIsTTY())
// produces tty:false for /dev/null; with N agents that must be the documented headless usage
// error AND the persisted-agent file must stay EMPTY (no silent #1).
func TestGuided_ManyAgents_NonInteractive_NeverPersistsFirst(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	// A scripted reader that yields EOF immediately, exactly like </dev/null would.
	gio, _, _, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{tty: false, agentFile: af}, gio)
	if err == nil || !isUsageError(err) {
		t.Fatalf("non-interactive N-agent run must be a usage error, got %v", err)
	}
	if got := client.ReadAgentFile(af); got != "" {
		t.Fatalf("a non-interactive run must NEVER persist an agent; got %q (the silent-#1 bug)", got)
	}
}

// --- Fix #2: parseMenuChoice re-prompts (returns -1) on EVERY invalid input — never the
// silent #1. Only a clean number in [0, n] is accepted.
func TestParseMenuChoice_RepromptsOnGarbage(t *testing.T) {
	const n = 3
	reprompt := []string{"", "  ", "9", "4", "xyz", "-1", "1.5", "2 3", "0x1"}
	for _, in := range reprompt {
		if got := parseMenuChoice(in+"\n", n); got != -1 {
			t.Fatalf("parseMenuChoice(%q, %d) = %d, want -1 (re-prompt), never a silent default", in, n, got)
		}
	}
	valid := map[string]int{"0\n": 0, "1\n": 1, "3\n": 3, "  2  \n": 2}
	for in, want := range valid {
		if got := parseMenuChoice(in, n); got != want {
			t.Fatalf("parseMenuChoice(%q, %d) = %d, want %d", in, n, got, want)
		}
	}
}

// --- Fix #2: an out-of-range '9' on a TTY menu re-prompts (it does NOT silently connect to
// agent #1); a subsequent valid '2' then picks the SECOND agent.
func TestGuided_ManyAgents_TTYMenuRepromptsThenPicks(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	// First an out-of-range '9' (re-prompt), then 'xyz' (re-prompt), then '2' = runner.
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "9\nxyz\n2\n")
	defer restore()
	g.key = "whisper_live_test"

	if err := runGuided(guidedOptions{tty: true, agentFile: af}, gio); err != nil {
		t.Fatalf("re-prompt-then-pick errored: %v", err)
	}
	if !strings.Contains(errb.String(), "pick a number between 0 and 2") {
		t.Fatalf("expected a re-prompt message after garbage, stderr=%q", errb.String())
	}
	if got := client.ReadAgentFile(af); got != "2a04:2a01::8" {
		t.Fatalf("expected runner (the eventually-valid pick), got %q — NOT a silent #1", got)
	}
}

// --- Fix #2: garbage with NO valid follow-up (EOF on the scripted reader) takes the headless
// error path, NOT a silent agent #1.
func TestGuided_ManyAgents_TTYMenuGarbageThenEOF_ErrorsNoSilentFirst(t *testing.T) {
	srv := guidedTestServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01::7"}, {name: "runner", addr: "2a04:2a01::8"},
	}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	// '9' then EOF (no trailing newline / closed stdin).
	gio, _, _, restore := guidedHarness(t, srv.URL, af, "9")
	defer restore()
	g.key = "whisper_live_test"

	err := runGuided(guidedOptions{tty: true, agentFile: af}, gio)
	if err == nil || !isUsageError(err) {
		t.Fatalf("garbage-then-EOF on the menu must be a usage error, got %v", err)
	}
	if got := client.ReadAgentFile(af); got != "" {
		t.Fatalf("garbage-then-EOF must NEVER persist agent #1; got %q", got)
	}
}

// --- helpers ----------------------------------------------------------------------

func containsOp(seen []string, op string) bool {
	for _, s := range seen {
		if s == op {
			return true
		}
	}
	return false
}
