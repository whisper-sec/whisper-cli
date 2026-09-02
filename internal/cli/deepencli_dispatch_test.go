// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// deepencli_dispatch_test.go: command dispatch against a stub control plane. Each test
// asserts the WIRE SHAPE the command fires (which op, which args) and the exit
// discipline (usage error vs runtime error vs clean), with no live network.

// deepencli_pipeStdin swaps os.Stdin for a pipe carrying content. A pipe is NOT a char
// device, so isInteractive() is deterministically false - the headless branch - no
// matter what stdin the test runner itself inherited.
func deepencli_pipeStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if content != "" {
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = saved; _ = r.Close() })
}

// --- list -------------------------------------------------------------------------

func TestDeepenCLI_ListCmd_FiresOpListAndRenders(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "web-agent", addr: "2a04:2a01:9::1"}}, &seen)
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second})

	stdout, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newListCmd()); err != nil {
			t.Errorf("list errored: %v", err)
		}
	})
	body, ok := bodyForOp(seen, "list")
	if !ok || !strings.Contains(body, "kind:'agents'") {
		t.Fatalf("list must fire op:list kind:'agents', body=%q", body)
	}
	if !strings.Contains(stdout, "web-agent") || !strings.Contains(stdout, "2a04:2a01:9::1") {
		t.Fatalf("the fleet table must render the agent: %q", stdout)
	}
	if !strings.Contains(stderr, "1 agent(s)") {
		t.Fatalf("count on stderr: %q", stderr)
	}
}

func TestDeepenCLI_ListCmd_KindFlagRidesTheWire(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	if err := deepencli_exec(t, newListCmd(), "--kind", "records"); err != nil {
		t.Fatalf("list --kind records errored: %v", err)
	}
	body, _ := bodyForOp(seen, "list")
	if !strings.Contains(body, "kind:'records'") {
		t.Fatalf("--kind must ride the wire, body=%q", body)
	}
}

func TestDeepenCLI_ListCmd_NoKeyIsCleanError(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{timeout: time.Second})
	err := deepencli_exec(t, newListCmd())
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 401 {
		t.Fatalf("no key must be a 401 problem with guidance, got %v", err)
	}
	if !strings.Contains(pe.Detail, "whisper login") {
		t.Fatalf("the no-key error must point at login, got %q", pe.Detail)
	}
}

// asProblem is a tiny local alias to keep the assertions readable.
func asProblem(err error, target **client.ProblemError) bool {
	pe, ok := err.(*client.ProblemError)
	if ok {
		*target = pe
	}
	return ok
}

// --- agent ------------------------------------------------------------------------

func TestDeepenCLI_AgentCmd_SelectorForms(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"v6 positional selects by address", []string{"2a04:2a01:9::7"}, "address:'2a04:2a01:9::7'"},
		{"id positional selects by agent", []string{"my-agent"}, "agent:'my-agent'"},
		{"--address flag wins", []string{"--address", "2a04:2a01:9::8"}, "address:'2a04:2a01:9::8'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []recordedCall
			srv := recordingServer(t, nil, &seen)
			defer srv.Close()
			deepencli_keyedGlobals(t, srv.URL)
			if err := deepencli_exec(t, newAgentCmd(), tc.args...); err != nil {
				t.Fatalf("agent %v errored: %v", tc.args, err)
			}
			body, ok := deepencli_bodyContaining(seen, "op:'agent'")
			if !ok || !strings.Contains(body, tc.want) {
				t.Fatalf("agent %v must carry %s, body=%q", tc.args, tc.want, body)
			}
		})
	}
}

func TestDeepenCLI_AgentCmd_NoSelectorIsUsageError(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)
	err := deepencli_exec(t, newAgentCmd())
	if err == nil || !isUsageError(err) {
		t.Fatalf("agent with no selector must be a usage error, got %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("no control call may fire on a usage error, ops=%v", opsSeen(seen))
	}
}

// --- kill -------------------------------------------------------------------------

func TestDeepenCLI_KillCmd_HeadlessWithoutYesRefuses(t *testing.T) {
	deepencli_pipeStdin(t, "") // a pipe: deterministically non-interactive
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	err := deepencli_exec(t, newKillCmd(), "agent-x")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("headless kill without --yes must refuse with guidance, got %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("NOTHING may be released without confirmation, ops=%v", opsSeen(seen))
	}
}

func TestDeepenCLI_KillCmd_YesWithAddressFiresIdentityRelease(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newKillCmd(), "--yes", "2a04:2a01:9::9"); err != nil {
			t.Errorf("kill --yes <v6> errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "2a04:2a01:9::9") {
		t.Fatalf("the released target must be confirmed on stderr: %q", stderr)
	}
	body, ok := bodyForOp(seen, "identity")
	if !ok || !strings.Contains(body, "release:true") || !strings.Contains(body, "address:'2a04:2a01:9::9'") {
		t.Fatalf("kill by /128 must fire op:identity release for THAT address, body=%q", body)
	}
}

func TestDeepenCLI_KillCmd_YesWithNameResolvesThenReleases(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "doomed", addr: "2a04:2a01:9::77"}}, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	captureStd(t, func() {
		if err := deepencli_exec(t, newKillCmd(), "--yes", "doomed"); err != nil {
			t.Errorf("kill --yes <name> errored: %v", err)
		}
	})
	// A name is resolved via op:list to its /128 and THAT address is released.
	if !containsOp(opsSeen(seen), "list") {
		t.Fatalf("a name must be resolved via op:list first, ops=%v", opsSeen(seen))
	}
	body, ok := bodyForOp(seen, "identity")
	if !ok || !strings.Contains(body, "address:'2a04:2a01:9::77'") {
		t.Fatalf("the RESOLVED address must be released, body=%q", body)
	}
}

func TestDeepenCLI_KillCmd_UnknownNameIsCleanNotFound(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "other", addr: "2a04:2a01:9::1"}}, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	err := deepencli_exec(t, newKillCmd(), "--yes", "ghost")
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 404 || !strings.Contains(pe.Detail, "ghost") {
		t.Fatalf("an unknown name must be a clean 404 naming it, got %v", err)
	}
	if containsOp(opsSeen(seen), "identity") {
		t.Fatalf("nothing may be released for an unresolved name, ops=%v", opsSeen(seen))
	}
}

func TestDeepenCLI_KillCmd_RevokeFiresOpRevoke(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	captureStd(t, func() {
		if err := deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "bad-agent"); err != nil {
			t.Errorf("kill --revoke errored: %v", err)
		}
	})
	body, ok := deepencli_bodyContaining(seen, "op:'revoke'")
	if !ok || !strings.Contains(body, "agent:'bad-agent'") {
		t.Fatalf("--revoke must fire op:revoke for the agent, body=%q", body)
	}
}

func TestDeepenCLI_Confirm(t *testing.T) {
	deepencli_pipeStdin(t, "agent-x\n")
	if !confirm("agent-x") {
		t.Fatal("typing the exact target must confirm")
	}
	deepencli_pipeStdin(t, "something-else\n")
	if confirm("agent-x") {
		t.Fatal("any other input must NOT confirm a destroy")
	}
	deepencli_pipeStdin(t, "") // EOF
	if confirm("agent-x") {
		t.Fatal("EOF must NOT confirm a destroy")
	}
}

// --- token ------------------------------------------------------------------------

func TestDeepenCLI_TokenCmd_MintAndRevokeWireShape(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	captureStd(t, func() {
		if err := deepencli_exec(t, newTokenCmd(), "ag-1", "--expires", "1719080000000"); err != nil {
			t.Errorf("token mint errored: %v", err)
		}
	})
	body, ok := deepencli_bodyContaining(seen, "op:'token'")
	if !ok || !strings.Contains(body, "agent:'ag-1'") || !strings.Contains(body, "expires:1719080000000") {
		t.Fatalf("token mint wire shape, body=%q", body)
	}
	if strings.Contains(body, "revoke") {
		t.Fatalf("a mint must NOT carry revoke, body=%q", body)
	}

	seen = nil
	captureStd(t, func() {
		if err := deepencli_exec(t, newTokenCmd(), "ag-1", "--revoke"); err != nil {
			t.Errorf("token revoke errored: %v", err)
		}
	})
	body, ok = deepencli_bodyContaining(seen, "op:'token'")
	if !ok || !strings.Contains(body, "revoke:true") {
		t.Fatalf("token --revoke wire shape, body=%q", body)
	}
}

// --- logs -------------------------------------------------------------------------

func TestDeepenCLI_LogsCmd_FlagsRideTheWire(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	captureStd(t, func() {
		err := deepencli_exec(t, newLogsCmd(),
			"--agent", "ag-1", "--kind", "dns", "--from", "-1h", "--to", "now", "--limit", "100")
		if err != nil {
			t.Errorf("logs errored: %v", err)
		}
	})
	body, ok := bodyForOp(seen, "logs")
	if !ok {
		t.Fatalf("logs must fire op:logs, ops=%v", opsSeen(seen))
	}
	for _, want := range []string{"agent:'ag-1'", "kind:'dns'", "from:'-1h'", "to:'now'", "limit:100"} {
		if !strings.Contains(body, want) {
			t.Fatalf("logs body must carry %s, body=%q", want, body)
		}
	}
}

// --- query (raw Cypher) -----------------------------------------------------------

func TestDeepenCLI_QueryCmd_PostsQueryAndParams(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["n"],"rows":[{"n":7}],"statistics":{"rowCount":1}}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second})

	stdout, stderr := captureStd(t, func() {
		// Several shell words are liberally joined into ONE statement.
		if err := deepencli_exec(t, newQueryCmd(), "CALL", "db.schema()", "--param", "n=5", "--param", "who='ag'"); err != nil {
			t.Errorf("query errored: %v", err)
		}
	})
	if len(bodies) != 1 {
		t.Fatalf("exactly one POST must fire, got %d", len(bodies))
	}
	if !strings.Contains(bodies[0], `"query":"CALL db.schema()"`) {
		t.Fatalf("the joined Cypher must ride as query, body=%q", bodies[0])
	}
	if !strings.Contains(bodies[0], `"n":5`) {
		t.Fatalf("a numeric param must keep its JSON type, body=%q", bodies[0])
	}
	if !strings.Contains(bodies[0], `"who":"'ag'"`) {
		t.Fatalf("a non-JSON param value stays a raw string, body=%q", bodies[0])
	}
	if !strings.Contains(stdout, "7") || !strings.Contains(stderr, "1 row(s)") {
		t.Fatalf("the result table + count must render: out=%q err=%q", stdout, stderr)
	}
}

func TestDeepenCLI_QueryCmd_BadParamIsUsageError(t *testing.T) {
	deepencli_keyedGlobals(t, "http://127.0.0.1:1") // must never be reached
	err := deepencli_exec(t, newQueryCmd(), "CALL db.schema()", "--param", "no-equals-here")
	if err == nil || !isUsageError(err) {
		t.Fatalf("a malformed --param must be a usage error before any network, got %v", err)
	}
}

// --- graph list -------------------------------------------------------------------

func TestDeepenCLI_GraphListCmd_JSONAndTable(t *testing.T) {
	deepencli_globals(t, globalFlags{jsonOut: true})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newGraphListCmd()); err != nil {
			t.Errorf("graph list --json errored: %v", err)
		}
	})
	var entries []map[string]any
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("graph list --json must emit a JSON array: %v (%q)", err, stdout)
	}
	if len(entries) == 0 {
		t.Fatal("the embedded catalog must not be empty")
	}
	for _, e := range entries {
		if e["id"] == "" || e["mode"] == "" || e["docs"] == "" {
			t.Fatalf("every entry carries id/mode/docs: %v", e)
		}
	}

	deepencli_globals(t, globalFlags{})
	stdout, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newGraphListCmd()); err != nil {
			t.Errorf("graph list errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "RECIPE") || !strings.Contains(stderr, "recipe(s)") {
		t.Fatalf("human catalog table: out=%q err=%q", stdout, stderr)
	}
}

// --- domain -----------------------------------------------------------------------

func TestDeepenCLI_DomainCmd_BareIsUsageError(t *testing.T) {
	err := deepencli_exec(t, newDomainCmd())
	if err == nil || !isUsageError(err) || !strings.Contains(err.Error(), "verify | submit | status | list") {
		t.Fatalf("bare domain must name its subcommands, got %v", err)
	}
}

func TestDeepenCLI_DomainStatusCmd_WireShape(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)

	if err := deepencli_exec(t, newDomainCmd(), "status", "example.com"); err != nil {
		t.Fatalf("domain status errored: %v", err)
	}
	body, ok := bodyForOp(seen, "domain")
	if !ok || !strings.Contains(body, "op:'status'") || !strings.Contains(body, "domain:'example.com'") {
		t.Fatalf("domain status must fire op:domain{op:'status'}, body=%q", body)
	}
}

// deepencli_verifyServer serves the keyless GET /verify-identity surface with a canned
// verdict + status per target ip.
func deepencli_verifyServer(t *testing.T, status int, verdict string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify-identity" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
			t.Error("the verify surface is keyless - no auth header may be sent")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(verdict))
	}))
}

func TestDeepenCLI_DomainVerifyCmd_VerifiedExitsClean(t *testing.T) {
	srv := deepencli_verifyServer(t, 200,
		`{"is_whisper_agent":true,"fqdn":"api.example.com.","operator":"acme","dane_ok":true,"jws_ok":true}`)
	defer srv.Close()
	deepencli_globals(t, globalFlags{verifyURL: srv.URL, timeout: 5 * time.Second})

	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newDomainVerifyCmd(), "api.example.com"); err != nil {
			t.Errorf("a fully-verified name must exit clean, got %v", err)
		}
	})
	if !strings.Contains(stderr, "verified Whisper agent") {
		t.Fatalf("the verified line must print: %q", stderr)
	}
}

func TestDeepenCLI_DomainVerifyCmd_NotAgentIsNonZeroWithReason(t *testing.T) {
	srv := deepencli_verifyServer(t, 404, `{"is_whisper_agent":false}`)
	defer srv.Close()
	deepencli_globals(t, globalFlags{verifyURL: srv.URL, timeout: 5 * time.Second})

	var err error
	captureStd(t, func() { err = deepencli_exec(t, newDomainVerifyCmd(), "203.0.113.9") })
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 404 {
		t.Fatalf("a non-agent must exit non-zero with the server status, got %v", err)
	}
	if !strings.Contains(pe.Detail, "not a verified Whisper agent") {
		t.Fatalf("the reason must be the honest one-liner, got %q", pe.Detail)
	}
}

func TestDeepenCLI_DomainVerifyCmd_400SurfacesServerDetail(t *testing.T) {
	srv := deepencli_verifyServer(t, 400, `{"detail":"not an address we can parse"}`)
	defer srv.Close()
	deepencli_globals(t, globalFlags{verifyURL: srv.URL, timeout: 5 * time.Second})

	err := deepencli_exec(t, newDomainVerifyCmd(), "!!!")
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 400 {
		t.Fatalf("a 400 must surface as a 400 problem, got %v", err)
	}
	if !strings.Contains(pe.Detail, "not an address we can parse") {
		t.Fatalf("the server's own detail must be surfaced, got %q", pe.Detail)
	}
}

// --- rdap -------------------------------------------------------------------------

func TestDeepenCLI_RDAPCmd_IPObjectVerbatim(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"WSPR-1"}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newRDAPCmd(), "2a04:2a01:9::1", "--history"); err != nil {
			t.Errorf("rdap errored: %v", err)
		}
	})
	if len(paths) != 1 || !strings.HasPrefix(paths[0], "/ip/") || !strings.Contains(paths[0], "history") {
		t.Fatalf("a colon target selects the /ip object with ?history, got %v", paths)
	}
	if !strings.Contains(stdout, `"objectClassName":"ip network"`) {
		t.Fatalf("RDAP JSON must be emitted verbatim on stdout: %q", stdout)
	}
}

func TestDeepenCLI_RDAPCmd_ErrorStatusIsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"errorCode":404}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})

	var err error
	captureStd(t, func() { err = deepencli_exec(t, newRDAPCmd(), "nosuch.example") })
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 404 {
		t.Fatalf("an RDAP >=400 must exit non-zero carrying the status, got %v", err)
	}
}

// --- use / status / config --------------------------------------------------------

func TestDeepenCLI_UseCmd_SavesAddressDirectly(t *testing.T) {
	deepencli_hermeticEnv(t)
	af := filepath.Join(t.TempDir(), "agent")
	deepencli_globals(t, globalFlags{quiet: true})

	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newUseCmd(), "2a04:2a01:9::42", "--agent-file", af); err != nil {
			t.Errorf("use <v6> errored: %v", err)
		}
	})
	if b, err := os.ReadFile(af); err != nil || strings.TrimSpace(string(b)) != "2a04:2a01:9::42" {
		t.Fatalf("the /128 must be persisted verbatim, got %q err=%v", b, err)
	}
	if strings.TrimSpace(stdout) != "2a04:2a01:9::42" {
		t.Fatalf("--quiet prints only the value: %q", stdout)
	}
}

func TestDeepenCLI_UseCmd_ResolvesNameWithKey(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "picked", addr: "2a04:2a01:9::5"}}, &seen)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second})

	captureStd(t, func() {
		if err := deepencli_exec(t, newUseCmd(), "picked", "--agent-file", af); err != nil {
			t.Errorf("use <name> errored: %v", err)
		}
	})
	// Postel: accept the name, STORE the canonical /128 (so a later connect binds right).
	if b, _ := os.ReadFile(af); strings.TrimSpace(string(b)) != "2a04:2a01:9::5" {
		t.Fatalf("a name must be stored as its resolved /128, got %q", b)
	}
}

func TestDeepenCLI_UseCmd_NoArgIsUsageError(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	err := deepencli_exec(t, newUseCmd())
	if err == nil || !isUsageError(err) {
		t.Fatalf("use with no selector is a usage error, got %v", err)
	}
}

func TestDeepenCLI_StatusCmd_JSONNeverLeaksTheKey(t *testing.T) {
	deepencli_hermeticEnv(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(af, []byte("2a04:2a01:9::5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deepencli_globals(t, globalFlags{key: "whisper_live_supersecret", jsonOut: true})

	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", af); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	var st map[string]any
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("status --json must be valid JSON: %v (%q)", err, stdout)
	}
	if st["key_present"] != true || st["selected_agent"] != "2a04:2a01:9::5" {
		t.Fatalf("status fields: %v", st)
	}
	if strings.Contains(stdout, "supersecret") {
		t.Fatal("the key VALUE must never be printed")
	}
}

func TestDeepenCLI_StatusCmd_NoKeyPointsAtLogin(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "whisper login") {
		t.Fatalf("the no-key state must point at login: %q", stdout)
	}
}

func TestDeepenCLI_ConfigCmd_ResolvedViewNeverLeaksTheKey(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{key: "whisper_live_supersecret", jsonOut: true})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newConfigCmd()); err != nil {
			t.Errorf("config errored: %v", err)
		}
	})
	var cfg map[string]any
	if err := json.Unmarshal([]byte(stdout), &cfg); err != nil {
		t.Fatalf("config --json must be valid JSON: %v (%q)", err, stdout)
	}
	if cfg["control_url"] != client.DefaultControlURL {
		t.Fatalf("an unset control URL shows the canonical default: %v", cfg["control_url"])
	}
	if cfg["key_present"] != true || cfg["auth_scheme"] != "X-API-Key" {
		t.Fatalf("key state: %v", cfg)
	}
	if strings.Contains(stdout, "supersecret") {
		t.Fatal("the key VALUE must never be printed")
	}

	// The human table, keyless: present fields, no key, scheme none.
	deepencli_globals(t, globalFlags{})
	stdout, _ = captureStd(t, func() {
		if err := deepencli_exec(t, newConfigCmd()); err != nil {
			t.Errorf("config errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "auth_scheme") || !strings.Contains(stdout, "none") {
		t.Fatalf("keyless config table: %q", stdout)
	}
}

// --- login ------------------------------------------------------------------------

func TestDeepenCLI_LoginCmd_WebPlusManualConflict(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	err := deepencli_exec(t, newLoginCmd(), "--web", "--manual")
	if err == nil || !isUsageError(err) || !strings.Contains(err.Error(), "--web / --manual") {
		t.Fatalf("web+manual must be one clear usage error, got %v", err)
	}
}

func TestDeepenCLI_LoginCmd_HeadlessNoKeyIsGuidedUsageError(t *testing.T) {
	deepencli_pipeStdin(t, "")
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{})
	err := deepencli_exec(t, newLoginCmd())
	if err == nil || !isUsageError(err) {
		t.Fatalf("headless login with no key must be a usage error, got %v", err)
	}
	if !strings.Contains(err.Error(), "whisper login --web") {
		t.Fatalf("the error must offer the browser flow, got %v", err)
	}
}

func TestDeepenCLI_LoginCmd_KeyArgSavesModeSixHundredAndVerifies(t *testing.T) {
	deepencli_hermeticEnv(t)
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	kf := filepath.Join(t.TempDir(), "keydir", "key")
	deepencli_globals(t, globalFlags{controlURL: srv.URL, keyFile: kf, timeout: 5 * time.Second})

	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newLoginCmd(), " whisper_live_pasted "); err != nil {
			t.Errorf("login <key> errored: %v", err)
		}
	})
	b, err := os.ReadFile(kf)
	if err != nil || !strings.Contains(string(b), "whisper_live_pasted") {
		t.Fatalf("the key must be saved (trimmed), got %q err=%v", b, err)
	}
	fi, _ := os.Stat(kf)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the key file must be mode 600, got %o", fi.Mode().Perm())
	}
	if !containsOp(opsSeen(seen), "list") {
		t.Fatalf("the saved key must be verified with a quick op:list, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(stderr, "key saved and verified") {
		t.Fatalf("the verified line must print: %q", stderr)
	}
}

func TestDeepenCLI_LoginCmd_VerifyFailureIsFailSoft(t *testing.T) {
	deepencli_hermeticEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"ok":false,"status":500}`))
	}))
	defer srv.Close()
	kf := filepath.Join(t.TempDir(), "key")
	deepencli_globals(t, globalFlags{controlURL: srv.URL, keyFile: kf, timeout: 2 * time.Second})

	var err error
	_, stderr := captureStd(t, func() { err = deepencli_exec(t, newLoginCmd(), "whisper_live_x") })
	if err != nil {
		t.Fatalf("a failed verify must NOT fail the login (the key IS saved), got %v", err)
	}
	if _, serr := os.Stat(kf); serr != nil {
		t.Fatal("the key must still be saved on a verify failure")
	}
	if !strings.Contains(stderr, "didn't accept it yet") {
		t.Fatalf("the honest fail-soft note must print: %q", stderr)
	}
}

// --- dash / explore (terminal gates) ----------------------------------------------

func TestDeepenCLI_DashAndExploreNeedATerminal(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	captureStd(t, func() { // captured stdout is a pipe: stdoutIsTTY() is false
		if err := deepencli_exec(t, newDashCmd()); err == nil || !isUsageError(err) {
			t.Errorf("dash without a terminal must be a usage error, got %v", err)
		}
		if err := deepencli_exec(t, newExploreCmd()); err == nil || !isUsageError(err) {
			t.Errorf("explore without a terminal must be a usage error, got %v", err)
		}
	})
}

// --- bestEffortTenant -------------------------------------------------------------

func TestDeepenCLI_BestEffortTenant(t *testing.T) {
	if got := bestEffortTenant(nil); got != "" {
		t.Fatalf("nil client tenant = %q", got)
	}
	if got := bestEffortTenant(client.New(client.Config{})); got != "" {
		t.Fatalf("keyless client tenant = %q (must not call anything)", got)
	}
	// An explicit tenant field on a row wins.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
			`"rows":[["agent",{"agent":"a1","tenant":"t-abc123"}]]}}`))
	}))
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_x"}})
	if got := bestEffortTenant(c); got != "t-abc123" {
		t.Fatalf("explicit tenant = %q", got)
	}
	// No tenant field: the handle is derived from the fqdn's second label (a t-handle
	// is at least 9 chars starting with 't' - see model.TenantFromFQDN).
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
			`"rows":[["agent",{"agent":"a1","fqdn":"a1.t-abcdef12.agents.whisper.online."}]]}}`))
	}))
	defer srv2.Close()
	c2 := client.New(client.Config{ControlURL: srv2.URL, Cred: client.Credential{Value: "whisper_live_x"}})
	if got := bestEffortTenant(c2); got != "t-abcdef12" {
		t.Fatalf("fqdn-derived tenant = %q", got)
	}
	// A control-plane failure is cosmetic: empty handle, never an error.
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv3.Close()
	c3 := client.New(client.Config{ControlURL: srv3.URL, Cred: client.Credential{Value: "whisper_live_x"}})
	if got := bestEffortTenant(c3); got != "" {
		t.Fatalf("failure must fail open to empty, got %q", got)
	}
}

// --- guidedClient -----------------------------------------------------------------

func TestDeepenCLI_GuidedClient_NoKeyHeadlessIsTheOneHardExit(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{})
	gio := guidedIO{out: io.Discard, err: io.Discard}
	_, err := guidedClient(guidedOptions{tty: false}, gio)
	var pe *client.ProblemError
	if err == nil || !asProblem(err, &pe) || pe.Status != 401 {
		t.Fatalf("no key + no TTY must be a 401 problem, got %v", err)
	}
	if !strings.Contains(pe.Detail, "whisper login") {
		t.Fatalf("the exit must carry guidance, got %q", pe.Detail)
	}
}

func TestDeepenCLI_GuidedClient_KeyPresentSkipsLogin(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{key: "whisper_live_x"})
	savedLogin := guidedLogin
	guidedLogin = func() error { t.Fatal("login must not run when a key resolves"); return nil }
	t.Cleanup(func() { guidedLogin = savedLogin })

	c, err := guidedClient(guidedOptions{tty: true}, guidedIO{out: io.Discard, err: io.Discard})
	if err != nil || c == nil || c.Credential().IsZero() {
		t.Fatalf("a present key must yield a keyed client: %v", err)
	}
}

func TestDeepenCLI_GuidedClient_TTYRunsLoginThenReresolves(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{})
	savedLogin := guidedLogin
	loginRan := false
	guidedLogin = func() error {
		loginRan = true
		g.key = "whisper_live_from_login" // what a real login leaves behind for re-resolve
		return nil
	}
	t.Cleanup(func() { guidedLogin = savedLogin })

	var buf strings.Builder
	c, err := guidedClient(guidedOptions{tty: true}, guidedIO{out: io.Discard, err: &buf})
	if err != nil || c == nil {
		t.Fatalf("the TTY path must sign in and return a client: %v", err)
	}
	if !loginRan {
		t.Fatal("the login seam must have run")
	}
	if !strings.Contains(buf.String(), "sign you in") {
		t.Fatalf("the friendly sign-in line must print: %q", buf.String())
	}
}

// --- MCP tools --------------------------------------------------------------------

func TestDeepenCLI_MCPToolGraphQuery(t *testing.T) {
	deepencli_hermeticEnv(t)
	// No query: a helpful tool error, no client work.
	deepencli_globals(t, globalFlags{})
	res := mcpToolGraphQuery(json.RawMessage(`{}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "query is required") {
		t.Fatalf("missing query result: %+v", res)
	}
	// No key: the standard MCP no-key guidance.
	res = mcpToolGraphQuery(json.RawMessage(`{"query":"CALL db.schema()"}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "API key") {
		t.Fatalf("no-key result: %+v", res)
	}
	// Keyed: the verbatim graph reply passes through as the tool text.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["x"],"rows":[{"x":1}]}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_x", timeout: 5 * time.Second})
	res = mcpToolGraphQuery(json.RawMessage(`{"query":"CALL db.schema()"}`))
	if res.IsError || !strings.Contains(res.Content[0].Text, `"columns":["x"]`) {
		t.Fatalf("keyed graph query result: %+v", res)
	}
}

func TestDeepenCLI_MCPToolGraphRecipe_DirectAndMissingInput(t *testing.T) {
	deepencli_hermeticEnv(t)
	entry := catalog.Entry{
		ID:      "deepencli-fixture",
		DocPath: "/docs/deepencli",
		Inputs:  []catalog.Input{{ID: "host", ParamName: "host"}},
		Exec:    catalog.Exec{Mode: catalog.ModeDirect, Cypher: "CALL whisper.identify([$host])"},
	}
	// A missing REQUIRED input is a clear tool error naming the input, before any client work.
	deepencli_globals(t, globalFlags{})
	res := mcpToolGraphRecipe(entry, json.RawMessage(`{}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, `"host"`) {
		t.Fatalf("missing input result: %+v", res)
	}
	// Addressing the input by its catalog ID works too (liberal in), and the direct
	// recipe returns the verbatim reply.
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["v"],"rows":[{"v":"ok"}]}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_x", timeout: 5 * time.Second})
	res = mcpToolGraphRecipe(entry, json.RawMessage(`{"host":"api.example.com"}`))
	if res.IsError || !strings.Contains(res.Content[0].Text, `"v":"ok"`) {
		t.Fatalf("direct recipe result: %+v", res)
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"host":"api.example.com"`) {
		t.Fatalf("the input must ride as a Cypher parameter, bodies=%v", bodies)
	}
}

func TestDeepenCLI_MCPToolRDAP(t *testing.T) {
	deepencli_hermeticEnv(t)
	deepencli_globals(t, globalFlags{})
	res := mcpToolRDAP(json.RawMessage(`{}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "ip is required") {
		t.Fatalf("missing ip result: %+v", res)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"ip network"}`))
	}))
	defer srv.Close()
	deepencli_globals(t, globalFlags{rdapURL: srv.URL, timeout: 5 * time.Second})
	res = mcpToolRDAP(json.RawMessage(`{"ip":"2a04:2a01:9::1"}`))
	if res.IsError || !strings.Contains(res.Content[0].Text, "ip network") {
		t.Fatalf("rdap tool result: %+v", res)
	}
}
