// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// --- whoami + version - the commands an agent naturally guesses ---------------

// TestWhoami_NoKey_FriendlyAnswer: keyless `whisper whoami` answers helpfully (key not
// set + the login nudge) and exits 0 - an identity question is never an error, and it
// must not touch the network.
func TestWhoami_NoKey_FriendlyAnswer(t *testing.T) {
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	savedG := g
	g = globalFlags{keyFile: filepath.Join(t.TempDir(), "absent-key"), timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("keyless whoami must not error: %v", err)
		}
	})
	if !strings.Contains(stdout, "not set - run: whisper login") {
		t.Fatalf("keyless whoami must nudge to login; stdout=%q", stdout)
	}
}

// TestWhoami_WithKey_ShowsFleet: with a key, whoami reports the key state and the
// fleet size from op:list (best-effort, tenant-confined).
func TestWhoami_WithKey_ShowsFleet(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01:9::1"},
		{name: "probe", addr: "2a04:2a01:9::2"},
	}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "set (flag)") {
		t.Fatalf("whoami must report the key source; stdout=%q", stdout)
	}
	// The CELL, not a bare substring: the old assertion was Contains(stdout, "2"), and the
	// agent-tenants row this change adds also prints a 2, so a digit match no longer
	// discriminates between counting the fleet and printing something else entirely. Matched
	// as a row rather than a fixed string because the column width follows the widest label.
	if !regexp.MustCompile(`(?m)^agents\s+2\s*$`).MatchString(stdout) {
		t.Fatalf("whoami must count the caller's agents in the agents cell; stdout=%q", stdout)
	}
	if !containsOp(opsSeen(seen), "list") {
		t.Fatalf("whoami must ask op:list for the fleet, ops=%v", opsSeen(seen))
	}
	// The handle under the label "tenant" is the CALLER'S, which only the plane can say.
	// The stub's agents carry no fqdn and no tenant field, so the old derivation would have
	// produced an empty cell here; a test that only asserted "not empty" would have passed on
	// either behaviour.
	if !strings.Contains(stdout, "towner00000000000000000000000000") {
		t.Fatalf("whoami must print the CALLER'S own tenant handle; stdout=%q", stdout)
	}
	// And it must say that the agents log somewhere else, which is the fact that made the
	// logging plane look like it was mis-attributing a key.
	if !strings.Contains(stdout, "agent tenants") {
		t.Fatalf("whoami must report the agents' own log tenants; stdout=%q", stdout)
	}
	// The key VALUE must never be printed.
	if strings.Contains(stdout, "whisper_live_test") {
		t.Fatalf("whoami must NEVER print the key value; stdout=%q", stdout)
	}
}

// TestWhoami_TenantIsNeverAnAgents is the regression for the borrowed handle, and
// it is the discriminating one: the stub answers op:list kind:'agents' with a roster whose rows DO carry a tenant
// field and an fqdn, both spelling a handle that is not the caller's. The old code took
// the first of those; this asserts the printed handle is the one the plane marked self
// and that the agent's handle appears nowhere under the bare label.
func TestWhoami_TenantIsNeverAnAgents(t *testing.T) {
	const own = "towner00000000000000000000000000"
	const agentHandle = "tagent000000000000000000000000000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch body := string(raw); {
		case strings.Contains(body, "'activityTenants'"):
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["activityTenants",{"tenant":"` + own + `","agents":1,"self":true,` +
				`"agent_tenants":3}]]}}`))
		case strings.Contains(body, "mode:'count'"):
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["count",{"count":3}]]}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["agent",{"agent":"a1","tenant":"` + agentHandle + `",` +
				`"fqdn":"a1.` + agentHandle + `.agents.whisper.online."}]]}}`))
		}
	}))
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, jsonOut: true}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami errored: %v", err)
		}
	})
	var got whoamiView
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("whoami --json did not emit an object: %v (%q)", err, stdout)
	}
	if got.Tenant != own {
		t.Fatalf("tenant = %q, want the CALLER'S handle %q", got.Tenant, own)
	}
	if got.Tenant == agentHandle || strings.Contains(stdout, agentHandle) {
		t.Fatalf("an AGENT'S handle must never be reported as the caller's tenant; stdout=%q", stdout)
	}
	if got.AgentTenants == nil || *got.AgentTenants != 3 {
		t.Fatalf("agent_tenants = %v, want 3", got.AgentTenants)
	}
	if got.Agents != 3 {
		t.Fatalf("agents = %d, want the count-mode total 3", got.Agents)
	}
}

// TestWhoami_AgentTenantsDistinguishesNoneFromUnknown: 0 and null are different answers on a
// machine surface, so the field is a pointer. A plane that says "nothing logs elsewhere" and
// a plane that did not answer must not look the same to a script.
func TestWhoami_AgentTenantsDistinguishesNoneFromUnknown(t *testing.T) {
	zero := whoamiView{AgentTenants: new(int)}
	b, err := json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"agent_tenants":0`) {
		t.Fatalf("a measured zero must be emitted as 0, not omitted: %s", b)
	}
	b, err = json.Marshal(whoamiView{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"agent_tenants":null`) {
		t.Fatalf("an unknown count must be emitted as null, not 0: %s", b)
	}
}

// TestWhoami_UnconfirmedTenantIsNotSubstituted: when the plane will not say what the
// caller's handle is, the cell is "-" and the fleet size still answers. The whole point is
// that a plausible substitute costs more than a dash: the roster here is perfectly
// readable and carries a handle, and it must still not be borrowed.
func TestWhoami_UnconfirmedTenantIsNotSubstituted(t *testing.T) {
	const agentHandle = "tagent000000000000000000000000000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch body := string(raw); {
		case strings.Contains(body, "'activityTenants'"):
			w.WriteHeader(500) // the plane declines to say
		case strings.Contains(body, "mode:'count'"):
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["count",{"count":7}]]}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["agent",{"agent":"a1","tenant":"` + agentHandle + `"}]]}}`))
		}
	}))
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, jsonOut: true}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami must not fail when one cell is unknown: %v", err)
		}
	})
	var got whoamiView
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("whoami --json did not emit an object: %v (%q)", err, stdout)
	}
	if got.Tenant != "" {
		t.Fatalf("tenant = %q, want empty: nothing confirmed it", got.Tenant)
	}
	if got.Agents != 7 {
		t.Fatalf("agents = %d, want 7: the half that answered still answers", got.Agents)
	}
	if got.AgentTenants != nil {
		t.Fatalf("agent_tenants = %v, want null: the read that would have said it failed", got.AgentTenants)
	}
}

// TestWhoami_FleetReadFailureKeepsTheTenantThatAnswered is the other direction of the same
// rule, and it is the one that regressed first: the original fix returned ("", 0, 0, err) the
// moment the fleet read failed, throwing away a tenant handle that had come back fine. Two
// independent reads fail independently, or a shed 429 on one blanks both cells.
func TestWhoami_FleetReadFailureKeepsTheTenantThatAnswered(t *testing.T) {
	const own = "towner00000000000000000000000000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(raw), "'activityTenants'") {
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
				`"rows":[["activityTenants",{"tenant":"` + own + `","agents":1,"self":true,` +
				`"agent_tenants":0}]]}}`))
			return
		}
		w.WriteHeader(503) // the fleet count is shed
	}))
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, jsonOut: true}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami must not fail when one read is shed: %v", err)
		}
	})
	var got whoamiView
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("whoami --json did not emit an object: %v (%q)", err, stdout)
	}
	if got.Tenant != own {
		t.Fatalf("tenant = %q, want %q: it answered, so it must survive the other read failing", got.Tenant, own)
	}
	if got.AgentTenants == nil || *got.AgentTenants != 0 {
		t.Fatalf("agent_tenants = %v, want a measured 0", got.AgentTenants)
	}
}

// whoamiStub answers the two reads whoami makes, each from its own script, so a test can make
// ONE of them misbehave while the other stays healthy.
func whoamiStub(t *testing.T, selfRows string, selfStatus int, countBody string, countStatus int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(raw), "'activityTenants'") {
			w.WriteHeader(selfStatus)
			_, _ = w.Write([]byte(selfRows))
			return
		}
		w.WriteHeader(countStatus)
		_, _ = w.Write([]byte(countBody))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// whoamiTable runs whoami in its HUMAN form, which is where the per-cell degrade and the
// stderr note live: agentsKnown is unexported on purpose, so it never survives a --json
// round-trip and a test that asserted it there would be asserting the zero value.
func whoamiTable(t *testing.T, controlURL string) (stdout, stderr string) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: controlURL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()
	return captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami must never fail an identity question: %v", err)
		}
	})
}

func whoamiJSON(t *testing.T, controlURL string) (whoamiView, string) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: controlURL, key: "whisper_live_test", timeout: 5 * time.Second, jsonOut: true}
	defer func() { g = savedG }()
	stdout, stderr := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami must never fail an identity question: %v", err)
		}
	})
	var got whoamiView
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("whoami --json did not emit an object: %v (%q)", err, stdout)
	}
	return got, stderr
}

const selfRowOK = `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":` +
	`[["activityTenants",{"tenant":"towner00000000000000000000000000","agents":1,"self":true,` +
	`"agent_tenants":2}]]}}`

// TestWhoami_ACountlessReplyIsADashNotAZero: a count mode that answers without a count must
// degrade the cell, not invent a total. That mode's own contract is that a count is the TRUE
// total and a reader must refuse it rather than accept "a fabricated 0 presented as a real
// total";
// printing `agents 0` beside a tenant that answered fine is that fabrication with no dash and
// no note to warn anybody. Three reply shapes reach it, so all three are pinned.
func TestWhoami_ACountlessReplyIsADashNotAZero(t *testing.T) {
	shapes := map[string]string{
		"a note row instead of a count": `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":` +
			`[["note",{"note":"count unavailable"}]]}}`,
		"ok with no result": `{"ok":true,"status":200}`,
		"ok with no rows":   `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[]}}`,
	}
	dash := regexp.MustCompile(`(?m)^agents\s+-\s*$`)
	for name, body := range shapes {
		t.Run(name, func(t *testing.T) {
			stdout, stderr := whoamiTable(t, whoamiStub(t, selfRowOK, 200, body, 200))
			if !strings.Contains(stdout, "towner00000000000000000000000000") {
				t.Fatalf("the half that answered must still answer; stdout=%q", stdout)
			}
			if !dash.MatchString(stdout) {
				t.Fatalf("a reply with no count must leave the cell a dash, never 0; stdout=%q", stdout)
			}
			if stderr == "" {
				t.Fatal("an unknown cell must say so on stderr rather than go quietly blank")
			}
		})
	}

	// The discriminating control: a reply that DOES carry a count prints it, and says nothing.
	stdout, stderr := whoamiTable(t, whoamiStub(t, selfRowOK, 200,
		`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["count",{"count":9}]]}}`, 200))
	if !regexp.MustCompile(`(?m)^agents\s+9\s*$`).MatchString(stdout) {
		t.Fatalf("a real count must be used; stdout=%q", stdout)
	}
	if stderr != "" {
		t.Fatalf("a healthy pair of reads must print no note; stderr=%q", stderr)
	}
}

// TestWhoami_ANonCountAgentTenantsIsNotAnAnswer: agent_tenants is a cardinality, so a negative
// value is not a smaller count, it is a plane saying something impossible. It used to ride into
// --json verbatim while the human table, gated on > 0, printed no row at all: two surfaces, two
// answers, from one reply.
func TestWhoami_ANonCountAgentTenantsIsNotAnAnswer(t *testing.T) {
	for _, bad := range []string{"-5", "\"nope\"", "null"} {
		row := `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":` +
			`[["activityTenants",{"tenant":"towner00000000000000000000000000","self":true,` +
			`"agent_tenants":` + bad + `}]]}}`
		got, _ := whoamiJSON(t, whoamiStub(t, row, 200,
			`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["count",{"count":3}]]}}`, 200))
		if got.AgentTenants != nil {
			t.Fatalf("agent_tenants %s must read as unknown, got %d", bad, *got.AgentTenants)
		}
		if got.Tenant == "" {
			t.Fatalf("a bad count must not cost the handle the same row carried (%s)", bad)
		}
	}
}

// TestWhoami_TwoSelfRowsDecideNothing: the handle under the label "tenant" must not be settled
// by which row arrived first. Only a hostile or buggy plane sends two rows marked self, and the
// honest answer to an ambiguous reply is "-", not whichever one the loop happened to see.
func TestWhoami_TwoSelfRowsDecideNothing(t *testing.T) {
	two := `{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` +
		`["activityTenants",{"tenant":"tstranger0000000000000000000000","self":true}],` +
		`["activityTenants",{"tenant":"towner00000000000000000000000000","self":true}]]}}`
	got, _ := whoamiJSON(t, whoamiStub(t, two, 200,
		`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["count",{"count":3}]]}}`, 200))
	if got.Tenant != "" {
		t.Fatalf("two self rows are not an answer; printed %q", got.Tenant)
	}
	if got.Agents != 3 {
		t.Fatalf("and the fleet size, which was unambiguous, must survive; agents=%d", got.Agents)
	}
}

// TestWhoami_Aliases: the guessed spellings (who / me / self) resolve to whoami, and
// `version` resolves as a real command - never "unknown command".
func TestWhoami_Aliases(t *testing.T) {
	root := NewRootCommand()
	for _, alias := range []string{"whoami", "who", "me", "self"} {
		cmd, _, err := root.Find([]string{alias})
		if err != nil || cmd == nil || cmd.Name() != "whoami" {
			t.Fatalf("%q must resolve to the whoami command (got %v, err %v)", alias, cmd, err)
		}
	}
	cmd, _, err := root.Find([]string{"version"})
	if err != nil || cmd == nil || cmd.Name() != "version" {
		t.Fatalf("`version` must be a real command (got %v, err %v)", cmd, err)
	}
}

// TestVersion_PrintsVersion: `whisper version` prints the same answer as --version;
// --quiet prints the bare value (the load-bearing form for scripts).
func TestVersion_PrintsVersion(t *testing.T) {
	savedG := g
	g = globalFlags{}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newVersionCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "whisper version "+Version) {
		t.Fatalf("version output = %q, want it to carry %q", stdout, Version)
	}

	g = globalFlags{quiet: true}
	stdout, _ = captureStd(t, func() {
		cmd := newVersionCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != Version {
		t.Fatalf("quiet version stdout = %q, want ONLY %q", stdout, Version)
	}
}
