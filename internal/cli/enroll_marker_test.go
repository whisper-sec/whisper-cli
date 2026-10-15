// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// enroll_marker_test.go pins `whisper enroll --force`, the command every identity-gone refusal
// names, to rebinding the device's OWN identity when the account still has it. The shape: a
// marker whose agent is still in the account under a label that is not this host's name, and a
// saved agent file that names an agent the account no longer has. Looked up by host name alone,
// the bare --force finds nothing under that name and registers a second identity.

const markedAddr = "2a04:2a01:9::a1a1"

// seedMarkedDevice writes the incident's shape: a marker whose agent is still in the account,
// and a saved agent file that names an agent the account no longer has.
func seedMarkedDevice(t *testing.T) {
	t.Helper()
	testenv.HermeticHome(t)
	if err := client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr(markedAddr),
		"agent-0000000000000a1a1.agents.whisper.online", "agent-0000000000000a1a1"); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveAgent("", "agent-0dead0dead0dead0"); err != nil {
		t.Fatal(err)
	}
}

// markedAccount holds the marker's agent under a label that is not this host's name.
func markedAccount() []agentChoice {
	return []agentChoice{
		{name: "This browser (Whisper Guard)", addr: "2a04:2a01:9::f55a"},
		{name: "studio-mac", addr: markedAddr},
	}
}

// withHostname makes os.Hostname() answer h for the length of the test.
func withHostname(t *testing.T, h string) {
	t.Helper()
	saved := osHostname
	osHostname = func() (string, error) { return h, nil }
	t.Cleanup(func() { osHostname = saved })
}

func enrollRecording(t *testing.T, agents []agentChoice) *[]recordedCall {
	t.Helper()
	var seen []recordedCall
	srv := recordingServer(t, agents, &seen)
	t.Cleanup(srv.Close)
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = savedG })
	return &seen
}

func registered(seen []recordedCall) bool {
	for _, op := range opsSeen(seen) {
		if op == "register" || op == "identity" {
			return true
		}
	}
	return false
}

// The account holds the marker's agent under a label that differs from the host name, and
// the saved agent file is stale: enroll --force rebinds the marker's own agent and registers
// nothing.
func TestEnrollForceRebindsTheMarkersOwnAgentUnderAnotherLabel(t *testing.T) {
	seedMarkedDevice(t)
	withHostname(t, "Mac.localdomain")
	seen := enrollRecording(t, markedAccount())

	res, err := runEnroll("", true)
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if registered(*seen) {
		t.Fatalf("enroll --force minted a new identity although the marker's own agent is in the account; ops %v", opsSeen(*seen))
	}
	if res.addr != markedAddr || !res.reused || !res.fromMarker {
		t.Fatalf("want the marker's own /128 %s reused from the marker, got %+v", markedAddr, res)
	}
	if id, ok := client.ReadBoundFile(""); !ok || id.Addr.String() != markedAddr || id.Agent != "agent-0000000000000a1a1" {
		t.Fatalf("the marker must still name the same identity, got %+v ok=%v", id, ok)
	}
	if got := client.ReadAgentFile(""); got != "agent-0000000000000a1a1" {
		t.Fatalf("the stale saved agent must now name the device's own identity, got %q", got)
	}
}

// The command line says what happened: the device's own identity, not "the agent already
// registered under this name", which is not why it was chosen.
func TestEnrollForceCommandSaysItKeptTheDevicesOwnIdentity(t *testing.T) {
	seedMarkedDevice(t)
	withHostname(t, "Mac.localdomain")
	enrollRecording(t, markedAccount())
	g.quiet = false

	cmd := newEnrollCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--force"})
	var err error
	_, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if !strings.Contains(stderr, markedAddr) || !strings.Contains(stderr, "this device's own identity") ||
		!strings.Contains(stderr, "agent-0dead0dead0dead0 is no longer in the account") {
		t.Fatalf("the report must say the device's own identity was kept, stderr=%q", stderr)
	}
}

// The re-mint path is unchanged: a marker whose agent the account provably no longer has falls
// through to the host-name rung, and with no agent under that name, registers one.
func TestEnrollForceStillRemintsWhenTheMarkersAgentIsGone(t *testing.T) {
	seedDeadIdentity(t, "ag_dead")
	withHostname(t, "this-mac")
	seen := enrollRecording(t, staleAgentAccount())
	res, err := runEnroll("", true)
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if res.addr != "2a04:2a01:9::beef" || res.fromMarker {
		t.Fatalf("a gone identity must be replaced by a new one, got %+v", res)
	}
	if body, ok := bodyForOp(*seen, "register"); !ok || !strings.Contains(body, "this-mac") {
		t.Fatalf("the new agent must be registered under the host name, register body %q (ok=%v)", body, ok)
	}
}

// A listing that did not answer proves nothing about the marker's identity. Minting then is
// exactly the silent second identity this guards against, so the bare --force refuses, changes
// nothing, and names the commands to run instead.
func TestEnrollForceRefusesWhenTheListingDoesNotAnswer(t *testing.T) {
	seedMarkedDevice(t)
	withHostname(t, "Mac.localdomain")
	var ops []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 4096)
		n, _ := r.Body.Read(raw)
		op := sniffOp(string(raw[:n]))
		ops = append(ops, op)
		if op == "list" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","address"],"rows":[["ag_new","2a04:2a01:9::1"]]}}`))
	}))
	t.Cleanup(srv.Close)
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = savedG })

	_, err := runEnroll("", true)
	if err == nil {
		t.Fatalf("enroll --force with an unreadable listing must refuse, ops %v", ops)
	}
	for _, op := range ops {
		if op == "register" || op == "identity" {
			t.Fatalf("enroll --force minted (%s) while the listing could not say whether the identity exists", op)
		}
	}
	for _, want := range []string{"agent-0000000000000a1a1", markedAddr, "Nothing was changed",
		"whisper enroll --force --name {name}"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name %q, got: %v", want, err)
		}
	}
	if id, ok := client.ReadBoundFile(""); !ok || id.Addr.String() != markedAddr {
		t.Fatalf("a refusal must leave the marker alone, got %+v ok=%v", id, ok)
	}
}

// An explicit --name is a person's choice and is honoured as before.
func TestEnrollForceWithANameBindsUnderThatName(t *testing.T) {
	seedMarkedDevice(t)
	withHostname(t, "Mac.localdomain")
	seen := enrollRecording(t, markedAccount())
	res, err := runEnroll("studio-mac", true)
	if err != nil {
		t.Fatalf("enroll --force --name studio-mac: %v", err)
	}
	if registered(*seen) || res.addr != markedAddr || res.fromMarker {
		t.Fatalf("--name studio-mac must reuse the agent by its name, got %+v ops %v", res, opsSeen(*seen))
	}
}

// The default name drops the suffixes a home network or macOS appends, case-insensitively.
func TestEnrollHostNameTrimsLocalNetworkSuffixes(t *testing.T) {
	for in, want := range map[string]string{
		"macbook.local":     "macbook",
		"Mac.localdomain":   "Mac",
		"Mac.LocalDomain.":  "Mac",
		"box.lan":           "box",
		"box.lan.":          "box",
		"db-01.example.com": "db-01.example.com",
		"plain":             "plain",
		" spaced.local ":    "spaced",
		"localdomain":       "localdomain",
	} {
		withHostname(t, in)
		if got := enrollHostName(); got != want {
			t.Errorf("enrollHostName() for %q = %q, want %q", in, got, want)
		}
	}
}

// Trimming a suffix must not orphan a host enrolled BEFORE the trim under its full name: the
// reuse rung also looks for the untrimmed name, so box.lan rebinds its box.lan agent.
func TestEnrollReusesAnAgentRegisteredUnderTheUntrimmedHostName(t *testing.T) {
	testenv.HermeticHome(t)
	withHostname(t, "box.lan")
	seen := enrollRecording(t, []agentChoice{{name: "box.lan", addr: "2a04:2a01:9::b0c5"}})
	res, err := runEnroll("", false)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if registered(*seen) || res.addr != "2a04:2a01:9::b0c5" || !res.reused {
		t.Fatalf("an agent under the untrimmed host name must be reused, got %+v ops %v", res, opsSeen(*seen))
	}
}
