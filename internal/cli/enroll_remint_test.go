// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// enroll_remint_test.go pins `whisper enroll --force` as the re-mint a device whose identity was
// removed actually needs. Before this, it re-bound the marker and left the saved agent naming the
// dead identity, so the next `whisper connect` went on refusing to start, naming an agent that no
// longer existed, after the person had run the very command the refusal told them to.

// seedDeadIdentity writes the incident's shape into a hermetic home: a marker and a saved agent
// that both name an identity the account no longer has.
func seedDeadIdentity(t *testing.T, saved string) {
	t.Helper()
	testenv.HermeticHome(t)
	dead := netip.MustParseAddr("2a04:2a01:9::dead")
	if err := client.WriteBoundFile(client.DefaultBoundFile(), "register", dead, "old.agents.whisper.online", "ag_dead"); err != nil {
		t.Fatal(err)
	}
	if err := client.SaveAgent("", saved); err != nil {
		t.Fatal(err)
	}
}

// staleAgentAccount is an account that still has agents, none of them this device's.
// "guard" is the browser identity the plane's most-recent default handed a Mac whose own
// agent had been removed.
func staleAgentAccount() []agentChoice {
	return []agentChoice{
		{name: "This browser (Whisper Guard)", addr: "2a04:2a01:9::f55a"},
		{name: "scout", addr: "2a04:2a01:9::abcd"},
	}
}

func enrollAgainst(t *testing.T, agents []agentChoice) {
	t.Helper()
	srv := recordingServer(t, agents, nil)
	t.Cleanup(srv.Close)
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = savedG })
}

func TestEnrollForceReplacesTheSavedAgentItPinnedLastTime(t *testing.T) {
	seedDeadIdentity(t, "ag_dead")
	enrollAgainst(t, staleAgentAccount())
	res, err := runEnroll("this-mac", true)
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if got := client.ReadAgentFile(""); got != "ag_1" {
		t.Fatalf("the saved agent must now be the new identity ag_1, got %q", got)
	}
	if res.replacedAgent != "ag_dead" {
		t.Fatalf("the result must say which saved agent it replaced, got %q", res.replacedAgent)
	}
	if id, ok := client.ReadBoundFile(""); !ok || id.Addr.String() != "2a04:2a01:9::beef" {
		t.Fatalf("the marker must name the new /128, got %v ok=%v", id.Addr, ok)
	}
}

func TestEnrollForceReplacesASavedAgentTheAccountNoLongerHas(t *testing.T) {
	seedDeadIdentity(t, "2a04:2a01:9::1d") // not the old binding, and not in the account
	enrollAgainst(t, staleAgentAccount())
	if _, err := runEnroll("this-mac", true); err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if got := client.ReadAgentFile(""); got != "ag_1" {
		t.Fatalf("a saved agent the account no longer has must be replaced, got %q", got)
	}
}

// A person picked scout, and scout is still in the account: it is theirs, and it stays.
func TestEnrollForceKeepsAPickedAgentThatStillExists(t *testing.T) {
	seedDeadIdentity(t, "scout")
	enrollAgainst(t, staleAgentAccount())
	res, err := runEnroll("this-mac", true)
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if got := client.ReadAgentFile(""); got != "scout" || res.replacedAgent != "" {
		t.Fatalf("a picked, live agent must be left alone, got %q (replaced %q)", got, res.replacedAgent)
	}
}

// Without --force nothing changes, as before: an already-bound host makes no call at all.
func TestEnrollWithoutForceLeavesTheSavedAgentAlone(t *testing.T) {
	seedDeadIdentity(t, "ag_dead")
	if _, err := runEnroll("this-mac", false); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got := client.ReadAgentFile(""); got != "ag_dead" {
		t.Fatalf("plain enroll on a bound host must change nothing, got %q", got)
	}
}

// The command line, end to end: the re-bind is reported, the replaced agent is named, and a
// refusal that was about the identity is cleared because it is no longer true.
func TestEnrollForceCommandReportsTheNewBindingAndClearsTheRefusal(t *testing.T) {
	seedDeadIdentity(t, "ag_dead")
	refusalAt(t)
	writeConnectRefusal(connectRefusal{CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Kind: refusalIdentityGone, Reason: "gone", Fix: fixIdentityGone})
	enrollAgainst(t, staleAgentAccount())
	g.quiet = false

	cmd := newEnrollCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--force", "--name", "this-mac"})
	var err error
	_, stderr := captureStd(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	if !strings.Contains(stderr, "whisper connect now binds ag_1") || !strings.Contains(stderr, "ag_dead") {
		t.Fatalf("the command must say connect now binds the new identity, stderr=%q", stderr)
	}
	if _, ok := readConnectRefusal(); ok {
		t.Fatal("an identity-gone refusal must be cleared once the identity is replaced")
	}
}
