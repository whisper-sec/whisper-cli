// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The control plane spells one agent id two ways. op:register prints agent-<hex>, an
// owner's listing carries agent-<hex>, and an agent key's own listing carries the bare <hex>. So
// `whisper ip --agent agent-<hex>` with the agent's own key was refused as "that agent isn't in
// your account" while its bare id, its label and its /128 all worked, and an owner key refused
// the bare id. The id register printed must be accepted back, in either spelling, against a
// listing in either spelling.

// What an agent key's own listing looks like on the wire: the bare id.
var agentKeyRow = agentChoice{name: "example-agent", addr: "2a04:2a01:9:1:aaaa:bbbb:cccc:dddd", id: "aaaabbbbccccdddd"}

// What an owner's listing looks like: the prefixed id.
var ownerRow = agentChoice{name: "example-agent", addr: "2a04:2a01:9:1:aaaa:bbbb:cccc:dddd", id: "agent-aaaabbbbccccdddd"}

func TestAgentIDMatchesInBothSpellingsAgainstBothListings(t *testing.T) {
	for _, row := range []agentChoice{agentKeyRow, ownerRow} {
		for _, sel := range []string{
			"agent-aaaabbbbccccdddd", // what op:register printed: the case that was refused with an agent key
			"aaaabbbbccccdddd",       // the bare id: the case that was refused with an owner key
			"AGENT-AAAABBBBCCCCDDDD", // either one in another casing
			"AAAABBBBCCCCDDDD",
			"  agent-aaaabbbbccccdddd ",
		} {
			if !choiceMatchesSelector(row, sel) {
				t.Errorf("listing id %q: selector %q does not match", row.id, sel)
			}
			got, ok, err := selectAgent([]agentChoice{row}, sel)
			if err != nil || !ok || got.addr != row.addr {
				t.Errorf("listing id %q: selectAgent(%q) = %+v ok=%v err=%v, want the agent", row.id, sel, got, ok, err)
			}
		}
	}
}

// The spelling rule is a prefix, not a substring: nothing else may start matching.
func TestAgentIDSpellingMatchesNothingElse(t *testing.T) {
	for _, row := range []agentChoice{agentKeyRow, ownerRow} {
		for _, sel := range []string{
			"agent-",                       // the prefix alone
			"agent-agent-aaaabbbbccccdddd", // the prefix twice is a different string
			"agent-aaaabbbbccccddde",       // a different id
			"aaaabbbbccccddd",              // a truncated id
			"xagent-aaaabbbbccccdddd",      // not a prefix
			"",
		} {
			if choiceMatchesSelector(row, sel) {
				t.Errorf("listing id %q: selector %q matched and must not", row.id, sel)
			}
			if _, ok, _ := selectAgent([]agentChoice{row}, sel); ok {
				t.Errorf("listing id %q: selectAgent(%q) found an agent and must not", row.id, sel)
			}
		}
	}
	if sameAgentID("", "") || sameAgentID("agent-", "") {
		t.Error("an empty id names no agent")
	}
}

// One agent listed under both spellings is one agent, not an ambiguous pair.
func TestOneAgentUnderBothSpellingsIsNotAmbiguous(t *testing.T) {
	a := agentChoice{id: "agent-a1", name: "x"}
	b := agentChoice{id: "a1", name: "y"}
	if got := appendDistinctAgent([]agentChoice{a}, b); len(got) != 1 {
		t.Errorf("the same id in two spellings counted as %d agents", len(got))
	}
	// Control: two different ids stay two.
	if got := appendDistinctAgent([]agentChoice{a}, agentChoice{id: "a2"}); len(got) != 2 {
		t.Errorf("two different ids counted as %d agents", len(got))
	}
}

// End to end through the connect selector, against a stub plane that lists the agent the way an
// agent key's listing does: `--agent agent-<id>` resolves to the agent's /128.
func TestResolveConnectAgent_RegisterSpellingAgainstAnAgentKeyListing(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{agentKeyRow}, &seen)
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test", Source: client.SourceFlag}, Timeout: 5 * time.Second})
	for _, sel := range []string{"agent-aaaabbbbccccdddd", "aaaabbbbccccdddd"} {
		got, err := resolveConnectAgent(c, context.Background(), sel)
		if err != nil {
			t.Fatalf("resolveConnectAgent(%q) errored: %v", sel, err)
		}
		if got != agentKeyRow.addr {
			t.Fatalf("resolveConnectAgent(%q) = %q, want the agent's /128", sel, got)
		}
	}
}
