// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The id `whisper list` prints in its AGENT column must be a selector you can pass back to
// us.
//
// The defect was not that the id resolved badly, it was that the id was never CARRIED:
// choicesFromResult folded label-or-id into one `name` field with the label winning, so on
// any agent that had a label - which is every agent a person has named - the `agent-<hex>`
// was discarded before anything could match it. A user copied a string out of our own
// output and we answered "that agent isn't in your account", about an agent we had just
// listed to them, which sends them back to the command that produced the rejected string.
func TestAgentIdSurvivesTheParse(t *testing.T) {
	// Exactly the shape op:list returns for a LABELLED agent, which is the case that broke.
	res := &client.Result{
		Columns: []string{"kind", "item"},
		Rows: [][]any{{"agents", map[string]any{
			"agent":   "agent-aaaabbbbccccdddd0",
			"address": "2a04:2a01:0:cafe:aaaa:bbbb:cccc:dddd",
			"label":   "BUILDER",
			"fqdn":    "aaaabbbbccccdddd0.t0123456789abcdef0123456789abcdef.agents.whisper.online.",
		}}},
	}
	got := choicesFromResult(res)
	if len(got) != 1 {
		t.Fatalf("want 1 choice, got %d", len(got))
	}
	// The label still wins for DISPLAY. That part was never wrong.
	if got[0].name != "BUILDER" {
		t.Errorf("name: want the label BUILDER, got %q", got[0].name)
	}
	// ...and the id is no longer discarded just because a label existed.
	if got[0].id != "agent-aaaabbbbccccdddd0" {
		t.Errorf("id: want agent-aaaabbbbccccdddd0, got %q - the id was dropped because the "+
			"agent has a label, so nothing can match the id whisper list prints", got[0].id)
	}
}

// Every string a user can copy out of `whisper list` selects the agent, and nothing else does.
func TestEverySelectorFormMatches(t *testing.T) {
	ch := agentChoice{
		name: "BUILDER",
		addr: "2a04:2a01:0:cafe:aaaa:bbbb:cccc:dddd",
		id:   "agent-aaaabbbbccccdddd0",
	}
	for _, sel := range []string{
		"BUILDER",                              // the LABEL column
		"builder",                              // ...in another casing
		"agent-aaaabbbbccccdddd0",              // the AGENT column, the one that used to be refused
		"AGENT-AAAABBBBCCCCDDDD0",              // ...in another casing
		"2a04:2a01:0:cafe:aaaa:bbbb:cccc:dddd", // the ADDRESS column
	} {
		if !choiceMatchesSelector(ch, sel) {
			t.Errorf("selector %q does not match, and a user can copy it straight out of `whisper list`", sel)
		}
	}
	// Controls. Without these the test would pass on a matcher that returns true for anything.
	for _, sel := range []string{"agent-deadbeefdeadbeef", "OTHER", "2a04:2a01::1", "", "   "} {
		if choiceMatchesSelector(ch, sel) {
			t.Errorf("selector %q matched and must not", sel)
		}
	}
}

// An agent with NO label must still be selectable by both its id and its address: the old
// code happened to work here (the id fell through into `name`), so this pins that the fix
// did not trade one case for the other.
func TestUnlabelledAgentStillSelectable(t *testing.T) {
	res := &client.Result{
		Columns: []string{"kind", "item"},
		Rows: [][]any{{"agents", map[string]any{
			"agent":   "agent-a5555666677778888",
			"address": "2a04:2a01:0:beef:5555:6666:7777:8888",
		}}},
	}
	got := choicesFromResult(res)
	if len(got) != 1 {
		t.Fatalf("want 1 choice, got %d", len(got))
	}
	for _, sel := range []string{"agent-a5555666677778888", "2a04:2a01:0:beef:5555:6666:7777:8888"} {
		if !choiceMatchesSelector(got[0], sel) {
			t.Errorf("unlabelled agent: selector %q does not match", sel)
		}
	}
}
