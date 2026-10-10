// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// `whisper use <friendly-name>` rejected an agent that `whisper list` had
// just shown under that exact name, while selecting the same agent by IPv6 worked
// and `connect --agent <name>` accepted it.
//
// The cause was field(item, "agent", "id", "label"), which returns the FIRST of
// those keys that exists. Every row carries "agent", so "label" was unreachable.
// The row shape below is the one the issue observed: label, agent, address, fqdn
// all present together, which is precisely the case the old code could not match.
func listRow() map[string]any {
	return map[string]any{
		"label":   "my-first-agent",
		"agent":   "ag_01J9ZQ7X",
		"address": "2a04:2a01:5ec5:1::a1",
		"fqdn":    "my-first-agent.agents.whisper.online.",
	}
}

func TestAgentItemMatches_EveryIdentifierTheRowCarries(t *testing.T) {
	row := listRow()
	for _, target := range []string{
		"my-first-agent",                        // the label: THE regression
		"ag_01J9ZQ7X",                           // the agent id
		"2a04:2a01:5ec5:1::a1",                  // the address
		"my-first-agent.agents.whisper.online.", // the fqdn as the wire spells it
		"my-first-agent.agents.whisper.online",  // and as a person types it
	} {
		if !agentItemMatches(row, target) {
			t.Errorf("a row shown as %q must match target %q", row["label"], target)
		}
	}
}

func TestAgentItemMatches_RejectsWhatIsNotThisAgent(t *testing.T) {
	row := listRow()
	for _, target := range []string{
		"", "   ", "some-other-agent", "ag_NOPE",
		"2a04:2a01:5ec5:1::a2", // one hex digit off
		"my-first",             // a prefix is not a name
		"agent",                // a field NAME is not a value
	} {
		if agentItemMatches(row, target) {
			t.Errorf("target %q must not match this row", target)
		}
	}
}

// The fold is for a person retyping a name they were shown, but an EXACT match
// must always win so two agents differing only in case cannot resolve to one
// another.
func TestAgentItemMatches_FoldsCaseButExactStillWins(t *testing.T) {
	row := listRow()
	if !agentItemMatches(row, "My-First-Agent") {
		t.Error("a DNS label typed in another case should still resolve")
	}
	if !agentItemMatches(row, " my-first-agent ") {
		t.Error("surrounding whitespace should not decide whether an agent exists")
	}

	exact := map[string]any{"label": "Prod", "address": "2a04:2a01::2"}
	fold := map[string]any{"label": "prod", "address": "2a04:2a01::3"}
	if !agentItemMatches(exact, "Prod") || !agentItemMatches(fold, "prod") {
		t.Fatal("each row must match its own exact label")
	}
	// Both DO fold-match the other's name; the ordering in resolveAddress is what
	// makes an exact hit win, and this pins that both are reachable at all.
	if !agentItemMatches(exact, "prod") {
		t.Error("fold matching should still be available as the second pass")
	}
}

// The bug reproduced against the OLD implementation, kept so the regression has a
// name: first-key-wins could never see the label.
func TestAgentItemMatches_FirstKeyWinsWouldHaveFailed(t *testing.T) {
	row := listRow()
	if got := field(row, "agent", "id", "label"); got == "my-first-agent" {
		t.Fatal("field() no longer returns the first present key; this test's premise is stale")
	} else if got != "ag_01J9ZQ7X" {
		t.Fatalf("field() returned %q, expected the agent id it picks first", got)
	}
	if !agentItemMatches(row, "my-first-agent") {
		t.Fatal("the label must match even though field() would have returned the agent id")
	}
}

// --- the call site, not just the helper ------------------------------------------
//
// The helper tests above pass whether or not resolveAddress actually USES the
// helper: reverting the call site to first-key-wins left every one of them green.
// This closes that gap by driving the real function against a stub control plane.
//
// The row it serves is the PRODUCTION shape the issue observed - label, agent,
// address and fqdn together. That matters: the existing listJSON test builder
// emits only label and address, and with "agent" absent the old
// field(item,"agent","id","label") fell through to the label and matched. The
// fixture had been quietly dodging the bug, which is why nothing caught it.
func TestResolveAddress_MatchesTheLabelListShows(t *testing.T) {
	const addr = "2a04:2a01:5ec5:1::a1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[
 ["agents",{"label":"my-first-agent","agent":"ag_01J9ZQ7X","address":"` + addr + `",
  "fqdn":"my-first-agent.agents.whisper.online."}]]}}`))
	}))
	defer srv.Close()
	c := client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper_live_test", Source: client.SourceFlag},
		Timeout:    5 * time.Second,
	})

	for _, target := range []string{
		"my-first-agent", // the reproduction
		"ag_01J9ZQ7X",
		addr,
		"my-first-agent.agents.whisper.online.",
	} {
		got, err := resolveAddress(c, target)
		if err != nil {
			t.Errorf("resolveAddress(%q) = error %v; the row is in the account", target, err)
			continue
		}
		if got != addr {
			t.Errorf("resolveAddress(%q) = %q, want %q", target, got, addr)
		}
	}
}

// A genuine miss must still be a miss: the fix widens what counts as a match, and
// without this it could have widened it to everything.
func TestResolveAddress_StillRejectsAnAgentNotInTheAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[
 ["agents",{"label":"my-first-agent","agent":"ag_01J9ZQ7X","address":"2a04:2a01:5ec5:1::a1"}]]}}`))
	}))
	defer srv.Close()
	c := client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper_live_test", Source: client.SourceFlag},
		Timeout:    5 * time.Second,
	})
	if _, err := resolveAddress(c, "somebody-elses-agent"); err == nil {
		t.Fatal("an agent that is not in the account must still be rejected")
	}
}
