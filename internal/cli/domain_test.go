// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// TestAgentDomain covers the FQDN→zone derivation that distinguishes a hosted identity
// (agents.whisper.online) from a BYOD-domain one (#168). Liberal in what it reads: trailing
// dot or not, blank in → blank out, a bare apex returns itself.
func TestAgentDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"scout.agents.whisper.online.", "agents.whisper.online"},    // hosted, trailing dot
		{"scout.agents.whisper.online", "agents.whisper.online"},     // hosted, no dot
		{"bot.example.com.", "example.com"},                          // BYOD
		{"a.b.c.d.example.co.uk", "b.c.d.example.co.uk"},             // deep label
		{"  scout.agents.whisper.online  ", "agents.whisper.online"}, // surrounding space
		{"example.com.", "com"},                                      // 2-label apex → its TLD parent
		{"localhost", "localhost"},                                   // no dot → itself (it IS the zone)
		{"", ""},                                                     // empty in → empty out
		{".", ""},                                                    // bare root
		{"trailing.", "trailing"},                                    // single label + dot
	}
	for _, c := range cases {
		if got := agentDomain(c.in); got != c.want {
			t.Errorf("agentDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestChoicesFromResult_CarriesDomain proves op:list rows flow their fqdn through to the
// agentChoice.domain the picker shows — so a BYOD vs hosted agent is distinguishable. Also
// covers the {kind,item} wrapper (Postel: liberal in what we read) and a row with no fqdn.
func TestChoicesFromResult_CarriesDomain(t *testing.T) {
	res := &client.Result{
		Columns: []string{"kind", "item"},
		Rows: [][]any{
			{"agent", map[string]any{"label": "scout", "address": "2a04:2a01:1::1", "fqdn": "scout.agents.whisper.online."}},
			{"agent", map[string]any{"label": "byod", "address": "2a04:2a01:1::2", "fqdn": "byod.example.com."}},
			{"agent", map[string]any{"label": "nofqdn", "address": "2a04:2a01:1::3"}},
		},
	}
	got := choicesFromResult(res)
	if len(got) != 3 {
		t.Fatalf("got %d choices, want 3", len(got))
	}
	want := []agentChoice{
		{name: "scout", addr: "2a04:2a01:1::1", domain: "agents.whisper.online"},
		{name: "byod", addr: "2a04:2a01:1::2", domain: "example.com"},
		{name: "nofqdn", addr: "2a04:2a01:1::3", domain: ""},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("choice[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
