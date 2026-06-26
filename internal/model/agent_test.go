// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import "testing"

func TestAgentFromListItemUnwrapsItem(t *testing.T) {
	// op:list wraps each row in an `item` map; AgentFromListItem must unwrap it.
	rec := map[string]any{"item": map[string]any{
		"agent": "agent-abc", "address": "2a04:2a01::5", "label": "scraper",
		"state": "active", "created": float64(1_700_000_000_000),
	}}
	a := AgentFromListItem(rec)
	if a.ID != "agent-abc" || a.Address != "2a04:2a01::5" || a.Label != "scraper" {
		t.Fatalf("unwrap failed: %+v", a)
	}
	if a.Key() != "2a04:2a01::5" {
		t.Errorf("Key should prefer the /128, got %q", a.Key())
	}
	if a.Name() != "scraper" {
		t.Errorf("Name should prefer the label, got %q", a.Name())
	}
}

func TestAgentFromListItemStateDefaults(t *testing.T) {
	a := AgentFromListItem(map[string]any{"agent": "agent-x"})
	if a.State != "active" {
		t.Errorf("missing state should default to active, got %q", a.State)
	}
	if a.Key() != "agent-x" || a.Name() != "agent-x" {
		t.Errorf("no-address agent should key/name on id, got key=%q name=%q", a.Key(), a.Name())
	}
}

func TestMergeDetailDoesNotClobberSummary(t *testing.T) {
	a := Agent{ID: "agent-1", Address: "2a04:2a01::9", Label: "keep-me", State: "active"}
	// A detail record with an empty label must NOT erase the summary label.
	a.MergeDetail(map[string]any{
		"dns_queries": float64(100), "dns_blocked": float64(10),
		"connections_active": float64(3), "bytes_up": float64(2048),
	})
	if !a.Detailed {
		t.Error("MergeDetail should set Detailed")
	}
	if a.Label != "keep-me" {
		t.Errorf("empty detail label clobbered summary: %q", a.Label)
	}
	if a.DNSQueries != 100 || a.DNSBlocked != 10 || a.ConnectionsActive != 3 || a.BytesUp != 2048 {
		t.Errorf("counters not merged: %+v", a)
	}
	if got := a.BlockedPct(); got != 10 {
		t.Errorf("BlockedPct = %v, want 10", got)
	}
}

func TestBlockedPctNoQueries(t *testing.T) {
	a := Agent{}
	if got := a.BlockedPct(); got != 0 {
		t.Errorf("BlockedPct with no queries = %v, want 0", got)
	}
}

func TestAsIntCoercions(t *testing.T) {
	cases := []struct {
		in   any
		want int64
		ok   bool
	}{
		{float64(42), 42, true},
		{"42", 42, true},
		{int(7), 7, true},
		{int64(9), 9, true},
		{"notnum", 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := asInt(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("asInt(%v) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
