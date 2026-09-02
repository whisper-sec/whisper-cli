// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import (
	"encoding/json"
	"testing"
)

func TestDeepenModelHasIdentity(t *testing.T) {
	if (Agent{Address: "2a04:2a01::5"}).HasIdentity() != true {
		t.Error("agent with a /128 must report HasIdentity")
	}
	if (Agent{ID: "agent-history-only"}).HasIdentity() != false {
		t.Error("history-only agent (no /128) must NOT report HasIdentity")
	}
}

func TestDeepenModelNameFallbackChain(t *testing.T) {
	// label > id > address, in that order.
	cases := []struct {
		name string
		a    Agent
		want string
	}{
		{"label-wins", Agent{Label: "scraper", ID: "agent-1", Address: "2a04:2a01::1"}, "scraper"},
		{"id-when-no-label", Agent{ID: "agent-1", Address: "2a04:2a01::1"}, "agent-1"},
		{"address-last-resort", Agent{Address: "2a04:2a01::1"}, "2a04:2a01::1"},
		{"all-empty", Agent{}, ""},
	}
	for _, c := range cases {
		if got := c.a.Name(); got != c.want {
			t.Errorf("%s: Name() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDeepenModelStringSummary(t *testing.T) {
	a := Agent{ID: "agent-9", Address: "2a04:2a01::9", State: "active"}
	if got := a.String(); got != "agent-9 2a04:2a01::9 active" {
		t.Errorf("String() = %q, want %q", got, "agent-9 2a04:2a01::9 active")
	}
}

func TestDeepenModelTenantFromFQDN(t *testing.T) {
	cases := []struct {
		name string
		fqdn string
		want string
	}{
		{"canonical", "web-scraper.t4f9a2b8c1.agents.whisper.online", "t4f9a2b8c1"},
		{"trailing-dot-trimmed", "web-scraper.t4f9a2b8c1.agents.whisper.online.", "t4f9a2b8c1"},
		{"minimum-handle-length", "a.t12345678.agents.zone", "t12345678"},
		{"handle-too-short", "a.t1234567.agents.zone", ""},
		{"handle-not-t-prefixed", "a.x123456789.agents.zone", ""},
		{"too-few-labels", "t123456789.agents.zone", ""},
		{"plain-hostname", "example.com", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := TenantFromFQDN(c.fqdn); got != c.want {
			t.Errorf("%s: TenantFromFQDN(%q) = %q, want %q", c.name, c.fqdn, got, c.want)
		}
	}
}

func TestDeepenModelMergeDetailOverwritesNonEmpty(t *testing.T) {
	// A detail record with real values MUST replace the stale summary fields,
	// including via the alias keys (agent, addr128, allocated_at).
	a := Agent{
		ID: "agent-old", Address: "2a04:2a01::1", FQDN: "old.t123456789.agents.zone",
		PTR: "old.ptr", Label: "old-label", State: "pending", Created: 111,
	}
	a.MergeDetail(map[string]any{
		"agent":             "agent-new",
		"addr128":           "2a04:2a01::2",
		"fqdn":              "new.t123456789.agents.zone",
		"ptr":               "new.ptr.ip6.arpa",
		"label":             "new-label",
		"state":             "active",
		"contact":           "ops@example.com",
		"allocated_at":      float64(222_000),
		"last_seen":         float64(1_700_000_000_000),
		"dns_nxdomain":      float64(4),
		"packets":           float64(99),
		"bytes_down":        float64(4096),
		"connections_total": float64(12),
	})
	if a.ID != "agent-new" || a.Address != "2a04:2a01::2" {
		t.Errorf("alias keys agent/addr128 not merged: id=%q addr=%q", a.ID, a.Address)
	}
	if a.FQDN != "new.t123456789.agents.zone" || a.PTR != "new.ptr.ip6.arpa" {
		t.Errorf("fqdn/ptr not overwritten: fqdn=%q ptr=%q", a.FQDN, a.PTR)
	}
	if a.Label != "new-label" || a.State != "active" || a.Contact != "ops@example.com" {
		t.Errorf("label/state/contact not overwritten: %+v", a)
	}
	if a.Created != 222_000 {
		t.Errorf("allocated_at should overwrite Created: %d", a.Created)
	}
	if a.LastSeen != 1_700_000_000_000 || a.DNSNxdomain != 4 || a.Packets != 99 ||
		a.BytesDown != 4096 || a.ConnectionsTotal != 12 {
		t.Errorf("detail counters not merged: %+v", a)
	}
}

func TestDeepenModelMergeDetailKeepsCreatedWhenAbsent(t *testing.T) {
	a := Agent{ID: "agent-1", Created: 111, State: "active"}
	a.MergeDetail(map[string]any{"dns_queries": float64(5)})
	if a.Created != 111 {
		t.Errorf("absent allocated_at/created must not zero Created: %d", a.Created)
	}
	if a.State != "active" || a.ID != "agent-1" {
		t.Errorf("empty detail fields clobbered summary: %+v", a)
	}
}

func TestDeepenModelAsStringRendering(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, ""},
		{"string", "x", "x"},
		{"bool-true", true, "true"},
		{"bool-false", false, "false"},
		{"integral-float", float64(42), "42"},
		{"negative-integral-float", float64(-7), "-7"},
		{"fractional-float", float64(3.5), "3.5"},
		{"json-number", json.Number("123"), "123"},
		{"json-number-fraction", json.Number("12.5"), "12.5"},
		{"object-falls-back-to-marshal", map[string]any{"a": float64(1)}, `{"a":1}`},
		{"array-falls-back-to-marshal", []any{"x"}, `["x"]`},
	}
	for _, c := range cases {
		if got := asString(c.in); got != c.want {
			t.Errorf("%s: asString(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestDeepenModelStrSkipsEmptyValues(t *testing.T) {
	// str must fall through a present-but-empty key to the next candidate,
	// and coerce non-string JSON values on the way out.
	m := map[string]any{"address": nil, "addr128": "2a04:2a01::3", "flag": true}
	if got := str(m, "address", "addr128"); got != "2a04:2a01::3" {
		t.Errorf("str should skip the nil value and use the alias: %q", got)
	}
	if got := str(m, "flag"); got != "true" {
		t.Errorf("str should coerce a bool: %q", got)
	}
	if got := str(m, "missing"); got != "" {
		t.Errorf("str on an absent key = %q, want empty", got)
	}
}

func TestDeepenModelAsIntJSONNumber(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
		ok   bool
	}{
		{"integer", json.Number("42"), 42, true},
		{"fraction-truncates", json.Number("3.9"), 3, true},
		{"garbage", json.Number("xyz"), 0, false},
		{"float-truncates", float64(3.9), 3, true},
	}
	for _, c := range cases {
		got, ok := asInt(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: asInt(%v) = (%d,%v), want (%d,%v)", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDeepenModelFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "second", "third"); got != "second" {
		t.Errorf("firstNonEmpty skipped wrong: %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("all-empty should return empty, got %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("no args should return empty, got %q", got)
	}
}
