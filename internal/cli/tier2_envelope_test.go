// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// tier2_envelope_test.go - the Tier-2 envelope mirror: the new doh_url / resolver_ip
// fields decode from op:register (agent + device) and op:identity results; absent stays
// absent (zero value, no panic); malformed values fail soft; the established fields of the
// same envelopes are untouched.

// resultOf builds a client.Result the way the wire delivers it (columns + positional rows).
func resultOf(t *testing.T, columns []string, row []any) *client.Result {
	t.Helper()
	// Round-trip through JSON so cell types match a real decode (numbers -> float64 etc).
	raw, err := json.Marshal(map[string]any{"columns": columns, "rows": []any{row}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var res client.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &res
}

func TestTier2FromResult_AgentRegisterShape(t *testing.T) {
	key := "whisper_live_AGENT_ag_1a"
	res := resultOf(t,
		[]string{"api_key", "agent", "address", "fqdn", "ptr", "doh_url", "resolver_ip"},
		[]any{key, "agent-a1b2", "2a04:2a01:9::1", "a1b2.t123.agents.whisper.online.", "ptr.example.",
			"https://doh.whisper.online/" + key + "/dns-query", "2a04:2a01:0:53::7c1"})

	got := tier2FromResult(res)
	if got.DoHURL != "https://doh.whisper.online/"+key+"/dns-query" {
		t.Fatalf("DoHURL = %q", got.DoHURL)
	}
	if got.ResolverIP != "2a04:2a01:0:53::7c1" {
		t.Fatalf("ResolverIP = %q", got.ResolverIP)
	}
	if got.empty() {
		t.Fatal("empty() must be false when endpoints are offered")
	}
}

func TestTier2FromResult_IdentityShape_HonestOmissions(t *testing.T) {
	// op:identity: doh_url is an honest "" (the server cannot derive the caller-keyed URL);
	// resolver_ip present only when the tenant slot is allocated.
	res := resultOf(t,
		[]string{"address", "fqdn", "ptr", "state", "doh_url", "resolver_ip"},
		[]any{"2a04:2a01:9::2", "bot7.t123.agents.whisper.online.", "ptr.example.", "active", "", ""})

	got := tier2FromResult(res)
	if got.DoHURL != "" || got.ResolverIP != "" {
		t.Fatalf("expected honest omissions, got %+v", got)
	}
	if !got.empty() {
		t.Fatal("empty() must be true when nothing is offered (the DoH-fallback signal)")
	}
}

func TestTier2FromResult_PreTier2ServerAbsentStaysAbsent(t *testing.T) {
	// An older server without the columns at all: the CLI must read "nothing offered", not fail.
	res := resultOf(t,
		[]string{"api_key", "agent", "address", "fqdn", "ptr"},
		[]any{"k", "agent-x", "2a04:2a01:9::3", "x.t1.agents.whisper.online.", "p."})
	if got := tier2FromResult(res); !got.empty() {
		t.Fatalf("expected zero value from an envelope without the new fields, got %+v", got)
	}
}

func TestTier2FromResult_DeviceShape(t *testing.T) {
	res := resultOf(t,
		[]string{"token", "doh_url", "dot_host", "resolver_ip", "address", "label"},
		[]any{"whisper_live_DEVICE_abc", "https://doh.whisper.online/whisper_live_DEVICE_abc/dns-query",
			"d0a1.dot.whisper.online", "2a04:2a01:0:53::9f2", "2a04:2a01:9::d0e", "kitchen-ipad"})
	got := tier2FromResult(res)
	if got.DoHURL == "" || got.ResolverIP != "2a04:2a01:0:53::9f2" {
		t.Fatalf("device shape decode = %+v", got)
	}
}

func TestTier2FromRecord_MalformedValuesFailSoft(t *testing.T) {
	cases := []struct {
		name string
		rec  map[string]any
	}{
		{"non-https doh_url", map[string]any{"doh_url": "http://doh.whisper.online/dns-query"}},
		{"garbage doh_url", map[string]any{"doh_url": "not a url"}},
		{"non-IP resolver_ip", map[string]any{"resolver_ip": "doh.whisper.online"}},
		{"garbage resolver_ip", map[string]any{"resolver_ip": "2a04:2a01::zzz"}},
		{"null cells", map[string]any{"doh_url": nil, "resolver_ip": nil}},
		{"numeric cells", map[string]any{"doh_url": 42, "resolver_ip": 42}},
	}
	for _, tc := range cases {
		if got := tier2FromRecord(tc.rec); !got.empty() {
			t.Fatalf("%s: expected fail-soft zero value, got %+v", tc.name, got)
		}
	}
	// Liberal-in: surrounding whitespace is trimmed, the value kept.
	got := tier2FromRecord(map[string]any{
		"doh_url":     "  https://doh.whisper.online/k/dns-query  ",
		"resolver_ip": " 2a04:2a01:0:53::1 ",
	})
	if got.DoHURL != "https://doh.whisper.online/k/dns-query" || got.ResolverIP != "2a04:2a01:0:53::1" {
		t.Fatalf("whitespace-trim decode = %+v", got)
	}
}

func TestTier2NilSafety_NoPanicAnywhere(t *testing.T) {
	if got := tier2FromRecord(nil); !got.empty() {
		t.Fatalf("nil record: %+v", got)
	}
	if got := tier2FromResult(nil); !got.empty() {
		t.Fatalf("nil result: %+v", got)
	}
	if got := tier2FromResult(&client.Result{}); !got.empty() {
		t.Fatalf("empty result: %+v", got)
	}
	if got := tier2FromEnvelope(nil); !got.empty() {
		t.Fatalf("nil envelope: %+v", got)
	}
	if got := tier2FromEnvelope(&client.Envelope{Ok: false}); !got.empty() {
		t.Fatalf("failed envelope: %+v", got)
	}
	if got := tier2FromEnvelope(&client.Envelope{Ok: true}); !got.empty() {
		t.Fatalf("resultless envelope: %+v", got)
	}
}

func TestTier2FromEnvelope_ReadsTheWireForm(t *testing.T) {
	// The full envelope path, decoded exactly as client.Agents hands it to a verb.
	raw := []byte(`{"ok":true,"status":200,"result":{` +
		`"columns":["api_key","agent","address","fqdn","ptr","doh_url","resolver_ip"],` +
		`"rows":[["k","agent-1","2a04:2a01:9::1","f.","p.",` +
		`"https://doh.whisper.online/k/dns-query","2a04:2a01:0:53::7c1"]]}}`)
	env, err := client.DecodeEnvelope(raw, 200)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	got := tier2FromEnvelope(env)
	if got.DoHURL != "https://doh.whisper.online/k/dns-query" || got.ResolverIP != "2a04:2a01:0:53::7c1" {
		t.Fatalf("envelope decode = %+v", got)
	}
}
