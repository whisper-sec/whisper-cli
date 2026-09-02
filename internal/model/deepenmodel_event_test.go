// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

func TestDeepenModelFlashTickRoundTripAndWireInvisibility(t *testing.T) {
	var e Event
	if e.FlashTick() != 0 {
		t.Errorf("zero Event should have FlashTick 0, got %d", e.FlashTick())
	}
	e.SetFlashTick(7)
	if e.FlashTick() != 7 {
		t.Errorf("SetFlashTick(7) then FlashTick() = %d", e.FlashTick())
	}
	// The contract: flashTick is a render-only stamp, invisible on the wire (the
	// drill card and the scriptable CLI marshal Events to JSON). If it ever leaks
	// into the JSON form, that is a conservative-emit regression.
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal Event: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "flash") {
		t.Errorf("flashTick leaked onto the wire: %s", b)
	}
}

func TestDeepenModelEventTimeUTC(t *testing.T) {
	e := Event{TsMicros: 1_700_000_000_000_123}
	got := e.Time()
	if got.Location() != time.UTC {
		t.Errorf("Time() must be UTC, got %v", got.Location())
	}
	want := time.Date(2023, 11, 14, 22, 13, 20, 123_000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Time() = %v, want %v", got, want)
	}
}

func TestDeepenModelLogTsMicrosSmallPassThrough(t *testing.T) {
	// Values at or below the epoch-seconds threshold pass through unscaled - a
	// relative or already-tiny ts must never be inflated into a fake epoch.
	cases := []struct {
		name string
		ts   float64
		want int64
	}{
		{"small-positive", 500, 500},
		{"exactly-one", 1, 1},
		{"negative", -5, -5},
	}
	for _, c := range cases {
		if got := logTsMicros(map[string]any{"ts": c.ts}); got != c.want {
			t.Errorf("%s: logTsMicros(ts=%v) = %d, want %d", c.name, c.ts, got, c.want)
		}
	}
}

func TestDeepenModelSplitPeerBracketEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		host string
		port int
	}{
		{"unclosed-bracket", "[2001:db8::1", "[2001:db8::1", 0},
		{"lone-open-bracket", "[", "[", 0},
		{"bracket-trailing-colon-no-digits", "[2001:db8::1]:", "2001:db8::1", 0},
		{"bracket-non-numeric-port", "[2001:db8::1]:abc", "2001:db8::1", 0},
		{"bracket-out-of-range-port", "[2001:db8::1]:70000", "2001:db8::1", 0},
		{"bracket-junk-after", "[2001:db8::1]x", "2001:db8::1", 0},
	}
	for _, c := range cases {
		h, p := splitPeer(c.in)
		if h != c.host || p != c.port {
			t.Errorf("%s: splitPeer(%q) = (%q, %d), want (%q, %d)", c.name, c.in, h, p, c.host, c.port)
		}
	}
}

func TestDeepenModelFromLogRecordDNSRowAndPeerAlias(t *testing.T) {
	rec := map[string]any{
		"ts":         float64(1_700_000_000_000),
		"kind":       "dns",
		"agent":      "agent-5",
		"addr128":    "2a04:2a01::5",
		"qname":      "malware.example.",
		"qtype":      "AAAA",
		"rcode":      "NOERROR",
		"decision":   "block",
		"source":     "graph",
		"latency_ms": float64(2),
		"peer_host":  "198.51.100.7", // alias key, host with no port
		"reason":     "listed",
	}
	e := FromLogRecord(rec)
	if e.Kind != "dns" || e.Agent != "agent-5" || e.Addr128 != "2a04:2a01::5" {
		t.Errorf("identity fields not carried: %+v", e)
	}
	if e.QName != "malware.example." || e.QType != "AAAA" || e.RCode != "NOERROR" {
		t.Errorf("dns fields not carried: %+v", e)
	}
	if e.Decision != "block" || e.Source != "graph" || e.Reason != "listed" {
		t.Errorf("policy fields not carried: %+v", e)
	}
	if e.LatUS != 2000 {
		t.Errorf("latency_ms not scaled to us: %d", e.LatUS)
	}
	if e.PeerHost != "198.51.100.7" || e.PeerPort != 0 {
		t.Errorf("peer_host alias not honoured: %s:%d", e.PeerHost, e.PeerPort)
	}
}

func TestDeepenModelFromLogRecordNoPeerLeavesZero(t *testing.T) {
	e := FromLogRecord(map[string]any{"kind": "hb", "agent": "agent-8"})
	if e.PeerHost != "" || e.PeerPort != 0 {
		t.Errorf("absent peer must stay zero: %q:%d", e.PeerHost, e.PeerPort)
	}
	if e.TsMicros != 0 {
		t.Errorf("absent ts must stay zero: %d", e.TsMicros)
	}
}

func TestDeepenModelStreamAndLogSurfacesConverge(t *testing.T) {
	// The whole point of Event: the SSE stream (us units) and the op:logs poll
	// (ms units) describing the SAME conn must normalise to the SAME internal
	// values, so views never reason about the unit split.
	fromStream := FromStream(client.MonitorEvent{
		TsMicros: 1_700_000_000_500_000, Kind: "conn", Agent: "agent-7",
		Addr128: "2a04:2a01::7", Proto: "tcp",
		PeerHost: "93.184.216.34", PeerPort: 443,
		BytesUp: 1000, BytesDown: 2000, DurationUS: 12_000,
	})
	fromLog := FromLogRecord(map[string]any{
		"ts": float64(1_700_000_000_500), "kind": "conn", "agent": "agent-7",
		"addr128":  "2a04:2a01::7",
		"peer":     "93.184.216.34:443",
		"bytes_up": float64(1000), "bytes_down": float64(2000),
		"duration_ms": float64(12),
	})
	if fromStream.TsMicros != fromLog.TsMicros {
		t.Errorf("ts diverges: stream=%d log=%d", fromStream.TsMicros, fromLog.TsMicros)
	}
	if fromStream.DurUS != fromLog.DurUS {
		t.Errorf("duration diverges: stream=%d log=%d", fromStream.DurUS, fromLog.DurUS)
	}
	if fromStream.PeerHost != fromLog.PeerHost || fromStream.PeerPort != fromLog.PeerPort {
		t.Errorf("peer diverges: stream=%s:%d log=%s:%d",
			fromStream.PeerHost, fromStream.PeerPort, fromLog.PeerHost, fromLog.PeerPort)
	}
	if fromStream.Kind != fromLog.Kind || fromStream.Agent != fromLog.Agent ||
		fromStream.Addr128 != fromLog.Addr128 ||
		fromStream.BytesUp != fromLog.BytesUp || fromStream.BytesDown != fromLog.BytesDown {
		t.Errorf("surfaces diverge:\nstream %+v\nlog    %+v", fromStream, fromLog)
	}
}
