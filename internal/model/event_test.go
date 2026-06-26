// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import (
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

func TestRoundUSToMS(t *testing.T) {
	cases := []struct {
		us, ms int64
	}{
		{0, 0},
		{1, 0},      // 0.001ms rounds to 0
		{499, 0},    // < half rounds down
		{500, 1},    // half rounds up
		{1499, 1},   // 1.499ms → 1
		{1500, 2},   // 1.500ms → 2 (round half up)
		{2_400, 2},  // 2.4ms → 2
		{2_600, 3},  // 2.6ms → 3
		{-500, -1},  // symmetric on the negative side
		{-1499, -1}, // -1.499 → -1
		{-1500, -2}, // -1.500 → -2
		{1_000_000, 1000},
	}
	for _, c := range cases {
		if got := roundUSToMS(c.us); got != c.ms {
			t.Errorf("roundUSToMS(%d) = %d, want %d", c.us, got, c.ms)
		}
	}
}

func TestLogTsMicros(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want int64
	}{
		{"absent", map[string]any{}, 0},
		{"zero", map[string]any{"ts": float64(0)}, 0},
		{"epoch-seconds", map[string]any{"ts": float64(1_700_000_000)}, 1_700_000_000 * 1_000_000},
		{"epoch-millis", map[string]any{"ts": float64(1_700_000_000_000)}, 1_700_000_000_000 * 1000},
		{"already-micros", map[string]any{"ts": float64(1_700_000_000_000_000_0)}, 17_000_000_000_000_000},
		{"string-millis", map[string]any{"ts": "1700000000000"}, 1_700_000_000_000 * 1000},
	}
	for _, c := range cases {
		if got := logTsMicros(c.in); got != c.want {
			t.Errorf("logTsMicros(%s) = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSplitPeer(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"", "", 0},
		{"example.com", "example.com", 0},
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"1.2.3.4", "1.2.3.4", 0},
		{"host:65535", "host", 65535},
		{"host:65536", "host:65536", 0},           // out-of-range → not a port
		{"host:notaport", "host:notaport", 0},     // non-digit tail → host-only
		{"[2001:db8::1]:443", "2001:db8::1", 443}, // bracketed v6 + port
		{"[2001:db8::1]", "2001:db8::1", 0},       // bracketed v6, no port
		{"2001:db8::1", "2001:db8::1", 0},         // BARE v6 literal: NEVER mis-split
		{"fe80::1", "fe80::1", 0},                 // bare v6, trailing digit must not be a port
		{"::1", "::1", 0},                         // bare v6 loopback
		{"[::1]:53", "::1", 53},                   // bracketed loopback + port
	}
	for _, c := range cases {
		h, p := splitPeer(c.in)
		if h != c.host || p != c.port {
			t.Errorf("splitPeer(%q) = (%q, %d), want (%q, %d)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestFromStreamPreservesMicros(t *testing.T) {
	m := client.MonitorEvent{
		TsMicros: 1_700_000_000_000_000, Kind: "conn", Addr128: "2a04:2a01::1",
		PeerHost: "1.1.1.1", PeerPort: 443, BytesUp: 100, BytesDown: 200,
		LatencyUS: 2_600, DurationUS: 5_500,
	}
	e := FromStream(m)
	if e.TsMicros != m.TsMicros {
		t.Errorf("TsMicros not preserved: %d != %d", e.TsMicros, m.TsMicros)
	}
	if e.LatUS != 2_600 || e.LatencyMS() != 3 {
		t.Errorf("latency µs→ms wrong: us=%d ms=%d", e.LatUS, e.LatencyMS())
	}
	if e.DurUS != 5_500 || e.DurationMS() != 6 {
		t.Errorf("duration µs→ms wrong: us=%d ms=%d", e.DurUS, e.DurationMS())
	}
	if e.PeerPort != 443 || e.PeerHost != "1.1.1.1" {
		t.Errorf("peer not carried: %s:%d", e.PeerHost, e.PeerPort)
	}
}

func TestFromLogRecordScalesMsToMicros(t *testing.T) {
	rec := map[string]any{
		"ts":          float64(1_700_000_000_000), // ms
		"kind":        "conn",
		"address":     "2a04:2a01::2",
		"client_src":  "203.0.113.0/24",
		"qname":       "example.com.",
		"peer":        "[2606:4700::1111]:443",
		"latency_ms":  float64(7),
		"duration_ms": float64(12),
		"bytes_up":    float64(1000),
		"bytes_down":  float64(2000),
	}
	e := FromLogRecord(rec)
	if e.TsMicros != 1_700_000_000_000*1000 {
		t.Errorf("ts ms→µs wrong: %d", e.TsMicros)
	}
	if e.LatUS != 7000 || e.DurUS != 12000 {
		t.Errorf("ms→µs scaling wrong: lat=%d dur=%d", e.LatUS, e.DurUS)
	}
	if e.PeerHost != "2606:4700::1111" || e.PeerPort != 443 {
		t.Errorf("bracketed v6 peer split wrong: %s:%d", e.PeerHost, e.PeerPort)
	}
	if e.Addr128 != "2a04:2a01::2" || e.ClientSrc != "203.0.113.0/24" {
		t.Errorf("chain fields not carried: addr=%s src=%s", e.Addr128, e.ClientSrc)
	}
}

func TestAllDigitsPort(t *testing.T) {
	cases := []struct {
		in   string
		port int
		ok   bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{"443", 443, true},
		{"65535", 65535, true},
		{"65536", 0, false},
		{"99999", 0, false},
		{"12a", 0, false},
		{"-1", 0, false},
	}
	for _, c := range cases {
		p, ok := allDigitsPort(c.in)
		if ok != c.ok || (ok && p != c.port) {
			t.Errorf("allDigitsPort(%q) = (%d,%v), want (%d,%v)", c.in, p, ok, c.port, c.ok)
		}
	}
}
