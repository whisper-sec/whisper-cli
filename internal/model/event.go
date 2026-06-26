// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import (
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// Event is the ONE internal activity model, normalised so views never reason about the
// µs-vs-ms split between the two surfaces:
//
//   - the SSE stream carries ts/latency/duration in MICROSECONDS (and alloc.allocated_at
//     in ms); a live conn event has NO qname (the chain is split across two events).
//   - the op:logs poll carries latency_ms/duration_ms in MILLISECONDS and a single
//     `peer` column, with the whole chain (client_src + qname + peer) on ONE row.
//
// We store time in microseconds internally (TsMicros) and format on render. The
// monitor (step C) stitches a live conn's qname from a per-agent dns join cache; an
// op:logs conn row already carries qname, so the same Event type serves both.
type Event struct {
	TsMicros int64  // epoch microseconds (native stream unit; ms sources are scaled up)
	Kind     string // dns | conn | alloc | hb
	Node     string // emitting ns box (e.g. "ns1")
	Agent    string // the agent id
	Addr128  string // the /128 (the join key for the dns→conn chain)

	// dns
	QName    string
	QType    string
	RCode    string
	Decision string // lowercase: allow/block/sinkhole/rewrite/refused
	Source   string // cache/graph/upstream/tenant-block/authoritative
	Answer   string // null today — render "-"
	LatUS    int64  // dns latency, microseconds

	// conn (egress)
	Proto     string
	PeerHost  string
	PeerPort  int
	BytesUp   int64
	BytesDown int64
	PktUp     int64 // relay read/write EVENT counts (chattiness), not wire packets
	PktDown   int64
	DurUS     int64 // conn duration, microseconds
	Reason    string
	ClientSrc string // masked original-client source prefix

	// alloc
	Action string // allocate | release

	// flashTick is a TUI-only render hint: the render-tick count at which this event was
	// folded onto the live feed, so the monitor can flash the row in for ~400ms after it
	// arrives (motion). Unexported ⇒ ignored by JSON (the drill card never shows it) and
	// invisible to the scriptable CLI — it is purely a presentation stamp.
	flashTick int
}

// FlashTick / SetFlashTick expose the render-only arrival stamp to the tui package
// (which lives in a different package) without leaking it onto the wire.
func (e Event) FlashTick() int      { return e.flashTick }
func (e *Event) SetFlashTick(t int) { e.flashTick = t }

// Time returns the event time as a Go time (UTC).
func (e Event) Time() time.Time { return time.UnixMicro(e.TsMicros).UTC() }

// LatencyMS / DurationMS expose the derived ms forms (rounded), for compact display.
func (e Event) LatencyMS() int64  { return roundUSToMS(e.LatUS) }
func (e Event) DurationMS() int64 { return roundUSToMS(e.DurUS) }

func roundUSToMS(us int64) int64 {
	if us == 0 {
		return 0
	}
	if us < 0 {
		return -((-us + 500) / 1000)
	}
	return (us + 500) / 1000
}

// FromStream converts a live SSE MonitorEvent (µs units) into the unified Event.
func FromStream(m client.MonitorEvent) Event {
	return Event{
		TsMicros:  m.TsMicros,
		Kind:      m.Kind,
		Node:      m.Node,
		Agent:     m.Agent,
		Addr128:   m.Addr128,
		QName:     m.QName,
		QType:     m.QType,
		RCode:     m.RCode,
		Decision:  m.Decision,
		Source:    m.Source,
		Answer:    m.Answer,
		LatUS:     m.LatencyUS,
		Proto:     m.Proto,
		PeerHost:  m.PeerHost,
		PeerPort:  m.PeerPort,
		BytesUp:   m.BytesUp,
		BytesDown: m.BytesDown,
		PktUp:     m.PacketsUp,
		PktDown:   m.PacketsDown,
		DurUS:     m.DurationUS,
		Reason:    m.Reason,
		ClientSrc: m.ClientSrc,
		Action:    m.Action,
	}
}

// FromLogRecord converts an op:logs row (ms units; whole chain on one row) into the
// unified Event. The poll carries latency_ms/duration_ms and a single `peer` column,
// which we scale to µs so the internal model has one unit. Liberal-in on field names.
func FromLogRecord(rec map[string]any) Event {
	e := Event{
		TsMicros:  logTsMicros(rec),
		Kind:      str(rec, "kind"),
		Agent:     str(rec, "agent"),
		Addr128:   str(rec, "addr128", "address"),
		QName:     str(rec, "qname"),
		QType:     str(rec, "qtype"),
		RCode:     str(rec, "rcode"),
		Decision:  str(rec, "decision"),
		Source:    str(rec, "source"),
		Answer:    str(rec, "answer"),
		LatUS:     num(rec, "latency_ms") * 1000, // ms → µs
		BytesUp:   num(rec, "bytes_up"),
		BytesDown: num(rec, "bytes_down"),
		PktUp:     num(rec, "packets_up"),
		PktDown:   num(rec, "packets_down"),
		DurUS:     num(rec, "duration_ms") * 1000, // ms → µs
		Reason:    str(rec, "reason"),
		ClientSrc: str(rec, "client_src", "client_subnet"),
	}
	// The poll's single `peer` column is "host:port" or just a host; split liberally.
	if peer := str(rec, "peer", "peer_host"); peer != "" {
		e.PeerHost, e.PeerPort = splitPeer(peer)
	}
	return e
}

// logTsMicros reads the op:logs `ts` (epoch-ms or RFC-3339-ish) and scales to µs.
// op:logs documents ms; if a value looks like µs already (very large) we keep it.
func logTsMicros(rec map[string]any) int64 {
	ts := num(rec, "ts")
	if ts == 0 {
		return 0
	}
	switch {
	case ts > 1_000_000_000_000_000: // already µs (>~ year 33000 in ms; clearly µs)
		return ts
	case ts > 1_000_000_000_000: // epoch ms
		return ts * 1000
	case ts > 1_000_000_000: // epoch s
		return ts * 1_000_000
	default:
		return ts
	}
}

func splitPeer(peer string) (host string, port int) {
	// Liberal-in across every form the poll might emit:
	//   - bracketed IPv6 with a port:  [2001:db8::1]:443  → host "2001:db8::1", port 443
	//   - bracketed IPv6, no port:     [2001:db8::1]      → host "2001:db8::1"
	//   - host/IPv4 with a port:       1.2.3.4:443 / a.b:443
	//   - a BARE IPv6 literal:         2001:db8::1        → host, NO port (≥2 colons)
	//   - host only:                   example.com
	// Conservative-emit: a bare IPv6 literal's trailing group is NEVER mistaken for a
	// port (that was a real foot-gun); a port is only split off after a closing bracket
	// or when exactly one colon is present.
	if peer == "" {
		return "", 0
	}
	if peer[0] == '[' {
		// Bracketed: the host is inside [...]; an optional :port follows the ].
		if end := lastIndexByte(peer, ']'); end > 0 {
			h := peer[1:end]
			rest := peer[end+1:]
			if len(rest) > 1 && rest[0] == ':' {
				if p, ok := allDigitsPort(rest[1:]); ok {
					return h, p
				}
			}
			return h, 0
		}
		return peer, 0
	}
	// Unbracketed: a port is only present when there is EXACTLY one colon (so a bare
	// IPv6 literal, which has two or more, is returned host-only).
	if countByte(peer, ':') != 1 {
		return peer, 0
	}
	idx := lastIndexByte(peer, ':')
	if p, ok := allDigitsPort(peer[idx+1:]); ok {
		return peer[:idx], p
	}
	return peer, 0
}

// allDigitsPort parses a non-empty all-digit string as a port (0 < p ≤ 65535).
func allDigitsPort(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	p := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		p = p*10 + int(r-'0')
		if p > 65535 {
			return 0, false
		}
	}
	return p, true
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func countByte(s string, b byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			n++
		}
	}
	return n
}
