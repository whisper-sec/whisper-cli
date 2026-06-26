// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
)

// Event kinds on the monitor stream (and in op:logs).
const (
	KindDNS   = "dns"
	KindConn  = "conn"
	KindAlloc = "alloc"
	KindHB    = "hb" // a heartbeat comment; surfaced so the TUI can show "connected" while idle
)

// MonitorEvent is one decoded stream event, normalised so the TUI/scripts never have
// to reason about the µs-vs-ms split: TsMicros is always epoch microseconds, and the
// derived latency/duration are exposed in BOTH units.
//
// Null fields are OMITTED on the wire (compact); an absent field decodes to its zero
// value here. Extra is the verbatim event JSON for the scriptable NDJSON tail.
type MonitorEvent struct {
	Node    string `json:"node,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	Agent   string `json:"agent,omitempty"`
	Addr128 string `json:"addr128,omitempty"`

	// TsMicros is epoch MICROSECONDS — the stream's native unit (preserves ordering).
	TsMicros int64 `json:"ts,omitempty"`

	// --- dns ---
	QName        string `json:"qname,omitempty"`
	QType        string `json:"qtype,omitempty"`
	QClass       string `json:"qclass,omitempty"`
	RCode        string `json:"rcode,omitempty"`
	Decision     string `json:"decision,omitempty"`
	Source       string `json:"source,omitempty"`
	Answer       string `json:"answer,omitempty"`
	LatencyUS    int64  `json:"latency_us,omitempty"`
	ClientSubnet string `json:"client_subnet,omitempty"`
	EDNS         bool   `json:"edns,omitempty"`
	DO           bool   `json:"do,omitempty"`

	// --- conn ---
	Proto       string `json:"proto,omitempty"`
	Direction   string `json:"direction,omitempty"`
	PeerHost    string `json:"peer_host,omitempty"`
	PeerPort    int    `json:"peer_port,omitempty"`
	BytesUp     int64  `json:"bytes_up,omitempty"`
	BytesDown   int64  `json:"bytes_down,omitempty"`
	PacketsUp   int64  `json:"packets_up,omitempty"`
	PacketsDown int64  `json:"packets_down,omitempty"`
	DurationUS  int64  `json:"duration_us,omitempty"`
	Reason      string `json:"reason,omitempty"`
	TokenMasked string `json:"token_masked,omitempty"`
	ClientSrc   string `json:"client_src,omitempty"`

	// --- alloc ---
	Action      string `json:"action,omitempty"`
	AllocatedAt int64  `json:"allocated_at,omitempty"` // epoch MILLISECONDS (per the contract)

	// Extra is the raw event JSON, preserved verbatim for the NDJSON tail.
	Extra json.RawMessage `json:"-"`
}

// TsMillis returns the event timestamp in epoch milliseconds (µs/1000).
func (e MonitorEvent) TsMillis() int64 { return e.TsMicros / 1000 }

// LatencyMillis returns the dns latency in milliseconds (rounded from µs).
func (e MonitorEvent) LatencyMillis() int64 { return roundUSToMS(e.LatencyUS) }

// DurationMillis returns the conn duration in milliseconds (rounded from µs).
func (e MonitorEvent) DurationMillis() int64 { return roundUSToMS(e.DurationUS) }

// roundUSToMS converts microseconds to milliseconds with round-half-up at the µs/ms
// boundary (e.g. 45000µs -> 45ms, 1500µs -> 2ms, 499µs -> 0ms).
func roundUSToMS(us int64) int64 {
	if us == 0 {
		return 0
	}
	if us < 0 {
		return -((-us + 500) / 1000)
	}
	return (us + 500) / 1000
}

// ParseEvent decodes one SSE `data:` JSON object into a MonitorEvent, preserving the
// raw bytes in Extra. A heartbeat (eventName "hb") with no/empty data yields a
// Kind==KindHB event. Returns ok=false for an empty/blank payload.
func ParseEvent(eventName string, data []byte) (MonitorEvent, bool) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		if eventName == KindHB {
			return MonitorEvent{Kind: KindHB}, true
		}
		return MonitorEvent{}, false
	}
	var ev MonitorEvent
	if err := json.Unmarshal([]byte(trimmed), &ev); err != nil {
		// Malformed event: don't crash the stream — drop it (liberal-in: tolerate noise).
		return MonitorEvent{}, false
	}
	ev.Extra = append(json.RawMessage(nil), []byte(trimmed)...)
	// The event: line names the kind; trust it when the JSON omitted `kind` (it never
	// does today, but be liberal — the `event:` framing is authoritative either way).
	if ev.Kind == "" && eventName != "" && eventName != "message" {
		ev.Kind = eventName
	}
	return ev, true
}

// ReadSSE reads an SSE byte stream to completion, emitting each decoded MonitorEvent
// on emit(). It parses the line-based SSE framing (`event:` + `data:`, blank line ends
// an event; a `:`-prefixed comment is a heartbeat) and is LIBERAL: a malformed data
// line is skipped, a heartbeat surfaces as a KindHB event, multi-line `data:` is
// concatenated per the SSE spec.
//
// It returns when r hits EOF, ctx is cancelled, or a read error occurs. The caller
// owns r's lifecycle (typically an *http.Response.Body closed on ctx-cancel).
func ReadSSE(ctx context.Context, r io.Reader, emit func(MonitorEvent)) error {
	sc := bufio.NewScanner(r)
	// Allow long event lines (an answer summary or a fat conn row); 1 MiB is ample.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var eventName string
	var dataLines []string

	flush := func() {
		defer func() { eventName = ""; dataLines = dataLines[:0] }()
		if len(dataLines) == 0 {
			// A lone `event: hb` with no data is a heartbeat — surface it.
			if eventName == KindHB {
				emit(MonitorEvent{Kind: KindHB})
			}
			return
		}
		joined := strings.Join(dataLines, "\n")
		if ev, ok := ParseEvent(eventName, []byte(joined)); ok {
			emit(ev)
		}
	}

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := sc.Text()
		switch {
		case line == "":
			flush() // blank line terminates the current event
		case strings.HasPrefix(line, ":"):
			// An SSE comment. The server sends `: hb` / `:heartbeat` keep-alives; treat
			// any comment as a heartbeat tick so the TUI shows "connected" while idle.
			emit(MonitorEvent{Kind: KindHB})
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			// SSE: a single leading space after the colon is stripped; the rest is data.
			d := strings.TrimPrefix(line, "data:")
			d = strings.TrimPrefix(d, " ")
			dataLines = append(dataLines, d)
		default:
			// id:/retry:/unknown fields — ignore (liberal-in).
		}
	}
	// A trailing event with no terminating blank line still counts (the stream closed).
	flush()
	if err := sc.Err(); err != nil {
		// A cancelled context surfaces here as a read error on the closed body; prefer
		// the ctx error so callers can distinguish a clean quit from a real fault.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return ctx.Err()
}
