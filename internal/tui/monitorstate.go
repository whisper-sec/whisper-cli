// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// monitorState is the live-stream connection state shown in the status bar / monitor.
type monitorState int

const (
	streamIdle  monitorState = iota // not started
	streamConn                      // SSE connected (sse●)
	streamPoll                      // falling back to op:logs poll (poll⤓)
	streamRetry                     // reconnecting after a drop / 503
)

func (s monitorState) String() string {
	switch s {
	case streamConn:
		return "connected"
	case streamPoll:
		return "poll"
	case streamRetry:
		return "reconnecting"
	default:
		return "idle"
	}
}

// feedSource is the data path currently filling the live picture (shown live in the
// MONITOR title so the operator always knows whether they're seeing the live tail, the
// op:logs backfill, or the poll fallback — the hybrid §6.4 made visible).
type feedSource int

const (
	srcNone     feedSource = iota
	srcBackfill            // painting the op:logs history seed
	srcSSE                 // live SSE tail
	srcPoll                // op:logs poll fallback (stream down)
)

func (s feedSource) String() string {
	switch s {
	case srcBackfill:
		return "backfill"
	case srcSSE:
		return "live"
	case srcPoll:
		return "poll"
	default:
		return "—"
	}
}

// glyph returns a leading source glyph (so source is never colour-only).
func (s feedSource) glyph() string {
	switch s {
	case srcBackfill:
		return "⟲"
	case srcSSE:
		return "⮕"
	case srcPoll:
		return "⤓"
	default:
		return "○"
	}
}

// feedRing is a bounded ring buffer of recent live events for the always-on feed and
// the MONITOR chain. Drop-oldest on overflow so memory is bounded (never block, never
// grow) — mirroring the server's own drop-on-full stream discipline.
type feedRing struct {
	buf  []model.Event
	cap  int
	next int
	full bool
}

func newFeedRing(capacity int) *feedRing {
	if capacity < 1 {
		capacity = 1
	}
	return &feedRing{buf: make([]model.Event, capacity), cap: capacity}
}

// push appends an event, evicting the oldest when full.
func (r *feedRing) push(e model.Event) {
	r.buf[r.next] = e
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
}

// len reports the number of stored events.
func (r *feedRing) len() int {
	if r.full {
		return r.cap
	}
	return r.next
}

// recent returns up to n most-recent events, newest first.
func (r *feedRing) recent(n int) []model.Event {
	total := r.len()
	if n > total {
		n = total
	}
	out := make([]model.Event, 0, n)
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + r.cap*2) % r.cap
		out = append(out, r.buf[idx])
	}
	return out
}

// clear empties the ring.
func (r *feedRing) clear() {
	r.next = 0
	r.full = false
}

// joinCache stitches a live conn event's missing qname from the most-recent dns event
// for the same /128 (the dev-guide §6.2 chain join). It is a tiny bounded map keyed by
// addr128 → {qname, when}: FIFO eviction caps the entry count so a long run never grows
// unbounded, and a per-entry TTL means a STALE lookup never stitches onto an unrelated
// later connection (a real correctness hazard — a conn 10 minutes after a dns is not
// "for" that name). Conservative-emit: when in doubt, show no qname rather than a wrong
// one. Time is the event's own µs timestamp (monotone on the stream), not wall-clock, so
// a backfill replay joins by its own ordering too.
type joinEntry struct {
	qname    string
	atMicros int64
}

type joinCache struct {
	last    map[string]joinEntry // addr128 → most-recent dns qname + when
	order   []string             // insertion order for cheap FIFO eviction
	cap     int
	ttlMcrs int64 // entries older than this (vs the query ts) don't stitch
}

// joinTTL is how long a dns qname is eligible to stitch onto a later conn for the same
// /128. 30s comfortably covers a lookup→connect gap while ruling out a stale match.
const joinTTL = 30_000_000 // 30s in microseconds

func newJoinCache(capacity int) *joinCache {
	if capacity < 1 {
		capacity = 1
	}
	return &joinCache{last: make(map[string]joinEntry, capacity), cap: capacity, ttlMcrs: joinTTL}
}

// observeDNS records the qname most-recently looked up by addr128 at time atMicros.
func (j *joinCache) observeDNS(addr128, qname string, atMicros int64) {
	if addr128 == "" || qname == "" {
		return
	}
	if _, seen := j.last[addr128]; !seen {
		j.order = append(j.order, addr128)
		if len(j.order) > j.cap {
			// Evict the oldest addr (FIFO) so the entry count stays bounded.
			old := j.order[0]
			j.order = j.order[1:]
			delete(j.last, old)
		}
	}
	j.last[addr128] = joinEntry{qname: qname, atMicros: atMicros}
}

// qnameAt returns the qname seen for addr128 IF it is within the TTL of the query time
// nowMicros (the conn event's own ts). A stale or missing entry returns "" — never a
// wrong stitch. Pass nowMicros==0 to ignore the TTL (e.g. a unit probe).
func (j *joinCache) qnameAt(addr128 string, nowMicros int64) string {
	e, ok := j.last[addr128]
	if !ok {
		return ""
	}
	if nowMicros > 0 && j.ttlMcrs > 0 {
		age := nowMicros - e.atMicros
		if age < 0 {
			age = -age // a slightly out-of-order pair still counts within the window
		}
		if age > j.ttlMcrs {
			return ""
		}
	}
	return e.qname
}

// len reports the cache size (for tests).
func (j *joinCache) len() int { return len(j.last) }

// policyRow is a single op:policy key/value entry (default / a block / an allow).
type policyRow struct {
	Key   string
	Value string
}
