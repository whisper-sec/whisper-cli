// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import "sort"

// Activity kinds the views reason about by name.
const (
	KindConn    = "conn"
	KindInterim = "interim"
)

// InterimIntervalUS is the server's interim cadence: an open egress tunnel writes one
// interim row every five minutes, and a tunnel open at least this long has its closed
// row's bytes already accounted in interim rows.
const InterimIntervalUS int64 = 5 * 60 * 1_000_000

const (
	// tallyMatchUS is how far two rows of one tunnel may disagree on its open instant
	// (row time minus tunnel age): clock noise and the ms rounding of op:logs, no more.
	tallyMatchUS int64 = 2_000_000
	// tallyFirstRowUS is the oldest a tunnel's FIRST interim row can be (the first tick
	// is jittered by up to a tenth of the interval). A first-seen row older than this
	// means the view joined mid-tunnel and its running total is a lower bound.
	tallyFirstRowUS = InterimIntervalUS + InterimIntervalUS/10 + 30_000_000
	// tallyStaleUS drops a run that has written nothing for three intervals: its closed
	// row went by unseen (outside the window, or a narrowed stream).
	tallyStaleUS = 3 * InterimIntervalUS
	// tallyMaxRuns bounds the memory of open tunnels the view tracks.
	tallyMaxRuns = 4096
)

type tunnelKey struct {
	who  string // the /128, or the agent id when no address rode the row
	host string
	port int
}

type tunnelRun struct {
	openUS, lastUS int64
	up, down       int64
	partial        bool
	seenMS         []int64 // the interim rows already summed, by ms timestamp (dedup)
}

// TunnelTally follows open egress tunnels through their interim rows. Annotate stamps
// an interim row with its tunnel's running totals, and marks a long tunnel's closed row
// InterimAccounted when the view has seen that tunnel's interim rows, so no running sum
// counts the tunnel twice. A tunnel is identified by agent, peer and its open instant
// (row time minus duration), so two tunnels to one peer stay apart.
//
// An old server writes no interim rows: nothing is ever tracked, and every row passes
// through untouched. The zero value is ready to use.
type TunnelTally struct {
	runs  map[tunnelKey][]*tunnelRun
	count int
}

// Reset forgets every tracked tunnel (a re-seeded view starts its sums over).
func (t *TunnelTally) Reset() {
	t.runs = nil
	t.count = 0
}

// Annotate updates the tally with one row, in time order, and stamps the row.
func (t *TunnelTally) Annotate(e *Event) {
	switch e.Kind {
	case KindInterim:
		k, ok := tunnelKeyOf(e)
		if !ok {
			// No peer to follow it by: the row's own delta is all that is known.
			e.RunUp, e.RunDown, e.RunPartial = e.BytesUp, e.BytesDown, true
			return
		}
		openUS := e.TsMicros - e.DurUS
		r := t.find(k, openUS)
		if r == nil {
			r = &tunnelRun{openUS: openUS, partial: e.DurUS > tallyFirstRowUS}
			t.add(k, r, e.TsMicros)
		}
		ms := e.TsMicros / 1000
		if !containsInt64(r.seenMS, ms) {
			r.seenMS = append(r.seenMS, ms)
			r.up += e.BytesUp
			r.down += e.BytesDown
		}
		if e.TsMicros > r.lastUS {
			r.lastUS = e.TsMicros
		}
		e.RunUp, e.RunDown, e.RunPartial = r.up, r.down, r.partial
	case KindConn:
		if e.Reason != "closed" {
			return
		}
		k, ok := tunnelKeyOf(e)
		if !ok {
			return
		}
		if t.take(k, e.TsMicros-e.DurUS) && e.DurUS >= InterimIntervalUS {
			// op:logs never carries the marker; the tunnel's own interim rows prove it.
			e.InterimAccounted = true
		}
	}
}

// CountsBytes reports whether a row's bytes belong in a running sum: a conn row's
// bytes, unless its interim rows already carried them, and an interim row's delta.
func (e Event) CountsBytes() bool {
	switch e.Kind {
	case KindConn:
		return !e.InterimAccounted
	case KindInterim:
		return true
	}
	return false
}

// RunningTotal is an interim row's tunnel total so far. A row the tally never saw has
// only its own delta to offer, reported as a lower bound.
func (e Event) RunningTotal() (up, down int64, partial bool) {
	if e.RunUp == 0 && e.RunDown == 0 {
		return e.BytesUp, e.BytesDown, true
	}
	return e.RunUp, e.RunDown, e.RunPartial
}

// SettleLogBatch prepares an op:logs batch (newest first) for a view that replays it
// from the end, then stamps it as AnnotateLogBatch does. The server writes a tunnel's
// last interim row before its closed row, often in the same millisecond, so among rows
// of one instant the interim rows move to the end, where a replay meets them first.
// No other row moves.
func SettleLogBatch(evs []Event) {
	for i := 0; i < len(evs); {
		j := i + 1
		for j < len(evs) && evs[j].TsMicros == evs[i].TsMicros {
			j++
		}
		if j-i > 1 {
			run := evs[i:j]
			sort.SliceStable(run, func(a, b int) bool {
				return run[a].Kind != KindInterim && run[b].Kind == KindInterim
			})
		}
		i = j
	}
	AnnotateLogBatch(evs)
}

// AnnotateLogBatch stamps an op:logs batch in place with a fresh tally, walking it in
// time order (interim before conn at one instant) without moving any row: a table
// keeps the server's order. The batch may come newest first (op:logs) or oldest first.
func AnnotateLogBatch(evs []Event) {
	n := len(evs)
	idx := make([]int, n)
	newestFirst := n > 1 && evs[0].TsMicros > evs[n-1].TsMicros
	for i := range idx {
		if newestFirst {
			idx[i] = n - 1 - i
		} else {
			idx[i] = i
		}
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := evs[idx[a]], evs[idx[b]]
		if x.TsMicros != y.TsMicros {
			return x.TsMicros < y.TsMicros
		}
		return x.Kind == KindInterim && y.Kind != KindInterim
	})
	var t TunnelTally
	for _, i := range idx {
		t.Annotate(&evs[i])
	}
}

func tunnelKeyOf(e *Event) (tunnelKey, bool) {
	who := e.Addr128
	if who == "" {
		who = e.Agent
	}
	if who == "" || e.PeerHost == "" {
		return tunnelKey{}, false
	}
	return tunnelKey{who: who, host: e.PeerHost, port: e.PeerPort}, true
}

func (t *TunnelTally) find(k tunnelKey, openUS int64) *tunnelRun {
	var best *tunnelRun
	bestD := tallyMatchUS + 1
	for _, r := range t.runs[k] {
		d := r.openUS - openUS
		if d < 0 {
			d = -d
		}
		if d < bestD {
			best, bestD = r, d
		}
	}
	return best
}

// take removes the run a closed row ends, reporting whether there was one.
func (t *TunnelTally) take(k tunnelKey, openUS int64) bool {
	r := t.find(k, openUS)
	if r == nil {
		return false
	}
	runs := t.runs[k]
	for i, x := range runs {
		if x == r {
			runs = append(runs[:i], runs[i+1:]...)
			break
		}
	}
	if len(runs) == 0 {
		delete(t.runs, k)
	} else {
		t.runs[k] = runs
	}
	t.count--
	return true
}

func (t *TunnelTally) add(k tunnelKey, r *tunnelRun, nowUS int64) {
	if t.runs == nil {
		t.runs = map[tunnelKey][]*tunnelRun{}
	}
	if t.count >= tallyMaxRuns {
		t.sweep(nowUS)
		if t.count >= tallyMaxRuns {
			t.Reset() // still full of live tunnels: start over rather than grow
			t.runs = map[tunnelKey][]*tunnelRun{}
		}
	}
	t.runs[k] = append(t.runs[k], r)
	t.count++
}

func (t *TunnelTally) sweep(nowUS int64) {
	for k, runs := range t.runs {
		kept := runs[:0]
		for _, r := range runs {
			if nowUS-r.lastUS < tallyStaleUS {
				kept = append(kept, r)
			} else {
				t.count--
			}
		}
		if len(kept) == 0 {
			delete(t.runs, k)
		} else {
			t.runs[k] = kept
		}
	}
}

func containsInt64(xs []int64, v int64) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
