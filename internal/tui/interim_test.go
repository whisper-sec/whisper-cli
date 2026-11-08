// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

const tunnelAddr = "2a04:2a01::7"

// tunnelRows is one 12-minute tunnel that closed 10 s ago, as the stream sends it:
// the open row, interim ticks at +5m and +10m, the tail interim row at close, then the
// closed row carrying the totals (marked when the server marks it).
func tunnelRows(marked bool) []model.Event {
	minute := int64(time.Minute / time.Microsecond)
	closeAt := time.Now().UnixMicro() - 10_000_000
	open := closeAt - 12*minute
	row := func(kind string, at, up, down int64, reason string) model.Event {
		return model.Event{Kind: kind, TsMicros: at, Addr128: tunnelAddr, Proto: "socks5",
			PeerHost: "198.51.100.7", PeerPort: 443, ClientSrc: "203.0.113.0/24",
			BytesUp: up, BytesDown: down, DurUS: at - open, Reason: reason}
	}
	closed := row("conn", closeAt, 1700, 26000, "closed")
	closed.InterimAccounted = marked
	return []model.Event{
		row("conn", open, 0, 0, "open"),
		row(model.KindInterim, open+5*minute, 1000, 20000, "interim"),
		row(model.KindInterim, open+10*minute, 500, 5000, "interim"),
		row(model.KindInterim, closeAt, 200, 1000, "interim"),
		closed,
	}
}

// asLogRecords renders rows the way op:logs returns them: newest first, ms units, one
// peer column, and never the marker.
func asLogRecords(evs []model.Event) []map[string]any {
	out := make([]map[string]any, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		out = append(out, map[string]any{
			"ts": float64(e.TsMicros / 1000), "kind": e.Kind, "addr128": e.Addr128,
			"peer": "198.51.100.7:443", "client_src": e.ClientSrc, "reason": e.Reason,
			"bytes_up": float64(e.BytesUp), "bytes_down": float64(e.BytesDown),
			"duration_ms": float64(e.DurUS / 1000),
		})
	}
	return out
}

func ringTotals(a *App, key string) (bytes, conns float64) {
	r := a.monitorVw.rings[key]
	if r == nil {
		return 0, 0
	}
	for i := 0; i < kbpsWindow; i++ {
		bytes += r.bytes[i]
		conns += r.conns[i]
	}
	return bytes, conns
}

// The rate ring holds the last 240 s: the +10m tick (2 min before close) and the tail
// are inside it, the rest is older. So the charted bytes are those two deltas, and the
// closed row adds no bytes again.
const inWindowBytes = 500 + 5000 + 200 + 1000

func TestInterimRowsFeedTheRingOnceFromTheStream(t *testing.T) {
	a := newTestApp(t, 120, 40)
	for _, e := range tunnelRows(true) {
		a.onStreamEvent(e)
	}
	bytes, conns := ringTotals(a, tunnelAddr)
	if bytes != inWindowBytes {
		t.Fatalf("charted bytes = %v, want %v (interim deltas only; the marked closed row adds none)", bytes, inWindowBytes)
	}
	if conns != 1 {
		t.Fatalf("conn opens in the window = %v, want 1 (the closed row; interim rows are not connections)", conns)
	}
	if a.liveConn != 2 {
		t.Fatalf("the session conn counter counts conn rows only: %d", a.liveConn)
	}
}

func TestInterimRowsFeedTheRingOnceFromABackfill(t *testing.T) {
	// op:logs carries no marker: the tunnel's interim rows prove the closed row's bytes
	// were accounted, so the backfill charts the same as the stream.
	a := newTestApp(t, 120, 40)
	a.onMonitorBackfill(monitorBackfillMsg{events: logEvents(asLogRecords(tunnelRows(false))), token: a.backfillToken})
	if bytes, _ := ringTotals(a, tunnelAddr); bytes != inWindowBytes {
		t.Fatalf("backfill charted %v bytes, want %v: no double count", bytes, inWindowBytes)
	}
}

func TestAnOldServerChartsExactlyAsBefore(t *testing.T) {
	// No interim rows, no marker: the closed row's bytes chart, as they always did.
	a := newTestApp(t, 120, 40)
	rows := tunnelRows(false)
	a.onStreamEvent(rows[0])
	a.onStreamEvent(rows[4])
	bytes, conns := ringTotals(a, tunnelAddr)
	if bytes != 1700+26000 || conns != 1 {
		t.Fatalf("old server: bytes %v conns %v, want %v and 1", bytes, conns, 1700+26000)
	}
	line := strip(a.renderChainRow(rows[4], 110, 27700, false))
	if !strings.Contains(line, "198.51.100.7:443") || !strings.Contains(line, "·closed") || strings.Contains(line, "open ") {
		t.Fatalf("a closed row renders as before: %q", line)
	}
}

func TestInterimChainRowReadsAsProgress(t *testing.T) {
	a := newTestApp(t, 120, 40)
	for _, e := range tunnelRows(true) {
		a.onStreamEvent(e)
	}
	recent := a.feed.recent(10)
	var tail model.Event
	for _, e := range recent {
		if e.Kind == model.KindInterim && e.BytesUp == 200 {
			tail = e
		}
	}
	wide := strip(a.renderChainRow(tail, 110, 1200, false))
	narrow := strip(a.renderChainRow(tail, 58, 21000, false)) // below 60 the heat bar folds away
	t.Logf("wide:   %s", wide)
	t.Logf("narrow: %s", narrow)
	for _, want := range []string{"conn", "198.51.100.7:443", "open 12m Σ27.7K", "──▶", "▕▰"} {
		if !strings.Contains(wide, want) {
			t.Errorf("wide interim row lacks %q: %q", want, wide)
		}
	}
	if strings.Contains(wide, "──╳") || strings.Contains(wide, "·interim") {
		t.Errorf("progress is neither a block nor a close reason: %q", wide)
	}
	if !strings.Contains(narrow, "open 12m Σ27.7K") || !strings.Contains(narrow, "conn") {
		t.Errorf("a narrow row keeps the progress text: %q", narrow)
	}
	// Mid-tunnel join: the total is a lower bound.
	mid := tail
	mid.RunPartial = true
	if s := strip(a.renderChainRow(mid, 110, 0, false)); !strings.Contains(s, "open 12m Σ≥27.7K") {
		t.Errorf("a partial total is marked ≥: %q", s)
	}
}

func TestConnFilterShowsInterimProgress(t *testing.T) {
	a := newTestApp(t, 120, 40)
	for _, e := range tunnelRows(true) {
		a.onStreamEvent(e)
	}
	a.monitorVw.kindF = "conn"
	n := 0
	for _, e := range a.monitorVw.filteredRecent(10) {
		if e.Kind == model.KindInterim {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("filter:conn keeps the tunnel's interim rows: %d", n)
	}
	a.monitorVw.kindF = "dns"
	if len(a.monitorVw.filteredRecent(10)) != 0 {
		t.Fatal("filter:dns hides them")
	}
}

func TestFocusStartsTheTunnelSumsOver(t *testing.T) {
	a := newTestApp(t, 120, 40)
	rows := tunnelRows(true)
	a.onStreamEvent(rows[1])
	a.monitorVw.focus(model.Agent{Address: tunnelAddr})
	e := rows[1]
	a.tunnels.Annotate(&e)
	if e.RunUp != 1000 {
		t.Fatalf("after a focus re-seed the tally starts over: %d", e.RunUp)
	}
}

func TestLogsTableRendersInterimRows(t *testing.T) {
	a := newTestApp(t, 160, 40)
	v := a.logsView
	v.resize(160, 40)
	v.onLogs(logsMsg{events: logEvents(asLogRecords(tunnelRows(false))), token: v.token})
	rows := v.tbl.Rows()
	if len(rows) != 5 {
		t.Fatalf("five rows, got %d", len(rows))
	}
	for _, r := range rows {
		t.Logf("%s", strings.Join(r, " | "))
	}
	// newest first: closed, tail interim, interim, interim, open
	if rows[0][1] != "conn" || rows[0][5] != "closed" || rows[0][6] != "↑1.7K ↓26.0K" {
		t.Fatalf("the closed row reads as before: %v", rows[0])
	}
	if rows[1][1] != "interim" || rows[1][5] != "open 12m, total ↑1.7K ↓26.0K" || rows[1][6] != "+↑200 ↓1.0K" {
		t.Fatalf("the tail interim row reads as progress: %v", rows[1])
	}
	if rows[3][5] != "open 5m, total ↑1.0K ↓20.0K" {
		t.Fatalf("the first tick's total is its delta: %v", rows[3])
	}
}

func TestLiveGraphCountsATunnelOnce(t *testing.T) {
	a := newTestApp(t, 120, 40)
	for _, e := range tunnelRows(true) {
		a.onStreamEvent(e)
	}
	ag := a.lgraph.agents[tunnelAddr]
	if ag == nil {
		t.Fatal("the agent is on the live graph")
	}
	d := ag.dests["198.51.100.7"]
	if d == nil || d.Hits != 2 {
		t.Fatalf("the open and closed rows are the hits; interim rows only keep it fresh: %+v", d)
	}
}
