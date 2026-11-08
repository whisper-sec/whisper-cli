// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package model

import (
	"encoding/json"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

const (
	t0     int64 = 1_762_500_000_000_000 // a tunnel's open instant, epoch µs
	minute int64 = 60 * 1_000_000
)

// longTunnel is one 12-minute tunnel as the stream sends it: two interim ticks, the
// tail interim row written at close, then the closed row (totals, marked).
func longTunnel(addr string, open int64, marked bool) []Event {
	row := func(kind string, at, up, down int64, reason string) Event {
		return Event{Kind: kind, TsMicros: at, Addr128: addr, PeerHost: "198.51.100.7", PeerPort: 443,
			BytesUp: up, BytesDown: down, DurUS: at - open, Reason: reason}
	}
	closed := row(KindConn, open+12*minute, 1700, 26000, "closed")
	closed.InterimAccounted = marked
	return []Event{
		row(KindConn, open, 0, 0, "open"),
		row(KindInterim, open+5*minute, 1000, 20000, "interim"),
		row(KindInterim, open+10*minute, 500, 5000, "interim"),
		row(KindInterim, open+12*minute, 200, 1000, "interim"),
		closed,
	}
}

func annotateAll(evs []Event) []Event {
	var t TunnelTally
	for i := range evs {
		t.Annotate(&evs[i])
	}
	return evs
}

func sumCounted(evs []Event) int64 {
	var n int64
	for _, e := range evs {
		if e.CountsBytes() {
			n += e.BytesUp + e.BytesDown
		}
	}
	return n
}

func TestTallyRunningTotalsFromTheStream(t *testing.T) {
	evs := annotateAll(longTunnel("2a04:2a01::1", t0, true))
	wants := [][2]int64{{1000, 20000}, {1500, 25000}, {1700, 26000}}
	for i, w := range wants {
		e := evs[i+1]
		if e.RunUp != w[0] || e.RunDown != w[1] || e.RunPartial {
			t.Errorf("interim %d: total %d/%d partial=%v, want %d/%d exact", i, e.RunUp, e.RunDown, e.RunPartial, w[0], w[1])
		}
	}
	if !evs[4].InterimAccounted {
		t.Fatal("the marked closed row keeps its marker")
	}
	if got := sumCounted(evs); got != 1700+26000 {
		t.Fatalf("the tunnel is counted once: got %d", got)
	}
}

func TestTallyInfersTheMarkerOnAnOpLogsBatch(t *testing.T) {
	// op:logs never sends the marker, rows come newest first, ts and duration in ms,
	// and the tail interim row shares the closed row's millisecond.
	var recs []map[string]any
	for _, e := range longTunnel("2a04:2a01::1", t0, false) {
		recs = append([]map[string]any{{
			"ts": e.TsMicros / 1000, "kind": e.Kind, "addr128": e.Addr128, "peer": "198.51.100.7:443",
			"bytes_up": e.BytesUp, "bytes_down": e.BytesDown, "duration_ms": e.DurUS / 1000, "reason": e.Reason,
		}}, recs...)
	}
	// put the closed row AFTER the tail interim row in newest-first order: the wrong way
	// round for a replay, which SettleLogBatch must fix
	recs[0], recs[1] = recs[1], recs[0]
	evs := make([]Event, len(recs))
	for i, r := range recs {
		evs[i] = FromLogRecord(r)
	}
	SettleLogBatch(evs)
	if evs[0].Kind != KindConn || evs[1].Kind != KindInterim {
		t.Fatalf("at one instant the interim row sorts after the conn row: %s, %s", evs[0].Kind, evs[1].Kind)
	}
	if !evs[0].InterimAccounted {
		t.Fatal("a 12-minute closed row whose interim rows are in the batch is inferred accounted")
	}
	if evs[1].RunUp != 1700 || evs[1].RunDown != 26000 {
		t.Fatalf("the tail row carries the whole total: %d/%d", evs[1].RunUp, evs[1].RunDown)
	}
	if got := sumCounted(evs); got != 1700+26000 {
		t.Fatalf("no double count over the batch: got %d", got)
	}
}

func TestTallyLeavesAnOldServerUntouched(t *testing.T) {
	// No interim rows: every row passes through, the closed row counts its bytes.
	in := []Event{
		{Kind: KindConn, TsMicros: t0, Addr128: "a", PeerHost: "p", PeerPort: 1, Reason: "open"},
		{Kind: KindConn, TsMicros: t0 + 30*minute, Addr128: "a", PeerHost: "p", PeerPort: 1, Reason: "closed",
			BytesUp: 9, BytesDown: 90, DurUS: 30 * minute},
		{Kind: "dns", TsMicros: t0 + minute, Addr128: "a", QName: "x."},
	}
	want := append([]Event(nil), in...)
	got := append([]Event(nil), in...)
	AnnotateLogBatch(got)
	annotateAll(got)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d changed: %+v -> %+v", i, want[i], got[i])
		}
	}
	if sumCounted(got) != 99 {
		t.Fatal("an old server's closed row counts its bytes")
	}
}

func TestTallyKeepsTunnelsToOnePeerApart(t *testing.T) {
	a := longTunnel("a", t0, false)
	b := longTunnel("a", t0+minute, false) // same agent and peer, opened a minute later
	short := []Event{
		{Kind: KindConn, TsMicros: t0 + 7*minute, Addr128: "a", PeerHost: "198.51.100.7", PeerPort: 443,
			Reason: "closed", BytesUp: 5, BytesDown: 5, DurUS: 2 * minute},
	}
	// interleave in time order
	evs := []Event{a[0], b[0], a[1], b[1], short[0], a[2], b[2], a[3], a[4], b[3], b[4]}
	annotateAll(evs)
	if evs[8].InterimAccounted != true || evs[10].InterimAccounted != true {
		t.Fatal("both long closed rows are matched to their own interim rows")
	}
	if evs[4].InterimAccounted {
		t.Fatal("a short tunnel to the same peer wrote no interim rows and keeps its bytes")
	}
	if evs[7].RunUp != 1700 || evs[9].RunUp != 1700 {
		t.Fatalf("each tunnel's total is its own: %d, %d", evs[7].RunUp, evs[9].RunUp)
	}
	if got := sumCounted(evs); got != 2*(1700+26000)+10 {
		t.Fatalf("each tunnel counted once: got %d", got)
	}
}

func TestTallyFlagsAViewThatJoinedMidTunnel(t *testing.T) {
	e := Event{Kind: KindInterim, TsMicros: t0 + 25*minute, Addr128: "a", PeerHost: "p", PeerPort: 1,
		BytesUp: 1, BytesDown: 2, DurUS: 25 * minute}
	var tl TunnelTally
	tl.Annotate(&e)
	if !e.RunPartial || e.RunUp != 1 || e.RunDown != 2 {
		t.Fatalf("a first-seen 25-minute-old row is a lower bound: %+v", e)
	}
	first := Event{Kind: KindInterim, TsMicros: t0 + 5*minute + 20_000_000, Addr128: "b", PeerHost: "p", PeerPort: 1,
		BytesUp: 1, DurUS: 5*minute + 20_000_000}
	tl.Annotate(&first)
	if first.RunPartial {
		t.Fatal("a first tick inside the jitter is the tunnel's first row")
	}
	// No peer to follow it by: its own delta, as a lower bound.
	lone := Event{Kind: KindInterim, BytesUp: 3, DurUS: 6 * minute}
	tl.Annotate(&lone)
	if up, _, partial := lone.RunningTotal(); up != 3 || !partial {
		t.Fatalf("an untracked row reports its delta as a lower bound: %+v", lone)
	}
	if up, _, partial := (Event{Kind: KindInterim, BytesUp: 4}).RunningTotal(); up != 4 || !partial {
		t.Fatal("RunningTotal falls back to the row's own delta")
	}
}

func TestTallyCountsARowSeenTwiceOnce(t *testing.T) {
	// The live stream delivers a row in µs, then the backfill delivers it again in ms.
	live := Event{Kind: KindInterim, TsMicros: t0 + 5*minute + 123, Addr128: "a", PeerHost: "p", PeerPort: 1,
		BytesUp: 10, DurUS: 5 * minute}
	again := live
	again.TsMicros = (live.TsMicros / 1000) * 1000
	again.DurUS = (live.DurUS / 1000) * 1000
	var tl TunnelTally
	tl.Annotate(&live)
	tl.Annotate(&again)
	if again.RunUp != 10 {
		t.Fatalf("a repeated row is not summed twice: %d", again.RunUp)
	}
}

func TestTallyStaysBounded(t *testing.T) {
	var tl TunnelTally
	for i := 0; i < tallyMaxRuns+10; i++ {
		e := Event{Kind: KindInterim, TsMicros: t0 + int64(i)*tallyMatchUS*4, Addr128: "a", PeerHost: "p", PeerPort: i,
			BytesUp: 1, DurUS: 5 * minute}
		tl.Annotate(&e)
	}
	if tl.count > tallyMaxRuns {
		t.Fatalf("the tally never grows past its cap: %d", tl.count)
	}
	tl.Reset()
	if tl.count != 0 || tl.runs != nil {
		t.Fatal("Reset forgets every tunnel")
	}
	// A swept run that went stale is dropped to make room.
	tl.add(tunnelKey{who: "x"}, &tunnelRun{lastUS: 0}, 0)
	tl.count = tallyMaxRuns
	tl.add(tunnelKey{who: "y"}, &tunnelRun{lastUS: 10 * tallyStaleUS}, 10*tallyStaleUS)
	if _, ok := tl.runs[tunnelKey{who: "x"}]; ok {
		t.Fatal("a stale run is swept when the tally is full")
	}
}

func TestCountsBytesByKind(t *testing.T) {
	cases := []struct {
		e    Event
		want bool
	}{
		{Event{Kind: KindConn}, true},
		{Event{Kind: KindConn, Reason: "closed"}, true},
		{Event{Kind: KindConn, InterimAccounted: true}, false},
		{Event{Kind: KindConn, Reason: "closed", InterimAccounted: true}, false},
		{Event{Kind: KindConn, Reason: "budget-breach:budget-bytes-up"}, false},
		{Event{Kind: KindConn, Reason: "denied"}, false},
		{Event{Kind: KindInterim}, true},
		{Event{Kind: "dns"}, false},
		{Event{Kind: "alloc"}, false},
	}
	for _, c := range cases {
		if got := c.e.CountsBytes(); got != c.want {
			t.Errorf("%+v: CountsBytes=%v want %v", c.e, got, c.want)
		}
	}
}

// A tunnel cut by its byte budget mid-stream writes interim rows, then a budget-breach
// row and a closed row that both carry the tunnel's totals. Whether the closed row is
// marked by the stream or the tally infers the mark from the interim rows, the bytes
// are summed once: the interim deltas, and neither the breach row nor the closed row.
func TestABreachRowNextToAnInterimAccountedCloseCountsOnce(t *testing.T) {
	for _, marked := range []bool{true, false} {
		evs := longTunnel("2a04:2a01::1", t0, marked)
		closed := evs[len(evs)-1]
		breach := closed
		breach.Reason = "budget-breach:budget-bytes-up"
		breach.InterimAccounted = false
		evs = append(evs[:len(evs)-1], breach, closed)
		evs = annotateAll(evs)
		if !evs[len(evs)-1].InterimAccounted {
			t.Fatalf("marked=%v: the closed row is interim-accounted", marked)
		}
		if got, want := sumCounted(evs), int64(1700+26000); got != want {
			t.Errorf("marked=%v: summed %d bytes, want %d (each byte once)", marked, got, want)
		}
	}
}

func TestTheMarkerSurvivesBothSources(t *testing.T) {
	m, ok := client.ParseEvent("conn", []byte(`{"kind":"conn","reason":"closed","bytes_up":5,"interim_accounted":true}`))
	if !ok || !FromStream(m).InterimAccounted {
		t.Fatal("the stream's interim_accounted reaches the Event")
	}
	m, _ = client.ParseEvent("conn", []byte(`{"kind":"conn","reason":"closed","bytes_up":5}`))
	if FromStream(m).InterimAccounted {
		t.Fatal("an old server's closed row is not accounted")
	}
	for _, v := range []any{true, "true", "TRUE", "1", json.Number("1"), float64(1)} {
		if !FromLogRecord(map[string]any{"interim_accounted": v}).InterimAccounted {
			t.Errorf("a log row's interim_accounted %#v is read liberally", v)
		}
	}
	for _, v := range []any{nil, false, "false", "", float64(0), "yes please"} {
		if FromLogRecord(map[string]any{"interim_accounted": v}).InterimAccounted {
			t.Errorf("%#v is not a set marker", v)
		}
	}
}
