// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// --- monitorState / feedSource -----------------------------------------------------

// TestStateAndSourceWords pins every status word + glyph the operator reads.
func TestStateAndSourceWords(t *testing.T) {
	states := map[monitorState]string{
		streamIdle: "idle", streamConn: "connected", streamPoll: "poll", streamRetry: "reconnecting",
	}
	for s, want := range states {
		if s.String() != want {
			t.Errorf("state %d reads %q, want %q", s, s.String(), want)
		}
	}
	sources := map[feedSource][2]string{
		srcNone: {"-", "○"}, srcBackfill: {"backfill", "⟲"}, srcSSE: {"live", "⮕"}, srcPoll: {"poll", "⤓"},
	}
	for s, want := range sources {
		if s.String() != want[0] || s.glyph() != want[1] {
			t.Errorf("source %d reads %q/%q, want %q/%q", s, s.String(), s.glyph(), want[0], want[1])
		}
	}
}

// TestFeedRingBounds drives the ring through wrap-around: bounded memory, drop-oldest,
// newest-first reads, and the clamped constructor.
func TestFeedRingBounds(t *testing.T) {
	r := newFeedRing(0) // liberal floor: capacity clamps to 1
	r.push(model.Event{TsMicros: 1})
	r.push(model.Event{TsMicros: 2})
	if r.len() != 1 || r.recent(5)[0].TsMicros != 2 {
		t.Fatalf("cap-1 ring keeps only the newest; len=%d", r.len())
	}

	r3 := newFeedRing(3)
	for i := 1; i <= 5; i++ {
		r3.push(model.Event{TsMicros: int64(i)})
	}
	if r3.len() != 3 {
		t.Fatalf("overflow must drop-oldest, len=%d", r3.len())
	}
	got := r3.recent(3)
	if got[0].TsMicros != 5 || got[1].TsMicros != 4 || got[2].TsMicros != 3 {
		t.Errorf("recent must read newest-first: %v", got)
	}
	if len(r3.recent(99)) != 3 {
		t.Error("recent clamps to what is stored")
	}
	r3.clear()
	if r3.len() != 0 || len(r3.recent(2)) != 0 {
		t.Error("clear must empty the ring")
	}
}

// TestStreamSendDropDiscipline pins the never-block contract: send delivers when there
// is room, silently drops on a full channel, and drops after cancel.
func TestStreamSendDropDiscipline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan tea.Msg, 1)
	send(ch, ctx, streamStateMsg{state: streamConn})
	if len(ch) != 1 {
		t.Fatal("send must deliver into a free slot")
	}
	send(ch, ctx, streamStateMsg{state: streamRetry}) // full: must NOT block
	if len(ch) != 1 {
		t.Fatal("a full channel drops, never blocks")
	}
	cancel()
	<-ch
	send(ch, ctx, streamStateMsg{state: streamPoll})
	// After cancel the send MAY drop even with room; what matters is it returns and
	// never panics. Drain whatever landed.
	for len(ch) > 0 {
		<-ch
	}
}

// TestWaitStreamNilAndRestartNoop covers the nil-channel guard and the same-addr
// restart no-op (no connection churn on a redundant focus).
func TestWaitStreamNilAndRestartNoop(t *testing.T) {
	a := newTestApp(t, 100, 30)
	if a.waitStream() != nil {
		t.Error("no channel: nothing to wait on")
	}
	a.streamAddr = "2a04:2a01::1"
	if a.restartStreamNarrowed("2a04:2a01::1") != nil {
		t.Error("an unchanged narrow must not churn the stream")
	}
	if a.restartStreamNarrowed("") == nil {
		t.Error("a real narrow change re-arms")
	}
	if a.streamAddr != "" || a.source != srcNone {
		t.Error("the restart resets the narrow + source")
	}
}

// --- the live fold (livestrip) ------------------------------------------------------

// TestHeartbeatFoldRevivesStream pins the hb semantics: a heartbeat marks the stream
// alive (idle/retry -> conn), upgrades the source, and never lands in the feed.
func TestHeartbeatFoldRevivesStream(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamRetry
	a.source = srcPoll
	a.onStreamEvent(model.Event{Kind: "hb"})
	if a.stream != streamConn || a.source != srcSSE || !a.hbSeen {
		t.Errorf("hb must revive the stream: stream=%v source=%v", a.stream, a.source)
	}
	if a.feed.len() != 0 {
		t.Error("a heartbeat is not activity; the feed stays empty")
	}
	// A poll-state fold of a REAL event flips the live badge back on.
	a.stream = streamPoll
	a.onStreamEvent(model.Event{Kind: "dns", TsMicros: 1, QName: "x."})
	if a.stream != streamConn || a.source != srcSSE || a.feed.len() != 1 {
		t.Error("a real event proves the tail is live")
	}
}

// TestLiveSessionCounters pins the live-only counter discipline: the live tail counts
// dns/blocked/conn; a backfill replay never double-counts.
func TestLiveSessionCounters(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 1, QName: "a.", Decision: "allow"}, true)
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 2, QName: "b.", Decision: "block"}, true)
	a.foldEvent(model.Event{Kind: "conn", TsMicros: 3, PeerHost: "1.1.1.1"}, true)
	if a.liveDNS != 2 || a.liveBlocked != 1 || a.liveConn != 1 {
		t.Fatalf("live counters wrong: dns=%d blocked=%d conn=%d", a.liveDNS, a.liveBlocked, a.liveConn)
	}
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 4, QName: "c.", Decision: "block"}, false)
	if a.liveDNS != 2 || a.liveBlocked != 1 {
		t.Error("a backfill fold must never bump the live session counters")
	}
	if a.feed.len() != 4 {
		t.Error("the backfill row still lands in the feed")
	}
	if a.lastEventUS != 4 {
		t.Errorf("the dedup watermark tracks every fold; got %d", a.lastEventUS)
	}
}

// TestBackfillErrorFailsOpen pins the error arm: the picture keeps its source and the
// feed is untouched.
func TestBackfillErrorFailsOpen(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.backfillToken = 2
	a.onMonitorBackfill(monitorBackfillMsg{token: 2, err: context.DeadlineExceeded})
	if a.feed.len() != 0 {
		t.Error("an errored backfill folds nothing")
	}
	if a.source != srcSSE {
		t.Errorf("a cold errored backfill hands the picture to the live tail; got %v", a.source)
	}
	// After the seed lands while connected, the source reads live again.
	a.stream = streamConn
	a.onMonitorBackfill(monitorBackfillMsg{token: 2, events: []model.Event{
		{Kind: "dns", TsMicros: 10, QName: "seed."},
	}})
	if a.source != srcSSE || a.feed.len() != 1 {
		t.Error("a connected stream resumes the live badge after the seed")
	}
}

// TestLiveTitleStates pins the honest header wording per state, including the
// never-connected poll distinction and the paused/buffered marker.
func TestLiveTitleStates(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamPoll
	a.hbSeen = false
	if got := strip(a.liveTitle()); !strings.Contains(got, "stream offline · polling") {
		t.Errorf("a never-answered stream must not read as a blip: %q", got)
	}
	a.hbSeen = true
	if got := strip(a.liveTitle()); !strings.Contains(got, "poll fallback") {
		t.Errorf("a dropped stream reads as the poll fallback: %q", got)
	}
	a.stream = streamRetry
	if got := strip(a.liveTitle()); !strings.Contains(got, "reconnecting") {
		t.Errorf("retry reads reconnecting: %q", got)
	}
	a.stream = streamConn
	a.paused = true
	a.bufferedPause = 3
	got := strip(a.liveTitle())
	if !strings.Contains(got, "connected") || !strings.Contains(got, "⏸ PAUSED · 3 buffered") {
		t.Errorf("the paused marker carries the buffered count: %q", got)
	}
	// The heartbeat dot is a dim ring whenever not connected.
	a.stream = streamIdle
	if got := strip(a.heartbeatDot(a.th.OK)); got != "○" {
		t.Errorf("a dead stream shows the static ring: %q", got)
	}
}

// TestRenderFeedLinesEmptyAndPad covers the placeholder hint and the height padding.
func TestRenderFeedLinesEmptyAndPad(t *testing.T) {
	a := newTestApp(t, 100, 30)
	lines := a.renderFeedLines(nil, 60, 4)
	if len(lines) != 1 || !strings.Contains(strip(lines[0]), "waiting for activity") {
		t.Errorf("an empty feed states itself: %v", lines)
	}
	lines = a.renderFeedLines([]model.Event{{Kind: "dns", TsMicros: 1, QName: "x.", Decision: "allow"}}, 60, 4)
	if len(lines) != 4 {
		t.Errorf("the chain pads to the panel height; got %d", len(lines))
	}
}

// TestIsFlashingWindow pins the flash-in window: only live-stamped rows, only fresh ones.
func TestIsFlashingWindow(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.tickCount = 10
	var backfill model.Event // FlashTick 0: a replay row never flashes
	if a.isFlashing(backfill) {
		t.Error("a backfill row must not flash")
	}
	var fresh model.Event
	fresh.SetFlashTick(10)
	if !a.isFlashing(fresh) {
		t.Error("a just-arrived row flashes")
	}
	a.tickCount = 10 + flashTicks + 1
	if a.isFlashing(fresh) {
		t.Error("the flash decays after the window")
	}
	if !a.isFlashTick(10 + flashTicks) {
		t.Error("isFlashTick agrees at the window edge")
	}
	if a.isFlashTick(0) {
		t.Error("a zero stamp never flashes")
	}
}

// TestToastDecayOnTick pins the ~4s toast lifecycle at the 4Hz tick.
func TestToastDecayOnTick(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.setToast("hello", true)
	if a.toastTicks != 16 || a.lastErr != "hello" {
		t.Fatalf("an error toast arms 16 ticks and records lastErr; got %d", a.toastTicks)
	}
	for i := 0; i < 15; i++ {
		a.onTick()
	}
	if a.toast != "hello" {
		t.Error("the toast holds until its window ends")
	}
	a.onTick()
	if a.toast != "" {
		t.Error("the toast clears exactly at zero")
	}
}

// --- the monitor rings ---------------------------------------------------------------

// TestMonitorAdvanceRollsBuckets asserts the per-second advance opens a fresh zero
// bucket (the sparkline's second boundary).
func TestMonitorAdvanceRollsBuckets(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.monitorVw.observe(model.Event{Kind: "conn", Addr128: "2a04:2a01::1", BytesUp: 100, BytesDown: 200})
	r := a.monitorVw.rings["2a04:2a01::1"]
	if r == nil {
		t.Fatal("observe must mint the ring")
	}
	head := r.head
	if r.bytes[head] != 300 || r.conns[head] != 1 {
		t.Fatalf("the open bucket accumulates: bytes=%v conns=%v", r.bytes[head], r.conns[head])
	}
	a.monitorVw.advance()
	if r.head != (head+1)%kbpsWindow {
		t.Error("advance moves the head")
	}
	if r.bytes[r.head] != 0 || r.conns[r.head] != 0 || r.dnsTotal[r.head] != 0 {
		t.Error("the fresh bucket starts at zero")
	}
}

// TestMonitorKindFilter pins the f-cycle and the filtered feed reads.
func TestMonitorKindFilter(t *testing.T) {
	a := newTestApp(t, 100, 30)
	for i := 0; i < 6; i++ {
		kind := "dns"
		if i%2 == 0 {
			kind = "conn"
		}
		a.feed.push(model.Event{Kind: kind, TsMicros: int64(i)})
	}
	if got := a.monitorVw.filteredRecent(4); len(got) != 4 {
		t.Errorf("no filter: newest 4; got %d", len(got))
	}
	if got := a.monitorVw.cycleKind(); got != "dns" {
		t.Errorf("the first cycle reads dns; got %q", got)
	}
	for _, e := range a.monitorVw.filteredRecent(10) {
		if e.Kind != "dns" {
			t.Fatalf("the dns filter leaked a %q row", e.Kind)
		}
	}
	if len(a.monitorVw.filteredRecent(2)) != 2 {
		t.Error("the filter still honours the cap")
	}
	a.monitorVw.cycleKind() // conn
	a.monitorVw.cycleKind() // alloc
	if got := a.monitorVw.cycleKind(); got != "all" {
		t.Errorf("the cycle wraps to all; got %q", got)
	}
}

// --- GRAPH view ----------------------------------------------------------------------

// TestGraphViewKeysAndTitle drives the GRAPH tab keys and its honest title.
func TestGraphViewKeysAndTitle(t *testing.T) {
	a := newTestApp(t, 110, 36)
	a.mode = modeGraph
	v := a.graphVw

	v.handleKey(deepentui_rune('j'))
	v.handleKey(deepentui_rune('j'))
	if v.scrollY != 2 {
		t.Errorf("j scrolls down; got %d", v.scrollY)
	}
	v.handleKey(deepentui_rune('k'))
	v.handleKey(deepentui_rune('k'))
	v.handleKey(deepentui_rune('k'))
	if v.scrollY != 0 {
		t.Errorf("k clamps at the top; got %d", v.scrollY)
	}
	v.scrollY = 7
	v.handleKey(deepentui_rune('g'))
	if v.scrollY != 0 {
		t.Error("g jumps home")
	}

	v.handleKey(deepentui_rune(' '))
	if !a.paused || !strings.Contains(a.toast, "graph paused") {
		t.Error("space pauses the graph")
	}
	a.bufferedPause = 9
	v.handleKey(deepentui_rune(' '))
	if a.paused || a.bufferedPause != 0 {
		t.Error("resume clears the buffered count")
	}

	// Grow the graph, then C clears it (the enrichment cache survives by design).
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 1, Addr128: "2a04:2a01::1",
		QName: "x.example.", Decision: "allow"}, true)
	if n, _ := a.lgraph.stats(); n == 0 {
		t.Fatal("the fold should grow the graph")
	}
	v.scrollY = 3
	v.handleKey(deepentui_rune('C'))
	if n, e := a.lgraph.stats(); n != 0 || e != 0 || v.scrollY != 0 {
		t.Error("C clears the picture and resets the scroll")
	}

	// The title carries size + scope; a focused agent renames the scope; pause marks it.
	title := v.title()
	if !strings.Contains(title, "(all agents)") {
		t.Errorf("the default scope is explicit (all agents): %q", title)
	}
	a.monitorVw.focused = "2a04:2a01::abcd:1"
	a.paused = true
	title = v.title()
	if !strings.Contains(title, "watching") || !strings.Contains(title, "⏸") {
		t.Errorf("a focused paused graph says both: %q", title)
	}

	v.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if a.mode != modeAgents {
		t.Error("esc lands back on AGENTS")
	}
}

// TestGraphScrollClampsToContent renders a short graph with a huge scroll and asserts
// the view clamps rather than showing a void.
func TestGraphScrollClampsToContent(t *testing.T) {
	a := newTestApp(t, 110, 36)
	a.graphVw.scrollY = 999
	out := a.graphVw.view(100, 20)
	if strings.TrimSpace(out) == "" {
		t.Fatal("the clamped view still renders")
	}
	if a.graphVw.scrollY > 10 {
		t.Errorf("the scroll must clamp to the content; got %d", a.graphVw.scrollY)
	}
}

// TestAgentNameAndIPKind pins the fleet-label resolver and the endpoint typing.
func TestAgentNameAndIPKind(t *testing.T) {
	a := newTestApp(t, 100, 30)
	deepentui_seedAgents(a)
	if a.agentName("2a04:2a01::1") != "scraper" {
		t.Error("a rostered key resolves to its label")
	}
	if a.agentName("2a04:2a01::ff") != "2a04:2a01::ff" {
		t.Error("an unknown key falls back to itself")
	}
	if l, g := ipKind("2606:4700::1111"); l != "IPV6" || g != "▥" {
		t.Errorf("v6 typing wrong: %s %s", l, g)
	}
	if l, g := ipKind("1.2.3.4"); l != "IPV4" || g != "▤" {
		t.Errorf("v4 typing wrong: %s %s", l, g)
	}
	if l, g := ipKind("db.internal"); l != "HOSTNAME" || g != "⬢" {
		t.Errorf("hostname typing wrong: %s %s", l, g)
	}
}

// --- fleet filter (agentsView) -------------------------------------------------------

// TestAgentsFilterFlow drives the / filter end to end: narrowing, regex support, the
// literal fallback on an invalid pattern, enter/esc semantics, and the title marker.
func TestAgentsFilterFlow(t *testing.T) {
	a := newTestApp(t, 120, 40)
	deepentui_seedAgents(a)
	v := a.agentsView

	v.handleKey(deepentui_rune('/'))
	if !v.filtering || v.filter != "" || len(v.matches) != 3 {
		t.Fatalf("/ opens an empty filter over the whole fleet; matches=%d", len(v.matches))
	}
	for _, r := range "craw" {
		v.handleFilterKey(deepentui_rune(r))
	}
	if len(v.matches) != 1 || a.agents[v.matches[0]].Label != "crawler" {
		t.Fatalf("the filter narrows case-insensitively: %v", v.matches)
	}
	if got := v.orderedIndices(); len(got) != 1 {
		t.Error("the visible order honours the filter")
	}
	if !strings.Contains(strip(v.fleetTitle()), "/craw") {
		t.Error("the title shows the live filter")
	}

	// Backspace re-widens.
	for i := 0; i < 4; i++ {
		v.handleFilterKey(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	if len(v.matches) != 3 {
		t.Error("clearing the filter re-widens the fleet")
	}

	// A real regex works: scraper|prober matches two.
	for _, r := range "scraper|prober" {
		v.handleFilterKey(deepentui_rune(r))
	}
	if len(v.matches) != 2 {
		t.Errorf("an alternation regex should match 2: %v", v.matches)
	}

	// An INVALID regex falls back to the quoted literal instead of erroring.
	v.clearFilter()
	v.filtering = true
	for _, r := range "scraper(" {
		v.handleFilterKey(deepentui_rune(r))
	}
	if len(v.matches) != 0 {
		t.Errorf("the literal 'scraper(' matches nothing (and must not panic): %v", v.matches)
	}

	// enter keeps the filter applied; esc clears it.
	v.handleFilterKey(tea.KeyMsg{Type: tea.KeyEnter})
	if v.filtering {
		t.Error("enter leaves filter-entry mode")
	}
	v.filtering = true
	v.handleFilterKey(tea.KeyMsg{Type: tea.KeyEscape})
	if v.filtering || v.filter != "" || v.matches != nil {
		t.Error("esc clears the filter whole")
	}
}

// TestAgentsSortCycleAndDensity covers Shift-K's sort cycle and the z density toggle.
func TestAgentsSortCycleAndDensity(t *testing.T) {
	a := newTestApp(t, 120, 40)
	deepentui_seedAgents(a)
	v := a.agentsView

	v.handleKey(deepentui_rune('K'))
	if v.sort != sortByCreated || !strings.Contains(a.toast, "created") {
		t.Errorf("K cycles active->created; got %s", sortKeyNames[v.sort])
	}
	v.handleKey(deepentui_rune('K')) // name
	order := v.orderedIndices()
	// name sort: crawler(1), prober(2), scraper(0)
	if a.agents[order[0]].Label != "crawler" || a.agents[2].Label != "prober" {
		t.Errorf("name sort wrong: %v", order)
	}
	v.handleKey(deepentui_rune('K')) // state
	order = v.orderedIndices()
	if a.agents[order[0]].State != "active" {
		t.Errorf("state sort puts active first: %v", order)
	}
	// traffic sort: give agent-3 the bytes.
	a.agents[2].BytesUp = 1 << 20
	v.handleKey(deepentui_rune('K')) // traffic
	if order = v.orderedIndices(); a.agents[order[0]].Label != "prober" {
		t.Errorf("traffic sort puts the heavy agent first: %v", order)
	}
	v.handleKey(deepentui_rune('K')) // wraps to active
	if v.sort != sortByActive {
		t.Error("the sort cycle wraps")
	}

	dense := v.autoDense()
	v.handleKey(deepentui_rune('z'))
	if v.autoDense() == dense {
		t.Error("z flips the density")
	}

	// Motion clamps at both ends of the fleet.
	v.moveTo(99)
	if a.selected != v.orderedIndices()[2] {
		t.Error("moveTo clamps at the tail")
	}
	v.move(-99)
	if a.selected != v.orderedIndices()[0] {
		t.Error("move clamps at the head")
	}

	// space pauses from the fleet too.
	v.handleKey(deepentui_rune(' '))
	if !a.paused {
		t.Error("space pauses the feed")
	}
}

// TestStateGlyphAndBadge pins the state glyphs (meaning without colour).
func TestStateGlyphAndBadge(t *testing.T) {
	a := newTestApp(t, 100, 30)
	if stateGlyph("active") != "●" || stateGlyph("released") != "○" {
		t.Error("state glyphs broke")
	}
	if !strings.Contains(strip(stateBadge(a.th, "active")), "● active") {
		t.Error("the active badge carries its glyph")
	}
	if !strings.Contains(strip(stateBadge(a.th, "released")), "○ released") {
		t.Error("the released badge carries its glyph")
	}
	if !strings.Contains(strip(stateBadge(a.th, "draining")), "◐ draining") {
		t.Error("an unknown state reads as the half glyph")
	}
}
