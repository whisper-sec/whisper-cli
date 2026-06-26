// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// --- chain-as-structure (the distinct silhouettes) -------------------------------

// TestChainSilhouettes asserts the three decision silhouettes are DISTINCT shapes:
// allow uses ──▶ at both lanes; block-at-dns puts ──╳ at the qname→peer boundary with NO
// peer; block-at-egress keeps ──▶ to the qname then ──╳ to the peer. Shape, not colour.
func TestChainSilhouettes(t *testing.T) {
	a := newTestApp(t, 120, 40)
	w := 110

	allow := strip(a.renderChainRow(model.Event{
		Kind: "dns", TsMicros: 1, ClientSrc: "203.0.113.0/24",
		QName: "ok.example.", Decision: "allow", QType: "A",
	}, w, 0, false))
	if !strings.Contains(allow, "──▶") || strings.Contains(allow, "──╳") {
		t.Errorf("allow dns should use ──▶ only; got %q", allow)
	}

	blockDNS := strip(a.renderChainRow(model.Event{
		Kind: "dns", TsMicros: 2, ClientSrc: "203.0.113.0/24",
		QName: "ads.bad.", Decision: "block",
	}, w, 0, false))
	if !strings.Contains(blockDNS, "──╳") {
		t.Errorf("block-at-dns should carry the ──╳ connector; got %q", blockDNS)
	}
	// block-at-dns has a ▶ for client→qname (the lookup happened) then ╳ (no peer).
	if !strings.Contains(blockDNS, "──▶") {
		t.Errorf("block-at-dns should still show ──▶ for the lookup leg; got %q", blockDNS)
	}

	blockEgress := strip(a.renderChainRow(model.Event{
		Kind: "conn", TsMicros: 3, ClientSrc: "203.0.113.0/24",
		QName: "ok.example.", PeerHost: "10.0.0.5", PeerPort: 22, Reason: "fw-deny",
	}, w, 100, false))
	// egress-block: ──▶ (client→qname) ... ──╳ (qname→peer) and the peer IS shown.
	if !strings.Contains(blockEgress, "──▶") || !strings.Contains(blockEgress, "──╳") {
		t.Errorf("block-at-egress should show ──▶ then ──╳; got %q", blockEgress)
	}
	if !strings.Contains(blockEgress, "10.0.0.5:22") {
		t.Errorf("block-at-egress should still render the peer it was denied to; got %q", blockEgress)
	}
	// The two block shapes differ: egress reaches a peer, dns does not.
	if strings.Contains(blockDNS, ":22") {
		t.Errorf("block-at-dns must NOT show a peer; got %q", blockDNS)
	}
}

// TestChainFlowHeat asserts a fat transfer renders more filled heat cells than a small one
// (the flow-heat bar maps bytes against the on-screen peak).
func TestChainFlowHeat(t *testing.T) {
	a := newTestApp(t, 120, 40)
	fat := strip(a.renderChainRow(model.Event{
		Kind: "conn", TsMicros: 1, PeerHost: "1.1.1.1", PeerPort: 443,
		BytesUp: 100, BytesDown: 1_000_000, Reason: "closed",
	}, 110, 1_000_100, false))
	small := strip(a.renderChainRow(model.Event{
		Kind: "conn", TsMicros: 2, PeerHost: "1.1.1.1", PeerPort: 443,
		BytesUp: 1, BytesDown: 10, Reason: "closed",
	}, 110, 1_000_100, false))
	if strings.Count(fat, "▰") <= strings.Count(small, "▰") {
		t.Errorf("a fat transfer should have more filled heat cells\nfat:  %q\nsmall:%q", fat, small)
	}
}

// TestChainNoColorSilhouette asserts the silhouette survives NO_COLOR (the ──▶/──╳ shapes
// carry the meaning, not colour).
func TestChainNoColorSilhouette(t *testing.T) {
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, NoColor: true, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	row := a.renderChainRow(model.Event{
		Kind: "conn", TsMicros: 1, QName: "x.", PeerHost: "10.0.0.5", PeerPort: 22, Reason: "ssrf-block",
	}, 110, 100, false)
	if !strings.Contains(row, "──╳") {
		t.Errorf("NO_COLOR egress-block should still carry ──╳; got %q", row)
	}
}

// TestFlashWrapPrependsMark asserts a flashing row gets the leading accent mark and a
// non-flashing one does not (motion is opt-in per row).
func TestFlashWrapPrependsMark(t *testing.T) {
	a := newTestApp(t, 120, 40)
	flashed := a.renderChainRow(model.Event{Kind: "dns", TsMicros: 1, QName: "x.", Decision: "allow"}, 80, 0, true)
	plain := a.renderChainRow(model.Event{Kind: "dns", TsMicros: 1, QName: "x.", Decision: "allow"}, 80, 0, false)
	if !strings.Contains(strip(flashed), "▎") {
		t.Errorf("a flashing row should carry the ▎ mark; got %q", strip(flashed))
	}
	if strings.Contains(strip(plain), "▎") {
		t.Errorf("a non-flashing row should not carry the ▎ mark; got %q", strip(plain))
	}
}

// --- join cache TTL --------------------------------------------------------------

// TestJoinCacheTTL asserts a qname stitches a conn within the TTL window and is dropped
// once stale (so a much-later conn never gets a wrong qname).
func TestJoinCacheTTL(t *testing.T) {
	j := newJoinCache(8)
	dnsAt := int64(1_000_000_000_000)
	j.observeDNS("2a04:2a01::1", "fresh.example.", dnsAt)

	// within TTL → stitches
	if got := j.qnameAt("2a04:2a01::1", dnsAt+5_000_000); got != "fresh.example." {
		t.Errorf("within-TTL stitch failed: %q", got)
	}
	// beyond TTL → no stitch (never a stale wrong name)
	if got := j.qnameAt("2a04:2a01::1", dnsAt+joinTTL+1); got != "" {
		t.Errorf("stale entry should not stitch; got %q", got)
	}
	// nowMicros==0 ignores the TTL (a unit probe)
	if got := j.qnameAt("2a04:2a01::1", 0); got != "fresh.example." {
		t.Errorf("ts=0 should ignore TTL; got %q", got)
	}
	// unknown addr → empty
	if got := j.qnameAt("2a04:2a01::ffff", dnsAt); got != "" {
		t.Errorf("unknown addr should be empty; got %q", got)
	}
}

// TestJoinCacheEviction asserts FIFO eviction caps the entry count (bounded memory).
func TestJoinCacheEviction(t *testing.T) {
	j := newJoinCache(3)
	for i := 0; i < 10; i++ {
		j.observeDNS(addrN(i), "name", int64(i))
	}
	if j.len() > 3 {
		t.Errorf("join cache should cap at 3 entries; has %d", j.len())
	}
	// The oldest (addr0) is evicted; the newest (addr9) remains.
	if got := j.qnameAt(addrN(9), 0); got == "" {
		t.Errorf("newest entry should survive eviction")
	}
	if got := j.qnameAt(addrN(0), 0); got != "" {
		t.Errorf("oldest entry should be evicted; got %q", got)
	}
}

// TestJoinCacheRefreshNoGrowth asserts re-observing the same addr updates in place (no
// double-count toward the cap).
func TestJoinCacheRefreshNoGrowth(t *testing.T) {
	j := newJoinCache(4)
	for i := 0; i < 20; i++ {
		j.observeDNS("2a04:2a01::1", "name", int64(i))
	}
	if j.len() != 1 {
		t.Errorf("re-observing one addr should keep len 1; got %d", j.len())
	}
}

// --- poll fallback state machine -------------------------------------------------

// TestStreamPollTransitionFiresPoll asserts the SSE→poll transition (a 503/drop) kicks the
// op:logs poll fallback and sets the source to poll.
func TestStreamPollTransitionFiresPoll(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamConn
	_, cmd := a.Update(streamStateMsg{state: streamPoll})
	if a.source != srcPoll {
		t.Errorf("source should be poll after the transition; got %v", a.source)
	}
	if cmd == nil {
		t.Error("the SSE→poll transition should return a command (the poll + re-arm)")
	}
}

// TestPollStopsWhenLive asserts a poll result is ignored once the live stream is back
// (no re-arm) — the SSE tail pre-empts the fallback.
func TestPollStopsWhenLive(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamConn
	cmd := a.onMonitorPoll(monitorPollMsg{})
	if cmd != nil {
		t.Error("onMonitorPoll should not re-arm while the stream is connected")
	}
}

// TestPollFoldsOnlyNewer asserts the poll dedups by ts — only rows newer than the
// last-seen watermark are folded into the feed.
func TestPollFoldsOnlyNewer(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamRetry // down → poll active
	a.lastEventUS = 1000
	a.onMonitorPoll(monitorPollMsg{events: []model.Event{
		{Kind: "dns", TsMicros: 500, QName: "old."},  // older — dropped
		{Kind: "dns", TsMicros: 2000, QName: "new."}, // newer — folded
	}})
	if a.feed.len() != 1 {
		t.Fatalf("only the newer row should be folded; feed has %d", a.feed.len())
	}
	if got := a.feed.recent(1)[0].QName; got != "new." {
		t.Errorf("the folded row should be the newer one; got %q", got)
	}
}

// TestBackfillReplayOrderAndToken asserts the backfill folds oldest→newest (newest ends on
// top) and a stale token is dropped.
func TestBackfillReplayOrderAndToken(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.backfillToken = 5
	// op:logs returns newest-first; the backfill should replay so the newest lands on top.
	a.onMonitorBackfill(monitorBackfillMsg{token: 5, events: []model.Event{
		{Kind: "dns", TsMicros: 3000, QName: "newest."},
		{Kind: "dns", TsMicros: 2000, QName: "mid."},
		{Kind: "dns", TsMicros: 1000, QName: "oldest."},
	}})
	if a.feed.len() != 3 {
		t.Fatalf("backfill should fold 3 rows; got %d", a.feed.len())
	}
	if got := a.feed.recent(1)[0].QName; got != "newest." {
		t.Errorf("newest row should be on top after backfill; got %q", got)
	}
	// A stale-token backfill is dropped.
	a.onMonitorBackfill(monitorBackfillMsg{token: 1, events: []model.Event{
		{Kind: "dns", TsMicros: 9000, QName: "stale."},
	}})
	if a.feed.len() != 3 {
		t.Errorf("a stale-token backfill must be dropped; feed grew to %d", a.feed.len())
	}
}

// --- motion: pause + buffered ----------------------------------------------------

// TestPausedBuffersAndCounts asserts that while paused, live events are NOT pushed onto
// the feed but ARE counted as "buffered"; resuming clears the count.
func TestPausedBuffersAndCounts(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.paused = true
	before := a.feed.len()
	a.onStreamEvent(model.Event{Kind: "dns", TsMicros: 1, QName: "a."})
	a.onStreamEvent(model.Event{Kind: "conn", TsMicros: 2, PeerHost: "x"})
	if a.feed.len() != before {
		t.Errorf("paused feed should not grow; grew from %d to %d", before, a.feed.len())
	}
	if a.bufferedPause != 2 {
		t.Errorf("paused events should be counted as buffered; got %d", a.bufferedPause)
	}
	// the title shows the buffered count.
	if !strings.Contains(strip(a.liveTitle()), "2 buffered") {
		t.Errorf("live title should show '2 buffered' while paused; got %q", strip(a.liveTitle()))
	}
}

// TestHeartbeatPulseAdvances asserts the heartbeat phase advances on the per-second tick
// while connected (the ●→◉→● breathing).
func TestHeartbeatPulseAdvances(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamConn
	start := a.hbPulse
	for i := 0; i < 4; i++ { // 4 ticks = one second
		a.onTick()
	}
	if a.hbPulse == start {
		t.Error("heartbeat pulse should advance after one second of ticks while connected")
	}
}

// TestSourceShownInTitle asserts the live source (backfill/live/poll) is surfaced in the
// strip title with its glyph (so the operator always knows where the picture comes from).
func TestSourceShownInTitle(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.source = srcPoll
	a.stream = streamPoll
	title := strip(a.liveTitle())
	if !strings.Contains(title, "poll") {
		t.Errorf("live title should name the poll source; got %q", title)
	}
}

// TestStreamRestartClosesOldChannel asserts a narrow change tears the old stream channel
// down (close), so a pending waitStream on it unblocks with streamIdle instead of leaking
// a forever-blocked goroutine. We start a stream, capture its channel, restart narrowed,
// and confirm the old channel is drained/closed within a bound.
func TestStreamRestartClosesOldChannel(t *testing.T) {
	a := newTestApp(t, 100, 30)
	// Start a stream goroutine (keyless client → it errors fast and loops, but the channel
	// + token lifecycle is what we exercise).
	_ = a.startStream()
	old := a.streamCh
	if old == nil {
		t.Fatal("startStream should have created a channel")
	}
	// Restart narrowed to a different /128.
	_ = a.restartStreamNarrowed("2a04:2a01::dead")
	if a.streamAddr != "2a04:2a01::dead" {
		t.Errorf("restart should set the narrow addr; got %q", a.streamAddr)
	}
	// The old goroutine was cancelled; it must close its channel on exit. Drain it: a closed
	// channel yields ok=false. Bound the wait so a leak fails the test rather than hanging.
	done := make(chan bool, 1)
	go func() {
		for {
			if _, ok := <-old; !ok {
				done <- true
				return
			}
		}
	}()
	select {
	case <-done:
		// good — the old channel closed (no leak)
	case <-time.After(2 * time.Second):
		t.Error("old stream channel was not closed after a restart (goroutine leak)")
	}
}

// --- monitor render --------------------------------------------------------------

// TestMonitorRendersHeroStripsChain asserts the full MONITOR frame renders all three
// bands (hero throughput, agent strips, live activity) with seeded data.
func TestMonitorRendersHeroStripsChain(t *testing.T) {
	a := newTestApp(t, 120, 42)
	a.mode = modeMonitor
	a.stream = streamConn
	a.source = srcSSE
	a.agents = []model.Agent{{ID: "agent-1", Address: "2a04:2a01::a17", Label: "scraper", State: "active"}}
	a.agentsView.syncRows()
	a.monitorVw.focused = "2a04:2a01::a17"
	// seed a ring + a feed event so each band has content
	r := &agentRing{}
	for i := 0; i < kbpsWindow; i++ {
		r.bytes[i] = float64(1000 * (i%10 + 1))
		r.conns[i] = 1
		r.dnsTotal[i] = 2
	}
	r.head = kbpsWindow - 1
	a.monitorVw.rings["2a04:2a01::a17"] = r
	a.feed.push(model.Event{Kind: "dns", TsMicros: 1, QName: "x.", Decision: "allow"})
	a.layout()
	out := strip(a.View())
	for _, want := range []string{"THROUGHPUT", "AGENTS ·", "LIVE ACTIVITY", "conn/min", "block-rate"} {
		if !strings.Contains(out, want) {
			t.Errorf("monitor frame missing %q; frame:\n%s", want, out)
		}
	}
}

// TestMonitorObserveBlockRate asserts the per-agent ring tracks dns block-rate from
// observed events (the gauge data path).
func TestMonitorObserveBlockRate(t *testing.T) {
	a := newTestApp(t, 100, 30)
	key := "2a04:2a01::1"
	for i := 0; i < 10; i++ {
		dec := "allow"
		if i < 3 {
			dec = "block"
		}
		a.monitorVw.observe(model.Event{Kind: "dns", Addr128: key, Decision: dec})
	}
	if br := a.monitorVw.blockRate(key); br < 0.29 || br > 0.31 {
		t.Errorf("block-rate should be ~0.30 (3/10); got %v", br)
	}
}

// --- helpers ---------------------------------------------------------------------

// strip removes ANSI escapes so assertions test the rendered text/shapes, not styling.
func strip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			// skip CSI ... m
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func addrN(n int) string {
	return "2a04:2a01::" + string(rune('a'+n))
}
