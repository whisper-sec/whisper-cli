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

// TestBlockedLookupNeverStitches asserts a BLOCKED dns fold stays out of the join
// cache: a blocked resolution returned no usable address, so a later conn can never
// be stitched onto that name (in the chain OR the live agent graph).
func TestBlockedLookupNeverStitches(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 1_000_000, Addr128: "2a04:2a01::9",
		QName: "ads.bad.", Decision: "block"}, true)
	a.foldEvent(model.Event{Kind: "conn", TsMicros: 1_500_000, Addr128: "2a04:2a01::9",
		PeerHost: "10.9.9.9", PeerPort: 443}, true)
	if got := a.join.qnameAt("2a04:2a01::9", 1_500_000); got != "" {
		t.Errorf("a blocked lookup must never stitch; got %q", got)
	}
	ag := a.lgraph.agents["2a04:2a01::9"]
	if ag == nil {
		t.Fatal("agent missing from the live graph")
	}
	if d := ag.dests["ads.bad"]; d == nil || !d.HostBlocked || d.IP != "" {
		t.Errorf("the blocked lookup must plot alone (no ip attached): %+v", d)
	}
	if d := ag.dests["10.9.9.9"]; d == nil || d.Host != "" {
		t.Errorf("the conn must plot as a separate direct-IP destination: %+v", d)
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
// (no re-arm) - the SSE tail pre-empts the fallback.
func TestPollStopsWhenLive(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamConn
	cmd := a.onMonitorPoll(monitorPollMsg{})
	if cmd != nil {
		t.Error("onMonitorPoll should not re-arm while the stream is connected")
	}
}

// TestPollFoldsOnlyNewer asserts the poll dedups by ts - only rows newer than the
// last-seen watermark are folded into the feed.
func TestPollFoldsOnlyNewer(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.stream = streamRetry // down → poll active
	a.lastEventUS = 1000
	a.onMonitorPoll(monitorPollMsg{events: []model.Event{
		{Kind: "dns", TsMicros: 500, QName: "old."},  // older - dropped
		{Kind: "dns", TsMicros: 2000, QName: "new."}, // newer - folded
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
		// good - the old channel closed (no leak)
	case <-time.After(2 * time.Second):
		t.Error("old stream channel was not closed after a restart (goroutine leak)")
	}
}

// --- the merged dashboard (fleet + live monitor in one panel) ---------------------

// TestMergedDashboardRendersMonitorPanel asserts the merged AGENTS frame renders the
// fleet table, the aggregate totals (incl. TOTAL CONNECTIONS), the watched agent's
// stats, the throughput graph, and the live activity chain - one panel, one picture.
func TestMergedDashboardRendersMonitorPanel(t *testing.T) {
	a := newTestApp(t, 140, 42)
	a.mode = modeAgents
	a.stream = streamConn
	a.source = srcSSE
	a.agents = []model.Agent{{
		ID: "agent-1", Address: "2a04:2a01::a17", Label: "scraper", State: "active",
		Detailed: true, DNSQueries: 1200, DNSBlocked: 34,
		ConnectionsActive: 3, ConnectionsTotal: 4200, BytesUp: 8 << 20, BytesDown: 92 << 20,
	}}
	a.selected = 0
	a.agentsView.syncRows()
	a.monitorVw.focused = "2a04:2a01::a17"
	// seed a ring + a feed event so every section has content
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
	for _, want := range []string{
		"FLEET",         // the fleet table panel
		"LIVE",          // the monitor panel's heartbeat title
		"dns 1.2k",      // fleet aggregate dns total
		"conn 4.2k",     // TOTAL CONNECTIONS aggregate
		"(3 active)",    // active connections
		"watching",      // the scope divider
		"scraper",       // the watched agent
		"conn/min",      // live rates line
		"LIVE ACTIVITY", // the chain section
	} {
		if !strings.Contains(out, want) {
			t.Errorf("merged dashboard missing %q; frame:\n%s", want, out)
		}
	}
}

// TestEnterWatchesSelectedAgent asserts ENTER on the fleet pins the monitor to the
// selected agent (the primary select-and-monitor action), and `d` opens the details
// drill that ENTER used to open.
func TestEnterWatchesSelectedAgent(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", Label: "scraper", State: "active"},
		{ID: "agent-2", Address: "2a04:2a01::2", Label: "crawler", State: "active"},
	}
	a.selected = 1
	a.agentsView.syncRows()

	_, cmd := a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.monitorVw.focused != "2a04:2a01::2" {
		t.Fatalf("enter should pin the monitor to the selected agent; focused=%q", a.monitorVw.focused)
	}
	if cmd == nil {
		t.Error("enter should fire the narrow + backfill commands")
	}
	if a.overlay != overlayNone {
		t.Error("enter must NOT open the details drill any more")
	}

	// `d` opens the details card ENTER used to open.
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if a.overlay != overlayDrill {
		t.Errorf("d should open the details drill; overlay=%v", a.overlay)
	}
	if !strings.Contains(strip(a.View()), "2a04:2a01::2") {
		t.Error("the details drill should show the selected agent")
	}
	a.overlay = overlayNone

	// `a` returns to the whole tenant.
	_, cmd = a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if a.monitorVw.focused != "" {
		t.Errorf("a should unfocus back to tenant-wide; focused=%q", a.monitorVw.focused)
	}
	if cmd == nil {
		t.Error("unfocus should restart the stream un-narrowed")
	}
}

// TestClickWatchesAgentRow asserts a mouse click on a fleet row selects that agent AND
// pins the monitor to it (the mouse is the same verb as ENTER). The table is windowed
// by the view, so visible row r maps exactly to position top+r.
func TestClickWatchesAgentRow(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", Label: "scraper", State: "active", Created: 3},
		{ID: "agent-2", Address: "2a04:2a01::2", Label: "crawler", State: "active", Created: 2},
		{ID: "agent-3", Address: "2a04:2a01::3", Label: "prober", State: "active", Created: 1},
	}
	a.selected = 0
	a.agentsView.syncRows()

	// Row geometry: header(1) + tabs(1) + panel border(1) + table header(1) = rows
	// start at y=4; the second row (created-desc order keeps input order) is y=5.
	_, cmd := a.handleMouse(tea.MouseMsg{
		Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 2, Y: 5,
	})
	if a.selected != 1 {
		t.Fatalf("click on row 1 should select agents[1]; selected=%d", a.selected)
	}
	if a.monitorVw.focused != "2a04:2a01::2" {
		t.Errorf("click should pin the monitor to the clicked agent; focused=%q", a.monitorVw.focused)
	}
	if cmd == nil {
		t.Error("click should fire the focus commands")
	}
	// A click on the monitor panel (right half) is not a row click.
	before := a.selected
	a.handleMouse(tea.MouseMsg{
		Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: a.width - 4, Y: 5,
	})
	if a.selected != before {
		t.Error("a click outside the fleet panel must not change the selection")
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

// --- last-active fleet ordering + the freeze toggle --------------------------

// TestAgentsOrderByLastActive asserts the DEFAULT fleet order follows folded activity:
// fresh traffic moves an agent up; with no traffic the roster falls back to created-desc.
func TestAgentsOrderByLastActive(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", Label: "one", State: "active", Created: 3},
		{ID: "agent-2", Address: "2a04:2a01::2", Label: "two", State: "active", Created: 2},
		{ID: "agent-3", Address: "2a04:2a01::3", Label: "three", State: "active", Created: 1},
	}
	a.agentsView.syncRows()
	if a.agentsView.sort != sortByActive {
		t.Fatalf("the default sort must be last-active; got %s", sortKeyNames[a.agentsView.sort])
	}
	// No folded traffic: created-desc fallback keeps 1,2,3.
	if order := a.agentsView.orderedIndices(); order[0] != 0 || order[2] != 2 {
		t.Fatalf("cold fallback should be created-desc; got %v", order)
	}
	// Traffic for the created-OLDEST agent moves it to the top.
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 5_000_000, Addr128: "2a04:2a01::3",
		QName: "x.", Decision: "allow"}, true)
	if order := a.agentsView.orderedIndices(); order[0] != 2 {
		t.Fatalf("newest traffic should move agent-3 up; got %v", order)
	}
	// Newer traffic for agent-1 tops it; agent-3 stays above the never-active agent-2.
	a.foldEvent(model.Event{Kind: "conn", TsMicros: 6_000_000, Addr128: "2a04:2a01::1",
		PeerHost: "1.1.1.1", PeerPort: 443}, true)
	order := a.agentsView.orderedIndices()
	if order[0] != 0 || order[1] != 2 || order[2] != 1 {
		t.Fatalf("order should be 1(newest),3,2; got %v", order)
	}
	// The fold marks the fleet dirty and the tick re-syncs it (no per-event rebuild).
	if !a.fleetDirty {
		t.Error("a fresh watermark should mark the fleet dirty for the tick re-sort")
	}
	a.onTick()
	if a.fleetDirty {
		t.Error("the tick should clear fleetDirty after re-syncing")
	}
}

// TestAgentsFreezeTogglePinsTheOrder asserts Shift-F pins the on-screen order (new
// traffic no longer reshuffles), newcomers append at the tail, and F again resumes.
func TestAgentsFreezeTogglePinsTheOrder(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", State: "active", Created: 2},
		{ID: "agent-2", Address: "2a04:2a01::2", State: "active", Created: 1},
	}
	a.agentsView.syncRows()
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 5_000_000, Addr128: "2a04:2a01::2",
		QName: "x.", Decision: "allow"}, true)
	if order := a.agentsView.orderedIndices(); order[0] != 1 {
		t.Fatalf("agent-2 should lead after its traffic; got %v", order)
	}
	// Freeze via the real key path.
	a.agentsView.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'F'}})
	if !a.agentsView.frozen {
		t.Fatal("F should freeze the ordering")
	}
	// Newer traffic for agent-1 must NOT reshuffle a frozen list.
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 9_000_000, Addr128: "2a04:2a01::1",
		QName: "y.", Decision: "allow"}, true)
	if order := a.agentsView.orderedIndices(); order[0] != 1 || order[1] != 0 {
		t.Fatalf("frozen order must hold 2,1; got %v", order)
	}
	// A newcomer (stream-discovered) appends at the tail of a frozen list.
	a.upsertStreamAgent("2a04:2a01::9", "agent-9")
	if order := a.agentsView.orderedIndices(); len(order) != 3 || a.agents[order[2]].Address != "2a04:2a01::9" {
		t.Fatalf("a newcomer should append at the frozen tail; got %v", order)
	}
	// The fleet title says so (the reader can see WHY it stopped moving).
	if !strings.Contains(strip(a.agentsView.fleetTitle()), "frozen") {
		t.Error("the fleet title should carry the frozen marker")
	}
	// Unfreeze: the live last-active order resumes (agent-1 now newest).
	a.agentsView.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'F'}})
	if order := a.agentsView.orderedIndices(); order[0] != 0 {
		t.Fatalf("unfreeze should resume last-active order with agent-1 first; got %v", order)
	}
}

// --- blocked events name WHAT was blocked -----------------------------------

// TestBlockedSummaryNamesTheTarget folds a blocked lookup + a denied egress and asserts
// the monitor summary names the qname and the peer host:port - in the (all) scope, the
// per-agent scope, and the rendered frame (glyph-carried, so NO_COLOR reads the same).
func TestBlockedSummaryNamesTheTarget(t *testing.T) {
	a := newTestApp(t, 170, 44)
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 1_000_000, Addr128: "2a04:2a01::9",
		QName: "ads.bad.example.", Decision: "block"}, true)
	a.foldEvent(model.Event{Kind: "conn", TsMicros: 2_000_000, Addr128: "2a04:2a01::9",
		PeerHost: "10.9.9.9", PeerPort: 445, Reason: "fw-deny"}, true)

	q, p := a.monitorVw.lastBlockedTargets("")
	if q != "ads.bad.example" || p != "10.9.9.9:445" {
		t.Fatalf("(all) scope should name both targets; got q=%q p=%q", q, p)
	}
	q, p = a.monitorVw.lastBlockedTargets("2a04:2a01::9")
	if q != "ads.bad.example" || p != "10.9.9.9:445" {
		t.Fatalf("the agent's own scope should name its targets; got q=%q p=%q", q, p)
	}
	if q, p = a.monitorVw.lastBlockedTargets("2a04:2a01::1"); q != "" || p != "" {
		t.Errorf("an uninvolved agent's scope must stay empty; got q=%q p=%q", q, p)
	}
	// An OLDER out-of-order row (a backfill replay) must never overwrite a fresher target.
	a.foldEvent(model.Event{Kind: "dns", TsMicros: 500_000, Addr128: "2a04:2a01::9",
		QName: "stale.example.", Decision: "block"}, false)
	if q, _ := a.monitorVw.lastBlockedTargets(""); q != "ads.bad.example" {
		t.Errorf("an older backfill row must not overwrite the newest target; got %q", q)
	}

	// The rendered (all)-scope frame carries the names + the ✗ glyph.
	a.mode = modeAgents
	a.layout()
	out := strip(a.View())
	for _, want := range []string{"last blocked:", "ads.bad.example", "10.9.9.9:445", "✗"} {
		if !strings.Contains(out, want) {
			t.Errorf("the monitor summary should name the blocked target %q; frame:\n%s", want, out)
		}
	}
}

// --- the explicit (all) selection is the default -----------------------------

// TestAllScopeIsDefaultAndAggregates pins the default: nothing focused, the scope reads
// (all), and the aggregate numbers sum EVERY agent's ring (panels honor the selection).
func TestAllScopeIsDefaultAndAggregates(t *testing.T) {
	a := newTestApp(t, 150, 42)
	if a.monitorVw.focused != "" {
		t.Fatalf("the default scope must be (all); focused=%q", a.monitorVw.focused)
	}
	if title := a.monitorVw.scopeTitle(); !strings.Contains(title, "(all)") {
		t.Errorf("the scope title should carry the explicit (all); got %q", title)
	}
	// Two agents' recent conns: the (all) rate sums both rings; a single key scopes to one.
	now := time.Now().UnixMicro()
	a.foldEvent(model.Event{Kind: "conn", TsMicros: now, Addr128: "2a04:2a01::1",
		PeerHost: "1.1.1.1", PeerPort: 443, BytesUp: 100, BytesDown: 100}, true)
	a.foldEvent(model.Event{Kind: "conn", TsMicros: now, Addr128: "2a04:2a01::2",
		PeerHost: "1.0.0.1", PeerPort: 443, BytesUp: 100, BytesDown: 100}, true)
	if got := a.monitorVw.connPerMin(""); got != 2 {
		t.Errorf("(all) conn rate should sum every ring; got %v", got)
	}
	if got := a.monitorVw.connPerMin("2a04:2a01::1"); got != 1 {
		t.Errorf("a single-agent scope should count only its ring; got %v", got)
	}
	// The frame names the (all) selection; the GRAPH tab honors it too.
	a.mode = modeAgents
	a.layout()
	if out := strip(a.View()); !strings.Contains(out, "(all)") {
		t.Error("the AGENTS frame should render the explicit (all) selection")
	}
	a.mode = modeGraph
	a.layout()
	if out := strip(a.View()); !strings.Contains(out, "(all agents)") {
		t.Error("the GRAPH title should honor the (all) scope")
	}
	// Focusing an agent leaves (all) reachable and labeled on the way back.
	a.agents = []model.Agent{{ID: "agent-1", Address: "2a04:2a01::1", State: "active"}}
	a.selected = 0
	a.agentsView.syncRows()
	a.monitorVw.focus(a.agents[0])
	if title := a.monitorVw.scopeTitle(); strings.Contains(title, "(all)") {
		t.Errorf("a focused scope must name the agent, not (all); got %q", title)
	}
	a.monitorVw.unfocus()
	if title := a.monitorVw.scopeTitle(); !strings.Contains(title, "(all)") {
		t.Errorf("unfocus must return to the (all) selection; got %q", title)
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
