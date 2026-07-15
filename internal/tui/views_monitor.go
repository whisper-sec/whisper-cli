// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/components"
)

// kbpsWindow is how many per-second buckets the per-agent rings keep - 4 minutes, enough
// to fill the braille graph (2 dot-columns per cell) on a wide terminal at one
// sample/second while staying tiny + bounded (~8 KiB/agent).
const kbpsWindow = 240

// agentRing holds rolling per-second buckets for one agent: total bytes (the kbps spark +
// the throughput graph), conn-opens (the conn/min number), and dns total/blocked (the
// block-rate). A fixed-size circular buffer: O(1) push, bounded memory, no allocation on
// the hot fold path. The 4Hz render tick advances the head once a real second (every 4th).
type agentRing struct {
	bytes      [kbpsWindow]float64 // per-second total bytes (up+down)
	conns      [kbpsWindow]float64 // per-second conn-open counts
	dnsTotal   [kbpsWindow]float64 // per-second dns query counts
	dnsBlocked [kbpsWindow]float64 // per-second dns blocked counts
	head       int                 // index of the current second's bucket

	// WHAT was blocked, not just how much: the most recent blocked/refused
	// lookup's qname and the most recent denied egress peer (host:port), with their
	// event timestamps so the tenant-wide aggregate can pick the newest across rings.
	// Session-lifetime (never rolled by advance) - "last blocked" means last seen.
	lastBlockedQName string
	lastBlockedUS    int64
	lastDeniedPeer   string
	lastDeniedUS     int64
}

// monitorView is the live half of the merged AGENTS dashboard: the per-agent rings (fed
// by every live/backfill/poll event) plus the right-hand panel renderer - aggregate
// counters (incl. TOTAL CONNECTIONS), the selected agent's stats, a braille throughput
// graph, and the structured activity chain over the shared feed ring.
type monitorView struct {
	app        *App
	rings      map[string]*agentRing // keyed by agent Key()
	focused    string                // a focused agent Key() ("" = whole tenant)
	kindF      string                // "", dns, conn, alloc cycle (f)
	backfilled bool                  // the op:logs backfill has run for the current focus (re-armed on focus change)
}

func newMonitorView(app *App) *monitorView {
	return &monitorView{app: app, rings: map[string]*agentRing{}}
}

// onEnter seeds the monitor with an op:logs backfill (the hybrid design: paint history,
// then tail the live SSE on top). It backfills once per focus; the stream is already
// running (the always-on panel). Fail-open: an empty/failed backfill is fine.
func (v *monitorView) onEnter() tea.Cmd {
	if v.app.client == nil || v.backfilled {
		return nil
	}
	v.backfilled = true
	v.app.backfillToken++
	v.app.source = srcBackfill
	return loadMonitorBackfill(v.app.client, v.narrowAddr(), "-15m", v.app.backfillToken)
}

// narrowAddr returns the /128 to narrow op:logs / the stream to when an agent is focused
// (empty = tenant-wide). The SSE narrow takes the address, not the id.
func (v *monitorView) narrowAddr() string {
	if v.focused == "" {
		return ""
	}
	if strings.Contains(v.focused, ":") { // focused is a Key() - the /128 when known
		return v.focused
	}
	return ""
}

// observe folds a live/backfill/poll event into the per-agent rings (called from
// foldEvent). It is allocation-free on the hot path (a map lookup + array writes).
func (v *monitorView) observe(e model.Event) {
	key := e.Addr128
	if key == "" {
		key = e.Agent
	}
	if key == "" {
		return
	}
	r := v.rings[key]
	if r == nil {
		r = &agentRing{}
		v.rings[key] = r
	}
	// Name the blocked TARGET, newest-wins by event time so an out-of-order
	// backfill row never overwrites a fresher live one. The feed rows already show
	// every target; this is the summary's memory of the most recent one.
	switch e.Kind {
	case "dns":
		if isBlock(e.Decision) && e.QName != "" && e.TsMicros >= r.lastBlockedUS {
			r.lastBlockedQName = components.TrimDot(e.QName)
			r.lastBlockedUS = e.TsMicros
		}
	case "conn":
		if isDeny(e.Reason) && e.PeerHost != "" && e.TsMicros >= r.lastDeniedUS {
			r.lastDeniedPeer = fmt.Sprintf("%s:%d", e.PeerHost, e.PeerPort)
			r.lastDeniedUS = e.TsMicros
		}
	}
	// Bucket by the EVENT's own timestamp, not the current head: a -15m backfill or a
	// 2-minute poll batch folded into head collapses history into one giant "now" spike
	// with a dead graph behind it. Older-than-window events don't chart (they
	// still count in the feed); clock skew clamps to now.
	idx := r.head
	if e.TsMicros > 0 {
		delta := time.Now().Unix() - e.TsMicros/1_000_000
		if delta < 0 {
			delta = 0
		}
		if delta >= kbpsWindow {
			return
		}
		idx = (r.head - int(delta) + kbpsWindow*2) % kbpsWindow
	}
	switch e.Kind {
	case "conn":
		r.bytes[idx] += float64(e.BytesUp + e.BytesDown)
		r.conns[idx]++
	case "dns":
		r.dnsTotal[idx]++
		if isBlock(e.Decision) {
			r.dnsBlocked[idx]++
		}
	}
}

// kbpsSeries returns the last n per-second kbps samples for an agent (newest last), for
// the throughput graph + sparklines. Cheap, allocation-light, deterministic per ring state.
func (v *monitorView) kbpsSeries(key string, n int) []float64 {
	r := v.rings[key]
	if r == nil {
		return nil
	}
	if n > kbpsWindow {
		n = kbpsWindow
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		idx := (r.head - n + 1 + i + kbpsWindow*2) % kbpsWindow
		out[i] = r.bytes[idx] * 8 / 1000 // bytes/s -> kbps
	}
	return out
}

// aggregateSeries sums every agent's kbps series (the tenant-wide throughput graph).
func (v *monitorView) aggregateSeries(n int) []float64 {
	if n > kbpsWindow {
		n = kbpsWindow
	}
	out := make([]float64, n)
	for k := range v.rings {
		s := v.kbpsSeries(k, n)
		for i := range s {
			out[i] += s[i]
		}
	}
	return out
}

// connPerMin sums the conn-opens over the window (the conn/min number). An empty key
// aggregates every ring (the tenant-wide rate).
func (v *monitorView) connPerMin(key string) float64 {
	var sum float64
	if key == "" {
		for _, r := range v.rings {
			for _, c := range r.conns {
				sum += c
			}
		}
		return sum
	}
	r := v.rings[key]
	if r == nil {
		return 0
	}
	for _, c := range r.conns {
		sum += c
	}
	return sum
}

// curKbps is the most-recent full second's kbps (the "now" number). An empty key
// aggregates every ring.
func (v *monitorView) curKbps(key string) float64 {
	if key == "" {
		var sum float64
		for k := range v.rings {
			sum += v.curKbps(k)
		}
		return sum
	}
	r := v.rings[key]
	if r == nil {
		return 0
	}
	prev := (r.head - 1 + kbpsWindow) % kbpsWindow // the last COMPLETE second
	return r.bytes[prev] * 8 / 1000
}

// blockRate returns the dns block fraction over the window (0..1). An empty key
// aggregates every ring.
func (v *monitorView) blockRate(key string) float64 {
	var tot, blk float64
	fold := func(r *agentRing) {
		for i := 0; i < kbpsWindow; i++ {
			tot += r.dnsTotal[i]
			blk += r.dnsBlocked[i]
		}
	}
	if key == "" {
		for _, r := range v.rings {
			fold(r)
		}
	} else if r := v.rings[key]; r != nil {
		fold(r)
	}
	if tot <= 0 {
		return 0
	}
	return blk / tot
}

// lastBlockedTargets returns the most recent blocked qname and denied peer for a scope
// : key = one agent's ring, "" = the newest across EVERY ring (the (all) view).
// Empty strings mean none seen this session - the caller renders nothing (honest).
func (v *monitorView) lastBlockedTargets(key string) (qname, peer string) {
	var qUS, pUS int64
	fold := func(r *agentRing) {
		if r.lastBlockedQName != "" && r.lastBlockedUS >= qUS {
			qname, qUS = r.lastBlockedQName, r.lastBlockedUS
		}
		if r.lastDeniedPeer != "" && r.lastDeniedUS >= pUS {
			peer, pUS = r.lastDeniedPeer, r.lastDeniedUS
		}
	}
	if key == "" {
		for _, r := range v.rings {
			fold(r)
		}
	} else if r := v.rings[key]; r != nil {
		fold(r)
	}
	return qname, peer
}

// blockedTargetLine renders the WHAT-was-blocked summary line for the current scope
// or "" when nothing was blocked this session. The ✗ glyph carries the meaning
// (NO_COLOR-safe); red reinforces. Both targets show when both exist.
func (v *monitorView) blockedTargetLine(key string, iw int) string {
	qname, peer := v.lastBlockedTargets(key)
	if qname == "" && peer == "" {
		return ""
	}
	th := v.app.th
	parts := make([]string, 0, 2)
	if qname != "" {
		parts = append(parts, th.Error.Render("✗ dns ")+th.Text.Render(qname))
	}
	if peer != "" {
		parts = append(parts, th.Error.Render("✗ egress ")+th.Text.Render(peer))
	}
	return truncate(th.Dim.Render("  last blocked: ")+strings.Join(parts, th.Dim.Render(" · ")), iw)
}

// advance rolls every ring forward one bucket (called once per real second from the tick).
func (v *monitorView) advance() {
	for _, r := range v.rings {
		r.head = (r.head + 1) % kbpsWindow
		r.bytes[r.head] = 0
		r.conns[r.head] = 0
		r.dnsTotal[r.head] = 0
		r.dnsBlocked[r.head] = 0
	}
}

// focus narrows the monitor to one agent: it re-arms the backfill and (when the agent has
// a /128) restarts the SSE stream narrowed to that address server-side, so the picture is
// pinned to that one agent rather than tenant-wide-then-filtered. Focusing the same agent
// is a no-op (no connection churn). This is the ENTER action on the fleet.
func (v *monitorView) focus(a model.Agent) tea.Cmd {
	key := a.Key()
	if key == v.focused {
		return nil
	}
	v.focused = key
	v.backfilled = false
	v.app.feed.clear()
	v.app.lastEventUS = 0
	return tea.Batch(v.onEnter(), v.app.restartStreamNarrowed(v.narrowAddr()))
}

// unfocus returns to the tenant-wide view (restart the stream un-narrowed).
func (v *monitorView) unfocus() tea.Cmd {
	if v.focused == "" {
		return nil
	}
	v.focused = ""
	v.backfilled = false
	v.app.feed.clear()
	v.app.lastEventUS = 0
	return tea.Batch(v.onEnter(), v.app.restartStreamNarrowed(""))
}

// cycleKind advances the activity-feed kind filter (f): all -> dns -> conn -> alloc.
func (v *monitorView) cycleKind() string {
	next := map[string]string{"": "dns", "dns": "conn", "conn": "alloc", "alloc": ""}
	v.kindF = next[v.kindF]
	return orPlaceholder(v.kindF, "all")
}

// --- fleet aggregates --------------------------------------------------------------

// fleetTotals is the aggregate counter block: the sum of every agent's op:agent
// counters (authoritative cumulative totals, incl. TOTAL CONNECTIONS) plus the
// active/total membership counts.
type fleetTotals struct {
	DNS, Blocked       int64
	Conns              int64 // TOTAL CONNECTIONS (cumulative egress conns across the fleet)
	ConnsActive        int64
	BytesUp, BytesDown int64
	Agents, Active     int
}

func (a *App) fleetTotals() fleetTotals {
	var t fleetTotals
	t.Agents = len(a.agents)
	for _, ag := range a.agents {
		if ag.State == "active" {
			t.Active++
		}
		t.DNS += ag.DNSQueries
		t.Blocked += ag.DNSBlocked
		t.Conns += ag.ConnectionsTotal
		t.ConnsActive += ag.ConnectionsActive
		t.BytesUp += ag.BytesUp
		t.BytesDown += ag.BytesDown
	}
	return t
}

// --- the merged-dashboard monitor panel ---------------------------------------------

// panel renders the right half of the merged AGENTS dashboard: aggregate totals,
// the watched agent's stats, the braille throughput graph, and the live activity
// chain - all inside one titled panel whose header is the live heartbeat.
func (v *monitorView) panel(w, h int) string {
	th := v.app.th
	inner := h - 2
	if inner < 1 {
		inner = 1
	}
	iw := w - 4
	if iw < 20 {
		iw = 20
	}
	body := strings.Join(v.panelLines(iw, inner), "\n")
	p := th.Panel.Width(w - 2).Height(inner).Render(body)
	return v.app.titledPanel(p, v.app.liveTitle(), w)
}

// panelLines composes the panel body: exactly ih lines, each fitted to iw columns.
func (v *monitorView) panelLines(iw, ih int) []string {
	th := v.app.th
	var lines []string

	// 1. Fleet aggregates - the totals row leads with the numbers that matter, TOTAL
	//    CONNECTIONS among them, plus the live-session deltas underneath.
	t := v.app.fleetTotals()
	lines = append(lines, truncate(fmt.Sprintf("%s %s %s  %s %s  %s %s %s  %s ↑%s ↓%s",
		th.Accent.Render("Σ"),
		th.DNS.Render("dns"), th.Text.Render(components.Count(t.DNS)),
		th.Error.Render("blocked"), th.Text.Render(components.Count(t.Blocked)),
		th.Conn.Render("conn"), th.Text.Render(components.Count(t.Conns)),
		th.Dim.Render(fmt.Sprintf("(%s active)", components.Count(t.ConnsActive))),
		th.Dim.Render("bw"), components.Bytes(t.BytesUp), components.Bytes(t.BytesDown)), iw))
	lines = append(lines, truncate(th.Dim.Render(fmt.Sprintf(
		"  %d/%d agents active · live session +%s dns · +%s conn · +%s blocked",
		t.Active, t.Agents,
		components.Count(v.app.liveDNS), components.Count(v.app.liveConn),
		components.Count(v.app.liveBlocked))), iw))

	// 2. The watched agent (or the honest tenant-wide state).
	lines = append(lines, sectionDivider(v.scopeTitle(), iw, th))
	lines = append(lines, v.watchedLines(iw)...)

	// 3. Braille throughput graph, when there is room to keep a useful chain below.
	used := len(lines)
	graphH := 0
	if ih-used >= 14 {
		graphH = 6
	}
	if graphH > 0 {
		key := v.focused
		graphW := iw - 2
		if graphW > kbpsWindow/2 {
			graphW = kbpsWindow / 2 // never plot more dot-columns than the ring holds
		}
		var series []float64
		if key != "" {
			series = v.kbpsSeries(key, graphW*2)
		} else {
			series = v.aggregateSeries(graphW * 2)
		}
		graph := components.Braille(series, components.BrailleOpts{
			Width: graphW, Height: graphH, NoColor: th.NoColor, Unit: "kbps",
			Lo: th.FlowLo(), Mid: th.FlowMid(), Hi: th.FlowHi(),
			Axis: th.Dim, Label: th.Dim,
		})
		lines = append(lines, strings.Split(graph, "\n")...)
	}

	// 4. The live activity chain fills the rest.
	lines = append(lines, sectionDivider(v.chainTitle(), iw, th))
	rest := ih - len(lines)
	if rest < 1 {
		rest = 1
	}
	lines = append(lines, v.app.renderFeedLines(v.filteredRecent(rest), iw, rest)...)

	if len(lines) > ih {
		lines = lines[:ih]
	}
	for len(lines) < ih {
		lines = append(lines, "")
	}
	return lines
}

// scopeTitle names what the monitor is pinned to (the section divider label). The
// default selection is the explicit "(all)" - every agent, aggregated.
func (v *monitorView) scopeTitle() string {
	if v.focused == "" {
		return fmt.Sprintf("watching · (all) · %d agents", len(v.app.agents))
	}
	return "watching · " + components.ShortAddr(v.focused, 14, 8)
}

// watchedLines renders the watched agent's own stat block, or - the default - the
// explicit "(all)" selection: every agent's traffic aggregated, with the
// what-was-blocked line and the how-to-scope hint.
func (v *monitorView) watchedLines(iw int) []string {
	th := v.app.th
	key := v.focused
	if key == "" {
		lines := []string{
			truncate(fmt.Sprintf("%s  conn/min %s · now %s kbps · block %.0f%%",
				th.Accent.Render("▸ (all) agents"),
				th.Text.Render(components.Count(int64(v.connPerMin("")))),
				th.Text.Render(components.Count(int64(v.curKbps("")))),
				v.blockRate("")*100), iw),
		}
		if bl := v.blockedTargetLine("", iw); bl != "" {
			lines = append(lines, bl)
		}
		return append(lines,
			truncate(th.Dim.Render("  ↵ on an agent (or click it) to pin · a returns to (all)"), iw))
	}
	var ag model.Agent
	found := false
	for _, x := range v.app.agents {
		if x.Key() == key {
			ag, found = x, true
			break
		}
	}
	if !found {
		return []string{
			truncate(th.Accent.Render("▸ ")+th.Addr.Render(key), iw),
			truncate(th.Dim.Render("  (not in the fleet roster yet - counters pending)"), iw),
		}
	}
	head := th.Accent.Render("▸ "+ag.Name()) + "  " + th.Addr.Render(orPlaceholder(ag.Address, "(no /128)")) + "  " + stateBadge(th, ag.State)
	blk := fmt.Sprintf("%s (%.1f%%)", components.Count(ag.DNSBlocked), ag.BlockedPct())
	stat := fmt.Sprintf("  %s %s · %s %s · %s %s act / %s total · ↑%s ↓%s",
		th.DNS.Render("dns"), th.Text.Render(components.Count(ag.DNSQueries)),
		th.Error.Render("blocked"), th.Text.Render(blk),
		th.Conn.Render("conn"), th.Text.Render(components.Count(ag.ConnectionsActive)),
		th.Text.Render(components.Count(ag.ConnectionsTotal)),
		components.Bytes(ag.BytesUp), components.Bytes(ag.BytesDown))
	rates := fmt.Sprintf("  conn/min %s · now %s kbps · block %.0f%%",
		th.Text.Render(components.Count(int64(v.connPerMin(key)))),
		th.Text.Render(components.Count(int64(v.curKbps(key)))),
		v.blockRate(key)*100)
	if !ag.Detailed {
		stat = "  " + th.Dim.Render("loading counters...")
	}
	out := []string{truncate(head, iw), truncate(stat, iw), truncate(rates, iw)}
	// The focused scope names ITS most recent blocked targets too.
	if bl := v.blockedTargetLine(key, iw); bl != "" {
		out = append(out, bl)
	}
	return out
}

// chainTitle labels the activity section: the data source, the kind filter, and pause.
func (v *monitorView) chainTitle() string {
	f := orPlaceholder(v.kindF, "all")
	pause := ""
	if v.app.paused {
		pause = " · ⏸ paused"
	}
	return fmt.Sprintf("LIVE ACTIVITY · %s%s · filter:%s%s",
		v.app.source.glyph(), v.app.source.String(), f, pause)
}

// filteredRecent returns recent feed events filtered by the kind filter (over-fetch then
// filter so a sparse kind still fills the panel).
func (v *monitorView) filteredRecent(n int) []model.Event {
	all := v.app.feed.recent(n * 4)
	if v.kindF == "" {
		if len(all) > n {
			return all[:n]
		}
		return all
	}
	out := make([]model.Event, 0, n)
	for _, e := range all {
		if e.Kind == v.kindF {
			out = append(out, e)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}
