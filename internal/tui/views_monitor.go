// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/components"
)

// kbpsWindow is how many per-second buckets the per-agent rings keep — 4 minutes, enough
// to fill the braille hero graph (2 dot-columns per cell) on a wide terminal at one
// sample/second while staying tiny + bounded (~8 KiB/agent).
const kbpsWindow = 240

// agentRing holds rolling per-second buckets for one agent: total bytes (the kbps spark +
// the hero graph), conn-opens (the conn/min gauge), and dns total/blocked (the block-rate
// gauge). A fixed-size circular buffer ⇒ O(1) push, bounded memory, no allocation on the
// hot fold path. The 4Hz render tick advances the head once a real second (every 4th).
type agentRing struct {
	bytes      [kbpsWindow]float64 // per-second total bytes (up+down)
	conns      [kbpsWindow]float64 // per-second conn-open counts
	dnsTotal   [kbpsWindow]float64 // per-second dns query counts
	dnsBlocked [kbpsWindow]float64 // per-second dns blocked counts
	head       int                 // index of the current second's bucket
}

// monitorView is the full-screen MONITOR tab AND the always-on right panel source. It
// holds the per-agent rings (fed by every live/backfill/poll event) and renders the
// btop-grade picture: a braille hero graph for the focused agent, collapsed strips for the
// rest, value-mapped gauges, and the structured activity chain over the shared feed ring.
type monitorView struct {
	app        *App
	rings      map[string]*agentRing // keyed by agent Key()
	focused    string                // a focused agent Key() ("" = whole tenant)
	scrollY    int
	kindF      string // "", dns, conn, alloc cycle (f)
	backfilled bool   // the op:logs backfill has run for the current focus (re-armed on focus change)
}

func newMonitorView(app *App) *monitorView {
	return &monitorView{app: app, rings: map[string]*agentRing{}}
}

func (v *monitorView) resize(w, h int) {}

// onEnter seeds the monitor with an op:logs backfill (the hybrid §6.4: paint history,
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
// (empty = tenant-wide). The SSE narrow takes the address, not the id (§6.1).
func (v *monitorView) narrowAddr() string {
	if v.focused == "" {
		return ""
	}
	if strings.Contains(v.focused, ":") { // focused is a Key() — the /128 when known
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
// the hero graph + strips. Cheap, allocation-light, deterministic per ring state.
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
		out[i] = r.bytes[idx] * 8 / 1000 // bytes/s → kbps
	}
	return out
}

// connPerMin sums the conn-opens over the window (the conn/min gauge value).
func (v *monitorView) connPerMin(key string) float64 {
	r := v.rings[key]
	if r == nil {
		return 0
	}
	var sum float64
	for _, c := range r.conns {
		sum += c
	}
	return sum
}

// curKbps is the most-recent full second's kbps (the strip's "now" number).
func (v *monitorView) curKbps(key string) float64 {
	r := v.rings[key]
	if r == nil {
		return 0
	}
	prev := (r.head - 1 + kbpsWindow) % kbpsWindow // the last COMPLETE second
	return r.bytes[prev] * 8 / 1000
}

// blockRate returns the dns block fraction over the window (0..1) for the block-rate gauge.
func (v *monitorView) blockRate(key string) float64 {
	r := v.rings[key]
	if r == nil {
		return 0
	}
	var tot, blk float64
	for i := 0; i < kbpsWindow; i++ {
		tot += r.dnsTotal[i]
		blk += r.dnsBlocked[i]
	}
	if tot <= 0 {
		return 0
	}
	return blk / tot
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

func (v *monitorView) scroll(delta int) {
	v.scrollY += delta
	if v.scrollY < 0 {
		v.scrollY = 0
	}
}

func (v *monitorView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	switch k.String() {
	case " ", "space":
		app.paused = !app.paused
		if !app.paused {
			app.bufferedPause = 0
		}
		app.setToast(map[bool]string{true: "feed paused", false: "feed resumed"}[app.paused], false)
	case "f":
		next := map[string]string{"": "dns", "dns": "conn", "conn": "alloc", "alloc": ""}
		v.kindF = next[v.kindF]
		app.setToast("kind filter: "+orPlaceholder(v.kindF, "all"), false)
	case "c":
		app.feed.clear()
	case "s":
		// narrow the monitor to the AGENTS-selected agent (restarts the SSE pinned to its
		// /128 + re-backfills). Server-side narrow when it has an address.
		if sel, ok := app.SelectedAgent(); ok {
			cmd := v.focus(sel)
			app.setToast("watching "+sel.Name(), false)
			return app, cmd
		}
	case "a":
		if cmd := v.unfocus(); cmd != nil {
			app.setToast("watching the whole tenant", false)
			return app, cmd
		}
	case "j", "down":
		v.scroll(1)
	case "k", "up":
		v.scroll(-1)
	case "enter":
		return app.openDrillEvent(v.topEvent())
	}
	return app, nil
}

// focus narrows the monitor to one agent: it re-arms the backfill and (when the agent has
// a /128) restarts the SSE stream narrowed to that address server-side, so the picture is
// pinned to that one agent rather than tenant-wide-then-filtered. Focusing the same agent
// is a no-op (no connection churn).
func (v *monitorView) focus(a model.Agent) tea.Cmd {
	key := a.Key()
	if key == v.focused {
		return nil
	}
	v.focused = key
	v.backfilled = false
	v.scrollY = 0
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

// topEvent returns the most-recent feed event (for drill on Enter).
func (v *monitorView) topEvent() (model.Event, bool) {
	r := v.app.feed.recent(1)
	if len(r) == 0 {
		return model.Event{}, false
	}
	return r[0], true
}

// --- render ----------------------------------------------------------------------

// view renders the full-screen MONITOR tab: a HERO band (the braille graph for the
// focused agent + value-mapped gauges) over the STRIPS band (collapsed per-agent rows)
// over the CHAIN band (the structured activity feed). Each band degrades gracefully on a
// short terminal; the whole frame is sample-and-render (no per-event work here).
func (v *monitorView) view(w, h int) string {
	th := v.app.th

	heroH := h * 40 / 100
	if heroH < 7 {
		heroH = 7
	}
	if heroH > 16 {
		heroH = 16
	}
	stripsH := h * 22 / 100
	if stripsH < 3 {
		stripsH = 3
	}
	chainH := h - heroH - stripsH
	if chainH < 3 {
		// Reclaim from the hero band on a short terminal so the chain is never starved.
		chainH = 3
		heroH = h - stripsH - chainH
		if heroH < 5 {
			heroH = 5
			stripsH = h - heroH - chainH
			if stripsH < 1 {
				stripsH = 1
			}
		}
	}

	hero := v.renderHero(w, heroH)
	strips := v.renderStrips(w, stripsH)
	chain := v.renderChainPanel(w, chainH)
	_ = th
	return lipgloss.JoinVertical(lipgloss.Left, hero, strips, chain)
}

// renderHero is the top band: the braille kbps-over-time graph for the FOCUSED agent (or
// the tenant aggregate when unfocused), flanked by value-mapped gauges (conn/min,
// bandwidth-now, block-rate). The graph is the showpiece — the btop glow over time.
func (v *monitorView) renderHero(w, h int) string {
	th := v.app.th
	inner := h - 2
	if inner < 3 {
		inner = 3
	}

	gaugeW := 26
	if w < 70 {
		gaugeW = 0 // too narrow — graph only
	}
	graphW := w - 4 - gaugeW
	if graphW < 10 {
		graphW = w - 4
	}
	// Never plot more dot-columns than the ring holds samples (2 dots per cell): an
	// over-wide plot left-pads with permanent zeros — a structurally dead left half.
	if graphW > kbpsWindow/2 {
		graphW = kbpsWindow / 2
	}

	key, label := v.heroTarget()
	series := v.heroSeries(key, graphW*2) // 2 samples per cell wide (braille resolution)

	graph := components.Braille(series, components.BrailleOpts{
		Width: graphW, Height: inner, NoColor: th.NoColor, Unit: "kbps",
		Lo: th.FlowLo(), Mid: th.FlowMid(), Hi: th.FlowHi(),
		Axis: th.Dim, Label: th.Dim,
	})

	body := graph
	if gaugeW > 0 {
		body = lipgloss.JoinHorizontal(lipgloss.Top, graph, "  ", v.renderGauges(key, gaugeW-2, inner))
	}

	panel := th.Panel.Width(w - 2).Height(inner).Render(body)
	return v.app.titledPanel(panel, v.heroTitle(label), w)
}

// heroTarget picks the agent the hero graph + gauges describe: the focused agent, else the
// busiest agent, else the tenant aggregate.
func (v *monitorView) heroTarget() (key, label string) {
	if v.focused != "" {
		return v.focused, components.ShortAddr(v.focused, 14, 8)
	}
	// busiest by conn/min
	var bestKey string
	var best float64 = -1
	for _, a := range v.app.agents {
		if c := v.connPerMin(a.Key()); c > best {
			best, bestKey = c, a.Key()
		}
	}
	if bestKey != "" && best > 0 {
		return bestKey, "busiest · " + components.ShortAddr(bestKey, 12, 6)
	}
	return "", "tenant (all agents)"
}

// heroSeries returns the kbps series for the hero target. For the tenant aggregate (no
// focus / no busiest) it sums every agent's series so the graph is never dead when there
// is activity somewhere.
func (v *monitorView) heroSeries(key string, n int) []float64 {
	if key != "" {
		return v.kbpsSeries(key, n)
	}
	// aggregate across all rings
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

// renderGauges renders the value-mapped gauge stack beside the hero graph: conn/min,
// bandwidth-now, and block-rate — each green→amber→red by load, glyph-labelled so colour
// is never the only signal. It emits EXACTLY h lines, each ≤ w columns, so the horizontal
// join with the (taller) graph aligns row-by-row with no wrapping or stray-line artefacts.
func (v *monitorView) renderGauges(key string, w, h int) string {
	th := v.app.th
	if w < 8 {
		return ""
	}
	barW := w - 8 // leave room for the trailing value
	if barW < 4 {
		barW = 4
	}
	cm := v.connPerMin(key)
	kbps := v.curKbps(key)
	br := v.blockRate(key)

	gauge := func(val, max float64) string {
		return components.GaugeGrad(val, max, barW, th.NoColor,
			th.LoadLo(), th.LoadMid(), th.LoadHi(), th.BorderColor())
	}

	var lines []string
	add := func(label, valLine string) {
		lines = append(lines, th.Dim.Render(label), valLine, "")
	}
	add("conn/min", gauge(cm, 60)+" "+th.Text.Render(components.Count(int64(cm))))
	add("kbps now", gauge(kbps, gaugeKbpsMax(kbps))+" "+th.Text.Render(components.Count(int64(kbps))))
	add("block-rate", gauge(br*100, 100)+" "+th.Text.Render(fmt.Sprintf("%.0f%%", br*100)))

	// Pad/clamp to exactly h lines so JoinHorizontal lines up with the graph.
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

// gaugeKbpsMax picks a sensible full-scale for the bandwidth gauge so a quiet agent's bar
// isn't pinned and a busy one isn't clipped (a soft auto-range).
func gaugeKbpsMax(cur float64) float64 {
	switch {
	case cur < 100:
		return 100
	case cur < 1000:
		return 1000
	case cur < 10000:
		return 10000
	default:
		return cur * 1.2
	}
}

// renderStrips is the middle band: one collapsed row per agent (name · kbps spark · conn
// gauge · block-rate), the focused agent marked. Sorted busiest-first so the active ones
// are always on top.
func (v *monitorView) renderStrips(w, h int) string {
	th := v.app.th
	inner := h - 2
	if inner < 1 {
		inner = 1
	}
	rows := v.stripRows(w-4, inner)
	body := strings.Join(rows, "\n")
	panel := th.Panel.Width(w - 2).Height(inner).Render(body)
	return v.app.titledPanel(panel, v.stripsTitle(), w)
}

// stripRows builds up to `max` per-agent strips, busiest-first, each: a focus marker, the
// name, a value-mapped kbps sparkline, the current kbps, and a tiny conn-gauge.
func (v *monitorView) stripRows(w, max int) []string {
	th := v.app.th
	type ent struct {
		a    model.Agent
		traf float64
	}
	var ents []ent
	for _, a := range v.app.agents {
		ents = append(ents, ent{a, v.connPerMin(a.Key()) + v.curKbps(a.Key())})
	}
	if len(ents) == 0 {
		return []string{th.Dim.Render(truncate(
			"no agents yet — every agent that resolves or connects appears here live", w))}
	}
	// busiest first
	for i := 1; i < len(ents); i++ {
		for j := i; j > 0 && ents[j].traf > ents[j-1].traf; j-- {
			ents[j], ents[j-1] = ents[j-1], ents[j]
		}
	}
	sparkW := clamp(w/4, 8, 28)
	out := make([]string, 0, max)
	for i, e := range ents {
		if i >= max {
			break
		}
		key := e.a.Key()
		marker := " "
		nameStyle := th.Text
		if key == v.focused {
			marker = th.Accent.Render("▸")
			nameStyle = th.Accent
		}
		name := nameStyle.Render(padTrunc(e.a.Name(), 16))
		spark := components.SparklineGradient(v.kbpsSeries(key, sparkW), sparkW, th.NoColor,
			th.FlowLo(), th.FlowMid(), th.FlowHi())
		kbps := th.Text.Render(padTrunc(components.Count(int64(v.curKbps(key)))+" kbps", 9))
		cm := v.connPerMin(key)
		cg := components.GaugeGrad(cm, 60, 10, th.NoColor,
			th.LoadLo(), th.LoadMid(), th.LoadHi(), th.BorderColor())
		br := v.blockRate(key)
		blk := th.Dim.Render("")
		if br > 0 {
			blk = th.Error.Render(fmt.Sprintf("✗%.0f%%", br*100))
		}
		line := fmt.Sprintf("%s %s %s %s %s %s %s",
			marker, name, spark, kbps, th.Dim.Render("conn"), cg, blk)
		out = append(out, truncate(line, w))
	}
	for len(out) < max {
		out = append(out, "")
	}
	return out
}

// renderChainPanel is the bottom band: the structured activity chain over the shared feed
// ring (filtered by the kind filter), newest first, with the new-row flash-in (motion).
func (v *monitorView) renderChainPanel(w, h int) string {
	th := v.app.th
	inner := h - 2
	if inner < 1 {
		inner = 1
	}
	events := v.filteredRecent(inner)
	lines := v.app.renderFeedLines(events, w-4, inner)
	panel := th.Panel.Width(w - 2).Height(inner).Render(strings.Join(lines, "\n"))
	return v.app.titledPanel(panel, v.chainTitle(), w)
}

// --- titles ----------------------------------------------------------------------

func (v *monitorView) heroTitle(label string) string {
	return fmt.Sprintf("◈ THROUGHPUT · %s · kbps/%dmin", label, kbpsWindow/60)
}

func (v *monitorView) stripsTitle() string {
	scope := "tenant-wide"
	if v.focused != "" {
		scope = "watching " + components.ShortAddr(v.focused, 10, 6)
	}
	return fmt.Sprintf("AGENTS · %d · %s", len(v.app.agents), scope)
}

func (v *monitorView) chainTitle() string {
	f := orPlaceholder(v.kindF, "all")
	pause := ""
	if v.app.paused {
		pause = "  ⏸"
	}
	return fmt.Sprintf("● LIVE ACTIVITY  client_src ─▶ qname ─▶ peer · %s · filter:%s%s",
		v.app.source.glyph()+v.app.source.String(), f, pause)
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
