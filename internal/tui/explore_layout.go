// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/tui/components"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// This file is the PURE, no-I/O ASCII engine for the EXPLORE view. Every function is
// deterministic (golden-testable), width-clamped, and returns exactly the requested
// height in lines. Nothing here touches the network or the clock. The constellation is
// ornament (never load-bearing): the same data always renders as the Miller-column list,
// and under ~90 cols or NO_COLOR the ornament drops entirely for a plain hub line + list.

// --- small width-safe text helpers -----------------------------------------------------

// padRight fits s to EXACTLY w visible columns: truncate (ANSI-safe) when too long,
// right-pad with spaces when short. It is the load-bearing primitive that keeps every
// grid row and column body a fixed footprint so borders never go ragged.
func padRight(s string, w int) string {
	if w <= 0 {
		return ""
	}
	vw := lipgloss.Width(s)
	if vw == w {
		return s
	}
	if vw > w {
		return truncate(s, w)
	}
	return s + strings.Repeat(" ", w-vw)
}

// fitBlock pads every line to width w and pads/clamps the slice to exactly h lines.
func fitBlock(lines []string, w, h int) []string {
	out := make([]string, 0, h)
	for i := 0; i < h; i++ {
		if i < len(lines) {
			out = append(out, padRight(lines[i], w))
		} else {
			out = append(out, strings.Repeat(" ", w))
		}
	}
	return out
}

// magBar is a log-scaled 5-cell magnitude bar for an edge-type degree. Log scale so a
// four-edge type and a 1.2M-edge type both read at a glance without the big one pinning
// every small one to empty.
func magBar(total, maxTotal int64, cells int, th *theme.Theme) string {
	if cells <= 0 {
		return ""
	}
	fill := 0
	ratio := 0.0
	if total > 0 && maxTotal > 0 {
		lt := math.Log1p(float64(total))
		lm := math.Log1p(float64(maxTotal))
		if lm > 0 {
			ratio = lt / lm
			fill = int(math.Round(ratio * float64(cells)))
		}
	}
	if fill < 1 && total > 0 {
		fill = 1
	}
	if fill > cells {
		fill = cells
	}
	// The filled cells brighten with the log-degree (dim -> steel -> bright cyan) so the
	// mega fan-out lane visibly dominates; the empty track stays dim. Colour off -> both dim,
	// and the bar reads by its filled-cell count exactly as before.
	return barFillStyle(th, ratio).Render(strings.Repeat("▓", fill)) +
		th.Dim.Render(strings.Repeat("░", cells-fill))
}

// sectionDivider draws a labelled rule inside a column: a short dash, the label, then a
// dash fill to width w (the k9s/btop inline-section look).
func sectionDivider(label string, w int, th *theme.Theme) string {
	if w < 4 {
		return th.Dim.Render(strings.Repeat("─", maxInt(w, 0)))
	}
	head := "─ " + label + " "
	hw := lipgloss.Width(head)
	if hw > w {
		head = truncate(head, w)
		hw = lipgloss.Width(head)
	}
	return th.Dim.Render(head + strings.Repeat("─", w-hw))
}

// --- TRAIL rail + minimap ---------------------------------------------------------------

// renderTrailRail draws the breadcrumb spine down the left column: the nodes you have
// walked (hollow) leading to where you stand (filled), then the minimap, then depth/pins.
func renderTrailRail(deck deckState, pins, w, h int, th *theme.Theme) []string {
	var lines []string
	path := append(append([]graphNode{}, deck.trail...), deck.focus)
	for i, n := range path {
		cur := i == len(path)-1
		dot := th.Dim.Render("○")
		nameStyle := th.Dim
		if cur {
			dot = th.Accent.Render("●")
			nameStyle = th.Text
		}
		lines = append(lines, dot+" "+nameStyle.Render(padRight(shortValue(n.Value, w-2), maxInt(w-2, 1))))
		// Tint the glyph by node type; keep the label dim (the trail is meta, so the type
		// hue is a quiet reinforcement, not a shout).
		typeLine := styledGlyphs(th, n.Labels) + th.Dim.Render(" "+primaryLabel(n.Labels))
		lines = append(lines, "  "+padRight(typeLine, maxInt(w-2, 1)))
	}
	if len(deck.trail) == 0 {
		lines = append(lines, th.Dim.Render("(start)"))
	}
	lines = append(lines, "")

	// The minimap is honest orientation (trail path + pins), never fake XY coordinates.
	mm := renderMinimap(deck, pins, w, 5, th)
	lines = append(lines, mm...)
	lines = append(lines, "")
	lines = append(lines, th.Dim.Render("depth ")+th.Text.Render(itoa(len(deck.trail))))
	pinStr := itoa(pins)
	if pins > 0 {
		pinStr += " ★"
	}
	lines = append(lines, th.Dim.Render("pins  ")+th.Text.Render(pinStr))
	return fitBlock(lines, w, h)
}

// renderMinimap draws a tiny grid showing WHERE you stand among your pins and trail. It
// uses NO invented coordinates: the current node sits centre, trail nodes stack above it,
// pins mark the edges. It is orientation, not a map of the 3.67B-node graph.
func renderMinimap(deck deckState, pins, w, h int, th *theme.Theme) []string {
	iw := w
	if iw > 11 {
		iw = 11
	}
	if iw < 5 {
		iw = 5
	}
	gh := h - 2 // minus the top+bottom rule
	if gh < 1 {
		gh = 1
	}
	grid := make([][]rune, gh)
	for r := range grid {
		grid[r] = []rune(strings.Repeat(" ", iw))
	}
	cx := iw / 2
	cy := gh - 1 // current stands at the bottom-centre
	set := func(y, x int, ch rune) {
		if y >= 0 && y < gh && x >= 0 && x < iw {
			grid[y][x] = ch
		}
	}
	// trail nodes climb up the centre column above the current position.
	depth := len(deck.trail)
	for i := 0; i < depth && i < gh-1; i++ {
		set(cy-1-i, cx, '◉')
	}
	// pins fan to the sides (honest markers, deterministic placement).
	for i := 0; i < pins; i++ {
		off := (i % (iw / 2)) + 1
		side := 1
		if i%2 == 1 {
			side = -1
		}
		set(cy-1, cx+side*off, '★')
	}
	set(cy, cx, '◉') // your current position: the ring at centre-bottom baseline

	top := th.Dim.Render("┌ minimap " + strings.Repeat("─", maxInt(iw-9, 0)) + "┐")
	bot := th.Dim.Render("└" + strings.Repeat("─", iw) + "┘")
	out := []string{top}
	for _, row := range grid {
		out = append(out, th.Dim.Render("│")+th.Text.Render(string(row))+th.Dim.Render("│"))
	}
	out = append(out, bot)
	return out
}

// --- EDGES pane -------------------------------------------------------------------------

// renderEdgePane lists EVERY edge type off the focus with its TRUE total count and a
// log-scaled magnitude bar. The active edge type carries the diamond gutter tick. This is
// the truth of the deck; the constellation is only a picture of it.
func renderEdgePane(edges []edgeGroup, curIdx, w, h int, th *theme.Theme) []string {
	var maxTotal int64
	countW := 1
	for _, e := range edges {
		if e.Total > maxTotal {
			maxTotal = e.Total
		}
		if cw := len(humanCommas(e.Total)); cw > countW {
			countW = cw
		}
	}
	barW := 5
	// budget: gutter(1) + dir(1) + space(1) + name + space(1) + count + space(1) + bar(5)
	nameW := w - countW - (barW + 5)
	if nameW < 8 {
		nameW = 8
	}
	var lines []string
	for i, e := range edges {
		if i >= h {
			break
		}
		gutter := " "
		nameStyle := th.Text
		if i == curIdx {
			gutter = th.Accent.Render("◆")
			nameStyle = th.Accent
		}
		name := e.Type
		if e.Capped {
			name = "╳ " + name
		}
		countStr := humanCommas(e.Total)
		row := gutter + th.Dim.Render(dirGlyph(e.Dir)) + " " +
			nameStyle.Render(padRight(name, nameW)) + " " +
			th.Text.Render(padLeftPlain(countStr, countW)) + " " +
			magBar(e.Total, maxTotal, barW, th)
		lines = append(lines, row)
	}
	return fitBlock(lines, w, h)
}

// --- NEIGHBORS pane ---------------------------------------------------------------------

// renderNeighborPane lists the sampled neighbours of the active edge type. Each row is a
// walkable node: value, its stacked glyphs, and its threat tag (glyph + word). The active
// neighbour carries the gutter tick only when this pane is the active one.
func renderNeighborPane(edge edgeGroup, nbrCur int, active bool, w, h int, th *theme.Theme) []string {
	var lines []string
	if len(edge.Sample) == 0 {
		lines = append(lines, th.Dim.Render("(no sampled neighbours)"))
		return fitBlock(lines, w, h)
	}
	// budget: gutter(1)+dir(1)+space(1) + value + space(1) + glyphs(2) + space(1) + tag
	tagW := 9
	glyphW := 2
	valW := w - 5 - glyphW - tagW
	if valW < 8 {
		valW = 8
	}
	for i, n := range edge.Sample {
		if i >= h {
			break
		}
		gutter := " "
		if active && i == nbrCur {
			gutter = th.Accent.Render("◆")
		}
		bstyle, bglyph := styleForBand(th, n.Band)
		tag := bstyle.Render(bglyph + " " + bandTag(n.Band, n.Labels))
		row := gutter + th.Dim.Render(dirGlyph(edge.Dir)) + " " +
			th.Text.Render(padRight(n.Value, valW)) + " " +
			padRight(styledGlyphs(th, n.Labels), glyphW) + " " +
			tag
		lines = append(lines, row)
	}
	return fitBlock(lines, w, h)
}

// --- FOCUS identity card ----------------------------------------------------------------

// renderIdentityCard is the FOCUS dossier: type + band on the head line, the canonical
// value, the descriptor sub-line, then props / identify / assess. A sparse node renders a
// calm honest state ("little is known ... honest, not broken"), never a blank pane.
func renderIdentityCard(focus graphNode, w, h int, th *theme.Theme) []string {
	bstyle, bglyph := styleForBand(th, focus.Band)
	// The glyph + type word carry the node TYPE (its hue); the value below carries FOCUS
	// (the accent). Two orthogonal signals, never fighting for the same colour.
	var typeLbl string
	if len(focus.Labels) > 0 {
		typeLbl = nodeHue(th, focus.Labels[0]).Render(primaryLabel(focus.Labels))
	} else {
		typeLbl = th.Dim.Render(primaryLabel(focus.Labels))
	}
	head := styledGlyphs(th, focus.Labels) + "  " + typeLbl + "  " +
		bstyle.Render(bglyph+" "+bandWord(focus.Band, focus.Labels))
	lines := []string{
		head,
		th.Accent.Render(focus.Value),
	}
	if sub := subOf(focus); sub != "" {
		lines = append(lines, th.Dim.Render(sub))
	}
	lines = append(lines, "")

	id := focus.Ident
	sparse := id == nil && strings.EqualFold(focus.Band, "UNKNOWN")

	// props line.
	if p := propsLine(focus); p != "" {
		lines = append(lines, th.Dim.Render("props    ")+th.Text.Render(p))
	}
	// identify line.
	if id != nil && id.Vendor != "" {
		roles := strings.Join(id.Roles, "·")
		il := id.Vendor
		if roles != "" {
			il += " · roles " + roles
		}
		lines = append(lines, th.Dim.Render("identify ")+th.Text.Render(il))
	} else {
		lines = append(lines, th.Dim.Render("identify ")+th.Dim.Render("no vendor on record"))
	}
	// assess line.
	if focus.Band != "" {
		cov := 0.0
		feeds := 0
		covWord := ""
		if id != nil {
			cov, feeds, covWord = id.Coverage, id.Feeds, id.CovWord
		}
		var tail string
		if covWord != "" {
			// the live graph reports coverage as a WORD; render it verbatim.
			tail = "  coverage " + covWord + " · " + itoa(feeds) + " evidence"
		} else {
			tail = "  coverage " + ftoa(cov) + " · " + itoa(feeds) + " feeds"
		}
		assess := bstyle.Render(bglyph+" "+bandWord(focus.Band, focus.Labels)) + th.Dim.Render(tail)
		lines = append(lines, th.Dim.Render("assess   ")+assess)
	}

	if sparse {
		lines = append(lines, "")
		lines = append(lines, th.Warn.Render("ℹ sparse node: little is known. This is honest,"))
		lines = append(lines, th.Dim.Render("  not broken. Try:  o catalog · : custom Cypher"))
	}
	return fitBlock(lines, w, h)
}

// --- the FOCUS ornament: constellation / bipartite / cluster ---------------------------

// renderConstellation draws the deterministic radial orrery: the focus at centre, the
// top-6 edge types placed in FIXED compass slots (never free placement), log-scaled
// spokes, and a "+k more" spoke for the rest. Over-cap edges render as a severed stub.
// It is ORNAMENT: it returns nil when there is no room, and the deck stays fully usable.
func renderConstellation(focus graphNode, edges []edgeGroup, curIdx, w, h int, th *theme.Theme) []string {
	if w < 30 || h < 6 {
		return nil
	}
	g := newCharGrid(w, h)
	rc, cc := h/2, w/2

	// centre: the focus glyph over a short value.
	g.putText(rc, cc-1, glyphsFor(focus.Labels), gkCenter)
	sv := shortValue(focus.Value, w/2)
	g.putText(rc+1, cc-lipgloss.Width(sv)/2, sv, gkCenter)

	// 8 fixed compass slots (deterministic slot -> position + text justification).
	type slot struct {
		r, c int
		just int // -1 left, 0 centre, 1 right
	}
	slots := []slot{
		{1, cc, 0},        // N
		{h / 2, w - 2, 1}, // E
		{h - 2, cc, 0},    // S
		{h / 2, 1, -1},    // W
		{h / 5, w - 2, 1}, // NE
		{h - 2, 1, -1},    // SW
		{h - 2, w - 2, 1}, // SE
		{h / 5, 1, -1},    // NW
	}
	top := edges
	if len(top) > 6 {
		top = edges[:6]
	}
	for i, e := range top {
		s := slots[i%len(slots)]
		label := edgeAbbrev(e.Type) + " " + dirGlyph(e.Dir) + components.Count(e.Total)
		kind := gkLabel
		if i == curIdx {
			kind = gkActive
		}
		if e.Capped {
			// severed stub: a ballot-x near the centre-facing side + the label.
			label = "╳ " + edgeAbbrev(e.Type) + " " + components.Count(e.Total)
			kind = gkSever
		} else {
			// spoke from centre toward the slot (stop short so it never hits the label).
			tr := rc + (s.r-rc)*3/5
			tcc := cc + (s.c-cc)*3/5
			g.line(rc, cc, tr, tcc)
		}
		lc := s.c
		switch s.just {
		case 1:
			lc = s.c - lipgloss.Width(label) + 1
		case 0:
			lc = s.c - lipgloss.Width(label)/2
		}
		g.putText(s.r, lc, label, kind)
	}
	if len(edges) > 6 {
		more := "+" + itoa(len(edges)-6) + " more"
		g.putText(h-2, cc-lipgloss.Width(more)/2, more, gkLabel)
	}
	return g.render(th)
}

// renderBipartiteHub is the ASN / PREFIX layout: inbound references on the left, the hub
// centred, originated / outbound on the right, joined by straight lanes. Zero crossings,
// which is exactly why a hub type does not use the radial orrery.
func renderBipartiteHub(focus graphNode, edges []edgeGroup, curIdx, w, h int, th *theme.Theme) []string {
	if w < 30 || h < 6 {
		return nil
	}
	var inbound, outbound []edgeGroup
	for _, e := range edges {
		if e.Dir < 0 {
			inbound = append(inbound, e)
		} else {
			outbound = append(outbound, e)
		}
	}
	colW := (w - 6) / 2
	if colW < 8 {
		colW = 8
	}
	var lines []string
	lines = append(lines, th.Dim.Render(padRight("inbound ◂", colW))+"      "+th.Dim.Render("▸ originated"))
	rows := maxInt(len(inbound), len(outbound))
	mid := rows / 2
	for i := 0; i < rows; i++ {
		l, r := "", ""
		if i < len(inbound) {
			l = edgeAbbrev(inbound[i].Type) + " " + components.Count(inbound[i].Total)
		}
		if i < len(outbound) {
			r = edgeAbbrev(outbound[i].Type) + " " + components.Count(outbound[i].Total)
		}
		center := "  "
		if i == mid {
			center = th.Accent.Render("◈")
		}
		lines = append(lines, th.Text.Render(padRight(l, colW))+" "+center+" ══ "+th.Text.Render(r))
	}
	// the hub value under the fan.
	lines = append(lines, "")
	lines = append(lines, "     "+th.Accent.Render(glyphsFor(focus.Labels)+" "+focus.Value))
	return fitBlock(lines, w, h)
}

// clusterCollapse renders each edge lane as a single density-shaded blob (the z toggle):
// one honest line per type, no per-neighbour rows. It collapses a mega fan-out to
// "IPV4 x1.24M" plus a shade bar rather than pretending to draw 1.24M nodes.
func clusterCollapse(edges []edgeGroup, w, h int, th *theme.Theme) []string {
	var maxTotal int64
	for _, e := range edges {
		if e.Total > maxTotal {
			maxTotal = e.Total
		}
	}
	var lines []string
	lines = append(lines, th.Dim.Render("cluster view (z) · one blob per lane"))
	lines = append(lines, "")
	for i, e := range edges {
		if i >= h-2 {
			break
		}
		blob := magBar(e.Total, maxTotal, 10, th)
		line := th.Text.Render(padRight(edgeAbbrev(e.Type)+" ×"+components.Count(e.Total), 22)) + " " + blob
		lines = append(lines, line)
	}
	return fitBlock(lines, w, h)
}

// --- the char grid (deterministic per-cell raster with a parallel kind grid) -----------

type gridKind byte

const (
	gkEmpty gridKind = iota
	gkSpoke
	gkLabel
	gkCenter
	gkActive
	gkSever
)

// charGrid is a tiny raster: a rune per cell plus a KIND per cell, so the renderer can
// colour spokes, labels, the centre, and severed stubs distinctly. Higher-kind writes win
// (a label overwrites a spoke; a spoke never overwrites a label).
type charGrid struct {
	w, h  int
	runes [][]rune
	kind  [][]gridKind
}

func newCharGrid(w, h int) *charGrid {
	g := &charGrid{w: w, h: h, runes: make([][]rune, h), kind: make([][]gridKind, h)}
	for r := 0; r < h; r++ {
		g.runes[r] = []rune(strings.Repeat(" ", w))
		g.kind[r] = make([]gridKind, w)
	}
	return g
}

func (g *charGrid) set(r, c int, ch rune, k gridKind) {
	if r < 0 || r >= g.h || c < 0 || c >= g.w {
		return
	}
	if k < g.kind[r][c] {
		return // never demote a higher-kind cell
	}
	g.runes[r][c] = ch
	g.kind[r][c] = k
}

func (g *charGrid) putText(r, c int, s string, k gridKind) {
	for _, ch := range s {
		if ch == ' ' {
			c++
			continue
		}
		g.set(r, c, ch, k)
		c++
	}
}

// line rasterises a spoke from (r0,c0) toward (r1,c1) choosing the box-drawing glyph by
// the local dominant axis; it never overwrites a label or the centre.
func (g *charGrid) line(r0, c0, r1, c1 int) {
	dr, dc := r1-r0, c1-c0
	steps := maxInt(absInt(dr), absInt(dc))
	if steps == 0 {
		return
	}
	glyph := '─'
	switch {
	case dc == 0:
		glyph = '│'
	case dr == 0:
		glyph = '─'
	case dr*dc > 0:
		glyph = '╲'
	default:
		glyph = '╱'
	}
	for i := 1; i < steps; i++ {
		r := r0 + dr*i/steps
		c := c0 + dc*i/steps
		g.set(r, c, glyph, gkSpoke)
	}
}

// render turns the grid into styled lines, grouping consecutive same-kind runs so each
// kind gets its style in one styled span (spoke=dim, label=text, centre/active=accent,
// sever=error). Colour merely reinforces; the glyphs already carry the meaning.
func (g *charGrid) render(th *theme.Theme) []string {
	styleFor := func(k gridKind) lipgloss.Style {
		switch k {
		case gkSpoke:
			return th.Dim
		case gkLabel:
			return th.Text
		case gkCenter, gkActive:
			return th.Accent
		case gkSever:
			return th.Error
		default:
			return th.Dim
		}
	}
	out := make([]string, g.h)
	for r := 0; r < g.h; r++ {
		var b strings.Builder
		c := 0
		for c < g.w {
			k := g.kind[r][c]
			start := c
			for c < g.w && g.kind[r][c] == k {
				c++
			}
			run := string(g.runes[r][start:c])
			if k == gkEmpty {
				b.WriteString(run)
			} else {
				b.WriteString(styleFor(k).Render(run))
			}
		}
		out[r] = b.String()
	}
	return out
}

// --- tiny local helpers (no fmt on the hot render path) --------------------------------

func padLeftPlain(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return strings.Repeat(" ", w-len(s)) + s
}

func shortValue(v string, w int) string {
	if w < 4 {
		w = 4
	}
	r := []rune(v)
	if len(r) <= w {
		return v
	}
	return components.ShortAddr(v, w-6, 5)
}

func primaryLabel(labels []string) string {
	if len(labels) == 0 {
		return "NODE"
	}
	return strings.ToUpper(labels[0])
}

func edgeAbbrev(t string) string {
	if len(t) <= 12 {
		return t
	}
	return string([]rune(t)[:11]) + "…"
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func itoa(n int) string {
	return intToStr(int64(n))
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ftoa renders a coverage fraction as a compact two-decimal string (0.98) with no fmt.
func ftoa(f float64) string {
	if f <= 0 {
		return "0"
	}
	whole := int(f)
	frac := int(math.Round((f-float64(whole))*100)) % 100
	fs := intToStr(int64(frac))
	if len(fs) < 2 {
		fs = "0" + fs
	}
	return intToStr(int64(whole)) + "." + fs
}
