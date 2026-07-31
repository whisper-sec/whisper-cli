// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/tui/components"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// This file composes the EXPLORE frame from the pure layout primitives: the three-column
// DECK (TRAIL | FOCUS | EDGES -> NEIGHBORS | preview), the breadcrumb strip, the CATALOG /
// JUMP / REPL overlay shells, and the type-aware RESULT card renderers. It reuses the
// existing theme Panel + titledPanel idioms, so EXPLORE matches the other five views.

// exploreColumns splits the body width into the three DECK columns (outer widths that sum
// to w exactly). It shrinks the rails first so the FOCUS pane keeps a usable width.
func exploreColumns(w int) (trailW, focusW, edgesW int) {
	trailW, edgesW = 16, 36
	switch {
	case w < 74:
		trailW, edgesW = 12, 28
	case w < 90:
		trailW, edgesW = 14, 32
	case w < 104:
		trailW, edgesW = 15, 34
	}
	focusW = w - trailW - edgesW
	if focusW < 24 {
		if take := min(24-focusW, edgesW-22); take > 0 {
			edgesW -= take
			focusW += take
		}
		if take := min(24-focusW, trailW-11); take > 0 {
			trailW -= take
			focusW += take
		}
	}
	if focusW < 10 {
		focusW = 10 // last-ditch: the App MaxWidth clamp catches any overflow
	}
	return trailW, focusW, edgesW
}

// renderDeck is the primary EXPLORE frame: the breadcrumb over the three Miller columns,
// with an optional REPL bar folded in at the bottom.
func (v *exploreView) renderDeck(w, h int) string {
	th := v.app.th
	replRows := 0
	if v.ov == ovRepl {
		replRows = 2
	}
	bc := v.renderBreadcrumb(w)
	colH := h - 1 - replRows
	if colH < 4 {
		colH = 4
	}
	trailW, focusW, edgesW := exploreColumns(w)

	trailBody := renderTrailRail(v.deck, len(v.pins), trailW-4, colH-2, th)
	var focusBody []string
	if v.degraded {
		focusBody = fitBlock(v.renderOutageBanner(focusW-4), focusW-4, colH-2)
	} else {
		focusBody = v.renderFocusColumn(focusW-4, colH-2)
	}
	edgesBody := v.renderRightColumn(edgesW-4, colH-2)

	trailPanel := v.app.titledPanel(
		th.Panel.Width(trailW-2).Height(colH-2).Render(strings.Join(trailBody, "\n")), "TRAIL", trailW)
	focusPanel := v.app.titledPanel(
		th.Panel.Width(focusW-2).Height(colH-2).Render(strings.Join(focusBody, "\n")), v.focusTitle(), focusW)
	edgesPanel := v.app.titledPanel(
		th.Panel.Width(edgesW-2).Height(colH-2).Render(strings.Join(edgesBody, "\n")), "EDGES ▸ by type", edgesW)

	cols := lipgloss.JoinHorizontal(lipgloss.Top, trailPanel, focusPanel, edgesPanel)
	parts := []string{bc, cols}
	if v.ov == ovRepl {
		parts = append(parts, v.renderReplBar(w)...)
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (v *exploreView) focusTitle() string {
	if v.orn == ornCluster {
		return "FOCUS · cluster"
	}
	return "FOCUS"
}

// renderBreadcrumb is the strip above the columns: the walked path leading to where you
// stand, plus the focus timing + edge-type count.
func (v *exploreView) renderBreadcrumb(w int) string {
	th := v.app.th
	var seg []string
	if len(v.deck.trail) == 0 {
		seg = append(seg, "ROOT")
	}
	for _, n := range v.deck.trail {
		seg = append(seg, shortValue(n.Value, 18))
	}
	parts := make([]string, 0, len(seg)+1)
	for _, s := range seg {
		parts = append(parts, th.Text.Render(s))
	}
	parts = append(parts, th.Accent.Render(v.deck.focus.Value))
	left := th.Accent.Render("⌖  ") + strings.Join(parts, th.Dim.Render(" ▸ "))
	src := "fixture"
	if v.deck.live {
		src = "live · " + itoa(v.deck.ms) + "ms"
		if v.loadingFocus || v.loadingEdges {
			src = "live · loading..."
		}
	}
	right := th.Dim.Render("focus · " + src + " · " + itoa(len(v.deck.edges)) + " edge-types")
	return twoCol(left, right, w, th)
}

// renderFocusColumn composes the FOCUS ornament (constellation / bipartite / cluster, or a
// degraded hub line) over the identity card. The ornament is never the only path.
func (v *exploreView) renderFocusColumn(cw, ch int) []string {
	th := v.app.th
	focus := v.deck.focus
	idH := 9
	switch {
	case focus.Ident == nil && strings.EqualFold(focus.Band, "UNKNOWN"):
		idH = 10 // sparse note
	case isMega(focus):
		idH = 12 // co-tenancy banner
	}
	if idH > ch-6 {
		idH = ch - 6
	}
	if idH < 4 {
		idH = 4
	}
	id := renderIdentityCard(focus, cw, idH, th)
	ornH := ch - idH - 1

	var orn []string
	ornamentAllowed := v.orn != ornOff && !th.NoColor && cw >= 34 && ornH >= 5
	switch {
	case v.orn == ornCluster && ornH >= 4:
		orn = clusterCollapse(v.deck.edges, cw, ornH, th)
	case ornamentAllowed && isHubLabels(focus.Labels):
		orn = renderBipartiteHub(focus, v.deck.edges, v.deck.edgeCur, cw, ornH, th)
	case ornamentAllowed:
		orn = renderConstellation(focus, v.deck.edges, v.deck.edgeCur, cw, ornH, th)
	}

	var body []string
	if len(orn) > 0 {
		body = append(body, orn...)
		body = append(body, sectionDivider("identity", cw, th))
		body = append(body, id...)
	} else {
		body = append(body, hubLine(focus, v.deck.edges, th))
		body = append(body, "")
		body = append(body, id...)
	}
	return fitBlock(body, cw, ch)
}

// hubLine is the degraded FOCUS header: the focus + band + edge-type count on one line,
// shown when the ornament is off / NO_COLOR / too narrow (the Miller columns still work).
func hubLine(focus graphNode, edges []edgeGroup, th *theme.Theme) string {
	bstyle, bglyph := styleForBand(th, focus.Band)
	return th.Accent.Render(glyphsFor(focus.Labels)+" "+focus.Value) + "  " +
		bstyle.Render(bglyph+" "+bandWord(focus.Band, focus.Labels)) +
		th.Dim.Render("  · "+itoa(len(edges))+" edge-types")
}

// renderRightColumn composes the EDGES list over the NEIGHBORS list over the preview card.
func (v *exploreView) renderRightColumn(cw, ch int) []string {
	th := v.app.th
	edges := v.deck.edges
	if len(edges) == 0 && v.loadingEdges {
		return fitBlock([]string{th.Dim.Render("loading edges from the graph...")}, cw, ch)
	}
	if len(edges) == 0 && v.deck.live {
		return fitBlock([]string{
			th.Dim.Render("(no edges on this node)"),
			th.Dim.Render("thin data is a fact, not an error"),
		}, cw, ch)
	}
	var cur edgeGroup
	if v.deck.edgeCur >= 0 && v.deck.edgeCur < len(edges) {
		cur = edges[v.deck.edgeCur]
	}
	eH := len(edges)
	if eH > ch-8 {
		eH = maxInt(ch-8, 1)
	}
	previewH := 4
	nbrH := ch - eH - 2 - previewH // minus the two section dividers
	if nbrH < 1 {
		nbrH = 1
	}

	var lines []string
	lines = append(lines, renderEdgePane(edges, v.deck.edgeCur, cw, eH, th)...)
	nbrLabel := "NEIGHBORS · " + cur.Type + " " + dirGlyph(cur.Dir) + components.Count(cur.Total)
	lines = append(lines, sectionDivider(nbrLabel, cw, th))
	lines = append(lines, renderNeighborPane(cur, v.deck.nbrCur, v.activePane == paneNeighbors, cw, nbrH, th)...)

	var sel graphNode
	if v.deck.nbrCur >= 0 && v.deck.nbrCur < len(cur.Sample) {
		sel = cur.Sample[v.deck.nbrCur]
	}
	lines = append(lines, sectionDivider("preview ▸ "+shortValue(sel.Value, cw-12), cw, th))
	lines = append(lines, v.renderPreview(sel, isMegaEdge(cur), cw, previewH)...)
	return fitBlock(lines, cw, ch)
}

// renderPreview is the highlighted neighbour's dossier (space = peek loads it here without
// travelling). For a mega reverse fan-out it carries the first-class SHARED not-equal
// RELATED banner so a shared CDN blob is never misread as linked infrastructure.
func (v *exploreView) renderPreview(sel graphNode, mega bool, w, h int) []string {
	th := v.app.th
	if sel.Value == "" {
		return fitBlock([]string{th.Dim.Render("(select a neighbour)")}, w, h)
	}
	var lines []string
	bstyle, bglyph := styleForBand(th, sel.Band)
	if id := sel.Ident; id != nil && id.ASN != "" {
		lines = append(lines, nodeHue(th, "ASN").Render("◈")+th.Text.Render(" "+id.ASN+" "+id.ASName+" · "+id.Country))
		if id.Prefix != "" {
			lines = append(lines, th.Dim.Render("prefix ")+th.Text.Render(id.Prefix))
		}
		if id.Hosts != "" {
			lines = append(lines, th.Dim.Render("hosts ")+th.Text.Render(id.Hosts)+" · "+bstyle.Render(bglyph+" "+bandTag(sel.Band, sel.Labels)))
		}
	} else {
		lines = append(lines, styledGlyphs(th, sel.Labels)+" "+th.Text.Render(sel.Value)+"  "+bstyle.Render(bglyph+" "+bandTag(sel.Band, sel.Labels)))
		if sel.Ident != nil && sel.Ident.Note != "" {
			lines = append(lines, th.Dim.Render(sel.Ident.Note))
		}
	}
	if mega {
		lines = append(lines, cotenancyStyle(th).Render("SHARED ≠ RELATED"))
	}
	lines = append(lines, th.Dim.Render("space = peek · ↵ = walk in"))
	return fitBlock(lines, w, h)
}

// --- REPL bar (Screen 5) ---------------------------------------------------------------

func (v *exploreView) renderReplBar(w int) []string {
	th := v.app.th
	q := "MATCH (n {" + matchKeyFor(v.deck.focus) + ":$v})-[r]-(m) RETURN type(r), labels(m), count(*) ORDER BY count(*) DESC"
	l1 := th.Accent.Render(": ") + th.Text.Render(q)
	// Honest hint: this bar previews the query shape; in-deck execution lands in a later
	// phase, so we say what works TODAY (`whisper query` runs it live) instead of
	// promising an ↵-to-RESULT that closes the bar (never a surprise).
	l2 := th.Dim.Render("  $v = " + v.deck.focus.Value + "   ·  ↵/esc close  ·  run it live: whisper query")
	return []string{padRight(l1, w), padRight(l2, w)}
}

// matchKeyFor maps a focus node to the property key the REPL binds $v against.
func matchKeyFor(n graphNode) string {
	kinds := nodeKinds(n.Labels)
	switch {
	case kinds["asn"]:
		return "asn"
	case kinds["ip"]:
		return "address"
	case kinds["email"]:
		return "address"
	default:
		return "name"
	}
}

// --- CATALOG frame (Screen 3) ----------------------------------------------------------

func (v *exploreView) renderCatalogFrame(w, h int) string {
	th := v.app.th
	bc := twoCol(
		th.Accent.Render("⌖  ")+th.Text.Render(v.deck.focus.Value),
		th.Dim.Render("catalog ▸ run on focus · keyed"), w, th)
	colH := h - 1
	leftW := w / 2
	if leftW > 54 {
		leftW = 54
	}
	rightW := w - leftW

	leftBody := v.renderCatalogList(leftW-4, colH-2)
	rightBody := v.renderCatalogResult(rightW-4, colH-2)
	leftPanel := v.app.titledPanel(
		th.Panel.Width(leftW-2).Height(colH-2).Render(strings.Join(leftBody, "\n")),
		"CATALOG · 14 verbs live · 15 flows", leftW)
	rightPanel := v.app.titledPanel(
		th.Panel.Width(rightW-2).Height(colH-2).Render(strings.Join(rightBody, "\n")),
		"RESULT · every row is a node", rightW)
	cols := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)
	return lipgloss.JoinVertical(lipgloss.Left, bc, cols)
}

// renderCatalogList shows the applicable verbs (pre-filtered to the focus label union),
// then the flows section, honestly labelled "anchor step runs in console".
func (v *exploreView) renderCatalogList(cw, ch int) []string {
	th := v.app.th
	all := applicableCatalog(v.deck.focus.Labels)
	ran := map[string]bool{}
	for _, r := range v.results {
		ran[r.Verb] = true
	}
	var lines []string
	nameW := 16
	shownFlows := false
	for i, cv := range all {
		if cv.Flow && !shownFlows {
			lines = append(lines, sectionDivider("flows (anchor step in console)", cw, th))
			shownFlows = true
		}
		gutter := " "
		nameStyle := th.Text
		if i == v.catalog.cursor {
			gutter = th.Accent.Render("◆")
			nameStyle = th.Accent
		}
		mark := "  "
		if ran[cv.Proc] || ran[cv.Name] {
			mark = th.OK.Render("●r")
		}
		prefix := "▸ "
		if cv.Flow {
			prefix = "⚙ "
		}
		row := gutter + nameStyle.Render(prefix+padRight(cv.Name, nameW)) + " " +
			th.Dim.Render(padRight(cv.Blurb, cw-nameW-8)) + mark
		lines = append(lines, row)
	}
	lines = append(lines, "")
	lines = append(lines, th.Dim.Render("↑↓ pick · ↵ run-on-focus · esc close"))
	return fitBlock(lines, cw, ch)
}

// renderCatalogResult stacks the RESULT cards (each type-aware) or a run hint.
func (v *exploreView) renderCatalogResult(cw, ch int) []string {
	th := v.app.th
	if len(v.results) == 0 {
		return fitBlock([]string{
			th.Dim.Render("↵ on a verb runs it on the focus."),
			"",
			th.Dim.Render("a direct verb renders type-aware here"),
			th.Dim.Render("(band chip · ranked table · vendor card)."),
			"",
			th.Dim.Render("every result row is a live node: ↵ walks"),
			th.Dim.Render("the whole deck onto it."),
		}, cw, ch)
	}
	var lines []string
	for i, card := range v.results {
		if i > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, renderResultCard(card, cw, th)...)
	}
	return fitBlock(lines, cw, ch)
}

// --- type-aware RESULT renderers -------------------------------------------------------

// renderResultCard dispatches on the result shape so intelligence reads correctly: a band
// chip, a ranked confidence table, a vendor card, or a WHOIS timeline.
func renderResultCard(card resultCard, w int, th *theme.Theme) []string {
	switch card.Shape {
	case shapeRanked:
		return renderResultRanked(card, w, th)
	case shapeVendor:
		return renderResultVendor(card, w, th)
	case shapeTimeline:
		return renderResultTimeline(card, w, th)
	default:
		return renderResultBand(card, w, th)
	}
}

func renderResultBand(card resultCard, w int, th *theme.Theme) []string {
	bstyle, bglyph := styleForBand(th, card.Band)
	head := bstyle.Render("BAND " + bglyph + " " + bandWord(card.Band, nil))
	if card.CovWord != "" {
		// The live graph reports coverage as a WORD; render it verbatim, no fake gauge.
		head += th.Dim.Render(" coverage " + card.CovWord)
	} else {
		fill := int(card.Coverage * 11)
		if fill < 0 {
			fill = 0
		}
		if fill > 11 {
			fill = 11
		}
		gauge := th.OK.Render(strings.Repeat("▓", fill)) + th.Dim.Render(strings.Repeat("░", 11-fill))
		head += " " + gauge + th.Dim.Render(" coverage "+ftoa(card.Coverage))
	}
	lines := []string{
		th.Dim.Render(card.Verb + "  " + itoa(card.MS) + "ms ✓"),
		head,
	}
	if card.Label != "" {
		lines = append(lines, th.Dim.Render("label    ")+th.Text.Render(card.Label))
	}
	if card.Evidence != "" {
		lines = append(lines, th.Dim.Render("evidence ")+th.Text.Render(card.Evidence))
	}
	lines = append(lines, th.Dim.Render("cypher   ")+th.Dim.Render(truncate(card.Cypher, w-9)))
	lines = append(lines, th.Dim.Render("rows     ")+th.Text.Render(itoa(card.Rows)))
	return lines
}

func renderResultRanked(card resultCard, w int, th *theme.Theme) []string {
	lines := []string{
		th.Dim.Render(card.Verb + " · " + itoa(card.Rows)),
	}
	nameW := w - 23
	if nameW < 10 {
		nameW = 10
	}
	lines = append(lines, th.Dim.Render(padRight("  variant", nameW+3)+padRight("method", 11)+"conf  thr"))
	for i, r := range card.Table {
		bstyle, bglyph := styleForBand(th, r.Band)
		gutter := " "
		if i == 0 {
			gutter = th.Accent.Render("◆")
		}
		row := gutter + bstyle.Render(bglyph) + " " +
			th.Text.Render(padRight(r.Name, nameW)) + " " +
			th.Dim.Render(padRight(r.Method, 10)) + " " +
			confBar(r.Conf, 6, th) + " " + bstyle.Render(bglyph)
		lines = append(lines, row)
	}
	if card.Note != "" {
		lines = append(lines, th.Dim.Render(card.Note))
	}
	return lines
}

func renderResultVendor(card resultCard, w int, th *theme.Theme) []string {
	lines := []string{th.Dim.Render(card.Verb + "  " + itoa(card.MS) + "ms ✓")}
	// The key column sizes to the longest live column name (capped) so a long name
	// like canonical_name never fuses into its value.
	keyW := 8
	for _, r := range card.Table {
		if l := len(r.Method); l > keyW {
			keyW = l
		}
	}
	if keyW > 16 {
		keyW = 16
	}
	for _, r := range card.Table {
		lines = append(lines, th.Dim.Render(padRight(r.Method, keyW))+" "+th.Text.Render(truncate(r.Name, maxInt(w-keyW-1, 8))))
	}
	if card.Note != "" {
		lines = append(lines, th.Dim.Render(truncate(card.Note, w)))
	}
	return lines
}

func renderResultTimeline(card resultCard, w int, th *theme.Theme) []string {
	lines := []string{th.Dim.Render(card.Verb + "  " + itoa(card.MS) + "ms ✓")}
	for _, r := range card.Table {
		lines = append(lines, th.Accent.Render(padRight(r.Method, 12))+th.Text.Render(truncate(r.Name, w-13)))
	}
	return lines
}

// confBar is a compact confidence bar (higher is more confident) for a ranked row. It
// rounds so a 0.97 reads as a full bar and low-confidence rows are visibly shorter.
func confBar(conf float64, cells int, th *theme.Theme) string {
	fill := int(conf*float64(cells) + 0.5)
	if fill < 0 {
		fill = 0
	}
	if fill > cells {
		fill = cells
	}
	return th.Text.Render(strings.Repeat("█", fill)) + th.Dim.Render(strings.Repeat("░", cells-fill))
}

// --- JUMP frame (Screen 4) -------------------------------------------------------------

// renderJumpFrame is the JUMP overlay shell (Postel-liberal search) with the your-agents
// bridge (land on an agent /128 as a graph node). Phase 1 renders it static.
func (v *exploreView) renderJumpFrame(w, h int) string {
	th := v.app.th
	kind, _ := normalizeRef(v.jump.query)
	if kind == "" {
		kind = "HOSTNAME"
	}
	bc := twoCol(
		th.Accent.Render("⌖  ")+th.Text.Render("JUMP - land on any node"),
		th.Dim.Render("Postel-liberal · type & ↵"), w, th)
	colH := h - 1
	leftW := w / 2
	if leftW > 50 {
		leftW = 50
	}
	rightW := w - leftW

	left := []string{
		th.Accent.Render("JUMP ▸ ") + th.Text.Render(v.jump.query),
		th.Dim.Render(" detected: ") + th.Text.Render(kind),
		th.Dim.Render(" accepts: host · ipv4 · ipv6 · email"),
		th.Dim.Render("          AS#/# · trailing-dot ok"),
		"",
		sectionDivider("your agents (whisper.agents)", leftW-4, th),
		th.Dim.Render(" land on an agent /128 to see identity,"),
		th.Dim.Render(" policy, live traffic as graph nodes, then"),
		th.Dim.Render(" walk its egress neighbours."),
		"",
		th.Dim.Render(" ↵ land · esc cancel · Tab node↔agents"),
	}
	_, landVal := normalizeRef(v.jump.query)
	var right []string
	if landVal == "" {
		right = []string{
			th.Dim.Render("type a node reference; ↵ lands on it."),
			"",
			th.Dim.Render("liberal in what we accept:"),
			th.Dim.Render("  https://api.openai.com/v1  -> api.openai.com"),
			th.Dim.Render("  162.159.140.245.           -> 162.159.140.245"),
			th.Dim.Render("  13335                      -> AS13335"),
		}
	} else {
		right = []string{
			th.Dim.Render("↵ lands the deck on:"),
			th.Accent.Render("◆▸ ") + styledGlyphs(th, []string{kind}) + " " + th.Text.Render(landVal),
			"",
			th.Dim.Render("an unknown node renders the honest"),
			th.Dim.Render("sparse state, never an error."),
		}
	}
	right = append(right,
		sectionDivider("your agents ▸ /128", rightW-4, th),
		th.Dim.Render("the agent bridge (land on your own"),
		th.Dim.Render("/128, walk its egress) arrives with"),
		th.Dim.Render("the Phase 3 catalog wiring."),
	)

	leftPanel := v.app.titledPanel(
		th.Panel.Width(leftW-2).Height(colH-2).Render(strings.Join(fitBlock(left, leftW-4, colH-2), "\n")),
		"JUMP", leftW)
	rightPanel := v.app.titledPanel(
		th.Panel.Width(rightW-2).Height(colH-2).Render(strings.Join(fitBlock(right, rightW-4, colH-2), "\n")),
		"MATCHES", rightW)
	cols := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)
	return lipgloss.JoinVertical(lipgloss.Left, bc, cols)
}

// --- total-outage state ----------------------------------------------------------------

// renderOutageBanner is the calm graph-unreachable state (fail-open, Postel): last-known
// stays visible, nothing hangs, never four dead spinners, never a 500.
func (v *exploreView) renderOutageBanner(w int) []string {
	th := v.app.th
	_ = w
	return []string{
		"",
		th.Warn.Render("○ graph unreachable"),
		th.Dim.Render("last-known shown; Ctrl-R to retry"),
		"",
		th.Dim.Render("the deck stays usable; nothing hangs,"),
		th.Dim.Render("never four dead spinners, never a 500."),
	}
}

// --- shared render helpers -------------------------------------------------------------

// twoCol lays a left + right segment across width w exactly (right-aligned tail), dropping
// the tail rather than wrapping when there is no room.
func twoCol(left, right string, w int, th *theme.Theme) string {
	_ = th
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	gap := w - lw - rw
	if gap < 1 {
		return padRight(left, w)
	}
	return left + strings.Repeat(" ", gap) + right
}

// isMega reports whether the focus stands on a mega fan-out (the co-tenancy banner shows).
func isMega(focus graphNode) bool {
	if focus.Props != nil {
		if b, ok := focus.Props["mega"].(bool); ok && b {
			return true
		}
	}
	return false
}

// isMegaEdge reports whether an edge group is a sampled mega fan-out (preview banner).
func isMegaEdge(e edgeGroup) bool {
	return e.Capped || e.Total >= 100000
}
