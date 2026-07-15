// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/components"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// sortKey orders the fleet table (Shift-K cycles). last-active leads and is the DEFAULT
// fresh traffic moves an agent up, so the busy fleet reads newest-first with
// zero configuration; Shift-F freezes the order in place while you read.
type sortKey int

const (
	sortByActive sortKey = iota
	sortByCreated
	sortByName
	sortByState
	sortByTraffic
)

var sortKeyNames = []string{"active", "created", "name", "state", "traffic"}

// agentsView is the merged primary dashboard: the fleet table on the left, the
// SELECTED agent's live monitor (aggregate counters, throughput, activity feed) on the
// right. ENTER (or a click) on an agent pins the monitor to it; `d` opens details.
//
// The table is WINDOWED by this view, not scrolled inside bubbles: the table always
// holds exactly the visible slice of rows (v.top..v.top+visRows), so a mouse click on
// row r maps to index v.top+r with no hidden viewport offset to guess at.
type agentsView struct {
	app   *App
	tbl   table.Model
	w, h  int
	top   int  // first visible position into orderedIndices()
	dense bool // z toggles a denser (no-created-column) layout

	// filter (/) state
	filtering bool
	filter    string
	filterRe  *regexp.Regexp
	matches   []int // indices into app.agents matching the filter

	sort sortKey

	// freeze: Shift-F pins the CURRENT visual order so the last-active sort
	// stops reshuffling under the reader's eyes. frozenOrder snapshots the Key() list
	// at freeze time; agents that appear later append at the tail (in live sort order),
	// removed ones simply drop out. Shift-F again resumes the live re-ordering.
	frozen      bool
	frozenOrder []string
}

func newAgentsView(app *App) *agentsView {
	v := &agentsView{app: app, sort: sortByActive}
	v.tbl = table.New(
		table.WithFocused(true),
		table.WithColumns(v.columns(80)),
	)
	v.styleTable()
	return v
}

func (v *agentsView) styleTable() {
	th := v.app.th
	s := table.DefaultStyles()
	s.Header = th.Title.Bold(true).BorderBottom(true).
		BorderForeground(lipgloss.Color(th.Pal.Border)).Padding(0, 1)
	s.Selected = th.Selected.Bold(true)
	s.Cell = th.Text.Padding(0, 1)
	if th.NoColor {
		s.Header = lipgloss.NewStyle().Bold(true).Underline(true).Padding(0, 1)
		s.Selected = lipgloss.NewStyle().Reverse(true)
		s.Cell = lipgloss.NewStyle().Padding(0, 1)
	}
	v.tbl.SetStyles(s)
}

func (v *agentsView) retheme() { v.styleTable() }

// leftW/rightW split the view width: the fleet panel takes ~40% (clamped so the dense
// table still fits and the monitor keeps usable chain lanes) and the monitor the rest.
// This is the ONE width budget every layer below derives from (panel -> padding ->
// table -> columns), so no inner layer can render wider than its box.
func (v *agentsView) leftW() int {
	lw := v.w * 2 / 5
	if lw < 30 {
		lw = 30
	}
	if lw > 56 {
		lw = 56
	}
	if lw > v.w-24 { // a very narrow terminal: keep SOME monitor
		lw = v.w - 24
	}
	if lw < 20 {
		lw = 20
	}
	return lw
}
func (v *agentsView) rightW() int { return v.w - v.leftW() - 1 }

// tableW is the fleet table's exact render width: the left panel minus its border (2)
// and its horizontal padding (2).
func (v *agentsView) tableW() int {
	tw := v.leftW() - 4
	if tw < 26 {
		tw = 26
	}
	return tw
}

// visRows is how many fleet rows fit the table: the view height minus the panel border
// (2), the table header (1), and the header's bottom border baked into table height.
func (v *agentsView) visRows() int {
	vr := v.h - 4
	if vr < 1 {
		vr = 1
	}
	return vr
}

// autoDense reports whether the table is too narrow for the 4-column layout - the
// column set drops to the dense 3-column one rather than overflow its box.
func (v *agentsView) autoDense() bool { return v.dense || v.tableW() < 44 }

func (v *agentsView) columns(tableW int) []table.Column {
	// Budget the columns within the table, leaving each cell's Padding(0,1) room:
	// bubbles renders every cell 2 wider than its column width.
	if v.autoDense() {
		tw := tableW - 3*2
		nameW := clamp(tw*35/100, 8, 22)
		return []table.Column{
			{Title: "AGENT", Width: nameW},
			{Title: "ADDRESS", Width: tw - nameW - 2},
			{Title: "●", Width: 2},
		}
	}
	tw := tableW - 4*2
	stateW := 8
	sparkW := 6
	nameW := clamp(tw*30/100, 8, 22)
	addrW := tw - nameW - stateW - sparkW
	if addrW < 12 {
		addrW = 12
	}
	return []table.Column{
		{Title: "AGENT", Width: nameW},
		{Title: "ADDRESS", Width: addrW},
		{Title: "STATE", Width: stateW},
		{Title: "kbps", Width: sparkW},
	}
}

func (v *agentsView) resize(w, h int) {
	v.w, v.h = w, h
	// A resize can flip autoDense (3 vs 4 cells per row): clear the rows BEFORE
	// swapping the column set (bubbles panics on rows wider than the columns), then
	// rebuild them to the new shape.
	v.tbl.SetRows(nil)
	v.tbl.SetColumns(v.columns(v.tableW()))
	// table height: header + the visible row window.
	th := h - 3
	if th < 2 {
		th = 2
	}
	v.tbl.SetHeight(th)
	v.tbl.SetWidth(v.tableW())
	v.syncRows()
}

// syncRows rebuilds the visible table window from the app fleet (after a load/merge/
// sort/filter/selection move). It clamps v.top so the selection is always in view and
// hands bubbles exactly the visible slice, cursor-aligned - never a scrolled viewport.
func (v *agentsView) syncRows() {
	order := v.orderedIndices()
	pos := v.selectedPos(order)
	vr := v.visRows()
	// Clamp the window to keep pos visible and the window inside the list.
	if pos >= 0 && pos < v.top {
		v.top = pos
	}
	if pos >= v.top+vr {
		v.top = pos - vr + 1
	}
	if v.top > len(order)-vr {
		v.top = len(order) - vr
	}
	if v.top < 0 {
		v.top = 0
	}
	end := v.top + vr
	if end > len(order) {
		end = len(order)
	}
	rows := make([]table.Row, 0, end-v.top)
	for _, idx := range order[v.top:end] {
		rows = append(rows, v.row(v.app.agents[idx]))
	}
	v.tbl.SetRows(rows)
	if pos >= v.top && pos < end {
		v.tbl.SetCursor(pos - v.top)
	} else if len(rows) > 0 {
		v.tbl.SetCursor(0)
		v.app.selected = order[v.top]
	}
}

// selectedPos finds app.selected's position in the current order (-1 when absent).
func (v *agentsView) selectedPos(order []int) int {
	for pos, idx := range order {
		if idx == v.app.selected {
			return pos
		}
	}
	return -1
}

func (v *agentsView) row(a model.Agent) table.Row {
	name := a.Name()
	addr := a.Address
	if addr == "" {
		addr = "(no /128)"
	}
	if v.autoDense() {
		return table.Row{name, addr, stateGlyph(a.State)}
	}
	spark := ""
	if a.Detailed {
		spark = components.Sparkline(v.app.monitorVw.kbpsSeries(a.Key(), 6), 6, v.app.th.NoColor)
	}
	return table.Row{name, addr, a.State, spark}
}

// orderedIndices returns app.agent indices in the active sort + filter order. When the
// order is FROZEN the freeze-time snapshot order wins: known agents keep their
// pinned positions, newcomers append at the tail (in live sort order), gone ones drop.
func (v *agentsView) orderedIndices() []int {
	var idxs []int
	if v.filtering || v.filter != "" {
		idxs = append(idxs, v.matches...)
	} else {
		for i := range v.app.agents {
			idxs = append(idxs, i)
		}
	}
	ag := v.app.agents
	sort.SliceStable(idxs, func(i, j int) bool {
		a, b := ag[idxs[i]], ag[idxs[j]]
		switch v.sort {
		case sortByName:
			return strings.ToLower(a.Name()) < strings.ToLower(b.Name())
		case sortByState:
			return a.State < b.State
		case sortByTraffic:
			return (a.BytesUp + a.BytesDown) > (b.BytesUp + b.BytesDown)
		case sortByCreated:
			return a.Created > b.Created
		default: // sortByActive: newest folded traffic first
			aa, bb := v.app.lastActiveUS[a.Key()], v.app.lastActiveUS[b.Key()]
			if aa != bb {
				return aa > bb
			}
			// No folded traffic yet: fall back to the roster's own recency signals
			// (op:agent last_seen, then created) so a cold launch is still sensible.
			if a.LastSeen != b.LastSeen {
				return a.LastSeen > b.LastSeen
			}
			return a.Created > b.Created
		}
	})
	if !v.frozen || len(v.frozenOrder) == 0 {
		return idxs
	}
	// Frozen: replay the snapshot order over the live-sorted list. Stable, so agents
	// outside the snapshot keep their live relative order at the tail.
	pos := make(map[string]int, len(v.frozenOrder))
	for i, k := range v.frozenOrder {
		pos[k] = i
	}
	sort.SliceStable(idxs, func(i, j int) bool {
		pi, iok := pos[ag[idxs[i]].Key()]
		pj, jok := pos[ag[idxs[j]].Key()]
		if iok && jok {
			return pi < pj
		}
		return iok && !jok // snapshot members first; newcomers sink to the tail
	})
	return idxs
}

// handleKey drives the merged dashboard: vim motion, sort, density, filter, the write
// actions, and THE key - ENTER pins the live monitor to the selected agent.
func (v *agentsView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	if v.filtering {
		return v.handleFilterKey(k)
	}
	switch k.String() {
	case "j", "down":
		v.move(1)
		return app, app.refreshSelectedDetail()
	case "k", "up":
		v.move(-1)
		return app, app.refreshSelectedDetail()
	case "g", "home":
		v.moveTo(0)
		return app, app.refreshSelectedDetail()
	case "G", "end":
		v.moveTo(len(v.orderedIndices()) - 1)
		return app, app.refreshSelectedDetail()
	case "ctrl+d":
		v.move(v.visRows() / 2)
		return app, app.refreshSelectedDetail()
	case "ctrl+u":
		v.move(-v.visRows() / 2)
		return app, app.refreshSelectedDetail()
	case "/":
		v.filtering = true
		v.filter = ""
		v.recomputeMatches()
		return app, nil
	case "n":
		v.move(1)
		return app, app.refreshSelectedDetail()
	case "N":
		v.move(-1)
		return app, app.refreshSelectedDetail()
	case "K": // Shift-K cycles the sort
		v.sort = sortKey((int(v.sort) + 1) % len(sortKeyNames))
		v.syncRows()
		app.setToast("sort: "+sortKeyNames[v.sort], false)
		return app, nil
	case "F": // Shift-F freezes/unfreezes the ordering - stop the reshuffle while reading
		v.frozen = !v.frozen
		if v.frozen {
			v.frozenOrder = v.snapshotOrderKeys()
			app.setToast("order frozen - F resumes auto-reorder", false)
		} else {
			v.frozenOrder = nil
			v.syncRows()
			app.setToast("auto-reorder resumed (sort: "+sortKeyNames[v.sort]+")", false)
		}
		return app, nil
	case "z":
		v.dense = !v.dense
		v.tbl.SetRows(nil) // rows must never be wider than the column set
		v.tbl.SetColumns(v.columns(v.tableW()))
		v.syncRows()
		return app, nil
	case "enter", "m":
		// ENTER is THE key: select the agent and pin the live monitor to it (narrows
		// the SSE + backfills for that one /128). `m` stays as the muscle-memory alias.
		return v.watchSelected()
	case "a":
		// back to the explicit (all) selection - every agent, aggregated.
		if cmd := app.monitorVw.unfocus(); cmd != nil {
			app.setToast("watching (all) agents", false)
			return app, cmd
		}
		return app, nil
	case "d":
		// details moved here: ENTER now selects-and-monitors, d drills.
		return app.openDrill()
	case " ", "space":
		app.paused = !app.paused
		if !app.paused {
			app.bufferedPause = 0
		}
		app.setToast(map[bool]string{true: "feed paused", false: "feed resumed"}[app.paused], false)
		return app, nil
	case "f":
		app.setToast("kind filter: "+app.monitorVw.cycleKind(), false)
		return app, nil
	case "x":
		return app.openKill()
	case "v":
		return app.openRDAP()
	case "y":
		return app.yankSelected()
	case "esc":
		if v.filter != "" {
			v.clearFilter()
		}
		return app, nil
	}
	return app, nil
}

// snapshotOrderKeys captures the CURRENT visual order as agent keys - taken at
// freeze time, while frozen is already set, so it snapshots what is on screen right now.
// (orderedIndices ignores an empty frozenOrder, so calling it here is snapshot-safe.)
func (v *agentsView) snapshotOrderKeys() []string {
	order := v.orderedIndices()
	keys := make([]string, 0, len(order))
	for _, idx := range order {
		keys = append(keys, v.app.agents[idx].Key())
	}
	return keys
}

// watchSelected pins the live monitor to the selected agent (the ENTER / click action).
func (v *agentsView) watchSelected() (tea.Model, tea.Cmd) {
	app := v.app
	sel, ok := app.SelectedAgent()
	if !ok {
		app.setToast("no agent selected", true)
		return app, nil
	}
	cmd := app.monitorVw.focus(sel)
	if cmd != nil {
		app.setToast("watching "+sel.Name(), false)
	}
	return app, cmd
}

// click maps a terminal-cell click to a fleet row: selects it AND pins the monitor to
// it (the mouse is the same verb as ENTER). Returns ok=false when the click was not on
// a fleet row. Geometry: header(1) + tabs(1) + panel border(1) + table header(1) = the
// first row sits at y=4; the visible row r maps EXACTLY to position v.top+r because
// the table holds only the visible window (never an internal scroll offset).
func (v *agentsView) click(x, y int) (tea.Cmd, bool) {
	if x >= v.leftW() {
		return nil, false
	}
	row := y - (headerRows + tabRows + 2)
	if row < 0 || row >= v.visRows() {
		return nil, false
	}
	order := v.orderedIndices()
	pos := v.top + row
	if pos < 0 || pos >= len(order) {
		return nil, false
	}
	v.app.selected = order[pos]
	v.syncRows()
	_, cmd := v.watchSelected()
	return tea.Batch(cmd, v.app.refreshSelectedDetail()), true
}

func (v *agentsView) handleFilterKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "enter":
		v.filtering = false
		return v.app, v.app.refreshSelectedDetail()
	case "esc":
		v.filtering = false
		v.clearFilter()
		return v.app, nil
	case "backspace":
		if v.filter != "" {
			v.filter = v.filter[:len(v.filter)-1]
		}
		v.recomputeMatches()
		return v.app, nil
	default:
		if len(k.String()) == 1 {
			v.filter += k.String()
			v.recomputeMatches()
		}
		return v.app, nil
	}
}

func (v *agentsView) recomputeMatches() {
	v.matches = v.matches[:0]
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(v.filter))
	if v.filter != "" {
		if r2, err2 := regexp.Compile("(?i)" + v.filter); err2 == nil {
			re, err = r2, nil // prefer a real regex when it compiles
		}
	}
	v.filterRe = re
	for i, a := range v.app.agents {
		if v.filter == "" || (err == nil && re.MatchString(a.Name()+" "+a.Address+" "+a.Label+" "+a.State)) {
			v.matches = append(v.matches, i)
		}
	}
	v.syncRows()
}

func (v *agentsView) clearFilter() {
	v.filter = ""
	v.filterRe = nil
	v.matches = nil
	v.syncRows()
}

// move shifts the selection by delta within the current order (clamped).
func (v *agentsView) move(delta int) {
	order := v.orderedIndices()
	if len(order) == 0 {
		return
	}
	pos := v.selectedPos(order)
	if pos < 0 {
		pos = 0
	}
	v.moveTo(pos + delta)
}

// moveTo selects the row at a position in the current order (clamped) and re-windows.
func (v *agentsView) moveTo(pos int) {
	order := v.orderedIndices()
	if len(order) == 0 {
		return
	}
	pos = clamp(pos, 0, len(order)-1)
	v.app.selected = order[pos]
	v.syncRows()
}

// view renders the merged dashboard: the fleet table (left) + the live monitor for the
// selected agent (right) - one panel, one picture.
func (v *agentsView) view(w, h int) string {
	leftW, rightW := v.leftW(), v.rightW()
	left := v.app.titledPanelStyled(
		v.app.th.PanelHi.Width(leftW-2).Height(h-2).Render(v.tbl.View()),
		v.fleetTitle(), leftW, v.app.th.BorderHiFg)
	right := v.app.monitorVw.panel(rightW, h)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (v *agentsView) fleetTitle() string {
	active := 0
	for _, a := range v.app.agents {
		if a.State == "active" {
			active++
		}
	}
	t := fmt.Sprintf("FLEET %d agents · %d active", len(v.app.agents), active)
	if v.frozen {
		t += " · ❄ frozen" // the order is pinned; F resumes
	}
	if v.filtering || v.filter != "" {
		t += "  /" + v.filter
	}
	return t
}

// --- small helpers ---------------------------------------------------------------

func stateGlyph(state string) string {
	if state == "active" {
		return "●"
	}
	return "○"
}

func stateBadge(th *theme.Theme, state string) string {
	switch state {
	case "active":
		return th.OK.Render("● active")
	case "released":
		return th.Dim.Render("○ released")
	default:
		return th.Warn.Render("◐ " + state)
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampLines(s string, max int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > max && max > 0 {
		lines = lines[:max]
	}
	return strings.Join(lines, "\n")
}
