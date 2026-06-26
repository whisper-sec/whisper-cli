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

// sortKey orders the fleet table (Shift-K cycles).
type sortKey int

const (
	sortByCreated sortKey = iota
	sortByName
	sortByState
	sortByTraffic
)

var sortKeyNames = []string{"created", "name", "state", "traffic"}

// agentsView is the AGENTS dashboard's left fleet table + the right detail panel.
type agentsView struct {
	app   *App
	tbl   table.Model
	w, h  int
	dense bool // z toggles a denser (no-created-column) layout

	// filter (/) state
	filtering bool
	filter    string
	filterRe  *regexp.Regexp
	matches   []int // indices into app.agents matching the filter

	sort sortKey
}

func newAgentsView(app *App) *agentsView {
	v := &agentsView{app: app, sort: sortByCreated}
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

func (v *agentsView) columns(w int) []table.Column {
	// Left fleet table is ~48% of the width; budget columns within it.
	tw := w/2 - 4
	if tw < 30 {
		tw = 30
	}
	nameW := clamp(tw*30/100, 8, 22)
	addrW := clamp(tw*40/100, 14, 30)
	stateW := 8
	sparkW := 6
	if v.dense {
		return []table.Column{
			{Title: "AGENT", Width: nameW},
			{Title: "ADDRESS", Width: addrW},
			{Title: "●", Width: 2},
		}
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
	v.tbl.SetColumns(v.columns(w))
	// table height: minus header + borders.
	th := h - 3
	if th < 1 {
		th = 1
	}
	v.tbl.SetHeight(th)
	v.tbl.SetWidth(w/2 - 2)
}

// syncRows rebuilds the table rows from the app fleet (after a load/merge/sort/filter).
func (v *agentsView) syncRows() {
	order := v.orderedIndices()
	rows := make([]table.Row, 0, len(order))
	for _, idx := range order {
		a := v.app.agents[idx]
		rows = append(rows, v.row(a))
	}
	v.tbl.SetRows(rows)
	// Keep the table cursor aligned with app.selected.
	v.alignCursor(order)
}

func (v *agentsView) row(a model.Agent) table.Row {
	name := a.Name()
	addr := a.Address
	if addr == "" {
		addr = "(no /128)"
	}
	if v.dense {
		return table.Row{name, addr, stateGlyph(a.State)}
	}
	spark := ""
	if a.Detailed {
		spark = components.Sparkline(v.app.monitorVw.kbpsSeries(a.Key(), 6), 6, v.app.th.NoColor)
	}
	return table.Row{name, addr, a.State, spark}
}

// orderedIndices returns app.agent indices in the active sort + filter order.
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
		default:
			return a.Created > b.Created
		}
	})
	return idxs
}

func (v *agentsView) alignCursor(order []int) {
	for pos, idx := range order {
		if idx == v.app.selected {
			v.tbl.SetCursor(pos)
			return
		}
	}
	if len(order) > 0 {
		v.tbl.SetCursor(0)
		v.app.selected = order[0]
	}
}

// handleKey drives the fleet: vim motion, sort, density, filter, and the action keys.
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
		v.tbl.GotoTop()
		v.syncSelectionFromCursor()
		return app, app.refreshSelectedDetail()
	case "G", "end":
		v.tbl.GotoBottom()
		v.syncSelectionFromCursor()
		return app, app.refreshSelectedDetail()
	case "ctrl+d":
		v.move(v.h / 2)
		return app, app.refreshSelectedDetail()
	case "ctrl+u":
		v.move(-v.h / 2)
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
	case "z":
		v.dense = !v.dense
		v.tbl.SetColumns(v.columns(v.w))
		v.syncRows()
		return app, nil
	case "enter":
		return app.openDrill()
	case "x":
		return app.openKill()
	case "m":
		// monitor the selected agent: jump to MONITOR focused on it (narrows the SSE +
		// backfills for that one /128).
		var focusCmd tea.Cmd
		if sel, ok := app.SelectedAgent(); ok {
			focusCmd = app.monitorVw.focus(sel)
		}
		app.mode = modeMonitor
		app.layout()
		return app, tea.Batch(app.onEnterMode(), focusCmd)
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

func (v *agentsView) move(delta int) {
	switch {
	case delta > 0:
		for i := 0; i < delta; i++ {
			v.tbl.MoveDown(1)
		}
	case delta < 0:
		for i := 0; i < -delta; i++ {
			v.tbl.MoveUp(1)
		}
	}
	v.syncSelectionFromCursor()
}

// syncSelectionFromCursor maps the table cursor back to an app.agents index.
func (v *agentsView) syncSelectionFromCursor() {
	order := v.orderedIndices()
	c := v.tbl.Cursor()
	if c >= 0 && c < len(order) {
		v.app.selected = order[c]
	}
}

// view renders the fleet table (left) + the selected-agent detail (right).
func (v *agentsView) view(w, h int) string {
	leftW := w/2 - 1
	rightW := w - leftW - 1
	left := v.app.titledPanel(
		v.app.th.PanelHi.Width(leftW-2).Height(h-2).Render(v.tbl.View()),
		v.fleetTitle(), leftW)
	right := v.app.titledPanel(
		v.app.th.Panel.Width(rightW-2).Height(h-2).Render(v.detail(rightW-4, h-2)),
		"DETAIL", rightW)
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
	if v.filtering || v.filter != "" {
		t += "  /" + v.filter
	}
	return t
}

// detail renders the selected agent's full panel (op:agent counters + sparklines).
func (v *agentsView) detail(w, h int) string {
	a, ok := v.app.SelectedAgent()
	if !ok {
		return v.app.th.Dim.Render("no agent selected")
	}
	th := v.app.th
	var b strings.Builder
	addr := a.Address
	if addr == "" {
		addr = "(no /128 yet)"
	}
	b.WriteString(th.Accent.Render(a.Name()) + "  " + th.Addr.Render(addr) + "  " + stateBadge(th, a.State) + "\n")
	b.WriteString(th.Dim.Render(strings.Repeat("─", min(w, 50))) + "\n")

	if a.Detailed {
		blk := fmt.Sprintf("%d (%.1f%%)", a.DNSBlocked, a.BlockedPct())
		spark := components.Sparkline(v.app.monitorVw.kbpsSeries(a.Key(), 20), 20, th.NoColor)
		b.WriteString(fmt.Sprintf("%s  %s  %s %s\n",
			th.DNS.Render("dns "), th.Text.Render(components.Count(a.DNSQueries)),
			th.Dim.Render("blocked"), th.Error.Render(blk)))
		b.WriteString(fmt.Sprintf("%s %s active · %s total  %s\n",
			th.Conn.Render("conn"), th.Text.Render(components.Count(a.ConnectionsActive)),
			th.Text.Render(components.Count(a.ConnectionsTotal)), th.Conn.Render(spark)))
		b.WriteString(fmt.Sprintf("%s ↑%s  ↓%s   %s %s\n",
			th.Dim.Render("bw  "), components.Bytes(a.BytesUp), components.Bytes(a.BytesDown),
			th.Dim.Render("pkts"), components.Count(a.Packets)))
	} else {
		b.WriteString(th.Dim.Render("loading counters…") + "\n")
	}
	if a.FQDN != "" {
		b.WriteString(th.Dim.Render("fqdn ") + th.Text.Render(components.TrimDot(a.FQDN)) + "\n")
	}
	ptr := "—"
	if a.PTR != "" {
		ptr = "✓"
	}
	contact := a.Contact
	if contact == "" {
		contact = th.Dim.Render("(none)")
	}
	b.WriteString(fmt.Sprintf("%s %s   %s %s   %s\n",
		th.Dim.Render("ptr"), ptr, th.Dim.Render("contact"), contact, th.Accent.Render("RDAP ↗")))
	if a.Created != 0 {
		b.WriteString(th.Dim.Render("allocated ") + th.Text.Render(components.Uptime(a.Created)+" ago") + "\n")
	}
	return clampLines(b.String(), h)
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
