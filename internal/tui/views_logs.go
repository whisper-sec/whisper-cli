// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/components"
)

// logsView is the LOGS tab: an op:logs query with a time-window + kind filter, rendered
// as the full-chain table (the one place client_src + qname + peer land on ONE row).
type logsView struct {
	app    *App
	tbl    table.Model
	w, h   int
	events []model.Event

	from  string // relative window (e.g. -1h); editable
	kind  string // "", dns, conn, alloc
	agent string // optional narrow (the AGENTS selection, by id/addr)

	token   int // request token: a stale reply (token mismatch) is dropped
	loaded  bool
	loading bool

	editing  bool   // a small inline editor is open (from / )
	editWhat string // "from"
	editBuf  string
}

func newLogsView(app *App) *logsView {
	v := &logsView{app: app, from: "-1h"}
	v.tbl = table.New(table.WithFocused(true))
	v.styleTable()
	return v
}

func (v *logsView) styleTable() {
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

func (v *logsView) resize(w, h int) {
	v.w, v.h = w, h
	v.tbl.SetColumns(v.columns(w))
	th := h - 5 // header band + table header + borders
	if th < 1 {
		th = 1
	}
	v.tbl.SetHeight(th)
	v.tbl.SetWidth(w - 2)
}

func (v *logsView) columns(w int) []table.Column {
	iw := w - 4
	return []table.Column{
		{Title: "TIME", Width: 8},
		{Title: "KIND", Width: 5},
		{Title: "CLIENT_SRC", Width: clamp(iw*15/100, 10, 18)},
		{Title: "QNAME", Width: clamp(iw*22/100, 12, 30)},
		{Title: "PEER", Width: clamp(iw*18/100, 12, 24)},
		{Title: "DECISION", Width: 10},
		{Title: "↑/↓", Width: 14},
	}
}

// onEnter runs the first query when the tab is opened (lazy).
func (v *logsView) onEnter() tea.Cmd {
	if v.app.client == nil {
		return nil
	}
	if v.loaded {
		return nil
	}
	return v.runQuery()
}

// runQuery issues an op:logs with the current filters; the reply carries the token.
func (v *logsView) runQuery() tea.Cmd {
	// Inherit the AGENTS selection as the default narrow.
	if v.agent == "" {
		if sel, ok := v.app.SelectedAgent(); ok {
			v.agent = sel.ID
			if v.agent == "" {
				v.agent = sel.Address
			}
		}
	}
	v.token++
	v.loading = true
	args := map[string]any{"limit": 500}
	if v.from != "" {
		args["from"] = v.from
	}
	if v.kind != "" {
		args["kind"] = v.kind
	}
	if v.agent != "" {
		args["agent"] = v.agent
	}
	return loadLogs(v.app.client, args, v.token)
}

// onLogs folds a query reply (dropping a stale one by token).
func (v *logsView) onLogs(m logsMsg) {
	if m.token != v.token {
		return
	}
	v.loading = false
	v.loaded = true
	if m.err != nil {
		v.app.setToast(friendlyErr(m.err), true)
		return
	}
	v.events = m.events
	v.syncRows()
}

func (v *logsView) syncRows() {
	rows := make([]table.Row, 0, len(v.events))
	for _, e := range v.events {
		peer := "—"
		if e.PeerHost != "" {
			if e.PeerPort > 0 {
				peer = fmt.Sprintf("%s:%d", e.PeerHost, e.PeerPort)
			} else {
				peer = e.PeerHost
			}
		}
		dec := e.Decision
		if dec == "" {
			dec = e.Reason
		}
		bw := "—"
		if e.BytesUp > 0 || e.BytesDown > 0 {
			bw = fmt.Sprintf("↑%s ↓%s", components.Bytes(e.BytesUp), components.Bytes(e.BytesDown))
		}
		rows = append(rows, table.Row{
			components.Clock(e.TsMicros),
			e.Kind,
			components.OrDash(e.ClientSrc),
			components.OrDash(components.TrimDot(e.QName)),
			peer,
			components.OrDash(dec),
			bw,
		})
	}
	v.tbl.SetRows(rows)
}

func (v *logsView) capturing() bool { return v.editing }

func (v *logsView) move(delta int) {
	if delta > 0 {
		v.tbl.MoveDown(delta)
	} else {
		v.tbl.MoveUp(-delta)
	}
}

func (v *logsView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	if v.editing {
		return v.handleEditKey(k)
	}
	switch k.String() {
	case "j", "down":
		v.tbl.MoveDown(1)
	case "k":
		// 'k' cycles kind (the footer hint), 'down'/'up' move — vim 'k'=up is overloaded
		// here with the kind cycle since LOGS is query-centric; use ↑ to move up.
		v.cycleKind()
		return app, v.runQuery()
	case "up":
		v.tbl.MoveUp(1)
	case "g":
		v.tbl.GotoTop()
	case "G":
		v.tbl.GotoBottom()
	case "ctrl+d":
		v.tbl.MoveDown(v.h / 2)
	case "ctrl+u":
		v.tbl.MoveUp(v.h / 2)
	case "r":
		return app, v.runQuery()
	case "t":
		v.editing, v.editWhat, v.editBuf = true, "from", v.from
	case "enter":
		return app.openDrillEvent(v.selectedEvent())
	}
	return app, nil
}

func (v *logsView) handleEditKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "enter":
		v.from = v.editBuf
		v.editing = false
		return v.app, v.runQuery()
	case "esc":
		v.editing = false
	case "backspace":
		if v.editBuf != "" {
			v.editBuf = v.editBuf[:len(v.editBuf)-1]
		}
	default:
		if len(k.String()) == 1 {
			v.editBuf += k.String()
		}
	}
	return v.app, nil
}

func (v *logsView) cycleKind() {
	next := map[string]string{"": "dns", "dns": "conn", "conn": "alloc", "alloc": ""}
	v.kind = next[v.kind]
}

func (v *logsView) selectedEvent() (model.Event, bool) {
	c := v.tbl.Cursor()
	if c >= 0 && c < len(v.events) {
		return v.events[c], true
	}
	return model.Event{}, false
}

func (v *logsView) view(w, h int) string {
	th := v.app.th
	// Filter band.
	from := v.from
	if v.editing && v.editWhat == "from" {
		from = v.editBuf + "▌"
	}
	band := fmt.Sprintf("%s %s   %s %s   %s %s   %s",
		th.Dim.Render("from"), th.Accent.Render(from),
		th.Dim.Render("kind"), th.Accent.Render(orPlaceholder(v.kind, "all")),
		th.Dim.Render("agent"), th.Text.Render(orPlaceholder(v.agent, "all")),
		th.Dim.Render(fmt.Sprintf("%d events", len(v.events))))
	if v.loading {
		band += "  " + th.Warn.Render("querying…")
	}
	body := v.tbl.View()
	inner := lipgloss.JoinVertical(lipgloss.Left, " "+band, body)
	panel := th.Panel.Width(w - 2).Height(h - 2).Render(inner)
	return v.app.titledPanel(panel, "LOGS  op:logs (warm history)", w)
}

// noop to satisfy a strings import if the build trims it later.
var _ = strings.TrimSpace
