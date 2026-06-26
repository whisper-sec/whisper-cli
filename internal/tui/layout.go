// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/tui/components"
)

// Layout constants (rows reserved for chrome). The body height is what's left for the
// active view + the always-on monitor panel.
const (
	headerRows = 1
	tabRows    = 1
	footerRows = 1
	// monitorRows is the always-on live panel height (border + a few feed lines). It
	// shrinks on short terminals and is hidden entirely when there is no room.
	monitorRowsDefault = 7
)

// layout recomputes derived geometry after a resize. It is cheap and idempotent.
func (a *App) layout() {
	a.agentsView.resize(a.bodyWidth(), a.viewHeight())
	a.logsView.resize(a.bodyWidth(), a.bodyHeight())
	a.policyView.resize(a.bodyWidth(), a.bodyHeight())
	a.monitorVw.resize(a.bodyWidth(), a.bodyHeight())
}

func (a *App) bodyWidth() int { return a.width }

// bodyHeight is the space between the tab bar and the footer (the whole content area).
func (a *App) bodyHeight() int {
	h := a.height - headerRows - tabRows - footerRows
	if h < 1 {
		h = 1
	}
	return h
}

// monitorRows returns the always-on monitor panel height for the AGENTS view, scaling
// down on short terminals and disappearing when there is no room (graceful degrade).
func (a *App) monitorRows() int {
	if a.bodyHeight() < 16 {
		return 0 // too short — drop the always-on panel; the MONITOR tab still has it
	}
	r := monitorRowsDefault
	if a.bodyHeight() < 24 {
		r = 5
	}
	return r
}

// viewHeight is the active view's height on the AGENTS dashboard (body minus the
// always-on monitor panel).
func (a *App) viewHeight() int {
	h := a.bodyHeight() - a.monitorRows()
	if h < 1 {
		h = 1
	}
	return h
}

// --- header ----------------------------------------------------------------------

func (a *App) renderHeader() string {
	left := a.th.Header.Render(" whisper ")
	tenant := a.opts.Tenant
	if tenant == "" {
		tenant = "—"
	}
	keyMark := a.th.OK.Render("key ✓")
	if a.client == nil || a.client.Credential().IsZero() {
		keyMark = a.th.Error.Render("key ✗")
	}
	node := a.opts.Node
	if node == "" {
		node = "ns"
	}
	streamDot := a.th.Dim.Render("○")
	switch a.stream {
	case streamConn:
		streamDot = a.th.OK.Render("●")
	case streamPoll:
		streamDot = a.th.Warn.Render("⤓")
	case streamRetry:
		streamDot = a.th.Warn.Render("◌")
	}
	right := fmt.Sprintf("tenant %s · %s · %s %s",
		a.th.Dim.Render(components.ShortAddr(tenant, 5, 3)), keyMark, node, streamDot)
	return a.bar(left, right)
}

// renderTabs draws the AGENTS · MONITOR · LOGS · POLICY · CONFIG tab strip.
func (a *App) renderTabs() string {
	var tabs []string
	for i, name := range modeNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if mode(i) == a.mode {
			tabs = append(tabs, a.th.TabActive.Render(label))
		} else {
			tabs = append(tabs, a.th.TabIdle.Render(label))
		}
	}
	left := strings.Join(tabs, a.th.Dim.Render(" · "))
	right := a.th.Dim.Render("⌘ palette  ? help")
	return a.bar(left, right)
}

// --- footer ----------------------------------------------------------------------

func (a *App) renderFooter() string {
	if a.toast != "" {
		st := a.th.Dim
		if a.toastErr {
			st = a.th.Error
		}
		return a.padLine(st.Render(" " + a.toast))
	}
	hints := a.footerHints()
	return a.padLine(a.th.Help.Render(" " + hints))
}

// footerHints returns the context-sensitive keybinding hints for the active view.
func (a *App) footerHints() string {
	switch a.mode {
	case modeAgents:
		return "j/k move · ↵ details · c create · x kill · e connect · m monitor · / filter · : palette · q quit"
	case modeMonitor:
		return "space pause · f kind · / filter · ↵ drill · s agent · 1 agents · q quit"
	case modeLogs:
		return "j/k move · ↵ drill · r run · k kind · t time · / filter · q quit"
	case modePolicy:
		return "a allow · b block · d default · w write · r reload · q quit"
	case modeConfig:
		return "t theme · l login · 1 agents · q quit"
	default:
		return "q quit"
	}
}

// --- body dispatch ---------------------------------------------------------------

func (a *App) renderBody() string {
	switch a.mode {
	case modeAgents:
		return a.renderAgentsDashboard()
	case modeMonitor:
		return a.monitorVw.view(a.bodyWidth(), a.bodyHeight())
	case modeLogs:
		return a.logsView.view(a.bodyWidth(), a.bodyHeight())
	case modePolicy:
		return a.policyView.view(a.bodyWidth(), a.bodyHeight())
	case modeConfig:
		return a.configView.view(a.bodyWidth(), a.bodyHeight())
	}
	return ""
}

// renderAgentsDashboard composes the AGENTS view: the fleet+detail region on top and
// the always-on live monitor panel underneath. On a first-run empty fleet it shows the
// centred hero instead.
func (a *App) renderAgentsDashboard() string {
	if len(a.agents) == 0 && !a.loading {
		return a.renderHero(a.bodyWidth(), a.bodyHeight())
	}
	top := a.agentsView.view(a.bodyWidth(), a.viewHeight())
	mr := a.monitorRows()
	if mr <= 0 {
		return top
	}
	mon := a.renderLiveStrip(a.bodyWidth(), mr)
	return lipgloss.JoinVertical(lipgloss.Left, top, mon)
}

// renderHero is the first-run welcome: a centred whisper mark + "press c to create".
func (a *App) renderHero(w, h int) string {
	mark := a.th.Hero.Render("whisper")
	sub := a.th.Dim.Render("identity-on-the-wire DNS — an agent IS a routable /128")
	cta := a.th.Accent.Render("press  c  to create your first agent") + "\n" +
		a.th.Dim.Render("or  :  for the command palette  ·  ?  for help")
	loading := ""
	if a.loading {
		loading = "\n\n" + a.th.Dim.Render("loading your fleet…")
	}
	block := lipgloss.JoinVertical(lipgloss.Center, mark, "", sub, "", cta) + loading
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, block)
}

// --- shared bar helpers ----------------------------------------------------------

// bar lays out a left and right segment across the full width (right-aligned tail).
func (a *App) bar(left, right string) string {
	lw := lipgloss.Width(left)
	rw := lipgloss.Width(right)
	gap := a.width - lw - rw
	if gap < 1 {
		// Not enough room: keep the left segment, drop the right (never wrap/overflow).
		return a.padLine(left)
	}
	return left + strings.Repeat(" ", gap) + right
}

// padLine pads a single line to the full width so the row paints edge-to-edge.
func (a *App) padLine(s string) string {
	w := lipgloss.Width(s)
	if w >= a.width {
		return s
	}
	return s + strings.Repeat(" ", a.width-w)
}
