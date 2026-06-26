// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// handleKey routes a key press. Overlays (palette/modal/help) get first refusal; then
// the global keys; then the active view's vim-ish bindings. Returns the next command.
func (a *App) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// 1. An open overlay consumes keys first.
	if a.overlay != overlayNone {
		return a.handleOverlayKey(k)
	}

	// 2. If a view is in a text-input sub-mode (e.g. the LOGS filter / POLICY entry),
	//    let it consume keys before the global single-letter shortcuts.
	if a.viewCapturesInput() {
		return a.routeToView(k)
	}

	// 3. Global keys.
	switch k.String() {
	case "ctrl+c":
		return a.quit()
	case "q":
		return a.quit()
	case ":", "ctrl+p", "ctrl+k":
		a.openPalette()
		return a, nil
	case "?":
		a.overlay = overlayHelp
		return a, nil
	case "tab":
		a.mode = mode((int(a.mode) + 1) % len(modeNames))
		a.layout()
		return a, a.onEnterMode()
	case "shift+tab":
		a.mode = mode((int(a.mode) - 1 + len(modeNames)) % len(modeNames))
		a.layout()
		return a, a.onEnterMode()
	case "1", "2", "3", "4", "5":
		a.mode = mode(int(k.String()[0] - '1'))
		a.layout()
		return a, a.onEnterMode()
	case "ctrl+r":
		a.loading = true
		return a, tea.Batch(loadFleet(a.client), a.viewReloadCmd())
	case "ctrl+t":
		a.cycleTheme()
		return a, nil
	}

	// 4. Action keys that apply across the dashboard (create/connect from anywhere).
	switch k.String() {
	case "c":
		return a.openCreate()
	case "e":
		return a.openConnect()
	}

	// 5. Otherwise route to the active view.
	return a.routeToView(k)
}

// routeToView dispatches a key to the active view's Update.
func (a *App) routeToView(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.mode {
	case modeAgents:
		return a.agentsView.handleKey(k)
	case modeMonitor:
		return a.monitorVw.handleKey(k)
	case modeLogs:
		return a.logsView.handleKey(k)
	case modePolicy:
		return a.policyView.handleKey(k)
	case modeConfig:
		return a.configView.handleKey(k)
	}
	return a, nil
}

// viewCapturesInput reports whether the active view is currently in a text-entry mode
// (so single-letter global shortcuts don't steal keystrokes).
func (a *App) viewCapturesInput() bool {
	switch a.mode {
	case modeAgents:
		return a.agentsView.filtering
	case modeLogs:
		return a.logsView.capturing()
	case modePolicy:
		return a.policyView.capturing()
	}
	return false
}

// onEnterMode lazily loads data for the view we just switched to.
func (a *App) onEnterMode() tea.Cmd {
	switch a.mode {
	case modeLogs:
		return a.logsView.onEnter()
	case modePolicy:
		if !a.policyView.loaded {
			return loadPolicy(a.client)
		}
	case modeMonitor:
		return a.monitorVw.onEnter()
	}
	return nil
}

// viewReloadCmd returns the per-view reload command for Ctrl-R.
func (a *App) viewReloadCmd() tea.Cmd {
	switch a.mode {
	case modeLogs:
		return a.logsView.runQuery()
	case modePolicy:
		return loadPolicy(a.client)
	}
	return nil
}

// cycleTheme advances to the next built-in theme (Ctrl-T) and rebuilds the style set.
func (a *App) cycleTheme() {
	next := theme.Next(a.th.Name)
	a.th = theme.New(next, a.opts.NoColor, a.opts.Light)
	a.opts.ThemeName = next
	a.agentsView.retheme()
	a.setToast("theme: "+string(next), false)
}

// quit cancels the stream and ends the program.
func (a *App) quit() (tea.Model, tea.Cmd) {
	a.quitting = true
	a.stopStream()
	return a, tea.Quit
}

// handleMouse supports click-to-select (rows), click-tabs, and wheel scroll. Keyboard
// is always fully sufficient; the mouse is a convenience (accessibility).
func (a *App) handleMouse(m tea.MouseMsg) (tea.Model, tea.Cmd) {
	if a.overlay != overlayNone {
		return a, nil
	}
	switch m.Action {
	case tea.MouseActionPress:
		switch m.Button {
		case tea.MouseButtonWheelUp:
			return a.routeWheel(-1)
		case tea.MouseButtonWheelDown:
			return a.routeWheel(1)
		case tea.MouseButtonLeft:
			// Row 1 is the tab bar (header is row 0): map an X to a tab.
			if m.Y == tabRows { // header(0) then tabs(1)
				if idx := a.tabAtX(m.X); idx >= 0 {
					a.mode = mode(idx)
					a.layout()
					return a, a.onEnterMode()
				}
			}
		}
	}
	return a, nil
}

func (a *App) routeWheel(delta int) (tea.Model, tea.Cmd) {
	switch a.mode {
	case modeAgents:
		a.agentsView.move(delta)
		return a, a.refreshSelectedDetail()
	case modeLogs:
		a.logsView.move(delta)
	case modeMonitor:
		a.monitorVw.scroll(delta)
	}
	return a, nil
}

// tabAtX maps a click X to a tab index (approximate, generous hit-boxes).
func (a *App) tabAtX(x int) int {
	// Each tab is "N NAME" + " · " separators; approximate by even division across the
	// left ~60% of the width. Good enough for a convenience affordance.
	span := a.width * 6 / 10
	if span < len(modeNames) {
		span = len(modeNames)
	}
	idx := x * len(modeNames) / span
	if idx < 0 || idx >= len(modeNames) {
		return -1
	}
	return idx
}
