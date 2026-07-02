// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// command is one palette entry: a title, an op-preview (what control verb it runs), and
// the action it triggers on the App.
type command struct {
	title   string
	preview string // the control op it maps to (shown dimmed, gh-dash style)
	run     func(*App) (tea.Model, tea.Cmd)
}

// palette is the Ctrl-P / : command palette: a fuzzy-filtered command list with an
// op-preview column. Keyboard-only; the whole surface is reachable from here.
type palette struct {
	app      *App
	input    textinput.Model
	all      []command
	filtered []command
	cursor   int
}

func newPalette(app *App) *palette {
	in := textinput.New()
	in.Placeholder = "type a command…"
	in.Prompt = "> "
	in.CharLimit = 64
	p := &palette{app: app, input: in}
	p.all = p.commands()
	p.filtered = p.all
	return p
}

// commands is the closed set of palette actions, each previewing its control op.
func (p *palette) commands() []command {
	return []command{
		{"create agent", "op:identity / op:register", func(a *App) (tea.Model, tea.Cmd) { return a.openCreate() }},
		{"connect (egress)", "op:connect {tier:socks5}", func(a *App) (tea.Model, tea.Cmd) { return a.openConnect() }},
		{"kill / revoke agent", "op:identity{release} / op:revoke", func(a *App) (tea.Model, tea.Cmd) { return a.openKill() }},
		{"RDAP lookup", "rdap.whisper.online/ip", func(a *App) (tea.Model, tea.Cmd) { return a.openRDAP() }},
		{"go to AGENTS", "view", func(a *App) (tea.Model, tea.Cmd) { a.mode = modeAgents; a.layout(); return a, nil }},
		{"go to MONITOR", "view · /monitor/stream", func(a *App) (tea.Model, tea.Cmd) { a.mode = modeMonitor; a.layout(); return a, a.onEnterMode() }},
		{"go to LOGS", "view · op:logs", func(a *App) (tea.Model, tea.Cmd) { a.mode = modeLogs; a.layout(); return a, a.onEnterMode() }},
		{"go to POLICY", "view · op:policy", func(a *App) (tea.Model, tea.Cmd) { a.mode = modePolicy; a.layout(); return a, a.onEnterMode() }},
		{"go to CONFIG", "view", func(a *App) (tea.Model, tea.Cmd) { a.mode = modeConfig; a.layout(); return a, nil }},
		{"refresh fleet", "op:list {kind:'agents'}", func(a *App) (tea.Model, tea.Cmd) { a.loading = true; return a, loadFleet(a.client) }},
		{"cycle theme", "local", func(a *App) (tea.Model, tea.Cmd) { a.cycleTheme(); return a, nil }},
		{"help", "local", func(a *App) (tea.Model, tea.Cmd) { a.overlay = overlayHelp; return a, nil }},
		{"quit", "local", func(a *App) (tea.Model, tea.Cmd) { return a.quit() }},
	}
}

// open resets and focuses the palette.
func (a *App) openPalette() {
	p := a.palette
	p.input.SetValue("")
	p.input.Focus()
	p.filter()
	p.cursor = 0
	a.overlay = overlayPalette
}

func (p *palette) filter() {
	q := strings.ToLower(strings.TrimSpace(p.input.Value()))
	if q == "" {
		p.filtered = p.all
		return
	}
	// A fresh slice every time: p.filtered aliases p.all whenever the query is empty,
	// so `p.filtered[:0]` + append would overwrite p.all's backing array in place and
	// permanently corrupt the command list.
	p.filtered = make([]command, 0, len(p.all))
	for _, c := range p.all {
		if fuzzyMatch(strings.ToLower(c.title), q) || strings.Contains(strings.ToLower(c.preview), q) {
			p.filtered = append(p.filtered, c)
		}
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = 0
	}
}

// handleKey drives the palette overlay.
func (p *palette) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	a := p.app
	switch k.String() {
	case "esc", "ctrl+c":
		a.overlay = overlayNone
		return a, nil
	case "enter":
		a.overlay = overlayNone
		if p.cursor >= 0 && p.cursor < len(p.filtered) {
			return p.filtered[p.cursor].run(a)
		}
		return a, nil
	case "down", "ctrl+n":
		if p.cursor < len(p.filtered)-1 {
			p.cursor++
		}
		return a, nil
	case "up", "ctrl+p":
		if p.cursor > 0 {
			p.cursor--
		}
		return a, nil
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(k)
	p.filter()
	return a, cmd
}

// view renders the palette box centred over the frame.
func (p *palette) view() string {
	th := p.app.th
	var b strings.Builder
	b.WriteString(p.input.View() + "\n")
	b.WriteString(th.Dim.Render(strings.Repeat("─", 48)) + "\n")
	if len(p.filtered) == 0 {
		b.WriteString(th.Dim.Render("  no matching command"))
	}
	for i, c := range p.filtered {
		if i > 9 {
			break
		}
		bullet := th.Dim.Render("○")
		title := th.Text.Render(c.title)
		if i == p.cursor {
			bullet = th.Accent.Render("●")
			title = th.Accent.Render(c.title)
		}
		// Clamp to the box's inner width (54 minus Padding(1,2)) — a long preview
		// truncates, never wraps the two-column row onto a second line.
		line := truncate(bullet+" "+pad(title, 26)+th.Dim.Render(c.preview), 50)
		b.WriteString(line + "\n")
	}
	box := th.ModalBox.Width(54).Render(
		th.ModalTitle.Render("⌘ command palette") + "\n\n" + b.String())
	return box
}

// fuzzyMatch reports whether all runes of needle appear in haystack in order.
func fuzzyMatch(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	hi := 0
	hr := []rune(haystack)
	for _, nr := range needle {
		found := false
		for hi < len(hr) {
			if hr[hi] == nr {
				found = true
				hi++
				break
			}
			hi++
		}
		if !found {
			return false
		}
	}
	return true
}

// pad pads a (possibly ANSI-styled) string to a visible width.
func pad(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}
