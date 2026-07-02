// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// handleOverlayKey routes a key to whichever overlay is open. Forms (create/kill/
// connect) delegate to Huh and submit on completion; the simple cards close on Esc/q.
func (a *App) handleOverlayKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.overlay {
	case overlayPalette:
		return a.palette.handleKey(k)
	case overlayHelp, overlayDrill, overlayResult:
		switch k.String() {
		case "esc", "q", "enter", "ctrl+c":
			a.overlay = overlayNone
		}
		return a, nil
	case overlayCreate:
		return a.updateCreate(k)
	case overlayKill:
		return a.updateKill(k)
	case overlayConnect:
		return a.updateConnect(k)
	}
	return a, nil
}

// updateCreate steps the create form; on completion it fires op:identity or op:register.
// It accepts ANY tea.Msg — huh advances fields/groups via its own internal messages
// (delivered as commands), so a KeyMsg-only diet leaves the form frozen.
func (a *App) updateCreate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "esc" {
		a.overlay = overlayNone
		return a, nil
	}
	f := a.create
	m, cmd := f.form.Update(msg)
	if ff, ok := m.(*huh.Form); ok {
		f.form = ff
	}
	if f.form.State == huh.StateAborted {
		a.overlay = overlayNone // ctrl+c aborts the form — never a dead overlay
		return a, nil
	}
	if f.form.State == huh.StateCompleted {
		// Build the write through the ONE shared guard (§3.2): it re-applies the
		// trimmed-non-blank name check at the write layer, so a blank name can NEVER create
		// an unnamed agent here even if the field validator was bypassed (defense in depth).
		// A blank name keeps the modal OPEN with a friendly toast — we don't fire the op.
		op, args, err := buildCreateArgs(f.label, f.contact, f.register)
		if err != nil {
			a.setToast(err.Error(), true)
			return a, cmd
		}
		a.overlay = overlayNone
		return a, runWrite(a.client, op, args)
	}
	return a, cmd
}

// updateKill steps the kill form; on completion it confirms the typed name and fires
// op:revoke or op:identity{release}. Accepts ANY tea.Msg — see updateCreate.
func (a *App) updateKill(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "esc" {
		a.overlay = overlayNone
		return a, nil
	}
	f := a.kill
	m, cmd := f.form.Update(msg)
	if ff, ok := m.(*huh.Form); ok {
		f.form = ff
	}
	if f.form.State == huh.StateAborted {
		a.overlay = overlayNone // ctrl+c aborts the form — never a dead overlay
		return a, nil
	}
	if f.form.State == huh.StateCompleted {
		a.overlay = overlayNone
		if strings.TrimSpace(f.confirm) != f.target.Name() {
			a.setToast("name didn't match — nothing released", true)
			return a, nil
		}
		if f.revoke {
			sel := f.target.ID
			if sel == "" {
				sel = f.target.Address
			}
			return a, runWrite(a.client, "revoke", map[string]any{"agent": sel})
		}
		// release the /128: op:identity{release, address}
		if f.target.Address == "" {
			a.setToast("this agent has no /128 to release", true)
			return a, nil
		}
		return a, runWrite(a.client, "identity", map[string]any{"release": true, "address": f.target.Address})
	}
	return a, cmd
}

// updateConnect steps the connect form; on completion it fires op:connect.
// Accepts ANY tea.Msg — see updateCreate.
func (a *App) updateConnect(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "esc" {
		a.overlay = overlayNone
		return a, nil
	}
	f := a.connect
	m, cmd := f.form.Update(msg)
	if ff, ok := m.(*huh.Form); ok {
		f.form = ff
	}
	if f.form.State == huh.StateAborted {
		a.overlay = overlayNone // ctrl+c aborts the form — never a dead overlay
		return a, nil
	}
	if f.form.State == huh.StateCompleted {
		a.overlay = overlayNone
		return a, runWrite(a.client, "connect", map[string]any{"tier": f.tier})
	}
	return a, cmd
}

// --- rendering -------------------------------------------------------------------

// renderOverlay centres the active overlay over a dimmed frame.
func (a *App) renderOverlay(frame string) string {
	var box string
	switch a.overlay {
	case overlayPalette:
		box = a.palette.view()
	case overlayHelp:
		box = a.helpCard()
	case overlayCreate:
		box = a.formCard("create agent", a.create.form.View())
	case overlayKill:
		box = a.formCard("kill / revoke agent", a.kill.form.View())
	case overlayConnect:
		box = a.formCard("provision egress", a.connect.form.View())
	case overlayDrill:
		box = a.jsonCard("detail", a.drill)
	case overlayResult:
		box = a.jsonCard("result", a.result)
	default:
		return a.th.App.Render(frame)
	}
	overlaid := lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, box)
	return a.th.App.MaxWidth(a.width).MaxHeight(a.height).Render(overlaid)
}

func (a *App) formCard(title, body string) string {
	th := a.th
	footer := th.Dim.Render("enter submit · esc cancel")
	// Card content (66-4 padding = 62) must be WIDER than the huh forms (≤56): a card
	// narrower than its form re-wraps huh's already-wrapped lines mid-token.
	// Clamp to the terminal so a narrow window never overflows.
	w := min(66, a.width-4)
	return th.ModalBox.Width(w).Render(
		th.ModalTitle.Render(title) + "\n\n" + body + "\n" + footer)
}

func (a *App) jsonCard(title, body string) string {
	th := a.th
	w := min(a.width-8, 76)
	if w < 30 {
		w = 30
	}
	footer := th.Dim.Render("esc / q close")
	return th.ModalBox.Width(w).Render(
		th.ModalTitle.Render(title) + "\n\n" + th.Text.Render(body) + "\n\n" + footer)
}

func (a *App) helpCard() string {
	th := a.th
	sec := func(s string) string { return th.Accent.Render(s) }
	key := func(s string) string { return th.Key.Render(s) }
	lines := []string{
		sec("global"),
		"  " + key("1–5") + " switch view   " + key("tab") + " cycle   " + key(":") + "/" + key("⌃P") + " palette   " + key("?") + " help",
		"  " + key("⌃R") + " refresh   " + key("⌃T") + " theme   " + key("q") + "/" + key("⌃C") + " quit",
		"",
		sec("fleet (AGENTS)"),
		"  " + key("j/k") + " move   " + key("g/G") + " top/bottom   " + key("⌃D/⌃U") + " half-page",
		"  " + key("/") + " filter   " + key("n/N") + " next/prev   " + key("⇧K") + " sort   " + key("z") + " density",
		"  " + key("↵") + " details   " + key("c") + " create   " + key("x") + " kill   " + key("e") + " connect",
		"  " + key("m") + " monitor   " + key("v") + " RDAP",
		"",
		sec("monitor"),
		"  " + key("space") + " pause   " + key("f") + " kind filter   " + key("/") + " filter",
		"  " + key("s") + " select agent   " + key("↵") + " drill",
		"",
		sec("logs / policy"),
		"  LOGS: " + key("r") + " run   " + key("t") + " time   " + key("k") + " kind   " + key("↵") + " drill",
		"  POLICY: " + key("a") + " allow   " + key("b") + " block   " + key("d") + " default   " + key("w") + " write",
	}
	head := th.ModalTitle.Render("whisper — keybindings")
	// The brand mark tops the card when colour + height allow ( approved art).
	if art := renderLogo(logoIcon, th.NoColor); art != "" && a.height >= 34 {
		head = lipgloss.JoinVertical(lipgloss.Center, art, "", head)
	}
	return th.ModalBox.Width(min(64, a.width-4)).Render(
		head + "\n\n" +
			strings.Join(lines, "\n") + "\n\n" + th.Dim.Render("esc / q close"))
}

// huhTheme adapts a Huh theme to the active palette so the modals match the dashboard.
func (a *App) huhTheme() *huh.Theme {
	t := huh.ThemeBase()
	if a.th.NoColor {
		return t // base is colourless-friendly
	}
	p := a.th.Pal
	accent := lipgloss.Color(p.Accent)
	text := lipgloss.Color(p.Text)
	dim := lipgloss.Color(p.Dim)
	t.Focused.Title = t.Focused.Title.Foreground(accent).Bold(true)
	t.Focused.Description = t.Focused.Description.Foreground(dim)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(accent)
	t.Focused.Base = t.Focused.Base.BorderForeground(accent)
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(accent)
	t.Focused.TextInput.Text = t.Focused.TextInput.Text.Foreground(text)
	t.Blurred.Title = t.Blurred.Title.Foreground(dim)
	return t
}
