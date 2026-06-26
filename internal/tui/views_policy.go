// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// policyView is the POLICY tab: the per-tenant DNS resolver policy editor. It reads the
// current policy (op:policy, no args), lets the operator stage allow/block entries and
// a default action, then writes them back (op:policy with args) on `w`. Edits are
// LOCAL until written — nothing hits the control plane until the operator confirms.
type policyView struct {
	app    *App
	w, h   int
	loaded bool

	defaultAction string   // allow | deny (server's current/staged)
	block         []string // staged block list
	allow         []string // staged allow list
	dirty         bool

	// inline entry editor
	editing  bool
	editKind string // "block" | "allow"
	editBuf  string

	cursor int // selection within the combined list (for delete)
}

func newPolicyView(app *App) *policyView {
	return &policyView{app: app, defaultAction: "allow"}
}

func (v *policyView) resize(w, h int) { v.w, v.h = w, h }

func (v *policyView) capturing() bool { return v.editing }

// onPolicy folds an op:policy read-back into the staged state.
func (v *policyView) onPolicy(m policyMsg) {
	v.loaded = true
	if m.err != nil {
		v.app.setToast(friendlyErr(m.err), true)
		return
	}
	v.block, v.allow = nil, nil
	for _, r := range m.rows {
		switch strings.ToLower(r.Key) {
		case "default":
			if r.Value != "" {
				v.defaultAction = r.Value
			}
		case "block":
			v.block = append(v.block, r.Value)
		case "allow":
			v.allow = append(v.allow, r.Value)
		}
	}
	v.dirty = false
}

func (v *policyView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	if v.editing {
		return v.handleEditKey(k)
	}
	switch k.String() {
	case "b":
		v.editing, v.editKind, v.editBuf = true, "block", ""
	case "a":
		v.editing, v.editKind, v.editBuf = true, "allow", ""
	case "d":
		if v.defaultAction == "allow" {
			v.defaultAction = "deny"
		} else {
			v.defaultAction = "allow"
		}
		v.dirty = true
	case "j", "down":
		v.cursor++
		v.clampCursor()
	case "k", "up":
		v.cursor--
		v.clampCursor()
	case "x", "delete":
		v.deleteAt(v.cursor)
	case "r":
		return app, loadPolicy(app.client)
	case "w":
		if !v.dirty {
			app.setToast("no changes to write", false)
			return app, nil
		}
		return app, v.write()
	}
	return app, nil
}

func (v *policyView) handleEditKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "enter":
		val := strings.TrimSpace(v.editBuf)
		if val != "" {
			if v.editKind == "block" {
				v.block = append(v.block, val)
			} else {
				v.allow = append(v.allow, val)
			}
			v.dirty = true
		}
		v.editing = false
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

// write stages an op:policy write of the current allow/block/default.
func (v *policyView) write() tea.Cmd {
	args := map[string]any{"default": v.defaultAction}
	if len(v.block) > 0 {
		args["block"] = toAnyList(v.block)
	}
	if len(v.allow) > 0 {
		args["allow"] = toAnyList(v.allow)
	}
	v.dirty = false
	return runWrite(v.app.client, "policy", args)
}

func (v *policyView) clampCursor() {
	n := len(v.block) + len(v.allow)
	if v.cursor < 0 {
		v.cursor = 0
	}
	if v.cursor >= n {
		v.cursor = n - 1
	}
	if v.cursor < 0 {
		v.cursor = 0
	}
}

func (v *policyView) deleteAt(i int) {
	if i < len(v.block) {
		v.block = append(v.block[:i], v.block[i+1:]...)
		v.dirty = true
	} else {
		j := i - len(v.block)
		if j >= 0 && j < len(v.allow) {
			v.allow = append(v.allow[:j], v.allow[j+1:]...)
			v.dirty = true
		}
	}
	v.clampCursor()
}

func (v *policyView) view(w, h int) string {
	th := v.app.th
	var b strings.Builder

	defStyle := th.OK
	if v.defaultAction == "deny" {
		defStyle = th.Error
	}
	b.WriteString(fmt.Sprintf("%s %s    %s\n\n",
		th.Dim.Render("default action"), defStyle.Render(strings.ToUpper(v.defaultAction)),
		th.Dim.Render("(d toggle)")))

	idx := 0
	emit := func(label string, list []string, st lipgloss.Style) {
		b.WriteString(st.Render(label) + th.Dim.Render(fmt.Sprintf("  (%d)", len(list))) + "\n")
		if len(list) == 0 {
			b.WriteString("  " + th.Dim.Render("(none)") + "\n")
		}
		for _, e := range list {
			cursor := "  "
			line := th.Text.Render(e)
			if idx == v.cursor {
				cursor = th.Accent.Render("▌ ")
				line = th.Selected.Render(e)
			}
			b.WriteString(cursor + line + "\n")
			idx++
		}
		b.WriteString("\n")
	}
	emit("BLOCK", v.block, th.Error)
	emit("ALLOW", v.allow, th.OK)

	if v.editing {
		b.WriteString(th.Accent.Render(fmt.Sprintf("add %s: ", v.editKind)) + v.editBuf + "▌\n")
	}
	if v.dirty {
		b.WriteString("\n" + th.Warn.Render("unwritten changes — press  w  to apply") + "\n")
	}
	if !v.loaded {
		b.WriteString(th.Dim.Render("loading current policy…") + "\n")
	}

	panel := th.Panel.Width(w - 2).Height(h - 2).Render(clampLines(b.String(), h-2))
	return v.app.titledPanel(panel, "POLICY  per-tenant DNS resolver", w)
}

func toAnyList(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
