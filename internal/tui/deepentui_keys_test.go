// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// deepentui_rune builds a plain-rune key message ("q", "c", ":", ...).
func deepentui_rune(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

// deepentui_seedAgents installs a small fleet and syncs the table.
func deepentui_seedAgents(a *App) {
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", Label: "scraper", State: "active", Created: 3},
		{ID: "agent-2", Address: "2a04:2a01::2", Label: "crawler", State: "active", Created: 2},
		{ID: "agent-3", Address: "2a04:2a01::3", Label: "prober", State: "released", Created: 1},
	}
	a.selected = 0
	a.agentsView.syncRows()
}

// TestKeysQuitPaths asserts q and ctrl+c both end the program (quitting set, tea.Quit
// returned) and that the quitting frame renders empty (the terminal is handed back clean).
func TestKeysQuitPaths(t *testing.T) {
	for _, k := range []tea.KeyMsg{deepentui_rune('q'), {Type: tea.KeyCtrlC}} {
		a := newTestApp(t, 100, 30)
		_, cmd := a.handleKey(k)
		if !a.quitting {
			t.Fatalf("%q should set quitting", k.String())
		}
		if cmd == nil {
			t.Fatalf("%q should return a command", k.String())
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("%q should return tea.Quit; got %T", k.String(), cmd())
		}
		if out := a.View(); out != "" {
			t.Errorf("the quitting frame must be empty; got %q", out)
		}
	}
}

// TestKeysTabCycleWraps asserts tab / shift+tab cycle the full mode ring in both
// directions, including the wrap at each end.
func TestKeysTabCycleWraps(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.mode = modeConfig
	a.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if a.mode != modeExplore {
		t.Errorf("tab from CONFIG should wrap to EXPLORE; got %s", modeNames[a.mode])
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyShiftTab})
	if a.mode != modeConfig {
		t.Errorf("shift+tab from EXPLORE should wrap back to CONFIG; got %s", modeNames[a.mode])
	}
}

// TestKeysDigitsJumpToMode asserts 1..6 land exactly on their tab (the order).
func TestKeysDigitsJumpToMode(t *testing.T) {
	a := newTestApp(t, 100, 30)
	want := []mode{modeExplore, modeAgents, modeGraph, modeLogs, modePolicy, modeConfig}
	for i, r := range []rune{'1', '2', '3', '4', '5', '6'} {
		a.handleKey(deepentui_rune(r))
		if a.mode != want[i] {
			t.Errorf("digit %c should land on %s; got %s", r, modeNames[want[i]], modeNames[a.mode])
		}
	}
}

// TestKeysPaletteVsRepl asserts ':' opens the raw-Cypher REPL in EXPLORE (the spec
// keymap) but the palette everywhere else, and ctrl+p / ctrl+k stay palette even there.
func TestKeysPaletteVsRepl(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.mode = modeAgents
	a.handleKey(deepentui_rune(':'))
	if a.overlay != overlayPalette {
		t.Fatalf("':' outside EXPLORE should open the palette; overlay=%v", a.overlay)
	}
	a.overlay = overlayNone

	a.mode = modeExplore
	a.handleKey(deepentui_rune(':'))
	if a.overlay != overlayNone || a.exploreVw.ov != ovRepl {
		t.Fatalf("':' in EXPLORE should open the REPL, not the palette (overlay=%v ov=%v)", a.overlay, a.exploreVw.ov)
	}
	a.exploreVw.ov = ovNone

	a.handleKey(tea.KeyMsg{Type: tea.KeyCtrlP})
	if a.overlay != overlayPalette {
		t.Error("ctrl+p must open the palette even in EXPLORE")
	}
	a.overlay = overlayNone
	a.handleKey(tea.KeyMsg{Type: tea.KeyCtrlK})
	if a.overlay != overlayPalette {
		t.Error("ctrl+k must open the palette even in EXPLORE")
	}
}

// TestKeysGlobalShortcuts covers ?, c, e, ctrl+r and ctrl+t.
func TestKeysGlobalShortcuts(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.handleKey(deepentui_rune('?'))
	if a.overlay != overlayHelp {
		t.Error("? should open help")
	}
	a.overlay = overlayNone

	_, cmd := a.handleKey(deepentui_rune('c'))
	if a.overlay != overlayCreate || cmd == nil {
		t.Error("c should open the create modal with its form init command")
	}
	a.overlay = overlayNone

	_, cmd = a.handleKey(deepentui_rune('e'))
	if a.overlay != overlayConnect || cmd == nil {
		t.Error("e should open the connect modal with its form init command")
	}
	a.overlay = overlayNone

	a.loading = false
	_, cmd = a.handleKey(tea.KeyMsg{Type: tea.KeyCtrlR})
	if !a.loading || cmd == nil {
		t.Error("ctrl+r should mark loading and fire the reload commands")
	}

	before := a.th.Name
	a.handleKey(tea.KeyMsg{Type: tea.KeyCtrlT})
	if a.th.Name == before {
		t.Error("ctrl+t should advance the theme")
	}
}

// TestKeysTextEntryNeverStolen is the protective contract: while a view is in
// a text-entry sub-mode, the single-letter global shortcuts (q quit, c create, e connect)
// must land in the text, never fire their global action.
func TestKeysTextEntryNeverStolen(t *testing.T) {
	// AGENTS filter: 'q' is filter text, not quit.
	a := newTestApp(t, 100, 30)
	deepentui_seedAgents(a)
	a.mode = modeAgents
	a.agentsView.filtering = true
	a.agentsView.recomputeMatches()
	a.handleKey(deepentui_rune('q'))
	if a.quitting {
		t.Fatal("'q' during the fleet filter must never quit")
	}
	if a.agentsView.filter != "q" {
		t.Fatalf("'q' should append to the filter; got %q", a.agentsView.filter)
	}

	// POLICY entry: 'c' is entry text, not the create modal.
	b := newTestApp(t, 100, 30)
	b.mode = modePolicy
	b.policyView.editing = true
	b.policyView.editKind = "block"
	b.handleKey(deepentui_rune('c'))
	if b.overlay == overlayCreate {
		t.Fatal("'c' during a policy entry must not open the create modal")
	}
	if b.policyView.editBuf != "c" {
		t.Fatalf("'c' should append to the policy entry; got %q", b.policyView.editBuf)
	}

	// EXPLORE jump: 'e' is query text, not the connect modal.
	c := newTestApp(t, 100, 30)
	c.mode = modeExplore
	c.exploreVw.ov = ovJump
	c.exploreVw.jump.query = ""
	c.handleKey(deepentui_rune('e'))
	if c.overlay == overlayConnect {
		t.Fatal("'e' during JUMP must not open the connect modal")
	}
	if c.exploreVw.jump.query != "e" {
		t.Fatalf("'e' should append to the jump query; got %q", c.exploreVw.jump.query)
	}
}

// TestViewCapturesInputMatrix pins each capture predicate to its view state.
func TestViewCapturesInputMatrix(t *testing.T) {
	a := newTestApp(t, 100, 30)
	cases := []struct {
		name string
		prep func()
		want bool
	}{
		{"agents idle", func() { a.mode = modeAgents }, false},
		{"agents filtering", func() { a.mode = modeAgents; a.agentsView.filtering = true }, true},
		{"logs idle", func() { a.mode = modeLogs; a.agentsView.filtering = false }, false},
		{"logs editing", func() { a.mode = modeLogs; a.logsView.editing = true }, true},
		{"policy idle", func() { a.mode = modePolicy; a.logsView.editing = false }, false},
		{"policy editing", func() { a.mode = modePolicy; a.policyView.editing = true }, true},
		{"explore idle", func() { a.mode = modeExplore; a.policyView.editing = false }, false},
		{"explore overlay", func() { a.mode = modeExplore; a.exploreVw.ov = ovCatalog }, true},
		{"graph never", func() { a.mode = modeGraph; a.exploreVw.ov = ovNone }, false},
	}
	for _, tc := range cases {
		tc.prep()
		if got := a.viewCapturesInput(); got != tc.want {
			t.Errorf("%s: viewCapturesInput = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestOnEnterModeLazyLoads pins which tabs fire a load on entry.
func TestOnEnterModeLazyLoads(t *testing.T) {
	a := newTestApp(t, 100, 30)

	a.mode = modeLogs
	if a.onEnterMode() == nil {
		t.Error("first LOGS entry should fire its query")
	}
	a.logsView.loaded = true
	if a.onEnterMode() != nil {
		t.Error("a loaded LOGS view must not re-query on entry")
	}

	a.mode = modePolicy
	if a.onEnterMode() == nil {
		t.Error("an unloaded POLICY entry should fire loadPolicy")
	}
	a.policyView.loaded = true
	if a.onEnterMode() != nil {
		t.Error("a loaded POLICY view must not reload on entry")
	}

	a.mode = modeGraph
	if a.onEnterMode() != nil {
		t.Error("GRAPH has no lazy load")
	}

	a.mode = modeAgents
	if a.onEnterMode() == nil {
		t.Error("AGENTS entry should re-seed the monitor backfill")
	}
}

// TestViewReloadCmdPerMode pins the ctrl+r per-view reload wiring.
func TestViewReloadCmdPerMode(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.mode = modeLogs
	if a.viewReloadCmd() == nil {
		t.Error("LOGS ctrl+r should re-run the query")
	}
	a.mode = modePolicy
	if a.viewReloadCmd() == nil {
		t.Error("POLICY ctrl+r should reload the policy")
	}
	a.mode = modeExplore // keyless: reload must honestly do nothing
	if a.viewReloadCmd() != nil {
		t.Error("keyless EXPLORE ctrl+r must not pretend to reload live")
	}
	a.mode = modeAgents
	if a.viewReloadCmd() != nil {
		t.Error("AGENTS has no extra reload beyond the fleet")
	}
}

// TestMouseTabsAndWheel drives the mouse conveniences: a tab-bar click switches modes, a
// wheel scroll moves the active view, and an open overlay swallows the mouse.
func TestMouseTabsAndWheel(t *testing.T) {
	a := newTestApp(t, 120, 40)
	deepentui_seedAgents(a)

	// Click on the tab bar (row 1): x=25 with span 72 maps to tab index 2 (GRAPH).
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 25, Y: tabRows})
	if a.mode != modeGraph {
		t.Fatalf("tab-bar click should land on GRAPH; got %s", modeNames[a.mode])
	}

	// Wheel in GRAPH scrolls; never negative.
	a.graphVw.scrollY = 0
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if a.graphVw.scrollY != 1 {
		t.Errorf("wheel-down should scroll the graph; got %d", a.graphVw.scrollY)
	}
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	if a.graphVw.scrollY != 0 {
		t.Errorf("wheel-up must clamp at 0; got %d", a.graphVw.scrollY)
	}

	// Wheel in AGENTS moves the selection.
	a.mode = modeAgents
	a.layout()
	a.selected = 0
	a.agentsView.syncRows()
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if a.selected != 1 {
		t.Errorf("wheel-down should advance the fleet selection; selected=%d", a.selected)
	}

	// Wheel in LOGS moves the table cursor.
	a.mode = modeLogs
	a.layout()
	a.logsView.events = []model.Event{{Kind: "dns", TsMicros: 1}, {Kind: "dns", TsMicros: 2}}
	a.logsView.syncRows()
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if a.logsView.tbl.Cursor() != 1 {
		t.Errorf("wheel-down should move the logs cursor; got %d", a.logsView.tbl.Cursor())
	}

	// An open overlay swallows every mouse event (no mode change).
	a.overlay = overlayHelp
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 25, Y: tabRows})
	if a.mode != modeLogs {
		t.Error("a click under an open overlay must not switch tabs")
	}
}

// TestTabAtXBounds pins the tab hit-box math at its edges.
func TestTabAtXBounds(t *testing.T) {
	a := newTestApp(t, 120, 40) // span = 72
	if got := a.tabAtX(0); got != 0 {
		t.Errorf("x=0 should be tab 0; got %d", got)
	}
	if got := a.tabAtX(71); got != len(modeNames)-1 {
		t.Errorf("x=71 should be the last tab; got %d", got)
	}
	if got := a.tabAtX(200); got != -1 {
		t.Errorf("x past the span must miss; got %d", got)
	}
	// A tiny terminal still divides by at least len(modeNames) (no division blowup).
	b := newTestApp(t, 5, 40)
	if got := b.tabAtX(0); got != 0 {
		t.Errorf("tiny width x=0 should still be tab 0; got %d", got)
	}
}
