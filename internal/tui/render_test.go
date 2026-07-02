// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// newTestApp builds an App backed by a keyless (but non-nil) client, sized to a default
// terminal. It exercises the headless render path — no TTY, no goroutine, no network.
func newTestApp(t *testing.T, w, h int) *App {
	t.Helper()
	c := client.New(client.Config{}) // non-nil; no key, never dialled in these tests
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: w, Height: h})
	a.loading = false // simulate the fleet load having returned
	return a
}

func renderOf(a *App) string { return a.View() }

// TestRenderAllModes asserts every mode renders a non-empty frame with its chrome.
func TestRenderAllModes(t *testing.T) {
	a := newTestApp(t, 120, 40)
	// Seed a couple of agents so the AGENTS view shows the table, not the hero.
	a.agents = []model.Agent{
		{ID: "agent-1", Address: "2a04:2a01::1", Label: "scraper", State: "active", Detailed: true,
			DNSQueries: 1000, DNSBlocked: 50, ConnectionsActive: 3, BytesUp: 4096, BytesDown: 8192},
		{ID: "agent-2", Address: "2a04:2a01::2", Label: "crawler", State: "active"},
	}
	a.agentsView.syncRows()

	for m := modeAgents; m <= modeConfig; m++ {
		a.mode = m
		a.layout()
		out := renderOf(a)
		if strings.TrimSpace(out) == "" {
			t.Fatalf("mode %s rendered empty", modeNames[m])
		}
		// The tab bar (all five labels) must be present in every frame.
		for _, name := range modeNames {
			if !strings.Contains(out, name) {
				t.Errorf("mode %s frame missing tab %q", modeNames[m], name)
			}
		}
	}
}

// TestFirstRunHero shows the centred hero when the fleet is empty.
func TestFirstRunHero(t *testing.T) {
	a := newTestApp(t, 100, 36)
	a.agents = nil
	a.mode = modeAgents
	out := renderOf(a)
	if !strings.Contains(out, "whisper") || !strings.Contains(out, "create your first agent") {
		t.Errorf("first-run hero missing; got:\n%s", out)
	}
}

// TestOverlaysRender opens each overlay and asserts it renders over the frame.
func TestOverlaysRender(t *testing.T) {
	a := newTestApp(t, 110, 38)
	a.agents = []model.Agent{{ID: "agent-1", Address: "2a04:2a01::1", Label: "scraper", State: "active"}}
	a.agentsView.syncRows()

	// palette
	a.openPalette()
	if out := renderOf(a); !strings.Contains(out, "command palette") {
		t.Error("palette overlay did not render")
	}
	a.overlay = overlayNone

	// help
	a.overlay = overlayHelp
	if out := renderOf(a); !strings.Contains(out, "keybindings") {
		t.Error("help overlay did not render")
	}
	a.overlay = overlayNone

	// create (Huh form)
	a.openCreate()
	if out := renderOf(a); !strings.Contains(out, "create agent") {
		t.Error("create modal did not render")
	}
	a.overlay = overlayNone

	// kill (Huh form, requires a selection)
	a.selected = 0
	a.openKill()
	if out := renderOf(a); !strings.Contains(out, "kill") {
		t.Error("kill modal did not render")
	}
	a.overlay = overlayNone

	// connect
	a.openConnect()
	if out := renderOf(a); !strings.Contains(out, "egress") {
		t.Error("connect modal did not render")
	}
	a.overlay = overlayNone

	// drill (pretty-JSON card)
	a.openDrill()
	if out := renderOf(a); !strings.Contains(out, "2a04:2a01::1") {
		t.Error("drill card did not render the agent address")
	}
}

// TestResizeFuzz renders across a wide range of sizes — including the too-small floor —
// without panicking or producing an empty frame (graceful degrade, Postel).
func TestResizeFuzz(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{{ID: "a1", Address: "2a04:2a01::1", State: "active"}}
	a.agentsView.syncRows()
	sizes := [][2]int{
		{20, 8}, {40, 10}, {59, 17}, {60, 18}, {80, 24}, {100, 30},
		{200, 60}, {1, 1}, {300, 12}, {61, 19}, {120, 16}, {120, 23},
	}
	for _, mdN := range []mode{modeAgents, modeMonitor, modeLogs, modePolicy, modeConfig} {
		a.mode = mdN
		for _, s := range sizes {
			a.Update(tea.WindowSizeMsg{Width: s[0], Height: s[1]})
			out := renderOf(a)
			if out == "" {
				t.Errorf("mode %s at %dx%d rendered empty", modeNames[mdN], s[0], s[1])
			}
		}
	}
}

// TestStreamEventFold folds a synthetic live event and asserts it lands in the feed,
// the join cache, and the fleet union — then renders on the AGENTS live strip.
func TestStreamEventFold(t *testing.T) {
	a := newTestApp(t, 120, 40)
	// A dns then a conn for the same /128: the conn's chain should stitch the qname.
	a.onStreamEvent(model.Event{
		TsMicros: 1_700_000_000_000_000, Kind: "dns", Addr128: "2a04:2a01::7",
		QName: "example.com.", Decision: "allow", QType: "A", Source: "graph",
	})
	a.onStreamEvent(model.Event{
		TsMicros: 1_700_000_000_500_000, Kind: "conn", Addr128: "2a04:2a01::7",
		ClientSrc: "203.0.113.0/24", PeerHost: "2606:4700::1111", PeerPort: 443,
		BytesUp: 1000, BytesDown: 2000, Reason: "fw-allow",
	})
	if a.feed.len() != 2 {
		t.Fatalf("feed should hold 2 events, has %d", a.feed.len())
	}
	if got := a.join.qnameAt("2a04:2a01::7", 1_700_000_000_500_000); got != "example.com." {
		t.Errorf("join cache miss: %q", got)
	}
	// The stream-discovered agent should be unioned into the fleet.
	found := false
	for _, ag := range a.agents {
		if ag.Address == "2a04:2a01::7" {
			found = true
		}
	}
	if !found {
		t.Error("stream-discovered agent not unioned into the fleet")
	}
	// The AGENTS dashboard live strip must render the activity.
	a.mode = modeAgents
	a.layout()
	out := renderOf(a)
	if !strings.Contains(out, "example.com") {
		t.Errorf("live strip did not render the stitched chain; frame:\n%s", out)
	}
}

// TestTooSmallFloor renders a clean message (never a broken layout) below the floor.
func TestTooSmallFloor(t *testing.T) {
	a := newTestApp(t, 30, 10)
	out := renderOf(a)
	if !strings.Contains(out, "too small") {
		t.Errorf("below-floor frame should show the too-small message; got:\n%s", out)
	}
}

// TestThemeCycleRebuildsStyles cycles themes (Ctrl-T path) and re-renders cleanly.
func TestThemeCycleRebuildsStyles(t *testing.T) {
	a := newTestApp(t, 100, 30)
	start := a.th.Name
	a.cycleTheme()
	if a.th.Name == start {
		t.Error("cycleTheme did not advance the theme")
	}
	if out := renderOf(a); strings.TrimSpace(out) == "" {
		t.Error("frame empty after theme cycle")
	}
}

// TestNoColorRendersGlyphs asserts the NO_COLOR path produces glyph-bearing output.
func TestNoColorRendersGlyphs(t *testing.T) {
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, NoColor: true, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	a.loading = false
	a.onStreamEvent(model.Event{
		TsMicros: 1_700_000_000_000_000, Kind: "dns", Addr128: "2a04:2a01::7",
		QName: "blocked.example.", Decision: "block", QType: "A",
	})
	a.mode = modeAgents
	a.layout()
	out := renderOf(a)
	// The block decision carries the ✗ glyph so meaning never depends on colour.
	if !strings.Contains(out, "✗") {
		t.Errorf("NO_COLOR block decision should carry a glyph; frame:\n%s", out)
	}
}
