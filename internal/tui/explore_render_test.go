// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// newExploreApp builds a headless App parked on the EXPLORE tab with a fixture deck (no
// TTY, no goroutine, no network) so the pure renderer is exercised end to end.
func newExploreApp(t *testing.T, w, h int, noColor bool, deck deckState) *App {
	t.Helper()
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, NoColor: noColor, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: w, Height: h})
	a.loading = false
	a.mode = modeExplore
	a.exploreVw.loadDeck(deck)
	a.layout()
	return a
}

// exploreFixtures is the golden-test matrix: every prototype screen.
func exploreFixtures() map[string]func() deckState {
	return map[string]func() deckState{
		"cloudflare":  fixtureCloudflare,
		"mega-fanout": fixtureMegaFanout,
		"asn":         fixtureASN,
		"sparse":      fixtureSparse,
	}
}

var widths = []int{60, 80, 100, 120}

// TestExploreRendersEveryScreenEveryWidth is the core golden test: every fixture at every
// width, colour on and off, renders a non-empty frame, carries the EXPLORE tab, and never
// emits a line wider than the terminal (the belt-and-braces width invariant).
func TestExploreRendersEveryScreenEveryWidth(t *testing.T) {
	for name, mk := range exploreFixtures() {
		for _, w := range widths {
			for _, noColor := range []bool{false, true} {
				deck := mk()
				a := newExploreApp(t, w, 34, noColor, deck)
				out := a.View()
				if strings.TrimSpace(out) == "" {
					t.Fatalf("%s @%d nocolor=%v rendered empty", name, w, noColor)
				}
				// The explore body must have rendered (its focus value is present). The
				// full 6-tab bar only fits from ~80 cols; below that the shared bar()
				// clamp drops the tail, which is acceptable degradation (Postel).
				if !strings.Contains(out, deck.focus.Value) {
					t.Errorf("%s @%d nocolor=%v missing focus value %q", name, w, noColor, deck.focus.Value)
				}
				if w >= 80 && !strings.Contains(out, "EXPLORE") {
					t.Errorf("%s @%d nocolor=%v missing EXPLORE tab", name, w, noColor)
				}
				for i, line := range strings.Split(out, "\n") {
					if lw := lipgloss.Width(line); lw > w {
						t.Errorf("%s @%d nocolor=%v line %d is %d cells wide (limit %d)", name, w, noColor, i, lw, w)
					}
				}
			}
		}
	}
}

// TestExploreGlyphsCarryMeaning asserts the honest, glyph-first content is present with
// colour OFF (NO_COLOR): the value, the truth-bearing edge types, and the band glyphs.
func TestExploreGlyphsCarryMeaning(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	out := a.View()
	for _, want := range []string{"cloudflare.com", "RESOLVES_TO", "LINKS_TO", "▪", "⬢", "▤"} {
		if !strings.Contains(out, want) {
			t.Errorf("cloudflare NO_COLOR frame missing %q; frame:\n%s", want, out)
		}
	}
}

// TestExploreMegaFanoutHonest asserts the mega fan-out states plainly that it is SAMPLED
// and carries the SHARED-not-RELATED co-tenancy banner (the credibility-critical honesty).
func TestExploreMegaFanoutHonest(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureMegaFanout())
	a.exploreVw.activePane = paneNeighbors
	out := a.View()
	for _, want := range []string{"104.16.132.229", "1,240,000", "SHARED ≠ RELATED", "glitch-me.tk", "✗"} {
		if !strings.Contains(out, want) {
			t.Errorf("mega-fanout frame missing %q; frame:\n%s", want, out)
		}
	}
}

// TestExploreSparseHonestState asserts a sparse UNKNOWN node renders the calm honest state
// instead of a blank pane.
func TestExploreSparseHonestState(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureSparse())
	out := a.View()
	if !strings.Contains(out, "sparse node") {
		t.Errorf("sparse node should render the honest state; frame:\n%s", out)
	}
}

// TestExploreCatalogResultRenders asserts the CATALOG frame renders the type-aware RESULT:
// the assess band chip and the variants ranked table (each row a node).
func TestExploreCatalogResultRenders(t *testing.T) {
	deck, cards := fixtureCatalog()
	a := newExploreApp(t, 110, 34, false, deck)
	a.exploreVw.ov = ovCatalog
	a.exploreVw.results = cards
	out := a.View()
	for _, want := range []string{"CATALOG", "RESULT", "BAND", "paypa1.com", "homoglyph"} {
		if !strings.Contains(out, want) {
			t.Errorf("catalog frame missing %q; frame:\n%s", want, out)
		}
	}
}

// TestExploreOutageBanner asserts the total-outage state paints a calm banner, never four
// dead spinners.
func TestExploreOutageBanner(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	a.exploreVw.degraded = true
	out := a.View()
	if !strings.Contains(out, "graph unreachable") {
		t.Errorf("degraded state should paint the outage banner; frame:\n%s", out)
	}
}

// TestExploreOrnamentToggle asserts the z toggle switches the FOCUS ornament between the
// constellation, the density-collapsed cluster, and off, without breaking the columns.
func TestExploreOrnamentToggle(t *testing.T) {
	a := newExploreApp(t, 120, 34, false, fixtureCloudflare())
	a.exploreVw.orn = ornCluster
	out := a.View()
	if !strings.Contains(out, "cluster") {
		t.Errorf("cluster ornament should render its label; frame:\n%s", out)
	}
	a.exploreVw.orn = ornConstellation
	if strings.TrimSpace(a.View()) == "" {
		t.Error("constellation frame empty")
	}
}

// TestExploreNavIsSynchronous exercises the Phase-1 key handling: cursor moves, pane
// switch, edge-type step, and a linked walk-in / back, all synchronous with no network.
func TestExploreNavIsSynchronous(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	v := a.exploreVw
	key := func(s string) { v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}) }

	key("j") // move edge cursor down
	if v.deck.edgeCur != 1 {
		t.Errorf("j should move the edge cursor to 1, got %d", v.deck.edgeCur)
	}
	key("k")
	if v.deck.edgeCur != 0 {
		t.Errorf("k should move the edge cursor back to 0, got %d", v.deck.edgeCur)
	}
	key("l") // descend to the NEIGHBORS pane
	if v.activePane != paneNeighbors {
		t.Error("l should descend to the NEIGHBORS pane")
	}
	// walk RESOLVES_TO -> 104.16.132.229 (linked fixture: the mega fan-out).
	v.deck.nbrCur = 0
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if v.deck.focus.Value != "104.16.132.229" {
		t.Errorf("enter should walk onto the linked fixture, got focus %q", v.deck.focus.Value)
	}
	if len(v.deck.trail) != 1 || v.deck.trail[0].Value != "cloudflare.com" {
		t.Errorf("walk should push cloudflare.com onto the trail, got %+v", v.deck.trail)
	}
	// back.
	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("h")})
	if v.deck.focus.Value != "cloudflare.com" {
		t.Errorf("h at the FOCUS pane should ascend to cloudflare.com, got %q", v.deck.focus.Value)
	}
}

// TestExploreOverlaysOpenClose asserts o / : open the CATALOG / REPL shells and esc closes.
func TestExploreOverlaysOpenClose(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	v := a.exploreVw
	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	if v.ov != ovCatalog {
		t.Error("o should open the CATALOG overlay")
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if v.ov != ovNone {
		t.Error("esc should close the overlay")
	}
}

// TestExploreRenderBudget asserts a 100-col EXPLORE frame renders well under 4ms so a 4Hz
// tick + fast walking never stutters (the pure renderer is never in the network path).
func TestExploreRenderBudget(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	const iters = 200
	start := time.Now()
	for i := 0; i < iters; i++ {
		_ = a.exploreVw.view(a.bodyWidth(), a.bodyHeight())
	}
	avg := time.Since(start) / iters
	if avg > 4*time.Millisecond {
		t.Errorf("100-col EXPLORE frame averaged %v (budget 4ms)", avg)
	}
	t.Logf("100-col EXPLORE frame avg render: %v", avg)
}

// BenchmarkExploreFrame100 profiles the 100-col frame render.
func BenchmarkExploreFrame100(b *testing.B) {
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "bench"})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 34})
	a.mode = modeExplore
	a.exploreVw.loadDeck(fixtureCloudflare())
	a.layout()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.exploreVw.view(a.bodyWidth(), a.bodyHeight())
	}
}

// TestExploreColorSmokeEmitsANSI is the colour-pass smoke test: with the colour profile
// forced to TrueColor (so SGR is emitted regardless of the non-TTY test pipe), the frame must
// carry the node-type hues we chose; and with NO_COLOR the same frame must emit NO truecolor
// foreground at all. This proves colour is actually emitted (not silently stripped) AND that
// the glyph-carries-meaning NO_COLOR contract the golden tests rely on still holds.
func TestExploreColorSmokeEmitsANSI(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)

	// Colour ON: real SGR, and specifically the HOSTNAME lavender (#c3b0ff) on the focus and
	// the IPV4 cyan (#5cc8d8) on a resolved neighbour glyph.
	on := newExploreApp(t, 100, 34, false, fixtureCloudflare()).View()
	if !strings.Contains(on, "\x1b[") {
		t.Fatal("colour-on frame emitted no ANSI escape at all")
	}
	if !strings.Contains(on, "38;2;195;176;255") { // hexHostname #c3b0ff
		t.Error("colour-on frame missing the HOSTNAME hue SGR (#c3b0ff)")
	}
	if !strings.Contains(on, "38;2;92;200;216") { // hexIPv4 #5cc8d8
		t.Error("colour-on frame missing the IPV4 hue SGR (#5cc8d8)")
	}

	// NO_COLOR: even under a TrueColor profile, the NoColor theme path must suppress every
	// truecolor foreground (the golden tests are colour-stripped and must stay identical).
	off := newExploreApp(t, 100, 34, true, fixtureCloudflare()).View()
	if strings.Contains(off, "38;2;") {
		t.Error("NO_COLOR frame emitted a truecolor SGR; colour must be fully suppressed")
	}
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestExploreDumpScreenshots writes the cloudflare + mega-fanout frames at 100 cols to the
// scratchpad (plain text, ANSI stripped) so the real prototype output can be shown to
// Kaveh. It is a dump helper, not an assertion; it only runs when WHISPER_EXPLORE_DUMP is
// set to a target directory.
func TestExploreDumpScreenshots(t *testing.T) {
	dir := os.Getenv("WHISPER_EXPLORE_DUMP")
	if dir == "" {
		t.Skip("set WHISPER_EXPLORE_DUMP=<dir> to write the prototype frames")
	}
	dump := func(name string, deck deckState, tweak func(*exploreView)) {
		a := newExploreApp(t, 100, 34, false, deck)
		if tweak != nil {
			tweak(a.exploreVw)
		}
		out := ansiRe.ReplaceAllString(a.View(), "")
		if err := os.WriteFile(dir+"/explore_"+name+"_100.txt", []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dump("cloudflare", fixtureCloudflare(), nil)
	dump("mega_fanout", fixtureMegaFanout(), func(v *exploreView) {
		v.activePane = paneNeighbors
		v.pins = []graphNode{host("glitch-me.tk", "MALICIOUS")}
	})
	deck, cards := fixtureCatalog()
	dump("catalog", deck, func(v *exploreView) { v.ov = ovCatalog; v.results = cards })
}
