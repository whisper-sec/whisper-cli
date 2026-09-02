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
		"cloudflare":       fixtureCloudflare,
		"whisper-security": fixtureWhisperSecurity, // the default landing
		"mega-fanout":      fixtureMegaFanout,
		"asn":              fixtureASN,
		"sparse":           fixtureSparse,
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

// TestExploreNavIsSynchronous exercises the key handling: cursor moves, pane
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

// TestExploreOverlaysOpenClose asserts o /: open the CATALOG / REPL shells and esc closes.
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

// TestExploreJumpTypesEveryPrintableRune is the regression: the JUMP query is a
// focused text input, so EVERY printable rune must land in the text - including j / k /
// h / l, which the old handler stole for list-cursor movement (typing "example.com" lost
// every k). Typed rune-by-rune through the real key path, top to bottom.
func TestExploreJumpTypesEveryPrintableRune(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	v := a.exploreVw
	// Open JUMP the way a user does.
	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	if v.ov != ovJump {
		t.Fatal("/ should open the JUMP overlay")
	}
	for _, r := range "example.com" {
		v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	if v.jump.query != "example.com" {
		t.Fatalf("typing example.com into JUMP produced %q - printable runes are being stolen", v.jump.query)
	}
	// And the frame paints exactly what was typed (the input is honest on screen too).
	if out := a.View(); !strings.Contains(out, "example.com") {
		t.Error("the JUMP frame does not show the typed query")
	}
	// Backspace deletes RUNE-wise (unicode-safe: the input accepts any rune now).
	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ü")})
	v.handleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if v.jump.query != "example.com" {
		t.Errorf("backspace should delete one rune; got %q", v.jump.query)
	}
	// Cursor movement stays on the arrow keys only.
	v.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	if v.jump.cursor != 1 {
		t.Errorf("down arrow should still move the list cursor; got %d", v.jump.cursor)
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyUp})
	if v.jump.cursor != 0 {
		t.Errorf("up arrow should still move the list cursor; got %d", v.jump.cursor)
	}
}

// TestExploreDefaultLandingIsWhisperSecurity pins the default: EXPLORE with no
// start node lands on whisper.security - keyless via the honest fixture demo, keyed via
// a live land on the same node (the deck focus is set synchronously; only the fetches
// are async).
func TestExploreDefaultLandingIsWhisperSecurity(t *testing.T) {
	// Keyless: the fixture demo opens on whisper.security.
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 34})
	_ = a.exploreVw.onEnter()
	if got := a.exploreVw.deck.focus.Value; got != "whisper.security" {
		t.Errorf("keyless EXPLORE should open the whisper.security fixture; got %q", got)
	}

	// Keyed: onEnter lands live on whisper.security (focus set synchronously; the
	// returned command carries the async loads and is never executed here - no network).
	kc := client.New(client.Config{Cred: client.Credential{Value: "whisper-0000000000000000"}})
	b := New(Options{Client: kc, ThemeName: theme.Whisper, Version: "test", StartOnExplore: true})
	b.Update(tea.WindowSizeMsg{Width: 100, Height: 34})
	if cmd := b.exploreVw.onEnter(); cmd == nil {
		t.Error("keyed onEnter should return the live-land command batch")
	}
	if got := b.exploreVw.deck.focus.Value; got != "whisper.security" {
		t.Errorf("keyed EXPLORE should land on whisper.security by default; got %q", got)
	}
	// An explicit start node still wins (Postel: the user's ask beats the default).
	kc2 := client.New(client.Config{Cred: client.Credential{Value: "whisper-0000000000000000"}})
	d := New(Options{Client: kc2, ThemeName: theme.Whisper, Version: "test",
		StartOnExplore: true, StartNode: "example.org"})
	d.Update(tea.WindowSizeMsg{Width: 100, Height: 34})
	_ = d.exploreVw.onEnter()
	if got := d.exploreVw.deck.focus.Value; got != "example.org" {
		t.Errorf("an explicit start node must win over the default; got %q", got)
	}
}

// TestExploreRenderBudget renders 200 100-col EXPLORE frames. The FUNCTIONAL half runs
// everywhere: every frame must be non-empty and never panic (200 renders exercise the
// width invariants hard). The WALL-CLOCK half - avg <= 4ms so a 4Hz tick + fast walking
// never stutters - is asserted only in a plain, local run: a shared 2-core CI
// runner averages ~6ms on the very same code (scheduler noise, not a regression), and
// the race detector's instrumentation alone is a ~10x slowdown (measured 0.4ms plain vs
// 4.9ms under -race on one machine), so wall-clock under CI/-short/-race measures the
// environment, not the code. The real interactivity requirement is the 4Hz tick =
// 250ms/frame, ~60x above this bar, so nothing is lost; the 4ms budget itself is
// deliberately NOT loosened (a plain local `go test` still catches a gross render
// regression), and BenchmarkExploreFrame100 below remains the profiling tool.
// Machine-independent where machines vary, strict where they don't - never a flake.
func TestExploreRenderBudget(t *testing.T) {
	a := newExploreApp(t, 100, 34, false, fixtureCloudflare())
	const iters = 200
	start := time.Now()
	for i := 0; i < iters; i++ {
		if frame := a.exploreVw.view(a.bodyWidth(), a.bodyHeight()); strings.TrimSpace(frame) == "" {
			t.Fatalf("frame %d of %d rendered empty", i, iters)
		}
	}
	avg := time.Since(start) / iters
	t.Logf("100-col EXPLORE frame avg render: %v", avg)
	if testing.Short() || raceEnabled || os.Getenv("CI") != "" {
		t.Log("wall-clock budget not asserted under CI/-short/-race (it would measure the environment, not the render)")
		return
	}
	if avg > 4*time.Millisecond {
		t.Errorf("100-col EXPLORE frame averaged %v (budget 4ms)", avg)
	}
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
// an operator. It is a dump helper, not an assertion; it only runs when WHISPER_EXPLORE_DUMP is
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
