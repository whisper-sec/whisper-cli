// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// The `?` help logo bug: the baked span tables are ragged (each row stops at its last
// glyph), and lipgloss.JoinVertical centers every LINE independently, so the narrower
// top/bottom rows of the mark drifted right of the middle ones - a bent cloverleaf.
// The fix makes renderLogo emit a RECTANGLE (every line padded to the widest row);
// these tests pin both the invariant and the end-to-end help-card alignment.

// leadingSpaces counts a baked row's left offset (its "" colour spans are plain spaces).
func leadingSpaces(row []logoSpan) int {
	n := 0
	for _, sp := range row {
		if sp.c != "" {
			break
		}
		n += len([]rune(sp.s))
	}
	return n
}

// TestRenderLogoIsRectangular asserts every rendered line of both baked marks has the
// SAME visible width (the rectangle invariant any aligner depends on).
func TestRenderLogoIsRectangular(t *testing.T) {
	for name, tbl := range map[string][][]logoSpan{"icon": logoIcon, "splash": logoSplash} {
		art := renderLogo(tbl, false)
		if art == "" {
			t.Fatalf("%s: colour render must not be empty", name)
		}
		lines := strings.Split(strip(art), "\n")
		if len(lines) != logoRows(tbl) {
			t.Fatalf("%s: %d lines, want %d", name, len(lines), logoRows(tbl))
		}
		want := logoWidth(tbl)
		for i, ln := range lines {
			if got := lipgloss.Width(ln); got != want {
				t.Errorf("%s line %d width = %d, want %d (ragged rows bend the mark)", name, i, got, want)
			}
		}
	}
}

// TestRenderLogoSurvivesCentering joins the mark with a wider headline under
// lipgloss.JoinVertical(Center) - exactly what the help card and hero do - and asserts
// every row keeps its baked left offset relative to the others (the raster intact).
func TestRenderLogoSurvivesCentering(t *testing.T) {
	art := renderLogo(logoIcon, false)
	joined := lipgloss.JoinVertical(lipgloss.Center, art, "", "a headline wider than the mark itself")
	lines := strings.Split(strip(joined), "\n")
	if len(lines) < logoRows(logoIcon) {
		t.Fatalf("joined block lost logo rows: %d", len(lines))
	}
	// Row offsets after centering must differ from the baked leading spaces by ONE
	// shared constant (the uniform centering shift).
	shift := -1
	for i := 0; i < logoRows(logoIcon); i++ {
		ln := lines[i]
		vis := strings.TrimLeft(ln, " ")
		if vis == "" {
			t.Fatalf("logo row %d vanished under centering", i)
		}
		off := len([]rune(ln)) - len([]rune(vis))
		delta := off - leadingSpaces(logoIcon[i])
		if shift == -1 {
			shift = delta
		}
		if delta != shift {
			t.Errorf("row %d shifted by %d, others by %d - the mark is bent", i, delta, shift)
		}
	}
}

// TestHelpCardLogoAlignment renders the real `?` overlay (colour on, tall terminal)
// and asserts the mark's rows sit at their baked relative offsets - the end-to-end
// regression for the broken help logo.
func TestHelpCardLogoAlignment(t *testing.T) {
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 44})
	a.loading = false
	a.overlay = overlayHelp
	out := strip(a.View())

	// Find the logo rows: the first logoRows lines containing block glyphs.
	var offs []int
	for _, ln := range strings.Split(out, "\n") {
		if i := strings.IndexAny(ln, "▄▟█▜▀"); i >= 0 {
			offs = append(offs, len([]rune(ln[:i])))
		}
		if len(offs) == logoRows(logoIcon) {
			break
		}
	}
	if len(offs) != logoRows(logoIcon) {
		t.Fatalf("help card did not render the %d-row mark; frame:\n%s", logoRows(logoIcon), out)
	}
	shift := offs[0] - leadingSpaces(logoIcon[0])
	for i, off := range offs {
		if off-leadingSpaces(logoIcon[i]) != shift {
			t.Errorf("help logo row %d off by %d columns (bent mark); offsets=%v", i, off-leadingSpaces(logoIcon[i])-shift, offs)
		}
	}
}

// TestHelpCardLinesFit asserts no help-card line exceeds the card's inner width, so
// lipgloss never re-wraps a row mid-token (the "↵ walk-in" spill this fixes).
func TestHelpCardLinesFit(t *testing.T) {
	c := client.New(client.Config{})
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 44})
	a.loading = false
	card := strip(a.helpCard())
	lines := strings.Split(card, "\n")
	// Every rendered line of the box is exactly the box width; a wrapped row would
	// add EXTRA lines. Count the content rows: they must match the source layout
	// (no line may have spilled onto a continuation row).
	if !strings.Contains(card, "walk-in") {
		t.Fatal("help card lost the walk-in binding")
	}
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "walk-in" {
			t.Fatalf("the walk-in binding wrapped onto its own line; card:\n%s", card)
		}
	}
	// And the card never renders wider than its box: Width(64) content + 2 border.
	for i, ln := range lines {
		if w := lipgloss.Width(ln); w > 66 {
			t.Errorf("card line %d is %d wide (> 66 box)", i, w)
		}
	}
}
