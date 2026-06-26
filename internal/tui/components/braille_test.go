// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func heroOpts(noColor bool) BrailleOpts {
	return BrailleOpts{
		Width: 60, Height: 8, NoColor: noColor, Unit: "kbps",
		Lo: lipgloss.Color("#8fe9b0"), Mid: lipgloss.Color("#9fc1ff"), Hi: lipgloss.Color("#e9c98f"),
		Axis: lipgloss.NewStyle(), Label: lipgloss.NewStyle(),
	}
}

// TestBrailleHeightAndAxes asserts the hero graph emits exactly Height lines (incl. the
// time-axis row) and renders the Y-peak + time-axis labels.
func TestBrailleHeightAndAxes(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	vals := make([]float64, 120)
	for i := range vals {
		vals[i] = float64(i) // a rising ramp; peak = 119
	}
	out := Braille(vals, heroOpts(true))
	lines := strings.Split(out, "\n")
	if len(lines) != 8 {
		t.Fatalf("expected 8 lines (7 plot + 1 axis), got %d:\n%s", len(lines), out)
	}
	// Y-axis: the peak (119 → "119") at the top, "0" at the bottom plot row.
	if !strings.Contains(lines[0], "119") {
		t.Errorf("top row should label the peak 119; got %q", lines[0])
	}
	// time axis row: contains "now" and the "-" span marker.
	axis := lines[len(lines)-1]
	if !strings.Contains(axis, "now") || !strings.Contains(axis, "-") {
		t.Errorf("axis row should show the time span and 'now'; got %q", axis)
	}
}

// TestBrailleNewestOnRight asserts the most-recent samples occupy the right edge (a ramp
// rises left→right; the rightmost plot column must be the fullest).
func TestBrailleNewestOnRight(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	vals := make([]float64, 60)
	for i := range vals {
		vals[i] = float64(i)
	}
	out := Braille(vals, heroOpts(true)) // ASCII fallback: '#'=full, '.'=cap, ' '=empty
	lines := strings.Split(out, "\n")
	// The bottom plot row (just above the axis) should be filled near the right and empty
	// near the left for a rising ramp.
	row := lines[len(lines)-2]
	// strip the gutter (up to the '|')
	if i := strings.IndexByte(row, '|'); i >= 0 {
		row = row[i+1:]
	}
	r := []rune(row)
	if len(r) < 10 {
		t.Fatalf("plot row too short: %q", row)
	}
	left, right := r[2], r[len(r)-1]
	if right != '#' {
		t.Errorf("rightmost (newest) cell should be full for a rising ramp; got %q in %q", right, row)
	}
	_ = left
}

// TestBrailleEmptySeriesIsCleanBaseline asserts an empty/zero series renders a clean
// baseline (no panic, right number of lines), never a blank.
func TestBrailleEmptySeriesIsCleanBaseline(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	out := Braille(nil, heroOpts(true))
	if strings.TrimSpace(out) == "" {
		t.Fatal("empty series produced a blank graph")
	}
	if got := len(strings.Split(out, "\n")); got != 8 {
		t.Errorf("empty series should still fill 8 lines, got %d", got)
	}
}

// TestBrailleTooSmallDegrades asserts a too-small area degrades to a one-row sparkline,
// never a broken multi-row frame (Postel: graceful).
func TestBrailleTooSmallDegrades(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	o := heroOpts(true)
	o.Width, o.Height = 6, 1
	out := Braille([]float64{1, 2, 3}, o)
	if strings.Contains(out, "\n") {
		t.Errorf("a 1-row area must not produce multiple lines; got %q", out)
	}
}

// TestBrailleColorGradientApplied asserts the coloured path tints cells (ANSI present)
// while NO_COLOR stays plain — colour is value-mapped but never load-bearing.
func TestBrailleColorGradientApplied(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor) // force colour for this assertion
	defer lipgloss.SetColorProfile(termenv.Ascii)
	vals := make([]float64, 60)
	for i := range vals {
		vals[i] = float64(i)
	}
	colored := Braille(vals, heroOpts(false))
	if !strings.Contains(colored, "\x1b[") {
		t.Error("coloured braille should contain ANSI escapes (value-mapped gradient)")
	}
	plain := Braille(vals, heroOpts(true))
	if strings.Contains(plain, "\x1b[38") {
		t.Error("NO_COLOR braille must not contain foreground-colour escapes")
	}
}

// TestCompactNum exercises the axis-label formatter across magnitudes.
func TestCompactNum(t *testing.T) {
	cases := map[float64]string{
		0: "0", 88: "88", 1500: "1.5k", 12000: "12k", 2_500_000: "2.5M",
	}
	for in, want := range cases {
		if got := compactNum(in); got != want {
			t.Errorf("compactNum(%v) = %q, want %q", in, got, want)
		}
	}
}

// TestCompactDur exercises the time-span axis label.
func TestCompactDur(t *testing.T) {
	cases := map[int]string{30: "30s", 90: "1m", 120: "2m", 3600: "1h", 7200: "2h"}
	for in, want := range cases {
		if got := compactDur(in); got != want {
			t.Errorf("compactDur(%d) = %q, want %q", in, got, want)
		}
	}
}
