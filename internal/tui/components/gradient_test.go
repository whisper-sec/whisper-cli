// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var (
	gLo  = lipgloss.Color("#00ff00")
	gMid = lipgloss.Color("#ffff00")
	gHi  = lipgloss.Color("#ff0000")
)

// TestStop3Buckets asserts the 3-stop value map: low<½ → lo, mid → mid, high≥⅘ → hi.
func TestStop3Buckets(t *testing.T) {
	last := 7
	cases := []struct {
		idx  int
		want lipgloss.TerminalColor
	}{
		{0, gLo}, {2, gLo}, {3, gLo}, // <0.5
		{4, gMid}, {5, gMid}, // 0.5..0.8
		{6, gHi}, {7, gHi}, // >=0.8
	}
	for _, c := range cases {
		if got := stop3(c.idx, last, gLo, gMid, gHi); got != c.want {
			t.Errorf("stop3(%d/%d) = %v, want %v", c.idx, last, got, c.want)
		}
	}
	// last<=0 must not divide-by-zero.
	if got := stop3(0, 0, gLo, gMid, gHi); got != gLo {
		t.Errorf("stop3 with last=0 should return lo, got %v", got)
	}
}

// TestSparklineGradientNoColorFallsBack asserts NO_COLOR returns the plain ASCII ramp
// (no ANSI), so colour is never load-bearing.
func TestSparklineGradientNoColorFallsBack(t *testing.T) {
	out := SparklineGradient([]float64{1, 2, 3, 4}, 4, true, gLo, gMid, gHi)
	if strings.Contains(out, "\x1b[") {
		t.Errorf("NO_COLOR gradient sparkline must be plain; got %q", out)
	}
	// The ascii ramp uses " .:-=+*#"; the tallest cell should be the densest glyph.
	if !strings.ContainsAny(out, ".:-=+*#") {
		t.Errorf("ascii sparkline should use the ramp glyphs; got %q", out)
	}
}

// TestSparklineGradientColored asserts the coloured path tints by height (ANSI present).
func TestSparklineGradientColored(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	out := SparklineGradient([]float64{1, 5, 10}, 3, false, gLo, gMid, gHi)
	if !strings.Contains(out, "\x1b[") {
		t.Errorf("coloured gradient sparkline should carry ANSI; got %q", out)
	}
}

// TestGaugeGradClampAndFill asserts the gauge clamps to [0,1] and fills proportionally,
// with the NO_COLOR fallback producing the ascii gauge (no ANSI).
func TestGaugeGradClampAndFill(t *testing.T) {
	// NO_COLOR → ascii Gauge ('#'/'-'), full at >=max.
	full := GaugeGrad(100, 50, 10, true, gLo, gMid, gHi, gLo) // 200% clamps to 100%
	if full != strings.Repeat("#", 10) {
		t.Errorf("over-max gauge should be fully filled ascii; got %q", full)
	}
	empty := GaugeGrad(0, 50, 10, true, gLo, gMid, gHi, gLo)
	if empty != strings.Repeat("-", 10) {
		t.Errorf("zero gauge should be empty ascii; got %q", empty)
	}
	half := GaugeGrad(25, 50, 10, true, gLo, gMid, gHi, gLo)
	if strings.Count(half, "#") != 5 {
		t.Errorf("half gauge should be 5/10 filled; got %q", half)
	}
}

// TestGaugeGradColorByLoad asserts the filled colour escalates with the fill fraction
// (green→amber→red): the high-load gauge must carry the hi colour escape.
func TestGaugeGradColorByLoad(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	low := GaugeGrad(10, 100, 10, false, gLo, gMid, gHi, lipgloss.Color("#333333"))
	hi := GaugeGrad(95, 100, 10, false, gLo, gMid, gHi, lipgloss.Color("#333333"))
	// The hi gauge renders the red foreground; the low gauge does not.
	if !strings.Contains(hi, "255;0;0") {
		t.Errorf("high-load gauge should use the hi (red) colour; got %q", hi)
	}
	if strings.Contains(low, "255;0;0") {
		t.Errorf("low-load gauge should not use the hi (red) colour; got %q", low)
	}
}

// TestGaugeGradZeroWidth is a guard: width<=0 returns empty, never a panic.
func TestGaugeGradZeroWidth(t *testing.T) {
	if got := GaugeGrad(1, 2, 0, false, gLo, gMid, gHi, gLo); got != "" {
		t.Errorf("zero-width gauge should be empty; got %q", got)
	}
}
