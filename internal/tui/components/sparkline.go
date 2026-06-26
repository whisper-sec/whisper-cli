// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package components holds the reusable Lip Gloss render helpers the views compose:
// the braille sparkline, the gauge, and small formatters. They are pure render
// functions (value-in, string-out) so they are trivially unit-testable and never touch
// the network or the Bubble Tea loop.
package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// brailleRamp is the eight-level vertical bar ramp (Unicode block elements) — the btop
// sparkline alphabet. asciiRamp is the NO_COLOR / non-UTF fallback (the v1 CLI ramp).
var (
	brailleRamp = []rune("▁▂▃▄▅▆▇█")
	asciiRamp   = []rune(" .:-=+*#")
)

// Sparkline renders the last `width` samples of vals as a peak-normalised bar string.
// When ascii is true (NO_COLOR or a non-UTF terminal) it uses the " .:-=+*#" ramp; a
// coloured terminal gets the braille ramp. An empty/zero series renders as flat low
// bars, never a blank — the panel always shows it is alive.
//
// Conservative-emit: width is clamped to a sane range; a nil/short series left-pads
// with the lowest bar so the gauge keeps a fixed footprint (no layout jitter).
func Sparkline(vals []float64, width int, ascii bool) string {
	if width <= 0 {
		return ""
	}
	ramp := brailleRamp
	if ascii {
		ramp = asciiRamp
	}
	// Take the last `width` samples (the most recent), left-padding with zeros.
	tail := make([]float64, width)
	n := len(vals)
	for i := 0; i < width; i++ {
		src := n - width + i
		if src >= 0 && src < n {
			tail[i] = vals[src]
		}
	}
	max := 0.0
	for _, v := range tail {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	last := len(ramp) - 1
	for _, v := range tail {
		idx := 0
		if max > 0 && v > 0 {
			idx = int(v / max * float64(last))
			if idx > last {
				idx = last
			}
			if idx < 0 {
				idx = 0
			}
		}
		b.WriteRune(ramp[idx])
	}
	return b.String()
}

// SparklineGradient is Sparkline with a per-cell THREE-stop colour gradient (value-
// mapped: short bars → lo, mid bars → mid, tall bars → hi). With colour off it returns
// the plain ASCII sparkline. This gives the btop "value-mapped glow" without per-cell
// state — each cell's colour is a pure function of its height fraction, so the render is
// deterministic and re-renders identically every frame (no flicker).
func SparklineGradient(vals []float64, width int, noColor bool, lo, mid, hi lipgloss.TerminalColor) string {
	if noColor {
		return Sparkline(vals, width, true)
	}
	if width <= 0 {
		return ""
	}
	tail := make([]float64, width)
	n := len(vals)
	for i := 0; i < width; i++ {
		src := n - width + i
		if src >= 0 && src < n {
			tail[i] = vals[src]
		}
	}
	maxV := 0.0
	for _, v := range tail {
		if v > maxV {
			maxV = v
		}
	}
	last := len(brailleRamp) - 1
	var b strings.Builder
	for _, v := range tail {
		idx := 0
		if maxV > 0 && v > 0 {
			idx = int(v / maxV * float64(last))
			if idx > last {
				idx = last
			}
		}
		b.WriteString(lipgloss.NewStyle().Foreground(stop3(idx, last, lo, mid, hi)).Render(string(brailleRamp[idx])))
	}
	return b.String()
}

// stop3 buckets a ramp index into one of three colour stops (low<½ → lo, mid → mid,
// high≥⅘ → hi). A shared helper so the sparkline, the braille hero, and the gauges all
// map height to colour the same way.
func stop3(idx, last int, lo, mid, hi lipgloss.TerminalColor) lipgloss.TerminalColor {
	if last <= 0 {
		return lo
	}
	frac := float64(idx) / float64(last)
	switch {
	case frac < 0.5:
		return lo
	case frac < 0.8:
		return mid
	default:
		return hi
	}
}
