// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The Whisper brand mark as terminal art (approved on): the four-ring
// cloverleaf, baked at two sizes in logo_gen.go. Colour is the BRAND ramp —
// blue → violet — deliberately theme-independent (a logo keeps its colours);
// lipgloss/termenv degrade truecolor to 256 automatically. On NO_COLOR every
// helper returns "" / plain text and the callers keep their text-only layout,
// so the mark never renders uncoloured.

// brand ramp endpoints, sampled from the mark itself.
const (
	brandBlue   = "#5b78e8"
	brandViolet = "#a862d8"
)

// renderLogo builds the coloured mark from a baked span table ("" on NoColor).
func renderLogo(rows [][]logoSpan, noColor bool) string {
	if noColor {
		return ""
	}
	var b strings.Builder
	for i, row := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, sp := range row {
			if sp.c == "" {
				b.WriteString(sp.s)
			} else {
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(sp.c)).Render(sp.s))
			}
		}
	}
	return b.String()
}

// logoRows reports a baked table's height in terminal rows.
func logoRows(rows [][]logoSpan) int { return len(rows) }

// brandGradient colours each rune of s across the blue→violet brand ramp
// (the header wordmark). Plain bold on NoColor — meaning never colour-only.
func brandGradient(s string, noColor bool) string {
	if noColor {
		return lipgloss.NewStyle().Bold(true).Render(s)
	}
	runes := []rune(s)
	n := len(runes) - 1
	if n < 1 {
		n = 1
	}
	var a, z [3]int
	fmt.Sscanf(brandBlue, "#%02x%02x%02x", &a[0], &a[1], &a[2])
	fmt.Sscanf(brandViolet, "#%02x%02x%02x", &z[0], &z[1], &z[2])
	var b strings.Builder
	for i, r := range runes {
		var c [3]int
		for j := 0; j < 3; j++ {
			c[j] = a[j] + (z[j]-a[j])*i/n
		}
		st := lipgloss.NewStyle().Bold(true).
			Foreground(lipgloss.Color(fmt.Sprintf("#%02x%02x%02x", c[0], c[1], c[2])))
		b.WriteString(st.Render(string(r)))
	}
	return b.String()
}
