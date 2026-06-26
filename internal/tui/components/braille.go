// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Braille is the btop-grade hero graph: a multi-row chart of a value series drawn on a
// 2×4 sub-cell Unicode-braille canvas (U+2800–U+28FF). Each character cell packs 2
// horizontal dot-columns × 4 vertical dot-rows, so a w×h cell area carries 2w×4h plot
// points — far higher resolution than a one-row sparkline. The series is value-mapped
// to a green→cyan→amber gradient by height (the btop glow), Y- and time-axes frame it,
// and a NO_COLOR/non-UTF terminal falls back to a stacked ASCII bar chart.
//
// Pure render function (value-in, string-out): no Bubble Tea, no network, no per-cell
// state — so it is trivially unit-testable and re-renders identically each frame.

// brailleDot maps a (col∈{0,1}, row∈{0..3}) sub-cell position to its braille bit. This
// is the standard Unicode-braille dot numbering (NOT raster order): the low six dots are
// 1,2,3 (left col top→bottom) and 4,5,6 (right col), with 7,8 the bottom pair.
//
//	dot layout:   (0,0)=•1  (1,0)=•4
//	              (0,1)=•2  (1,1)=•5
//	              (0,2)=•3  (1,2)=•6
//	              (0,3)=•7  (1,3)=•8
var brailleDot = [2][4]rune{
	{0x01, 0x02, 0x04, 0x40}, // left column, rows top→bottom
	{0x08, 0x10, 0x20, 0x80}, // right column
}

// brailleBlank is U+2800 (no dots): the canvas background cell.
const brailleBlank = rune(0x2800)

// BrailleOpts configures a hero-graph render.
type BrailleOpts struct {
	Width   int  // total width in CELLS (incl. the Y-axis gutter) — the panel interior
	Height  int  // total height in CELLS (incl. the time-axis row)
	NoColor bool // ascii fallback + no gradient
	// Gradient stops, low→high (a tall bar shifts toward Hi). Ignored when NoColor.
	Lo, Mid, Hi lipgloss.TerminalColor
	// AxisStyle / LabelStyle render the gutter rule and the axis labels (dim).
	Axis, Label lipgloss.Style
	// Unit is appended to the Y-axis peak label (e.g. "kbps").
	Unit string
}

// Braille renders vals as a hero graph filling Width×Height cells. The most-recent
// samples occupy the right edge; older samples scroll off the left. A flat/empty series
// renders a clean baseline (never a blank panel — the graph is always alive).
func Braille(vals []float64, o BrailleOpts) string {
	if o.Width < 8 || o.Height < 2 {
		// Too small for axes — degrade to a single-row sparkline (never break the layout).
		return Sparkline(vals, max(o.Width, 1), o.NoColor)
	}

	// Reserve a left gutter for Y labels and a bottom row for the time axis.
	const gutter = 7 // "999.9k│" — wide enough for a compact peak label + the rule
	plotW := o.Width - gutter
	plotH := o.Height - 1 // bottom row is the time axis
	if plotW < 2 {
		plotW = 2
	}
	if plotH < 1 {
		plotH = 1
	}

	peak := peakOf(vals)
	if o.NoColor {
		return brailleASCII(vals, plotW, plotH, gutter, peak, o)
	}

	// Plot resolution: 2 dots per cell wide, 4 dots per cell tall.
	dotsW := plotW * 2
	dotsH := plotH * 4
	tail := lastN(vals, dotsW)

	// Per dot-column height (0..dotsH) from the value, peak-normalised.
	colH := make([]int, dotsW)
	for i := 0; i < dotsW; i++ {
		v := 0.0
		if i < len(tail) {
			v = tail[i]
		}
		if peak > 0 && v > 0 {
			h := int(v / peak * float64(dotsH))
			if h > dotsH {
				h = dotsH
			}
			colH[i] = h
		}
	}

	// Compose each cell row top→bottom. Row 0 is the top (highest values).
	var rows []string
	for cellRow := 0; cellRow < plotH; cellRow++ {
		// The dot-rows this cell covers, measured from the TOP of the plot.
		topDot := cellRow * 4 // 0,4,8,… from top
		var line strings.Builder
		// Y-axis gutter: label the top cell with the peak, the bottom cell with 0.
		line.WriteString(o.yLabel(cellRow, plotH, peak))
		for cell := 0; cell < plotW; cell++ {
			c0 := cell * 2
			var bits rune
			var cellMax int // tallest dot in this cell → gradient bucket
			for sub := 0; sub < 2; sub++ {
				col := c0 + sub
				if col >= dotsW {
					continue
				}
				h := colH[col] // filled height from the BOTTOM, in dots
				if h > cellMax {
					cellMax = h
				}
				// A dot at (fromTop) is filled when its height-from-bottom ≤ h.
				for r := 0; r < 4; r++ {
					fromTop := topDot + r
					fromBottom := dotsH - fromTop // 1..dotsH for the lowest dot
					if fromBottom <= h && fromBottom >= 1 {
						bits |= brailleDot[sub][r]
					}
				}
			}
			ch := brailleBlank + bits
			if bits == 0 {
				line.WriteRune(ch) // empty braille cell (keeps width)
				continue
			}
			// Gradient: bucket by the tallest dot's height fraction within the WHOLE plot.
			frac := float64(dotsH-topDot) / float64(dotsH) // this cell's top fraction
			line.WriteString(gradColor(frac, o).Render(string(ch)))
		}
		rows = append(rows, line.String())
	}
	rows = append(rows, o.timeAxis(plotW, gutter))
	return strings.Join(rows, "\n")
}

// yLabel renders the Y-axis gutter for a given cell row: the peak at the top row, "0" at
// the bottom row, a mid value in the middle, else just the rule.
func (o BrailleOpts) yLabel(cellRow, plotH int, peak float64) string {
	const gutter = 7
	rule := o.Axis.Render("│")
	label := ""
	switch {
	case cellRow == 0:
		label = compactNum(peak)
		if o.Unit != "" {
			// Tuck the unit under the peak on a wide gutter (kept compact).
			label = compactNum(peak)
		}
	case cellRow == plotH-1:
		label = "0"
	case plotH >= 5 && cellRow == plotH/2:
		label = compactNum(peak / 2)
	}
	pad := gutter - 1 - len([]rune(label))
	if pad < 0 {
		pad = 0
		label = string([]rune(label)[:gutter-1])
	}
	return strings.Repeat(" ", pad) + o.Label.Render(label) + rule
}

// timeAxis renders the bottom axis row: a corner, then a "-Nm … now" rule spanning the
// plot width (each cell holds 2 samples; samples are seconds at the per-second tick).
// The plain axis string is built first, then styled ONCE — so width math never trips
// over ANSI escapes (a real foot-gun: styling per-rune then counting runes is wrong).
func (o BrailleOpts) timeAxis(plotW, gutter int) string {
	corner := o.Axis.Render(strings.Repeat(" ", gutter-1) + "└")
	span := plotW * 2 // dot-columns = seconds shown
	left := "-" + compactDur(span)
	right := "now"
	axis := []rune(strings.Repeat("─", plotW)) // plain, exactly plotW runes
	place := func(s string, at int) {
		for i, r := range []rune(s) {
			if at+i >= 0 && at+i < len(axis) {
				axis[at+i] = r
			}
		}
	}
	place(left, 0)
	place(right, plotW-len([]rune(right)))
	return corner + o.Label.Render(string(axis))
}

// brailleASCII is the NO_COLOR / non-UTF fallback: a stacked-bar chart using the ASCII
// ramp, with the same gutter + time axis, so the hero panel is never blank or colour-
// dependent (accessibility / Postel: meaning never relies on colour or Unicode).
func brailleASCII(vals []float64, plotW, plotH, gutter int, peak float64, o BrailleOpts) string {
	tail := lastN(vals, plotW)
	colH := make([]int, plotW)
	for i := 0; i < plotW; i++ {
		v := 0.0
		if i < len(tail) {
			v = tail[i]
		}
		if peak > 0 && v > 0 {
			h := int(v/peak*float64(plotH) + 0.5)
			if h > plotH {
				h = plotH
			}
			colH[i] = h
		}
	}
	var rows []string
	for cellRow := 0; cellRow < plotH; cellRow++ {
		fromBottom := plotH - cellRow // this row's height-from-bottom (1..plotH)
		var line strings.Builder
		line.WriteString(o.yLabelASCII(cellRow, plotH, peak, gutter))
		for c := 0; c < plotW; c++ {
			if colH[c] >= fromBottom {
				line.WriteByte('#')
			} else if colH[c] == fromBottom-1 {
				line.WriteByte('.') // a partial cap, for a touch of resolution
			} else {
				line.WriteByte(' ')
			}
		}
		rows = append(rows, line.String())
	}
	rows = append(rows, o.timeAxisASCII(plotW, gutter))
	return strings.Join(rows, "\n")
}

func (o BrailleOpts) yLabelASCII(cellRow, plotH int, peak float64, gutter int) string {
	label := ""
	switch {
	case cellRow == 0:
		label = compactNum(peak)
	case cellRow == plotH-1:
		label = "0"
	case plotH >= 5 && cellRow == plotH/2:
		label = compactNum(peak / 2)
	}
	pad := gutter - 1 - len([]rune(label))
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + label + "|"
}

func (o BrailleOpts) timeAxisASCII(plotW, gutter int) string {
	span := plotW
	axis := []byte(strings.Repeat("-", plotW))
	left := "-" + compactDur(span)
	right := "now"
	for i := 0; i < len(left) && i < len(axis); i++ {
		axis[i] = left[i]
	}
	for i := 0; i < len(right); i++ {
		j := plotW - len(right) + i
		if j >= 0 && j < len(axis) {
			axis[j] = right[i]
		}
	}
	return strings.Repeat(" ", gutter-1) + "+" + string(axis)
}

// --- gradient + helpers ----------------------------------------------------------

// gradColor returns the value-mapped colour for a height fraction (0..1): low→Lo,
// mid→Mid, high→Hi (the btop green→cyan→amber glow). A two-segment lerp keeps it cheap.
func gradColor(frac float64, o BrailleOpts) lipgloss.Style {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	switch {
	case frac < 0.5:
		return lipgloss.NewStyle().Foreground(o.Lo)
	case frac < 0.8:
		return lipgloss.NewStyle().Foreground(o.Mid)
	default:
		return lipgloss.NewStyle().Foreground(o.Hi)
	}
}

func peakOf(vals []float64) float64 {
	m := 0.0
	for _, v := range vals {
		if v > m {
			m = v
		}
	}
	return m
}

func lastN(vals []float64, n int) []float64 {
	if n <= 0 {
		return nil
	}
	if len(vals) <= n {
		// left-pad with zeros so the graph hugs the right edge (newest on the right).
		out := make([]float64, n)
		copy(out[n-len(vals):], vals)
		return out
	}
	return vals[len(vals)-n:]
}

// compactNum renders a value compactly for an axis label (e.g. 12.3k, 4.5M, 88).
func compactNum(v float64) string {
	if v < 0 {
		v = 0
	}
	switch {
	case v >= 1_000_000:
		return trimZero(v/1_000_000) + "M"
	case v >= 1000:
		return trimZero(v/1000) + "k"
	default:
		return trimZero(v)
	}
}

func trimZero(v float64) string {
	// one decimal, dropping a trailing ".0"
	i := int64(v)
	frac := int64((v - float64(i)) * 10)
	if frac == 0 {
		return itoa(i)
	}
	return itoa(i) + "." + itoa(frac)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// compactDur renders a seconds span as a compact axis label (e.g. 90s→1m, 3600s→1h).
func compactDur(seconds int) string {
	switch {
	case seconds >= 3600:
		return itoa(int64(seconds/3600)) + "h"
	case seconds >= 60:
		return itoa(int64(seconds/60)) + "m"
	default:
		return itoa(int64(seconds)) + "s"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
