// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Bytes renders a byte count in a compact human form (1.0K, 45.2M, 5.8G). It uses
// 1000-base units (matching the dev guide's display style) so "45.2M" reads naturally.
func Bytes(n int64) string {
	if n < 0 {
		return "0"
	}
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"K", "M", "G", "T", "P"}[exp]
	return fmt.Sprintf("%.1f%s", float64(n)/float64(div), suffix)
}

// Count renders a plain integer count compactly (1.2k, 88k, 4k) for high-cardinality
// counters; small values stay exact.
func Count(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 1_000_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	default:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
}

// Gauge renders a fixed-width fraction bar (filled ▓ / empty ░), like btop. value/max
// clamps to [0,1]; width is the bar interior. With ascii on it uses '#'/'-'.
func Gauge(value, max float64, width int, ascii bool) string {
	if width <= 0 {
		return ""
	}
	frac := 0.0
	if max > 0 {
		frac = value / max
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	full, empty := '█', '░'
	if ascii {
		full, empty = '#', '-'
	}
	return strings.Repeat(string(full), fill) + strings.Repeat(string(empty), width-fill)
}

// GaugeGrad renders a fixed-width fraction bar whose FILLED portion is coloured by a
// three-stop value map of the fill fraction (low→lo, mid→mid, high→hi — the btop
// green→amber→red "load" look). The empty portion is dim. value/max clamps to [0,1].
// With colour off it falls back to the plain ascii Gauge (meaning never depends on
// colour). Pure: deterministic per (value,max,width), so no flicker on re-render.
func GaugeGrad(value, max float64, width int, noColor bool, lo, mid, hi, empty lipgloss.TerminalColor) string {
	if width <= 0 {
		return ""
	}
	if noColor {
		return Gauge(value, max, width, true)
	}
	frac := 0.0
	if max > 0 {
		frac = value / max
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	// Colour the whole filled run by the fill fraction (one colour per gauge — clean,
	// and a saturated gauge reads as solid red at a glance).
	col := lo
	switch {
	case frac >= 0.8:
		col = hi
	case frac >= 0.5:
		col = mid
	}
	filled := lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("█", fill))
	rest := lipgloss.NewStyle().Foreground(empty).Render(strings.Repeat("░", width-fill))
	return filled + rest
}

// Clock renders an event microsecond timestamp as HH:MM:SS (local-safe UTC).
func Clock(tsMicros int64) string {
	if tsMicros == 0 {
		return "--:--:--"
	}
	return time.UnixMicro(tsMicros).UTC().Format("15:04:05")
}

// Uptime renders a duration since an epoch-ms instant as a compact "3d2h" / "5m" form.
func Uptime(epochMs int64) string {
	if epochMs == 0 {
		return "-"
	}
	d := time.Since(time.UnixMilli(epochMs))
	if d < 0 {
		return "-"
	}
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hrs)
	case hrs > 0:
		return fmt.Sprintf("%dh%dm", hrs, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// ShortAddr abbreviates a long handle (an opaque t<sha256> tenant) to head…tail so the
// header stays compact while still being recognisable.
func ShortAddr(s string, head, tail int) string {
	if len(s) <= head+tail+1 {
		return s
	}
	return s[:head] + "…" + s[len(s)-tail:]
}

// TrimDot drops a trailing FQDN dot for display.
func TrimDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// OrDash returns "-" for an empty string (never a blank cell).
func OrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
