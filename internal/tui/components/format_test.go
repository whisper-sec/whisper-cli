// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package components

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{-5, "0"}, {0, "0"}, {999, "999"}, {1000, "1.0K"},
		{45_200_000, "45.2M"}, {5_800_000_000, "5.8G"},
	}
	for _, c := range cases {
		if got := Bytes(c.n); got != c.want {
			t.Errorf("Bytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestCount(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0"}, {999, "999"}, {1500, "1.5k"}, {88_000, "88.0k"}, {4_200_000, "4.2M"},
	}
	for _, c := range cases {
		if got := Count(c.n); got != c.want {
			t.Errorf("Count(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestSparklineFixedWidth(t *testing.T) {
	// A braille sparkline must always be exactly `width` cells (no jitter), even on a
	// nil/short series (left-pad) and a longer one (take the tail).
	for _, w := range []int{1, 6, 24} {
		for _, vals := range [][]float64{nil, {1}, {1, 2, 3}, {5, 4, 3, 2, 1, 9, 8, 7, 6, 5}} {
			s := Sparkline(vals, w, false)
			if n := utf8.RuneCountInString(s); n != w {
				t.Errorf("Sparkline(len=%d, w=%d) = %d runes, want %d", len(vals), w, n, w)
			}
		}
	}
	if Sparkline([]float64{1, 2}, 0, false) != "" {
		t.Error("Sparkline width 0 should be empty")
	}
}

func TestSparklineAsciiRamp(t *testing.T) {
	// NO_COLOR / ascii mode must use only the ASCII ramp runes, never braille blocks.
	s := Sparkline([]float64{1, 5, 9, 3}, 4, true)
	for _, r := range s {
		if !strings.ContainsRune(" .:-=+*#", r) {
			t.Errorf("ascii sparkline contains non-ascii ramp rune %q in %q", r, s)
		}
	}
}

func TestGaugeClampsAndWidth(t *testing.T) {
	if g := Gauge(0.5, 1, 10, false); utf8.RuneCountInString(g) != 10 {
		t.Errorf("gauge width = %d, want 10", utf8.RuneCountInString(g))
	}
	full := Gauge(2, 1, 8, true) // over-full clamps to all-filled
	if full != strings.Repeat("#", 8) {
		t.Errorf("over-full gauge = %q", full)
	}
	empty := Gauge(-1, 1, 8, true) // negative clamps to empty
	if empty != strings.Repeat("-", 8) {
		t.Errorf("negative gauge = %q", empty)
	}
}

func TestClockAndHelpers(t *testing.T) {
	if Clock(0) != "--:--:--" {
		t.Error("zero ts should render the placeholder clock")
	}
	if got := Clock(1_700_000_000_000_000); len(got) != 8 || !strings.Contains(got, ":") {
		t.Errorf("Clock format wrong: %q", got)
	}
	if OrDash("  ") != "-" || OrDash("x") != "x" {
		t.Error("OrDash wrong")
	}
	if TrimDot("a.b.") != "a.b" || TrimDot("a.b") != "a.b" {
		t.Error("TrimDot wrong")
	}
	if ShortAddr("tdeadbeefcafebabefoo", 5, 3) != "tdead…foo" {
		t.Errorf("ShortAddr wrong: %q", ShortAddr("tdeadbeefcafebabefoo", 5, 3))
	}
	if ShortAddr("short", 5, 3) != "short" {
		t.Error("ShortAddr should leave a short string untouched")
	}
}
