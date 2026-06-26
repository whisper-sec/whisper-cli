// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

func TestVisibleLenIgnoresANSI(t *testing.T) {
	cases := map[string]int{
		"hello":                  5,
		"\033[1;36mhello\033[0m": 5, // colour codes are zero-width
		"café":                   4,
		"":                       0,
		"\033[31m\033[0m":        0,
	}
	for in, want := range cases {
		if got := visibleLen(in); got != want {
			t.Fatalf("visibleLen(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestPadUsesVisibleWidth(t *testing.T) {
	// A coloured cell must pad to the same VISIBLE width as a plain one (alignment).
	plain := pad("ab", 5)
	colored := pad("\033[31mab\033[0m", 5)
	if visibleLen(plain) != visibleLen(colored) {
		t.Fatalf("coloured and plain pad to different visible widths: %d vs %d",
			visibleLen(plain), visibleLen(colored))
	}
}

func TestFieldFirstNonEmpty(t *testing.T) {
	rec := map[string]any{"a": "", "b": "x", "c": "y"}
	if got := field(rec, "a", "b", "c"); got != "x" {
		t.Fatalf("field = %q, want x", got)
	}
	if got := field(rec, "missing", "a"); got != "" {
		t.Fatalf("all-empty field = %q, want empty", got)
	}
}

func TestAsStringNumberRendering(t *testing.T) {
	// JSON numbers decode to float64; integers must render without a trailing .0.
	if got := asString(float64(1719080000000)); got != "1719080000000" {
		t.Fatalf("integer float = %q", got)
	}
	if got := asString(3.5); got != "3.5" {
		t.Fatalf("real float = %q", got)
	}
	if got := asString(nil); got != "" {
		t.Fatalf("nil = %q", got)
	}
	if got := asString(true); got != "true" {
		t.Fatalf("bool = %q", got)
	}
}

func TestLooksLikeV6(t *testing.T) {
	if !looksLikeV6("2a04:2a01::1") {
		t.Fatal("a /128 has a colon")
	}
	if looksLikeV6("agent-ab12cd") {
		t.Fatal("an agent id has no colon")
	}
}

func TestHumanTimeEpochMs(t *testing.T) {
	// epoch-ms heuristic (> 1e12).
	if got := humanTime("1719080000000"); got == "1719080000000" {
		t.Fatalf("epoch-ms not formatted: %q", got)
	}
	// a non-numeric value passes through unchanged.
	if got := humanTime("not-a-time"); got != "not-a-time" {
		t.Fatalf("non-numeric should pass through: %q", got)
	}
}
