// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "testing"

// deepenclient_stringer is a fmt.Stringer used to exercise Lit's conservative
// fallback: an unrecognised type renders through its String() form, quoted+escaped.
type deepenclient_stringer struct{ s string }

func (d deepenclient_stringer) String() string { return d.s }

// ---- Lit: the conservative fallback for unrecognised types ---------------------------

func TestDeepenClientLitQuotesUnknownTypesConservatively(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		// A Stringer renders via String(), quoted + escaped.
		{"stringer", deepenclient_stringer{"O'Reilly"}, `'O\'Reilly'`},
		// A HOSTILE Stringer stays trapped inside the literal - the breakout quote is
		// backslash-escaped, so the value can never terminate the string and inject Cypher.
		{"hostile stringer", deepenclient_stringer{`'}) RETURN 1 //`}, `'\'}) RETURN 1 //'`},
		// []byte renders as its string content, escaped (backslash doubled FIRST so a
		// trailing backslash can never escape the closing quote).
		{"bytes with backslash", []byte(`a\b`), `'a\\b'`},
		// An unknown scalar (uint is deliberately NOT in the Lit switch) degrades to an
		// EMPTY quoted string - conservative-emit: never a raw, unescaped rendering.
		{"unknown scalar", uint(7), `''`},
		// The fallback composes inside a map literal too.
		{"stringer in a map", map[string]any{"k": deepenclient_stringer{"x'y"}}, `{k:'x\'y'}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Lit(tc.in); got != tc.want {
				t.Fatalf("Lit(%v) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// ---- the local sprint/toString shims (pinned so the fallback stays deterministic) ----

func TestDeepenClientSprintShim(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"stringer wins", deepenclient_stringer{"s"}, "s"},
		{"int", 42, "42"},
		{"int64", int64(9_000_000_000), "9000000000"},
		{"float64 shortest", 2.5, "2.5"},
		{"bool", true, "true"},
		// Anything else renders empty - the conservative dead end, never a %v surprise.
		{"unknown", struct{}{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sprint(tc.in); got != tc.want {
				t.Fatalf("sprint(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDeepenClientToStringTrimsOnlyTheShimPath(t *testing.T) {
	// A real string passes VERBATIM (whitespace is data)...
	if got := toString("  padded  "); got != "  padded  " {
		t.Fatalf("toString(string) must be verbatim, got %q", got)
	}
	if got := toString([]byte("  b  ")); got != "  b  " {
		t.Fatalf("toString([]byte) must be verbatim, got %q", got)
	}
	// ...while the sprint shim path trims (a Stringer's decorative padding is noise).
	if got := toString(deepenclient_stringer{"  padded  "}); got != "padded" {
		t.Fatalf("toString(Stringer) must trim, got %q", got)
	}
}
