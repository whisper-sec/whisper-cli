// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"strings"
	"testing"
)

func TestEscapeCypherString(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "crawler-1", "crawler-1"},
		{"empty", "", ""},
		{"single apostrophe doubled", "O'Reilly", "O''Reilly"},
		{"two apostrophes", "''", "''''"},
		{"backslash doubled", `a\b`, `a\\b`},
		{"trailing backslash cannot escape the quote", `x\`, `x\\`},
		{"breakout attempt stays trapped", "'}}) RETURN 1 //", "''}}) RETURN 1 //"},
		{"mixed quote and backslash", `it's a \ test`, `it''s a \\ test`},
		{"unicode passes through", "café-π", "café-π"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EscapeCypherString(c.in); got != c.want {
				t.Fatalf("EscapeCypherString(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestQuoteCypherString(t *testing.T) {
	if got := QuoteCypherString("O'Reilly"); got != "'O''Reilly'" {
		t.Fatalf("QuoteCypherString = %q", got)
	}
	// The escaped value is always wrapped in exactly one pair of single quotes, and the
	// inner text can never contain an UN-doubled quote (the breakout invariant).
	got := QuoteCypherString("a'b'c")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("not wrapped: %q", got)
	}
	inner := got[1 : len(got)-1]
	// every apostrophe in the inner text must be part of a doubled pair
	if strings.Count(inner, "'")%2 != 0 {
		t.Fatalf("inner text has an unbalanced quote (breakout risk): %q", inner)
	}
}

func TestLit(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil is null", nil, "null"},
		{"string quoted", "hi", "'hi'"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"int", 42, "42"},
		{"int64", int64(-7), "-7"},
		{"float", 3.5, "3.5"},
		{"string slice", []string{"a", "b'c"}, "['a','b''c']"},
		{"any slice mixed", []any{1, "x", true}, "[1,'x',true]"},
		{"empty map", map[string]any{}, "{}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Lit(c.in); got != c.want {
				t.Fatalf("Lit(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestCypherMapIsDeterministic(t *testing.T) {
	// Keys must come out sorted regardless of insertion/iteration order — stable for
	// tests, caches, and logs.
	m := map[string]any{"zeta": 1, "alpha": "x", "mid": true}
	want := "{alpha:'x',mid:true,zeta:1}"
	for i := 0; i < 20; i++ {
		if got := CypherMap(m); got != want {
			t.Fatalf("CypherMap not deterministic: got %q, want %q", got, want)
		}
	}
}

func TestBuildAgentsQuery(t *testing.T) {
	t.Run("no args -> empty map", func(t *testing.T) {
		got := BuildAgentsQuery("list", nil)
		want := "CALL whisper.agents({op:'list', args:{}})"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("escapes op and args", func(t *testing.T) {
		got := BuildAgentsQuery("identity", map[string]any{"friendly_name": "Tim O'Reilly", "label": "c1"})
		want := "CALL whisper.agents({op:'identity', args:{friendly_name:'Tim O''Reilly',label:'c1'}})"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("injection attempt is trapped inside the literal", func(t *testing.T) {
		got := BuildAgentsQuery("list", map[string]any{"kind": "agents'}}) DETACH DELETE n //"})
		// The whole hostile value remains a single quoted literal — the only un-escaped
		// quotes in the string are the literal's own delimiters; the args map never
		// closes early.
		if !strings.Contains(got, "args:{kind:'agents''}}) DETACH DELETE n //'}") {
			t.Fatalf("injection not trapped: %q", got)
		}
		if strings.Contains(got, "DETACH DELETE n //'}})\n") {
			t.Fatalf("query terminated early — breakout: %q", got)
		}
	})
}
