// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"strings"
	"testing"
)

// readMapLiteralString is the control plane's own string scanner, transcribed.
//
// It is a deliberate second copy of somebody else's code, and that is the point: the
// question "did we escape this correctly" has exactly one right answer, and it belongs to
// the reader at the far end, not to us. This mirrors the reader's rules exactly - the
// closing quote ENDS the string, and a backslash introduces an escape - so a test written
// against it fails whenever we emit something that reader cannot take back apart.
//
// It returns the decoded value and whether the literal ended where we said it did.
func readMapLiteralString(lit string) (value string, wholeLiteralConsumed bool) {
	if len(lit) < 2 || lit[0] != '\'' {
		return "", false
	}
	var b strings.Builder
	for i := 1; i < len(lit); {
		c := lit[i]
		i++
		if c == '\'' {
			return b.String(), i == len(lit)
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i >= len(lit) {
			return b.String(), false
		}
		e := lit[i]
		i++
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		default:
			b.WriteByte(e) // covers \' \" \\ and, liberally, anything else
		}
	}
	return b.String(), false // unterminated
}

// TestQuotedStringRoundTripsThroughTheControlPlanesOwnReader is the test that fails
// without the fix. With the earlier doubling, "O'Reilly" was emitted as 'O”Reilly',
// which that reader ends after the O, so the value came back as "O" and the rest of the
// query became garbage - live, that was a 400 bad_request naming the map literal.
func TestQuotedStringRoundTripsThroughTheControlPlanesOwnReader(t *testing.T) {
	for _, in := range []string{
		"crawler-1",
		"",
		"O'Reilly",
		"''",
		`a\b`,
		`x\`,
		"'}}) RETURN 1 //",
		`it's a \ test`,
		"café-π",
		"line one\nline two",
		"tab\there",
		`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:internet"],"ip":["tcp:443"]}]}`,
		"// an operator's comment\n{\"default\": \"deny\"}\n",
	} {
		got, whole := readMapLiteralString(QuoteCypherString(in))
		if !whole {
			t.Fatalf("QuoteCypherString(%q) = %q: the reader did not consume the whole literal, so the "+
				"value ends the string early and the rest of the query is misparsed", in, QuoteCypherString(in))
		}
		if got != in {
			t.Fatalf("round trip of %q came back as %q via %q", in, got, QuoteCypherString(in))
		}
	}
}

func TestEscapeCypherString(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "crawler-1", "crawler-1"},
		{"empty", "", ""},
		{"apostrophe is backslash-escaped, not doubled", "O'Reilly", `O\'Reilly`},
		{"two apostrophes", "''", `\'\'`},
		{"backslash doubled", `a\b`, `a\\b`},
		{"trailing backslash cannot escape the quote", `x\`, `x\\`},
		{"breakout attempt stays trapped", "'}}) RETURN 1 //", `\'}}) RETURN 1 //`},
		{"mixed quote and backslash", `it's a \ test`, `it\'s a \\ test`},
		{"newline is escaped, not carried raw", "a\nb", `a\nb`},
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
	if got := QuoteCypherString("O'Reilly"); got != `'O\'Reilly'` {
		t.Fatalf("QuoteCypherString = %q", got)
	}
	// The escaped value is always wrapped in exactly one pair of single quotes, and the
	// inner text can never contain an UNESCAPED quote (the breakout invariant).
	got := QuoteCypherString("a'b'c")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("not wrapped: %q", got)
	}
	inner := got[1 : len(got)-1]
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' {
			i++ // skip whatever the backslash introduces
			continue
		}
		if inner[i] == '\'' {
			t.Fatalf("inner text has an unescaped quote (breakout risk): %q", inner)
		}
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
		{"string slice", []string{"a", "b'c"}, `['a','b\'c']`},
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
	// Keys must come out sorted regardless of insertion/iteration order - stable for
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
		want := `CALL whisper.agents({op:'identity', args:{friendly_name:'Tim O\'Reilly',label:'c1'}})`
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("a null value survives as null, which is how a document is withdrawn", func(t *testing.T) {
		got := BuildAgentsQuery("policy", map[string]any{"whale": map[string]any{"acl": nil, "base": "sha256:x"}})
		want := "CALL whisper.agents({op:'policy', args:{whale:{acl:null,base:'sha256:x'}}})"
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("injection attempt is trapped inside the literal", func(t *testing.T) {
		got := BuildAgentsQuery("list", map[string]any{"kind": "agents'}}) DETACH DELETE n //"})
		// The whole hostile value remains a single quoted literal - the only unescaped
		// quotes in the string are the literal's own delimiters; the args map never
		// closes early.
		if !strings.Contains(got, `args:{kind:'agents\'}}) DETACH DELETE n //'}`) {
			t.Fatalf("injection not trapped: %q", got)
		}
		if strings.Contains(got, "DETACH DELETE n //'}})\n") {
			t.Fatalf("query terminated early - breakout: %q", got)
		}
	})
}
