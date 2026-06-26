// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package client is the ONE place that talks to the Whisper control plane. It backs
// BOTH the scriptable Cobra subcommands and the Bubble Tea TUI (DRY): the Cypher
// query builder, the {ok,status,result} envelope decoder, the SSE reader, the key
// ladder, an embedded Mozilla CA bundle, and the RDAP client.
//
// Robustness Principle (RFC 761): conservative in what we EMIT — every Cypher literal
// is escaped so a value can never break out of the map; liberal in what we ACCEPT —
// the envelope decoder handles both wire shapes the control plane may return.
package client

import (
	"sort"
	"strconv"
	"strings"
)

// EscapeCypherString renders s safe to embed inside a single-quoted Cypher literal.
// Neo4j/openCypher escapes a single quote by DOUBLING it (” ); a backslash is also
// doubled so a trailing backslash can never escape the closing quote. A legitimate
// apostrophe in a label ("Tim O'Reilly") just works; a breakout attempt
// ("'}}) RETURN 1 //") stays trapped inside the literal value.
//
// Conservative in what we emit: the returned string is the INNER text only (no
// surrounding quotes) — callers wrap it in '...'.
func EscapeCypherString(s string) string {
	// Order matters: escape backslashes first, then quotes, so we never double-escape.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

// QuoteCypherString returns s as a complete single-quoted, escaped Cypher string literal.
func QuoteCypherString(s string) string {
	return "'" + EscapeCypherString(s) + "'"
}

// Lit renders an arbitrary Go value as a Cypher literal:
//   - string            -> a quoted, escaped string literal
//   - bool              -> true / false
//   - int / int64       -> the decimal form
//   - float64           -> the shortest exact decimal form
//   - []T / []any       -> a bracketed list of literals
//   - map[string]any    -> a brace map literal (keys sorted for determinism)
//   - nil               -> null
//
// Conservative-emit: every leaf string flows through QuoteCypherString, so no value —
// however hostile — can break out of the surrounding map/list.
func Lit(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return QuoteCypherString(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		// 'g' with -1 precision yields the shortest representation that round-trips.
		return strconv.FormatFloat(x, 'g', -1, 64)
	case []string:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = QuoteCypherString(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Lit(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		return CypherMap(x)
	default:
		// Be conservative: anything we don't recognise is rendered as its string form,
		// quoted+escaped, so it can never inject. (Numbers boxed oddly, etc.)
		return QuoteCypherString(toString(x))
	}
}

// CypherMap renders a map as a Cypher map literal: {k1:v1,k2:v2}. Keys are emitted in
// sorted order so the produced query is DETERMINISTIC (stable for tests, caches, and
// logs) regardless of Go map iteration order. An empty map renders as {}.
func CypherMap(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+Lit(m[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// BuildAgentsQuery builds the one control-plane verb:
//
//	CALL whisper.agents({op:'<op>', args:{...}})
//
// args may be nil/empty (rendered as {}). Both op and every arg value are escaped, so
// the produced Cypher is always well-formed and injection-proof.
func BuildAgentsQuery(op string, args map[string]any) string {
	var b strings.Builder
	b.WriteString("CALL whisper.agents({op:")
	b.WriteString(QuoteCypherString(op))
	b.WriteString(", args:")
	if len(args) == 0 {
		b.WriteString("{}")
	} else {
		b.WriteString(CypherMap(args))
	}
	b.WriteString("})")
	return b.String()
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return strings.TrimSpace(sprint(x))
	}
}

// sprint is a tiny fmt.Sprint shim kept local so cypher.go has no fmt import churn.
func sprint(v any) string {
	if s, ok := v.(interface{ String() string }); ok {
		return s.String()
	}
	switch x := v.(type) {
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}
