// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

// hujson.go turns Tailscale's policy file into something encoding/json will read.
//
// Their policy file is HuJSON: JSON plus // and /* */ comments plus trailing commas.
// The API returns it verbatim, comments intact, which is exactly what we want to read
// (the comments are how an operator explains a rule to the next operator, and the
// fidelity report quotes them back). encoding/json will not parse it.
//
// This is Postel at a file boundary. We accept the file as it is actually written,
// including the two things standard JSON forbids, and we emit strict JSON. The
// transformation is byte-preserving for everything else: it replaces a comment with
// nothing and drops a comma, and it changes nothing inside a string literal, so line
// and column offsets in a downstream json error still point at real content.
//
// It is a scanner rather than a parser on purpose: it must not have an opinion about
// the schema, because the schema is theirs and it changes.

// HuJSONToJSON strips comments and trailing commas from HuJSON, leaving strict JSON.
//
// Bytes inside a string literal are copied untouched, escapes included, so a URL in a
// value ("https://example.com") never loses its tail to the // scanner, and a comment
// marker inside a string survives verbatim.
//
// Unterminated constructs are left as they are rather than repaired: this function's job
// is to remove what JSON cannot read, and a genuinely malformed file must still fail in
// the JSON decoder with its own message rather than be silently rewritten here.
func HuJSONToJSON(in []byte) []byte {
	out := make([]byte, 0, len(in))
	// lastSignificant is the index in out of the last non-space byte written, so a
	// trailing comma can be found back past whitespace and a comment.
	lastSignificant := -1

	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(in) {
				if in[j] == '\\' {
					j += 2
					continue
				}
				if in[j] == '"' {
					j++
					break
				}
				j++
			}
			if j > len(in) {
				j = len(in)
			}
			out = append(out, in[i:j]...)
			lastSignificant = len(out) - 1
			i = j

		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			j := i + 2
			for j+1 < len(in) && !(in[j] == '*' && in[j+1] == '/') {
				j++
			}
			if j+1 < len(in) {
				j += 2
			} else {
				j = len(in)
			}
			// A block comment can span lines. Keep the newlines it swallowed so a
			// decoder's line number still lines up with the operator's file.
			for _, b := range in[i:j] {
				if b == '\n' {
					out = append(out, '\n')
				}
			}
			i = j

		case c == '}' || c == ']':
			// A trailing comma is the comma that closes nothing. Erase it in place,
			// keeping the whitespace and newlines between it and the bracket.
			if lastSignificant >= 0 && out[lastSignificant] == ',' {
				out[lastSignificant] = ' '
			}
			out = append(out, c)
			lastSignificant = len(out) - 1
			i++

		default:
			out = append(out, c)
			if !isJSONSpace(c) {
				lastSignificant = len(out) - 1
			}
			i++
		}
	}
	return out
}

// isJSONSpace is RFC 8259's whitespace set, and only that set.
func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
