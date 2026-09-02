// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"strings"
	"testing"
)

// hujson_test.go is the parser's positive, negative and round-trip matrix. A policy file
// is the input this whole migration hangs on, so the cases that matter are the ones where
// a naive comment stripper eats real content: a URL in a value, a comment marker inside a
// string, and a block comment that spans lines.

func TestHuJSONStripsLineComments(t *testing.T) {
	in := []byte("{\n // the engineering group\n \"groups\": {\"group:eng\": [\"a@example.com\"]}\n}")
	var out map[string]any
	if err := json.Unmarshal(HuJSONToJSON(in), &out); err != nil {
		t.Fatalf("a policy file with a line comment did not parse: %v", err)
	}
	if _, ok := out["groups"]; !ok {
		t.Fatal("the groups section was lost while stripping a comment")
	}
}

func TestHuJSONStripsBlockCommentsAndKeepsLineNumbers(t *testing.T) {
	in := []byte("{\n/* a comment\n   over three\n   lines */\n\"a\": 1\n}")
	got := HuJSONToJSON(in)
	if strings.Contains(string(got), "comment") {
		t.Fatalf("the block comment survived: %q", got)
	}
	if strings.Count(string(got), "\n") != strings.Count(string(in), "\n") {
		t.Fatalf("the line count changed (%d -> %d), so a decoder error would point at the wrong line",
			strings.Count(string(in), "\n"), strings.Count(string(got), "\n"))
	}
	var out map[string]any
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("did not parse after stripping a block comment: %v", err)
	}
}

// A URL is the case a naive `//` stripper destroys, and it is in real policy files as a
// comment and as a value.
func TestHuJSONDoesNotEatAURLInsideAString(t *testing.T) {
	in := []byte(`{"where": "https://example.com/policy", "n": 1}`)
	var out map[string]any
	if err := json.Unmarshal(HuJSONToJSON(in), &out); err != nil {
		t.Fatalf("a value containing // did not parse: %v", err)
	}
	if out["where"] != "https://example.com/policy" {
		t.Fatalf("the URL was truncated to %v", out["where"])
	}
}

func TestHuJSONKeepsCommentMarkersInsideStrings(t *testing.T) {
	in := []byte(`{"a": "/* not a comment */", "b": "// nor this"}`)
	var out map[string]string
	if err := json.Unmarshal(HuJSONToJSON(in), &out); err != nil {
		t.Fatalf("comment markers inside strings did not survive: %v", err)
	}
	if out["a"] != "/* not a comment */" || out["b"] != "// nor this" {
		t.Fatalf("string contents were rewritten: %+v", out)
	}
}

func TestHuJSONDropsTrailingCommas(t *testing.T) {
	for _, in := range []string{
		`{"a": 1, "b": 2,}`,
		`{"a": [1, 2, 3,],}`,
		"{\n \"a\": 1,\n // trailing comment then a close\n}",
	} {
		var out map[string]any
		if err := json.Unmarshal(HuJSONToJSON([]byte(in)), &out); err != nil {
			t.Errorf("%q did not parse after the trailing comma was dropped: %v", in, err)
		}
	}
}

func TestHuJSONKeepsCommasThatAreNotTrailing(t *testing.T) {
	in := []byte(`{"a": [1, 2], "b": 3}`)
	var out struct {
		A []int `json:"a"`
		B int   `json:"b"`
	}
	if err := json.Unmarshal(HuJSONToJSON(in), &out); err != nil {
		t.Fatalf("a well-formed document stopped parsing: %v", err)
	}
	if len(out.A) != 2 || out.B != 3 {
		t.Fatalf("content changed: %+v", out)
	}
}

func TestHuJSONLeavesStrictJSONByteIdentical(t *testing.T) {
	in := []byte(`{"a":1,"b":[2,3],"c":"x"}`)
	if got := string(HuJSONToJSON(in)); got != string(in) {
		t.Fatalf("strict JSON was rewritten:\n  in  %s\n  out %s", in, got)
	}
}

// A malformed file must still be malformed afterwards. Repairing it here would hide the
// operator's actual mistake behind a confident but wrong parse.
func TestHuJSONDoesNotRepairMalformedInput(t *testing.T) {
	for _, in := range []string{`{"a": `, `{"a": "unterminated`, `[1,2`} {
		var out any
		if err := json.Unmarshal(HuJSONToJSON([]byte(in)), &out); err == nil {
			t.Errorf("%q parsed after the comment strip, so a broken file was silently repaired", in)
		}
	}
}

func TestHuJSONHandlesEscapedQuotesInStrings(t *testing.T) {
	in := []byte(`{"a": "he said \"// hi\"", "b": 1}`)
	var out map[string]any
	if err := json.Unmarshal(HuJSONToJSON(in), &out); err != nil {
		t.Fatalf("an escaped quote broke the string scanner: %v", err)
	}
	if out["a"] != `he said "// hi"` {
		t.Fatalf("the escaped content changed: %v", out["a"])
	}
}

func TestHuJSONEmptyInput(t *testing.T) {
	if got := HuJSONToJSON(nil); len(got) != 0 {
		t.Fatalf("empty input produced %q", got)
	}
}
