// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// graph_value_shapes_test.go: `whisper query` carries every relationship and path value shape the graph engine sends
// today and the one it is about to send (one breaking release, rolled one engine node at a time), whichever
// node answers. --json is the engine's reply byte for byte; the table renders a value cell as its JSON. Nothing in the
// CLI reads a relationship's or a path's fields, so the shape change must change nothing but the text in the cell.

func loadShapes(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("../client/testdata/graph_value_shapes.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "_comment")
	if len(m) < 6 {
		t.Fatalf("the shape fixture lost entries: %d", len(m))
	}
	return m
}

func renderCaptured(t *testing.T, res *client.GraphResult, jsonOut bool) string {
	t.Helper()
	prev := g.jsonOut
	g.jsonOut = jsonOut
	defer func() { g.jsonOut = prev }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved, savedErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	renderGraphResult(res)
	_ = w.Close()
	os.Stdout, os.Stderr = saved, savedErr
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestQuery_EveryGraphValueShapeRendersUnchanged(t *testing.T) {
	for name, raw := range loadShapes(t) {
		res, err := client.DecodeGraphResult(raw, 200)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if got := renderCaptured(t, res, true); strings.TrimRight(got, "\n") != string(raw) {
			t.Fatalf("%s: --json must be the engine's reply byte for byte\n got %s\nwant %s", name, got, raw)
		}
		table := renderCaptured(t, res, false)
		if !strings.Contains(table, "1 row(s)") {
			t.Fatalf("%s: the table lost the row: %q", name, table)
		}
		var wire struct {
			Rows []map[string]json.RawMessage `json:"rows"`
		}
		_ = json.Unmarshal(raw, &wire)
		for col, v := range wire.Rows[0] {
			// The cell is the value's JSON (keys in Go's sorted order); a string cell is the string itself.
			want := strings.TrimSpace(string(v))
			var decoded any
			dec := json.NewDecoder(bytes.NewReader(v))
			dec.UseNumber()
			_ = dec.Decode(&decoded)
			if s, ok := decoded.(string); ok {
				want = s
			} else if b, err := json.Marshal(decoded); err == nil {
				want = string(b)
			}
			if !strings.Contains(table, want) {
				t.Fatalf("%s: column %s must render as %s, table was\n%s", name, col, want, table)
			}
		}
	}
}
