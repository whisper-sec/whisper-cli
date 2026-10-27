// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// mcp_query_parameters_test.go: the two raw-Cypher MCP tools take their bound values under the engine's own
// name, "parameters", as well as under "params". The graph's request field is "parameters", so that is what a
// model that has read the graph's docs writes first, and until now it was silently dropped: the query ran with no
// values bound and came back empty or wrong, the exact failure the graph engine is closing on its side by
// refusing a body key it does not know.

func TestMCP_RawQueryToolsTakeParametersUnderEitherName(t *testing.T) {
	for _, tool := range []string{mcpGraphQueryToolName, mcpQueryToolName} {
		for _, field := range []string{"params", "parameters"} {
			f := newFakeGraph(t, `{"columns":["x"],"rows":[{"x":1}]}`)
			pinKeyState(t, "whisper_live_test", f.srv.URL)

			args := `{"query":"RETURN $h AS x","` + field + `":{"h":"example.com"}}`
			r := drive(t, callLine(70, tool, args))
			if text, isError := toolText(t, r[0]); isError {
				t.Fatalf("%s with %q: unexpected error %q", tool, field, text)
			}
			_, _, _, body := f.snapshot()
			params, _ := body["parameters"].(map[string]any)
			if params["h"] != "example.com" {
				t.Fatalf("%s with %q: the graph received parameters %v, want h=example.com", tool, field, body["parameters"])
			}
			for k := range body {
				if k != "query" && k != "parameters" {
					t.Fatalf("%s with %q: the graph received the undocumented top-level key %q", tool, field, k)
				}
			}
		}
	}
}

func TestMCP_RawQueryToolsRefuseTwoDifferentParameterMaps(t *testing.T) {
	for _, tool := range []string{mcpGraphQueryToolName, mcpQueryToolName} {
		f := newFakeGraph(t, `{"columns":["x"],"rows":[{"x":1}]}`)
		pinKeyState(t, "whisper_live_test", f.srv.URL)

		args := `{"query":"RETURN $h AS x","params":{"h":"a.example"},"parameters":{"h":"b.example"}}`
		r := drive(t, callLine(71, tool, args))
		text, isError := toolText(t, r[0])
		if !isError || !strings.Contains(text, "params") || !strings.Contains(text, "parameters") {
			t.Fatalf("%s: two different maps must be refused naming both fields, got isError=%v %q", tool, isError, text)
		}
		if hits, _, _, _ := f.snapshot(); hits != 0 {
			t.Fatalf("%s: an ambiguous call must not reach the graph, it was hit %d times", tool, hits)
		}
	}
}
