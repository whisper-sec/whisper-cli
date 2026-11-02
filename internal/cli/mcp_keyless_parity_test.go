// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// mcp_keyless_parity_test.go holds `whisper mcp` to one rule: the tools a keyless
// tools/list shows are exactly the tools that answer a keyless tools/call. A tool that works
// without a key but is hidden without one understates the surface, so a keyless client never
// learns it can, say, read the docs. A tool that is listed but refuses overstates it. Either
// is a manifest that lies.
//
// "Answers" is measured, not declared: every tool of the KEYED catalogue is called with no
// key, with arguments that satisfy its own inputSchema, and a tool counts as keyed exactly
// when the reply is the no-key refusal (mcpNoKeyErr), and answers when the reply is no error
// at all. The network is a local stub: the verify, RDAP and graph tools that answer really
// sent a request and got bytes back; read_docs (in list mode) and list_workflows answer from
// the embedded index and catalog.

// listToolNames drives tools/list and returns the tools in listing order.
func listToolNames(t *testing.T) ([]string, map[string]map[string]any) {
	t.Helper()
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	raw, _ := res["tools"].([]any)
	names := make([]string, 0, len(raw))
	byName := map[string]map[string]any{}
	for _, ti := range raw {
		tm, _ := ti.(map[string]any)
		n, _ := tm["name"].(string)
		names = append(names, n)
		byName[n] = tm
	}
	return names, byName
}

// argsFor fills every required property of a tool's inputSchema with a value of the
// declared type, and every optional string too (run_workflow takes slug OR runs, so neither
// is "required" yet one must be present). That gets a call past argument validation to
// wherever the key is (or is not) demanded. A refusal for a missing argument would read as
// "answers without a key" and hide exactly the defect this file is about.
func argsFor(tool map[string]any) string {
	schema, _ := tool["inputSchema"].(map[string]any)
	props, _ := schema["properties"].(map[string]any)
	fill := map[string]bool{}
	req, _ := schema["required"].([]any)
	for _, ri := range req {
		name, _ := ri.(string)
		fill[name] = true
	}
	for name, pi := range props {
		if p, _ := pi.(map[string]any); p["type"] == "string" {
			fill[name] = true
		}
	}
	out := map[string]any{}
	for name := range fill {
		p, _ := props[name].(map[string]any)
		switch p["type"] {
		case "object":
			out[name] = map[string]any{}
		case "array":
			out[name] = []any{"example.com"}
		case "integer", "number":
			out[name] = 1
		case "boolean":
			out[name] = true
		default:
			if enum, ok := p["enum"].([]any); ok && len(enum) > 0 {
				out[name] = enum[0]
				continue
			}
			out[name] = "2a04:2a01::1"
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// parityArgs overrides argsFor where the schema-derived values would take a tool down an
// error path before it does its work. read_docs with no argument lists the index, the mode a
// keyless client reaches first; with a path it would fetch a public page from the internet,
// which a unit test must not do.
var parityArgs = map[string]string{
	"read_docs": `{}`,
}

func TestMCP_KeylessListingIsExactlyWhatAnswersWithoutAKey(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["n"],"rows":[{"n":1}]}`))
	}))
	defer stub.Close()

	pinKeyState(t, "whisper_live_test", stub.URL)
	keyedNames, keyed := listToolNames(t)

	pinKeyState(t, "", stub.URL)
	g.rdapURL, g.verifyURL, g.echoURL, g.monitorURL, g.consoleURL = stub.URL, stub.URL, stub.URL, stub.URL, stub.URL
	listedNames, _ := listToolNames(t)
	listed := map[string]bool{}
	for _, n := range listedNames {
		listed[n] = true
		if _, ok := keyed[n]; !ok {
			t.Errorf("%q is listed without a key but missing from the keyed listing", n)
		}
	}

	// A keyed listing no longer than the keyless one means the key was not honoured, and every
	// comparison below would be of one list against itself.
	if len(keyedNames) <= len(listedNames) {
		t.Fatalf("the keyed listing (%d) is not longer than the keyless one (%d), so the key was not honoured", len(keyedNames), len(listedNames))
	}

	// Each call lands in one of three buckets: it answers (no error), it is refused for the
	// missing key (exactly mcpNoKeyErr), or it fails for some other reason. The third bucket
	// is a failure of this test, never a quiet "answers": an argument error or a client
	// error says nothing about whether the tool needs a key.
	var answers []string
	for i, name := range keyedNames {
		args := argsFor(keyed[name])
		if a, ok := parityArgs[name]; ok {
			args = a
		}
		r := drive(t, callLine(100+i, name, args))
		text, isError := toolText(t, r[0])
		refused := isError && text == mcpNoKeyErr
		switch {
		case !isError:
			answers = append(answers, name)
			if !listed[name] {
				t.Errorf("%q answers without a key (%.120q) but a keyless tools/list hides it", name, text)
			}
		case refused:
			if listed[name] {
				t.Errorf("%q is listed without a key, yet a keyless call is refused: %q", name, text)
			}
		default:
			t.Errorf("%q failed keyless for a reason other than the key, so this test cannot tell whether it needs one: %.160q", name, text)
		}
	}

	sort.Strings(answers)
	sortedListed := append([]string(nil), listedNames...)
	sort.Strings(sortedListed)
	if strings.Join(answers, ",") != strings.Join(sortedListed, ",") {
		t.Fatalf("listed without a key: %v\nanswers without a key: %v", sortedListed, answers)
	}
	for _, must := range []string{"read_docs", "list_workflows"} {
		if !listed[must] {
			t.Errorf("%s needs no key and must be in the keyless listing, got %v", must, listedNames)
		}
	}
}

// The keyless listing names every reference tool it carries in the no-key refusal, so the
// error a keyed call gets tells the model what it CAN call instead.
func TestMCP_NoKeyErrorNamesEveryKeylessTool(t *testing.T) {
	pinKeyState(t, "", "")
	names, _ := listToolNames(t)
	for _, n := range names {
		if !strings.Contains(mcpNoKeyErr, n) {
			t.Errorf("the no-key refusal must name the keyless tool %q: %q", n, mcpNoKeyErr)
		}
	}
}
