// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
)

// drive runs the MCP server over a canned newline-delimited input and returns the decoded
// response objects (one per non-notification request).
func drive(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	if err := runMCPServer(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("runMCPServer: %v", err)
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("response not valid JSON: %q (%v)", line, err)
		}
		resps = append(resps, m)
	}
	return resps
}

// TestMCP_Initialize: initialize returns a result with our serverInfo and echoes the client's
// requested protocolVersion.
func TestMCP_Initialize(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if len(r) != 1 {
		t.Fatalf("expected 1 response, got %d", len(r))
	}
	res, _ := r[0]["result"].(map[string]any)
	if res == nil {
		t.Fatalf("no result: %v", r[0])
	}
	if res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("should echo client protocolVersion, got %v", res["protocolVersion"])
	}
	si, _ := res["serverInfo"].(map[string]any)
	if si == nil || si["name"] != "whisper" {
		t.Fatalf("serverInfo wrong: %v", res["serverInfo"])
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("must declare tools capability: %v", res["capabilities"])
	}
}

// TestMCP_ToolsList: tools/list returns exactly the keyless tools, each with an inputSchema.
func TestMCP_ToolsList(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	names := map[string]bool{}
	for _, ti := range tools {
		tm := ti.(map[string]any)
		names[tm["name"].(string)] = true
		if _, ok := tm["inputSchema"].(map[string]any); !ok {
			t.Fatalf("tool %v missing inputSchema", tm["name"])
		}
	}
	for _, want := range []string{"whisper_verify", "whisper_rdap"} {
		if !names[want] {
			t.Fatalf("missing tool %q (have %v)", want, names)
		}
	}
}

// TestMCP_PingAndNotificationsAndUnknown: ping replies {}; a notification (no id) gets NO reply;
// an unknown method with an id returns method-not-found.
func TestMCP_PingAndNotificationsAndUnknown(t *testing.T) {
	r := drive(t,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`, // notification — no response
		`{"jsonrpc":"2.0","id":4,"method":"does/notExist"}`,
	)
	if len(r) != 2 {
		t.Fatalf("expected 2 responses (ping + unknown; notification silent), got %d: %v", len(r), r)
	}
	// ping → empty result object
	if _, ok := r[0]["result"]; !ok {
		t.Fatalf("ping must return a result: %v", r[0])
	}
	// unknown → error -32601
	em, _ := r[1]["error"].(map[string]any)
	if em == nil || int(em["code"].(float64)) != -32601 {
		t.Fatalf("unknown method must be -32601, got %v", r[1])
	}
}

// TestMCP_BadToolArgsAreToolErrors: a tools/call with a missing required arg returns a normal
// result with isError:true (an MCP tool error), NOT a JSON-RPC protocol error.
func TestMCP_BadToolArgsAreToolErrors(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"whisper_verify","arguments":{}}}`)
	res, _ := r[0]["result"].(map[string]any)
	if res == nil {
		t.Fatalf("a tool error must be a result, not a protocol error: %v", r[0])
	}
	if res["isError"] != true {
		t.Fatalf("missing target must set isError:true, got %v", res)
	}
}
