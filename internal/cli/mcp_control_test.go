// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// problemServer is a control-plane stub that always replies with one canned status+body.
func problemServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// mcp_control_test.go covers the KEY-GATED half of the MCP surface: the
// two-tier tools/list gate, the missing-key tool error, each control tool's op mapping
// through the recordingServer stub, and the egress-config strings.

// pinKeyState pins the key ladder for a test: key == "" means NO credential can resolve
// (env cleared via t.Setenv, key file pointed into an empty temp dir), key != "" supplies
// that key via the flag rung. controlURL points the client at a stub. g is restored on
// cleanup. This keeps the gate tests deterministic on a dev box that has a real
// ~/.config/whisper-ns/key.
func pinKeyState(t *testing.T, key, controlURL string) {
	t.Helper()
	saved := g
	t.Cleanup(func() { g = saved })
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	g = globalFlags{
		key:        key,
		controlURL: controlURL,
		keyFile:    filepath.Join(t.TempDir(), "no-key"),
		timeout:    5 * time.Second,
	}
}

// toolText pulls the single text content out of a tools/call response.
func toolText(t *testing.T, resp map[string]any) (text string, isError bool) {
	t.Helper()
	res, _ := resp["result"].(map[string]any)
	if res == nil {
		t.Fatalf("tools/call must return a result, got %v", resp)
	}
	isError, _ = res["isError"].(bool)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("tool result has no content: %v", res)
	}
	first, _ := content[0].(map[string]any)
	text, _ = first["text"].(string)
	return text, isError
}

func callLine(id int, tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

// TestMCP_ToolsList_WithKey: with a key resolved, tools/list advertises BOTH tiers — the 2
// keyless tools plus all 6 control tools, each carrying a description and an inputSchema
// (the LLM must know exactly when/how to use each).
func TestMCP_ToolsList_WithKey(t *testing.T) {
	pinKeyState(t, "whisper_live_test", "")
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("expected 8 tools with a key (2 keyless + 6 control), got %d", len(tools))
	}
	names := map[string]bool{}
	for _, ti := range tools {
		tm := ti.(map[string]any)
		name, _ := tm["name"].(string)
		names[name] = true
		if d, _ := tm["description"].(string); strings.TrimSpace(d) == "" {
			t.Fatalf("tool %q has no description (agent-unfriendly)", name)
		}
		if _, ok := tm["inputSchema"].(map[string]any); !ok {
			t.Fatalf("tool %q missing inputSchema", name)
		}
	}
	for _, want := range []string{
		"whisper_verify", "whisper_rdap",
		"whisper_register", "whisper_list", "whisper_policy",
		"whisper_logs", "whisper_revoke", "whisper_egress_config",
	} {
		if !names[want] {
			t.Fatalf("missing tool %q (have %v)", want, names)
		}
	}
}

// TestMCP_ControlCallWithoutKey: calling a control tool with NO key resolvable is a normal
// MCP tool error (isError:true) whose text names the exact fix — never an opaque failure
// and never a JSON-RPC protocol error.
func TestMCP_ControlCallWithoutKey(t *testing.T) {
	pinKeyState(t, "", "")
	for i, tool := range []string{"whisper_list", "whisper_register", "whisper_revoke", "whisper_egress_config"} {
		r := drive(t, callLine(10+i, tool, `{"name":"x","agent":"y"}`))
		text, isError := toolText(t, r[0])
		if !isError {
			t.Fatalf("%s without a key must be a tool error, got %q", tool, text)
		}
		if !strings.Contains(text, "WHISPER_API_KEY") {
			t.Fatalf("%s no-key error must name WHISPER_API_KEY, got %q", tool, text)
		}
	}
}

// TestMCP_Register_FiresOpIdentity: whisper_register maps to op:identity with the name as
// the server label (mirroring `whisper create`), and the result carries the /128 as
// column-keyed records.
func TestMCP_Register_FiresOpIdentity(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	r := drive(t, callLine(1, "whisper_register", `{"name":"mcp-scout"}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("register errored: %q", text)
	}
	if !containsOp(opsSeen(seen), "identity") {
		t.Fatalf("whisper_register must fire op:identity, ops=%v", opsSeen(seen))
	}
	body, _ := bodyForOp(seen, "identity")
	if !strings.Contains(body, "mcp-scout") {
		t.Fatalf("register must pass the name as the label, body=%q", body)
	}
	if !strings.Contains(text, "2a04:2a01:9::abcd") {
		t.Fatalf("register result must carry the /128 address, got %q", text)
	}
	var parsed struct {
		Ok      bool             `json:"ok"`
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil || !parsed.Ok || len(parsed.Records) == 0 {
		t.Fatalf("register result must be {ok,records} JSON, got %q (err %v)", text, err)
	}
}

// TestMCP_Register_WithKey_FiresOpRegister: with_key:true maps to op:register and returns
// the once-only api_key exactly as the CLI does — no more, no less.
func TestMCP_Register_WithKey_FiresOpRegister(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	r := drive(t, callLine(1, "whisper_register", `{"name":"mcp-own-key","with_key":true}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("register with_key errored: %q", text)
	}
	if !containsOp(opsSeen(seen), "register") {
		t.Fatalf("with_key must fire op:register, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(text, "whisper_live_oncekey") {
		t.Fatalf("op:register result must carry the once-only api_key (CLI parity), got %q", text)
	}
}

// TestMCP_Register_RequiresName: the mandatory-name rule (§3.2) holds on the MCP surface too.
func TestMCP_Register_RequiresName(t *testing.T) {
	pinKeyState(t, "whisper_live_test", "")
	r := drive(t, callLine(1, "whisper_register", `{}`))
	text, isError := toolText(t, r[0])
	if !isError || !strings.Contains(text, "name") {
		t.Fatalf("register without a name must be a clear tool error, got isError=%v %q", isError, text)
	}
}

// TestMCP_ListLogsPolicyRevoke_OpMapping: each control tool fires its documented op with the
// documented args — the exact same wire the CLI subcommands produce.
func TestMCP_ListLogsPolicyRevoke_OpMapping(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	drive(t,
		callLine(1, "whisper_list", `{}`),
		callLine(2, "whisper_logs", `{"agent":"2a04:2a01:9::abcd","limit":5,"kind":"dns"}`),
		callLine(3, "whisper_policy", `{}`),
		callLine(4, "whisper_policy", `{"block":["evil.example"],"default":"allow"}`),
		callLine(5, "whisper_revoke", `{"agent":"2a04:2a01:9::abcd"}`),
	)
	ops := opsSeen(seen)
	for _, want := range []string{"list", "logs", "policy", "revoke"} {
		if !containsOp(ops, want) {
			t.Fatalf("expected op %q to fire, ops=%v", want, ops)
		}
	}
	if body, _ := bodyForOp(seen, "logs"); !strings.Contains(body, "2a04:2a01:9::abcd") || !strings.Contains(body, "dns") {
		t.Fatalf("logs must pass agent+kind, body=%q", body)
	}
	if body, _ := bodyForOp(seen, "revoke"); !strings.Contains(body, "2a04:2a01:9::abcd") {
		t.Fatalf("revoke must pass the agent, body=%q", body)
	}
	// The SET policy call (the second) must carry the block list; the READ (the first) fired
	// op:policy with no entries — both are op:policy, CLI verb semantics.
	var policyBodies []string
	for _, c := range seen {
		if c.op == "policy" {
			policyBodies = append(policyBodies, c.body)
		}
	}
	if len(policyBodies) != 2 {
		t.Fatalf("expected 2 op:policy calls (read + set), got %d", len(policyBodies))
	}
	if strings.Contains(policyBodies[0], "evil.example") {
		t.Fatalf("the no-arg policy call must be a pure read, body=%q", policyBodies[0])
	}
	if !strings.Contains(policyBodies[1], "evil.example") || !strings.Contains(policyBodies[1], "allow") {
		t.Fatalf("the set policy call must carry block+default, body=%q", policyBodies[1])
	}
}

// TestMCP_ControlPlaneFailure_IsToolError: an ok:false envelope surfaces as a tool error with
// the server's helpful detail (never opaque, never a protocol error).
func TestMCP_ControlPlaneFailure_IsToolError(t *testing.T) {
	srv := problemServer(t, 403, `{"ok":false,"status":403,"error":{"status":403,"detail":"scope dns:zone:write required"}}`)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	r := drive(t, callLine(1, "whisper_list", `{}`))
	text, isError := toolText(t, r[0])
	if !isError {
		t.Fatalf("ok:false must be a tool error, got %q", text)
	}
	if !strings.Contains(text, "not accepted") && !strings.Contains(text, "scope") {
		t.Fatalf("tool error must carry helpful detail, got %q", text)
	}
}

// TestMCP_EgressConfig_ExactStrings: whisper_egress_config returns the exact local endpoint +
// proxy-env strings `whisper connect`/`whisper init` emit for the pinned port, plus the start
// commands — with no secret anywhere in the output.
func TestMCP_EgressConfig_ExactStrings(t *testing.T) {
	pinKeyState(t, "whisper_live_test", "")
	r := drive(t, callLine(1, "whisper_egress_config", `{"port":23456,"agent":"2a04:2a01:9::abcd"}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("egress_config errored: %q", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("egress_config must return JSON: %v (%q)", err, text)
	}
	if out["proxy_socks5"] != "socks5h://127.0.0.1:23456" || out["proxy_http"] != "http://127.0.0.1:23456" {
		t.Fatalf("wrong endpoints: %v", out)
	}
	env, _ := out["proxy_env"].(string)
	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:23456",
		"HTTPS_PROXY=http://127.0.0.1:23456",
		"ALL_PROXY=socks5h://127.0.0.1:23456",
		"NO_PROXY=localhost,127.0.0.1,::1",
		"NODE_USE_ENV_PROXY=1",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("proxy_env must carry %q (the exact init strings), got %q", want, env)
		}
	}
	start, _ := out["start"].(string)
	if !strings.Contains(start, "whisper connect --agent 2a04:2a01:9::abcd --port 23456") {
		t.Fatalf("start must pin agent+port, got %q", start)
	}
	if strings.Contains(text, "whisper_live_test") {
		t.Fatalf("egress_config must never echo the key: %q", text)
	}
}

// TestMCP_EgressConfig_DefaultPortDeterministic: with no port given, the config picks the
// deterministic project port (same machinery as `whisper init`) — a sane in-window value.
func TestMCP_EgressConfig_DefaultPortDeterministic(t *testing.T) {
	pinKeyState(t, "whisper_live_test", "")
	r := drive(t, callLine(1, "whisper_egress_config", `{}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("egress_config errored: %q", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("egress_config must return JSON: %v", err)
	}
	socks, _ := out["proxy_socks5"].(string)
	var port int
	if _, err := fmt.Sscanf(socks, "socks5h://127.0.0.1:%d", &port); err != nil || port < 20000 || port >= 40000 {
		t.Fatalf("default port must sit in the deterministic 20000-40000 window, got %q", socks)
	}
}
