// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// mcp.go is `whisper mcp`: a Model Context Protocol server over stdio (#193). An MCP client
// (Claude Desktop, Cursor, Windsurf, VS Code, Cline, Goose, …) spawns `whisper mcp` and talks
// newline-delimited JSON-RPC 2.0 on stdin/stdout. It exposes the KEYLESS Whisper trust surface
// as tools — verify an agent identity (DANE/DNSSEC/JWS) and fetch RDAP for a /128 — so an agent
// can check "is this address a real Whisper agent, and whose?" in-chat, with NO API key and NO
// dependency on the private control backend (the work is done by the public endpoints).
//
// This is identity/verify/resolve in-chat — NOT host-socket egress; for egress an agent still
// uses `whisper init`/`whisper run`. The stdio transport keeps stdout for protocol bytes ONLY;
// all diagnostics go to stderr.

// mcpProtocolVersion is the MCP version we implement; we echo the client's requested version when
// it sends one (per the spec's negotiation), falling back to this.
const mcpProtocolVersion = "2024-11-05"

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a Model Context Protocol server (stdio) exposing Whisper's keyless verify/RDAP tools",
		Long: "Start an MCP server on stdio so an MCP client (Claude Desktop, Cursor, Windsurf, VS Code,\n" +
			"Cline, Goose, …) can call Whisper's KEYLESS trust tools in-chat:\n" +
			"  • whisper_verify <address|fqdn>  — is it a real Whisper agent? (DANE + DNSSEC + JWS)\n" +
			"  • whisper_rdap <ipv6>            — RDAP for a Whisper /128 (who operates it)\n\n" +
			"No API key is needed (the verify/RDAP surface is public). This is identity/verify in-chat,\n" +
			"not host egress — for egress use `whisper init` / `whisper run`.\n\n" +
			"Bare `whisper mcp` runs the server (point your client's stdio config at it). Use\n" +
			"`whisper mcp install` to write the client config for you.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPServer(os.Stdin, os.Stdout)
		},
	}
	cmd.AddCommand(newMCPInstallCmd())
	return cmd
}

// newMCPInstallCmd is `whisper mcp install`: it wires the `whisper mcp` stdio server into the
// MCP clients whose config is strict JSON keyed by `mcpServers` (the project `.mcp.json` used by
// Claude Code, and Cursor's `.cursor/mcp.json`) by surgical merge — and PRINTS the verified
// config snippet for clients whose format we won't risk auto-editing (VS Code's JSONC `servers`,
// Zed's JSONC `context_servers`, Goose/Continue YAML, and the global Claude Desktop/Windsurf
// files). Conservative-emit: we only auto-write where a JSON round-trip is safe.
func newMCPInstallCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wire `whisper mcp` into your MCP client config (project .mcp.json + .cursor/mcp.json), and print the rest",
		Long: "Write the Whisper stdio MCP server into the project-level MCP client configs that are\n" +
			"safe to edit as strict JSON — `.mcp.json` (Claude Code) and `.cursor/mcp.json` (Cursor) —\n" +
			"merging in a `whisper` server without touching your other servers. For clients with a\n" +
			"JSONC or YAML config (VS Code, Zed, Goose, Continue) or a global file (Claude Desktop,\n" +
			"Windsurf), it prints the exact verified snippet to paste.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPInstall(dir)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "the project directory (default: the current directory)")
	return cmd
}

// mcpServerEntry is the stdio entry that runs `whisper mcp` — the same shape Claude Code and
// Cursor both accept (command + args; type is inferred from command).
func mcpServerEntry() map[string]any {
	return map[string]any{"command": "whisper", "args": []string{"mcp"}}
}

// runMCPInstall merges the `whisper` server into the project JSON configs and prints the matrix.
func runMCPInstall(dir string) error {
	root := strings.TrimSpace(dir)
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return &client.ProblemError{Status: 500, Detail: "couldn't determine the current directory"}
		}
		root = cwd
	}

	// Auto-write the strict-JSON, mcpServers-keyed, project-scoped configs (safe surgical merge).
	targets := []struct{ label, path string }{
		{"Claude Code (.mcp.json)", filepath.Join(root, ".mcp.json")},
		{"Cursor (project .cursor/mcp.json)", filepath.Join(root, ".cursor", "mcp.json")},
	}
	w := os.Stderr
	if !g.jsonOut && !g.quiet {
		fmt.Fprintln(w, "whisper: wiring `whisper mcp` into your project MCP clients ✓")
	}
	var wrote []string
	for _, t := range targets {
		if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
			return fmt.Errorf("could not create %s: %w", filepath.Dir(t.path), err)
		}
		res, err := projcfg.MergeJSONServer(t.path, "mcpServers", "whisper", mcpServerEntry())
		if err != nil {
			return err
		}
		wrote = append(wrote, t.path)
		if !g.jsonOut && !g.quiet {
			verb := "updated"
			if res.Created {
				verb = "created"
			} else if res.Replaced {
				verb = "refreshed"
			}
			fmt.Fprintf(w, "  %s  %s\n", verb, relTo(root, t.path))
		}
	}

	if g.jsonOut {
		emitJSONValue(map[string]any{"wrote": wrote, "server": "whisper", "command": "whisper mcp"})
		return nil
	}
	if g.quiet {
		for _, p := range wrote {
			fmt.Fprintln(os.Stdout, p)
		}
		return nil
	}

	fmt.Fprint(w, mcpClientMatrix())
	return nil
}

// mcpClientMatrix is the verified copy-paste matrix for the clients we don't auto-edit. Paths and
// keys are the 2026-verified values (web-confirmed); we print rather than auto-write because each
// is JSONC or YAML or a per-OS global file where a blind edit could corrupt the user's config.
func mcpClientMatrix() string {
	return "" +
		"\nother clients — paste the snippet into the file shown (command on PATH: `whisper`):\n\n" +
		"  Cursor (global)        ~/.cursor/mcp.json                          → \"mcpServers\": { \"whisper\": {\"command\":\"whisper\",\"args\":[\"mcp\"]} }\n" +
		"  Windsurf               ~/.codeium/windsurf/mcp_config.json         → \"mcpServers\": { \"whisper\": {\"command\":\"whisper\",\"args\":[\"mcp\"]} }\n" +
		"  Claude Desktop (mac)   ~/Library/Application Support/Claude/claude_desktop_config.json → same \"mcpServers\" shape\n" +
		"  Claude Desktop (win)   %APPDATA%\\Claude\\claude_desktop_config.json → same \"mcpServers\" shape\n" +
		"  VS Code (project)      .vscode/mcp.json   (key is \"servers\", not mcpServers) → \"servers\": { \"whisper\": {\"type\":\"stdio\",\"command\":\"whisper\",\"args\":[\"mcp\"]} }\n" +
		"  Zed                    ~/.config/zed/settings.json (key \"context_servers\") → \"context_servers\": { \"whisper\": {\"command\":\"whisper\",\"args\":[\"mcp\"]} }\n" +
		"  Goose                  ~/.config/goose/config.yaml (YAML, key \"extensions\") — add a `whisper` extension running `whisper mcp`\n" +
		"  Continue               ~/.continue/config.yaml (YAML list \"mcpServers\") — add a `whisper` entry running `whisper mcp`\n" +
		"\nthen restart the client. Verify in-chat: ask it to run the `whisper_verify` tool.\n"
}

// --- JSON-RPC 2.0 wire types ---------------------------------------------------------------

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent ⇒ a notification (no response)
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpToolContent is one item of an MCP tool result (we only emit text).
type mcpToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content []mcpToolContent `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// runMCPServer is the stdio read/dispatch/write loop. It reads newline-delimited JSON-RPC
// messages, dispatches each, and writes one JSON response line per request (notifications get
// none). It returns nil on clean EOF (the client closed the pipe).
func runMCPServer(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate large tool args (Postel: liberal-accept)
	enc := json.NewEncoder(out)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req jsonrpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// Parse error — but only answer if it looked like a request with an id; a malformed
			// notification is dropped (can't address a response). Use a null id per JSON-RPC.
			writeResp(enc, jsonrpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &jsonrpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp, isNotification := dispatchMCP(req)
		if isNotification {
			continue // notifications get no response
		}
		writeResp(enc, resp)
	}
	return sc.Err()
}

func writeResp(enc *json.Encoder, r jsonrpcResponse) {
	// json.Encoder writes a trailing newline → newline-delimited framing, exactly what stdio MCP wants.
	_ = enc.Encode(r)
}

// dispatchMCP routes one request to its handler. The second return is true when the message was a
// notification (no id) and must not be answered.
func dispatchMCP(req jsonrpcRequest) (jsonrpcResponse, bool) {
	isNotification := len(req.ID) == 0
	resp := jsonrpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = mcpInitializeResult(req.Params)
	case "notifications/initialized", "notifications/cancelled":
		return resp, true // notifications — no reply
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		resp.Result = mcpCallTool(req.Params)
	default:
		if isNotification {
			return resp, true // unknown notification — ignore
		}
		resp.Error = &jsonrpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, isNotification
}

// mcpInitializeResult echoes the client's requested protocolVersion (or our default) and declares
// the tools capability + server identity.
func mcpInitializeResult(params json.RawMessage) map[string]any {
	version := mcpProtocolVersion
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 && json.Unmarshal(params, &p) == nil && strings.TrimSpace(p.ProtocolVersion) != "" {
		version = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": "whisper", "version": Version},
	}
}

// mcpTools is the static tool catalogue (keyless verify + RDAP).
func mcpTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "whisper_verify",
			"description": "Verify whether an address or FQDN is a real Whisper agent and, if so, whose — running the full keyless trust chain (reverse-DNS + DANE-EE TLSA pin + DNSSEC + JWS identity doc). Returns the verdict as JSON.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"required":             []string{"target"},
				"additionalProperties": false,
				"properties": map[string]any{
					"target": map[string]any{"type": "string", "description": "an IPv6 /128 address or an agent FQDN"},
				},
			},
		},
		{
			"name":        "whisper_rdap",
			"description": "Fetch the RDAP record for a Whisper IPv6 /128 (the IP-anchored registration object: who operates the agent identity). Returns RDAP JSON. Keyless.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"required":             []string{"ip"},
				"additionalProperties": false,
				"properties": map[string]any{
					"ip": map[string]any{"type": "string", "description": "an IPv6 /128 address"},
				},
			},
		},
	}
}

// mcpCallTool executes a tools/call. It never returns a JSON-RPC error for a tool failure — per
// MCP, a tool error is a normal result with isError:true so the model can see + react to it.
func mcpCallTool(params json.RawMessage) mcpToolResult {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return mcpErr("invalid tools/call params")
	}
	switch call.Name {
	case "whisper_verify":
		return mcpToolVerify(call.Arguments)
	case "whisper_rdap":
		return mcpToolRDAP(call.Arguments)
	default:
		return mcpErr("unknown tool: " + call.Name)
	}
}

func mcpToolVerify(args json.RawMessage) mcpToolResult {
	var a struct {
		Target string `json:"target"`
	}
	_ = json.Unmarshal(args, &a)
	if strings.TrimSpace(a.Target) == "" {
		return mcpErr("target is required (an IPv6 /128 or an agent FQDN)")
	}
	c, err := resolveClient(false, false) // keyless
	if err != nil {
		return mcpErr(err.Error())
	}
	cx, cancel := ctx()
	defer cancel()
	_, raw, _, err := c.VerifyIdentity(cx, a.Target)
	if err != nil {
		return mcpErr("verify failed: " + err.Error())
	}
	return mcpText(string(raw))
}

func mcpToolRDAP(args json.RawMessage) mcpToolResult {
	var a struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(args, &a)
	if strings.TrimSpace(a.IP) == "" {
		return mcpErr("ip is required (an IPv6 /128)")
	}
	c, err := resolveClient(false, false) // keyless
	if err != nil {
		return mcpErr(err.Error())
	}
	cx, cancel := ctx()
	defer cancel()
	raw, _, err := c.RDAP(cx, client.RDAPIP, a.IP, "")
	if err != nil {
		return mcpErr("rdap failed: " + err.Error())
	}
	return mcpText(string(raw))
}

func mcpText(s string) mcpToolResult {
	return mcpToolResult{Content: []mcpToolContent{{Type: "text", Text: s}}}
}

func mcpErr(msg string) mcpToolResult {
	return mcpToolResult{Content: []mcpToolContent{{Type: "text", Text: msg}}, IsError: true}
}
