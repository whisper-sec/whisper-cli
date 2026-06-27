// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
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
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run a Model Context Protocol server (stdio) exposing Whisper's keyless verify/RDAP tools",
		Long: "Start an MCP server on stdio so an MCP client (Claude Desktop, Cursor, Windsurf, VS Code,\n" +
			"Cline, Goose, …) can call Whisper's KEYLESS trust tools in-chat:\n" +
			"  • whisper_verify <address|fqdn>  — is it a real Whisper agent? (DANE + DNSSEC + JWS)\n" +
			"  • whisper_rdap <ipv6>            — RDAP for a Whisper /128 (who operates it)\n\n" +
			"No API key is needed (the verify/RDAP surface is public). This is identity/verify in-chat,\n" +
			"not host egress — for egress use `whisper init` / `whisper run`.\n\n" +
			"Configure your client to run `whisper mcp` as a stdio MCP server.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCPServer(os.Stdin, os.Stdout)
		},
	}
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
