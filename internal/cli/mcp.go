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

// mcp.go is `whisper mcp`: a Model Context Protocol server over stdio. An MCP
// client (Claude Desktop, Cursor, Windsurf, VS Code, Cline, Goose, …) spawns `whisper mcp` and
// talks newline-delimited JSON-RPC 2.0 on stdin/stdout. The tool surface is TWO-TIER, per the
// Robustness Principle:
//
//   - KEYLESS (always): verify an agent identity (DANE/DNSSEC/JWS) and fetch RDAP for a /128 —
//     "is this address a real Whisper agent, and whose?" in-chat, with NO API key and NO
//     dependency on the private control backend (the work is done by the public endpoints).
//   - KEY-GATED (when the standard key ladder resolves a credential — WHISPER_API_KEY /
//     WHISPER_KEY env, or the `whisper login` key file): the FULL control plane —
//     register / list / policy / logs / revoke / egress-config — every one a thin shell over
//     the SAME internal/client op paths the CLI subcommands use (no new protocol code).
//
// Without a key, only the two keyless tools are listed (graceful degradation, zero friction);
// with a key, the control half unlocks — auth is optional, never demanded. The MCP server
// itself cannot HOLD egress open (it is a stdio child of the client), so whisper_egress_config
// hands out the exact ready-to-run config `whisper connect`/`whisper init` use. The stdio
// transport keeps stdout for protocol bytes ONLY; all diagnostics go to stderr.

// mcpProtocolVersion is the MCP version we implement; we echo the client's requested version when
// it sends one (per the spec's negotiation), falling back to this.
const mcpProtocolVersion = "2024-11-05"

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a Model Context Protocol server (stdio): keyless verify/RDAP for all, full control tools with your API key",
		Long: "Start an MCP server on stdio so an MCP client (Claude Desktop, Cursor, Windsurf, VS Code,\n" +
			"Cline, Goose, …) can use Whisper in-chat. The tool surface is two-tier:\n\n" +
			"KEYLESS (always available — the verify/RDAP surface is public):\n" +
			"  • whisper_verify <address|fqdn>  — is it a real Whisper agent? (DANE + DNSSEC + JWS)\n" +
			"  • whisper_rdap <ipv6>            — RDAP for a Whisper /128 (who operates it)\n\n" +
			"WITH YOUR API KEY (WHISPER_API_KEY in the client's env, or `whisper login`):\n" +
			"  • whisper_register        — mint a named agent: name → routable IPv6 /128 identity\n" +
			"  • whisper_list            — your agents (name, /128, DNS name, state)\n" +
			"  • whisper_policy          — read or set your DNS resolver policy\n" +
			"  • whisper_logs            — recent per-agent DNS/conn/alloc activity\n" +
			"  • whisper_revoke          — tear an agent down (irreversible)\n" +
			"  • whisper_egress_config   — the ready-to-use proxy/env config for agent egress\n\n" +
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
		"\nthen restart the client. Verify in-chat: ask it to run the `whisper_verify` tool.\n" +
		"keyless verify/RDAP work as-is; with WHISPER_API_KEY in the client's env (or after\n" +
		"`whisper login`) the control tools — register/list/policy/logs/revoke/egress — unlock too.\n"
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

// mcpHasKey reports whether the standard key ladder resolves a credential (WHISPER_API_KEY /
// WHISPER_KEY env, --key, or the `whisper login` key file). It gates WHICH tools are listed:
// the keyless verify/RDAP pair always; the control tools only when a key is present — the
// two-tier surface mandates (keyless value for everyone, the full product for
// key-holders, auth optional).
func mcpHasKey() bool {
	c, err := resolveClient(false, false)
	return err == nil && !c.Credential().IsZero()
}

// mcpNoKeyErr is the helpful tool error a control tools/call gets when no key resolves —
// it names the exact fix (Postel: a clear error, never an opaque failure).
const mcpNoKeyErr = "this tool needs your Whisper API key — set WHISPER_API_KEY in the environment " +
	"your MCP client uses to launch `whisper mcp` (or run `whisper login` once on this machine), " +
	"then restart the client. The keyless whisper_verify / whisper_rdap tools work without a key."

// mcpTools is the tool catalogue: the keyless pair always, plus the key-gated control tools
// when a credential resolves (two-tier).
func mcpTools() []map[string]any {
	tools := []map[string]any{
		{
			"name":        "whisper_verify",
			"description": "Verify whether an address or FQDN is a real Whisper agent and, if so, whose — running the full keyless trust chain (reverse-DNS + DANE-EE TLSA pin + DNSSEC + JWS identity doc). Returns the verdict as JSON. Use it to check any peer's claimed identity before trusting it. No API key needed.",
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
			"description": "Fetch the RDAP record for a Whisper IPv6 /128 (the IP-anchored registration object: who operates the agent identity, since when, under which tenant). Returns RDAP JSON. Use it to look up ownership/registration facts about an address. No API key needed.",
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
	if mcpHasKey() {
		tools = append(tools, mcpControlTools()...)
	}
	return tools
}

// mcpControlTools is the key-gated half of the catalogue: the full control plane
// (register/list/policy/logs/revoke) plus the egress config — each a thin shell over the
// SAME internal/client op paths the CLI subcommands use. Descriptions are written for the
// LLM reading tools/list: they say exactly when and how to use each tool.
func mcpControlTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "whisper_register",
			"description": "Create (register) a new Whisper agent in YOUR tenant: give it a human name and receive its routable IPv6 /128 address plus DNS name — a real, verifiable network identity (reverse-DNS and RDAP resolve to it worldwide). Use this to give an agent or workload an identity before connecting it. Set with_key:true ONLY when the agent needs its OWN separate API key — that key appears ONCE in the result and can never be retrieved again, so store it immediately.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"required":             []string{"name"},
				"additionalProperties": false,
				"properties": map[string]any{
					"name":     map[string]any{"type": "string", "description": "the agent's human name (required — every agent has one), e.g. \"scout\""},
					"email":    map[string]any{"type": "string", "description": "optional public contact email (surfaced in RDAP)"},
					"with_key": map[string]any{"type": "boolean", "description": "mint the agent its OWN API key (shown once in the result). Default false: the agent lives under your key."},
				},
			},
		},
		{
			"name":        "whisper_list",
			"description": "List the agents in YOUR tenant — name, /128 address, DNS name, state, created. Call this first to discover what exists before registering, revoking, or fetching logs. kind can also be 'records' (DNS records) or 'identities'.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"kind": map[string]any{"type": "string", "enum": []string{"agents", "records", "identities"}, "description": "what to list (default: agents)"},
				},
			},
		},
		{
			"name":        "whisper_policy",
			"description": "Read or set YOUR tenant's DNS resolver policy (what your agents may resolve). Call with NO arguments to READ the current policy. To SET it, pass block and/or allow (lists of domain names) and/or default ('allow' or 'deny' — the action for names on no list).",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"block":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "domain names to block"},
					"allow":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "domain names to allow"},
					"default": map[string]any{"type": "string", "enum": []string{"allow", "deny"}, "description": "default action for unlisted names"},
				},
			},
		},
		{
			"name":        "whisper_logs",
			"description": "Query YOUR agents' recent activity — DNS queries (with allow/block decisions), connections, and allocations. Narrow with agent (an agent id or its /128 address from whisper_list), kind ('dns' | 'conn' | 'alloc'), a time window (from/to: epoch-ms, RFC-3339, or relative like '-1h'), and limit. Use this to audit what an agent actually did on the network.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"agent": map[string]any{"type": "string", "description": "narrow to one agent (id or /128 address)"},
					"kind":  map[string]any{"type": "string", "enum": []string{"dns", "conn", "alloc", "all"}, "description": "event kind (omit for all)"},
					"from":  map[string]any{"type": "string", "description": "window start (epoch-ms, RFC-3339, or relative like -1h)"},
					"to":    map[string]any{"type": "string", "description": "window end"},
					"limit": map[string]any{"type": "integer", "description": "max rows (default 1000, cap 10k)"},
				},
			},
		},
		{
			"name":        "whisper_revoke",
			"description": "IRREVERSIBLY revoke an agent: withdraw its /128 address, reverse-DNS, tokens, and (if it had one) its API key. The identity stops verifying immediately. Use whisper_list first to confirm the exact agent; there is no undo. Requires the agent id or its /128 address.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"required":             []string{"agent"},
				"additionalProperties": false,
				"properties": map[string]any{
					"agent": map[string]any{"type": "string", "description": "the agent id or its /128 address"},
				},
			},
		},
		{
			"name":        "whisper_egress_config",
			"description": "Get the ready-to-use egress configuration for running a workload FROM a Whisper agent's /128 address: the local proxy endpoints, the exact proxy environment block (the same .whisper/proxy.env that `whisper init` writes), and the `whisper connect` / `whisper run` commands that bring the tunnel up. The MCP server itself cannot hold a tunnel open — run the returned start command in the workload's environment. Pass agent to pin a specific identity, port to pin the local proxy port.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"agent": map[string]any{"type": "string", "description": "bind egress to this agent (id or /128); omit for your most recent agent"},
					"port":  map[string]any{"type": "integer", "description": "pin the local proxy port (default: a deterministic free port for this project)"},
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
	case "whisper_register":
		return mcpToolRegister(call.Arguments)
	case "whisper_list":
		return mcpToolList(call.Arguments)
	case "whisper_policy":
		return mcpToolPolicy(call.Arguments)
	case "whisper_logs":
		return mcpToolLogs(call.Arguments)
	case "whisper_revoke":
		return mcpToolRevoke(call.Arguments)
	case "whisper_egress_config":
		return mcpToolEgressConfig(call.Arguments)
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
	_, raw, status, err := c.VerifyIdentity(cx, a.Target)
	if err != nil {
		return mcpErr("verify failed: " + err.Error())
	}
	if status == 400 {
		// a 400 is malformed input, not a verdict — surface the server's own JSON
		// detail so the model can correct the target, never an opaque failure.
		return mcpErr(problemDetail(raw, fmt.Sprintf("verify-identity rejected %q (HTTP 400)", a.Target)))
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

// --- key-gated control tools -------------------------------------------------
//
// Every control tool is a thin shell over the SAME internal/client op path its CLI twin uses
// (whisper_register ↔ `whisper create [--register]`, whisper_list ↔ `whisper list`,
// whisper_policy ↔ `whisper policy`, whisper_logs ↔ `whisper logs`, whisper_revoke ↔
// `whisper kill --revoke`) — no new protocol code, one mechanism.

// mcpAgents runs one control-plane op (CALL whisper.agents({op,…})) through the standard
// client and folds the reply into an MCP tool result: a clear tool error for a missing key /
// transport fault / ok:false, else the result rows as column-keyed JSON records.
func mcpAgents(op string, args map[string]any) mcpToolResult {
	c, err := resolveClient(false, false)
	if err != nil {
		return mcpErr(err.Error())
	}
	if c.Credential().IsZero() {
		return mcpErr(mcpNoKeyErr)
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, op, args)
	if err != nil {
		return mcpErr(err.Error())
	}
	if perr := envelopeError(env); perr != nil {
		return mcpErr(friendly(perr))
	}
	return mcpRecords(env)
}

// mcpRecords renders a successful envelope as {"ok":true,"records":[{col:val,…},…]} — the
// LLM-friendly projection (no positional columns/rows zip to do), with no field loss: every
// column the server returned is present. This is the record shape the CLI's own renderers
// read; for op:register it carries the once-only api_key exactly as the CLI returns it.
func mcpRecords(env *client.Envelope) mcpToolResult {
	recs := env.Result.Records()
	if recs == nil {
		recs = []map[string]any{}
	}
	b, err := json.MarshalIndent(map[string]any{"ok": true, "records": recs}, "", "  ")
	if err != nil {
		return mcpErr("could not encode the control-plane result: " + err.Error())
	}
	return mcpText(string(b))
}

// mcpToolRegister mints a NAMED agent (§3.2 — never an unnamed one): op:identity by default
// (the agent lives under the caller's key, mirroring `whisper create`), op:register when
// with_key is set (a NEW agent with its OWN once-shown API key, mirroring
// `whisper create --register`).
func mcpToolRegister(args json.RawMessage) mcpToolResult {
	var a struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		WithKey bool   `json:"with_key"`
	}
	_ = json.Unmarshal(args, &a)
	name := strings.TrimSpace(a.Name)
	if name == "" {
		return mcpErr("name is required — every Whisper agent has a human name (e.g. \"scout\")")
	}
	op := "identity"
	if a.WithKey {
		op = "register"
	}
	wire := map[string]any{"label": name}
	if e := strings.TrimSpace(a.Email); e != "" {
		wire["contact_email"] = e
	}
	return mcpAgents(op, wire)
}

func mcpToolList(args json.RawMessage) mcpToolResult {
	var a struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(args, &a)
	kind := strings.TrimSpace(a.Kind)
	if kind == "" {
		kind = "agents"
	}
	return mcpAgents("list", map[string]any{"kind": kind})
}

// mcpToolPolicy mirrors the CLI verb semantics exactly: no arguments READS the current
// policy back; block/allow/default SET it (op:policy either way).
func mcpToolPolicy(args json.RawMessage) mcpToolResult {
	var a struct {
		Block   []string `json:"block"`
		Allow   []string `json:"allow"`
		Default string   `json:"default"`
	}
	_ = json.Unmarshal(args, &a)
	wire := map[string]any{}
	if len(a.Block) > 0 {
		wire["block"] = toAnySlice(a.Block)
	}
	if len(a.Allow) > 0 {
		wire["allow"] = toAnySlice(a.Allow)
	}
	if d := strings.TrimSpace(a.Default); d != "" {
		wire["default"] = d
	}
	return mcpAgents("policy", wire)
}

func mcpToolLogs(args json.RawMessage) mcpToolResult {
	var a struct {
		Agent string `json:"agent"`
		Kind  string `json:"kind"`
		From  string `json:"from"`
		To    string `json:"to"`
		Limit int    `json:"limit"`
	}
	_ = json.Unmarshal(args, &a)
	wire := map[string]any{}
	if v := strings.TrimSpace(a.Agent); v != "" {
		wire["agent"] = v
	}
	if v := strings.TrimSpace(a.Kind); v != "" {
		wire["kind"] = v
	}
	if v := strings.TrimSpace(a.From); v != "" {
		wire["from"] = v
	}
	if v := strings.TrimSpace(a.To); v != "" {
		wire["to"] = v
	}
	if a.Limit > 0 {
		wire["limit"] = a.Limit
	}
	return mcpAgents("logs", wire)
}

func mcpToolRevoke(args json.RawMessage) mcpToolResult {
	var a struct {
		Agent string `json:"agent"`
	}
	_ = json.Unmarshal(args, &a)
	target := strings.TrimSpace(a.Agent)
	if target == "" {
		return mcpErr("agent is required (the agent id or its /128 address) — call whisper_list to find it")
	}
	// The tools/call itself is the confirmation (the model + its human decided); op:revoke is
	// the same full-teardown path `whisper kill --revoke` uses.
	return mcpAgents("revoke", map[string]any{"agent": target})
}

// mcpToolEgressConfig hands out the READY-TO-USE egress config for an agent — the exact
// strings `whisper connect`/`whisper init` emit (the proxy_env block IS the .whisper/proxy.env
// bytes, via projcfg.ProxyEnvContent) — because a stdio MCP child cannot hold a tunnel open
// itself. Key-gated: the config is only actionable with a key (`whisper connect` needs one).
func mcpToolEgressConfig(args json.RawMessage) mcpToolResult {
	var a struct {
		Agent string `json:"agent"`
		Port  int    `json:"port"`
	}
	_ = json.Unmarshal(args, &a)
	if !mcpHasKey() {
		return mcpErr(mcpNoKeyErr)
	}
	port := a.Port
	if port <= 0 {
		// The same deterministic, collision-avoiding project port `whisper init` picks.
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "whisper-mcp"
		}
		p, perr := projcfg.ProbeFreePort(cwd)
		if perr != nil {
			return mcpErr(perr.Error())
		}
		port = p
	}
	start := fmt.Sprintf("whisper connect --port %d", port)
	if agent := strings.TrimSpace(a.Agent); agent != "" {
		start = fmt.Sprintf("whisper connect --agent %s --port %d", agent, port)
	}
	out := map[string]any{
		"proxy_http":   fmt.Sprintf("http://127.0.0.1:%d", port),
		"proxy_socks5": fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"proxy_env":    string(projcfg.ProxyEnvContent(port)),
		"start":        start + "   # brings the tunnel up and holds it (Ctrl-C to stop)",
		"one_shot":     "whisper run <command>   # run ONE command with egress, no held-open terminal",
		"verify":       "whisper run curl -s https://api64.ipify.org   # prints the agent's /128 when egress is live",
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return mcpErr("could not encode the egress config: " + err.Error())
	}
	return mcpText(string(b))
}

func mcpText(s string) mcpToolResult {
	return mcpToolResult{Content: []mcpToolContent{{Type: "text", Text: s}}}
}

func mcpErr(msg string) mcpToolResult {
	return mcpToolResult{Content: []mcpToolContent{{Type: "text", Text: msg}}, IsError: true}
}
