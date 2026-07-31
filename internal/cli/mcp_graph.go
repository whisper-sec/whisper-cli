// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// mcp_graph.go is the GRAPH half of the MCP tool surface: one whisper_<camelId>
// tool per embedded catalog recipe (direct recipes run their Cypher against the
// public graph endpoint; flow recipes run by slug via the console gallery/run SSE
// endpoint) plus whisper_graph_query for raw parameterised Cypher. The graph is a
// keyed surface, so like the control tools these list only when a key resolves.
// Every description ends with the recipe's docs URL (docsBase + docPath).

// mcpFlowCap bounds one flow run inside a tools/call (an MCP call is one
// request/response, so the stream is collected; a flow walks many steps).
const mcpFlowCap = 3 * time.Minute

// mcpGraphQueryToolName is the raw-Cypher tool.
const mcpGraphQueryToolName = "whisper_graph_query"

// mcpGraphTools builds the graph tool catalogue: raw Cypher first, then every
// catalog recipe as whisper_<camelId>.
func mcpGraphTools() []map[string]any {
	tools := []map[string]any{
		{
			"name": mcpGraphQueryToolName,
			"description": "Run raw parameterised Cypher against the whisper.security graph (7.4B nodes / " +
				"39B relationships: hostnames, IPs, ASNs, certs, threat intel) and get {columns,rows} back - rows are objects " +
				"keyed by column name. Reference parameters as $name in the query and pass them in params. " +
				"Prefer the named whisper_* recipe tools for their questions; use this for everything else. " +
				"Docs: " + catalog.RawCypherDocsURL(),
			"inputSchema": map[string]any{
				"type":                 "object",
				"required":             []string{"query"},
				"additionalProperties": false,
				"properties": map[string]any{
					"query":  map[string]any{"type": "string", "description": "the Cypher statement, e.g. CALL whisper.identify(['api.openai.com'])"},
					"params": map[string]any{"type": "object", "description": "query parameters, referenced as $name in the query"},
				},
			},
		},
	}
	for _, e := range catalog.All() {
		tools = append(tools, mcpGraphRecipeTool(e))
	}
	return tools
}

// mcpGraphRecipeTool renders one catalog entry as an MCP tool definition, its
// inputSchema generated from the catalog inputs (wire paramName as the property
// key, enums for selects, catalog defaults) and its description ending with the
// docs URL so the model can cite the recipe's documentation.
func mcpGraphRecipeTool(e catalog.Entry) map[string]any {
	var d strings.Builder
	d.WriteString(e.Purpose)
	if e.Why != "" {
		d.WriteString(" ")
		d.WriteString(e.Why)
	}
	if !e.IsDirect() {
		d.WriteString(" Multi-step flow: the result streams as step events and can take a minute.")
	}
	d.WriteString(" Docs: ")
	d.WriteString(e.DocsURL())

	props := map[string]any{}
	var required []string
	for _, in := range e.Inputs {
		prop := map[string]any{"type": jsonSchemaType(in.Kind)}
		desc := in.ID
		if len(in.Examples) > 0 {
			parts := make([]string, 0, len(in.Examples))
			for _, ex := range in.Examples {
				parts = append(parts, fmt.Sprintf("%v", ex))
			}
			desc += " (e.g. " + strings.Join(parts, ", ") + ")"
		}
		prop["description"] = desc
		if in.Default != nil {
			prop["default"] = in.Default
		}
		if len(in.Options) > 0 {
			prop["enum"] = in.Options
		}
		props[in.ParamName] = prop
		if in.Default == nil && !in.Optional {
			required = append(required, in.ParamName)
		}
	}
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"name":        e.ToolName(),
		"description": d.String(),
		"inputSchema": map[string]any{
			"type":       "object",
			"required":   required,
			"properties": props,
		},
	}
}

// jsonSchemaType maps a catalog input kind to its JSON-schema type (everything but
// an explicit number is a string on this wire).
func jsonSchemaType(kind string) string {
	if kind == "number" {
		return "number"
	}
	return "string"
}

// mcpGraphCall routes a graph tools/call: raw Cypher, or a recipe by tool name
// (liberal: whisper_<camelId>, the bare id, any case). ok=false means the name is
// not a graph tool and the caller should keep dispatching.
func mcpGraphCall(name string, args json.RawMessage) (mcpToolResult, bool) {
	if name == mcpGraphQueryToolName {
		return mcpToolGraphQuery(args), true
	}
	e, found := catalog.Find(name)
	if !found {
		return mcpToolResult{}, false
	}
	return mcpToolGraphRecipe(e, args), true
}

// mcpGraphClient resolves the keyed client every graph tool needs, with the same
// helpful no-key guidance the control tools give.
func mcpGraphClient() (*client.Client, mcpToolResult, bool) {
	c, err := resolveClient(false, false)
	if err != nil {
		return nil, mcpErr(err.Error()), false
	}
	if c.Credential().IsZero() {
		return nil, mcpErr(mcpNoKeyErr), false
	}
	return c, mcpToolResult{}, true
}

// mcpToolGraphQuery runs raw parameterised Cypher and returns the graph endpoint's
// verbatim {columns,rows,statistics} JSON (already the LLM-friendly shape).
func mcpToolGraphQuery(args json.RawMessage) mcpToolResult {
	var a struct {
		Query  string         `json:"query"`
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(args, &a)
	if strings.TrimSpace(a.Query) == "" {
		return mcpErr("query is required - a Cypher statement, e.g. CALL whisper.identify(['api.openai.com'])")
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, a.Query, a.Params)
	if err != nil {
		return mcpErr(friendly(err))
	}
	return mcpText(string(res.Raw))
}

// mcpToolGraphRecipe executes one catalog recipe: args are matched to the catalog
// inputs (by wire paramName, or liberally by input id), missing ones take the
// catalog default. Direct recipes return the verbatim {columns,rows} reply; flow
// recipes collect the SSE stream and return the events as one JSON array.
func mcpToolGraphRecipe(e catalog.Entry, args json.RawMessage) mcpToolResult {
	given := map[string]any{}
	_ = json.Unmarshal(args, &given)
	inputs := map[string]any{}
	for _, in := range e.Inputs {
		if v, ok := given[in.ParamName]; ok {
			inputs[in.ParamName] = v
			continue
		}
		if v, ok := given[in.ID]; ok && in.ID != in.ParamName {
			inputs[in.ParamName] = v // liberal-in: the catalog input id also addresses it
			continue
		}
		if in.Default != nil {
			inputs[in.ParamName] = in.Default
			continue
		}
		if !in.Optional {
			return mcpErr(fmt.Sprintf("%s needs the %q input - see %s", e.ID, in.ParamName, e.DocsURL()))
		}
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}

	if e.IsDirect() {
		cx, cancel := ctx()
		defer cancel()
		res, err := c.GraphQuery(cx, e.Exec.Cypher, inputs)
		if err != nil {
			return mcpErr(friendly(err))
		}
		return mcpText(string(res.Raw))
	}

	// A flow: collect the SSE stream (an MCP call is one request/response).
	cx, cancel := context.WithTimeout(context.Background(), mcpFlowCap)
	defer cancel()
	value, paramValues := flowValueAndParams(e, inputs, nil)
	events := []map[string]json.RawMessage{}
	err := c.RunFlow(cx, g.consoleURL, e.ID, value, paramValues, func(ev client.FlowEvent) {
		data := ev.Data
		if !json.Valid(data) {
			data = mustJSONString(string(data))
		}
		events = append(events, map[string]json.RawMessage{
			"event": mustJSONString(ev.Event),
			"data":  data,
		})
	})
	if err != nil && cx.Err() != context.DeadlineExceeded {
		return mcpErr(friendly(err))
	}
	out := map[string]any{"ok": err == nil, "flow": e.ID, "events": events, "docs": e.DocsURL()}
	if cx.Err() == context.DeadlineExceeded {
		out["truncated"] = fmt.Sprintf("the stream was cut at %s; events up to that point are included", mcpFlowCap)
	}
	b, merr := json.Marshal(out)
	if merr != nil {
		return mcpErr("could not encode the flow result: " + merr.Error())
	}
	return mcpText(string(b))
}
