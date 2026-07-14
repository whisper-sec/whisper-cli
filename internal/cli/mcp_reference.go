// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// mcp_reference.go mirrors the whisper.security reference MCP server's cypher surface
// (the public whisper-ai server at mcp.whisper.security) inside `whisper mcp`, so an
// agent gets the SAME named tools, resources, and prompts here as there:
//
//   TOOLS   query, explain_indicator, explain_schema, read_docs, list_workflows,
//           run_workflow, text2cypher
//   RESOURCES  whisper://schema/full, whisper://stats, whisper://quota, whisper://server
//   PROMPTS    one gallery-driven investigation prompt per catalog workflow
//
// The cypher tools + graph-backed resources are keyed (X-API-Key); read_docs, the
// server descriptor, and prompt discovery are keyless (public). Every tool description
// ends with a docs link, matching the reference server. Handlers back onto the SAME
// public endpoints the reference server uses (the graph /api/query, its /stats
// companion, the console gallery/run stream, the text2cypher translator, and the
// whisper.security docs) - never a backend internal.

// mcpDocsToolName etc.: the reference tool names, kept verbatim so an agent that knows
// the whisper-ai MCP finds the identical tool here.
const (
	mcpQueryToolName            = "query"
	mcpExplainIndicatorToolName = "explain_indicator"
	mcpExplainSchemaToolName    = "explain_schema"
	mcpReadDocsToolName         = "read_docs"
	mcpListWorkflowsToolName    = "list_workflows"
	mcpRunWorkflowToolName      = "run_workflow"
	mcpText2CypherToolName      = "text2cypher"
)

// mcpReferenceTools returns the whisper-ai-mirrored tool definitions (the keyed cypher
// surface). read_docs is keyless-capable but, like the rest of the graph surface, it is
// only advertised alongside a resolved key so the keyless tier stays exactly
// verify/rdap (the established two-tier boundary).
func mcpReferenceTools() []map[string]any {
	graphDocs := catalog.RawCypherDocsURL()
	return []map[string]any{
		{
			"name": mcpQueryToolName,
			"description": "Execute a Cypher query against WhisperGraph - the internet's largest infrastructure " +
				"graph (hostnames, IPs, prefixes, ASNs, DNS, BGP, WHOIS, TLS, threat intel). Returns " +
				"{columns, rows, statistics}; rows are objects keyed by column name. Anchor on {name: \"value\"} " +
				"or bind $params. READ-ONLY. Use this for single-fact lookups and to finish/cross-check a " +
				"workflow; for multi-step investigations prefer list_workflows + run_workflow. Docs: " + graphDocs,
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"cypher"},
				"properties": map[string]any{
					"cypher": map[string]any{"type": "string", "description": "the Cypher statement (e.g. MATCH (h:HOSTNAME {name:$h})-[:RESOLVES_TO]->(ip:IPV4) RETURN ip.name)"},
					"params": map[string]any{"type": "object", "description": "bound parameters referenced as $name in the query"},
				},
			},
		},
		{
			"name": mcpExplainIndicatorToolName,
			"description": "One-call threat assessment for a single indicator - an IPv4, IPv6, hostname, CIDR " +
				"network, or ASN (auto-detected). Returns a structured verdict: score, level " +
				"(NONE/INFO/LOW/MEDIUM/HIGH/CRITICAL), explanation, factors[], and sources[]. A NONE/clean " +
				"result means \"not listed\", not \"safe\" - no-data is not benign. Prefer this over manual " +
				"ASN->PREFIX->IP->LISTED_IN walks (those time out on large networks). Docs: " + graphDocs,
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"indicator"},
				"properties": map[string]any{
					"indicator": map[string]any{"type": "string", "description": "IPv4 / IPv6 / hostname / CIDR / ASN, e.g. \"185.220.101.1\", \"google.com\", \"3.64.0.0/12\", \"AS13335\""},
				},
			},
		},
		{
			"name": mcpExplainSchemaToolName,
			"description": "Describe WhisperGraph's schema - what an entity is and how it connects. Call with NO " +
				"argument for the full label catalog (every node label + count). Call WITH a label (e.g. " +
				"{\"label\":\"IPV4\"}) for that label's entity card: its properties and its inbound/outbound " +
				"edges with directions + target labels. Use it to rule out hallucinated labels (there is no " +
				"DOMAIN/FQDN - only HOSTNAME) before you traverse. Docs: " + graphDocs,
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"label": map[string]any{"type": "string", "description": "optional node label for the entity card (e.g. HOSTNAME, IPV4, ASN); omit for the label catalog"},
				},
			},
		},
		{
			"name": mcpReadDocsToolName,
			"description": "Read whisper.security documentation on demand - the canonical Cypher, schema, recipe, " +
				"and reference guides. Three modes: no argument lists the available pages; {\"query\":\"rpki\"} " +
				"searches pages by keyword; {\"path\":\"reference/graph-schema\"} fetches that page's markdown. " +
				"Only indexed whisper.security/docs pages are served (path is index-relative, never a URL). " +
				"No API key needed. Docs: " + catalog.DocsBase() + "/docs",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "optional keyword search over doc titles/sections/summaries/paths"},
					"path":  map[string]any{"type": "string", "description": "optional index-relative doc path to fetch (e.g. \"reference/graph-schema\")"},
				},
			},
		},
		{
			"name": mcpListWorkflowsToolName,
			"description": "List or search the gallery of ready-made investigations (workflows) and recipes you " +
				"can run with run_workflow - so a multi-step investigation is ONE call instead of many " +
				"hand-written queries. CALL THIS FIRST for attack-surface, footprint, recon, domain/ASN/IP/" +
				"prefix profiling, DNS & email posture, BGP/RPKI health, and takeover checks. Returns each " +
				"item's slug, kind (workflow|recipe), title, summary, its inputs, and its tunable params. " +
				"Filter with keyword and/or kind. Docs: " + catalog.DocsBase() + "/docs",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"keyword": map[string]any{"type": "string", "description": "case-insensitive substring over slug/title/summary"},
					"kind":    map[string]any{"type": "string", "enum": []string{"workflow", "recipe"}, "description": "workflow (multi-step flow) or recipe (single direct call); omit for both"},
				},
			},
		},
		{
			"name": mcpRunWorkflowToolName,
			"description": "Run one or more gallery workflows/recipes by slug and return their results - " +
				"collapsing a whole investigation (resolve -> pivot -> enrich -> score) into a single call. " +
				"A workflow streams multi-step evidence; a recipe returns one result table. Discover slugs and " +
				"their params with list_workflows; finish or cross-check a surprising result with the query " +
				"tool. NO EVIDENCE, NO CLAIM: cite each step's cypher + row count. Docs: " + catalog.DocsBase() + "/docs",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":   map[string]any{"type": "string", "description": "a single workflow/recipe slug (from list_workflows), e.g. \"attack-surface\", \"identify\""},
					"input":  map[string]any{"type": "string", "description": "the primary entity, e.g. \"google.com\", \"AS13335\", \"8.8.8.0/24\""},
					"params": map[string]any{"type": "object", "description": "tuning params by name (e.g. {\"level\":\"deep\"}) and any secondary inputs"},
					"runs": map[string]any{
						"type":        "array",
						"description": "batch: run several {slug, input, params} together in one call (alternative to the single slug/input)",
						"items": map[string]any{
							"type":     "object",
							"required": []string{"slug"},
							"properties": map[string]any{
								"slug":   map[string]any{"type": "string"},
								"input":  map[string]any{"type": "string"},
								"params": map[string]any{"type": "object"},
							},
						},
					},
				},
			},
		},
		{
			"name": mcpText2CypherToolName,
			"description": "Translate a natural-language question into a validated Cypher query against " +
				"WhisperGraph (and optionally execute it). Returns {cypher, explanation, confidence, " +
				"validationPassed, ...} - and, with execute:true, the query result too. Use it to draft a query " +
				"from an English question, then refine or run it with the query tool. Docs: " + graphDocs,
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"question"},
				"properties": map[string]any{
					"question": map[string]any{"type": "string", "description": "the question in English, e.g. \"What IPs does google.com resolve to?\""},
					"execute":  map[string]any{"type": "boolean", "description": "also run the generated Cypher and return its rows (default false)"},
					"provider": map[string]any{"type": "string", "description": "optional LLM provider hint (openai | xai | anthropic); default auto"},
					"fast":     map[string]any{"type": "boolean", "description": "use the faster/cheaper model (default false)"},
				},
			},
		},
	}
}

// mcpReferenceCall dispatches a reference tools/call by name. ok=false means the name
// is not a reference tool and the caller should keep dispatching.
func mcpReferenceCall(name string, args json.RawMessage) (mcpToolResult, bool) {
	switch name {
	case mcpQueryToolName:
		return mcpToolQuery(args), true
	case mcpExplainIndicatorToolName:
		return mcpToolExplainIndicator(args), true
	case mcpExplainSchemaToolName:
		return mcpToolExplainSchema(args), true
	case mcpReadDocsToolName:
		return mcpToolReadDocs(args), true
	case mcpListWorkflowsToolName:
		return mcpToolListWorkflows(args), true
	case mcpRunWorkflowToolName:
		return mcpToolRunWorkflow(args), true
	case mcpText2CypherToolName:
		return mcpToolText2Cypher(args), true
	default:
		return mcpToolResult{}, false
	}
}

// mcpToolQuery runs raw parameterised Cypher (the reference `query` tool). Liberal-in:
// accepts the cypher under `cypher` (whisper-ai canonical) or `query`.
func mcpToolQuery(args json.RawMessage) mcpToolResult {
	var a struct {
		Cypher string         `json:"cypher"`
		Query  string         `json:"query"`
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(args, &a)
	cypher := strings.TrimSpace(a.Cypher)
	if cypher == "" {
		cypher = strings.TrimSpace(a.Query)
	}
	if cypher == "" {
		return mcpErr("cypher is required - a Cypher statement, e.g. MATCH (h:HOSTNAME {name:$h})-[:RESOLVES_TO]->(ip:IPV4) RETURN ip.name")
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, cypher, a.Params)
	if err != nil {
		return mcpErr(friendly(err))
	}
	return mcpText(string(res.Raw))
}

// mcpToolExplainIndicator runs CALL explain($indicator) - the one-call threat verdict.
func mcpToolExplainIndicator(args json.RawMessage) mcpToolResult {
	var a struct {
		Indicator string `json:"indicator"`
	}
	_ = json.Unmarshal(args, &a)
	indicator := strings.TrimSpace(a.Indicator)
	if indicator == "" {
		return mcpErr("indicator is required (an IPv4 / IPv6 / hostname / CIDR / ASN)")
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, "CALL explain($indicator)", map[string]any{"indicator": indicator})
	if err != nil {
		return mcpErr(friendly(err))
	}
	return mcpText(string(res.Raw))
}

// mcpToolExplainSchema returns the label catalog (no argument) or one label's entity
// card (properties + inbound/outbound edges), synthesised from the live db.schema.
func mcpToolExplainSchema(args json.RawMessage) mcpToolResult {
	var a struct {
		Label string `json:"label"`
	}
	_ = json.Unmarshal(args, &a)
	label := strings.TrimSpace(a.Label)
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	cx, cancel := ctx()
	defer cancel()
	if label == "" {
		res, err := c.GraphQuery(cx, "CALL db.labels()", nil)
		if err != nil {
			return mcpErr(friendly(err))
		}
		return mcpText(string(res.Raw))
	}
	res, err := c.GraphQuery(cx, `CALL db.schema("json")`, nil)
	if err != nil {
		return mcpErr(friendly(err))
	}
	card, err := schemaCard(res, label)
	if err != nil {
		return mcpErr(err.Error())
	}
	b, _ := json.MarshalIndent(card, "", "  ")
	return mcpText(string(b))
}

// schemaCard extracts a single label's entity card from a db.schema("json") result:
// its node record (count, virtual, properties) plus the edges that touch it, split
// into outbound (label on the source side) and inbound (label on the target side).
func schemaCard(res *client.GraphResult, label string) (map[string]any, error) {
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("schema introspection returned no rows")
	}
	rawSchema, _ := res.Rows[0]["schema"].(string)
	if rawSchema == "" {
		return nil, fmt.Errorf("schema introspection returned an unexpected shape")
	}
	var schema struct {
		Nodes []struct {
			Label      string           `json:"label"`
			Count      any              `json:"count"`
			Virtual    bool             `json:"virtual"`
			Properties []map[string]any `json:"properties"`
		} `json:"nodes"`
		Relationships []struct {
			Type    string   `json:"type"`
			Source  []string `json:"source"`
			Target  []string `json:"target"`
			Count   any      `json:"count"`
			Virtual bool     `json:"virtual"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal([]byte(rawSchema), &schema); err != nil {
		return nil, fmt.Errorf("could not parse the live schema: %v", err)
	}
	want := strings.ToUpper(label)
	card := map[string]any{"label": want}
	found := false
	for _, n := range schema.Nodes {
		if strings.EqualFold(n.Label, want) {
			card["count"] = n.Count
			card["virtual"] = n.Virtual
			card["properties"] = n.Properties
			found = true
			break
		}
	}
	if !found {
		var labels []string
		for _, n := range schema.Nodes {
			labels = append(labels, n.Label)
		}
		sort.Strings(labels)
		return nil, fmt.Errorf("no label %q in the schema - known labels: %s", want, strings.Join(labels, ", "))
	}
	var outbound, inbound []map[string]any
	for _, r := range schema.Relationships {
		if containsFold(r.Source, want) {
			outbound = append(outbound, map[string]any{"type": r.Type, "to": r.Target})
		}
		if containsFold(r.Target, want) {
			inbound = append(inbound, map[string]any{"type": r.Type, "from": r.Source})
		}
	}
	card["outbound"] = outbound
	card["inbound"] = inbound
	return card, nil
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// mcpToolReadDocs lists, searches, or fetches whisper.security documentation (keyless).
func mcpToolReadDocs(args json.RawMessage) mcpToolResult {
	var a struct {
		Query string `json:"query"`
		Path  string `json:"path"`
	}
	_ = json.Unmarshal(args, &a)
	path := strings.TrimSpace(a.Path)
	query := strings.TrimSpace(a.Query)

	// Fetch mode: an index-relative path -> that page's markdown.
	if path != "" {
		d, ok := catalog.DocByPath(path)
		if !ok {
			return mcpErr(fmt.Sprintf("no doc page %q in the index - call read_docs with no argument to list the available paths", path))
		}
		c, err := resolveClient(false, false) // keyless: the docs are public
		if err != nil {
			return mcpErr(err.Error())
		}
		cx, cancel := ctx()
		defer cancel()
		md, err := c.FetchDoc(cx, catalog.DocURL(d.Path))
		if err != nil {
			return mcpErr(friendly(err))
		}
		out := map[string]any{"path": d.Path, "title": d.Title, "section": d.Section, "markdown": md}
		b, _ := json.MarshalIndent(out, "", "  ")
		return mcpText(string(b))
	}

	// List / search mode: return the index (optionally keyword-filtered).
	entries := catalog.SearchDocs(query)
	list := make([]map[string]any, 0, len(entries))
	for _, d := range entries {
		list = append(list, map[string]any{"path": d.Path, "title": d.Title, "section": d.Section, "summary": d.Summary})
	}
	out := map[string]any{"docs": list, "count": len(list)}
	b, _ := json.MarshalIndent(out, "", "  ")
	return mcpText(string(b))
}

// mcpToolListWorkflows lists/searches the embedded gallery catalog (local data - no key
// needed). Each entry carries its slug, kind, title, summary, inputs, params, and docs.
func mcpToolListWorkflows(args json.RawMessage) mcpToolResult {
	var a struct {
		Keyword string `json:"keyword"`
		Kind    string `json:"kind"`
	}
	_ = json.Unmarshal(args, &a)
	kw := strings.ToLower(strings.TrimSpace(a.Keyword))
	kind := strings.ToLower(strings.TrimSpace(a.Kind))

	list := make([]map[string]any, 0)
	for _, e := range catalog.All() {
		k := "recipe"
		if !e.IsDirect() {
			k = "workflow"
		}
		if kind != "" && kind != k {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(e.ID+" "+e.Title+" "+e.Purpose), kw) {
			continue
		}
		inputs := make([]map[string]any, 0, len(e.Inputs))
		for _, in := range e.Inputs {
			im := map[string]any{"id": in.ID, "kind": in.Kind, "required": in.Default == nil && !in.Optional}
			if in.Default != nil {
				im["default"] = in.Default
			}
			if len(in.Examples) > 0 {
				im["examples"] = in.Examples
			}
			inputs = append(inputs, im)
		}
		params := make([]map[string]any, 0, len(e.Params))
		for _, p := range e.Params {
			pm := map[string]any{"name": p.Name, "kind": p.Kind}
			if p.Default != nil {
				pm["default"] = p.Default
			}
			if len(p.Options) > 0 {
				pm["options"] = p.Options
			}
			params = append(params, pm)
		}
		list = append(list, map[string]any{
			"slug": e.ID, "kind": k, "title": e.Title, "summary": e.Purpose,
			"inputs": inputs, "params": params, "docs": e.DocsURL(),
		})
	}
	out := map[string]any{"workflows": list, "count": len(list)}
	b, _ := json.MarshalIndent(out, "", "  ")
	return mcpText(string(b))
}

// mcpRunSpec is one {slug, input, params} run for run_workflow.
type mcpRunSpec struct {
	Slug   string         `json:"slug"`
	Input  string         `json:"input"`
	Params map[string]any `json:"params"`
}

// mcpToolRunWorkflow runs one or more gallery workflows/recipes by slug. A recipe
// (direct) returns its result table; a workflow (flow) collects its step-event stream.
func mcpToolRunWorkflow(args json.RawMessage) mcpToolResult {
	var a struct {
		Slug   string         `json:"slug"`
		Input  string         `json:"input"`
		Params map[string]any `json:"params"`
		Runs   []mcpRunSpec   `json:"runs"`
	}
	_ = json.Unmarshal(args, &a)
	runs := a.Runs
	if len(runs) == 0 {
		if strings.TrimSpace(a.Slug) == "" {
			return mcpErr("slug is required (a workflow/recipe slug from list_workflows), or pass runs:[{slug,input,params}]")
		}
		runs = []mcpRunSpec{{Slug: a.Slug, Input: a.Input, Params: a.Params}}
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	results := make([]map[string]any, 0, len(runs))
	for _, r := range runs {
		results = append(results, runOneWorkflow(c, r))
	}
	out := map[string]any{"results": results}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return mcpErr("could not encode the run result: " + err.Error())
	}
	return mcpText(string(b))
}

// runOneWorkflow executes a single slug. Known direct recipe -> its Cypher; known flow
// (or an unknown slug, treated liberally as a live gallery slug) -> the SSE stream.
func runOneWorkflow(c *client.Client, r mcpRunSpec) map[string]any {
	slug := strings.TrimSpace(r.Slug)
	if slug == "" {
		return map[string]any{"success": false, "error": "empty slug"}
	}
	e, found := catalog.Find(slug)
	if found && e.IsDirect() {
		params := map[string]any{}
		for k, v := range r.Params {
			params[k] = v
		}
		if in := primaryInput(e); in != "" && strings.TrimSpace(r.Input) != "" {
			params[in] = r.Input
		}
		cx, cancel := ctx()
		defer cancel()
		res, err := c.GraphQuery(cx, e.Exec.Cypher, params)
		if err != nil {
			return map[string]any{"slug": e.ID, "kind": "recipe", "success": false, "error": friendly(err)}
		}
		var rows any
		_ = json.Unmarshal(res.Raw, &rows)
		return map[string]any{"slug": e.ID, "kind": "recipe", "success": true, "result": rows, "docs": e.DocsURL()}
	}

	// A flow (or an unknown slug run liberally against the live gallery): collect the stream.
	flowSlug := slug
	docs := catalog.DocsBase() + "/docs"
	paramValues := map[string]any{}
	for k, v := range r.Params {
		paramValues[k] = v
	}
	if found {
		flowSlug = e.ID
		docs = e.DocsURL()
	}
	cx, cancel := context.WithTimeout(context.Background(), mcpFlowCap)
	defer cancel()
	events := []map[string]json.RawMessage{}
	err := c.RunFlow(cx, g.consoleURL, flowSlug, strings.TrimSpace(r.Input), paramValues, func(ev client.FlowEvent) {
		data := ev.Data
		if !json.Valid(data) {
			data = mustJSONString(string(data))
		}
		events = append(events, map[string]json.RawMessage{"event": mustJSONString(ev.Event), "data": data})
	})
	out := map[string]any{"slug": flowSlug, "kind": "workflow", "success": err == nil, "events": events, "docs": docs}
	if err != nil && cx.Err() != context.DeadlineExceeded {
		out["error"] = friendly(err)
	}
	if cx.Err() == context.DeadlineExceeded {
		out["truncated"] = fmt.Sprintf("the stream was cut at %s; events up to that point are included", mcpFlowCap)
	}
	return out
}

// primaryInput is the wire paramName of a recipe's first input (the entity it runs on).
func primaryInput(e catalog.Entry) string {
	if len(e.Inputs) == 0 {
		return ""
	}
	return e.Inputs[0].ParamName
}

// mcpToolText2Cypher translates an English question into Cypher via the public
// text2cypher endpoint (optionally executing it).
func mcpToolText2Cypher(args json.RawMessage) mcpToolResult {
	var a struct {
		Question string `json:"question"`
		Execute  bool   `json:"execute"`
		Provider string `json:"provider"`
		Fast     bool   `json:"fast"`
	}
	_ = json.Unmarshal(args, &a)
	if strings.TrimSpace(a.Question) == "" {
		return mcpErr("question is required - the question in English, e.g. \"What IPs does google.com resolve to?\"")
	}
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return errRes
	}
	cx, cancel := ctx()
	defer cancel()
	raw, err := c.Text2Cypher(cx, "", client.Text2CypherRequest{
		Question: a.Question, Execute: a.Execute, Provider: strings.TrimSpace(a.Provider), Fast: a.Fast,
	})
	if err != nil {
		return mcpErr(friendly(err))
	}
	return mcpText(string(raw))
}

// --- MCP resources (mirror whisper://schema/full, stats, quota, server) --------------

const (
	mcpResSchemaFull = "whisper://schema/full"
	mcpResStats      = "whisper://stats"
	mcpResQuota      = "whisper://quota"
	mcpResServer     = "whisper://server"
)

// mcpResourcesList advertises the four reference resources (always listed - discovery
// is keyless; reading a graph-backed resource returns a clear no-key error).
func mcpResourcesList() []map[string]any {
	return []map[string]any{
		{"uri": mcpResSchemaFull, "name": "Complete Schema", "title": "WhisperGraph Full Schema",
			"description": "Full WhisperGraph schema: node labels with counts, edge types with directions.", "mimeType": "text/markdown"},
		{"uri": mcpResStats, "name": "Database Statistics", "title": "Live Database Statistics",
			"description": "Live node/edge counts, object count, and threat-intel summary.", "mimeType": "application/json"},
		{"uri": mcpResQuota, "name": "Plan Quota", "title": "Live Plan / Quota / Usage",
			"description": "The caller's plan tier, limits, and current usage.", "mimeType": "application/json"},
		{"uri": mcpResServer, "name": "Server Descriptor", "title": "Server / Deployment Descriptor",
			"description": "This MCP server's identity + the graph endpoint and catalog it exposes.", "mimeType": "application/json"},
	}
}

// mcpResourceRead reads one resource by URI, returning an MCP resources/read result.
func mcpResourceRead(uri string) (map[string]any, bool) {
	switch uri {
	case mcpResServer:
		return mcpResourceContent(uri, "application/json", mcpServerDescriptor()), true
	case mcpResSchemaFull:
		return mcpGraphResource(uri, "text/markdown", `CALL db.schema("markdown")`, "schema"), true
	case mcpResStats:
		return mcpStatsResource(uri), true
	case mcpResQuota:
		return mcpQuotaResource(uri), true
	default:
		return nil, false
	}
}

// mcpResourceContent wraps a text body as a resources/read result.
func mcpResourceContent(uri, mime, text string) map[string]any {
	return map[string]any{"contents": []map[string]any{{"uri": uri, "mimeType": mime, "text": text}}}
}

// mcpServerDescriptor is the CLI MCP server's honest self-descriptor: who it is and
// which public graph endpoint + catalog it exposes (no backend internals).
func mcpServerDescriptor() string {
	workflows, recipes := 0, 0
	for _, e := range catalog.All() {
		if e.IsDirect() {
			recipes++
		} else {
			workflows++
		}
	}
	d := map[string]any{
		"name":            "whisper",
		"version":         Version,
		"protocolVersion": mcpProtocolVersion,
		"graphEndpoint":   catalog.GraphEndpoint(),
		"docsBase":        catalog.DocsBase(),
		"recipes":         recipes,
		"workflows":       workflows,
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	return string(b)
}

// mcpGraphResource reads a single-column graph result (e.g. db.schema markdown) and
// returns its cell as the resource body. Keyed: a clear no-key error otherwise.
func mcpGraphResource(uri, mime, query, column string) map[string]any {
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return mcpResourceContent(uri, "application/json", mcpErrText(errRes))
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, query, nil)
	if err != nil {
		return mcpResourceContent(uri, "application/json", jsonErr(friendly(err)))
	}
	if len(res.Rows) > 0 {
		if s, ok := res.Rows[0][column].(string); ok {
			return mcpResourceContent(uri, mime, s)
		}
	}
	return mcpResourceContent(uri, "application/json", string(res.Raw))
}

// mcpStatsResource serves whisper://stats from the graph /stats companion (keyed).
func mcpStatsResource(uri string) map[string]any {
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return mcpResourceContent(uri, "application/json", mcpErrText(errRes))
	}
	cx, cancel := ctx()
	defer cancel()
	raw, err := c.GraphStats(cx)
	if err != nil {
		return mcpResourceContent(uri, "application/json", jsonErr(friendly(err)))
	}
	return mcpResourceContent(uri, "application/json", string(raw))
}

// mcpQuotaResource serves whisper://quota, flattening the {key,value} rows into a plain
// object the way the reference resource does (keyed).
func mcpQuotaResource(uri string) map[string]any {
	c, errRes, ok := mcpGraphClient()
	if !ok {
		return mcpResourceContent(uri, "application/json", mcpErrText(errRes))
	}
	cx, cancel := ctx()
	defer cancel()
	res, err := c.GraphQuery(cx, "CALL whisper.quota()", nil)
	if err != nil {
		return mcpResourceContent(uri, "application/json", jsonErr(friendly(err)))
	}
	flat := map[string]any{}
	for _, row := range res.Rows {
		if k, ok := row["key"].(string); ok {
			flat[k] = row["value"]
		}
	}
	if len(flat) == 0 {
		return mcpResourceContent(uri, "application/json", string(res.Raw))
	}
	b, _ := json.MarshalIndent(flat, "", "  ")
	return mcpResourceContent(uri, "application/json", string(b))
}

// jsonErr renders a message as a small JSON error object.
func jsonErr(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// mcpErrText pulls the text out of an mcpToolResult (used to surface a no-key error as
// a resource body).
func mcpErrText(r mcpToolResult) string {
	if len(r.Content) > 0 {
		return jsonErr(r.Content[0].Text)
	}
	return jsonErr("unavailable")
}

// --- MCP prompts (gallery-driven investigation prompts) ------------------------------

// mcpPromptsList advertises one investigation prompt per catalog workflow (flow). Each
// prompt is a canned run_workflow directive with an EVIDENCE instruction, mirroring the
// reference server's gallery prompts. Static templates - listed keyless (pure discovery).
func mcpPromptsList() []map[string]any {
	prompts := make([]map[string]any, 0)
	for _, e := range catalog.All() {
		if e.IsDirect() {
			continue // prompts wrap multi-step workflows
		}
		var arguments []map[string]any
		if len(e.Inputs) > 0 {
			in := e.Inputs[0]
			desc := in.ID
			if len(in.Examples) > 0 {
				desc += fmt.Sprintf(" (e.g. %v)", in.Examples[0])
			}
			arguments = append(arguments, map[string]any{
				"name": in.ID, "description": desc, "required": in.Default == nil && !in.Optional,
			})
		}
		prompts = append(prompts, map[string]any{
			"name": e.ID, "title": e.Title, "description": e.Purpose, "arguments": arguments,
		})
	}
	return prompts
}

// mcpPromptGet returns one prompt's message: a run_workflow directive for that
// workflow, filled with the caller's input, plus a cite-the-evidence instruction.
func mcpPromptGet(name string, args map[string]any) (map[string]any, bool) {
	e, ok := catalog.Find(name)
	if !ok || e.IsDirect() {
		return nil, false
	}
	input := ""
	if len(e.Inputs) > 0 {
		in := e.Inputs[0]
		if v, ok := args[in.ID]; ok {
			input = fmt.Sprintf("%v", v)
		} else if v, ok := args[in.ParamName]; ok {
			input = fmt.Sprintf("%v", v)
		} else if in.Default != nil {
			input = fmt.Sprintf("%v", in.Default)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Run the \"%s\" investigation (%s) using the run_workflow tool: slug %q", e.Title, e.Purpose, e.ID)
	if input != "" {
		fmt.Fprintf(&b, ", input %q", input)
	}
	b.WriteString(".\n\nThen report the findings. NO EVIDENCE, NO CLAIM: cite each step's Cypher and row count. ")
	b.WriteString("Treat a skipped or empty step as a coverage gap, not a clean result. Docs: ")
	b.WriteString(e.DocsURL())

	return map[string]any{
		"description": e.Purpose,
		"messages": []map[string]any{
			{"role": "user", "content": map[string]any{"type": "text", "text": b.String()}},
		},
	}, true
}
