// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
)

// mcp_reference_test.go covers the whisper-ai reference surface mirrored into
// `whisper mcp`: the 7 cypher tools, the 4 resources, and the gallery prompts. It uses
// a graph stub that answers by inspecting the posted Cypher, so query / explain_schema /
// run_workflow exercise the real handler paths without a live graph.

// graphStub answers /api/query POSTs by sniffing the query string, so one stub serves
// query, explain_indicator, explain_schema, and a direct run_workflow recipe.
func graphStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(raw, &body)
		q := body.Query
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "db.schema"):
			schema := `{"nodes":[{"label":"IPV4","count":12,"virtual":false,"properties":[{"name":"name","type":"String"}]},{"label":"HOSTNAME","count":34,"virtual":false,"properties":[]}],"relationships":[{"type":"RESOLVES_TO","source":["HOSTNAME"],"target":["IPV4","IPV6"],"count":1,"virtual":false},{"type":"LOCATED_IN","source":["IPV4"],"target":["CITY"],"count":1,"virtual":false}]}`
			enc, _ := json.Marshal(schema)
			_, _ = w.Write([]byte(`{"columns":["schema"],"rows":[{"schema":` + string(enc) + `}]}`))
		case strings.Contains(q, "db.labels"):
			_, _ = w.Write([]byte(`{"columns":["label","count"],"rows":[{"label":"HOSTNAME","count":34},{"label":"IPV4","count":12}]}`))
		case strings.Contains(q, "explain"):
			_, _ = w.Write([]byte(`{"columns":["indicator","score","level"],"rows":[{"indicator":"1.1.1.1","score":37.8,"level":"INFO"}]}`))
		case strings.Contains(q, "whisper.identify"):
			_, _ = w.Write([]byte(`{"columns":["host","vendor_id","category"],"rows":[{"host":"api.openai.com","vendor_id":"cloudflare","category":"cdn"}]}`))
		case strings.Contains(q, "whisper.quota"):
			_, _ = w.Write([]byte(`{"columns":["key","value"],"rows":[{"key":"plan","value":"INTERNAL"}]}`))
		default:
			_, _ = w.Write([]byte(`{"columns":["n"],"rows":[{"n":1}]}`))
		}
	}))
}

// TestMCP_Initialize_DeclaresResourcesAndPrompts: the reference surface adds the
// resources + prompts capabilities alongside tools.
func TestMCP_Initialize_DeclaresResourcesAndPrompts(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	res, _ := r[0]["result"].(map[string]any)
	caps, _ := res["capabilities"].(map[string]any)
	for _, want := range []string{"tools", "resources", "prompts"} {
		if _, ok := caps[want]; !ok {
			t.Fatalf("must declare %q capability: %v", want, caps)
		}
	}
}

// TestMCP_ReferenceToolsGatedByKey: the reference cypher tools are advertised only WITH a
// key (the keyless tier stays exactly verify/rdap).
func TestMCP_ReferenceToolsGatedByKey(t *testing.T) {
	pinKeyState(t, "", "")
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	for _, ti := range tools {
		name, _ := ti.(map[string]any)["name"].(string)
		for _, banned := range []string{"query", "explain_indicator", "read_docs", "list_workflows", "run_workflow", "text2cypher"} {
			if name == banned {
				t.Fatalf("reference tool %q must not list without a key", banned)
			}
		}
	}
}

// TestMCP_ReferenceCallWithoutKey: a keyed reference tool called with no key is a clean
// MCP tool error naming the fix, never opaque.
func TestMCP_ReferenceCallWithoutKey(t *testing.T) {
	pinKeyState(t, "", "")
	for i, tc := range []struct{ tool, args string }{
		{"query", `{"cypher":"RETURN 1"}`},
		{"explain_indicator", `{"indicator":"1.1.1.1"}`},
		{"text2cypher", `{"question":"resolve google.com"}`},
		{"run_workflow", `{"slug":"identify","input":"api.openai.com"}`},
	} {
		r := drive(t, callLine(20+i, tc.tool, tc.args))
		text, isError := toolText(t, r[0])
		if !isError || !strings.Contains(text, "WHISPER_API_KEY") {
			t.Fatalf("%s without a key must name WHISPER_API_KEY, got isError=%v %q", tc.tool, isError, text)
		}
	}
}

// TestMCP_Query_ReturnsRows: the query tool posts the Cypher and returns the graph's
// verbatim {columns,rows}. Accepts the cypher under `cypher` (whisper-ai canonical).
func TestMCP_Query_ReturnsRows(t *testing.T) {
	srv := graphStub(t)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	r := drive(t, callLine(1, "query", `{"cypher":"MATCH (n) RETURN n"}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("query errored: %q", text)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("query must return JSON: %v (%q)", err, text)
	}
	if _, ok := out["rows"].([]any); !ok {
		t.Fatalf("query must return rows, got %q", text)
	}
}

// TestMCP_ExplainSchema_Catalog_And_Card: no argument returns the label catalog; a label
// returns an entity card with inbound/outbound edges synthesised from db.schema.
func TestMCP_ExplainSchema_Catalog_And_Card(t *testing.T) {
	srv := graphStub(t)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	// No label → label catalog.
	r := drive(t, callLine(1, "explain_schema", `{}`))
	text, isError := toolText(t, r[0])
	if isError || !strings.Contains(text, "HOSTNAME") {
		t.Fatalf("explain_schema (catalog) must list labels, got %q", text)
	}

	// With a label → the entity card.
	r = drive(t, callLine(2, "explain_schema", `{"label":"IPV4"}`))
	text, isError = toolText(t, r[0])
	if isError {
		t.Fatalf("explain_schema (card) errored: %q", text)
	}
	var card map[string]any
	if err := json.Unmarshal([]byte(text), &card); err != nil {
		t.Fatalf("card must be JSON: %v (%q)", err, text)
	}
	if card["label"] != "IPV4" {
		t.Fatalf("card label = %v", card["label"])
	}
	outbound, _ := card["outbound"].([]any)
	inbound, _ := card["inbound"].([]any)
	if len(outbound) == 0 || len(inbound) == 0 {
		t.Fatalf("IPV4 card must have inbound (RESOLVES_TO) + outbound (LOCATED_IN) edges, got %q", text)
	}
}

// TestMCP_ReadDocs_ListAndSearch: read_docs is keyless. No argument lists the index; a
// keyword narrows it.
func TestMCP_ReadDocs_ListAndSearch(t *testing.T) {
	pinKeyState(t, "", "")
	r := drive(t, callLine(1, "read_docs", `{}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("read_docs list errored: %q", text)
	}
	var out struct {
		Docs  []map[string]any `json:"docs"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil || out.Count == 0 {
		t.Fatalf("read_docs list must return the doc index, got %q (err %v)", text, err)
	}
	// Keyword search narrows it (and finds the schema reference page).
	r = drive(t, callLine(2, "read_docs", `{"query":"schema"}`))
	text, _ = toolText(t, r[0])
	if !strings.Contains(text, "schema") {
		t.Fatalf("read_docs search for 'schema' must return schema pages, got %q", text)
	}
	// An unknown path is a clear error (index-relative, never a URL).
	r = drive(t, callLine(3, "read_docs", `{"path":"not/a/real/page"}`))
	text, isError = toolText(t, r[0])
	if !isError || !strings.Contains(text, "index") {
		t.Fatalf("read_docs on an unknown path must be a clear error, got isError=%v %q", isError, text)
	}
}

// TestMCP_ListWorkflows: list_workflows returns the embedded catalog; kind:workflow
// narrows to flows.
func TestMCP_ListWorkflows(t *testing.T) {
	pinKeyState(t, "", "")
	r := drive(t, callLine(1, "list_workflows", `{}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("list_workflows errored: %q", text)
	}
	var all struct {
		Workflows []map[string]any `json:"workflows"`
		Count     int              `json:"count"`
	}
	if err := json.Unmarshal([]byte(text), &all); err != nil {
		t.Fatalf("list_workflows must be JSON: %v", err)
	}
	if all.Count != len(catalog.All()) {
		t.Fatalf("list_workflows must return every catalog entry (%d), got %d", len(catalog.All()), all.Count)
	}
	// kind:workflow returns only flows.
	r = drive(t, callLine(2, "list_workflows", `{"kind":"workflow"}`))
	text, _ = toolText(t, r[0])
	var flows struct {
		Workflows []map[string]any `json:"workflows"`
	}
	_ = json.Unmarshal([]byte(text), &flows)
	for _, w := range flows.Workflows {
		if w["kind"] != "workflow" {
			t.Fatalf("kind:workflow filter leaked a %v", w["kind"])
		}
	}
	if len(flows.Workflows) == 0 {
		t.Fatalf("expected some workflows, got none")
	}
}

// TestMCP_RunWorkflow_DirectRecipe: run_workflow on a direct recipe (identify) fires its
// Cypher with the input bound to the primary param and returns the rows.
func TestMCP_RunWorkflow_DirectRecipe(t *testing.T) {
	srv := graphStub(t)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)

	r := drive(t, callLine(1, "run_workflow", `{"slug":"identify","input":"api.openai.com"}`))
	text, isError := toolText(t, r[0])
	if isError {
		t.Fatalf("run_workflow errored: %q", text)
	}
	if !strings.Contains(text, "cloudflare") || !strings.Contains(text, "recipe") {
		t.Fatalf("run_workflow(identify) must return the recipe result, got %q", text)
	}
}

// TestMCP_ResourcesList: resources/list advertises the four reference resources.
func TestMCP_ResourcesList(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	resources, _ := res["resources"].([]any)
	got := map[string]bool{}
	for _, ri := range resources {
		got[ri.(map[string]any)["uri"].(string)] = true
	}
	for _, want := range []string{"whisper://schema/full", "whisper://stats", "whisper://quota", "whisper://server"} {
		if !got[want] {
			t.Fatalf("resources/list missing %q (have %v)", want, got)
		}
	}
}

// TestMCP_ResourceRead_ServerKeyless: whisper://server reads with no key (it describes the
// CLI MCP server itself); a graph-backed resource surfaces a clear no-key error body.
func TestMCP_ResourceRead_ServerKeyless(t *testing.T) {
	pinKeyState(t, "", "")
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"whisper://server"}}`)
	res, _ := r[0]["result"].(map[string]any)
	contents, _ := res["contents"].([]any)
	if len(contents) == 0 {
		t.Fatalf("server descriptor must have contents: %v", res)
	}
	text, _ := contents[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "graphEndpoint") || !strings.Contains(text, "whisper") {
		t.Fatalf("server descriptor wrong: %q", text)
	}
	// A graph-backed resource without a key returns an error body, never a crash.
	r = drive(t, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"whisper://stats"}}`)
	res, _ = r[0]["result"].(map[string]any)
	contents, _ = res["contents"].([]any)
	body, _ := contents[0].(map[string]any)["text"].(string)
	if !strings.Contains(body, "API key") {
		t.Fatalf("stats without a key must carry a clear no-key error, got %q", body)
	}
}

// TestMCP_ResourceRead_QuotaFlattened: whisper://quota flattens the {key,value} rows into
// a plain object (keyed).
func TestMCP_ResourceRead_QuotaFlattened(t *testing.T) {
	srv := graphStub(t)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"whisper://quota"}}`)
	res, _ := r[0]["result"].(map[string]any)
	contents, _ := res["contents"].([]any)
	body, _ := contents[0].(map[string]any)["text"].(string)
	var flat map[string]any
	if err := json.Unmarshal([]byte(body), &flat); err != nil || flat["plan"] != "INTERNAL" {
		t.Fatalf("quota must flatten to {plan:INTERNAL,...}, got %q (err %v)", body, err)
	}
}

// TestMCP_PromptsListAndGet: prompts/list returns one prompt per catalog workflow;
// prompts/get fills it with the input and a run_workflow + evidence directive.
func TestMCP_PromptsListAndGet(t *testing.T) {
	r := drive(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	res, _ := r[0]["result"].(map[string]any)
	prompts, _ := res["prompts"].([]any)
	flowCount := 0
	for _, e := range catalog.All() {
		if !e.IsDirect() {
			flowCount++
		}
	}
	if len(prompts) != flowCount {
		t.Fatalf("prompts/list must have one prompt per workflow (%d), got %d", flowCount, len(prompts))
	}

	// prompts/get an existing workflow with an argument.
	r = drive(t, `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"attack-surface","arguments":{"domain":"cloudflare.com"}}}`)
	res, _ = r[0]["result"].(map[string]any)
	msgs, _ := res["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatalf("prompts/get must return messages: %v", r[0])
	}
	content, _ := msgs[0].(map[string]any)["content"].(map[string]any)
	text, _ := content["text"].(string)
	if !strings.Contains(text, "attack-surface") || !strings.Contains(text, "cloudflare.com") || !strings.Contains(text, "run_workflow") {
		t.Fatalf("prompt text must direct a run_workflow on the input, got %q", text)
	}

	// An unknown prompt is a JSON-RPC error.
	r = drive(t, `{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"nope"}}`)
	if _, ok := r[0]["error"].(map[string]any); !ok {
		t.Fatalf("unknown prompt must be a JSON-RPC error, got %v", r[0])
	}
}
