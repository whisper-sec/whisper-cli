// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/catalog"
)

func mustEntry(t *testing.T, id string) catalog.Entry {
	t.Helper()
	e, ok := catalog.Find(id)
	if !ok {
		t.Fatalf("catalog entry %q not found", id)
	}
	return e
}

// A positional arg fills the recipe's input in catalog order, keyed by paramName.
func TestBuildRecipeInputsPositional(t *testing.T) {
	e := mustEntry(t, "identify")
	got, err := buildRecipeInputs(e, []string{"api.openai.com"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["v"] != "api.openai.com" {
		t.Fatalf("inputs = %v", got)
	}
}

// k=v positionals and --in address inputs by id OR wire paramName, any case.
func TestBuildRecipeInputsNamed(t *testing.T) {
	e := mustEntry(t, "attack-path") // inputs: asset->value, other->other
	got, err := buildRecipeInputs(e, []string{"asset=paypal.com"}, []string{"OTHER=paypa1.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["value"] != "paypal.com" || got["other"] != "paypa1.com" {
		t.Fatalf("inputs = %v", got)
	}
}

// A missing input falls back to the catalog default.
func TestBuildRecipeInputsDefaults(t *testing.T) {
	e := mustEntry(t, "identify")
	got, err := buildRecipeInputs(e, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["v"] != "api.openai.com" {
		t.Fatalf("default not applied: %v", got)
	}
}

// Optional inputs with no value are simply omitted (never sent as null).
func TestBuildRecipeInputsOptionalOmitted(t *testing.T) {
	e := mustEntry(t, "submit")
	got, err := buildRecipeInputs(e, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := got["observation_id"]; present {
		t.Fatalf("optional input should be omitted, got %v", got)
	}
	if got["kind"] != "indicator" || got["value"] != "203.0.113.5" {
		t.Fatalf("defaults missing: %v", got)
	}
}

// Surplus positionals are a clear usage error (exit 2), not a silent drop.
func TestBuildRecipeInputsTooMany(t *testing.T) {
	e := mustEntry(t, "identify")
	if _, err := buildRecipeInputs(e, []string{"a", "b"}, nil); err == nil {
		t.Fatal("expected a usage error for surplus positionals")
	}
}

// An unknown named input is a clear usage error naming the recipe.
func TestBuildRecipeInputsUnknownName(t *testing.T) {
	e := mustEntry(t, "identify")
	if _, err := buildRecipeInputs(e, nil, []string{"nope=1"}); err == nil {
		t.Fatal("expected a usage error for an unknown input name")
	}
}

// A number-kind input is coerced to a real number on the wire.
func TestCoerceInputNumber(t *testing.T) {
	e := mustEntry(t, "blast-radius") // params carry depth, inputs the indicator
	_ = e
	in := catalog.Input{ID: "depth", Kind: "number", ParamName: "depth"}
	if v := coerceInput(in, "2"); v != int64(2) {
		t.Fatalf("coerceInput number = %#v", v)
	}
	if v := coerceInput(in, "2.5"); v != 2.5 {
		t.Fatalf("coerceInput float = %#v", v)
	}
	str := catalog.Input{ID: "v", Kind: "any", ParamName: "v"}
	if v := coerceInput(str, "8.8.8.8"); v != "8.8.8.8" {
		t.Fatalf("a dotted quad must stay a string, got %#v", v)
	}
	if v := coerceInput(str, `["a","b"]`); len(v.([]any)) != 2 {
		t.Fatalf("a JSON list should decode, got %#v", v)
	}
}

// --param k=v values decode as JSON when they parse, else stay strings.
func TestParseKVParams(t *testing.T) {
	got, err := parseKVParams([]string{"v=8.8.8.8", "n=5", "ok=true", "s=plain text"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["v"] != "8.8.8.8" || got["n"] != float64(5) || got["ok"] != true || got["s"] != "plain text" {
		t.Fatalf("params = %#v", got)
	}
	if _, err := parseKVParams([]string{"missing"}); err == nil {
		t.Fatal("expected a usage error for a flag without '='")
	}
}

// --- the MCP graph tool surface ------------------------------------------------------

// One tool per catalog entry + whisper_graph_query; every description ends with the
// recipe's docs URL (docsBase + docPath).
func TestMCPGraphToolsSurface(t *testing.T) {
	tools := mcpGraphTools()
	if len(tools) != len(catalog.All())+1 {
		t.Fatalf("expected %d graph tools, got %d", len(catalog.All())+1, len(tools))
	}
	byName := map[string]map[string]any{}
	for _, tool := range tools {
		byName[tool["name"].(string)] = tool
	}
	if _, ok := byName["whisper_graph_query"]; !ok {
		t.Fatal("whisper_graph_query missing")
	}
	for _, e := range catalog.All() {
		tool, ok := byName[e.ToolName()]
		if !ok {
			t.Fatalf("tool %s missing", e.ToolName())
		}
		desc := tool["description"].(string)
		if !strings.HasSuffix(desc, "Docs: "+e.DocsURL()) {
			t.Errorf("%s description must end with its docs URL, got ...%q", e.ToolName(), desc[max(0, len(desc)-60):])
		}
	}
	// The raw tool's description ends with the cypher-api docs URL.
	if desc := byName["whisper_graph_query"]["description"].(string); !strings.HasSuffix(desc, "Docs: "+catalog.RawCypherDocsURL()) {
		t.Errorf("whisper_graph_query description must end with %s", catalog.RawCypherDocsURL())
	}
}

// The generated inputSchema keys properties by the WIRE paramName with catalog
// defaults and select enums.
func TestMCPGraphRecipeToolSchema(t *testing.T) {
	tool := mcpGraphRecipeTool(mustEntry(t, "identify"))
	schema := tool["inputSchema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	v, ok := props["v"].(map[string]any)
	if !ok {
		t.Fatalf("identify schema must key its input by paramName v: %v", props)
	}
	if v["type"] != "string" || v["default"] != "api.openai.com" {
		t.Fatalf("identify v schema = %v", v)
	}

	sub := mcpGraphRecipeTool(mustEntry(t, "submit"))
	sprops := sub["inputSchema"].(map[string]any)["properties"].(map[string]any)
	kind := sprops["kind"].(map[string]any)
	if enum, isList := kind["enum"].([]string); !isList || len(enum) != 2 {
		t.Fatalf("submit kind enum = %v", kind["enum"])
	}
}

// mcpGraphCall routes graph names (liberally) and declines everything else. Key state
// is pinned to "none" so routing never touches the network (the routed calls answer
// with the helpful no-key tool error).
func TestMCPGraphCallRouting(t *testing.T) {
	pinKeyState(t, "", "")
	if _, ok := mcpGraphCall("whisper_totally_unknown", nil); ok {
		t.Fatal("unknown names must not route to the graph half")
	}
	if _, ok := mcpGraphCall("whisper_verify", nil); ok {
		t.Fatal("whisper_verify is a keyless tool, not a graph recipe")
	}
	// A graph name routes (the call itself will report the missing key as a tool
	// error; routing is what we assert here).
	if _, ok := mcpGraphCall("whisper_graph_query", []byte(`{}`)); !ok {
		t.Fatal("whisper_graph_query must route")
	}
	if _, ok := mcpGraphCall("whisper_identify", []byte(`{}`)); !ok {
		t.Fatal("whisper_identify must route")
	}
}
