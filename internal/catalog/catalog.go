// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package catalog embeds the whisper.security graph recipe catalog (the SSOT
// catalog.json) and exposes it to both the CLI (`whisper graph`) and the MCP server
// (`whisper mcp`). Every entry is one runnable recipe:
//
//   - mode "direct": exec.cypher runs as-is against the public graph endpoint
//     (POST /api/query with {"query","parameters"}), inputs mapped by paramName;
//   - mode "flow":   a multi-step workflow run by slug via the console gallery/run
//     endpoint ({"slug","inputs","params"}, Server-Sent-Events stream).
//
// Each entry carries a docPath; DocsURL() joins it with the catalog's docsBase so
// every surface (CLI help, MCP tool description) can point at the recipe's docs.
package catalog

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed catalog.json
var catalogJSON []byte

// Fallback endpoints, used only if an (older/trimmed) embedded catalog omits them
// (Postel: a sane zero-config default, never a panic).
const (
	fallbackDocsBase   = "https://www.whisper.security"
	fallbackGraphURL   = "https://graph.whisper.security/api/query"
	fallbackFlowRunURL = "https://console.whisper.security/api/gallery/run"
	rawCypherDocPath   = "/docs/cypher-api"
	toolNamePrefix     = "whisper_"
)

// Catalog is the decoded catalog.json.
type Catalog struct {
	Graph   Graph   `json:"graph"`
	Entries []Entry `json:"entries"`
}

// Graph is the catalog's top-level endpoint + docs contract.
type Graph struct {
	Endpoint string  `json:"endpoint"`
	DocsBase string  `json:"docsBase"`
	FlowRun  FlowRun `json:"flowRun"`
}

// FlowRun is the gallery/run contract for mode:"flow" entries.
type FlowRun struct {
	Endpoint string `json:"endpoint"`
}

// Entry is one recipe: a named, documented, runnable unit of graph intelligence.
type Entry struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Purpose string  `json:"purpose"`
	Why     string  `json:"why"`
	DocPath string  `json:"docPath"`
	Inputs  []Input `json:"inputs"`
	Params  []Param `json:"params"`
	Exec    Exec    `json:"exec"`
}

// Input is one recipe input; ParamName is the wire name (the Cypher $param for a
// direct recipe, the inputs{} key for a flow).
type Input struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	ParamName string   `json:"paramName"`
	Default   any      `json:"default"`
	Optional  bool     `json:"optional"`
	Options   []string `json:"options"`
	Examples  []any    `json:"examples"`
}

// Param is one flow tuning knob (sent in the gallery/run params{} map).
type Param struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Default any      `json:"default"`
	Options []string `json:"options"`
}

// Exec says how an entry runs.
type Exec struct {
	Mode   string         `json:"mode"` // "direct" | "flow"
	Cypher string         `json:"cypher"`
	Params map[string]any `json:"params"`
	Note   string         `json:"note"` // honesty note surfaced for flows (multi-step, runs in the console)
}

// ModeDirect / ModeFlow are the two exec modes.
const (
	ModeDirect = "direct"
	ModeFlow   = "flow"
)

var (
	loadOnce sync.Once
	loaded   Catalog
	byKey    map[string]int // normalised id / camel id / tool name -> Entries index
)

// load parses the embedded catalog exactly once. The embed is build-time-verified
// JSON; a parse failure would be a build defect, so it degrades to an empty catalog
// rather than panicking (fail soft: the rest of the CLI keeps working).
func load() {
	loadOnce.Do(func() {
		_ = json.Unmarshal(catalogJSON, &loaded)
		byKey = make(map[string]int, len(loaded.Entries)*3)
		for i, e := range loaded.Entries {
			byKey[normalize(e.ID)] = i
			byKey[normalize(e.CamelID())] = i
			byKey[normalize(e.ToolName())] = i
		}
	})
}

// All returns every catalog entry, in catalog order.
func All() []Entry {
	load()
	return loaded.Entries
}

// Find resolves a recipe LIBERALLY: the catalog id ("psl-tldplusone"), its camel form
// ("pslTldplusone"), the MCP tool name ("whisper_pslTldplusone"), any case, with '-'
// and '_' interchangeable. Returns ok=false when nothing matches.
func Find(name string) (Entry, bool) {
	load()
	i, ok := byKey[normalize(name)]
	if !ok {
		return Entry{}, false
	}
	return loaded.Entries[i], true
}

// DocsBase is the documentation site root every DocPath joins onto.
func DocsBase() string {
	load()
	if strings.TrimSpace(loaded.Graph.DocsBase) == "" {
		return fallbackDocsBase
	}
	return strings.TrimRight(loaded.Graph.DocsBase, "/")
}

// GraphEndpoint is the public Cypher endpoint (POST {"query","parameters"}).
func GraphEndpoint() string {
	load()
	if strings.TrimSpace(loaded.Graph.Endpoint) == "" {
		return fallbackGraphURL
	}
	return loaded.Graph.Endpoint
}

// FlowRunEndpoint is the gallery/run endpoint flows execute against (SSE).
func FlowRunEndpoint() string {
	load()
	if strings.TrimSpace(loaded.Graph.FlowRun.Endpoint) == "" {
		return fallbackFlowRunURL
	}
	return loaded.Graph.FlowRun.Endpoint
}

// RawCypherDocsURL is the docs page for the raw Cypher API (the `whisper query` /
// whisper_graph_query surface).
func RawCypherDocsURL() string { return DocsBase() + rawCypherDocPath }

// DocsURL is the entry's full documentation URL (docsBase + docPath).
func (e Entry) DocsURL() string { return DocsBase() + e.DocPath }

// IsDirect reports whether the entry runs as one Cypher statement (vs a flow).
func (e Entry) IsDirect() bool { return e.Exec.Mode == ModeDirect }

// CamelID is the id in lowerCamelCase ("psl-tldplusone" -> "pslTldplusone"), the
// form the generated SDK/MCP artifacts use.
func (e Entry) CamelID() string {
	segs := strings.Split(e.ID, "-")
	var b strings.Builder
	for i, s := range segs {
		if s == "" {
			continue
		}
		if i == 0 {
			b.WriteString(s)
			continue
		}
		b.WriteString(strings.ToUpper(s[:1]))
		b.WriteString(s[1:])
	}
	return b.String()
}

// ToolName is the MCP tool name for this entry: whisper_<camelId>.
func (e Entry) ToolName() string { return toolNamePrefix + e.CamelID() }

// normalize folds case and drops '-'/'_' so every reasonable spelling of a recipe
// name finds it (Postel: liberal in what we accept).
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}
