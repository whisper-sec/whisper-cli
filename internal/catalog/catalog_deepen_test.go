// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package catalog

import (
	"strings"
	"sync"
	"testing"
)

// deepencatalog_swapCatalog swaps the embedded catalog bytes for raw and forces a
// re-parse, restoring the real embed (and a fresh parse of it) when the test ends.
// Package tests run sequentially, so touching the package singletons is safe.
func deepencatalog_swapCatalog(t *testing.T, raw []byte) {
	t.Helper()
	orig := catalogJSON
	catalogJSON = raw
	loaded = Catalog{} // a fresh process starts from the zero value
	byKey = nil
	loadOnce = sync.Once{}
	t.Cleanup(func() {
		catalogJSON = orig
		loaded = Catalog{}
		byKey = nil
		loadOnce = sync.Once{}
		load()
	})
}

// deepencatalog_swapDocsIndex does the same for the embedded docs index.
func deepencatalog_swapDocsIndex(t *testing.T, raw []byte) {
	t.Helper()
	orig := docsIndexJSON
	docsIndexJSON = raw
	docsData = docsIndex{} // a fresh process starts from the zero value
	docsByKey = nil
	docsOnce = sync.Once{}
	t.Cleanup(func() {
		docsIndexJSON = orig
		docsData = docsIndex{}
		docsByKey = nil
		docsOnce = sync.Once{}
		loadDocs()
	})
}

func deepencatalog_mustFind(t *testing.T, name string) Entry {
	t.Helper()
	e, ok := Find(name)
	if !ok {
		t.Fatalf("catalog entry %q not found", name)
	}
	return e
}

func deepencatalog_mustDoc(t *testing.T, path string) DocEntry {
	t.Helper()
	d, ok := DocByPath(path)
	if !ok {
		t.Fatalf("doc path %q not found", path)
	}
	return d
}

// Every entry must resolve under every spelling the lookup index promises: the
// catalog id, the camel id, the MCP tool name, and case/dash/underscore/space
// variants. A mutated byKey construction or normalize() breaks this immediately.
func TestDeepenCatalogFindRoundTripAllEntries(t *testing.T) {
	entries := All()
	if len(entries) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, e := range entries {
		for _, spelling := range []string{
			e.ID,
			e.CamelID(),
			e.ToolName(),
			strings.ToUpper(e.ID),
			strings.ReplaceAll(e.ID, "-", "_"),
			"  " + e.ID + "  ",
		} {
			got, ok := Find(spelling)
			if !ok {
				t.Errorf("Find(%q) should resolve entry %q", spelling, e.ID)
				continue
			}
			if got.ID != e.ID {
				t.Errorf("Find(%q) = %q, want %q", spelling, got.ID, e.ID)
			}
		}
	}
}

// CamelID must survive empty segments (leading/trailing/doubled dashes and the
// empty id). The empty-segment guard is what keeps s[:1] from panicking; a
// mutant that drops the guard dies here.
func TestDeepenCatalogCamelIDBoundarySegments(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"-":              "",
		"a--b":           "aB",
		"-x":             "X",
		"x-":             "x",
		"--deep--scan--": "DeepScan",
	}
	for id, want := range cases {
		e := Entry{ID: id}
		if got := e.CamelID(); got != want {
			t.Errorf("CamelID(%q) = %q, want %q", id, got, want)
		}
	}
	if got := (Entry{ID: "a--b"}).ToolName(); got != "whisper_aB" {
		t.Errorf("ToolName(a--b) = %q, want whisper_aB", got)
	}
}

// Structural contracts a catalog edit must not break: unique non-blank ids,
// titles present, every flow carries its honesty note, and every direct entry
// references each REQUIRED input's wire param ($paramName) in its Cypher. This
// is what keeps a catalog edit from silently shipping an unrunnable recipe.
func TestDeepenCatalogEntryContracts(t *testing.T) {
	seen := make(map[string]bool)
	for _, e := range All() {
		if strings.TrimSpace(e.ID) == "" {
			t.Fatal("catalog entry with blank id")
		}
		if seen[e.ID] {
			t.Errorf("duplicate entry id %q", e.ID)
		}
		seen[e.ID] = true
		if strings.TrimSpace(e.Title) == "" {
			t.Errorf("entry %q has no title", e.ID)
		}
		switch e.Exec.Mode {
		case ModeFlow:
			if e.IsDirect() {
				t.Errorf("flow entry %q claims IsDirect", e.ID)
			}
			if strings.TrimSpace(e.Exec.Note) == "" {
				t.Errorf("flow entry %q has no honesty note", e.ID)
			}
		case ModeDirect:
			if !e.IsDirect() {
				t.Errorf("direct entry %q not IsDirect", e.ID)
			}
			for _, in := range e.Inputs {
				if in.Optional {
					continue
				}
				if !strings.Contains(e.Exec.Cypher, "$"+in.ParamName) {
					t.Errorf("direct entry %q: required input %q ($%s) not referenced in cypher", e.ID, in.ID, in.ParamName)
				}
			}
		}
	}
}

// The submit entry is the govern surface: its select inputs must decode with
// their options, required vs optional must survive the JSON round trip, and
// the wire paramName mapping (identifierKind -> identifier_kind) must hold.
func TestDeepenCatalogSubmitGovernSurface(t *testing.T) {
	e := deepencatalog_mustFind(t, "submit")
	if !e.IsDirect() {
		t.Fatal("submit should be a direct entry")
	}
	byID := make(map[string]Input, len(e.Inputs))
	for _, in := range e.Inputs {
		byID[in.ID] = in
	}
	kind, ok := byID["kind"]
	if !ok || kind.Kind != "select" {
		t.Fatalf("submit input kind = %+v, want a select input", kind)
	}
	if len(kind.Options) != 2 || kind.Options[0] != "indicator" || kind.Options[1] != "feedback" {
		t.Errorf("submit kind options = %v, want [indicator feedback]", kind.Options)
	}
	idk, ok := byID["identifierKind"]
	if !ok || idk.ParamName != "identifier_kind" {
		t.Fatalf("submit identifierKind = %+v, want paramName identifier_kind", idk)
	}
	opts := strings.Join(idk.Options, " ")
	for _, want := range []string{"ip", "asn", "cert_sha256", "cidr"} {
		if !strings.Contains(opts, want) {
			t.Errorf("submit identifierKind options %v missing %q", idk.Options, want)
		}
	}
	for _, required := range []string{"kind", "identifierKind", "value"} {
		in, ok := byID[required]
		if !ok {
			t.Errorf("submit missing input %q", required)
			continue
		}
		if in.Optional {
			t.Errorf("submit input %q must be required, decoded optional", required)
		}
	}
	for _, optional := range []string{"observationId", "confidence", "provenance"} {
		in, ok := byID[optional]
		if !ok {
			t.Errorf("submit missing input %q", optional)
			continue
		}
		if !in.Optional {
			t.Errorf("submit input %q must be optional, decoded required", optional)
		}
	}
}

// Defaults, exec params, and flow tuning params must survive decoding: they are
// what the CLI pre-fills and what the gallery/run body carries.
func TestDeepenCatalogDefaultsAndFlowParams(t *testing.T) {
	psl := deepencatalog_mustFind(t, "psl-tldplusone")
	if len(psl.Inputs) != 1 || psl.Inputs[0].Default != "www.foo.co.uk" {
		t.Fatalf("psl-tldplusone inputs = %+v, want one input defaulting to www.foo.co.uk", psl.Inputs)
	}
	if got := psl.Exec.Params["v"]; got != "www.foo.co.uk" {
		t.Errorf("psl-tldplusone exec.params[v] = %v, want www.foo.co.uk", got)
	}
	ap := deepencatalog_mustFind(t, "attack-path")
	if len(ap.Params) != 1 || ap.Params[0].Name != "level" || ap.Params[0].Default != "standard" {
		t.Fatalf("attack-path params = %+v, want one param level defaulting to standard", ap.Params)
	}
	if got := strings.Join(ap.Params[0].Options, ","); got != "quick,standard,deep,comprehensive,exhaustive" {
		t.Errorf("attack-path level options = %q", got)
	}
	sov := deepencatalog_mustFind(t, "anycast-dns-root-sovereignty")
	if len(sov.Inputs) != 1 || sov.Inputs[0].ParamName != "country" || sov.Inputs[0].Default != "BR" {
		t.Fatalf("anycast-dns-root-sovereignty inputs = %+v, want country defaulting to BR", sov.Inputs)
	}
}

// A trimmed embedded catalog (an older build may omit the graph block, or ship
// whitespace-only endpoints) must fall back to the shipped defaults rather than
// emitting a blank endpoint (Postel: sane zero-config defaults, never a surprise).
func TestDeepenCatalogEndpointFallbacksOnTrimmedCatalog(t *testing.T) {
	deepencatalog_swapCatalog(t, []byte(`{"graph":{"endpoint":"  ","docsBase":" ","flowRun":{"endpoint":"\t"}},"entries":[{"id":"probe","docPath":"/docs/probe"}]}`))
	if got := GraphEndpoint(); got != "https://graph.whisper.online/api/query" {
		t.Errorf("GraphEndpoint fallback = %q", got)
	}
	if got := FlowRunEndpoint(); got != "https://console.whisper.security/api/gallery/run" {
		t.Errorf("FlowRunEndpoint fallback = %q", got)
	}
	if got := DocsBase(); got != "https://www.whisper.security" {
		t.Errorf("DocsBase fallback = %q", got)
	}
	if got := RawCypherDocsURL(); got != "https://www.whisper.security/docs/cypher-api" {
		t.Errorf("RawCypherDocsURL fallback = %q", got)
	}
	e := deepencatalog_mustFind(t, "probe")
	if got := e.DocsURL(); got != "https://www.whisper.security/docs/probe" {
		t.Errorf("DocsURL on fallback base = %q", got)
	}
}

// A docsBase carrying trailing slashes must be trimmed so DocsURL never emits
// a doubled slash.
func TestDeepenCatalogDocsBaseTrailingSlashTrim(t *testing.T) {
	deepencatalog_swapCatalog(t, []byte(`{"graph":{"docsBase":"https://docs.example.test///"}}`))
	if got := DocsBase(); got != "https://docs.example.test" {
		t.Errorf("DocsBase trim = %q, want https://docs.example.test", got)
	}
	if got := RawCypherDocsURL(); got != "https://docs.example.test/docs/cypher-api" {
		t.Errorf("RawCypherDocsURL on trimmed base = %q", got)
	}
}

// The embed is build-time-verified JSON, but a corrupt build must degrade to an
// empty catalog and the fallback endpoints, never panic the whole CLI.
func TestDeepenCatalogMalformedCatalogFailsSoft(t *testing.T) {
	deepencatalog_swapCatalog(t, []byte(`{"graph":{"endpoint":"https://x`))
	if got := All(); len(got) != 0 {
		t.Errorf("malformed catalog should decode to zero entries, got %d", len(got))
	}
	if _, ok := Find("identify"); ok {
		t.Error("Find should not resolve against a malformed catalog")
	}
	if got := GraphEndpoint(); got != "https://graph.whisper.online/api/query" {
		t.Errorf("GraphEndpoint on malformed catalog = %q", got)
	}
}

// The docs index is the SSOT snapshot: 56 pages, every field populated, paths
// unique after normalization and site-relative (never URL-shaped), index order
// preserved.
func TestDeepenCatalogDocsIndexShape(t *testing.T) {
	docs := Docs()
	if len(docs) != 56 {
		t.Fatalf("expected 56 indexed docs, got %d", len(docs))
	}
	seen := make(map[string]bool, len(docs))
	for _, d := range docs {
		if strings.TrimSpace(d.Path) == "" || strings.TrimSpace(d.Title) == "" ||
			strings.TrimSpace(d.Section) == "" || strings.TrimSpace(d.Summary) == "" {
			t.Errorf("doc %+v has a blank field", d)
		}
		if strings.Contains(d.Path, "://") {
			t.Errorf("doc path %q is URL-shaped; the index must stay site-relative", d.Path)
		}
		key := strings.ToLower(strings.Trim(d.Path, "/"))
		if seen[key] {
			t.Errorf("duplicate doc path %q after normalization", d.Path)
		}
		seen[key] = true
	}
	if docs[0].Path != "ai/agent-signup" {
		t.Errorf("index order not preserved: first path %q", docs[0].Path)
	}
}

// DocByPath is liberal in what it accepts: any case, leading/trailing slashes,
// surrounding whitespace, all resolving to the same indexed page.
func TestDeepenCatalogDocByPathLiberal(t *testing.T) {
	want := deepencatalog_mustDoc(t, "changelog")
	if want.Title != "Changelog" || want.Section != "Guides" {
		t.Fatalf("changelog doc = %+v", want)
	}
	for _, spelling := range []string{"changelog", "CHANGELOG", "/changelog", "changelog/", "  /changelog/  "} {
		got, ok := DocByPath(spelling)
		if !ok {
			t.Errorf("DocByPath(%q) should resolve", spelling)
			continue
		}
		if got.Path != want.Path {
			t.Errorf("DocByPath(%q) = %q, want %q", spelling, got.Path, want.Path)
		}
	}
	mcp := deepencatalog_mustDoc(t, "AI/MCP/Setup")
	if mcp.Path != "ai/mcp/setup" {
		t.Errorf("case-folded lookup returned %q", mcp.Path)
	}
}

// The index is also the security boundary for read_docs: URL-shaped input,
// path traversal, file extensions, fragments, and unindexed prefixes must all
// MISS, so the tool can never be pointed off-site.
func TestDeepenCatalogDocByPathRejectsOffIndex(t *testing.T) {
	for _, p := range []string{
		"",
		"   ",
		"nope/nothing",
		"https://www.whisper.security/docs/changelog",
		"../../etc/passwd",
		"changelog.md",
		"changelog#frag",
		"ai/mcp",
	} {
		if _, ok := DocByPath(p); ok {
			t.Errorf("DocByPath(%q) should NOT resolve", p)
		}
	}
}

// SearchDocs: blank keyword returns the whole index, matching is
// case-insensitive over path+title+section+summary, every hit really contains
// the keyword, and a miss returns empty (not the whole index).
func TestDeepenCatalogSearchDocs(t *testing.T) {
	all := Docs()
	if got := SearchDocs(""); len(got) != len(all) {
		t.Errorf("SearchDocs(blank) = %d docs, want the whole index (%d)", len(got), len(all))
	}
	if got := SearchDocs("   "); len(got) != len(all) {
		t.Errorf("SearchDocs(whitespace) = %d docs, want the whole index (%d)", len(got), len(all))
	}
	lower := SearchDocs("splunk")
	upper := SearchDocs("SPLUNK")
	if len(lower) == 0 {
		t.Fatal("SearchDocs(splunk) found nothing")
	}
	if len(upper) != len(lower) {
		t.Errorf("search must be case-insensitive: %d vs %d hits", len(upper), len(lower))
	}
	for _, d := range lower {
		hay := strings.ToLower(d.Path + " " + d.Title + " " + d.Section + " " + d.Summary)
		if !strings.Contains(hay, "splunk") {
			t.Errorf("hit %q does not contain the keyword", d.Path)
		}
	}
	found := false
	for _, d := range SearchDocs("credentials") {
		if d.Path == "ai/agent-signup" {
			found = true
		}
	}
	if !found {
		t.Error("summary-only keyword `credentials` should surface ai/agent-signup")
	}
	if got := SearchDocs("zzz-not-a-topic"); len(got) != 0 {
		t.Errorf("SearchDocs(miss) = %d docs, want 0", len(got))
	}
}

// DocURL joins base + path + .md and trims slashes on both parts.
func TestDeepenCatalogDocURLJoins(t *testing.T) {
	if got := DocURL("ai/agent-signup"); got != "https://www.whisper.security/docs/ai/agent-signup.md" {
		t.Errorf("DocURL(ai/agent-signup) = %q", got)
	}
	if got := DocURL("/changelog/"); got != "https://www.whisper.security/docs/changelog.md" {
		t.Errorf("DocURL(/changelog/) = %q", got)
	}
}

// A docs index shipped without its baseUrl must keep DocURL anchored on the
// site root instead of emitting a scheme-less URL, and lookups still work.
func TestDeepenCatalogDocsIndexBlankBaseURLFailsSoft(t *testing.T) {
	deepencatalog_swapDocsIndex(t, []byte(`{"docs":[{"path":"probe/page","title":"Probe","section":"S","summary":"s"}]}`))
	if got := DocURL("probe/page"); got != "https://www.whisper.security/docs/probe/page.md" {
		t.Errorf("DocURL on blank baseUrl = %q", got)
	}
	d := deepencatalog_mustDoc(t, "/Probe/Page/")
	if d.Title != "Probe" {
		t.Errorf("lookup on swapped index = %+v", d)
	}
}

// A corrupt docs index degrades to an empty index with the fallback base, so
// listing and lookup fail closed while DocURL stays well-formed.
func TestDeepenCatalogDocsIndexMalformedFailsSoft(t *testing.T) {
	deepencatalog_swapDocsIndex(t, []byte(`not json at all`))
	if got := Docs(); len(got) != 0 {
		t.Errorf("malformed docs index should decode to zero docs, got %d", len(got))
	}
	if _, ok := DocByPath("changelog"); ok {
		t.Error("DocByPath should not resolve against a malformed index")
	}
	if got := DocURL("x"); got != "https://www.whisper.security/docs/x.md" {
		t.Errorf("DocURL on malformed index = %q", got)
	}
}
