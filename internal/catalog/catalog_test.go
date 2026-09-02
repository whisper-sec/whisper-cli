// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package catalog

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The embedded catalog is the SSOT snapshot: 29 entries, 14 direct + 15 flow.
func TestCatalogShape(t *testing.T) {
	entries := All()
	if len(entries) != 29 {
		t.Fatalf("expected 29 catalog entries, got %d", len(entries))
	}
	direct, flow := 0, 0
	for _, e := range entries {
		switch e.Exec.Mode {
		case ModeDirect:
			direct++
			if strings.TrimSpace(e.Exec.Cypher) == "" {
				t.Errorf("direct entry %q has no exec.cypher", e.ID)
			}
		case ModeFlow:
			flow++
		default:
			t.Errorf("entry %q has unknown exec.mode %q", e.ID, e.Exec.Mode)
		}
		if strings.TrimSpace(e.DocPath) == "" {
			t.Errorf("entry %q has no docPath", e.ID)
		}
		if !strings.HasPrefix(e.DocsURL(), "https://www.whisper.security/docs/") {
			t.Errorf("entry %q DocsURL %q does not join docsBase+docPath", e.ID, e.DocsURL())
		}
	}
	if direct != 14 || flow != 15 {
		t.Fatalf("expected 14 direct + 15 flow, got %d direct + %d flow", direct, flow)
	}
}

// Camel ids must match the generated SDK/MCP artifact naming exactly.
func TestCamelID(t *testing.T) {
	cases := map[string]string{
		"identify":                     "identify",
		"psl-tldplusone":               "pslTldplusone",
		"history-whois":                "historyWhois",
		"db-schema":                    "dbSchema",
		"lookup-tor-relay":             "lookupTorRelay",
		"anycast-dns-root-sovereignty": "anycastDnsRootSovereignty",
	}
	for id, want := range cases {
		e, ok := Find(id)
		if !ok {
			t.Fatalf("catalog entry %q not found", id)
		}
		if got := e.CamelID(); got != want {
			t.Errorf("CamelID(%q) = %q, want %q", id, got, want)
		}
		if got := e.ToolName(); got != "whisper_"+want {
			t.Errorf("ToolName(%q) = %q, want %q", id, got, "whisper_"+want)
		}
	}
}

// Find is liberal: id, camel, tool name, any case, '-'/'_' interchangeable.
func TestFindLiberal(t *testing.T) {
	for _, name := range []string{
		"identify", "IDENTIFY", "whisper_identify",
		"psl-tldplusone", "pslTldplusone", "whisper_pslTldplusone", "psl_tldplusone",
		"  db-schema  ", "dbSchema",
	} {
		if _, ok := Find(name); !ok {
			t.Errorf("Find(%q) should resolve", name)
		}
	}
	for _, name := range []string{"", "nope", "whisper_", "whisper_verify"} {
		if _, ok := Find(name); ok {
			t.Errorf("Find(%q) should NOT resolve", name)
		}
	}
}

// The endpoints and docs base come from the embedded SSOT.
func TestEndpoints(t *testing.T) {
	if got := GraphEndpoint(); got != "https://graph.whisper.online/api/query" {
		t.Errorf("GraphEndpoint() = %q", got)
	}
	if got := FlowRunEndpoint(); got != "https://console.whisper.security/api/gallery/run" {
		t.Errorf("FlowRunEndpoint() = %q", got)
	}
	if got := DocsBase(); got != "https://www.whisper.security" {
		t.Errorf("DocsBase() = %q", got)
	}
	if got := RawCypherDocsURL(); got != "https://www.whisper.security/docs/cypher-api" {
		t.Errorf("RawCypherDocsURL() = %q", got)
	}
}

// Direct entries address their inputs by wire paramName in exec.params.
func TestDirectInputParamNames(t *testing.T) {
	e, ok := Find("identify")
	if !ok {
		t.Fatal("identify not found")
	}
	if !e.IsDirect() {
		t.Fatal("identify should be direct")
	}
	if len(e.Inputs) != 1 || e.Inputs[0].ParamName != "v" {
		t.Fatalf("identify inputs = %+v, want one input with paramName v", e.Inputs)
	}
	if !strings.Contains(e.Exec.Cypher, "$v") {
		t.Fatalf("identify cypher %q should reference $v", e.Exec.Cypher)
	}
}

// --- the access tier -------------------------------------------------

// The keyless tier is EXACTLY the three public graph procedures. Pinning the set both
// ways is the point: a catalog refresh that quietly re-marks them keyed would silently
// empty the MCP server's keyless half, and one that marks something else keyless would
// hand a key-less caller a recipe the endpoint will refuse.
func TestCatalogKeylessTierIsExactlyThePublicProcedures(t *testing.T) {
	want := map[string]bool{"assess": true, "identify": true, "explain": true}
	got := map[string]bool{}
	for _, e := range All() {
		if e.IsKeyless() {
			got[e.ID] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("keyless entries = %v, want exactly %v", keys(got), keys(want))
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("%s must be on the keyless tier (keyless set is %v)", id, keys(got))
		}
	}
}

// Every keyless recipe must be a DIRECT one. A flow runs through the console gallery,
// which is keyed, so a keyless flow could only ever fail.
func TestCatalogKeylessEntriesAreAllDirect(t *testing.T) {
	seen := 0
	for _, e := range All() {
		if !e.IsKeyless() {
			continue
		}
		seen++
		if !e.IsDirect() {
			t.Fatalf("%s is keyless but runs as a %q - a flow needs the keyed console", e.ID, e.Exec.Mode)
		}
		if !strings.HasPrefix(e.Exec.Cypher, "CALL whisper.") {
			t.Fatalf("%s is keyless but its cypher %q is not a public whisper.* procedure", e.ID, e.Exec.Cypher)
		}
	}
	if seen == 0 {
		t.Fatal("no keyless entries at all - this test would otherwise pass vacuously")
	}
}

// Everything else stays keyed, and an entry with no access field at all reads as keyed:
// the safe tier is what a trimmed or older catalog degrades to.
func TestCatalogAccessDefaultsToKeyed(t *testing.T) {
	if (Entry{}).IsKeyless() {
		t.Fatal("an entry with no access field must NOT read as keyless")
	}
	if !(Entry{Access: "  KeyLess "}).IsKeyless() {
		t.Fatal("access must be read liberally (case and surrounding space)")
	}
	if (Entry{Access: "keyed"}).IsKeyless() || (Entry{Access: "public"}).IsKeyless() {
		t.Fatal("only the exact keyless tier name may read as keyless")
	}
	keyed := 0
	for _, e := range All() {
		if !e.IsKeyless() {
			keyed++
		}
	}
	if keyed != len(All())-3 {
		t.Fatalf("keyed entries = %d, want %d (every entry but the three keyless ones)", keyed, len(All())-3)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestFlowRunEndpointNamesTheHostTheClientDials pins the two places that name the
// console to the SAME host.
//
// RunFlow does not read this catalog value at all: it builds its URL from
// client.DefaultConsoleURL. So the catalog's flowRun endpoint is a published
// contract (it is baked into every shipped binary and it is what CONTROL_API.md
// documents) that nothing dispatches on, which is exactly the shape of defect
// that lets the two drift apart unnoticed. One change moved this one to the EDR
// console and left the dialled one where it was, and nothing failed, because nothing
// executes the published value. This test fails when they disagree.
func TestFlowRunEndpointNamesTheHostTheClientDials(t *testing.T) {
	got := FlowRunEndpoint()
	want := client.DefaultConsoleURL + "/api/gallery/run"
	if got != want {
		t.Errorf(
			"FlowRunEndpoint() = %q, but the CLI actually POSTs to %q.\n"+
				"The catalog publishes one host and RunFlow dials another; a reader of the "+
				"catalog or of CONTROL_API.md would call a host that does not serve the gallery.",
			got, want)
	}
	// The control: this must be comparing real values, not two empty strings.
	if !strings.HasPrefix(got, "https://") || !strings.HasSuffix(got, "/api/gallery/run") {
		t.Fatalf("FlowRunEndpoint() returned something that is not a gallery URL: %q", got)
	}
}
