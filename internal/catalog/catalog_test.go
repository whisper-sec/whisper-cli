// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package catalog

import (
	"strings"
	"testing"
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
