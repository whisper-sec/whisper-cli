// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// These are the live-pass unit tests: the embedded catalog, the live row -> deck
// mappers, the band normaliser, and the focusToken fold discipline. All hermetic
// (no network); the live path itself is exercised by the env-guarded e2e test.

// --- the embedded catalog ----------------------------------------------------------------

func TestCatalogEmbeddedParses(t *testing.T) {
	all := loadCatalog()
	if len(all) != 29 {
		t.Fatalf("expected the 29 vendored catalog entries, got %d", len(all))
	}
	var direct, flows int
	for _, cv := range all {
		if cv.Flow {
			flows++
			if cv.Cypher != "" {
				t.Errorf("flow %s must not pretend to carry runnable Cypher", cv.Name)
			}
		} else {
			direct++
			if cv.Cypher == "" {
				t.Errorf("direct verb %s must carry its catalog Cypher", cv.Name)
			}
		}
	}
	if direct != 14 || flows != 15 {
		t.Fatalf("expected 14 direct + 15 flows, got %d + %d", direct, flows)
	}
	// The picker's flows divider relies on direct-then-flows ordering.
	seenFlow := false
	for _, cv := range all {
		if cv.Flow {
			seenFlow = true
		} else if seenFlow {
			t.Fatal("catalog order must be all direct verbs, then all flows")
		}
	}
}

func TestCatalogVerbContracts(t *testing.T) {
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	id := byName["identify"]
	if id.ParamName != "v" || !strings.Contains(id.Cypher, "whisper.identify") {
		t.Fatalf("identify contract wrong: %+v", id)
	}
	if id.Proc != "whisper.identify" {
		t.Fatalf("identify proc derivation wrong: %q", id.Proc)
	}
	if !byName["submit"].Write {
		t.Fatal("submit must be marked as the guarded write verb")
	}
	if byName["db-schema"].ParamName != "" {
		t.Fatal("db-schema has no node input; ParamName must be empty")
	}
	if len(byName["db-schema"].Kinds) == 0 {
		t.Fatal("db-schema must apply anywhere (kinds [any])")
	}
}

func TestCatalogApplicability(t *testing.T) {
	names := func(labels ...string) map[string]bool {
		out := map[string]bool{}
		for _, cv := range applicableCatalog(labels) {
			out[cv.Name] = true
		}
		return out
	}
	host := names("HOSTNAME")
	for _, want := range []string{"identify", "assess", "variants", "origins", "explain", "typosquat"} {
		if !host[want] {
			t.Errorf("HOSTNAME should offer %s", want)
		}
	}
	ip := names("IPV4")
	if !ip["identify"] || !ip["assess"] || !ip["lookup-tor-relay"] {
		t.Error("IPV4 should offer identify + assess + lookup-tor-relay")
	}
	if ip["variants"] {
		t.Error("IPV4 must not offer variants (a domain verb)")
	}
	asn := names("ASN")
	if !asn["bgp-hijack-exposure"] || !asn["assess"] {
		t.Error("ASN should offer bgp-hijack-exposure + assess")
	}
	// Multi-label union: an IPV4 that is also a threat FEED keeps the IP verbs.
	multi := names("IPV4", "FEED")
	if !multi["lookup-tor-relay"] {
		t.Error("multi-label node lost an applicable verb (union broken)")
	}
}

// --- band + prop normalisation -----------------------------------------------------------

func TestNormalizeBandLiberal(t *testing.T) {
	cases := map[string]string{
		"NONE": "", "": "", "DERIVED": "",
		"clean": "BENIGN", "LOW": "BENIGN", "Benign": "BENIGN",
		"MEDIUM": "SUSPICIOUS", "suspicious": "SUSPICIOUS",
		"HIGH": "MALICIOUS", "CRITICAL": "MALICIOUS", "malicious": "MALICIOUS",
		"UNKNOWN": "UNKNOWN", "weird-new-word": "UNKNOWN",
	}
	for in, want := range cases {
		if got := normalizeBand(in); got != want {
			t.Errorf("normalizeBand(%q) = %q, want %q", in, got, want)
		}
	}
	// assess: an explicit clean label outranks a NONE band (the live vocabulary).
	if got := normalizeAssess("NONE", "clean"); got != "BENIGN" {
		t.Errorf("assess NONE+clean should read BENIGN, got %q", got)
	}
	if got := normalizeAssess("HIGH", ""); got != "MALICIOUS" {
		t.Errorf("assess HIGH should read MALICIOUS, got %q", got)
	}
	if got := normalizeAssess("NONE", ""); got != "" {
		t.Errorf("assess NONE with no label must stay unassessed, got %q", got)
	}
}

func TestCuratePropsKeepsFactsDropsNoise(t *testing.T) {
	raw := map[string]any{
		"id": "4:whisper:123", "label": "IPV4", "name": "1.2.3.4",
		"isTor": true, "isC2": false, "isPhishing": false,
		"threatScore": float64(6), "verdictScore": float64(0),
		"registrationDate": float64(1279146957000),
		"rir":              "ARIN", "orgId": "deadbeef",
	}
	out := curateProps(raw)
	if out["isTor"] != true {
		t.Error("a TRUE flag (isTor) is a first-class fact and must survive")
	}
	if _, ok := out["isC2"]; ok {
		t.Error("a FALSE flag is noise and must be dropped")
	}
	if _, ok := out["id"]; ok {
		t.Error("internal ids must be dropped")
	}
	if out["threatScore"] != "6 (evidence)" {
		t.Errorf("a positive raw score must survive as EVIDENCE, trimmed: %v", out["threatScore"])
	}
	if out["registrationDate"] != "2010-07-14" {
		t.Errorf("epoch-ms dates must render readable, got %v", out["registrationDate"])
	}
	if out["rir"] != "ARIN" {
		t.Errorf("registry facts must survive, got %v", out["rir"])
	}
}

// --- live row -> deck mappers ------------------------------------------------------------

func TestEdgesFromRecordsLiveShape(t *testing.T) {
	rows := []map[string]any{
		{"et": "RESOLVES_TO", "outb": true, "total": float64(2), "sample": []any{
			[]any{[]any{"IPV4"}, "162.159.140.245", "NONE"},
			[]any{[]any{"IPV4"}, "172.66.0.243", "HIGH"},
		}},
		{"et": "LINKS_TO", "outb": false, "total": float64(725), "sample": []any{
			[]any{[]any{"HOSTNAME"}, "portkey.ai", nil},
		}},
	}
	edges := edgesFromRecords(rows)
	if len(edges) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(edges))
	}
	g := edges[0]
	if g.Type != "RESOLVES_TO" || g.Dir != 1 || g.Total != 2 || len(g.Sample) != 2 {
		t.Fatalf("outbound group mapped wrong: %+v", g)
	}
	if g.Sample[0].Value != "162.159.140.245" || g.Sample[0].Band != "" {
		t.Fatalf("sample node mapped wrong (NONE must read unassessed): %+v", g.Sample[0])
	}
	if g.Sample[1].Band != "MALICIOUS" {
		t.Fatalf("HIGH must read MALICIOUS: %+v", g.Sample[1])
	}
	rev := edges[1]
	if rev.Type != "LINKS_TO⁻¹" || rev.Dir != -1 || rev.baseType() != "LINKS_TO" {
		t.Fatalf("inbound group must carry the reverse notation + raw base type: %+v", rev)
	}
}

func TestNodeFromInspectBandsHonestly(t *testing.T) {
	n := nodeFromInspect("api.openai.com", map[string]any{
		"labels": []any{"HOSTNAME"},
		"props":  map[string]any{"verdictLevel": "NONE", "isThreat": false},
	})
	if n.Band != "" {
		t.Errorf("verdictLevel NONE must read unassessed, got %q", n.Band)
	}
	if len(n.Labels) != 1 || n.Labels[0] != "HOSTNAME" {
		t.Errorf("labels lost: %+v", n.Labels)
	}
	bad := nodeFromInspect("evil.example", map[string]any{
		"labels": []any{"HOSTNAME"},
		"props":  map[string]any{"verdictLevel": "MEDIUM"},
	})
	if bad.Band != "SUSPICIOUS" {
		t.Errorf("MEDIUM must read SUSPICIOUS, got %q", bad.Band)
	}
}

func TestCardFromRecordsTypeAware(t *testing.T) {
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	focus := host("api.openai.com", "")
	stats := client.GraphStats{Rows: 1, MS: 22}

	assess := cardFromRecords(byName["assess"], focus, []map[string]any{{
		"host": "api.openai.com", "label": "clean", "band": "NONE",
		"sub_labels": []any{}, "coverage": "known-clean",
		"evidence": []any{"coverage:known-clean", "band:NONE"},
	}}, stats)
	if assess.Shape != shapeBand || assess.Band != "BENIGN" || assess.CovWord != "known-clean" {
		t.Fatalf("assess card mapped wrong: %+v", assess)
	}
	if !strings.Contains(assess.Cypher, "'api.openai.com'") {
		t.Fatalf("the card must bind the reproducible Cypher, got %q", assess.Cypher)
	}

	variants := cardFromRecords(byName["variants"], focus, []map[string]any{
		{"variant": "api-openai.com", "method": "insertion", "exists": true, "confidence": 0.4},
		{"variant": "api.0penai.com", "method": "homoglyph", "exists": false, "confidence": 0.9},
	}, client.GraphStats{Rows: 2, MS: 40})
	if variants.Shape != shapeRanked || len(variants.Table) != 2 {
		t.Fatalf("variants card mapped wrong: %+v", variants)
	}
	if variants.Table[0].Name != "api.0penai.com" {
		t.Fatalf("variants must rank by confidence desc, got %+v", variants.Table[0])
	}
	if variants.Table[0].Node.Value != "api.0penai.com" {
		t.Fatal("every variants row must be a walkable node")
	}

	empty := cardFromRecords(byName["origins"], focus, nil, client.GraphStats{})
	if !strings.Contains(empty.Note, "honest empty") {
		t.Fatalf("an empty result must say so plainly: %+v", empty)
	}
}

// TestReproCypherIsInjectionSafe: a hostile focus value can never break out of the
// display literal (conservative in what we emit).
func TestReproCypherIsInjectionSafe(t *testing.T) {
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	out := reproCypher(byName["assess"], "evil']) RETURN 1 //")
	if strings.Contains(out, `evil']`) {
		t.Fatalf("hostile value escaped the literal: %q", out)
	}
	if !strings.Contains(out, `evil\']`) {
		t.Fatalf("hostile value is not escaped in place: %q", out)
	}
}

// --- the focusToken fold discipline ------------------------------------------------------

func TestExploreStaleRepliesAreDropped(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.deck.live = true
	v.token = 7

	stale := edgesMsg{token: 6, edges: []edgeGroup{{Type: "SHOULD_NOT_PAINT", Total: 1}}}
	a.Update(stale)
	for _, e := range v.deck.edges {
		if e.Type == "SHOULD_NOT_PAINT" {
			t.Fatal("a stale edges reply was painted")
		}
	}

	fresh := edgesMsg{token: 7, ms: 42, edges: []edgeGroup{{Type: "RESOLVES_TO", Base: "RESOLVES_TO", Dir: 1, Total: 2}}}
	a.Update(fresh)
	if len(v.deck.edges) != 1 || v.deck.edges[0].Type != "RESOLVES_TO" || v.deck.ms != 42 {
		t.Fatalf("a fresh edges reply must fold: %+v", v.deck.edges)
	}
}

func TestExploreFocusFoldMergesNotClobbers(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, deckState{focus: host("api.openai.com", ""), live: true})
	v := a.exploreVw
	v.deck.live = true
	v.token = 1

	// enrichment already arrived (band + ident) ...
	a.Update(enrichMsg{token: 1, value: "api.openai.com", band: "BENIGN", ident: &identity{Vendor: "Cloudflare"}})
	// ... then the inspect lands with labels + props and an unassessed own-verdict.
	a.Update(focusMsg{token: 1, node: graphNode{Labels: []string{"HOSTNAME"}, Value: "api.openai.com",
		Props: map[string]any{"rir": "ARIN"}}})

	f := v.deck.focus
	if f.Band != "BENIGN" || f.Ident == nil || f.Ident.Vendor != "Cloudflare" {
		t.Fatalf("the inspect fold clobbered richer enrichment: %+v", f)
	}
	if len(f.Labels) != 1 || f.Props["rir"] != "ARIN" {
		t.Fatalf("the inspect fold lost its own data: %+v", f)
	}
}

func TestExploreTransportErrorFailsOpen(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.deck.live = true
	v.token = 3
	prevEdges := len(v.deck.edges)

	a.Update(edgesMsg{token: 3, err: &client.ProblemError{Status: 502, Detail: "graph endpoint unreachable"}})
	if !v.degraded {
		t.Fatal("a transport failure must set the calm degraded state")
	}
	if len(v.deck.edges) != prevEdges {
		t.Fatal("fail-open must keep the last-known deck visible")
	}
	out := a.View()
	if !strings.Contains(out, "graph unreachable") {
		t.Error("the outage banner must paint")
	}
}

func TestExploreLiveWalkFiresLoads(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, deckState{
		focus: host("api.openai.com", ""),
		edges: []edgeGroup{{Type: "RESOLVES_TO", Base: "RESOLVES_TO", Dir: 1, Total: 2,
			Sample: []graphNode{ipv4("162.159.140.245", "", nil)}}},
		live: true,
	})
	v := a.exploreVw
	v.deck.live = true
	v.activePane = paneNeighbors
	tokenBefore := v.token

	cmd := v.walkIn()
	if cmd == nil {
		t.Fatal("a live walk must fire the async loads")
	}
	if v.token != tokenBefore+1 {
		t.Fatal("a live walk must mint a fresh focusToken")
	}
	if v.deck.focus.Value != "162.159.140.245" || !v.loadingFocus || !v.loadingEdges {
		t.Fatalf("the deck must re-root provisionally while loading: %+v", v.deck.focus)
	}
	if len(v.deck.trail) != 1 || v.deck.trail[0].Value != "api.openai.com" {
		t.Fatalf("the walk must push the old focus onto the trail: %+v", v.deck.trail)
	}

	// back is instant, from history, and invalidates the in-flight token.
	tok := v.token
	v.ascendTrail()
	if v.deck.focus.Value != "api.openai.com" {
		t.Fatalf("back must re-land the parent instantly, got %q", v.deck.focus.Value)
	}
	if v.token == tok {
		t.Fatal("back must invalidate in-flight replies for the abandoned focus")
	}
}

func TestExploreCachedLandIsInstant(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, deckState{focus: host("api.openai.com", ""), live: true})
	v := a.exploreVw
	v.deck.cache = newLRU(8)
	cached := deckState{
		focus: ipv4("162.159.140.245", "", nil),
		edges: []edgeGroup{{Type: "ANNOUNCED_BY", Base: "ANNOUNCED_BY", Dir: 1, Total: 1}},
		live:  true,
	}
	v.deck.cache.put("162.159.140.245", cached)

	cmd := v.land(ipv4("162.159.140.245", "", nil), true)
	if cmd != nil {
		t.Fatal("a cache hit must land instantly with no refetch")
	}
	if v.deck.focus.Value != "162.159.140.245" || len(v.deck.edges) != 1 {
		t.Fatalf("the cached deck must install whole: %+v", v.deck)
	}
	if len(v.deck.trail) != 1 || v.deck.trail[0].Value != "api.openai.com" {
		t.Fatalf("the cached land must still extend the trail: %+v", v.deck.trail)
	}
}

func TestExploreFlowAndWriteVerbsAreHonest(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	applicable := applicableCatalog(v.deck.focus.Labels)

	var flowIdx, writeIdx = -1, -1
	for i, cv := range applicable {
		if cv.Flow && flowIdx < 0 {
			flowIdx = i
		}
		if cv.Write && writeIdx < 0 {
			writeIdx = i
		}
	}
	if flowIdx < 0 || writeIdx < 0 {
		t.Fatal("a HOSTNAME must offer at least one flow and the guarded submit")
	}

	v.catalog.cursor = flowIdx
	if cmd := v.runSelectedVerb(applicable); cmd != nil {
		t.Fatal("a flow must never fire a network run (anchor step runs in console)")
	}
	v.catalog.cursor = writeIdx
	if cmd := v.runSelectedVerb(applicable); cmd != nil {
		t.Fatal("the guarded write verb must never auto-run")
	}
	if len(v.results) != 2 {
		t.Fatalf("both honest cards must render, got %d", len(v.results))
	}
	joined := v.results[0].Note + v.results[1].Note
	if !strings.Contains(joined, "never faked") || !strings.Contains(joined, "not run") {
		t.Fatalf("the honesty notes must be present: %q", joined)
	}
}

func TestExploreSortWorstFirst(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, deckState{
		focus: ipv4("104.16.132.229", "", nil),
		edges: []edgeGroup{{Type: "RESOLVES_TO⁻¹", Base: "RESOLVES_TO", Dir: -1, Total: 4, Sample: []graphNode{
			host("benign.example", "BENIGN"),
			host("unknown.example", "UNKNOWN"),
			host("evil.example", "MALICIOUS"),
			host("meh.example", "SUSPICIOUS"),
		}}},
		live: true,
	})
	v := a.exploreVw
	v.sortWorstFirst()
	got := []string{}
	for _, n := range v.deck.edges[0].Sample {
		got = append(got, n.Value)
	}
	want := "evil.example meh.example unknown.example benign.example"
	if strings.Join(got, " ") != want {
		t.Fatalf("worst-first sort wrong: %v", got)
	}
}

func TestExploreJumpLandsExact(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.ov = ovJump
	v.jump.query = "https://API.OpenAI.com/v1/models"
	// keyless: the jump must close, explain, and NOT pretend to land live.
	if cmd := v.jumpLand(); cmd != nil {
		t.Fatal("keyless jump must not fire a live land")
	}
	if v.ov != ovNone {
		t.Fatal("jump must close either way")
	}
	if !a.toastErr || !strings.Contains(a.toast, "API key") {
		t.Fatalf("keyless jump must say it needs a key, got %q", a.toast)
	}
}
