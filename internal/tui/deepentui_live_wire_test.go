// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// deepentui_graphServer spins a graph endpoint that dispatches on a substring of the
// incoming Cypher: the first matching key's body answers; unmatched queries get the
// fallback. Returns a keyed client pointed at it.
func deepentui_graphServer(t *testing.T, bodies map[string]string, fallback string) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		q, _ := req["query"].(string)
		w.Header().Set("Content-Type", "application/json")
		for sub, body := range bodies {
			if strings.Contains(q, sub) {
				_, _ = w.Write([]byte(body))
				return
			}
		}
		_, _ = w.Write([]byte(fallback))
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper-0000000000000000"},
		HTTPClient: srv.Client(),
	})
}

// deepentui_graphDown spins a graph endpoint that is hard-down: every call answers
// HTTP 503 with an RFC-7807 problem body.
func deepentui_graphDown(t *testing.T) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":503,"detail":"graph endpoint down"}`))
	}))
	t.Cleanup(srv.Close)
	return client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper-0000000000000000"},
		HTTPClient: srv.Client(),
	})
}

// --- the EXPLORE live wire (exLoad* / exEnrich / exRunVerb) --------------------------

// TestExLoadFocusShapes covers the inspect round-trip: a live hit maps labels + curated
// props + the reconciled verdict band; zero rows is the honest sparse state, NOT an
// error; a transport failure carries the error.
func TestExLoadFocusShapes(t *testing.T) {
	hit := deepentui_graphServer(t, nil,
		`{"columns":["labels","props"],"rows":[{"labels":["HOSTNAME"],"props":{"verdictLevel":"MEDIUM","rir":"ARIN"}}],"statistics":{"rowCount":1}}`)
	m := exLoadFocus(hit, "shady.example", 5)().(focusMsg)
	if m.err != nil || m.token != 5 {
		t.Fatalf("focus load contract broken: %+v", m)
	}
	if m.node.Band != "SUSPICIOUS" || len(m.node.Labels) != 1 {
		t.Errorf("the node must band from its reconciled verdict: %+v", m.node)
	}
	if m.node.Props["rir"] != "ARIN" {
		t.Errorf("registry facts survive curation: %v", m.node.Props)
	}

	empty := deepentui_graphServer(t, nil, `{"columns":["labels","props"],"rows":[]}`)
	m = exLoadFocus(empty, "ghost.example", 1)().(focusMsg)
	if m.err != nil {
		t.Fatal("not-in-graph is a fact, never an error")
	}
	if m.node.Band != "UNKNOWN" || !strings.Contains(asStr(m.node.Props["sub"]), "not in the graph") {
		t.Errorf("the sparse state must say so plainly: %+v", m.node)
	}

	sad := deepentui_graphDown(t)
	if m = exLoadFocus(sad, "x", 1)().(focusMsg); m.err == nil {
		t.Error("a transport problem must carry through")
	}
}

// TestExLoadEdgesLive maps the bounded-neighbourhood reply into banded edge groups with
// the honest latency badge.
func TestExLoadEdgesLive(t *testing.T) {
	c := deepentui_graphServer(t, nil,
		`{"columns":["et","outb","total","sample"],"rows":[`+
			`{"et":"RESOLVES_TO","outb":true,"total":2,"sample":[[["IPV4"],"1.2.3.4","NONE"]]},`+
			`{"et":"LINKS_TO","outb":false,"total":725,"sample":[[["HOSTNAME"],"peer.example","HIGH"]]}`+
			`],"statistics":{"rowCount":2,"executionTimeMs":42}}`)
	m := exLoadEdges(c, "cloudflare.com", 9)().(edgesMsg)
	if m.err != nil || m.token != 9 || m.ms != 42 {
		t.Fatalf("edges contract broken: %+v", m)
	}
	if len(m.edges) != 2 || m.edges[0].Type != "RESOLVES_TO" || m.edges[1].Type != "LINKS_TO⁻¹" {
		t.Fatalf("edge groups mapped wrong: %+v", m.edges)
	}
	if m.edges[1].Sample[0].Band != "MALICIOUS" {
		t.Errorf("HIGH reads MALICIOUS on the sample: %+v", m.edges[1].Sample[0])
	}
}

// TestExLoadNeighborsPagingAndGuard covers the +200 page mapping AND the conservative
// edge-type guard: a non-word relationship name refuses to splice into Cypher.
func TestExLoadNeighborsPagingAndGuard(t *testing.T) {
	c := deepentui_graphServer(t, nil,
		`{"columns":["lbls","value","level"],"rows":[{"lbls":["HOSTNAME"],"value":"a.example","level":"LOW"}]}`)
	edge := edgeGroup{Type: "LINKS_TO⁻¹", Base: "LINKS_TO", Dir: -1, Total: 500}
	m := exLoadNeighbors(c, "hub.example", edge, 200, 3)().(neighborsMsg)
	if m.err != nil || m.edgeType != "LINKS_TO⁻¹" || m.off != 200 {
		t.Fatalf("paging contract broken: %+v", m)
	}
	if len(m.sample) != 1 || m.sample[0].Band != "BENIGN" {
		t.Errorf("the page rows band liberally: %+v", m.sample)
	}

	// The injection guard: an edge type that is not a plain word never dials at all.
	evil := edgeGroup{Base: "X]->(m) DETACH DELETE m//"}
	m = exLoadNeighbors(c, "x", evil, 0, 1)().(neighborsMsg)
	if m.err == nil || !strings.Contains(m.err.Error(), "not a plain relationship name") {
		t.Fatalf("a hostile edge type must be refused client-side: %+v", m.err)
	}

	sad := deepentui_graphDown(t)
	if m = exLoadNeighbors(sad, "x", edge, 0, 1)().(neighborsMsg); m.err == nil {
		t.Error("a failed page carries its error")
	}
}

// TestExEnrichHalves covers the two-half enrichment: both halves landing, and the
// both-down error surface (one helpful error, never four dead spinners).
func TestExEnrichHalves(t *testing.T) {
	c := deepentui_graphServer(t, map[string]string{
		"whisper.identify": `{"columns":["host","vendor_id","canonical_name","category","roles","host_class","band"],` +
			`"rows":[{"host":"api.openai.com","vendor_id":"openai","canonical_name":"OpenAI","category":"ai-api",` +
			`"roles":["api","llm"],"host_class":"api","band":"NONE"}]}`,
		"whisper.assess": `{"columns":["host","label","band","sub_labels","coverage","evidence"],` +
			`"rows":[{"host":"api.openai.com","label":"clean","band":"NONE","sub_labels":[],` +
			`"coverage":"known-clean","evidence":["coverage:known-clean","band:NONE"]}]}`,
	}, `{"columns":[],"rows":[]}`)
	m := exEnrich(c, "api.openai.com", 4)().(enrichMsg)
	if m.err != nil || m.token != 4 || m.value != "api.openai.com" {
		t.Fatalf("enrich contract broken: %+v", m)
	}
	if m.ident == nil || m.ident.Vendor != "OpenAI" || len(m.ident.Roles) != 2 || m.ident.Note != "ai-api" {
		t.Fatalf("the identify half mapped wrong: %+v", m.ident)
	}
	if m.band != "BENIGN" || m.ident.CovWord != "known-clean" || m.ident.Feeds != 2 {
		t.Errorf("the assess half mapped wrong: band=%q ident=%+v", m.band, m.ident)
	}

	sad := deepentui_graphDown(t)
	if m = exEnrich(sad, "x", 1)().(enrichMsg); m.err == nil || m.ident != nil {
		t.Error("both halves down must surface ONE error, no half-built card")
	}
}

// TestExRunVerbLive runs a real catalog verb round-trip and asserts the type-aware card
// binds the reproducible Cypher; the error path carries through.
func TestExRunVerbLive(t *testing.T) {
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	c := deepentui_graphServer(t, nil,
		`{"columns":["host","label","band","sub_labels","coverage","evidence"],`+
			`"rows":[{"host":"evil.example","label":"malicious","band":"HIGH","sub_labels":["phishing"],`+
			`"coverage":"full","evidence":["feed:abuse"]}],"statistics":{"rowCount":1,"executionTimeMs":7}}`)
	m := exRunVerb(c, byName["assess"], host("evil.example", ""), 2)().(verbResultMsg)
	if m.err != nil || m.token != 2 {
		t.Fatalf("verb run contract broken: %+v", m)
	}
	if m.card.Shape != shapeBand || m.card.Band != "MALICIOUS" || m.card.MS != 7 {
		t.Errorf("the assess card mapped wrong: %+v", m.card)
	}
	if !strings.Contains(m.card.Label, "malicious · phishing") {
		t.Errorf("sub_labels join onto the label: %q", m.card.Label)
	}
	if !strings.Contains(m.card.Cypher, "'evil.example'") {
		t.Error("the card binds its reproducible Cypher")
	}

	sad := deepentui_graphDown(t)
	if m = exRunVerb(sad, byName["assess"], host("x", ""), 1)().(verbResultMsg); m.err == nil {
		t.Error("a failed verb carries its error")
	}
}

// TestCardFromRecordsAllShapes sweeps the remaining card shapes: the variants ranking +
// registered glyph + the >12 trim, the timeline shape, the generic single-row card, the
// generic multi-row card with its >10 note, and the honest empty.
func TestCardFromRecordsAllShapes(t *testing.T) {
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	focus := host("paypal.com", "")

	// variants: nameless rows skipped, exists -> ●, ranked desc, 14 rows trim to 12.
	rows := []map[string]any{{"variant": "", "method": "skipped"}}
	for i := 0; i < 14; i++ {
		rows = append(rows, map[string]any{
			"variant": "v" + itoa(i) + ".example", "method": "homoglyph",
			"exists": i%2 == 0, "confidence": float64(i) / 20,
		})
	}
	card := cardFromRecords(byName["variants"], focus, rows, client.GraphStats{Rows: 14})
	if card.Shape != shapeRanked || len(card.Table) != 12 {
		t.Fatalf("variants must rank + trim to 12: %d rows", len(card.Table))
	}
	if card.Table[0].Conf < card.Table[11].Conf {
		t.Error("variants rank confidence-desc")
	}
	if !strings.Contains(card.Note, "more") {
		t.Error("the trim states the remainder honestly")
	}
	seenReg := false
	for _, r := range card.Table {
		if r.Reg == "●" {
			seenReg = true
		}
	}
	if !seenReg {
		t.Error("a registered variant carries the ● mark")
	}

	// history -> the timeline shape via the generic table.
	if hist, ok := byName["history-whois"]; ok {
		c := cardFromRecords(hist, focus, []map[string]any{{"when": "2010-07-14", "what": "registered"}}, client.GraphStats{})
		if c.Shape != shapeTimeline {
			t.Error("history renders as the timeline")
		}
	}

	// generic single row: one column:value line per key, sorted.
	gen := cardFromRecords(byName["identify"], focus, []map[string]any{
		{"vendor": "PayPal", "category": "payments"},
	}, client.GraphStats{Rows: 1})
	if len(gen.Table) != 2 || gen.Table[0].Method != "category" {
		t.Errorf("the single-row card sorts its keys: %+v", gen.Table)
	}

	// generic many rows: one line each, null-ish values dropped, >10 noted.
	many := make([]map[string]any, 0, 12)
	for i := 0; i < 12; i++ {
		many = append(many, map[string]any{"n": float64(i), "empty": "", "nul": "null"})
	}
	genMany := cardFromRecords(byName["identify"], focus, many, client.GraphStats{Rows: 12})
	if len(genMany.Table) != 10 || !strings.Contains(genMany.Note, "2 more rows") {
		t.Errorf("the many-row card caps at 10 with an honest note: %d %q", len(genMany.Table), genMany.Note)
	}
	if strings.Contains(genMany.Table[0].Name, "empty") || strings.Contains(genMany.Table[0].Name, "nul ") {
		t.Errorf("null-ish values must drop from the row line: %q", genMany.Table[0].Name)
	}

	// the honest empty.
	if c := cardFromRecords(byName["identify"], focus, nil, client.GraphStats{}); !strings.Contains(c.Note, "honest empty") {
		t.Error("0 rows says so plainly")
	}
}

// TestCuratePropsBranches sweeps the curation rules not covered elsewhere: verdictScore
// vs evidence scores, the sources count (both wire forms), date rendering (epoch + word),
// dropped false flags / ids, and the 6-fact determinism cap.
func TestCuratePropsBranches(t *testing.T) {
	if curateProps(nil) != nil {
		t.Error("nil in, nil out")
	}
	out := curateProps(map[string]any{
		"verdictScore":     float64(16),
		"threatScore":      float64(40),
		"sources":          []any{"feedA", "feedB"},
		"registrationDate": "2019-01-02",
		"orgId":            "deadbeef",
		"isTor":            true,
		"isC2":             false,
	})
	if out["verdictScore"] != "16" {
		t.Errorf("verdictScore is the one band-consistent number: %v", out["verdictScore"])
	}
	if out["threatScore"] != "40 (evidence)" {
		t.Errorf("raw threat scores are labelled evidence: %v", out["threatScore"])
	}
	if out["sources"] != "listed in 2 feeds" {
		t.Errorf("sources read as a feed count: %v", out["sources"])
	}
	if out["registrationDate"] != "2019-01-02" {
		t.Errorf("a word date passes through: %v", out["registrationDate"])
	}
	if _, ok := out["orgId"]; ok {
		t.Error("internal hashes are dropped")
	}
	if out["isTor"] != true {
		t.Error("a true flag is a first-class fact")
	}
	if _, ok := out["isC2"]; ok {
		t.Error("a false flag is noise")
	}

	// The numeric sources form counts too (liberal accept).
	if got := curateProps(map[string]any{"sources": float64(1)}); got["sources"] != "listed in 1 feed" {
		t.Errorf("a numeric sources counts (singular): %v", got["sources"])
	}

	// More than 6 facts trim deterministically (sorted key order).
	big := map[string]any{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		big[k] = k
	}
	if got := curateProps(big); len(got) != 6 {
		t.Errorf("the card caps at 6 facts: %d", len(got))
	}
}

// TestSmallDecodedHelpers sweeps strsOf / int64OfAny / f64OfAny / trimFloat /
// reproCypher / flowCard / subOf / bandWord spellings.
func TestSmallDecodedHelpers(t *testing.T) {
	if got := strsOf([]string{"a"}); len(got) != 1 {
		t.Error("a []string passes through")
	}
	if got := strsOf([]any{"a", "", "b"}); len(got) != 2 {
		t.Errorf("empties drop from a []any: %v", got)
	}
	if got := strsOf("solo"); len(got) != 1 || got[0] != "solo" {
		t.Error("a bare string wraps")
	}
	if strsOf("") != nil || strsOf(42) != nil {
		t.Error("empty / non-string forms are nil")
	}

	if int64OfAny(float64(9)) != 9 || int64OfAny(int64(8)) != 8 || int64OfAny(7) != 7 || int64OfAny("x") != 0 {
		t.Error("int64OfAny branch broke")
	}
	if f64OfAny(float64(1.5)) != 1.5 || f64OfAny(int64(2)) != 2 || f64OfAny(3) != 3 || f64OfAny("x") != 0 {
		t.Error("f64OfAny branch broke")
	}
	if trimFloat(6.0) != "6" || trimFloat(1.2) != ftoa(1.2) {
		t.Error("trimFloat must drop float noise only")
	}

	// A no-input verb's repro Cypher is the catalog text verbatim.
	if got := reproCypher(catalogVerb{Cypher: "CALL db.schema()"}, "ignored"); got != "CALL db.schema()" {
		t.Errorf("no ParamName: verbatim Cypher; got %q", got)
	}

	// A note-less flow gets the honest default; guardedCard never runs.
	fc := flowCard(catalogVerb{Proc: "flow:x", Title: "X"}, host("h.example", ""))
	if fc.Table[1].Name != "anchor step runs in console" {
		t.Errorf("the default flow note is honest: %+v", fc.Table)
	}
	gc := guardedCard(catalogVerb{Proc: "whisper.submit"}, host("h.example", ""))
	if !strings.Contains(gc.Note, "not run") {
		t.Error("the guarded write card says it did not run")
	}

	if subOf(graphNode{Props: map[string]any{"sub": 42}}) != "" {
		t.Error("a non-string sub reads empty")
	}
	if bandWord("SUSP", nil) != "SUSPICIOUS" || bandWord("MAL", nil) != "MALICIOUS" || bandWord("unknown", nil) != "UNKNOWN" {
		t.Error("the short band spellings normalise")
	}
}

// TestNodeAndGlyphHues pins the fixed type->hue language (it must NOT shift per theme)
// and the NO_COLOR plain fallback.
func TestNodeAndGlyphHues(t *testing.T) {
	th := theme.New(theme.Whisper, false, false)
	plain := theme.New(theme.Whisper, true, false)

	labelWant := map[string]interface{}{
		"HOSTNAME": stHostname, "IPV4": stIPv4, "IPV6": stIPv6, "PREFIX": stPrefix,
		"ASN": stASN, "AS": stASN, "PTR": stPTR, "EMAIL": stEmail,
	}
	for label, want := range labelWant {
		if got := nodeHue(th, label); !reflect.DeepEqual(got, want) {
			t.Errorf("nodeHue(%s) lost its fixed hue", label)
		}
		if got := nodeHue(plain, label); !reflect.DeepEqual(got, stPlain) {
			t.Errorf("NO_COLOR nodeHue(%s) must be plain", label)
		}
	}
	// Case/space liberality + the dim fallback for an unknown label.
	if got := nodeHue(th, "  hostname "); !reflect.DeepEqual(got, stHostname) {
		t.Error("nodeHue must accept case + padding liberally")
	}
	if got := nodeHue(th, "MYSTERY"); !reflect.DeepEqual(got, th.Dim) {
		t.Error("an unknown label dims, never invents a hue")
	}

	glyphWant := map[rune]interface{}{
		'⬢': stHostname, '▤': stIPv4, '▥': stIPv6, '▦': stPrefix, '◈': stASN,
		'▷': stPTR, '✉': stEmail, '⯃': stOrg, '⬡': stTLSFP, '⌾': stTLD, '⚑': stThreat,
	}
	for r, want := range glyphWant {
		if got := glyphHue(th, r); !reflect.DeepEqual(got, want) {
			t.Errorf("glyphHue(%c) lost its fixed hue", r)
		}
	}
	if got := glyphHue(th, '?'); !reflect.DeepEqual(got, th.Dim) {
		t.Error("an unknown glyph dims")
	}
	if got := glyphHue(plain, '⬢'); !reflect.DeepEqual(got, stPlain) {
		t.Error("NO_COLOR glyphHue must be plain")
	}
	// styledGlyphs keeps the exact rune sequence (width invariant).
	if got := strip(styledGlyphs(th, []string{"IPV4", "FEED"})); got != "▤⚑" {
		t.Errorf("styledGlyphs must not change the glyph string: %q", got)
	}
}

// --- chain rows for the non dns/conn kinds ------------------------------------------

// TestChainRowOtherKinds covers the alloc row, the invisible heartbeat, and the honest
// unknown-kind fallback.
func TestChainRowOtherKinds(t *testing.T) {
	a := newTestApp(t, 120, 40)
	alloc := strip(a.renderChainRow(model.Event{Kind: "alloc", TsMicros: 1,
		Addr128: "2a04:2a01::9", Action: "identity"}, 100, 0, false))
	if !strings.Contains(alloc, "aloc") || !strings.Contains(alloc, "identity") || !strings.Contains(alloc, "2a04:2a01::9") {
		t.Errorf("the alloc row names its action + /128: %q", alloc)
	}
	if got := a.renderChainRow(model.Event{Kind: "hb"}, 100, 0, false); got != "" {
		t.Errorf("a heartbeat renders nothing: %q", got)
	}
	if got := a.renderChainRow(model.Event{Kind: ""}, 100, 0, false); got != "" {
		t.Errorf("an empty kind renders nothing: %q", got)
	}
	other := strip(a.renderChainRow(model.Event{Kind: "audit", TsMicros: 2}, 100, 0, false))
	if !strings.Contains(other, "audit") {
		t.Errorf("an unknown kind still renders honestly: %q", other)
	}
}

// --- Update arms not yet exercised ---------------------------------------------------

// TestUpdateStreamAndExploreArms drives the remaining Update routes end to end.
func TestUpdateStreamAndExploreArms(t *testing.T) {
	a := newTestApp(t, 100, 30)

	// A live stream event folds and re-arms.
	a.Update(streamEventMsg{event: model.Event{Kind: "dns", TsMicros: 1, QName: "x.", Decision: "allow"}})
	if a.feed.len() != 1 {
		t.Error("streamEventMsg must fold into the feed")
	}

	// A stale backfill via Update is dropped whole.
	a.backfillToken = 7
	a.Update(monitorBackfillMsg{token: 1, events: []model.Event{{Kind: "dns", TsMicros: 9}}})
	if a.feed.len() != 1 {
		t.Error("a stale backfill must be dropped at the Update seam too")
	}

	// A poll fold while down re-arms the chain.
	a.stream = streamRetry
	if _, cmd := a.Update(monitorPollMsg{events: nil}); cmd == nil {
		t.Error("a down-stream poll must re-arm")
	}

	// streamRestartMsg re-arms the SSE goroutine.
	if _, cmd := a.Update(streamRestartMsg{}); cmd == nil {
		t.Error("streamRestartMsg must restart the stream")
	}
	a.stopStream()

	// The EXPLORE async arms route into the view with the token discipline intact.
	a.exploreVw.token = 3
	a.exploreVw.deck.live = true
	a.Update(focusMsg{token: 3, node: graphNode{Labels: []string{"HOSTNAME"}, Value: "cloudflare.com",
		Props: map[string]any{"rir": "ARIN"}, Band: "BENIGN"}})
	if len(a.exploreVw.deck.focus.Labels) != 1 || a.exploreVw.deck.focus.Band != "BENIGN" {
		t.Errorf("focusMsg must fold labels + band: %+v", a.exploreVw.deck.focus)
	}
	a.Update(enrichMsg{token: 3, value: a.exploreVw.deck.focus.Value, err: &client.ProblemError{Status: 500}})
	// enrichment failures are silent (a bonus, never load-bearing): no toast, no degrade.
	if a.exploreVw.degraded {
		t.Error("an enrich error must not degrade the deck")
	}
	a.Update(focusMsg{token: 3, err: &client.ProblemError{Status: 503, Detail: "down"}})
	if !a.exploreVw.degraded {
		t.Error("a focus transport error degrades calmly")
	}
	a.Update(searchMsg{}) // reserved: must simply not blow up
}

// TestUpdateForwardsToOpenForm pins the fix at the Update seam: a non-key message
// while a form overlay is open is forwarded to the form (huh drives itself through its
// own messages), and the palette's input gets them too.
func TestUpdateForwardsToOpenForm(t *testing.T) {
	type deepentui_alienMsg struct{}
	a := newTestApp(t, 100, 30)
	deepentui_seedAgents(a)

	a.openCreate()
	if _, _ = a.Update(deepentui_alienMsg{}); a.overlay != overlayCreate {
		t.Error("a foreign message must forward to the create form, not close it")
	}
	a.overlay = overlayNone

	a.openKill()
	if _, _ = a.Update(deepentui_alienMsg{}); a.overlay != overlayKill {
		t.Error("a foreign message must forward to the kill form")
	}
	a.overlay = overlayNone

	a.openConnect()
	if _, _ = a.Update(deepentui_alienMsg{}); a.overlay != overlayConnect {
		t.Error("a foreign message must forward to the connect form")
	}
	a.overlay = overlayNone

	a.openPalette()
	if _, _ = a.Update(deepentui_alienMsg{}); a.overlay != overlayPalette {
		t.Error("the palette input needs its cursor-blink messages")
	}
	a.overlay = overlayNone

	// With no overlay, a foreign message is simply absorbed.
	if _, cmd := a.Update(deepentui_alienMsg{}); cmd != nil {
		t.Error("an unknown message with no overlay is a calm no-op")
	}
}

// --- stream guard branches -----------------------------------------------------------

// TestStartStreamSingleFlightGuard pins the one-goroutine-at-a-time token: while the
// token is held, startStream backs off with a re-arm tick instead of double-binding.
func TestStartStreamSingleFlightGuard(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.streamMu <- struct{}{} // simulate a goroutine still holding the token
	cmd := a.startStream()
	if cmd == nil {
		t.Fatal("a held token still returns the re-arm tick")
	}
	if a.streamCh != nil {
		t.Error("a held token must NOT bind a channel")
	}
	if _, ok := cmd().(streamRestartMsg); !ok {
		t.Error("the re-arm tick must deliver streamRestartMsg")
	}
	<-a.streamMu
}

// TestWaitStreamClosedChannel asserts a closed channel unblocks as streamIdle (the
// no-leak contract for a pending waitStream after a restart).
func TestWaitStreamClosedChannel(t *testing.T) {
	a := newTestApp(t, 100, 30)
	ch := make(chan tea.Msg)
	close(ch)
	a.streamCh = ch
	msg := a.waitStream()()
	if st, ok := msg.(streamStateMsg); !ok || st.state != streamIdle {
		t.Errorf("a closed channel must yield streamIdle; got %#v", msg)
	}
}

// --- the remaining agents-view verbs -------------------------------------------------

// TestAgentsActionKeys sweeps the fleet action keys not covered elsewhere: n/N motion,
// home/end, half-page, unfocus, drill, kill, RDAP, yank, kind filter, esc-clears-filter,
// and the empty-fleet watch refusal.
func TestAgentsActionKeys(t *testing.T) {
	a := newTestApp(t, 120, 40)
	deepentui_seedAgents(a)
	v := a.agentsView

	v.handleKey(deepentui_rune('n'))
	if a.selected != v.orderedIndices()[1] {
		t.Error("n advances the selection")
	}
	v.handleKey(deepentui_rune('N'))
	if a.selected != v.orderedIndices()[0] {
		t.Error("N steps back")
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnd})
	if a.selected != v.orderedIndices()[2] {
		t.Error("end jumps to the tail")
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyHome})
	if a.selected != v.orderedIndices()[0] {
		t.Error("home jumps to the head")
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	v.handleKey(tea.KeyMsg{Type: tea.KeyCtrlU})
	if a.selected != v.orderedIndices()[0] {
		t.Error("half-page down+up round-trips")
	}

	// a unfocuses a pinned monitor with the (all) toast.
	a.monitorVw.focused = "2a04:2a01::1"
	_, cmd := v.handleKey(deepentui_rune('a'))
	if a.monitorVw.focused != "" || cmd == nil || !strings.Contains(a.toast, "(all)") {
		t.Error("a returns to the explicit (all) scope")
	}
	// a again is a calm no-op.
	if _, cmd = v.handleKey(deepentui_rune('a')); cmd != nil {
		t.Error("an already-(all) scope has nothing to do")
	}

	v.handleKey(deepentui_rune('d'))
	if a.overlay != overlayDrill {
		t.Error("d drills the selected agent")
	}
	a.overlay = overlayNone
	v.handleKey(deepentui_rune('x'))
	if a.overlay != overlayKill {
		t.Error("x opens the kill modal")
	}
	a.overlay = overlayNone
	v.handleKey(deepentui_rune('v'))
	if a.overlay != overlayResult {
		t.Error("v opens the RDAP card")
	}
	a.overlay = overlayNone
	v.handleKey(deepentui_rune('y'))
	if !strings.Contains(a.toast, "2a04:2a01::") {
		t.Error("y yanks the address")
	}
	v.handleKey(deepentui_rune('f'))
	if !strings.Contains(a.toast, "kind filter: dns") {
		t.Errorf("f cycles the feed kind; toast=%q", a.toast)
	}

	v.filter = "scr"
	v.recomputeMatches()
	v.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if v.filter != "" {
		t.Error("esc clears an applied filter")
	}

	// An empty fleet refuses the watch with a toast, not a crash.
	b := newTestApp(t, 120, 40)
	b.agents = nil
	if _, cmd := b.agentsView.watchSelected(); cmd != nil || !b.toastErr {
		t.Error("watching an empty fleet is a friendly refusal")
	}
}

// TestRefreshSelectedDetailSkipsEnriched pins the no-refetch contract for an already
// detailed selection.
func TestRefreshSelectedDetailSkipsEnriched(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.agents = []model.Agent{{ID: "a1", Address: "2a04:2a01::1", Detailed: true}}
	a.selected = 0
	if a.refreshSelectedDetail() != nil {
		t.Error("an enriched selection needs no refetch")
	}
	a.agents[0].Detailed = false
	if a.refreshSelectedDetail() == nil {
		t.Error("an un-enriched selection fetches its detail")
	}
}

// TestLogsMoveBothWays covers the wheel-path move helper in both directions.
func TestLogsMoveBothWays(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	v.onLogs(logsMsg{token: v.token, events: []model.Event{
		{Kind: "dns", TsMicros: 1}, {Kind: "dns", TsMicros: 2}, {Kind: "dns", TsMicros: 3},
	}})
	v.move(2)
	if v.tbl.Cursor() != 2 {
		t.Errorf("move(+2) lands on row 2; got %d", v.tbl.Cursor())
	}
	v.move(-1)
	if v.tbl.Cursor() != 1 {
		t.Errorf("move(-1) steps back; got %d", v.tbl.Cursor())
	}
}

// TestJoinCacheFloorAndConfigResize covers two tiny liberal-floor branches.
func TestJoinCacheFloorAndConfigResize(t *testing.T) {
	j := newJoinCache(0)
	j.observeDNS("2a04:2a01::1", "a.example.", 1)
	j.observeDNS("2a04:2a01::2", "b.example.", 2)
	if j.len() != 1 {
		t.Errorf("a zero capacity clamps to 1; len=%d", j.len())
	}
	a := newTestApp(t, 100, 30)
	a.configView.resize(80, 24)
	if a.configView.w != 80 || a.configView.h != 24 {
		t.Error("the config view records its geometry")
	}
}
