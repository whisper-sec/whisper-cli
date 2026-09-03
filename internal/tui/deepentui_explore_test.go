// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// deepentui_keyedExploreApp builds an EXPLORE app whose client carries a key (so the
// live paths arm) WITHOUT ever invoking the returned network closures.
func deepentui_keyedExploreApp(t *testing.T, deck deckState) *App {
	t.Helper()
	kc := client.New(client.Config{Cred: client.Credential{Value: "whisper-0000000000000000"}})
	a := New(Options{Client: kc, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 100, Height: 34})
	a.loading = false
	a.mode = modeExplore
	a.exploreVw.loadDeck(deck)
	a.layout()
	return a
}

// TestExploreDeckNavigation drives the Miller-column cursor: list motion clamps in both
// panes, pane switching, edge stepping, gg/G, and the peek preview.
func TestExploreDeckNavigation(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	if v.activePane != paneFocus {
		t.Fatal("a fresh deck starts on the focus pane")
	}

	// Edge-cursor motion clamps at both ends.
	v.handleKey(deepentui_rune('k'))
	if v.deck.edgeCur != 0 {
		t.Error("k at the top clamps")
	}
	for i := 0; i < len(v.deck.edges)+3; i++ {
		v.handleKey(deepentui_rune('j'))
	}
	if v.deck.edgeCur != len(v.deck.edges)-1 {
		t.Errorf("j must clamp at the last edge; got %d", v.deck.edgeCur)
	}

	// gg goes top (the pendingG chord), G goes bottom.
	v.handleKey(deepentui_rune('g'))
	if !v.pendingG {
		t.Fatal("the first g arms the chord")
	}
	v.handleKey(deepentui_rune('g'))
	if v.deck.edgeCur != 0 || v.pendingG {
		t.Error("gg must land on the first edge and clear the chord")
	}
	// Any other key between the two g's cancels the chord.
	v.handleKey(deepentui_rune('g'))
	v.handleKey(deepentui_rune('j'))
	if v.pendingG {
		t.Error("a non-g key must cancel the pending chord")
	}
	v.handleKey(deepentui_rune('G'))
	if v.deck.edgeCur != len(v.deck.edges)-1 {
		t.Error("G must land on the last edge")
	}

	// l enters the neighbour pane; j/k move the neighbour cursor with its own clamp.
	v.handleKey(deepentui_rune('g'))
	v.handleKey(deepentui_rune('g'))
	v.handleKey(deepentui_rune('l'))
	if v.activePane != paneNeighbors {
		t.Fatal("l must move into the neighbour pane")
	}
	n := len(v.curEdge().Sample)
	for i := 0; i < n+3; i++ {
		v.handleKey(deepentui_rune('j'))
	}
	if v.deck.nbrCur != n-1 {
		t.Errorf("the neighbour cursor clamps at %d; got %d", n-1, v.deck.nbrCur)
	}
	v.handleKey(deepentui_rune('G'))
	if v.deck.nbrCur != n-1 {
		t.Error("G in the neighbour pane lands on the last neighbour")
	}
	v.handleKey(deepentui_rune('g'))
	v.handleKey(deepentui_rune('g'))
	if v.deck.nbrCur != 0 {
		t.Error("gg in the neighbour pane lands on the first neighbour")
	}

	// space peeks (no travel), naming the neighbour in the toast.
	v.handleKey(deepentui_rune(' '))
	if !strings.Contains(a.toast, "peek:") {
		t.Errorf("space should peek; toast=%q", a.toast)
	}
	if v.deck.focus.Value != "cloudflare.com" {
		t.Error("peek must never travel")
	}

	// h returns to the focus pane; [ ] step the edge cursor.
	v.handleKey(deepentui_rune('h'))
	if v.activePane != paneFocus {
		t.Error("h must return to the focus pane")
	}
	v.handleKey(deepentui_rune(']'))
	if v.deck.edgeCur != 1 {
		t.Errorf("] steps the edge cursor; got %d", v.deck.edgeCur)
	}
	v.handleKey(deepentui_rune('['))
	if v.deck.edgeCur != 0 {
		t.Errorf("[ steps back; got %d", v.deck.edgeCur)
	}

	// esc leaves EXPLORE for the operational home.
	v.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if a.mode != modeAgents {
		t.Error("esc must land back on AGENTS")
	}
}

// TestExploreOrnamentAndOverlayKeys covers the ornament cycle and the o / / / :
// overlay openers.
func TestExploreOrnamentAndOverlayKeys(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	if v.orn != ornConstellation {
		t.Fatal("the ornament starts as the constellation")
	}
	v.handleKey(deepentui_rune('z'))
	if v.orn != ornCluster || !strings.Contains(a.toast, "cluster") {
		t.Error("z cycles to cluster")
	}
	v.handleKey(deepentui_rune('z'))
	if v.orn != ornOff || !strings.Contains(a.toast, "off") {
		t.Error("z cycles to off")
	}
	v.handleKey(deepentui_rune('z'))
	if v.orn != ornConstellation {
		t.Error("z wraps back to the constellation")
	}
	if ornamentName(ornCluster) != "cluster" || ornamentName(ornOff) != "off" ||
		ornamentName(ornConstellation) != "constellation" {
		t.Error("ornamentName must name all three modes")
	}

	v.handleKey(deepentui_rune('o'))
	if v.ov != ovCatalog {
		t.Error("o opens the catalog")
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEscape})
	if v.ov != ovNone {
		t.Error("esc closes the catalog")
	}
	v.handleKey(deepentui_rune('/'))
	if v.ov != ovJump || v.jump.query != "" {
		t.Error("/ opens a fresh JUMP")
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEscape})
	v.handleKey(deepentui_rune(':'))
	if v.ov != ovRepl {
		t.Error(": opens the REPL bar")
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if v.ov != ovNone {
		t.Error("enter closes the REPL bar")
	}
}

// TestExploreJumpUnicodeInput pins the fix in the overlay: bracketed paste (multi-
// rune KeyMsg) lands whole, backspace deletes RUNES not bytes, tab flips the list.
func TestExploreJumpUnicodeInput(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.handleKey(deepentui_rune('/'))
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("exämple.org")})
	if v.jump.query != "exämple.org" {
		t.Fatalf("a pasted multi-rune payload must land whole; got %q", v.jump.query)
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if v.jump.query != "exämple.or" {
		t.Fatalf("backspace must delete one RUNE; got %q", v.jump.query)
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyTab})
	if !v.jump.onAgents {
		t.Error("tab flips onto the agents list")
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyDown})
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyDown})
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyUp})
	if v.jump.cursor != 1 {
		t.Errorf("arrow keys drive the cursor; got %d", v.jump.cursor)
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyUp})
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyUp})
	if v.jump.cursor != 0 {
		t.Errorf("the cursor clamps at 0; got %d", v.jump.cursor)
	}
	if trimLastRune("") != "" {
		t.Error("trimLastRune on empty is a no-op")
	}
}

// TestExploreJumpBackspaceRuneBoundary strengthens the pin: a backspace whose
// last character IS a multibyte rune must delete the whole RUNE, not one byte. A byte
// truncation of "cafe<0xc3 0xa9>" would leave the invalid UTF-8 "caf\xc3"; the earlier
// TestExploreJumpUnicodeInput only ever backspaced an ASCII tail, so it never exercised
// this boundary (a byte-truncating trimLastRune still passed it).
func TestExploreJumpBackspaceRuneBoundary(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.handleKey(deepentui_rune('/'))
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("café")})
	if v.jump.query != "café" {
		t.Fatalf("paste must land whole; got %q", v.jump.query)
	}
	v.handleOverlayKey(tea.KeyMsg{Type: tea.KeyBackspace}) // must delete the whole 'é'
	if v.jump.query != "caf" {
		t.Fatalf("backspace at a multibyte boundary must delete the whole rune; got %q", v.jump.query)
	}
	if !utf8.ValidString(v.jump.query) {
		t.Fatalf("rune-safe backspace must leave valid UTF-8; got % x", v.jump.query)
	}
}

// TestExploreFixtureWalkAndBack drives the keyless demo walk: a linked fixture walks the
// whole deck, an unlinked node walks shallow and says so, and backspace pops the trail.
func TestExploreFixtureWalkAndBack(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw

	// walkIn from the focus pane only moves the pane.
	if v.walkIn() != nil {
		t.Fatal("a fixture walk never returns a network command")
	}
	if v.activePane != paneNeighbors {
		t.Fatal("walkIn from focus moves into the neighbour pane")
	}

	// Select the RESOLVES_TO sample and walk onto the linked mega-fanout fixture.
	v.deck.edgeCur, v.deck.nbrCur = 0, 0
	target := v.curEdge().Sample[0].Value
	if target != "104.16.132.229" {
		t.Fatalf("fixture layout changed; got %q", target)
	}
	v.walkIn()
	if v.deck.focus.Value != "104.16.132.229" {
		t.Fatalf("the linked fixture must land whole; got %q", v.deck.focus.Value)
	}
	if len(v.deck.trail) != 1 || v.deck.trail[0].Value != "cloudflare.com" {
		t.Fatalf("the walk must extend the trail: %+v", v.deck.trail)
	}
	if len(v.deck.edges) == 0 {
		t.Error("the linked deck carries its own edges")
	}

	// Walk onto an unlinked neighbour: a shallow honest deck. Search the deck for a
	// sample value that has no linked fixture (fixtureWalk table membership).
	v.activePane = paneNeighbors
	sel := ""
	for ei, e := range v.deck.edges {
		for ni, s := range e.Sample {
			if _, linked := fixtureWalk(s.Value); !linked {
				v.deck.edgeCur, v.deck.nbrCur, sel = ei, ni, s.Value
			}
		}
	}
	if sel == "" {
		t.Fatal("the fixture must offer at least one unlinked neighbour")
	}
	v.walkIn()
	if v.deck.focus.Value != sel {
		t.Fatalf("the shallow walk still lands the node; got %q", v.deck.focus.Value)
	}
	if len(v.deck.edges) != 0 {
		t.Error("an unlinked fixture walk has honestly empty edges")
	}
	if !strings.Contains(a.toast, "no linked deck") {
		t.Errorf("the shallow walk says so; toast=%q", a.toast)
	}

	// backspace pops back; H returns to the root and clears the history.
	v.handleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if v.deck.focus.Value != "104.16.132.229" {
		t.Errorf("back must pop one step; got %q", v.deck.focus.Value)
	}
	v.handleKey(deepentui_rune('H'))
	if v.deck.focus.Value != "cloudflare.com" || len(v.history) != 0 {
		t.Errorf("H must land on the trail root; got %q", v.deck.focus.Value)
	}
	// With no history, both are calm no-ops.
	v.ascendTrail()
	v.trailRoot()
	if v.deck.focus.Value != "cloudflare.com" {
		t.Error("back/root with no history must not move")
	}
}

// TestExploreNeighborsFold covers the +200 paging fold: replace at off=0, append at an
// offset, the stale-token drop, and the error toast.
func TestExploreNeighborsFold(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.token = 4
	edge := v.deck.edges[0].Type
	was := len(v.deck.edges[0].Sample)

	// A stale reply is dropped whole.
	v.onNeighbors(neighborsMsg{token: 3, edgeType: edge, sample: []graphNode{host("stale.example", "")}})
	if len(v.deck.edges[0].Sample) != was {
		t.Fatal("a stale neighbours reply must be dropped")
	}

	// off=0 replaces the sample.
	v.onNeighbors(neighborsMsg{token: 4, edgeType: edge, off: 0,
		sample: []graphNode{host("fresh.example", "")}})
	if len(v.deck.edges[0].Sample) != 1 || v.deck.edges[0].Sample[0].Value != "fresh.example" {
		t.Fatalf("off=0 must replace: %+v", v.deck.edges[0].Sample)
	}

	// off=len appends the next page.
	v.onNeighbors(neighborsMsg{token: 4, edgeType: edge, off: 1,
		sample: []graphNode{host("page2.example", "")}})
	if len(v.deck.edges[0].Sample) != 2 || v.deck.edges[0].Sample[1].Value != "page2.example" {
		t.Fatalf("a paged reply must append: %+v", v.deck.edges[0].Sample)
	}
	if v.deck.edges[0].off != 2 {
		t.Errorf("the paging offset tracks the sample; got %d", v.deck.edges[0].off)
	}

	// An errored page is a toast, not a wipe.
	v.onNeighbors(neighborsMsg{token: 4, edgeType: edge,
		err: &client.ProblemError{Status: 500, Detail: "page sad"}})
	if len(v.deck.edges[0].Sample) != 2 {
		t.Error("an errored page keeps the loaded sample")
	}
	if !strings.Contains(a.toast, "page sad") {
		t.Errorf("the page error should toast; got %q", a.toast)
	}
}

// TestExploreVerbResultFold covers the RESULT fold + its stale/error paths.
func TestExploreVerbResultFold(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.token = 2
	v.onVerbResult(verbResultMsg{token: 1, card: resultCard{Verb: "stale"}})
	if len(v.results) != 0 {
		t.Fatal("a stale verb result must be dropped")
	}
	v.onVerbResult(verbResultMsg{token: 2, card: resultCard{Verb: "whisper.assess"}})
	if len(v.results) != 1 || !strings.Contains(a.toast, "ran whisper.assess") {
		t.Fatalf("a fresh result must fold + toast; results=%d toast=%q", len(v.results), a.toast)
	}
	v.onVerbResult(verbResultMsg{token: 2, err: &client.ProblemError{Status: 500, Detail: "verb sad"}})
	if len(v.results) != 1 || !strings.Contains(a.toast, "verb sad") {
		t.Error("an errored verb is a toast, never a fake card")
	}
}

// TestExploreFailOpenSeverity pins the outage semantics: a 4xx user problem is a toast
// only; a 5xx/transport (and a 401) paints the calm degraded banner.
func TestExploreFailOpenSeverity(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	v.failOpen(&client.ProblemError{Status: 404, Detail: "no such node"})
	if v.degraded {
		t.Error("a 404 is the user's typo, not an outage")
	}
	if !strings.Contains(a.toast, "no such node") {
		t.Error("the 4xx detail should toast")
	}
	v.failOpen(&client.ProblemError{Status: 503, Detail: "graph down"})
	if !v.degraded {
		t.Error("a 5xx paints the degraded state")
	}
	v.degraded = false
	v.failOpen(&client.ProblemError{Status: 401, Detail: "key rejected"})
	if !v.degraded {
		t.Error("a 401 is an outage-grade condition (the whole surface is keyed)")
	}
}

// TestExploreRunVerbHonesty pins runSelectedVerb's four arms: a keyless direct verb
// stays on the fixture card; a live keyed direct verb fires the network run; the cursor
// bound is honest.
func TestExploreRunVerbHonesty(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	applicable := applicableCatalog(v.deck.focus.Labels)
	direct := -1
	for i, cv := range applicable {
		if !cv.Flow && !cv.Write {
			direct = i
			break
		}
	}
	if direct < 0 {
		t.Fatal("a HOSTNAME must offer a direct verb")
	}

	v.catalog.cursor = len(applicable) + 5
	if v.runSelectedVerb(applicable) != nil || len(v.results) != 0 {
		t.Fatal("an out-of-range cursor runs nothing")
	}

	v.catalog.cursor = direct
	if cmd := v.runSelectedVerb(applicable); cmd != nil {
		t.Fatal("a keyless direct verb must stay on the fixture, never dial")
	}
	if len(v.results) != 1 || !strings.Contains(a.toast, "(fixture)") {
		t.Fatalf("the fixture run must say so; toast=%q", a.toast)
	}

	// Keyed + live: the direct verb fires the real run.
	b := deepentui_keyedExploreApp(t, fixtureCloudflare())
	bv := b.exploreVw
	bv.deck.live = true
	bv.catalog.cursor = direct
	if cmd := bv.runSelectedVerb(applicable); cmd == nil {
		t.Fatal("a keyed live direct verb must fire the network run")
	}
	if !strings.Contains(b.toast, "running ") {
		t.Errorf("the live run announces itself; toast=%q", b.toast)
	}
}

// TestExploreReloadAndJumpLive covers the keyed live arms that never dial in the
// keyless suite: reload re-lands under a fresh token; jumpLand parses liberally and
// lands live.
func TestExploreReloadAndJumpLive(t *testing.T) {
	a := deepentui_keyedExploreApp(t, fixtureCloudflare())
	v := a.exploreVw
	v.degraded = true
	tok := v.token
	if v.reload() == nil {
		t.Fatal("a keyed reload must fire the three loads")
	}
	if v.token != tok+1 || v.degraded || !v.loadingFocus || !v.loadingEdges {
		t.Error("reload must mint a token, clear degraded, and mark loading")
	}

	// An empty focus reloads nothing (no phantom fetch).
	b := deepentui_keyedExploreApp(t, deckState{})
	if b.exploreVw.reload() != nil {
		t.Error("an empty deck has nothing to reload")
	}

	// jumpLand: liberal parse (scheme + path + case), the overlay closes, the deck
	// re-roots provisionally.
	v.ov = ovJump
	v.jump.query = "https://API.Example.COM/v1/x"
	if v.jumpLand() == nil {
		t.Fatal("a keyed jump must land live")
	}
	if v.ov != ovNone {
		t.Error("jump closes on land")
	}
	if v.deck.focus.Value != "api.example.com" {
		t.Errorf("the jump must land the normalised node; got %q", v.deck.focus.Value)
	}

	// An empty query is a friendly prompt, not a jump.
	v.ov = ovJump
	v.jump.query = "   "
	if v.jumpLand() != nil {
		t.Error("an empty query lands nothing")
	}
	if !strings.Contains(a.toast, "type a node") {
		t.Errorf("the empty query should prompt; toast=%q", a.toast)
	}
}

// TestExploreExpandNeighborsGates covers the x paging gates: keyless refusal, an
// already-complete edge, and the empty-edge no-op.
func TestExploreExpandNeighborsGates(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	if v.expandNeighbors() != nil {
		t.Fatal("keyless expand must not dial")
	}
	if !strings.Contains(a.toast, "needs a live deck") {
		t.Errorf("the keyless refusal explains itself; toast=%q", a.toast)
	}

	b := deepentui_keyedExploreApp(t, fixtureCloudflare())
	bv := b.exploreVw
	bv.deck.live = true
	// The fixture's first edge sample already holds >= its Total: fully loaded.
	bv.deck.edges[0].Total = int64(len(bv.deck.edges[0].Sample))
	if bv.expandNeighbors() != nil {
		t.Error("a fully-loaded edge must not re-page")
	}
	if !strings.Contains(b.toast, "fully loaded") {
		t.Errorf("the fully-loaded state says so; toast=%q", b.toast)
	}
	// A genuinely partial edge fires the page.
	bv.deck.edges[0].Total = int64(len(bv.deck.edges[0].Sample)) + 500
	if bv.expandNeighbors() == nil {
		t.Error("a partial edge must page")
	}
	if !bv.loadingNbrs {
		t.Error("paging marks loadingNbrs")
	}
	// An empty deck pages nothing.
	c := deepentui_keyedExploreApp(t, deckState{})
	c.exploreVw.deck.live = true
	if c.exploreVw.expandNeighbors() != nil {
		t.Error("no edge selected: nothing to page")
	}
}

// TestExploreHydrateCacheDiscipline pins when a deck may be cached: only live, only
// fully landed, and never keyed on an empty value.
func TestExploreHydrateCacheDiscipline(t *testing.T) {
	a := deepentui_keyedExploreApp(t, fixtureCloudflare())
	v := a.exploreVw
	v.deck.cache = newLRU(4)

	v.deck.live = false
	v.hydrateCache()
	if _, ok := v.deck.cache.get("cloudflare.com"); ok {
		t.Fatal("a fixture deck must never enter the live cache")
	}

	v.deck.live = true
	v.loadingFocus = true
	v.hydrateCache()
	if _, ok := v.deck.cache.get("cloudflare.com"); ok {
		t.Fatal("a half-landed deck must not be cached")
	}

	v.loadingFocus, v.loadingEdges = false, false
	v.deck.trail = []graphNode{host("parent.example", "")}
	v.hydrateCache()
	hit, ok := v.deck.cache.get("cloudflare.com")
	if !ok {
		t.Fatal("a fully-landed live deck must cache")
	}
	if hit.trail != nil {
		t.Error("the cached deck must shed its trail (the trail belongs to the walk)")
	}
}

// TestExploreFixtureVerbCards pins fixtureVerbResult's four shapes and fixtureWalk's
// link table.
func TestExploreFixtureVerbCards(t *testing.T) {
	focus := host("paypal.com", "")
	byName := map[string]catalogVerb{}
	for _, cv := range loadCatalog() {
		byName[cv.Name] = cv
	}
	if c := fixtureVerbResult(byName["assess"], focus); c.Shape != shapeBand {
		t.Error("the assess fixture is the band card")
	}
	if c := fixtureVerbResult(byName["variants"], focus); c.Shape != shapeRanked || len(c.Table) == 0 {
		t.Error("the variants fixture is the ranked table")
	}
	var flow catalogVerb
	for _, cv := range loadCatalog() {
		if cv.Flow {
			flow = cv
			break
		}
	}
	if c := fixtureVerbResult(flow, focus); !strings.Contains(c.Table[0].Name, "console") {
		t.Errorf("a flow fixture stays honest: %+v", c)
	}
	if c := fixtureVerbResult(byName["identify"], focus); !strings.Contains(c.Note, "keyless fixture") {
		t.Errorf("a plain direct verb names the demo: %+v", c)
	}

	if _, ok := fixtureWalk("104.16.132.229"); !ok {
		t.Error("the mega-fanout link must exist")
	}
	if _, ok := fixtureWalk("AS13335"); !ok {
		t.Error("the ASN link must exist")
	}
	if _, ok := fixtureWalk("nowhere.example"); ok {
		t.Error("an unknown value must not pretend to link")
	}
}

// TestExplorePureHelpers sweeps the small pure functions: normalizeRef, asnOf, isIPv4,
// humanCommas, anyToStr, glyphsFor, bandWord/bandTag, matchKeyFor, catalogDocURL,
// nodeKinds, curEdge on an empty deck.
func TestExplorePureHelpers(t *testing.T) {
	refCases := []struct{ in, kind, val string }{
		{"https://API.OpenAI.com/v1/models", "HOSTNAME", "api.openai.com"},
		{"dns://example.org.", "HOSTNAME", "example.org"},
		{"user@Example.COM", "EMAIL", "user@example.com"},
		{"AS13335", "ASN", "AS13335"},
		{"13335", "ASN", "AS13335"},
		{"1.2.3.4.", "IPV4", "1.2.3.4"},
		{"2606:4700::1111", "IPV6", "2606:4700::1111"},
		{"  ", "", ""},
		{"http://", "", ""},
	}
	for _, tc := range refCases {
		kind, val := normalizeRef(tc.in)
		if kind != tc.kind || val != tc.val {
			t.Errorf("normalizeRef(%q) = %q,%q want %q,%q", tc.in, kind, val, tc.kind, tc.val)
		}
	}

	if asnOf("as0x") != "" || asnOf("AS") != "" || asnOf("as42") != "AS42" {
		t.Error("asnOf must accept only digit tails")
	}
	for _, bad := range []string{"1.2.3", "1.2.3.4.5", "999.1.1.1", "1..2.3", "1.2.3.1234"} {
		if isIPv4(bad) {
			t.Errorf("isIPv4(%q) must be false", bad)
		}
	}
	if humanCommas(1240000) != "1,240,000" || humanCommas(-4200) != "-4,200" || humanCommas(7) != "7" {
		t.Error("humanCommas broke")
	}

	if anyToStr(7) != "7" || anyToStr(int64(8)) != "8" || anyToStr(2.5) != "2.5" ||
		anyToStr(float64(3)) != "3" || anyToStr(true) != "true" || anyToStr([]int{1}) != "" {
		t.Error("anyToStr branch broke")
	}

	if glyphsFor(nil) != glyphUnknown {
		t.Error("no labels reads the unknown glyph")
	}
	if g := glyphsFor([]string{"IPV4", "FEED"}); g != "▤⚑" {
		t.Errorf("a multi-label node stacks canonical-order glyphs; got %q", g)
	}
	if g := glyphsFor([]string{"WEIRD_NEW"}); g != glyphUnknown {
		t.Errorf("an unmapped label reads the dotted circle; got %q", g)
	}

	if bandWord("BENIGN", []string{"IPV4"}) != "CLEAN" || bandWord("BENIGN", []string{"HOSTNAME"}) != "BENIGN" {
		t.Error("BENIGN reads CLEAN only for IPs")
	}
	if bandWord("", nil) != "not assessed" || bandTag("", nil) != "n/a" {
		t.Error("the empty band is honestly unassessed")
	}
	if bandTag("MALICIOUS", nil) != "MAL" || bandTag("BENIGN", []string{"IPV6"}) != "clean" {
		t.Error("bandTag branch broke")
	}

	if matchKeyFor(node("ASN", "AS1", "")) != "asn" ||
		matchKeyFor(ipv4("1.2.3.4", "", nil)) != "address" ||
		matchKeyFor(node("EMAIL", "a@b.c", "")) != "address" ||
		matchKeyFor(host("x.example", "")) != "name" {
		t.Error("matchKeyFor mapping broke")
	}

	if !strings.Contains(catalogDocURL(catalogVerb{}), "http") {
		t.Error("a pathless verb still links the docs base")
	}
	if u := catalogDocURL(catalogVerb{DocPath: "/docs/verbs/assess"}); !strings.HasSuffix(u, "/docs/verbs/assess") {
		t.Errorf("the doc path must append cleanly: %q", u)
	}

	k := nodeKinds([]string{"IPV6", "ORG"})
	if !k["ipv6"] || !k["ip"] || !k["org"] || !k["any"] || k["hostname"] {
		t.Errorf("nodeKinds union wrong: %v", k)
	}

	var empty exploreView
	if e := empty.curEdge(); e.Type != "" {
		t.Error("curEdge on an empty deck is the zero group")
	}
}

// TestExploreRenderHelpers pins the REPL bar and the vendor/timeline/conf renderers.
func TestExploreRenderHelpers(t *testing.T) {
	a := newExploreApp(t, 100, 34, true, fixtureCloudflare())
	v := a.exploreVw
	repl := strings.Join(v.renderReplBar(90), "\n")
	if !strings.Contains(repl, "MATCH (n {name:$v})") || !strings.Contains(repl, "$v = cloudflare.com") {
		t.Errorf("the REPL bar previews the anchored query: %q", repl)
	}
	if !strings.Contains(repl, "whisper query") {
		t.Error("the REPL bar honestly points at what runs TODAY")
	}

	th := a.th
	vendor := renderResultCard(resultCard{Verb: "whisper.identify", Shape: shapeVendor, MS: 12, Table: []resultRow{
		{Method: "canonical_name_extra_long", Name: "Cloudflare, Inc."},
		{Method: "roles", Name: "cdn · dns"},
	}, Note: "note here"}, 60, th)
	joined := strip(strings.Join(vendor, "\n"))
	if !strings.Contains(joined, "Cloudflare, Inc.") || !strings.Contains(joined, "note here") {
		t.Errorf("the vendor card renders keys+note: %q", joined)
	}

	timeline := renderResultCard(resultCard{Verb: "whisper.explain", Shape: shapeTimeline, Table: []resultRow{
		{Method: "2010-07-14", Name: "registered (ARIN)"},
	}}, 60, th)
	if !strings.Contains(strip(strings.Join(timeline, "\n")), "registered (ARIN)") {
		t.Error("the timeline card renders its rows")
	}

	if got := strip(confBar(0.97, 6, th)); strings.Count(got, "█") != 6 {
		t.Errorf("0.97 rounds to a full bar: %q", got)
	}
	if got := strip(confBar(-1, 6, th)); strings.Count(got, "█") != 0 || strings.Count(got, "░") != 6 {
		t.Errorf("a negative confidence clamps empty: %q", got)
	}
	if got := strip(confBar(2, 6, th)); strings.Count(got, "█") != 6 {
		t.Errorf("an overweight confidence clamps full: %q", got)
	}
}

// TestExploreLRUBounds pins the tiny deck cache: eviction order and the re-put no-growth.
func TestExploreLRUBounds(t *testing.T) {
	l := newLRU(0) // liberal floor: capacity clamps to 1
	l.put("a", deckState{})
	l.put("b", deckState{})
	if _, ok := l.get("a"); ok {
		t.Error("cap 1 must evict the older key")
	}
	if _, ok := l.get("b"); !ok {
		t.Error("the newest key survives")
	}
	l2 := newLRU(2)
	l2.put("x", deckState{})
	l2.put("x", deckState{ms: 5}) // re-put: update in place, no double slot
	l2.put("y", deckState{})
	if _, ok := l2.get("x"); !ok {
		t.Error("a re-put key must not burn a second slot")
	}
	if hit, _ := l2.get("x"); hit.ms != 5 {
		t.Error("a re-put updates the value")
	}
}
