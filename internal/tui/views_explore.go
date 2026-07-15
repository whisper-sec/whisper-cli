// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// exploreView is the tab-1 top-level view: the DECK graph explorer. It folds into the App
// exactly like monitorView (no new tea.Program, no new event loop). Keystrokes mutate
// the cursor / overlay SYNCHRONOUSLY (instant); only travel, verbs and enrichment touch
// the network, each as an async tea.Cmd tagged with the focusToken so a stale reply
// after a fast walk flurry is dropped, never painted.
//
// Two-tier (Postel): with a key the deck walks the LIVE graph; with no key it renders
// the fixture demo and says so plainly in the breadcrumb (never fake-live).
type exploreView struct {
	app        *App
	deck       deckState
	activePane pane
	results    []resultCard
	catalog    *catalogPicker
	jump       *jumpOverlay
	repl       textinput.Model
	pins       []graphNode
	marks      map[string]bool
	token      int // focusToken: a reply whose token != current is stale and dropped

	loadingFocus, loadingEdges, loadingNbrs bool

	ov       exploreOverlay
	orn      ornamentMode
	degraded bool
	pendingG bool        // the gg (go-top) chord
	history  []deckState // instant back (no refetch)

	w, h int
}

// catalogPicker is the CATALOG overlay state (filter + cursor over the applicable verbs).
type catalogPicker struct {
	filter string
	cursor int
}

// jumpOverlay is the JUMP overlay state (Postel-liberal query + which list is active).
type jumpOverlay struct {
	query    string
	cursor   int
	onAgents bool
}

func newExploreView(app *App) *exploreView {
	in := textinput.New()
	in.Prompt = ": "
	in.CharLimit = 512
	return &exploreView{
		app:        app,
		activePane: paneFocus,
		catalog:    &catalogPicker{},
		jump:       &jumpOverlay{},
		repl:       in,
		marks:      map[string]bool{},
		orn:        ornConstellation,
	}
}

// keyless reports whether the CLI has no credential: the graph is keyed-only (Cypher =
// API key), so keyless EXPLORE stays on the honest fixture demo.
func (v *exploreView) keyless() bool {
	return v.app.client == nil || v.app.client.Credential().IsZero()
}

// --- lifecycle (the same interface App calls on the other five views) ------------------

func (v *exploreView) resize(w, h int) { v.w, v.h = w, h }

// exploreDefaultNode is where EXPLORE lands when no start node is given: our own
// front door - dog-fooding the graph on the domain that serves it.
const exploreDefaultNode = "whisper.security"

// onEnter lands the first time EXPLORE opens: live on the start node (default
// whisper.security) when a key is present; the honest whisper.security fixture
// demo otherwise, stated plainly.
func (v *exploreView) onEnter() tea.Cmd {
	if v.deck.focus.Value != "" {
		return nil
	}
	if v.keyless() {
		v.loadDeck(fixtureWhisperSecurity())
		v.app.setToast("no API key: fixture demo - set a key for live traversal", false)
		return nil
	}
	start := v.app.opts.StartNode
	if start == "" {
		start = exploreDefaultNode
	}
	kind, val := normalizeRef(start)
	if val == "" {
		kind, val = "HOSTNAME", exploreDefaultNode
	}
	if v.deck.cache == nil {
		v.deck.cache = newLRU(512)
	}
	return v.land(graphNode{Labels: []string{kind}, Value: val}, false)
}

// retheme is a no-op: EXPLORE pulls every style from app.th fresh each frame, so a theme
// cycle needs no cached-style rebuild (unlike the bubbles tables in AGENTS/LOGS).
func (v *exploreView) retheme() {}

func (v *exploreView) view(w, h int) string {
	switch v.ov {
	case ovCatalog:
		return v.renderCatalogFrame(w, h)
	case ovJump:
		return v.renderJumpFrame(w, h)
	default: // ovNone, or ovRepl which folds a bar into the deck
		return v.renderDeck(w, h)
	}
}

// loadDeck installs a deck (a fixture, or a cache hit) and resets the cursors.
func (v *exploreView) loadDeck(d deckState) {
	if d.cache == nil {
		d.cache = newLRU(512)
	}
	v.deck = d
	v.activePane = paneFocus
	v.deck.edgeCur = clamp(v.deck.edgeCur, 0, maxInt(len(d.edges)-1, 0))
	v.deck.nbrCur = 0
	v.results = nil
}

// --- the live landing engine -------------------------------------------------------------

// land re-roots the deck onto sel and fires the three async loads (focus + edges +
// enrich) under a fresh token. push snapshots the current deck for instant back. A
// cache hit re-lands instantly with no refetch (the LRU discipline).
func (v *exploreView) land(sel graphNode, push bool) tea.Cmd {
	if push {
		v.history = append(v.history, v.deck)
	}
	cache := v.deck.cache
	if cache == nil {
		cache = newLRU(512)
	}
	trail := v.deck.trail
	if push {
		trail = append(append([]graphNode{}, v.deck.trail...), v.deck.focus)
	}

	if hit, ok := cache.get(sel.Value); ok {
		hit.trail = trail
		hit.cache = cache
		v.deck = hit
		v.deck.edgeCur, v.deck.nbrCur = 0, 0
		v.activePane = paneFocus
		v.results = nil
		v.loadingFocus, v.loadingEdges = false, false
		v.app.setToast("landed on "+sel.Value+" (cached)", false)
		return nil
	}

	v.token++
	v.deck = deckState{trail: trail, focus: sel, cache: cache, live: true}
	v.activePane = paneFocus
	v.results = nil
	v.loadingFocus, v.loadingEdges = true, true
	c := v.app.client
	return tea.Batch(
		exLoadFocus(c, sel.Value, v.token),
		exLoadEdges(c, sel.Value, v.token),
		exEnrich(c, sel.Value, v.token),
	)
}

// reload re-lands the current focus live (Ctrl-R: the outage banner's retry).
func (v *exploreView) reload() tea.Cmd {
	if v.keyless() || v.deck.focus.Value == "" {
		return nil
	}
	v.degraded = false
	v.token++
	v.deck.live = true
	v.loadingFocus, v.loadingEdges = true, true
	c := v.app.client
	val := v.deck.focus.Value
	return tea.Batch(
		exLoadFocus(c, val, v.token),
		exLoadEdges(c, val, v.token),
		exEnrich(c, val, v.token),
	)
}

// --- async reply folds (App.Update routes the six messages here) ------------------------

// stale reports whether a reply belongs to a node we already left.
func (v *exploreView) stale(token int) bool { return token != v.token }

func (v *exploreView) onFocus(m focusMsg) tea.Cmd {
	if v.stale(m.token) {
		return nil
	}
	v.loadingFocus = false
	if m.err != nil {
		v.failOpen(m.err)
		return nil
	}
	// Merge: labels + curated props + the node's own verdict band. Keep any richer
	// band/ident enrichment that already arrived.
	f := &v.deck.focus
	if len(m.node.Labels) > 0 {
		f.Labels = m.node.Labels
	}
	if m.node.Props != nil {
		f.Props = m.node.Props
	}
	if f.Band == "" && m.node.Band != "" {
		f.Band = m.node.Band
	}
	v.degraded = false
	v.hydrateCache()
	return nil
}

func (v *exploreView) onEdges(m edgesMsg) tea.Cmd {
	if v.stale(m.token) {
		return nil
	}
	v.loadingEdges = false
	if m.err != nil {
		v.failOpen(m.err)
		return nil
	}
	v.deck.edges = m.edges
	v.deck.ms = m.ms
	v.deck.edgeCur = clamp(v.deck.edgeCur, 0, maxInt(len(m.edges)-1, 0))
	v.deck.nbrCur = 0
	v.degraded = false
	v.hydrateCache()
	return nil
}

func (v *exploreView) onNeighbors(m neighborsMsg) tea.Cmd {
	if v.stale(m.token) {
		return nil
	}
	v.loadingNbrs = false
	if m.err != nil {
		v.app.setToast(friendlyErr(m.err), true)
		return nil
	}
	for i := range v.deck.edges {
		if v.deck.edges[i].Type != m.edgeType {
			continue
		}
		e := &v.deck.edges[i]
		if m.off <= 0 {
			e.Sample = m.sample
		} else {
			e.Sample = append(e.Sample[:min(m.off, len(e.Sample))], m.sample...)
		}
		e.off = len(e.Sample)
		v.app.setToast("loaded "+itoa(len(m.sample))+" more of "+e.Type, false)
		break
	}
	v.hydrateCache()
	return nil
}

func (v *exploreView) onEnrich(m enrichMsg) tea.Cmd {
	if v.stale(m.token) || m.value != v.deck.focus.Value {
		return nil
	}
	if m.err != nil {
		// Enrichment is a bonus, never load-bearing: fail open quietly.
		return nil
	}
	if m.ident != nil {
		v.deck.focus.Ident = m.ident
	}
	if m.band != "" {
		v.deck.focus.Band = m.band
	}
	v.hydrateCache()
	return nil
}

func (v *exploreView) onVerbResult(m verbResultMsg) tea.Cmd {
	if v.stale(m.token) {
		return nil
	}
	if m.err != nil {
		v.app.setToast(friendlyErr(m.err), true)
		return nil
	}
	v.results = append(v.results, m.card)
	v.app.setToast("ran "+m.card.Verb, false)
	return nil
}

// failOpen paints the calm degraded state: last-known stays visible, Ctrl-R retries.
// A 4xx problem (e.g. a bad query) is a toast, not an outage.
func (v *exploreView) failOpen(err error) {
	if pe, ok := client.AsProblem(err); ok && pe.Status >= 400 && pe.Status < 500 && pe.Status != 401 {
		v.app.setToast(friendlyErr(err), true)
		return
	}
	v.degraded = true
	v.app.setToast(friendlyErr(err), true)
}

// hydrateCache stores the current live deck under its focus value so a revisit (back /
// forward / re-walk) is instant, no refetch.
func (v *exploreView) hydrateCache() {
	if !v.deck.live || v.deck.cache == nil || v.deck.focus.Value == "" {
		return
	}
	if v.loadingFocus || v.loadingEdges {
		return // cache only a fully-landed deck
	}
	snap := v.deck
	snap.trail = nil // the trail belongs to the walk, not the node
	v.deck.cache.put(v.deck.focus.Value, snap)
}

// --- key handling (synchronous; only travel/verbs return commands) ----------------------

func (v *exploreView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	if v.ov != ovNone {
		return v.handleOverlayKey(k)
	}
	ks := k.String()
	if ks != "g" {
		v.pendingG = false
	}
	switch ks {
	case "j", "down":
		v.moveList(1)
	case "k", "up":
		v.moveList(-1)
	case "l", "right":
		v.paneRight()
	case "h", "left":
		if v.activePane == paneFocus {
			v.ascendTrail()
		} else {
			v.paneLeft()
		}
	case "backspace":
		v.ascendTrail()
	case "H":
		v.trailRoot()
	case "[":
		v.edgeStep(-1)
	case "]":
		v.edgeStep(1)
	case "g":
		if v.pendingG {
			v.gotoTop()
			v.pendingG = false
		} else {
			v.pendingG = true
		}
	case "G":
		v.gotoBottom()
	case " ", "space":
		v.peek()
	case "enter":
		return app, v.walkIn()
	case "x":
		return app, v.expandNeighbors()
	case "S":
		v.sortWorstFirst()
	case "z":
		v.orn = ornamentMode((int(v.orn) + 1) % 3)
		app.setToast("ornament: "+ornamentName(v.orn), false)
	case "o":
		v.ov = ovCatalog
		v.catalog.cursor = 0
	case "/":
		v.ov = ovJump
		v.jump.query = ""
	case ":":
		v.ov = ovRepl
	case "esc":
		app.mode = modeAgents
		app.layout()
	}
	return app, nil
}

// handleOverlayKey drives the CATALOG / JUMP / REPL shells.
func (v *exploreView) handleOverlayKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	ks := k.String()
	switch v.ov {
	case ovCatalog:
		applicable := applicableCatalog(v.deck.focus.Labels)
		switch ks {
		case "esc", "q":
			v.ov = ovNone
		case "j", "down":
			v.catalog.cursor = clamp(v.catalog.cursor+1, 0, maxInt(len(applicable)-1, 0))
		case "k", "up":
			v.catalog.cursor = clamp(v.catalog.cursor-1, 0, maxInt(len(applicable)-1, 0))
		case "enter":
			return app, v.runSelectedVerb(applicable)
		}
	case ovJump:
		switch ks {
		case "esc":
			v.ov = ovNone
		case "tab":
			v.jump.onAgents = !v.jump.onAgents
		case "enter":
			return app, v.jumpLand()
		// The JUMP query is a FOCUSED TEXT INPUT: every printable rune belongs to the
		// text, so list-cursor movement is arrow-keys ONLY. The bare "j"/"k" cases that
		// used to sit here made it impossible to type them ("example.com" lost every k -
		// the bug); a focused input must never lose printable keys to hotkeys.
		case "down":
			v.jump.cursor++
		case "up":
			if v.jump.cursor > 0 {
				v.jump.cursor--
			}
		case "backspace":
			if v.jump.query != "" {
				v.jump.query = trimLastRune(v.jump.query)
			}
		default:
			// Liberal in what we accept: take the full rune payload - any
			// unicode rune types, and a bracketed paste (multiple runes in one
			// KeyMsg) lands whole - not just single-byte ASCII.
			if k.Type == tea.KeyRunes {
				v.jump.query += string(k.Runes)
			}
		}
	case ovRepl:
		if ks == "esc" || ks == "enter" {
			v.ov = ovNone
		}
	}
	return app, nil
}

// --- cursor + pane helpers ---------------------------------------------------------------

func (v *exploreView) curEdge() edgeGroup {
	if v.deck.edgeCur >= 0 && v.deck.edgeCur < len(v.deck.edges) {
		return v.deck.edges[v.deck.edgeCur]
	}
	return edgeGroup{}
}

func (v *exploreView) moveList(d int) {
	if v.activePane == paneNeighbors {
		cur := v.curEdge()
		v.deck.nbrCur = clamp(v.deck.nbrCur+d, 0, maxInt(len(cur.Sample)-1, 0))
		return
	}
	v.deck.edgeCur = clamp(v.deck.edgeCur+d, 0, maxInt(len(v.deck.edges)-1, 0))
	v.deck.nbrCur = 0
}

func (v *exploreView) paneRight() {
	if v.activePane == paneFocus {
		v.activePane = paneNeighbors
	}
}

func (v *exploreView) paneLeft() {
	if v.activePane == paneNeighbors {
		v.activePane = paneFocus
	}
}

func (v *exploreView) edgeStep(d int) {
	v.deck.edgeCur = clamp(v.deck.edgeCur+d, 0, maxInt(len(v.deck.edges)-1, 0))
	v.deck.nbrCur = 0
}

func (v *exploreView) gotoTop() {
	if v.activePane == paneNeighbors {
		v.deck.nbrCur = 0
	} else {
		v.deck.edgeCur = 0
		v.deck.nbrCur = 0
	}
}

func (v *exploreView) gotoBottom() {
	if v.activePane == paneNeighbors {
		v.deck.nbrCur = maxInt(len(v.curEdge().Sample)-1, 0)
	} else {
		v.deck.edgeCur = maxInt(len(v.deck.edges)-1, 0)
		v.deck.nbrCur = 0
	}
}

// peek loads the highlighted neighbour into the preview WITHOUT travelling (the
// pathfinder graft: triage before you commit).
func (v *exploreView) peek() {
	v.activePane = paneNeighbors
	cur := v.curEdge()
	if v.deck.nbrCur >= 0 && v.deck.nbrCur < len(cur.Sample) {
		v.app.setToast("peek: "+cur.Sample[v.deck.nbrCur].Value, false)
	}
}

// walkIn descends onto the highlighted neighbour. A LIVE deck lands live (with the
// focusToken discipline); a fixture deck keeps the Phase 1 demo behaviour.
func (v *exploreView) walkIn() tea.Cmd {
	if v.activePane != paneNeighbors {
		v.paneRight()
		return nil
	}
	cur := v.curEdge()
	if v.deck.nbrCur < 0 || v.deck.nbrCur >= len(cur.Sample) {
		return nil
	}
	sel := cur.Sample[v.deck.nbrCur]

	if v.deck.live {
		v.app.setToast("walking to "+sel.Value, false)
		return v.land(sel, true)
	}

	// Fixture walk (keyless demo): when a linked fixture exists it walks the whole
	// deck onto it; else a shallow walk keeps the honest empty-edges state.
	prev := v.deck
	v.history = append(v.history, prev)
	if target, ok := fixtureWalk(sel.Value); ok {
		target.trail = append(append([]graphNode{}, prev.trail...), prev.focus)
		if target.cache == nil {
			target.cache = prev.cache
		}
		v.deck = target
		v.deck.edgeCur = clamp(v.deck.edgeCur, 0, maxInt(len(v.deck.edges)-1, 0))
		v.deck.nbrCur = 0
		v.activePane = paneFocus
		v.app.setToast("walked to "+target.focus.Value, false)
		return nil
	}
	newTrail := append(append([]graphNode{}, prev.trail...), prev.focus)
	v.deck = deckState{trail: newTrail, focus: sel, cache: prev.cache}
	v.activePane = paneFocus
	v.app.setToast("walked to "+sel.Value+" (fixture: no linked deck)", false)
	return nil
}

// expandNeighbors pages +200 more of the selected edge's fan-out (x). Honest paging:
// the count is the truth, the sample grows page by page.
func (v *exploreView) expandNeighbors() tea.Cmd {
	if !v.deck.live || v.keyless() {
		v.app.setToast("expand needs a live deck (set a key)", false)
		return nil
	}
	cur := v.curEdge()
	if cur.Type == "" {
		return nil
	}
	if int64(len(cur.Sample)) >= cur.Total {
		v.app.setToast(cur.Type+" fully loaded ("+itoa(len(cur.Sample))+")", false)
		return nil
	}
	v.loadingNbrs = true
	v.app.setToast("loading +"+itoa(neighborPage)+" of "+cur.Type+"...", false)
	return exLoadNeighbors(v.app.client, v.deck.focus.Value, cur, len(cur.Sample), v.token)
}

// sortWorstFirst ranks the selected edge's sample band-worst-first (S): the one
// malicious co-tenant in a mega fan-out surfaces on page 1.
func (v *exploreView) sortWorstFirst() {
	i := v.deck.edgeCur
	if i < 0 || i >= len(v.deck.edges) {
		return
	}
	rank := func(b string) int {
		switch b {
		case "MALICIOUS":
			return 0
		case "SUSPICIOUS":
			return 1
		case "UNKNOWN":
			return 2
		case "":
			return 3
		default: // BENIGN
			return 4
		}
	}
	s := v.deck.edges[i].Sample
	// stable insertion by rank keeps equal-band rows in their arrival order.
	stableSortSample(s, rank)
	v.deck.nbrCur = 0
	v.app.setToast("sorted "+v.deck.edges[i].Type+" worst-first", false)
}

// stableSortSample is a tiny stable sort (insertion) over a neighbour sample.
func stableSortSample(s []graphNode, rank func(string) int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && rank(s[j].Band) < rank(s[j-1].Band); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ascendTrail pops back to the parent deck (instant, from the history stack).
func (v *exploreView) ascendTrail() {
	if len(v.history) == 0 {
		return
	}
	last := v.history[len(v.history)-1]
	v.history = v.history[:len(v.history)-1]
	v.token++ // anything still in flight for the abandoned focus is now stale
	v.loadingFocus, v.loadingEdges, v.loadingNbrs = false, false, false
	v.deck = last
	v.activePane = paneFocus
	v.app.setToast("back to "+last.focus.Value, false)
}

func (v *exploreView) trailRoot() {
	if len(v.history) == 0 {
		return
	}
	root := v.history[0]
	v.history = nil
	v.token++
	v.loadingFocus, v.loadingEdges, v.loadingNbrs = false, false, false
	v.deck = root
	v.activePane = paneFocus
}

// jumpLand closes the JUMP overlay and lands on the typed node reference, parsed
// Postel-liberally (scheme/path/trailing-dot stripped, kind detected).
func (v *exploreView) jumpLand() tea.Cmd {
	kind, val := normalizeRef(v.jump.query)
	if val == "" {
		v.app.setToast("type a node: host / IPv4 / IPv6 / email / AS#", false)
		return nil
	}
	v.ov = ovNone
	if v.keyless() {
		v.app.setToast("live jump needs an API key (whisper login)", true)
		return nil
	}
	push := v.deck.focus.Value != ""
	return v.land(graphNode{Labels: []string{kind}, Value: val}, push)
}

// runSelectedVerb runs the selected catalog entry on the focus: a direct verb goes to
// the live graph in one keyed round-trip; a flow renders its honest console card; the
// guarded write verb never auto-runs. A keyless (fixture) deck keeps the demo cards.
func (v *exploreView) runSelectedVerb(applicable []catalogVerb) tea.Cmd {
	if v.catalog.cursor < 0 || v.catalog.cursor >= len(applicable) {
		return nil
	}
	cv := applicable[v.catalog.cursor]
	switch {
	case cv.Flow:
		v.results = append(v.results, flowCard(cv, v.deck.focus))
		return nil
	case cv.Write:
		v.results = append(v.results, guardedCard(cv, v.deck.focus))
		return nil
	case v.keyless() || !v.deck.live:
		v.results = append(v.results, fixtureVerbResult(cv, v.deck.focus))
		v.app.setToast("ran "+cv.Proc+" (fixture)", false)
		return nil
	}
	v.app.setToast("running "+cv.Proc+" on "+v.deck.focus.Value+"...", false)
	return exRunVerb(v.app.client, cv, v.deck.focus, v.token)
}

// trimLastRune drops the final RUNE (not byte) from s - the backspace for a query that
// may hold multi-byte unicode (JUMP accepts any rune, so deletion must be rune-wise too).
func trimLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:len(r)-1])
}

func ornamentName(o ornamentMode) string {
	switch o {
	case ornCluster:
		return "cluster"
	case ornOff:
		return "off"
	default:
		return "constellation"
	}
}

// --- the async message contract (explore_commands.go emits these) -----------------------

type focusMsg struct {
	node  graphNode
	token int
	err   error
}

type edgesMsg struct {
	edges []edgeGroup
	ms    int // the live round-trip time (the honest latency badge)
	token int
	err   error
}

type neighborsMsg struct {
	edgeType string
	sample   []graphNode
	off      int
	token    int
	err      error
}

type enrichMsg struct {
	value string
	ident *identity
	band  string
	token int
	err   error
}

type verbResultMsg struct {
	card  resultCard
	token int
	err   error
}

type searchMsg struct {
	results []graphNode
	token   int
	err     error
}
