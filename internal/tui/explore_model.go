// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// This file is PURE DATA for the EXPLORE (graph-explorer) view: the DECK design
// (Miller columns TRAIL | FOCUS | EDGES-by-type -> NEIGHBORS | preview). It carries no
// I/O and no network; the live pass fills these shapes from the graph. Everything
// here is deterministic so the renderer is golden-testable.

// graphNode is one node you can stand on or walk to. A node is MULTI-LABEL: it can be
// IPV4 and a Tor exit and a threat indicator all at once, so glyphs (and the catalog
// filter) union over every label.
type graphNode struct {
	Labels []string       // e.g. ["IPV4"] or ["IPV4","FEED"]
	Value  string         // canonical key (name / address / email / asn)
	Props  map[string]any // free props; "sub" is the descriptor line under the value
	Band   string         // BENIGN | SUSPICIOUS | MALICIOUS | UNKNOWN | "" (not assessed)
	Ident  *identity      // lazy enrichment (vendor / roles / assess coverage)
}

// identity is the enrichment dossier a node carries once identify + assess have run.
type identity struct {
	Vendor   string
	Roles    []string
	Coverage float64
	CovWord  string // the live graph reports coverage as a WORD (e.g. "known-clean")
	Feeds    int
	ASN      string
	ASName   string
	Country  string
	Prefix   string
	Hosts    string
	Note     string
}

// edgeGroup is every edge of one type off the focus node, with its TRUE total count
// (from the bounded query) and a small sample. A mega fan-out (1.24M reverse edges) is
// never enumerated: Total is the truth, Sample is 200 paged rows, Capped says the count
// itself hit a ceiling.
type edgeGroup struct {
	Type   string // RESOLVES_TO, LINKS_TO, RESOLVES_TO (superscript minus one) for reverse
	Base   string // the canonical live edge type for paging Cypher ("" => Type is it)
	Dir    int    // +1 outbound, -1 inbound, 0 set/membership
	Total  int64  // TRUE total from the bounded query
	Capped bool   // the count itself was capped (server ceiling)
	Sample []graphNode
	off    int // paging offset into the fan-out
}

// baseType is the raw live edge type for paging Cypher (fixtures leave Base empty).
func (e edgeGroup) baseType() string {
	if e.Base != "" {
		return e.Base
	}
	return e.Type
}

// deckState is the whole walk: where you stand, the trail behind you, the edges around
// you, and the two cursors (edge-type + neighbour) that are two renderings of one logical
// cursor.
type deckState struct {
	trail   []graphNode
	fwd     []graphNode
	focus   graphNode
	edges   []edgeGroup
	edgeCur int
	nbrCur  int
	live    bool // this deck came from the live graph (vs a fixture)
	ms      int  // the live edges round-trip time (the honest latency badge)
	cache   *lru // instant back / forward + revisit, hydrated on every live land
}

// pane is the active Miller column; exactly one is active at a time (a diamond gutter
// tick marks it, never colour alone, so NO_COLOR / colourblind users always know where).
type pane int

const (
	paneFocus pane = iota
	paneNeighbors
	paneResult
)

// exploreOverlay is a modal shell stacked over the deck (rendered static for now).
type exploreOverlay int

const (
	ovNone exploreOverlay = iota
	ovCatalog
	ovJump
	ovRepl
)

// ornamentMode toggles the FOCUS ornament: the constellation, the density-collapsed
// blobs, or off. The ornament is never load-bearing; the Miller columns are the nav.
type ornamentMode int

const (
	ornConstellation ornamentMode = iota
	ornCluster
	ornOff
)

// resultShape drives the type-aware RESULT renderer (a catalog verb result is a node too).
type resultShape int

const (
	shapeBand resultShape = iota
	shapeRanked
	shapeVendor
	shapeTimeline
)

// resultCard is one catalog-verb result, carrying the exact Cypher + rowCount it ran so
// an export is reproducible, not a screenshot.
type resultCard struct {
	Verb   string
	Shape  resultShape
	MS     int
	Cypher string
	Rows   int

	// band shape
	Band     string
	Coverage float64
	CovWord  string // the live coverage WORD (e.g. "known-clean"); shown when set
	Label    string
	Evidence string

	// ranked / vendor / timeline shapes
	Cols  []string
	Table []resultRow

	Note string
}

// resultRow is a single result line; every row is itself a walkable node.
type resultRow struct {
	Node   graphNode
	Name   string
	Method string
	Conf   float64
	Reg    string
	Band   string
}

// catalogVerb is one entry of the intelligence catalog (14 direct verbs + 15 flows),
// loaded from the embedded catalog.json. A direct verb carries its real Cypher + params
// and runs inline in one keyed round-trip; a flow honestly labels itself "anchor step
// runs in console" and deep-links there (never faked as one call).
type catalogVerb struct {
	Name  string
	Title string
	Proc  string
	Blurb string
	Kinds []string // input kinds it applies to (hostname/domain/ipv4/asn/any)
	Flow  bool
	Write bool // a guarded write verb (submit): listed, never auto-run

	// live run contract (direct verbs only).
	Cypher    string         // the catalog's exact Cypher, with $-parameters
	ParamName string         // the node-ref parameter (usually "v"); "" => no node input
	Params    map[string]any // baked catalog defaults for any extra parameters
	Note      string         // the catalog's honesty note (flows)
	DocPath   string         // docs deep-link path
}

// --- the LRU (instant back / forward / revisit) -----------------------------------------

// lru is a tiny value-keyed DECK cache: a revisited node re-lands instantly from here
// (focus + edges + enrichment), no refetch. Hydrated on every live land. Kept
// intentionally small and allocation-light.
type lru struct {
	cap   int
	m     map[string]deckState
	order []string
}

func newLRU(capacity int) *lru {
	if capacity < 1 {
		capacity = 1
	}
	return &lru{cap: capacity, m: make(map[string]deckState, capacity)}
}

func (l *lru) get(key string) (deckState, bool) {
	n, ok := l.m[key]
	return n, ok
}

func (l *lru) put(key string, n deckState) {
	if _, ok := l.m[key]; !ok {
		l.order = append(l.order, key)
		if len(l.order) > l.cap {
			evict := l.order[0]
			l.order = l.order[1:]
			delete(l.m, evict)
		}
	}
	l.m[key] = n
}

// --- glyph + band helpers (glyph carries meaning; colour is reinforcement only) --------

// labelGlyph maps a node label to its terminal glyph. A node stacks the glyphs of ALL its
// labels (glyphsFor), so a multi-label node reads honestly at a glance (e.g. IPV4+threat).
var labelGlyph = map[string]string{
	"HOSTNAME":     "⬢", // hexagon
	"IPV4":         "▤", // square with horizontal fill
	"IPV6":         "▥", // square with vertical fill
	"EMAIL":        "✉", // envelope
	"ORGANIZATION": "⯃", // diamond-ish org mark
	"ORG":          "⯃",
	"ASN":          "◈", // diamond in square
	"AS":           "◈",
	"TLS_FP":       "⬡", // open hexagon
	"TLSFP":        "⬡",
	"FEED":         "⚑", // flag (threat / feed)
	"THREAT":       "⚑",
	"INDICATOR":    "⚑",
	"TLD":          "⌾", // apl circle-jot
	"PREFIX":       "▦", // square with orthogonal fill
	"PTR":          "▷", // white right triangle
	// live-graph label spellings (be liberal in what we accept: same glyph family).
	"REGISTERED_PREFIX": "▦",
	"ANNOUNCED_PREFIX":  "▦",
	"CITY":              "⌾",
	"COUNTRY":           "⌾",
}

// glyphOrder is the canonical stacking order so glyphsFor is deterministic.
var glyphOrder = []string{
	"HOSTNAME", "IPV4", "IPV6", "PREFIX", "REGISTERED_PREFIX", "ANNOUNCED_PREFIX",
	"ASN", "EMAIL", "ORGANIZATION", "TLS_FP", "TLD", "CITY", "COUNTRY", "PTR",
	"FEED", "THREAT", "INDICATOR",
}

const glyphUnknown = "◌" // dotted circle (a label we do not have a glyph for)

// glyphsFor returns the UNION of a node's label glyphs, stacked in canonical order and
// de-duplicated (a multi-label node stacks, e.g. IPV4+FEED -> two glyphs side by side).
func glyphsFor(labels []string) string {
	if len(labels) == 0 {
		return glyphUnknown
	}
	seen := map[string]bool{}
	var out strings.Builder
	for _, canon := range glyphOrder {
		for _, l := range labels {
			if strings.EqualFold(l, canon) {
				if g := labelGlyph[strings.ToUpper(l)]; g != "" && !seen[g] {
					seen[g] = true
					out.WriteString(g)
				}
			}
		}
	}
	for _, l := range labels {
		if _, ok := labelGlyph[strings.ToUpper(l)]; !ok {
			if !seen[glyphUnknown] {
				seen[glyphUnknown] = true
				out.WriteString(glyphUnknown)
			}
		}
	}
	if out.Len() == 0 {
		return glyphUnknown
	}
	return out.String()
}

// styleForBand returns the style AND the band glyph for a threat band. The glyph is the
// signal; the colour merely reinforces it, so NO_COLOR reads identically. The empty band
// (not assessed) is a plain hyphen, never an em-dash.
func styleForBand(th *theme.Theme, band string) (lipgloss.Style, string) {
	switch strings.ToUpper(strings.TrimSpace(band)) {
	case "BENIGN", "CLEAN":
		return th.OK, "▪" // small black square
	case "SUSPICIOUS", "SUSP":
		return th.Warn, "!"
	case "MALICIOUS", "MAL":
		return th.Error, "✗" // ballot x
	case "UNKNOWN":
		return th.Dim, "·" // middle dot
	default:
		return th.Dim, "-" // not assessed (plain hyphen, not an em-dash)
	}
}

// isIPLabels reports whether a node is an IP address (BENIGN reads as "clean" for IPs).
func isIPLabels(labels []string) bool {
	for _, l := range labels {
		switch strings.ToUpper(l) {
		case "IPV4", "IPV6":
			return true
		}
	}
	return false
}

// isHubLabels reports whether the focus is a hub type (ASN / PREFIX), which uses the
// bipartite layout instead of the radial constellation (hubs crush a radial orrery).
func isHubLabels(labels []string) bool {
	for _, l := range labels {
		switch strings.ToUpper(l) {
		case "ASN", "AS", "PREFIX", "REGISTERED_PREFIX", "ANNOUNCED_PREFIX":
			return true
		}
	}
	return false
}

// bandWord is the FOCUS-card band word (BENIGN reads as CLEAN for IPs; "" is honest).
func bandWord(band string, labels []string) string {
	switch strings.ToUpper(strings.TrimSpace(band)) {
	case "BENIGN", "CLEAN":
		if isIPLabels(labels) {
			return "CLEAN"
		}
		return "BENIGN"
	case "SUSPICIOUS", "SUSP":
		return "SUSPICIOUS"
	case "MALICIOUS", "MAL":
		return "MALICIOUS"
	case "UNKNOWN":
		return "UNKNOWN"
	default:
		return "not assessed"
	}
}

// bandTag is the short neighbour-row band tag (clean / benign / susp / MAL / unknown).
func bandTag(band string, labels []string) string {
	switch strings.ToUpper(strings.TrimSpace(band)) {
	case "BENIGN", "CLEAN":
		if isIPLabels(labels) {
			return "clean"
		}
		return "benign"
	case "SUSPICIOUS", "SUSP":
		return "susp"
	case "MALICIOUS", "MAL":
		return "MAL"
	case "UNKNOWN":
		return "unknown"
	default:
		return "n/a"
	}
}

// dirGlyph is the spoke direction mark: outbound / inbound / set-membership.
func dirGlyph(dir int) string {
	switch {
	case dir < 0:
		return "◂" // black left triangle (inbound)
	case dir > 0:
		return "▸" // black right triangle (outbound)
	default:
		return "▹" // white right triangle (set / membership)
	}
}

// --- the intelligence catalog (embedded catalog.json; see explore_catalog.go) ----------

// nodeKinds maps a node's labels to the catalog input-kinds it can satisfy. "any" always
// matches so an any-kind verb applies everywhere.
func nodeKinds(labels []string) map[string]bool {
	k := map[string]bool{"any": true}
	for _, l := range labels {
		switch strings.ToUpper(l) {
		case "HOSTNAME":
			k["hostname"], k["domain"] = true, true
		case "IPV4":
			k["ipv4"], k["ip"] = true, true
		case "IPV6":
			k["ipv6"], k["ip"] = true, true
		case "ASN", "AS":
			k["asn"] = true
		case "PREFIX", "REGISTERED_PREFIX", "ANNOUNCED_PREFIX":
			k["prefix"] = true
		case "EMAIL":
			k["email"] = true
		case "ORGANIZATION", "ORG":
			k["org"] = true
		}
	}
	return k
}

func (cv catalogVerb) appliesTo(kinds map[string]bool) bool {
	for _, want := range cv.Kinds {
		if kinds[want] {
			return true
		}
	}
	return false
}

// applicableCatalog filters the catalog to entries that apply to the node's label UNION,
// so a multi-label node never has a verb wrongly hidden (Postel: liberal in what we show).
func applicableCatalog(labels []string) []catalogVerb {
	all := loadCatalog()
	kinds := nodeKinds(labels)
	out := make([]catalogVerb, 0, len(all))
	for _, cv := range all {
		if cv.appliesTo(kinds) {
			out = append(out, cv)
		}
	}
	return out
}

// normalizeRef is the Postel-liberal reference parser for JUMP: it strips schemes, a
// trailing dot, and a path, then detects the node kind. It returns the detected label and
// the cleaned value (the live pass turns the label into the MATCH property key).
func normalizeRef(s string) (kind, value string) {
	v := strings.TrimSpace(s)
	// strip common schemes.
	for _, sch := range []string{"https://", "http://", "dns://", "//"} {
		if strings.HasPrefix(strings.ToLower(v), sch) {
			v = v[len(sch):]
			break
		}
	}
	// strip a path / query.
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	// email.
	if strings.Contains(v, "@") && !strings.HasPrefix(v, "@") {
		return "EMAIL", strings.ToLower(strings.TrimSuffix(v, "."))
	}
	// ASN: AS13335 or bare 13335.
	if a := asnOf(v); a != "" {
		return "ASN", a
	}
	// IPv4: four dotted decimal octets.
	if isIPv4(strings.TrimSuffix(v, ".")) {
		return "IPV4", strings.TrimSuffix(v, ".")
	}
	// IPv6: has a colon and is not host:port style handled above.
	if strings.Contains(v, ":") {
		return "IPV6", strings.ToLower(v)
	}
	// hostname (default): drop a trailing dot, lower-case.
	return "HOSTNAME", strings.ToLower(strings.TrimSuffix(v, "."))
}

// asnOf normalizes an AS reference ("AS13335" or "13335") to "AS13335", or "" if not one.
func asnOf(s string) string {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "AS")
	if t == "" {
		return ""
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return "AS" + t
}

// isIPv4 reports whether s is four dotted decimal octets in range.
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// humanCommas renders an integer with thousands separators (the TRUE edge count).
func humanCommas(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// propsLine builds the FOCUS-card "props" line from a node's Props, DETERMINISTICALLY
// (keys sorted so the render is golden-testable) and skipping the display-only keys.
func propsLine(n graphNode) string {
	if n.Props == nil {
		return ""
	}
	skip := map[string]bool{"sub": true, "mega": true, "note": true}
	keys := make([]string, 0, len(n.Props))
	for k := range n.Props {
		if skip[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+" "+anyToStr(n.Props[k]))
	}
	return strings.Join(parts, " · ")
}

// anyToStr renders a prop value (string / bool / number) for the props line.
func anyToStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return ""
	}
}

// subOf returns the descriptor line under a node's value (Props["sub"]), or "".
func subOf(n graphNode) string {
	if n.Props == nil {
		return ""
	}
	if s, ok := n.Props["sub"].(string); ok {
		return s
	}
	return ""
}

// maxInt is a small two-arg int max (the package defines its own min; keep a twin here).
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
