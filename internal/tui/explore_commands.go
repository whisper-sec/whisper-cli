// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// This file is the EXPLORE network layer: every live graph call is an async tea.Cmd,
// bounded by callTimeout, tagged with the focusToken (a stale reply after a fast walk
// flurry is dropped in the fold), and fail-open (an error paints the calm degraded
// state, never a hang or four dead spinners).
//
// The live contract, validated against the graph:
// - every node keys its canonical value on the `name` property (HOSTNAME, IPV4,
// IPV6, ASN, PREFIX alike); `{address:...}` would be an unindexed full scan
// - rows come back as column-keyed objects with {rowCount, executionTimeMs} stats
// - $-parameters are bound server-side, so a value never touches the query text

// exCypherFocus resolves a node's labels + properties in one anchored round-trip.
const exCypherFocus = "MATCH (n {name:$v}) RETURN labels(n) AS labels, properties(n) AS props LIMIT 1"

// exCypherEdges is pathfinder's one-round-trip bounded neighbourhood: every edge type
// off the focus with its TRUE total AND a small sample, in a single call. The sample
// carries [labels, canonical value, threat level] so the neighbour list lands banded.
const exCypherEdges = "MATCH (n {name:$v})-[r]-(m) " +
	"WITH type(r) AS et, startNode(r) = n AS outb, m " +
	"RETURN et, outb, count(m) AS total, " +
	"collect([labels(m), coalesce(m.name, m.asn, m.address, m.email, m.value), " +
	"coalesce(m.verdictLevel, m.threatLevel)])[0..8] AS sample " +
	"ORDER BY total DESC"

// neighborPage is the SKIP/LIMIT page size for x (expand the fan-out).
const neighborPage = 200

// edgeTypeRe guards the one place a live value is spliced into Cypher text: an edge
// TYPE (which cannot be a $-parameter). Types come from the graph's own type(r), but
// be conservative anyway: only word characters pass.
var edgeTypeRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// exLoadFocus resolves the focus node's labels + props. Zero rows is NOT an error: the
// graph simply does not know the node, and the deck renders the honest sparse state.
func exLoadFocus(c *client.Client, value string, token int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		rows, _, err := c.GraphQueryRows(ctx, exCypherFocus, map[string]any{"v": value})
		if err != nil {
			return focusMsg{token: token, err: err}
		}
		if len(rows) == 0 {
			// Honest not-in-graph state: a sparse UNKNOWN node, not an error.
			return focusMsg{token: token, node: graphNode{
				Value: value,
				Band:  "UNKNOWN",
				Props: map[string]any{"sub": "not in the graph (yet) - that's a fact, not an error"},
			}}
		}
		return focusMsg{token: token, node: nodeFromInspect(value, rows[0])}
	}
}

// exLoadEdges runs the bounded one-round-trip neighbourhood query.
func exLoadEdges(c *client.Client, value string, token int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		rows, stats, err := c.GraphQueryRows(ctx, exCypherEdges, map[string]any{"v": value})
		if err != nil {
			return edgesMsg{token: token, err: err}
		}
		return edgesMsg{token: token, edges: edgesFromRecords(rows), ms: stats.MS}
	}
}

// exLoadNeighbors pages one edge type's fan-out (x = +200): a bounded adjacency query
// with the direction pinned, ordered so paging is deterministic.
func exLoadNeighbors(c *client.Client, value string, edge edgeGroup, off, token int) tea.Cmd {
	et := edge.baseType()
	if !edgeTypeRe.MatchString(et) {
		return func() tea.Msg {
			return neighborsMsg{token: token, err: &client.ProblemError{Status: 400,
				Detail: "edge type " + et + " is not a plain relationship name; not paging it"}}
		}
	}
	dirClause := "startNode(r) = n"
	if edge.Dir < 0 {
		dirClause = "startNode(r) <> n"
	}
	cypher := "MATCH (n {name:$v})-[r:" + et + "]-(m) WHERE " + dirClause + " " +
		"RETURN labels(m) AS lbls, coalesce(m.name, m.asn, m.address, m.email, m.value) AS value, " +
		"coalesce(m.verdictLevel, m.threatLevel) AS level " +
		"ORDER BY value SKIP " + itoa(maxInt(off, 0)) + " LIMIT " + itoa(neighborPage)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		rows, _, err := c.GraphQueryRows(ctx, cypher, map[string]any{"v": value})
		if err != nil {
			return neighborsMsg{token: token, err: err}
		}
		sample := make([]graphNode, 0, len(rows))
		for _, r := range rows {
			sample = append(sample, graphNode{
				Labels: strsOf(r["lbls"]),
				Value:  asStr(r["value"]),
				Band:   normalizeBand(asStr(r["level"])),
			})
		}
		return neighborsMsg{token: token, edgeType: edge.Type, sample: sample, off: off}
	}
}

// exEnrich runs identify + assess on the focus (one round-trip each, fired on land).
// Either half failing is fail-open: whatever arrived still enriches the card.
func exEnrich(c *client.Client, value string, token int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*callTimeout)
		defer cancel()
		msg := enrichMsg{token: token, value: value}
		id := &identity{}

		idRows, _, idErr := c.GraphQueryRows(ctx,
			"CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band",
			map[string]any{"v": value})
		if idErr == nil && len(idRows) > 0 {
			r := idRows[0]
			id.Vendor = asStr(r["canonical_name"])
			if id.Vendor == "" {
				id.Vendor = asStr(r["vendor_id"])
			}
			id.Roles = strsOf(r["roles"])
			if cat := asStr(r["category"]); cat != "" && cat != "null" {
				id.Note = cat
			}
		}

		asRows, _, asErr := c.GraphQueryRows(ctx,
			"CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence",
			map[string]any{"v": value})
		if asErr == nil && len(asRows) > 0 {
			r := asRows[0]
			msg.band = normalizeAssess(asStr(r["band"]), asStr(r["label"]))
			id.CovWord = asStr(r["coverage"])
			id.Feeds = len(strsOf(r["evidence"]))
		}

		if idErr != nil && asErr != nil {
			msg.err = idErr // both halves down: surface one helpful error
			return msg
		}
		msg.ident = id
		return msg
	}
}

// exRunVerb runs a DIRECT catalog verb on the focus: the catalog's exact Cypher with
// its $-params bound (the node ref + any baked defaults). The result card binds the
// reproducible Cypher + rowCount, so an export is evidence, not a screenshot.
func exRunVerb(c *client.Client, cv catalogVerb, focus graphNode, token int) tea.Cmd {
	params := map[string]any{}
	for k, v := range cv.Params {
		params[k] = v
	}
	if cv.ParamName != "" {
		params[cv.ParamName] = focus.Value
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		rows, stats, err := c.GraphQueryRows(ctx, cv.Cypher, params)
		if err != nil {
			return verbResultMsg{token: token, err: err}
		}
		return verbResultMsg{token: token, card: cardFromRecords(cv, focus, rows, stats)}
	}
}

// --- live row -> deck mappers (pure, unit-tested) ---------------------------------------

// nodeFromInspect maps the labels+props inspect row to a graphNode: curated props (the
// card shows what matters, not 20 false flags), and the node's own verdict as its band.
func nodeFromInspect(value string, rec map[string]any) graphNode {
	labels := strsOf(rec["labels"])
	props, _ := rec["props"].(map[string]any)
	return graphNode{
		Labels: labels,
		Value:  value,
		Props:  curateProps(props),
		Band:   bandFromVerdict(props),
	}
}

// bandFromVerdict derives the deck band from the node's RECONCILED verdict, never raw
// feed evidence: verdictLevel first (threatLevel/overallThreatLevel only as
// legacy fallbacks), and an explicit isThreat:false clamps any raw-evidence residue
// down to BENIGN so an allowlisted resolver or multi-tenant apex (github.com is
// verdictLevel INFO + threatScore 40) never reads as an alert. threatScore is
// evidence, not severity; it never enters this decision.
func bandFromVerdict(props map[string]any) string {
	band := normalizeBand(firstStr(props, "verdictLevel", "threatLevel", "overallThreatLevel"))
	if isThreat, ok := props["isThreat"].(bool); ok && !isThreat {
		// the graph reconciled this node as not-a-threat: never alert on it
		if band == "SUSPICIOUS" || band == "MALICIOUS" || band == "UNKNOWN" {
			return "BENIGN"
		}
	}
	return band
}

// edgesFromRecords maps the bounded-edges rows to edge groups. An inbound group reads
// as TYPE with a superscript minus-one (the deck's reverse-edge notation); Base keeps
// the raw type for paging Cypher.
func edgesFromRecords(rows []map[string]any) []edgeGroup {
	out := make([]edgeGroup, 0, len(rows))
	for _, r := range rows {
		et := asStr(r["et"])
		if et == "" {
			continue
		}
		outb := true
		if b, ok := r["outb"].(bool); ok {
			outb = b
		}
		g := edgeGroup{Base: et, Type: et, Dir: 1, Total: int64OfAny(r["total"])}
		if !outb {
			g.Type = et + "⁻¹"
			g.Dir = -1
		}
		if samp, ok := r["sample"].([]any); ok {
			for _, s := range samp {
				trip, ok := s.([]any)
				if !ok || len(trip) < 2 {
					continue
				}
				n := graphNode{Labels: strsOf(trip[0]), Value: asStr(trip[1])}
				if len(trip) > 2 {
					n.Band = normalizeBand(asStr(trip[2]))
				}
				if n.Value != "" {
					g.Sample = append(g.Sample, n)
				}
			}
		}
		g.off = len(g.Sample)
		out = append(out, g)
	}
	return out
}

// cardFromRecords renders a direct verb's rows type-aware: assess -> the band chip,
// variants -> the ranked table (every row a walkable node), identify -> the vendor
// card, history -> a timeline, anything else -> an honest generic table.
func cardFromRecords(cv catalogVerb, focus graphNode, rows []map[string]any, stats client.GraphStats) resultCard {
	card := resultCard{
		Verb:   cv.Proc + "(" + focus.Value + ")",
		Shape:  shapeVendor,
		MS:     stats.MS,
		Rows:   stats.Rows,
		Cypher: reproCypher(cv, focus.Value),
	}
	switch cv.Name {
	case "assess":
		card.Shape = shapeBand
		if len(rows) > 0 {
			r := rows[0]
			card.Band = normalizeAssess(asStr(r["band"]), asStr(r["label"]))
			card.CovWord = asStr(r["coverage"])
			card.Label = asStr(r["label"])
			if subs := strsOf(r["sub_labels"]); len(subs) > 0 {
				card.Label += " · " + strings.Join(subs, ",")
			}
			card.Evidence = strings.Join(strsOf(r["evidence"]), " · ")
		}
		return card
	case "variants":
		card.Shape = shapeRanked
		for _, r := range rows {
			name := asStr(r["variant"])
			if name == "" {
				continue
			}
			reg := "✗"
			if b, ok := r["exists"].(bool); ok && b {
				reg = "●"
			}
			card.Table = append(card.Table, resultRow{
				Node:   graphNode{Labels: []string{"HOSTNAME"}, Value: name},
				Name:   name,
				Method: asStr(r["method"]),
				Conf:   f64OfAny(r["confidence"]),
				Reg:    reg,
			})
		}
		sort.SliceStable(card.Table, func(i, j int) bool { return card.Table[i].Conf > card.Table[j].Conf })
		if len(card.Table) > 12 {
			card.Note = "..." + itoa(len(card.Table)-12) + " more (rows " + itoa(stats.Rows) + " total)"
			card.Table = card.Table[:12]
		}
		return card
	case "history", "history-whois":
		card.Shape = shapeTimeline
	}
	// Generic honest table: one row -> a column:value card; many rows -> one line per
	// row. Never invented structure; always the real columns.
	if len(rows) == 1 {
		r := rows[0]
		keys := make([]string, 0, len(r))
		for k := range r {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			card.Table = append(card.Table, resultRow{Method: k, Name: asStr(r[k])})
		}
		return card
	}
	for i, r := range rows {
		if i >= 10 {
			card.Note = "..." + itoa(len(rows)-10) + " more rows"
			break
		}
		keys := make([]string, 0, len(r))
		for k := range r {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if v := asStr(r[k]); v != "" && v != "null" {
				parts = append(parts, k+" "+v)
			}
		}
		card.Table = append(card.Table, resultRow{Method: "row " + itoa(i+1), Name: strings.Join(parts, " · ")})
	}
	if len(rows) == 0 {
		card.Note = "0 rows - an honest empty result, not an error"
	}
	return card
}

// flowCard is the honest FLOW result: the anchor step runs in the console; we render
// the catalog's own note + the docs deep-link, never a faked run.
func flowCard(cv catalogVerb, focus graphNode) resultCard {
	note := cv.Note
	if note == "" {
		note = "anchor step runs in console"
	}
	return resultCard{
		Verb:  cv.Proc + " · " + focus.Value,
		Shape: shapeVendor,
		Table: []resultRow{
			{Method: "flow", Name: cv.Title},
			{Method: "honest", Name: note},
			{Method: "docs", Name: catalogDocURL(cv)},
		},
		Note: "flows orchestrate multiple steps; they are never faked as one call",
	}
}

// guardedCard is the honest GUARDED-WRITE result (submit): listed, never auto-run.
func guardedCard(cv catalogVerb, focus graphNode) resultCard {
	return resultCard{
		Verb:  cv.Proc + " · " + focus.Value,
		Shape: shapeVendor,
		Table: []resultRow{
			{Method: "guarded", Name: "a WRITE to shared threat intel"},
			{Method: "docs", Name: catalogDocURL(cv)},
		},
		Note: "submit needs the confirm + dup-check + undo flow (a later story); not run",
	}
}

// reproCypher is the display/export form of a verb run: the catalog Cypher with the
// node-ref parameter inlined as a QUOTED literal, so the line is runnable standalone.
// Conservative in what we emit: the value flows through QuoteCypherString.
func reproCypher(cv catalogVerb, value string) string {
	if cv.ParamName == "" {
		return cv.Cypher
	}
	return strings.ReplaceAll(cv.Cypher, "$"+cv.ParamName, client.QuoteCypherString(value))
}

// --- band + prop normalisation (liberal in what we accept) ------------------------------

// normalizeBand maps the live graph's threat vocabulary onto the deck's four bands.
// NONE / DERIVED mean "no verdict", which is honestly NOT-ASSESSED (""), never green.
// INFO is a verdictLevel word: an informational verdict is clean, not unknown.
func normalizeBand(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE", "DERIVED", "NULL":
		return ""
	case "CLEAN", "BENIGN", "OK", "SAFE", "LOW", "INFO", "WHITELIST", "ALLOWLISTED":
		return "BENIGN"
	case "MEDIUM", "SUSPICIOUS", "SUSP", "WARN", "WARNING":
		return "SUSPICIOUS"
	case "HIGH", "CRITICAL", "MALICIOUS", "MAL", "BLOCK", "BLOCKING", "BLOCKED":
		return "MALICIOUS"
	default:
		return "UNKNOWN"
	}
}

// normalizeAssess folds whisper.assess's {band, label} pair: an explicit label word
// ("clean" / "malicious") outranks a NONE band, so a clean verdict reads BENIGN.
func normalizeAssess(band, label string) string {
	if b := normalizeBand(label); b != "" && b != "UNKNOWN" {
		return b
	}
	if b := normalizeBand(band); b != "" {
		return b
	}
	// band NONE + label clean was handled above; band NONE + no label is a clean
	// no-signal verdict from the assess verb, which we surface as BENIGN only when
	// the label says so; otherwise stay honestly unassessed.
	if strings.EqualFold(strings.TrimSpace(label), "clean") {
		return "BENIGN"
	}
	return ""
}

// curateProps distils the live node's raw properties into the identity card's props
// line: the interesting facts (true flags, non-zero scores, registry data, dates),
// never the 20 false booleans and internal ids that would drown the card.
func curateProps(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range raw {
		switch {
		case k == "id" || k == "label" || k == "name":
			continue // internal / already the focus value
		case strings.HasPrefix(k, "verdict") || strings.HasPrefix(k, "threat") ||
			strings.HasPrefix(k, "maxThreat") || strings.HasPrefix(k, "avgThreat") ||
			strings.HasPrefix(k, "overallThreat"):
			// the verdict family is already the band; verdictScore is the ONE
			// band-consistent number. The raw threat* scores are feed evidence,
			// shown as such, never a severity (github.com carries
			// threatScore 40 next to a reconciled verdictScore 16).
			if f := f64OfAny(v); f > 0 && strings.HasSuffix(k, "Score") {
				if k == "verdictScore" {
					out[k] = trimFloat(f)
				} else {
					out[k] = trimFloat(f) + " (evidence)"
				}
			}
			continue
		case k == "sources":
			// feed evidence only: how many feeds list it, never a severity
			if n := len(strsOf(v)); n > 0 {
				out[k] = "listed in " + itoa(n) + " feed" + plural(n)
			} else if c := int(int64OfAny(v)); c > 0 {
				out[k] = "listed in " + itoa(c) + " feed" + plural(c)
			}
			continue
		case strings.HasPrefix(k, "is") || k == "allowlisted" || k == "hasThreateningPrefixes":
			if b, ok := v.(bool); ok && b {
				out[k] = true // a TRUE flag (isTor, isC2...) is a first-class fact
			}
			continue
		case strings.HasSuffix(k, "Date") || strings.HasSuffix(k, "date"):
			if f := f64OfAny(v); f > 1e11 { // epoch millis -> a readable date
				out[k] = time.UnixMilli(int64(f)).UTC().Format("2006-01-02")
				continue
			}
			if s := asStr(v); s != "" {
				out[k] = s
			}
			continue
		case k == "orgId":
			continue // an internal hash, not a fact for the card
		}
		if s := asStr(v); s != "" && s != "null" {
			out[k] = s
		}
	}
	// Keep the card tidy and deterministic: at most 6 facts, sorted key order.
	if len(out) > 6 {
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		trimmed := map[string]any{}
		for _, k := range keys[:6] {
			trimmed[k] = out[k]
		}
		out = trimmed
	}
	return out
}

// plural is the "s" of "listed in N feeds" (1 feed, 2 feeds).
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// trimFloat renders a score without float noise (6 not 6.0; 1.2 stays 1.2).
func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return itoa(int(f))
	}
	return ftoa(f)
}

// --- tiny decoded-JSON helpers -----------------------------------------------------------

// strsOf renders a decoded JSON value as a string slice (labels, roles, evidence).
func strsOf(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s := asStr(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}

// firstStr returns the first present, non-empty string among keys in a props map.
func firstStr(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		if s := asStr(m[k]); s != "" && s != "null" {
			return s
		}
	}
	return ""
}

// int64OfAny reads a decoded JSON number as int64 (counts).
func int64OfAny(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	default:
		return 0
	}
}

// f64OfAny reads a decoded JSON number as float64 (confidence, scores).
func f64OfAny(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int64:
		return float64(t)
	case int:
		return float64(t)
	default:
		return 0
	}
}
