// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// domain_render.go renders the three op:domain reply shapes `whisper domain` prints.
//
// They used to go through renderFleet, the agent-table renderer, on the comment that
// "op:domain rows share the enriched item shape". They do not. submit answers [kind, value],
// status answers [name, state, key, value] and list answers [name, state], so renderFleet
// found no agent field in any row, printed "no agents yet" and exited 0. The one
// command a customer runs to onboard a domain told them about agents instead of the NS and
// DS records to publish.
//
// Each renderer reads its columns BY NAME, never by position, and a reply that does not
// carry the columns it expects is printed as the table it is rather than reduced to
// nothing: an unexpected shape must stay visible, never render as empty.

// domainSubmitColumns, domainStatusColumns and domainListColumns are the contract the
// control plane documents for op:domain, the columns each sub-command's reply carries.
var (
	domainSubmitColumns = []string{"kind", "value"}
	domainStatusColumns = []string{"name", "state", "key", "value"}
	domainListColumns   = []string{"name", "state"}
)

// hasColumns reports whether res names every one of cols.
func hasColumns(res *client.Result, cols ...string) bool {
	if res == nil {
		return false
	}
	have := make(map[string]bool, len(res.Columns))
	for _, c := range res.Columns {
		have[c] = true
	}
	for _, c := range cols {
		if !have[c] {
			return false
		}
	}
	return true
}

// renderRawResult prints a result in whatever shape it arrived, so a reply we did not
// expect is still shown to the user rather than swallowed.
func renderRawResult(w io.Writer, res *client.Result) {
	if res == nil || len(res.Columns) == 0 {
		fmt.Fprintln(w, "(the control plane answered with no columns)")
		return
	}
	rows := make([][]string, 0, len(res.Rows))
	for _, r := range res.Rows {
		cells := make([]string, len(res.Columns))
		for i := range res.Columns {
			if i < len(r) {
				cells[i] = asString(r[i])
			}
		}
		rows = append(rows, cells)
	}
	printTableTo(w, res.Columns, rows)
}

// printTableTo is printTable aimed at a writer: the real stdout gets printTable itself (with
// its colour rules), any other writer a plain table, so the renderers are testable by what
// they print without swapping the process streams.
func printTableTo(w io.Writer, headers []string, rows [][]string) {
	if f, ok := w.(*os.File); ok && f == os.Stdout {
		printTable(headers, rows)
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := visibleLen(r[i]); l > widths[i] {
				widths[i] = l
			}
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		for i := range headers {
			if i > 0 {
				b.WriteString("  ")
			}
			v := ""
			if i < len(cells) {
				v = cells[i]
			}
			if i == len(headers)-1 {
				b.WriteString(v)
			} else {
				b.WriteString(pad(v, widths[i]))
			}
		}
		b.WriteByte('\n')
	}
	line(headers)
	for _, r := range rows {
		line(r)
	}
	fmt.Fprint(w, b.String())
}

// --- submit: [kind, value] ----------------------------------------------------------

// renderDomainKindValue prints a [kind, value] answer (op:domain webpki) one line per row, with
// notes last; any other shape is printed raw. Every server string is made terminal-safe.
func renderDomainKindValue(w io.Writer, res *client.Result) error {
	if !hasColumns(res, domainSubmitColumns...) {
		renderRawResult(w, res)
		return nil
	}
	labels := map[string]string{"webpki": "WebPKI", "webpki_node": "WebPKI node"}
	var notes []string
	for _, rec := range res.Records() {
		kind, value := asString(rec["kind"]), asString(rec["value"])
		if kind == "note" {
			notes = append(notes, value)
			continue
		}
		label := kind
		if l, ok := labels[kind]; ok {
			label = l
		}
		if kind == "webpki" {
			value = statusValue("webpki", value)
		}
		fmt.Fprintf(w, "%s  %s\n", termSafe(label), termSafe(value))
	}
	for _, n := range notes {
		fmt.Fprintf(w, "note: %s\n", termSafe(n))
	}
	return nil
}

// renderDomainSubmit prints a submit reply: the state, then the records to publish, then
// the notes. A VERIFIED domain (a re-submit) is told to KEEP the records, not to go
// and publish them, because sending someone with a working domain off to change their
// registrar is how a working domain gets broken.
func renderDomainSubmit(w io.Writer, res *client.Result, apex string) error {
	if !hasColumns(res, domainSubmitColumns...) {
		renderRawResult(w, res)
		return nil
	}
	if len(res.Rows) == 0 {
		return &client.ProblemError{Status: 502,
			Detail: fmt.Sprintf("the control plane answered the submit of %s with no rows; check it with:  whisper domain status %s", apex, apex)}
	}
	var name, state string
	var records, notes []string
	var other [][2]string
	for _, rec := range res.Records() {
		kind, value := asString(rec["kind"]), asString(rec["value"])
		switch kind {
		case "state":
			state = value
		case "name":
			name = value
		case "record":
			records = append(records, value)
		case "note":
			notes = append(notes, value)
		default:
			other = append(other, [2]string{kind, value})
		}
	}
	fmt.Fprintf(w, "%s  %s\n", orDash(name), orDash(state))
	if len(records) > 0 {
		fmt.Fprintln(w)
		if strings.EqualFold(state, "verified") {
			fmt.Fprintln(w, "Your parent zone already publishes these; keep them in place:")
		} else {
			fmt.Fprintln(w, "Publish these records at your registrar (in the parent zone):")
		}
		for _, r := range records {
			fmt.Fprintf(w, "  %s\n", r)
		}
	}
	for _, kv := range other {
		fmt.Fprintf(w, "%s: %s\n", kv[0], kv[1])
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range notes {
			fmt.Fprintln(w, n)
		}
	}
	return nil
}

// --- status: [name, state, key, value] -----------------------------------------------

// domainStatus is one domain's status rows, folded by key.
type domainStatus struct {
	name, state string
	values      map[string][]string
	order       []string // keys in arrival order, for the ones we do not know
}

// statusLabels is the order and wording of the keys we know. Anything else the control
// plane adds is printed after these under its own key, never dropped.
var statusLabels = []struct{ key, label string }{
	{"observed_ns", "observed NS"},
	{"observed_ds", "observed DS"},
	{"anchor", "anchor"},
	{"parent_ds_ttl", "parent DS TTL"},
	{"served_here", "served here"},
	{"first_seen_wild", "first seen"},
	{"last_observed", "last observed"},
	{"webpki", "WebPKI"},
	{"webpki_node", "WebPKI node"},
	{"webpki_not_after", "WebPKI expires"},
	{"webpki_reason", "WebPKI reason"},
	{"webpki_next_attempt", "WebPKI next try"},
}

// statusHandledElsewhere are the keys printed as their own lines below the table.
var statusHandledElsewhere = map[string]bool{"missing": true, "orphan_delegation": true, "webpki_caa_hint": true}

func foldDomainStatus(res *client.Result) []*domainStatus {
	var out []*domainStatus
	byName := map[string]*domainStatus{}
	for _, rec := range res.Records() {
		name := asString(rec["name"])
		ds, ok := byName[name]
		if !ok {
			ds = &domainStatus{name: name, state: asString(rec["state"]), values: map[string][]string{}}
			byName[name] = ds
			out = append(out, ds)
		}
		key := asString(rec["key"])
		if _, seen := ds.values[key]; !seen {
			ds.order = append(ds.order, key)
		}
		ds.values[key] = append(ds.values[key], asString(rec["value"]))
	}
	return out
}

// statusValue renders one key's value for a person: epoch-ms timestamps as UTC times,
// a TTL with its unit, booleans as yes/no.
func statusValue(key, v string) string {
	switch key {
	case "webpki":
		switch v {
		case "unavailable":
			return "not offered by this control plane yet"
		case "pending_verification":
			return "requested; ordered once the domain is verified"
		case "requested":
			return "requested; each node orders its own on its next pass"
		case "backing_off":
			return "the last order did not issue; retrying later"
		}
		return v
	case "first_seen_wild", "last_observed":
		if parseEpoch(v) > 0 {
			return humanTime(v) + " UTC"
		}
		return v // "never" / "unknown" are the control plane's own words; keep them
	case "parent_ds_ttl":
		if parseEpoch(v) > 0 {
			return v + "s"
		}
	case "served_here":
		switch v {
		case "true":
			return "yes"
		case "false":
			return "no"
		}
	}
	return v
}

// renderDomainStatus prints a status reply. A domain that is not verified says so on one
// line, "<state>: <reason>", where the reason is the first gap the control plane names,
// and every further gap follows on its own "also:" line, each one a step to take. It returns the states it rendered, so the
// caller can apply --check.
func renderDomainStatus(w io.Writer, res *client.Result, apex string) ([]*domainStatus, error) {
	if !hasColumns(res, domainStatusColumns...) {
		renderRawResult(w, res)
		return nil, nil
	}
	domains := foldDomainStatus(res)
	if len(domains) == 0 {
		return nil, &client.ProblemError{Status: 404, Type: localActionable,
			Detail: fmt.Sprintf("%s is not a domain on this account - submit it first:  whisper domain submit %s",
				apex, apex)}
	}
	for i, d := range domains {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  %s\n", termSafe(d.name), termSafe(d.state))
		width := 0
		for _, l := range statusLabels {
			if _, ok := d.values[l.key]; ok && len(l.label) > width {
				width = len(l.label)
			}
		}
		known := map[string]bool{}
		for _, l := range statusLabels {
			known[l.key] = true
		}
		for _, k := range d.order {
			if !known[k] && !statusHandledElsewhere[k] && len(k) > width {
				width = len(k)
			}
		}
		row := func(label string, values []string, key string) {
			for j, v := range values {
				lead := label
				if j > 0 {
					lead = ""
				}
				fmt.Fprintf(w, "  %s  %s\n", pad(termSafe(lead), width), termSafe(statusValue(key, v)))
			}
		}
		for _, l := range statusLabels {
			if vs, ok := d.values[l.key]; ok {
				row(l.label, vs, l.key)
			}
		}
		for _, k := range d.order {
			if !known[k] && !statusHandledElsewhere[k] {
				row(k, d.values[k], k)
			}
		}
		for _, o := range d.values["orphan_delegation"] {
			fmt.Fprintf(w, "note: %s\n", termSafe(o))
		}
		for _, h := range d.values["webpki_caa_hint"] {
			fmt.Fprintf(w, "CAA: %s\n", termSafe(h))
		}
		if strings.EqualFold(d.state, "verified") {
			continue
		}
		missing := d.values["missing"]
		reason := "waiting for the next scheduled check of your parent zone"
		if len(missing) > 0 {
			reason = missing[0]
		}
		fmt.Fprintf(w, "%s: %s\n", d.state, reason)
		for _, m := range missing[min(1, len(missing)):] {
			fmt.Fprintf(w, "  also: %s\n", m)
		}
	}
	return domains, nil
}

// --- list: [name, state] --------------------------------------------------------------

// renderDomainList prints the account's domains as a two-column table. An empty account
// says so in its own words on stderr, the way `whisper list` does for agents, and exits 0.
func renderDomainList(w, errw io.Writer, res *client.Result) error {
	if !hasColumns(res, domainListColumns...) {
		renderRawResult(w, res)
		return nil
	}
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(errw, "whisper: no domains on this account yet - submit one, e.g.  whisper domain submit example.com")
		return nil
	}
	rows := make([][]string, 0, len(recs))
	for _, rec := range recs {
		rows = append(rows, []string{asString(rec["name"]), asString(rec["state"])})
	}
	printTableTo(w, []string{"DOMAIN", "STATE"}, rows)
	fmt.Fprintf(errw, "%d domain(s)\n", len(rows))
	return nil
}

// --- `whisper list --kind <records|identities|...>`: [kind, item] ----------------------

// listItemLead are the item fields shown first, in this order, when a kind carries them;
// every other field follows alphabetically, so the table is the same on every run.
var listItemLead = []string{"name", "fqdn", "friendly", "address", "type", "value", "ttl", "ptr", "state"}

// renderListItems prints a non-agent `whisper list` kind as a table of its item fields.
// renderFleet is the agent table, and an item with no agent field is not an absence of
// agents; printing "no agents yet" for a records listing was the same defect as.
func renderListItems(w, errw io.Writer, res *client.Result, kind string) {
	var items []map[string]any
	for _, rec := range res.Records() {
		if m, ok := rec["item"].(map[string]any); ok {
			items = append(items, m)
		} else if len(rec) > 0 {
			items = append(items, rec)
		}
	}
	if len(items) == 0 {
		fmt.Fprintf(errw, "whisper: no %s on this account\n", kind)
		return
	}
	seen := map[string]bool{}
	var cols []string
	for _, k := range listItemLead {
		for _, it := range items {
			if _, ok := it[k]; ok {
				cols = append(cols, k)
				seen[k] = true
				break
			}
		}
	}
	var rest []string
	for _, it := range items {
		for k := range it {
			if !seen[k] {
				seen[k] = true
				rest = append(rest, k)
			}
		}
	}
	sort.Strings(rest)
	cols = append(cols, rest...)
	rows := make([][]string, 0, len(items))
	for _, it := range items {
		cells := make([]string, len(cols))
		for i, c := range cols {
			cells[i] = asString(it[c])
		}
		rows = append(rows, cells)
	}
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = strings.ToUpper(c)
	}
	printTableTo(w, headers, rows)
	fmt.Fprintf(errw, "%d %s\n", len(rows), kind)
}
