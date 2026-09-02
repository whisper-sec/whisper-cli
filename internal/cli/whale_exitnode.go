// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_exitnode.go is `whisper whale exit-node`.
//
// Tailscale ranks exit nodes by latency. We rank by what the graph knows about the ASN as
// well, because we have a graph and they do not. Two rules keep that from becoming worse
// than latency alone:
//
// - The number is read from a FIELD, never from prose. `whisper.explain` writes a
// composite reputation into an English sentence and leaves its `score` column at 0.0
// with `level` NONE; a scraper would be parsing English and calling it evidence. The
// two real fields are asnThreatDensity().densityRatio and
// explain().breakdown.graphDensityRatio, and both are read and both are shown.
// - An ASN the graph has no routed space for answers NULL, not 0. Our own AS219419 does
// exactly that today. So an unknown density stays unknown all the way to the screen: it
// never becomes a zero, and it never outranks something measured.
//
// Two-tier, like every surface here: with no key you still get the candidate list and a
// real measured round trip to each, because that half is public. The graph's density needs
// your key, and the row says so instead of showing a blank.

func newWhaleExitNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exit-node",
		Aliases: []string{"exitnode"},
		Short:   "Ways out, ranked by what the graph knows and what we measured",
		Long: "Exit-node selection.\n\n" +
			"  list      the ways out, with a measured round trip and the graph's density\n" +
			"  suggest   one recommendation, with the machine-readable evidence for it\n\n" +
			"Ranking reads asnThreatDensity().densityRatio and\n" +
			"explain().breakdown.graphDensityRatio. It never reads the prose in an\n" +
			"explanation, and an ASN with no routed space in the graph reads `unknown`\n" +
			"rather than a zero that would look like a clean bill of health.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleExitNodeListCmd(false), newWhaleExitNodeListCmd(true))
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

func newWhaleExitNodeListCmd(suggest bool) *cobra.Command {
	var asns []string
	use, short := "list", "The ways out, ranked"
	if suggest {
		use, short = "suggest", "One recommendation, with its evidence"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cx, cancel := ctx()
			defer cancel()
			view := buildWhaleExitNodes(cx, asns)
			if suggest {
				return emitWhaleExitSuggestion(view)
			}
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			renderWhaleExitNodes(view)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&asns, "asn", nil,
		"also rank these ASNs (AS20473,AS60729) - how you compare transit before choosing")
	return cmd
}

// whaleExitView is the whole answer and the --json shape.
type whaleExitView struct {
	Candidates []whale.ExitCandidate `json:"candidates"`
	Keyed      bool                  `json:"keyed"`
	Note       string                `json:"note"`
	Notes      []string              `json:"notes,omitempty"`
}

// buildWhaleExitNodes assembles the candidate set and ranks it. Every leg is fail-open: a
// graph that does not answer costs the density column and adds a note, it never turns
// "which ways out do I have" into an error.
func buildWhaleExitNodes(cx context.Context, extraASNs []string) whaleExitView {
	view := whaleExitView{Note: whale.ExitNodeNote()}

	// The egress points, measured. Netcheck is the existing probe that already resolves
	// each box over both families and times it, so this adds no second measurement path.
	report := whale.Netcheck(cx, whaleBoxHosts(), whale.NewNetProber(whaleProbeTimeout))
	view.Candidates = exitCandidatesFromReport(report)
	for _, asn := range normaliseASNs(extraASNs) {
		view.Candidates = append(view.Candidates, whale.ExitCandidate{Name: asn, Kind: "asn", ASN: asn})
	}

	c, cerr := resolveClient(false, false)
	view.Keyed = cerr == nil && c != nil && !c.Credential().IsZero()
	if !view.Keyed {
		for i := range view.Candidates {
			view.Candidates[i].Density = whale.NewDensity(nil, nil, "")
		}
		view.Notes = append(view.Notes,
			"no key in effect, so the graph's density is not read - run `whisper login` for it. "+
				"The candidates and the round trips above are real and keyless.")
		view.Candidates = whale.RankExitCandidates(view.Candidates)
		return view
	}

	cache := map[string]whale.Density{}
	for i := range view.Candidates {
		asn := view.Candidates[i].ASN
		if asn == "" {
			view.Candidates[i].Density = whale.NewDensity(nil, nil, "")
			continue
		}
		d, ok := cache[asn]
		if !ok {
			var note string
			d, note = readASNDensity(cx, c, asn)
			if note != "" {
				view.Notes = appendUnique(view.Notes, note)
			}
			cache[asn] = d
		}
		view.Candidates[i].Density = d
	}
	view.Candidates = whale.RankExitCandidates(view.Candidates)
	view.Notes = appendUnique(view.Notes, densityHintFor(view.Candidates))
	return view
}

// densityHintFor is the line that makes this verb's own promise reachable. The default
// candidate set is the Whisper egress points, all of which present AS219419, and the graph
// holds no routed space for our own ASN - so a plain `exit-node list` shows two rows of
// `unknown` and a reader could reasonably conclude the graph ranking does not work. It
// works; it has nothing to rank. Saying how to give it something to rank is the difference
// between a help text that is true and one that is merely defensible.
//
// Returns "" when at least one density IS known, because a hint nobody needs is noise.
func densityHintFor(candidates []whale.ExitCandidate) string {
	for _, c := range candidates {
		if c.Density.Known {
			return ""
		}
	}
	return "no candidate here has a graph density, so this list is ordered on the measured round trip. " +
		"That is not the graph failing: the Whisper egress points all present AS219419, and the graph " +
		"holds no routed space for it. To see the graph ranking, name transit ASNs to compare: " +
		"`whisper whale exit-node list --asn AS3320,AS20473`."
}

// exitCandidatesFromReport turns a measured netcheck into candidates. A box that answered
// nothing carries the REASON and no round trip: a zero here would sort as instant, which is
// the shape that has turned a dead box into a recommendation before.
func exitCandidatesFromReport(report whale.NetcheckReport) []whale.ExitCandidate {
	out := make([]whale.ExitCandidate, 0, len(report.Boxes))
	for _, b := range report.Boxes {
		c := whale.ExitCandidate{Name: b.Host, Kind: "box", ASN: whisperEgressASN, Address: b.IPv6.Addr}
		if msVal, fam, ok := b.BestMs(); ok {
			c.RTTMs = msVal
			c.Note = "measured over " + fam
		} else {
			c.Note = "no probe answered: " + firstNonBlank(b.IPv6.Note, b.IPv4.Note, "nothing came back")
		}
		out = append(out, c)
	}
	return out
}

// whisperEgressASN is the ASN an agent's traffic presents to the internet whichever box
// carries it: the /128 comes out of 2a04:2a01::/32, announced by AS219419. Naming it is
// the point - the density column then honestly reports what the graph holds for OUR space,
// which today is nothing, rather than implying each box is a different neighbourhood.
const whisperEgressASN = "AS219419"

// readASNDensity reads the two machine-readable density fields for one ASN. Both reads are
// independent and either may come back empty; a failure is a note, never an error, and
// never a zero.
func readASNDensity(cx context.Context, c *client.Client, asn string) (whale.Density, string) {
	var fromDensity, fromExplain *float64
	coverage := ""
	note := ""

	qx, cancel := context.WithTimeout(cx, 20*time.Second)
	defer cancel()

	rows, _, err := c.GraphQueryRows(qx, "CALL whisper.asnThreatDensity($a)", map[string]any{"a": asn})
	switch {
	case err != nil:
		note = "the graph did not answer asnThreatDensity for " + asn + ": " + friendly(err)
	case len(rows) == 0:
		note = "the graph returned no asnThreatDensity row for " + asn
	default:
		fromDensity = asFloatPtr(rows[0]["densityRatio"])
		coverage = asString(rows[0]["coverage"])
	}

	erows, _, eerr := c.GraphQueryRows(qx, "CALL whisper.explain($a) YIELD indicator, found, breakdown",
		map[string]any{"a": asn})
	if eerr == nil && len(erows) > 0 {
		if bd, ok := erows[0]["breakdown"].(map[string]any); ok {
			fromExplain = asFloatPtr(bd["graphDensityRatio"])
		}
	}
	return whale.NewDensity(fromDensity, fromExplain, coverage), note
}

func emitWhaleExitSuggestion(view whaleExitView) error {
	best, why, ok := whale.SuggestExit(view.Candidates)
	if !ok {
		return &client.ProblemError{Status: 404, Detail: "there are no exit candidates to choose between: " +
			"no Whisper egress point answered a probe and no --asn was given"}
	}
	if g.jsonOut {
		emitJSONValue(map[string]any{"suggested": best, "why": why, "keyed": view.Keyed, "note": view.Note})
		return nil
	}
	fmt.Println(best.Name)
	whaleNote("%s", why)
	for _, n := range view.Notes {
		whaleNote("%s", n)
	}
	whaleNote("%s", view.Note)
	return nil
}

func renderWhaleExitNodes(view whaleExitView) {
	rows := make([][]string, 0, len(view.Candidates))
	for _, c := range view.Candidates {
		rows = append(rows, []string{
			c.Name,
			orDash(c.ASN),
			c.Density.Render(),
			fmtMs(c.RTTMs),
			firstNonBlank(c.Density.Note, c.Note),
		})
	}
	if len(rows) == 0 {
		rows = append(rows, []string{"-", "-", "-", "-", "no candidates"})
	}
	printTable([]string{"CANDIDATE", "ASN", "DENSITY", "RTT", "NOTE"}, rows)
	for _, n := range view.Notes {
		whaleNote("%s", n)
	}
	whaleNote("%s", view.Note)
}

// normaliseASNs is Postel at the flag boundary: AS20473, as20473, 20473 and a
// comma-separated run of them all name the same thing.
func normaliseASNs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		for _, field := range strings.Split(raw, ",") {
			s := strings.ToUpper(strings.TrimSpace(field))
			if s == "" {
				continue
			}
			if !strings.HasPrefix(s, "AS") {
				s = "AS" + s
			}
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// asFloatPtr reads a JSON number into a pointer, and returns nil for null, for a missing
// key and for anything that is not a number. That nil is load-bearing: it is what keeps a
// null densityRatio from becoming a zero the ranker would treat as excellent.
func asFloatPtr(v any) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case float32:
		f := float64(n)
		return &f
	case int:
		f := float64(n)
		return &f
	case int64:
		f := float64(n)
		return &f
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return &f
		}
	}
	return nil
}
