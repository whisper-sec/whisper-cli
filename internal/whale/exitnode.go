// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// exitnode.go is the exit-node half of Whalenet: which way out should this node take,
// and on what evidence.
//
// Tailscale ranks exit nodes by latency. We can do better, because we hold a graph that
// knows what else lives in an ASN. But "better" is only better if the number is real, so
// this file is written around one rule and one hazard.
//
// THE RULE: rank on a MACHINE-READABLE field. `whisper.explain` returns a prose sentence
// carrying a composite reputation score, and it is tempting to grep. Do not: it has no
// reputationScore COLUMN, its `score` column is 0.0 and its `level` is NONE, so a scraper
// would be reading English and calling it telemetry. The two fields that are real are
// `whisper.asnThreatDensity().densityRatio` and `whisper.explain().breakdown.
// graphDensityRatio`. Both are read, both are shown, and a disagreement between them is
// surfaced rather than averaged away.
//
// THE HAZARD: an ASN with no routed space in the graph returns densityRatio NULL, not 0.
// Live today, AS219419 - our own - answers exactly that, with coverage "no-routed-space".
// A ranker that read null as 0.0 would sort our own ASN top and call it evidence of being
// clean. So Density has three states, not two, the unknown one carries the reason, and
// nothing in this file lets an unknown become a number. A fault and an answer are
// different things and the type refuses to conflate them.

// Density is one ASN's threat density as the graph reports it, or the fact that the graph
// did not report one. Ratio is meaningful ONLY when Known is true.
type Density struct {
	Known bool `json:"known"`
	// Ratio is listed IPs over announced IPv4 space: lower is better. Only read it when
	// Known.
	Ratio float64 `json:"ratio,omitempty"`
	// FromThreatDensity and FromExplain are the two independent machine-readable sources,
	// kept separately so `suggest` can show both and a disagreement cannot hide.
	FromThreatDensity *float64 `json:"from_threat_density,omitempty"`
	FromExplain       *float64 `json:"from_explain,omitempty"`
	// Coverage is the graph's own word for why: "computed", "no-routed-space", "".
	Coverage string `json:"coverage,omitempty"`
	// Note says why an unknown is unknown, in words a person can act on.
	Note string `json:"note,omitempty"`
}

// densityAgreementEpsilon: two reads of the same underlying figure that differ by more than
// this are reported as a disagreement rather than silently reconciled.
const densityAgreementEpsilon = 1e-9

// NewDensity folds the two sources into one answer. Either may be absent. A ratio that is
// not a real number in [0,1] is treated as absent: a corrupt reading must not outrank a
// clean one.
func NewDensity(fromThreatDensity, fromExplain *float64, coverage string) Density {
	d := Density{Coverage: strings.TrimSpace(coverage)}
	td := usableRatio(fromThreatDensity)
	ex := usableRatio(fromExplain)
	d.FromThreatDensity, d.FromExplain = td, ex
	switch {
	case td != nil:
		d.Known, d.Ratio = true, *td
	case ex != nil:
		d.Known, d.Ratio = true, *ex
	default:
		d.Note = unknownDensityNote(d.Coverage)
		return d
	}
	if td != nil && ex != nil && math.Abs(*td-*ex) > densityAgreementEpsilon {
		d.Note = fmt.Sprintf("the two graph reads disagree: asnThreatDensity says %g, explain says %g", *td, *ex)
	}
	return d
}

func usableRatio(v *float64) *float64 {
	if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > 1 {
		return nil
	}
	return v
}

func unknownDensityNote(coverage string) string {
	switch coverage {
	case "no-routed-space":
		return "the graph holds no routed space for this ASN, so there is no density to compute - " +
			"absence of a signal, not a clean bill of health"
	case "":
		return "the graph was not asked or did not answer"
	default:
		return "the graph reported coverage " + coverage + " and no density"
	}
}

// Render is what a table cell shows. An unknown density is never a number and never a
// blank: a blank cell reads as zero to everybody who has ever looked at a table.
func (d Density) Render() string {
	if !d.Known {
		return "unknown"
	}
	return fmt.Sprintf("%.4f", d.Ratio)
}

// ExitCandidate is one way out, with everything the ranking used.
type ExitCandidate struct {
	Name    string  `json:"name"`
	Kind    string  `json:"kind"` // "box" | "asn"
	Address string  `json:"address,omitempty"`
	ASN     string  `json:"asn,omitempty"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Density Density `json:"density"`
	// Note carries anything a reader needs to interpret the row (a probe that did not run,
	// an ASN we could not determine). Never used to carry a ranking value.
	Note string `json:"note,omitempty"`
}

// RankExitCandidates orders candidates best-first and is the whole ranking policy, in one
// pure function so it can be argued with in a test rather than in production.
//
// Order:
// 1. a KNOWN density, ascending - lower listed-IP density is a cleaner neighbourhood;
// 2. then candidates with an UNKNOWN density, because absence of a signal must not
// outrank a measured clean one, and must not be treated as dirty either;
// 3. within each group, a measured RTT ascending (an unmeasured RTT sorts last, since a
// zero here means "not probed", not "instant");
// 4. then by name, so the order is stable and a diff of two runs means something.
func RankExitCandidates(in []ExitCandidate) []ExitCandidate {
	out := append([]ExitCandidate(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Density.Known != b.Density.Known {
			return a.Density.Known
		}
		if a.Density.Known && a.Density.Ratio != b.Density.Ratio {
			return a.Density.Ratio < b.Density.Ratio
		}
		am, bm := a.RTTMs > 0, b.RTTMs > 0
		if am != bm {
			return am
		}
		if am && a.RTTMs != b.RTTMs {
			return a.RTTMs < b.RTTMs
		}
		return a.Name < b.Name
	})
	return out
}

// SuggestExit picks one candidate and says why in the same breath, because a suggestion
// without its evidence is an opinion. ok is false when there is nothing to suggest.
func SuggestExit(in []ExitCandidate) (ExitCandidate, string, bool) {
	ranked := RankExitCandidates(in)
	if len(ranked) == 0 {
		return ExitCandidate{}, "", false
	}
	best := ranked[0]
	var why strings.Builder
	if best.Density.Known {
		fmt.Fprintf(&why, "%s has the lowest graph threat density of the candidates: %s",
			exitLabel(best), best.Density.Render())
		if best.Density.FromThreatDensity != nil && best.Density.FromExplain != nil {
			fmt.Fprintf(&why, " (asnThreatDensity.densityRatio %g, explain.breakdown.graphDensityRatio %g)",
				*best.Density.FromThreatDensity, *best.Density.FromExplain)
		}
		if next, ok := firstOther(ranked, best); ok && next.Density.Known {
			fmt.Fprintf(&why, ", against %s at %s", exitLabel(next), next.Density.Render())
		}
	} else {
		fmt.Fprintf(&why, "no candidate has a graph density: %s. Ranked on measured round trip instead",
			best.Density.Note)
		if best.RTTMs > 0 {
			fmt.Fprintf(&why, ", and %s answered fastest at %.1f ms", exitLabel(best), best.RTTMs)
		}
	}
	return best, why.String(), true
}

func exitLabel(c ExitCandidate) string {
	if c.ASN != "" && c.ASN != c.Name {
		return c.Name + " (" + c.ASN + ")"
	}
	return c.Name
}

func firstOther(ranked []ExitCandidate, best ExitCandidate) (ExitCandidate, bool) {
	for _, c := range ranked {
		if c.Name != best.Name {
			return c, true
		}
	}
	return ExitCandidate{}, false
}

// ExitNodeNote is the line under the table. Exit nodes have the same two structural
// constraints subnet routers do, and the table must not imply otherwise.
//
// The blocker clause is derived from UniversalDirectPathAvailable rather than written out,
// for the same reason SupportForRoutes reads it: when the code that builds a general
// direct path lands, this sentence corrects itself and nobody has to remember this file.
// It also has to be the UNIVERSAL constant and not DirectPathAvailable. The two used to be
// one thing; now that many pairs DO get a direct path, a flat "this build does not have
// one" is a claim a reader disproves in a single `whale status`, and a sentence a reader
// catches out is a sentence they stop believing the rest of.
func ExitNodeNote() string {
	blocker := "and needs a direct node-to-node path to EVERY node that would use it, which this " +
		"build does not have for the general case: many pairs get one, but a pair with a " +
		"port-varying NAT at both ends still relays and a pair split across two boxes has no " +
		"path at all"
	if UniversalDirectPathAvailable {
		blocker = "and needs a direct node-to-node path, which this build now has"
	}
	return "These are the Whisper egress points this node can use today. A PEER-advertised exit node is " +
		"kernel-tier only " + blocker + ". Density is " +
		"the graph's listed-IP ratio for the ASN, read from asnThreatDensity().densityRatio and " +
		"explain().breakdown.graphDensityRatio - never from the prose in an explanation."
}
