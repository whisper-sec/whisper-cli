// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"math"
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }

// --- density ---------------------------------------------------------------------------

// The live shape this was written against: AS60729 answers densityRatio
// 0.24088541666666666 with coverage "computed", and explain's breakdown carries the same
// figure at graphDensityRatio. Both are read, both are kept.
func TestNewDensityKeepsBothSources(t *testing.T) {
	d := NewDensity(f(0.24088541666666666), f(0.24088541666666666), "computed")
	if !d.Known {
		t.Fatal("a computed density must be Known")
	}
	if d.Ratio != 0.24088541666666666 {
		t.Fatalf("ratio = %v", d.Ratio)
	}
	if d.FromThreatDensity == nil || d.FromExplain == nil {
		t.Fatal("both machine-readable sources must survive: suggest has to show them")
	}
	if d.Note != "" {
		t.Fatalf("note = %q, want none when the two sources agree", d.Note)
	}
}

// THE hazard. Live today AS219419 answers densityRatio null with coverage
// "no-routed-space". Reading that as 0.0 would rank our own ASN top on invented evidence.
func TestNewDensityNullIsUnknownNotZero(t *testing.T) {
	d := NewDensity(nil, nil, "no-routed-space")
	if d.Known {
		t.Fatal("a null densityRatio must not be Known")
	}
	if d.Ratio != 0 {
		t.Fatalf("ratio = %v; an unknown must carry no number at all", d.Ratio)
	}
	if d.Render() != "unknown" {
		t.Fatalf("Render() = %q, want unknown - a blank cell reads as zero", d.Render())
	}
	if !strings.Contains(d.Note, "no routed space") || !strings.Contains(d.Note, "not a clean bill of health") {
		t.Fatalf("note = %q, want the reason and the warning against reading it as clean", d.Note)
	}
}

func TestNewDensityUnaskedSaysSo(t *testing.T) {
	d := NewDensity(nil, nil, "")
	if d.Known || !strings.Contains(d.Note, "not asked") {
		t.Fatalf("d = %+v, want an unknown that says the graph was not asked", d)
	}
}

func TestNewDensityFallsBackToExplain(t *testing.T) {
	d := NewDensity(nil, f(0.5), "computed")
	if !d.Known || d.Ratio != 0.5 {
		t.Fatalf("d = %+v, want explain's figure used when threat density is absent", d)
	}
}

func TestNewDensitySurfacesADisagreement(t *testing.T) {
	d := NewDensity(f(0.24), f(0.31), "computed")
	if !d.Known {
		t.Fatal("a disagreement is still an answer")
	}
	if !strings.Contains(d.Note, "disagree") {
		t.Fatalf("note = %q, want the disagreement surfaced rather than averaged away", d.Note)
	}
}

// A corrupt reading must not become a ranking value: it is absence, not excellence.
func TestNewDensityRejectsUnusableNumbers(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.5, 1.5} {
		if d := NewDensity(f(v), nil, "computed"); d.Known {
			t.Fatalf("NewDensity(%v) was accepted as a ranking value", v)
		}
	}
}

func TestDensityRenderIsFixedWidthAndNeverBlank(t *testing.T) {
	if got := NewDensity(f(0.24088541666666666), nil, "computed").Render(); got != "0.2409" {
		t.Fatalf("Render() = %q, want 0.2409", got)
	}
	if got := (Density{}).Render(); got != "unknown" {
		t.Fatalf("zero-value Render() = %q, want unknown", got)
	}
}

// --- ranking ---------------------------------------------------------------------------

func TestRankPutsLowDensityAboveHigh(t *testing.T) {
	got := RankExitCandidates([]ExitCandidate{
		{Name: "dirty", ASN: "AS60729", Density: NewDensity(f(0.2409), f(0.2409), "computed")},
		{Name: "clean", ASN: "AS20473", Density: NewDensity(f(0.0012), f(0.0012), "computed")},
	})
	if got[0].Name != "clean" {
		t.Fatalf("order = %s,%s, want the lower density first", got[0].Name, got[1].Name)
	}
}

// An unknown density sorts below every known one, and above nothing on its own merit.
func TestRankPutsUnknownDensityAfterKnown(t *testing.T) {
	got := RankExitCandidates([]ExitCandidate{
		{Name: "ours", ASN: "AS219419", RTTMs: 0.4, Density: NewDensity(nil, nil, "no-routed-space")},
		{Name: "dirty", ASN: "AS60729", RTTMs: 90, Density: NewDensity(f(0.2409), nil, "computed")},
	})
	if got[0].Name != "dirty" {
		t.Fatalf("order = %s,%s: an unknown must not outrank a measured one on a fast RTT", got[0].Name, got[1].Name)
	}
}

func TestRankUsesRTTWithinAGroup(t *testing.T) {
	got := RankExitCandidates([]ExitCandidate{
		{Name: "ns2", RTTMs: 24.1, Density: NewDensity(nil, nil, "no-routed-space")},
		{Name: "ns1", RTTMs: 0.9, Density: NewDensity(nil, nil, "no-routed-space")},
	})
	if got[0].Name != "ns1" {
		t.Fatalf("order = %s,%s, want the faster first", got[0].Name, got[1].Name)
	}
}

// An RTT of zero means "not probed". It must sort last, not first.
func TestRankTreatsAnUnmeasuredRTTAsUnmeasured(t *testing.T) {
	got := RankExitCandidates([]ExitCandidate{
		{Name: "unprobed", RTTMs: 0, Density: NewDensity(nil, nil, "")},
		{Name: "probed", RTTMs: 24.1, Density: NewDensity(nil, nil, "")},
	})
	if got[0].Name != "probed" {
		t.Fatalf("order = %s,%s: a zero RTT is not instant, it is unmeasured", got[0].Name, got[1].Name)
	}
}

func TestRankIsStableAndDeterministic(t *testing.T) {
	in := []ExitCandidate{
		{Name: "b", Density: NewDensity(nil, nil, "")},
		{Name: "a", Density: NewDensity(nil, nil, "")},
		{Name: "c", Density: NewDensity(nil, nil, "")},
	}
	first := RankExitCandidates(in)
	second := RankExitCandidates(in)
	for i := range first {
		if first[i].Name != second[i].Name {
			t.Fatal("ranking is not deterministic; a diff of two runs would mean nothing")
		}
	}
	if first[0].Name != "a" || first[2].Name != "c" {
		t.Fatalf("order = %v, want a,b,c", []string{first[0].Name, first[1].Name, first[2].Name})
	}
}

func TestRankDoesNotMutateItsInput(t *testing.T) {
	in := []ExitCandidate{
		{Name: "dirty", Density: NewDensity(f(0.9), nil, "computed")},
		{Name: "clean", Density: NewDensity(f(0.1), nil, "computed")},
	}
	RankExitCandidates(in)
	if in[0].Name != "dirty" {
		t.Fatal("the caller's slice was reordered underneath it")
	}
}

// --- suggest ----------------------------------------------------------------------------

// The acceptance criterion, exactly: a low-density ASN above a high-density one, with BOTH
// machine-readable values shown and no prose scraped from an explanation.
func TestSuggestShowsBothMachineReadableValues(t *testing.T) {
	best, why, ok := SuggestExit([]ExitCandidate{
		{Name: "dirty", ASN: "AS60729", Density: NewDensity(f(0.24088541666666666), f(0.24088541666666666), "computed")},
		{Name: "clean", ASN: "AS20473", Density: NewDensity(f(0.0012), f(0.0012), "computed")},
	})
	if !ok || best.Name != "clean" {
		t.Fatalf("best = %s (ok=%v), want clean", best.Name, ok)
	}
	for _, want := range []string{"asnThreatDensity.densityRatio", "explain.breakdown.graphDensityRatio", "0.0012", "AS60729"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why = %q is missing %q", why, want)
		}
	}
}

func TestSuggestWithNoDensityRanksOnRTTAndSaysSo(t *testing.T) {
	best, why, ok := SuggestExit([]ExitCandidate{
		{Name: "ns2", ASN: "AS219419", RTTMs: 24.1, Density: NewDensity(nil, nil, "no-routed-space")},
		{Name: "ns1", ASN: "AS219419", RTTMs: 0.9, Density: NewDensity(nil, nil, "no-routed-space")},
	})
	if !ok || best.Name != "ns1" {
		t.Fatalf("best = %s (ok=%v), want ns1", best.Name, ok)
	}
	if !strings.Contains(why, "no candidate has a graph density") || !strings.Contains(why, "0.9 ms") {
		t.Fatalf("why = %q, want the missing signal and the measurement it fell back to", why)
	}
	if strings.Contains(why, "0.0000") {
		t.Fatalf("why = %q fabricates a density figure", why)
	}
}

func TestSuggestOnAnEmptySetSaysNothing(t *testing.T) {
	if _, _, ok := SuggestExit(nil); ok {
		t.Fatal("an empty candidate set must not produce a suggestion")
	}
}

func TestExitNodeNoteStatesTheConstraints(t *testing.T) {
	n := ExitNodeNote()
	for _, want := range []string{"kernel-tier only", "direct node-to-node path", "densityRatio", "never from the prose"} {
		if !strings.Contains(n, want) {
			t.Fatalf("note is missing %q: %s", want, n)
		}
	}
}

// TestExitNodeNoteTracksUniversalDirectPathAvailable: the note under the exit-node table
// carries the same blocker the route refusal does, and it must be derived from the same
// constant rather than written out.
//
// It used to say flatly "which this build does not have". The direct-path work then made
// DirectPathAvailable true, `whale status` started printing direct-local cells, and the
// sentence became something a reader disproves in one command - which costs them their
// belief in the rest of it, including the part about where the density number comes from.
// Asserted in BOTH directions, so it can never turn itself off, and against the UNIVERSAL
// constant, because an exit node has to be reachable by every node that would use it.
func TestExitNodeNoteTracksUniversalDirectPathAvailable(t *testing.T) {
	note := ExitNodeNote()
	if UniversalDirectPathAvailable {
		if !strings.Contains(note, "which this build now has") {
			t.Fatalf("a general direct path exists, so the note must have opened on its own:\n%s", note)
		}
		return
	}
	if !strings.Contains(note, "does not have for the general case") {
		t.Fatalf("the note must name the missing GENERAL direct path:\n%s", note)
	}
	if strings.Contains(note, "which this build does not have.") {
		t.Fatalf("the flat claim is disprovable by one `whale status` in this build:\n%s", note)
	}
	// The note still has to carry the other structural constraint and the provenance of the
	// number, or trimming the blocker would have cost the two things the line is for.
	for _, want := range []string{"kernel-tier only", "asnThreatDensity().densityRatio",
		"explain().breakdown.graphDensityRatio", "never from the prose"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note lost %q:\n%s", want, note)
		}
	}
}
