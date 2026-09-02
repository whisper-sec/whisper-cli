// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// --- wiring: the anti-unreachable gate ------------------------------------------------

func TestWhaleExitNodeIsReachableFromTheRoot(t *testing.T) {
	for _, sub := range []string{"list", "suggest"} {
		c := whaleSubcommand(t, "whale", "exit-node", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale exit-node %s` has no RunE, so it does nothing", sub)
		}
		if c.Flags().Lookup("asn") == nil {
			t.Fatalf("`whisper whale exit-node %s` has no --asn flag", sub)
		}
	}
	// tailscale spells it exitnode in scripts; accept both rather than teach a new word.
	if c := whaleSubcommand(t, "whale", "exitnode"); c.Name() != "exit-node" {
		t.Fatalf("the exitnode alias resolves to %q", c.Name())
	}
}

// --- candidates from a measurement ------------------------------------------------------

func TestExitCandidatesCarryTheMeasuredRTT(t *testing.T) {
	report := whale.NetcheckReport{Boxes: []whale.BoxReport{{
		Host: "ns1.whisper.online",
		IPv6: whale.FamilyProbe{Family: "ipv6", Addr: "2a05:f480:1400:ab7::fe45:10c", TCP443: true, TCPMs: 24.3},
	}}}
	got := exitCandidatesFromReport(report)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	if got[0].RTTMs != 24.3 || !strings.Contains(got[0].Note, "ipv6") {
		t.Fatalf("candidate = %+v, want the measurement and the family it came from", got[0])
	}
	if got[0].ASN != whisperEgressASN {
		t.Fatalf("asn = %q, want the ASN an agent's traffic actually presents", got[0].ASN)
	}
}

// A box that answered nothing must carry the REASON and no round trip. A zero RTT would
// sort as instant and turn a dead box into the recommendation.
func TestExitCandidateWithNoAnswerCarriesTheReasonNotAZero(t *testing.T) {
	report := whale.NetcheckReport{Boxes: []whale.BoxReport{{
		Host: "ns2.whisper.online",
		IPv6: whale.FamilyProbe{Family: "ipv6", Note: "no IPv6 route on this host"},
	}}}
	got := exitCandidatesFromReport(report)
	if got[0].RTTMs != 0 {
		t.Fatalf("rtt = %v, want none recorded", got[0].RTTMs)
	}
	if !strings.Contains(got[0].Note, "no IPv6 route") {
		t.Fatalf("note = %q, want the probe's own reason", got[0].Note)
	}
	ranked := whale.RankExitCandidates(append(got, whale.ExitCandidate{Name: "alive", RTTMs: 24.3}))
	if ranked[0].Name != "alive" {
		t.Fatalf("ranked %s first; a box that answered nothing must not lead", ranked[0].Name)
	}
}

func TestExitCandidatesOnAnEmptyReport(t *testing.T) {
	if got := exitCandidatesFromReport(whale.NetcheckReport{}); len(got) != 0 {
		t.Fatalf("got %d candidates from an empty report", len(got))
	}
}

// --- reading the graph's numbers ----------------------------------------------------------

// THE hazard, at the JSON boundary: densityRatio comes back null for an ASN with no routed
// space (live, AS219419). It must arrive as nil, never as 0.0.
func TestASNDensityNullDecodesToNil(t *testing.T) {
	var row map[string]any
	live := `{"asn":"AS219419","listedIps":0,"announcedIpv4":0,"densityRatio":null,"coverage":"no-routed-space"}`
	if err := json.Unmarshal([]byte(live), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := asFloatPtr(row["densityRatio"]); got != nil {
		t.Fatalf("asFloatPtr(null) = %v, want nil - a null must never become a ranking number", *got)
	}
	d := whale.NewDensity(asFloatPtr(row["densityRatio"]), nil, asString(row["coverage"]))
	if d.Known || d.Render() != "unknown" {
		t.Fatalf("density = %+v, want an unknown that renders as unknown", d)
	}
}

// The other live shape, so the decode is proven on a real row rather than a hand-written one.
func TestASNDensityComputedDecodesToTheFigure(t *testing.T) {
	var row map[string]any
	live := `{"asn":"AS60729","listedIps":185,"announcedIpv4":768,"densityRatio":0.24088541666666666,"coverage":"computed"}`
	if err := json.Unmarshal([]byte(live), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := asFloatPtr(row["densityRatio"])
	if got == nil || *got != 0.24088541666666666 {
		t.Fatalf("asFloatPtr = %v, want the live figure", got)
	}
}

// explain's density lives inside the breakdown MAP, not in a column. Prove we read the map.
func TestExplainBreakdownDensityDecodes(t *testing.T) {
	var row map[string]any
	live := `{"indicator":"AS60729","found":true,"breakdown":{"graphDensityRatio":0.24088541666666666,` +
		`"reputationScore":46.82743014070445}}`
	if err := json.Unmarshal([]byte(live), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bd, ok := row["breakdown"].(map[string]any)
	if !ok {
		t.Fatal("breakdown did not decode as a map")
	}
	if got := asFloatPtr(bd["graphDensityRatio"]); got == nil || *got != 0.24088541666666666 {
		t.Fatalf("graphDensityRatio = %v, want the live figure", got)
	}
}

func TestAsFloatPtrRejectsNonNumbers(t *testing.T) {
	for _, v := range []any{nil, "0.24", true, map[string]any{}, []any{1.0}} {
		if got := asFloatPtr(v); got != nil {
			t.Fatalf("asFloatPtr(%v) = %v, want nil", v, *got)
		}
	}
}

// --- flags ---------------------------------------------------------------------------------

func TestNormaliseASNsIsLiberalInWhatItAccepts(t *testing.T) {
	got := normaliseASNs([]string{"as20473, 60729", "AS20473", "  ", "as219419"})
	want := []string{"AS20473", "AS219419", "AS60729"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNormaliseASNsOnNothing(t *testing.T) {
	if got := normaliseASNs(nil); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

func TestAppendUniqueDoesNotRepeatANote(t *testing.T) {
	list := appendUnique(appendUnique(nil, "a"), "a")
	if len(list) != 1 {
		t.Fatalf("list = %v, want one entry", list)
	}
}

// --- the density hint ------------------------------------------------------------

// The verb promises ranking "by what the graph knows". The DEFAULT candidate set is the
// Whisper egress points, which all present AS219419, and the graph holds no routed space
// for our own ASN - so the default run can only ever show `unknown`. That is honest but it
// reads like a broken feature, so the list must say how to make the graph ranking visible.
func TestExitNodeListHintsHowToSeeTheGraphRankingWhenNothingIsKnown(t *testing.T) {
	view := whaleExitView{Candidates: []whale.ExitCandidate{
		{Name: "ns1.whisper.online", Kind: "box", ASN: whisperEgressASN, RTTMs: 31,
			Density: whale.NewDensity(nil, nil, "no-routed-space")},
		{Name: "ns2.whisper.online", Kind: "box", ASN: whisperEgressASN, RTTMs: 33,
			Density: whale.NewDensity(nil, nil, "no-routed-space")},
	}}
	hint := densityHintFor(view.Candidates)
	if hint == "" {
		t.Fatal("no hint on a list where every density is unknown: the reader is left thinking the " +
			"graph ranking does not work")
	}
	for _, want := range []string{"--asn", whisperEgressASN, "round trip"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("hint %q does not mention %q", hint, want)
		}
	}
}

// And it must go away the moment it stops being true, or it becomes noise on exactly the
// runs where the feature IS demonstrating itself.
func TestExitNodeHintDisappearsOnceADensityIsKnown(t *testing.T) {
	known := 0.0002
	cands := []whale.ExitCandidate{
		{Name: "ns1.whisper.online", Kind: "box", ASN: whisperEgressASN,
			Density: whale.NewDensity(nil, nil, "no-routed-space")},
		{Name: "AS3320", Kind: "asn", ASN: "AS3320",
			Density: whale.NewDensity(&known, &known, "computed")},
	}
	if h := densityHintFor(cands); h != "" {
		t.Fatalf("hint %q shown on a list that already carries a real density", h)
	}
	if h := densityHintFor(nil); h == "" {
		t.Fatal("an empty candidate list has no known density either, so the hint still applies")
	}
}
