// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"strings"
	"testing"
	"time"
)

// The reference moment for every case here. Chosen well above epochAnchorFloor so a
// serial derived from it is a plausible production serial rather than a test artefact.
var snapNow = time.Unix(1_788_239_069, 0)

// TestAgeOf_ReadsAnEpochAnchoredSerialAsATime: the ordinary case, and the one the whole
// line rests on. bumpSerial = max(current+1, epochSeconds), so on any zone written less
// than once a second the serial IS the second it last changed.
func TestAgeOf_ReadsAnEpochAnchoredSerialAsATime(t *testing.T) {
	a := AgeOf("ns1.whisper.online", uint32(snapNow.Unix()-600), snapNow)
	if !a.Known {
		t.Fatalf("an epoch-anchored serial must be readable: %+v", a)
	}
	if a.Age != 10*time.Minute {
		t.Fatalf("Age = %v, want 10m", a.Age)
	}
	if a.AgeSeconds != 600 {
		t.Fatalf("AgeSeconds = %d, want 600", a.AgeSeconds)
	}
	if a.Note != "" {
		t.Fatalf("a known age carries no note, got %q", a.Note)
	}
}

// TestAgeOf_RefusesToDateASerialItCannotStandBehind. THE regression this guard exists for:
// a hand-written or imported serial (the classic YYYYMMDDnn form, or a plain counter) read
// as seconds since the epoch prints an age of decades, with total confidence, on a zone
// that may be perfectly fresh. An unknown age is the honest answer and it says why.
func TestAgeOf_RefusesToDateASerialItCannotStandBehind(t *testing.T) {
	for _, serial := range []uint32{0, 1, 42, 2026090101, 1_500_000_000} {
		a := AgeOf("ns1", serial, snapNow)
		if serial == 2026090101 {
			// The YYYYMMDDnn form overflows past a plausible epoch, so it is caught by the
			// LEAD check rather than the floor. Either way it must not be dated.
			if a.Known {
				t.Fatalf("serial %d must not be read as a time: %+v", serial, a)
			}
			continue
		}
		if a.Known {
			t.Fatalf("serial %d must not be read as a time: %+v", serial, a)
		}
		if a.Note == "" {
			t.Fatalf("serial %d was refused without saying why", serial)
		}
	}
}

// TestAgeOf_ASerialAheadOfTheClockIsNeverFreshness: a negative interval must never render
// as an age, because "0s old" on a zone whose serial is a year in the future is the most
// confident wrong answer this file could give. A SMALL lead is legitimate (every write
// above one per second buys a second) and reads as fresh; a large one is a finding.
func TestAgeOf_ASerialAheadOfTheClockIsNeverFreshness(t *testing.T) {
	small := AgeOf("ns1", uint32(snapNow.Unix()+30), snapNow)
	if !small.Known || small.Age != 0 {
		t.Fatalf("a 30s lead is an ordinary busy zone: %+v", small)
	}
	big := AgeOf("ns1", uint32(snapNow.Unix()+90_000), snapNow)
	if big.Known {
		t.Fatalf("a 25h lead must not be dated: %+v", big)
	}
	if !strings.Contains(big.Note, "ahead of this host's clock") {
		t.Fatalf("the reason must name the clock, got %q", big.Note)
	}
	if strings.Contains(big.Note, "is -") {
		t.Fatalf("the lead must be a magnitude, not a signed duration, got %q", big.Note)
	}
}

// TestSnapshotNote_SaysTheNodesAgree: the healthy fleet, which is what this prints almost
// always. It has to be short and it has to be unmistakable, or a reader stops looking.
func TestSnapshotNote_SaysTheNodesAgree(t *testing.T) {
	serial := uint32(snapNow.Unix() - 300)
	note := SnapshotNote("agents.whisper.online", []SnapshotAge{
		AgeOf("ns1.whisper.online", serial, snapNow),
		AgeOf("ns2.whisper.online", serial, snapNow),
	})
	if !strings.Contains(note, "same recent snapshot") {
		t.Fatalf("an agreeing fleet must say so, got %q", note)
	}
	if strings.Contains(note, "DISAGREE") {
		t.Fatalf("an agreeing fleet must not warn, got %q", note)
	}
	for _, want := range []string{"agents.whisper.online", "ns1.whisper.online 5m", "ns2.whisper.online 5m"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note must carry %q, got %q", want, note)
		}
	}
}

// TestSnapshotNote_SaysTheNodesDISAGREE. THE case this whole file exists for. Two nodes on
// different serials means which one answers decides what you are told, and a principal
// removed from the fleet may still be admitted by the node that is behind. It must be
// impossible to read the line and miss that.
func TestSnapshotNote_SaysTheNodesDISAGREE(t *testing.T) {
	note := SnapshotNote("agents.whisper.online", []SnapshotAge{
		AgeOf("ns1.whisper.online", uint32(snapNow.Unix()-60), snapNow),
		AgeOf("ns2.whisper.online", uint32(snapNow.Unix()-90_000), snapNow),
	})
	if !strings.Contains(note, "THE NODES DISAGREE") {
		t.Fatalf("divergence must be stated, got %q", note)
	}
	if !strings.Contains(note, "may still be admitted") {
		t.Fatalf("the consequence must be stated, not just the fact, got %q", note)
	}
	// Both ages are still shown: a warning with no numbers cannot be acted on.
	if !strings.Contains(note, "ns1.whisper.online 1m") || !strings.Contains(note, "ns2.whisper.online 25h") {
		t.Fatalf("both nodes must be named with their ages, got %q", note)
	}
}

// TestSnapshotNote_AnAgreeingButOldFleetIsStillNamed: the nodes can agree perfectly and
// still both be stale, which is what a fleet cut off from the primary as a whole looks
// like. Agreement is not health, and the line must not imply it is.
func TestSnapshotNote_AnAgreeingButOldFleetIsStillNamed(t *testing.T) {
	serial := uint32(snapNow.Unix() - 5*86_400)
	note := SnapshotNote("agents.whisper.online", []SnapshotAge{
		AgeOf("ns1", serial, snapNow),
		AgeOf("ns2", serial, snapNow),
	})
	if !strings.Contains(note, "older than a healthy fleet runs") {
		t.Fatalf("an old but agreeing fleet must still be flagged, got %q", note)
	}
	if strings.Contains(note, "same recent snapshot") {
		t.Fatalf("5 days is not recent, got %q", note)
	}
}

// TestSnapshotNote_ANodeThatDidNotAnswerIsShownRatherThanDropped: dropping it would hide
// exactly the node worth looking at. Its row carries its own reason and it does not turn
// the whole line into a warning by itself.
func TestSnapshotNote_ANodeThatDidNotAnswerIsShownRatherThanDropped(t *testing.T) {
	note := SnapshotNote("agents.whisper.online", []SnapshotAge{
		AgeOf("ns1", uint32(snapNow.Unix()-120), snapNow),
		{Server: "ns2", Note: "did not answer for the zone's SOA"},
	})
	if !strings.Contains(note, "ns2 unknown (did not answer") {
		t.Fatalf("a silent node must be named, got %q", note)
	}
	if !strings.Contains(note, "ns1 2m") {
		t.Fatalf("the node that DID answer must still be dated, got %q", note)
	}
}

// TestSnapshotNote_NothingDatableIsSaidPlainly: the control for the case above. When NO
// node could be dated, the line must not read as a clean bill of health, because an
// absence of evidence is the one thing this line must never render as evidence of absence.
func TestSnapshotNote_NothingDatableIsSaidPlainly(t *testing.T) {
	note := SnapshotNote("agents.whisper.online", []SnapshotAge{
		{Server: "ns1", Note: "did not answer for the zone's SOA"},
		{Server: "ns2", Note: "answered without an SOA record"},
	})
	if !strings.Contains(note, "of unknown age") {
		t.Fatalf("an undatable fleet must say so, got %q", note)
	}
	if strings.Contains(note, "same recent snapshot") {
		t.Fatalf("nothing was dated, so nothing may be called recent: %q", note)
	}
}

// TestSnapshotNote_EmptyYieldsNothing: a footnote that says nothing is worse than no
// footnote, so a run that read no nodes prints no line at all.
func TestSnapshotNote_EmptyYieldsNothing(t *testing.T) {
	if got := SnapshotNote("agents.whisper.online", nil); got != "" {
		t.Fatalf("no readings must render nothing, got %q", got)
	}
}

// TestSnapshotNote_IsStableAcrossOrdering: the same fleet read in a different order is the
// same fleet. Without this the line churns between runs and a person stops trusting it.
func TestSnapshotNote_IsStableAcrossOrdering(t *testing.T) {
	a := AgeOf("ns1.whisper.online", uint32(snapNow.Unix()-60), snapNow)
	b := AgeOf("ns2.whisper.online", uint32(snapNow.Unix()-60), snapNow)
	one := SnapshotNote("agents.whisper.online", []SnapshotAge{a, b})
	two := SnapshotNote("agents.whisper.online", []SnapshotAge{b, a})
	if one != two {
		t.Fatalf("ordering changed the line:\n%q\n%q", one, two)
	}
}

// TestRoundAge_ReadsAsAPersonWouldSayIt, including the days branch the snapshot age needs:
// "168h" is a number a reader has to divide before it means anything.
func TestRoundAge_ReadsAsAPersonWouldSayIt(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{47 * time.Hour, "47h"},
		{48 * time.Hour, "2d"},
		{7 * 24 * time.Hour, "7d"},
		{-90 * time.Second, "1m"}, // a magnitude, never a signed duration
	}
	for _, c := range cases {
		if got := roundAge(c.d); got != c.want {
			t.Fatalf("roundAge(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
