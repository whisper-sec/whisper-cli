// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"testing"
	"time"
)

func snapOf(b *Book) Snapshot { return Snap(b, Options{Now: testNow}) }

// A tail that opened by replaying the whole standing book as news would be the one thing
// a tail must not do. The first poll is a baseline.
func TestDiff_TheFirstPollIsABaselineNotNews(t *testing.T) {
	if got := Diff(Snapshot{}, snapOf(busyBook()), testNow); len(got) != 0 {
		t.Fatalf("the first poll emitted %d change(s); it must emit none", len(got))
	}
}

// THE rule that keeps a tail usable: emit on a state change, never on a severity change.
// Severity is derived and moves as the graph improves, so a feed that emitted on it would
// get noisier every time our intelligence got better - exactly backwards.
func TestDiff_AScoreMoveIsNotAChange(t *testing.T) {
	before := busyBook()
	after := busyBook()
	after.Rows[0].Fused = ptr(99.0)
	after.Rows[0].Priority = ptr(99.0)
	after.Rows[0].Exposure = "critical"
	after.Rows[0].Title = "an edited sentence that says the same thing"
	if got := Diff(snapOf(before), snapOf(after), testNow); len(got) != 0 {
		t.Fatalf("a score, exposure and prose edit emitted %d change(s): %+v", len(got), got)
	}
}

// A demotion is never emitted. A row falling out of act-now has become LESS interesting,
// and waking somebody for that would be paying for a graph update with an interruption.
func TestDiff_ADemotionIsSilentAndAPromotionIsNot(t *testing.T) {
	base := busyBook()

	down := busyBook()
	down.Rows[0].Lane = LaneReview
	if got := Diff(snapOf(base), snapOf(down), testNow); len(got) != 0 {
		t.Fatalf("a lane demotion emitted %d change(s): %+v", len(got), got)
	}

	up := busyBook()
	up.Rows[1].Lane = LaneActNow
	got := Diff(snapOf(base), snapOf(up), testNow)
	if len(got) != 1 || got[0].Kind != ChangePromoted {
		t.Fatalf("a promotion emitted %+v; want exactly one %q", got, ChangePromoted)
	}
}

func TestDiff_OpensHoldsReleasesSeversAndResolves(t *testing.T) {
	base := busyBook()

	opened := busyBook()
	extra := rowAt(LaneActNow, "T1490", 2*time.Minute)
	extra.Agent, extra.Address = "backup-01", "2a04:2a01:9::9"
	opened.Rows = append(opened.Rows, extra)
	opened.Index()
	if got := Diff(snapOf(base), snapOf(opened), testNow); len(got) != 1 || got[0].Kind != ChangeOpened {
		t.Fatalf("a new condition emitted %+v; want one %q", got, ChangeOpened)
	}

	held := busyBook()
	held.Rows[0].Ack = "dana"
	if got := Diff(snapOf(base), snapOf(held), testNow); len(got) != 1 || got[0].Kind != ChangeHeld {
		t.Fatalf("an acknowledgement emitted %+v; want one %q", got, ChangeHeld)
	}

	released := busyBook()
	released.Rows[1].Assignee = ""
	if got := Diff(snapOf(base), snapOf(released), testNow); len(got) != 1 || got[0].Kind != ChangeReleased {
		t.Fatalf("a released row emitted %+v; want one %q", got, ChangeReleased)
	}

	severed := busyBook()
	severed.Trail = []Action{landed("2a04:2a01:9::1", 2*time.Minute)}
	got := Diff(snapOf(base), snapOf(severed), testNow)
	if len(got) != 1 || got[0].Kind != ChangeSevered {
		t.Fatalf("a landed containment emitted %+v; want one %q", got, ChangeSevered)
	}
	// The receipt says what we actually did, and what we did not.
	if got[0].Line == "" || !contains(got[0].Line, "files on disk are unchanged") {
		t.Fatalf("the severed line overclaims: %q", got[0].Line)
	}

	gone := busyBook()
	gone.Rows = gone.Rows[:1]
	gone.Index()
	if got := Diff(snapOf(base), snapOf(gone), testNow); len(got) != 1 || got[0].Kind != ChangeResolved {
		t.Fatalf("a vanished condition emitted %+v; want one %q", got, ChangeResolved)
	}
}

// Every change carries the whole row, so a consumer piping NDJSON never needs a second
// call before it can act.
func TestDiff_EveryChangeCarriesItsRow(t *testing.T) {
	base := busyBook()
	held := busyBook()
	held.Rows[0].Ack = "dana"
	for _, ch := range Diff(snapOf(base), snapOf(held), testNow) {
		if ch.Alert.Ref == "" || ch.Alert.Ref != ch.Ref {
			t.Fatalf("change %+v does not carry its own row", ch)
		}
		if ch.Alert.Interrupt == "" {
			t.Fatalf("change %+v carries a row with no interrupt verdict", ch)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
