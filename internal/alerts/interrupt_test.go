// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 30, 3, 30, 0, 0, time.UTC)

func ms(t time.Time) int64 { return t.UnixMilli() }

func rowAt(lane, technique string, began time.Duration) Row {
	return Row{
		Agent:     "finance-01",
		Address:   "2a04:2a01:9::1",
		ID:        technique,
		Technique: technique,
		Kind:      "detection",
		Title:     "nine files were encrypted in 40 seconds",
		Lane:      lane,
		State:     StateOpen,
		FirstSeen: ms(testNow.Add(-began)),
	}
}

func landed(addr string, at time.Duration) Action {
	return Action{TsMs: ms(testNow.Add(-at)), Action: "revoke", Address: addr, Result: "ok"}
}

func refused(addr string, at time.Duration) Action {
	return Action{TsMs: ms(testNow.Add(-at)), Action: "revoke", Address: addr,
		Result: "refused:disarmed", Detail: "containment is not armed for this endpoint"}
}

// The interruption test, as a fixture table. This is the assertion a reviewer points at
// when somebody changes the scoring model: if any change to it makes the contained
// ransomware row page, or makes the refused one quiet, this fails.
func TestJudge_InterruptComesFromAgencyNotSeverity(t *testing.T) {
	online := Endpoint{Address: "2a04:2a01:9::1", Connectivity: "online", Sensor: "shipping", known: true}
	offline := Endpoint{Address: "2a04:2a01:9::1", Connectivity: "offline", Sensor: "absent", known: true}

	cases := []struct {
		name  string
		row   Row
		ep    Endpoint
		trail []Action
		want  string
	}{
		{
			name: "the worst thing we know of, still running, nobody on it",
			row:  rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:   online, want: InterruptPage,
		},
		{
			name:  "the same thing, after we severed the identity: a receipt, not a page",
			row:   rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:    online,
			trail: []Action{landed("2a04:2a01:9::1", 16*time.Minute)},
			want:  InterruptDigest,
		},
		{
			name:  "we reached for containment and it did not take, and the host is reachable",
			row:   rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:    online,
			trail: []Action{refused("2a04:2a01:9::1", 16*time.Minute)},
			want:  InterruptPage,
		},
		{
			name: "a human already has it",
			row: func() Row {
				r := rowAt(LaneActNow, "T1486", 19*time.Minute)
				r.Ack = "operator-a"
				r.AckAt = ptr(ms(testNow.Add(-10 * time.Minute)))
				return r
			}(),
			ep: online, want: InterruptDigest,
		},
		{
			name: "that human acknowledged it three weeks ago and nothing moved",
			row: func() Row {
				r := rowAt(LaneActNow, "T1486", 22*24*time.Hour)
				r.Ack = "operator-a"
				r.AckAt = ptr(ms(testNow.Add(-22 * 24 * time.Hour)))
				return r
			}(),
			ep: online, want: InterruptPage,
		},
		{
			name: "a laptop in a bag at 3am, on a technique that is not destructive",
			row:  rowAt(LaneActNow, "T1021.004", 19*time.Minute),
			ep:   offline, want: InterruptDigest,
		},
		{
			name: "the same bag, but the technique is ransomware and we could not reach it",
			row:  rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:   offline, want: InterruptPage,
		},
		{
			name: "the plane bands it for review",
			row:  rowAt(LaneReview, "T1021.004", 4*time.Hour),
			ep:   online, want: InterruptDigest,
		},
		{
			name: "never scored is read, never silenced",
			row:  rowAt(LaneUnscored, "T1055", time.Hour),
			ep:   online, want: InterruptDigest,
		},
		{
			name: "banded below review: counted, not raised",
			row:  rowAt(LaneQuiet, "T1055", time.Hour),
			ep:   online, want: InterruptSilent,
		},
		{
			name:  "a containment that landed BEFORE the finding began proves nothing about it",
			row:   rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:    online,
			trail: []Action{landed("2a04:2a01:9::1", 3*time.Hour)},
			want:  InterruptPage,
		},
		{
			name:  "a containment that landed on a DIFFERENT endpoint proves nothing either",
			row:   rowAt(LaneActNow, "T1486", 19*time.Minute),
			ep:    online,
			trail: []Action{landed("2a04:2a01:9::2", 16*time.Minute)},
			want:  InterruptPage,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Judge(c.row, c.ep, c.trail, testNow, DefaultStaleAck)
			if got.Token != c.want {
				t.Fatalf("interrupt = %q (%s), want %q", got.Token, got.Reason, c.want)
			}
			if got.Reason == "" {
				t.Fatal("every interrupt decision must carry the reason it came out that way")
			}
		})
	}
}

// P4, and the direction that matters. "We did not see it" and "we looked and it is clean"
// are different epistemic states. An endpoint that was not in the read must produce the
// IDENTICAL verdict to one the plane positively reports online: absence never lowers.
func TestJudge_AbsenceNeverLowers(t *testing.T) {
	row := rowAt(LaneActNow, "T1486", 19*time.Minute)
	online := Endpoint{Address: "2a04:2a01:9::1", Connectivity: "online", Sensor: "shipping", known: true}

	unread := Judge(row, Endpoint{}, nil, testNow, DefaultStaleAck)
	seen := Judge(row, online, nil, testNow, DefaultStaleAck)
	if unread.Token != seen.Token {
		t.Fatalf("an unread endpoint judged %q and a live one judged %q; absence must not change the verdict",
			unread.Token, seen.Token)
	}

	// And an endpoint the plane says nothing useful about is not an offline one either.
	blank := Endpoint{Address: "2a04:2a01:9::1", known: true}
	if got := Judge(row, blank, nil, testNow, DefaultStaleAck); got.Token != InterruptPage {
		t.Fatalf("an endpoint with no connectivity cell judged %q; unknown is not offline", got.Token)
	}
}

// A control action that did NOT take can never be read as containment. This is the one
// class where our own product is the failure, and reading a refusal as a receipt would
// convert the loudest signal on the plane into silence.
func TestDisposition_OnlyALandedActionIsSevered(t *testing.T) {
	row := rowAt(LaneActNow, "T1486", 19*time.Minute)
	if got := Disposition(row, []Action{landed("2a04:2a01:9::1", 10*time.Minute)}, testNow); got != "severed" {
		t.Fatalf("a landed action = %q, want severed", got)
	}
	for _, bad := range []string{"refused:disarmed", "refused:not_armed", "error", "failed:error", ""} {
		a := Action{TsMs: ms(testNow.Add(-10 * time.Minute)), Address: "2a04:2a01:9::1", Result: bad}
		if got := Disposition(row, []Action{a}, testNow); got == "severed" {
			t.Fatalf("result %q rendered as severed; only ok is containment", bad)
		}
	}
	row.Evidence = `{"whatHappened":"held","confidence":1.0}`
	if got := Disposition(row, nil, testNow); got != "held" {
		t.Fatalf("an observe-only stamp = %q, want held", got)
	}
	row.Evidence = ""
	if got := Disposition(row, nil, testNow); got != "noticed" {
		t.Fatalf("no action and no stamp = %q, want noticed", got)
	}
}

// Three hits of one technique across three hosts inside one window is one wave, not three
// unrelated items. Nine rows would be nine decisions.
func TestFold_OneWaveIsOneDecision(t *testing.T) {
	var rows []Row
	for i, host := range []string{"finance-01", "finance-02", "finance-03"} {
		r := rowAt(LaneActNow, "T1486", time.Duration(19+i)*time.Minute)
		r.Agent = host
		rows = append(rows, r)
	}
	got := Fold(rows, FoldWindow)
	if len(got) != 1 || !got[0].Wave() || len(got[0].Rows) != 3 {
		t.Fatalf("three hits in one window folded into %d group(s); want one wave of three", len(got))
	}
}

func TestFold_ADayApartIsNotOneWave(t *testing.T) {
	a := rowAt(LaneActNow, "T1486", 10*time.Minute)
	b := rowAt(LaneActNow, "T1486", 26*time.Hour)
	b.Agent = "finance-02"
	got := Fold([]Row{a, b}, FoldWindow)
	if len(got) != 2 {
		t.Fatalf("two hits a day apart folded into %d group(s); want two", len(got))
	}
	for _, c := range got {
		if c.Wave() {
			t.Fatal("neither of those is a wave")
		}
	}
}

func TestFold_SplitsTheRosterByWhatWeDid(t *testing.T) {
	var rows []Row
	for i, host := range []string{"finance-01", "finance-02", "hr-app-01"} {
		r := rowAt(LaneActNow, "T1486", time.Duration(19+i)*time.Minute)
		r.Agent = host
		r.Address = "2a04:2a01:9::" + string(rune('1'+i))
		rows = append(rows, r)
	}
	b := &Book{Rows: rows, Trail: []Action{
		landed("2a04:2a01:9::1", 16*time.Minute),
		landed("2a04:2a01:9::2", 16*time.Minute),
		refused("2a04:2a01:9::3", 16*time.Minute),
	}}
	b.Index()
	c := Fold(rows, FoldWindow)[0]
	severed, unsevered := c.Severed(b, testNow)
	if len(severed) != 2 || len(unsevered) != 1 {
		t.Fatalf("roster split = %d severed / %d not; want 2 / 1", len(severed), len(unsevered))
	}
	if unsevered[0].Agent != "hr-app-01" {
		t.Fatalf("the endpoint that needs a human is %s; want hr-app-01", unsevered[0].Agent)
	}
}

func ptr[T any](v T) *T { return &v }

// The three reserved words in WHAT IS TRUE NOW are a claim about somebody's machine, so
// they are read out of the sensor's evidence rather than searched for in it. Reverting
// Disposition to the two independent substring searches fails on the first case here:
// evidence that says "contained" and happens to carry a signal named "held" rendered as
// held, which is the surface contradicting the sensor.
func TestDisposition_ReadsTheSensorsVerdictRatherThanGreppingForIt(t *testing.T) {
	cases := []struct {
		name     string
		evidence string
		want     string
	}{
		{"a signal named held is not the verdict",
			`{"technique":"T1486","whatHappened":"contained","signals":["mass_write","held"]}`, "noticed"},
		{"a path containing the word is not the verdict",
			`{"whatHappened":"blocked","paths":["/srv/\"held\""]}`, "noticed"},
		{"the verdict itself is",
			`{"technique":"T1486","whatHappened":"held","signals":["mass_write"]}`, "held"},
		{"no verdict is not a verdict",
			`{"technique":"T1486","signals":["held"]}`, "noticed"},
		{"unparseable evidence never invents one",
			`{"whatHappened":"held"`, "noticed"},
		{"no evidence at all", "", "noticed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Disposition(Row{Evidence: c.evidence}, nil, testNow)
			if got != c.want {
				t.Errorf("Disposition = %q, want %q for evidence %s", got, c.want, c.evidence)
			}
		})
	}

	// The control: a landed control action still outranks whatever the evidence says.
	r := Row{Address: "2a04:2a01:9::1", FirstSeen: ms(testNow.Add(-time.Hour)),
		Evidence: `{"whatHappened":"held"}`}
	if got := Disposition(r, []Action{landed("2a04:2a01:9::1", 10*time.Minute)}, testNow); got != "severed" {
		t.Errorf("a landed containment must still read severed, got %q", got)
	}
}
