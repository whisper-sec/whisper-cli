// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// rendezvous_test.go is the timing half of a relayed pair's punch: placing the plane's window on this
// process's clock, the train that sends only inside it, and the backoff both ends have to agree on.

// ==========================================================================================
// ParseRendezvous: the plane's UTC window, on our monotonic clock.
// ==========================================================================================

const serverMs = int64(1_790_000_000_000) // an instant in 2026, as the box's clock reads it

func TestParseRendezvous_PlacesTheWindowByTheBoxsClockNotOurs(t *testing.T) {
	// This host's wall clock is wrong by ten minutes. The window still lands where the box meant it,
	// because only the DIFFERENCE between the box's clock and its window is used.
	sent := time.Now()
	received := sent.Add(200 * time.Millisecond)
	r, err := ParseRendezvous(serverMs+20_000, serverMs+26_000, slotOf(serverMs+20_000), serverMs, 60_000, 0, sent, received)
	if err != nil {
		t.Fatalf("a well-formed window was refused: %v", err)
	}
	mid := sent.Add(100 * time.Millisecond)
	if got := r.At.Sub(mid); got != 20*time.Second {
		t.Fatalf("the window opens %v after the read's midpoint, want 20s", got)
	}
	if got := r.Until.Sub(r.At); got != 6*time.Second {
		t.Fatalf("window length = %v, want 6s", got)
	}
	if r.Period != time.Minute || r.Slot != slotOf(serverMs+20_000) {
		t.Fatalf("period/slot = %v/%d", r.Period, r.Slot)
	}
	if r.IsZero() {
		t.Fatal("a parsed window reports itself as none")
	}
}

func TestParseRendezvous_ReadsAWindowAlreadyInProgress(t *testing.T) {
	// The box hands out the window in progress when the read lands inside one: join it, do not wait.
	now := time.Now()
	r, err := ParseRendezvous(serverMs-2_000, serverMs+4_000, slotOf(serverMs-2_000), serverMs, 60_000, 0, now, now)
	if err != nil {
		t.Fatalf("a window in progress was refused: %v", err)
	}
	if r.current(now) != slotOf(serverMs-2_000) {
		t.Fatalf("current slot = %d, want the one in progress", r.current(now))
	}
}

func TestParseRendezvous_WithNoServerClockUsesOurWallClock(t *testing.T) {
	now := time.Now()
	at := now.UnixMilli() + 30_000
	at -= (at % 60_000) - 1_000 // one second into its period, so the window cannot straddle the next
	if at < now.UnixMilli()+1_000 {
		at += 60_000
	}
	r, err := ParseRendezvous(at, at+6_000, slotOf(at), 0, 0, 0, now, now)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if d := r.At.Sub(now); d != time.Duration(at-now.UnixMilli())*time.Millisecond {
		t.Fatalf("window opens in %v, want %dms by the local wall clock", d, at-now.UnixMilli())
	}
	if r.Period != defaultRendezvousPeriod {
		t.Fatalf("an unstated period should be the plane's own, got %v", r.Period)
	}
}

func TestParseRendezvous_RefusesWhatItCannotStandBehind(t *testing.T) {
	now := time.Now()
	at := serverMs + 20_000
	ok := slotOf(at)
	cases := map[string][6]int64{ // at, until, slot, server, period, skew
		"no window":                  {0, 0, ok, serverMs, 60_000, 0},
		"ends before it opens":       {at, at - 1_000, ok, serverMs, 60_000, 0},
		"empty":                      {at, at, ok, serverMs, 60_000, 0},
		"longer than any window":     {at, at + 10_001, ok, serverMs, 60_000, 0},
		"a period under the plane's": {at, at + 6_000, ok, serverMs, 30_000, 0},
		"a period of a millisecond":  {at, at + 1, ok, serverMs, 1, 0},
		"a period of a day":          {at, at + 6_000, ok, serverMs, 86_400_000, 0},
		"a negative period":          {at, at + 6_000, ok, serverMs, -60_000, 0},
		"a negative slot":            {at, at + 6_000, -1, serverMs, 60_000, 0},
		"a slot near overflow":       {at, at + 6_000, math.MaxInt64, serverMs, 60_000, 0},
		"a slot one period off":      {at, at + 6_000, ok + 1, serverMs, 60_000, 0},
		"a slot sixty periods off":   {at, at + 6_000, ok - 60, serverMs, 60_000, 0},
		"straddles a period":         {at + 58_000 - (at % 60_000), at + 64_000 - (at % 60_000), ok, serverMs, 60_000, 0},
		"an hour ahead":              {at + 3_600_000, at + 3_606_000, slotOf(at + 3_600_000), serverMs, 60_000, 0},
		"an hour ago":                {at - 3_600_000, at - 3_594_000, slotOf(at - 3_600_000), serverMs, 60_000, 0},
		"at the end of time":         {math.MaxInt64 - 6_000, math.MaxInt64, ok, serverMs, 60_000, 0},
	}
	for why, c := range cases {
		if r, err := ParseRendezvous(c[0], c[1], c[2], c[3], c[4], c[5], now, now); err == nil {
			t.Fatalf("%s: accepted %+v", why, r)
		}
	}
}

func TestParseRendezvous_ARoundTripTooSlowToPlaceTheWindowIsNotUsed(t *testing.T) {
	// Half the round trip is the uncertainty in where the box's clock sits on ours. Past the plane's
	// skew tolerance the window could be placed outside the far side's, so the read is not used for it.
	sent := time.Now()
	at := serverMs + 20_000
	if _, err := ParseRendezvous(at, at+6_000, slotOf(at), serverMs, 60_000, 1_500, sent, sent.Add(3001*time.Millisecond)); err == nil {
		t.Fatal("a 3s round trip placed a window with 1.5s of tolerance")
	}
	if _, err := ParseRendezvous(at, at+6_000, slotOf(at), serverMs, 60_000, 1_500, sent, sent.Add(2900*time.Millisecond)); err != nil {
		t.Fatalf("a 2.9s round trip is inside the tolerance: %v", err)
	}
	// The header may tighten the tolerance and never loosen it.
	for _, loose := range []int64{2_000, 10_000, 999_999_999} {
		if _, err := ParseRendezvous(at, at+6_000, slotOf(at), serverMs, 60_000, loose, sent, sent.Add(3500*time.Millisecond)); err == nil {
			t.Fatalf("a stated skew tolerance of %dms widened what a slow read may place", loose)
		}
	}
	if _, err := ParseRendezvous(at, at+6_000, slotOf(at), serverMs, 60_000, 500, sent, sent.Add(1200*time.Millisecond)); err == nil {
		t.Fatal("a tighter stated tolerance was not honoured")
	}
}

// slotOf is the plane's numbering of the period a window opens in.
func slotOf(atMs int64) int64 { return atMs / 60_000 }

func TestParseRendezvous_AReadThatEndedBeforeItStartedIsNotNegativeTime(t *testing.T) {
	now := time.Now()
	r, err := ParseRendezvous(serverMs+5_000, serverMs+11_000, slotOf(serverMs+5_000), serverMs, 60_000, 0, now, now.Add(-time.Second))
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if d := r.At.Sub(now); d != 5*time.Second {
		t.Fatalf("window opens in %v, want 5s", d)
	}
}

// ==========================================================================================
// The window maths.
// ==========================================================================================

func TestRendezvous_CurrentAndBoundsAgreeOnEverySideOfAWindow(t *testing.T) {
	base := time.Now()
	r := Rendezvous{At: base, Until: base.Add(time.Second), Period: 10 * time.Second, Slot: 100}
	cases := []struct {
		at   time.Duration
		slot int64
	}{
		{-11 * time.Second, 99},        // before the previous window opened
		{-10 * time.Second, 99},        // the previous window opening
		{-9500 * time.Millisecond, 99}, // inside the previous window
		{-9 * time.Second, 100},        // the previous window just closed: the next is At's
		{-1, 100},                      // a nanosecond before At
		{0, 100},                       // At itself
		{999 * time.Millisecond, 100},  // inside
		{time.Second, 101},             // the window closed: next
		{25 * time.Second, 103},        // after a couple of periods
		{20*time.Second + 500*time.Millisecond, 102},
	}
	for _, c := range cases {
		now := base.Add(c.at)
		got := r.current(now)
		if got != c.slot {
			t.Fatalf("at %v: slot %d, want %d", c.at, got, c.slot)
		}
		start, end := r.bounds(got)
		if !now.Before(end) {
			t.Fatalf("at %v: the current window already closed at %v", c.at, end.Sub(base))
		}
		if _, prevEnd := r.bounds(got - 1); now.Before(start) && now.Before(prevEnd) {
			t.Fatalf("at %v: skipped the window in progress for slot %d at %v", c.at, got, start.Sub(base))
		}
	}
}

func TestAttends_TheSlowerSideAttendsASubsetOfTheFastersWindows(t *testing.T) {
	// The property the backoff exists for: two ends that have missed a different number of windows
	// still share windows, so they still meet. Checked over every pair of backoff levels.
	for a := 0; a <= maxWindowBackoff+2; a++ {
		for b := 0; b <= maxWindowBackoff+2; b++ {
			shared := 0
			for slot := int64(29_833_000); slot < 29_833_000+64; slot++ {
				if attends(slot, a) && attends(slot, b) {
					shared++
				}
			}
			if shared == 0 {
				t.Fatalf("backoffs %d and %d never attend the same window, so the pair could never meet", a, b)
			}
		}
	}
	// Bounded: past the cap, one window in sixteen.
	n := 0
	for slot := int64(0); slot < 160; slot++ {
		if attends(slot, 99) {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("a fully backed-off train attends %d windows in 160, want 10", n)
	}
	if !attends(-16, 4) || attends(-15, 4) {
		t.Fatal("a negative slot breaks the modulus")
	}
}

// ==========================================================================================
// The timed train: nothing outside a window it attends.
// ==========================================================================================

// timedTrain is a train for a peer at ::7 with a one-second window opening 10 s after base, every 40 s.
// opener says whether this end has the lower address, and so sends first in each window.
func timedTrain(base time.Time, opener bool) *punchTrain {
	p := Peer{
		Address:    netip.MustParseAddr("2a04:2a01:4::7"),
		Candidates: []Candidate{{Endpoint: "198.51.100.4:51820", Source: SourceObserved}},
		Rendezvous: Rendezvous{At: base.Add(10 * time.Second), Until: base.Add(11 * time.Second), Period: 40 * time.Second, Slot: 200},
	}
	self := netip.MustParseAddr("2a04:2a01:4::9")
	if opener {
		self = netip.MustParseAddr("2a04:2a01:4::1")
	}
	return newPunchTrainFor(p, self, base, punchCarry{}, directRearmAfter)
}

type step struct {
	act punchAction
	at  time.Duration // when a send is due, from base
}

// stepUntil ticks a train every 100 ms over [from, to) with a one-second lookahead, and returns what it
// asked for at each tick that asked for something.
func stepUntil(tr *punchTrain, base time.Time, from, to, period time.Duration, rx uint64) map[time.Duration]step {
	out := map[time.Duration]step{}
	for at := from; at < to; at += 100 * time.Millisecond {
		if act, _, when := tr.windowStep(base.Add(at), period, time.Second, rx); act != punchNothing {
			st := step{act: act}
			if act == punchSend {
				st.at = when.Sub(base)
			}
			out[at] = st
		}
	}
	return out
}

func TestTimedTrain_TheOpenerSendsAtTheWindowsStartAndTheOtherEndHalfAWindowLater(t *testing.T) {
	for _, opener := range []bool{true, false} {
		base := time.Now()
		tr := timedTrain(base, opener)
		if !tr.timed() || tr.trains != 0 || tr.opener != opener {
			t.Fatalf("opener=%v: wrong train: %+v", opener, tr)
		}
		want := 10 * time.Second
		if !opener {
			want = 10*time.Second + 500*time.Millisecond
		}
		got := stepUntil(tr, base, 0, 20*time.Second, time.Second, 0)
		var sends []step
		for _, st := range got {
			if st.act == punchSend {
				sends = append(sends, st)
			}
		}
		// Exactly one aimed handshake in the window, due at the end's own point in it, and scheduled no
		// more than the lookahead ahead of it.
		if len(sends) != 1 || sends[0].at != want {
			t.Fatalf("opener=%v: sends %v, want one due at %v", opener, got, want)
		}
		for tick, st := range got {
			if st.act == punchSend && (tick > want || want-tick > time.Second) {
				t.Fatalf("opener=%v: scheduled at %v for %v, outside the lookahead", opener, tick, want)
			}
		}
		if tr.trains != 1 || tr.slot != 200 {
			t.Fatalf("opener=%v: the attended window was not counted: trains %d slot %d", opener, tr.trains, tr.slot)
		}
	}
}

func TestTimedTrain_NothingBeforeTheWindowComesIntoView(t *testing.T) {
	base := time.Now()
	tr := timedTrain(base, true)
	if got := stepUntil(tr, base, 0, 9*time.Second-time.Millisecond, time.Second, 0); len(got) != 0 {
		t.Fatalf("the train acted before the window came within its lookahead: %v", got)
	}
	if in := tr.info(false); in.Phase != PunchTrying {
		t.Fatalf("waiting for the first window reads %q, want %q", in.Phase, PunchTrying)
	}
}

func TestTimedTrain_AJoinMidWindowSendsAtOnce(t *testing.T) {
	// A node that reads its peer map in the middle of a window joins it, whichever end it is.
	for _, opener := range []bool{true, false} {
		base := time.Now()
		tr := timedTrain(base, opener)
		act, _, at := tr.windowStep(base.Add(10*time.Second+800*time.Millisecond), time.Second, time.Second, 0)
		if act != punchSend || !at.Equal(base.Add(10*time.Second+800*time.Millisecond)) {
			t.Fatalf("opener=%v: a mid-window join gave %v at %v", opener, act, at.Sub(base))
		}
	}
}

func TestTimedTrain_SilencesAfterTheRetryCoverAndBacksOff(t *testing.T) {
	base := time.Now()
	tr := timedTrain(base, true)
	period := 300 * time.Millisecond
	got := stepUntil(tr, base, 9*time.Second, 17*time.Second, period, 0)
	// The window closes at 11 s and a period later is 11.3 s, but the device's first retry is due about
	// five seconds after the handshake (sent at 10 s): the silence waits for retransmitCover after it.
	var quietAt time.Duration
	for tick, st := range got {
		if st.act == punchQuiet {
			if quietAt != 0 {
				t.Fatalf("silenced twice: %v", got)
			}
			quietAt = tick
		}
	}
	if quietAt < 10*time.Second+retransmitCover || quietAt > 10*time.Second+retransmitCover+100*time.Millisecond {
		t.Fatalf("silenced at %v, want just after %v: %v", quietAt, 10*time.Second+retransmitCover, got)
	}
	if in := tr.info(false); in.Phase != PunchGaveUp || tr.missed != 1 {
		t.Fatalf("after a missed window: phase %q missed %d", in.Phase, tr.missed)
	}
	// Slot 201 (odd, at 50 s) is skipped by a train that missed once; slot 202 at 90 s is attended.
	got = stepUntil(tr, base, 17*time.Second, 91*time.Second, period, 0)
	if len(got) != 1 {
		t.Fatalf("after one miss, want exactly the send for slot 202: %v", got)
	}
	for _, st := range got {
		if st.act != punchSend || st.at != 90*time.Second {
			t.Fatalf("after one miss, want the send due at slot 202's opening (90s): %v", got)
		}
	}
}

func TestTimedTrain_AnAnswerInFlightPutsTheSilenceOffOnceOnly(t *testing.T) {
	base := time.Now()
	tr := timedTrain(base, true)
	period := time.Second
	tr.windowStep(base.Add(10*time.Second), period, time.Second, 500)
	// Something arrived from the peer (rx 500 -> 648, its initiation): the silence waits one more period.
	if act, _, _ := tr.windowStep(base.Add(16*time.Second), period, time.Second, 648); act != punchNothing {
		t.Fatalf("silenced while our answer to the far side was unconfirmed: %v", act)
	}
	if act, _, _ := tr.windowStep(base.Add(16900*time.Millisecond), period, time.Second, 800); act != punchNothing {
		t.Fatal("silenced inside the extension")
	}
	// Once only: more traffic cannot keep this side going.
	if act, _, _ := tr.windowStep(base.Add(17*time.Second), period, time.Second, 900); act != punchQuiet {
		t.Fatalf("a second extension: %v", act)
	}
	// And the tunnel's own last-moment deferral is refused once the window has been extended.
	if tr.deferQuiet(base.Add(17*time.Second), period) {
		t.Fatal("a deferral after the extension was granted")
	}
}

func TestTimedTrain_ARestartAttendsTheNextWindowFromTheFirstRung(t *testing.T) {
	base := time.Now()
	tr := timedTrain(base, true)
	tr.missed = maxWindowBackoff
	tr.attended, tr.slot = true, 200
	tr.restart(base.Add(49*time.Second+500*time.Millisecond), Candidate{})
	if tr.missed != 0 || tr.attending {
		t.Fatalf("a restart kept the backoff: %+v", tr)
	}
	// Slot 201 opens at base+50s: a restarted train schedules it although a backed-off one would not.
	if act, _, at := tr.windowStep(base.Add(49*time.Second+500*time.Millisecond), time.Second, time.Second, 0); act != punchSend || !at.Equal(base.Add(50*time.Second)) {
		t.Fatalf("a restarted train did not attend the next window: %v at %v", act, at.Sub(base))
	}
}

func TestTimedTrain_NoRefreshCanStretchOrMoveAWindowInProgress(t *testing.T) {
	// A read can number the same instants differently (a box a whole number of periods off) or change
	// the period. While a window is attended, none of it may move when the silence comes; afterwards the
	// new window is taken. Delta 2^40 also checks nothing overflows.
	for name, mutate := range map[string]func(r Rendezvous) Rendezvous{
		"relabelled -60":   func(r Rendezvous) Rendezvous { r.Slot -= 60; return r },
		"relabelled +60":   func(r Rendezvous) Rendezvous { r.Slot += 60; return r },
		"relabelled 2^40":  func(r Rendezvous) Rendezvous { r.Slot += 1 << 40; return r },
		"a new period":     func(r Rendezvous) Rendezvous { r.Period = time.Hour; return r },
		"moved a whole hr": func(r Rendezvous) Rendezvous { r.At = r.At.Add(time.Hour); r.Until = r.Until.Add(time.Hour); return r },
	} {
		base := time.Now()
		tr := timedTrain(base, true)
		tr.windowStep(base.Add(10*time.Second), time.Second, time.Second, 0)
		tr.adoptWindow(mutate(tr.window))
		got := stepUntil(tr, base, 10*time.Second+100*time.Millisecond, 17*time.Second, time.Second, 0)
		quiet := 0
		for tick, st := range got {
			if st.act != punchQuiet || tick > 10*time.Second+retransmitCover+100*time.Millisecond {
				t.Fatalf("%s: a refresh moved the window in progress: %v", name, got)
			}
			quiet++
		}
		if quiet != 1 {
			t.Fatalf("%s: want exactly one silence at the original time, got %v", name, got)
		}
		if tr.window != mutate(timedTrain(base, true).window) {
			t.Fatalf("%s: the refreshed window was not taken once the attended one was over", name)
		}
	}
}

func TestTimedTrain_ARefreshMidWindowKeepsTheSlot(t *testing.T) {
	base := time.Now()
	tr := timedTrain(base, true)
	tr.windowStep(base.Add(10*time.Second), time.Second, time.Second, 0)
	moved := tr.window
	moved.At = moved.At.Add(40 * time.Millisecond) // a second read, placed a little differently
	moved.Until = moved.Until.Add(40 * time.Millisecond)
	tr.adoptWindow(moved)
	if !tr.attending || tr.slot != 200 {
		t.Fatalf("a refresh inside a window ended it: %+v", tr)
	}
	// And an untimed train never becomes timed by adoption.
	untimed := newPunchTrain([]Candidate{{Endpoint: "a:1"}}, base)
	untimed.adoptWindow(moved)
	if untimed.timed() {
		t.Fatal("adoption turned an untimed train into a timed one")
	}
}

// ==========================================================================================
// The documents.
// ==========================================================================================

func TestQuietDoc_SilencesWithoutRoutingAnything(t *testing.T) {
	p := Peer{PublicKeyHex: strings.Repeat("33", 32)}
	doc := quietDoc(p, "198.51.100.4:51820")
	want := "public_key=" + p.PublicKeyHex + "\nremove=true\npublic_key=" + p.PublicKeyHex + "\n" +
		"endpoint=198.51.100.4:51820\nreplace_allowed_ips=true\npersistent_keepalive_interval=0\n"
	if doc != want {
		t.Fatalf("quiet document:\n%s\nwant:\n%s", doc, want)
	}
	if strings.Contains(doc, "allowed_ip=") {
		t.Fatal("a quiet routed a /128")
	}
	if strings.Contains(doc, "private_key") {
		t.Fatal("a quiet document carried key material")
	}
}

func TestUnkeepDoc_TurnsOffTheKeepaliveAndNothingElse(t *testing.T) {
	p := Peer{PublicKeyHex: strings.Repeat("33", 32)}
	if got, want := unkeepDoc(p), "public_key="+p.PublicKeyHex+"\nupdate_only=true\npersistent_keepalive_interval=0\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUapiConfig_ATimedPeerWaitsForItsWindowSilent(t *testing.T) {
	timed, err := ParsePeer(testPeerKeyB64, "198.51.100.4:51820", "2a04:2a01:4::7", "db-01", "direct-punch")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	timed.Rendezvous = Rendezvous{At: now, Until: now.Add(time.Second), Period: time.Minute, Slot: 1}
	listed, ok := ListedPeer("2a04:2a01:4::8", "")
	if !ok {
		t.Fatal("ListedPeer refused an agent address")
	}
	doc := uapiConfig(Config{
		PrivateKeyHex: strings.Repeat("11", 32), ServerPublicKeyHex: strings.Repeat("22", 32),
		Endpoint: "[::1]:51826", Address: mustAddr(t, "2a04:2a01:4::9"), Peers: []Peer{timed, listed},
	})
	section := doc[strings.Index(doc, "public_key="+timed.PublicKeyHex):]
	if !strings.Contains(section, "persistent_keepalive_interval=0\n") {
		t.Fatalf("a timed peer was armed with a keepalive, so it would initiate before its window:\n%s", section)
	}
	if strings.Count(doc, "public_key=") != 2 {
		t.Fatalf("a listed marker reached the device:\n%s", doc)
	}
}

func TestListedPeer_MarksOnlyAnAgentAddress(t *testing.T) {
	for _, bad := range []string{"", "2001:db8::1", "10.0.0.1", "2a04:2a01::/32", "not an address"} {
		if _, ok := ListedPeer(bad, testPeerKeyB64); ok {
			t.Fatalf("marked %q", bad)
		}
	}
	p, ok := ListedPeer("[2a04:2a01:4::7]", testPeerKeyB64)
	if !ok || !p.Listed || p.Address.String() != "2a04:2a01:4::7" || len(p.PublicKeyHex) != 64 {
		t.Fatalf("got %+v %v", p, ok)
	}
	if p, _ := ListedPeer("2a04:2a01:4::7", "not-a-key"); p.PublicKeyHex != "" {
		t.Fatal("a marker carried a key that is not one")
	}
}

// TestKeepsHeld_EveryWayAHeldPeerGoes is the hold rule on its own, for a promoted peer and a timed one:
// kept on a row with no evidence, and removed on a refusal, on another key, on another peer at the
// address, after maxHeldReads reads, and after maxHeldAge.
func TestKeepsHeld_EveryWayAHeldPeerGoes(t *testing.T) {
	addr := netip.MustParseAddr("2a04:2a01:4::7")
	key := strings.Repeat("6b", 32)
	now := time.Now()
	timed := newPunchTrainFor(Peer{Address: addr, Candidates: []Candidate{{Endpoint: "198.51.100.4:51820"}},
		Rendezvous: Rendezvous{At: now, Until: now.Add(time.Second), Period: time.Minute, Slot: 1}}, netip.Addr{}, now,
		punchCarry{}, directRearmAfter)
	untimed := newPunchTrain([]Candidate{{Endpoint: "198.51.100.4:51820"}}, now)
	for _, c := range []struct {
		name     string
		promoted bool
		train    *punchTrain
	}{{"promoted", true, untimed}, {"timed", false, timed}} {
		peer := func() *directPeer {
			return &directPeer{peer: Peer{Address: addr}, promoted: c.promoted, punch: c.train}
		}
		heldNone := map[netip.Addr]heldRow{addr: {}}
		if keepsHeld(peer(), heldNone, nil, key, now) != heldBounded {
			t.Fatalf("%s: not kept on a row with no evidence", c.name)
		}
		if keepsHeld(peer(), map[netip.Addr]heldRow{addr: {named: key}}, nil, key, now) != heldBounded {
			t.Fatalf("%s: not kept on a row naming its own key", c.name)
		}
		if keepsHeld(peer(), map[netip.Addr]heldRow{}, nil, key, now) != heldNot {
			t.Fatalf("%s: kept on a refusal (a listed row without the hold)", c.name)
		}
		if keepsHeld(peer(), map[netip.Addr]heldRow{addr: {named: strings.Repeat("6c", 32)}}, nil, key, now) != heldNot {
			t.Fatalf("%s: kept when the read names another key for its address", c.name)
		}
		if keepsHeld(peer(), heldNone, map[netip.Addr]bool{addr: true}, key, now) != heldNot {
			t.Fatalf("%s: kept when the read installs another peer at its address", c.name)
		}
		d := peer()
		d.held = maxHeldReads
		if keepsHeld(d, heldNone, nil, key, now) != heldNot {
			t.Fatalf("%s: kept past maxHeldReads", c.name)
		}
		d = peer()
		d.held, d.heldSince = 1, now.Add(-maxHeldAge)
		if keepsHeld(d, heldNone, nil, key, now) != heldNot {
			t.Fatalf("%s: kept past maxHeldAge", c.name)
		}
	}
	// An untimed peer that is not promoted is never held: it has neither a proven path nor a schedule.
	if keepsHeld(&directPeer{peer: Peer{Address: addr}, punch: untimed}, map[netip.Addr]heldRow{addr: {}}, nil, key, now) != heldNot {
		t.Fatal("an unpromoted untimed peer was held")
	}
}
