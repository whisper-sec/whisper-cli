// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// punch_phase_test.go pins what the punch phase may say. gave-up is a finding, "a full train, or
// an attended window, produced no handshake", and `whale ping` turns it into "relayed because the punch
// failed: N attempts". A train that has made no attempt has found nothing, so it may never read gave-up.

// shortLivedRow is a direct row with the pair's window whose path came up from its first untimed train and
// died within a rekey of coming up, with that train inside directRearmAfter: the row reconcile sends back
// to its window rather than buying another untimed train (restartFor with fresh=false). Its quiet hold
// runs for hold from withdrawn, and the pair's next window opens at window after withdrawn.
func shortLivedRow(t *testing.T, withdrawn time.Time, hold, window time.Duration, opener bool) *punchTrain {
	t.Helper()
	w := Rendezvous{At: withdrawn.Add(window), Until: withdrawn.Add(window + 6*time.Second), Period: time.Minute, Slot: 4242}
	self := netip.MustParseAddr("2a04:2a01:4::c")
	if opener {
		self = netip.MustParseAddr("2a04:2a01:4::a")
	}
	p := Peer{Address: netip.MustParseAddr("2a04:2a01:4::b"), Window: w,
		Candidates: []Candidate{{Endpoint: "198.51.100.7:51820", Source: SourceLocal}}}
	armed := withdrawn.Add(-50 * time.Second)
	tr := newPunchTrainFor(p, self, armed, punchCarry{}, directRearmAfter)
	if tr.timed() || !tr.canFallBack() {
		t.Fatal("a direct row with a window and no history must run its first train untimed")
	}
	// The untimed train lands on its second attempt and the path is promoted.
	for i := 0; i < 2; i++ {
		if _, due := tr.due(armed.Add(time.Duration(i)*punchPeriod), punchPeriod); !due {
			t.Fatalf("attempt %d of the first train was not due", i+1)
		}
	}
	tr.winner, tr.won = tr.cands[0], true
	// Forty seconds later the path stops answering: it lasted less than a rekey, and the untimed train is
	// inside directRearmAfter, so the row goes back to its window (Tunnel.reconcileDirectPeers).
	tr.restartFor(withdrawn, tr.winner, false)
	tr.holdFor(withdrawn.Add(hold))
	tr.withdrawnAt = withdrawn
	return tr
}

// TestRestartFor_AShortLivedDirectRowWaitsForItsWindowItDoesNotGiveUp is the transition a live check caught on
// v0.268.1: between the end of the quiet hold and the pair's first window the row read gave-up, with no
// attempt made, for twenty to thirty seconds, and `whale ping` printed "the punch failed: 0 attempts across
// 1 endpoint" of two nodes on one segment whose path had been withdrawn on purpose. It reads resting for the
// hold, punching from the hold's end until the window (a timed train waiting for its first window), and
// gave-up only once a window it attended has produced no handshake, with that attempt counted.
func TestRestartFor_AShortLivedDirectRowWaitsForItsWindowItDoesNotGiveUp(t *testing.T) {
	const hold = 40 * time.Second
	const window = 70 * time.Second // the pair's next window opens 30 s after the hold ends

	// During the hold: resting, since the withdrawal, and nothing is due.
	now := time.Now()
	held := shortLivedRow(t, now, hold, window, true)
	if in := held.info(false); in.Phase != PunchResting || in.Attempts != 0 || !in.Timed || !in.Since.Equal(now) {
		t.Fatalf("inside the hold the row reads %+v, want resting since the withdrawal, timed, no attempt", in)
	}

	// After the hold, before the window. The row was withdrawn 45 s ago, so its hold ended 5 s ago.
	withdrawn := time.Now().Add(-45 * time.Second)
	tr := shortLivedRow(t, withdrawn, hold, window, true)
	if !tr.timed() || tr.attempts != 0 || tr.spent() {
		t.Fatalf("back on its window the row is timed=%v attempts=%d spent=%v; it is waiting for a window, not spent",
			tr.timed(), tr.attempts, tr.spent())
	}
	in := tr.info(false)
	if in.Phase != PunchTrying || in.Attempts != 0 || !in.Timed {
		t.Fatalf("between the hold and the window the row reads %+v, want punching (waiting for its first window)", in)
	}
	// Every tick up to the window's send point asks for nothing and leaves the reading alone.
	for at := hold; at < window-time.Second; at += 100 * time.Millisecond {
		if act, _, _ := tr.windowStep(withdrawn.Add(at), punchPeriod, time.Second, 0); act != punchNothing {
			t.Fatalf("the row acted %v after the withdrawal, before its window", at)
		}
		if ph := tr.info(false).Phase; ph != PunchTrying {
			t.Fatalf("%v after the withdrawal the row reads %q, want punching", at, ph)
		}
	}
	// The window: the opener sends at its start, one attempt, still punching.
	act, _, at := tr.windowStep(withdrawn.Add(window-500*time.Millisecond), punchPeriod, time.Second, 0)
	if act != punchSend || !at.Equal(withdrawn.Add(window)) {
		t.Fatalf("the first window after the hold was not attended at its start: %v at %v", act, at.Sub(withdrawn))
	}
	if in := tr.info(false); in.Phase != PunchTrying || in.Attempts != 1 {
		t.Fatalf("in the window the row reads %+v, want punching with one attempt", in)
	}
	// No handshake: once the window and a period are over the device is silenced, and the miss is a finding.
	act, _, _ = tr.windowStep(withdrawn.Add(window+6*time.Second+punchPeriod), punchPeriod, time.Second, 0)
	if act != punchQuiet {
		t.Fatalf("the attended window did not end with the quiet: %v", act)
	}
	if in := tr.info(false); in.Phase != PunchGaveUp || in.Attempts != 1 {
		t.Fatalf("after a window with no handshake the row reads %+v, want gave-up with its one attempt", in)
	}

	// The other end of the pair sends half a window later, and reads the same in between.
	other := shortLivedRow(t, withdrawn, hold, window, false)
	if in := other.info(false); in.Phase != PunchTrying || in.Attempts != 0 {
		t.Fatalf("the non-opener reads %+v between the hold and the window, want punching", in)
	}

	// A path that lasted longer than a rekey takes the fresh branch, an untimed train from the endpoint that
	// carried it, which is punching too, and gave-up only once all its attempts are spent.
	fresh := shortLivedRow(t, withdrawn, hold, window, true)
	fresh.restartFor(withdrawn, fresh.winner, true)
	if fresh.timed() || fresh.info(false).Phase != PunchTrying {
		t.Fatalf("the fresh branch reads %+v, want an untimed train, punching", fresh.info(false))
	}
}

// TestPunchInfo_ATrainWithNoAttemptNeverReadsGaveUp is the guard on the reading itself: whatever a train's
// flags say, gave-up is reported only with at least one attempt behind it.
func TestPunchInfo_ATrainWithNoAttemptNeverReadsGaveUp(t *testing.T) {
	tr := newPunchTrain([]Candidate{{Endpoint: "198.51.100.7:51820", Source: SourceLocal}}, time.Now())
	tr.gaveUp = true
	if in := tr.info(false); in.Phase == PunchGaveUp {
		t.Fatalf("a spent flag with no attempt read %+v", in)
	}
	tr.attempts = 1
	if in := tr.info(false); in.Phase != PunchGaveUp {
		t.Fatalf("a spent train with an attempt behind it read %+v, want gave-up", in)
	}
}

// TestPunchTrain_NoReachableStateIsSpentWithoutAnAttempt drives trains of every row shape through the
// calls the monitor makes, in the order it makes them (Tunnel.reconcileDirectPeers, quietDirectPeer and a
// refresh's re-arm), with handshakes, deaths, re-arms and refreshed windows at random, and checks after
// every step that no train is spent without an attempt behind it, and that none reads gave-up without one.
func TestPunchTrain_NoReachableStateIsSpentWithoutAnAttempt(t *testing.T) {
	self := netip.MustParseAddr("2a04:2a01:4::a")
	far := netip.MustParseAddr("2a04:2a01:4::b")
	cands := []Candidate{{Endpoint: "198.51.100.7:51820", Source: SourceLocal},
		{Endpoint: "198.51.100.4:51820", Source: SourceObserved}}
	const (
		rearm = directRearmAfter
		dead  = directDeadAfter
		tick  = 5 * time.Second
	)
	for seed := uint64(1); seed <= 300; seed++ {
		r := rand.New(rand.NewPCG(seed, 2597))
		base := time.Now().Add(-time.Hour)
		w := Rendezvous{At: base.Add(13 * time.Second), Until: base.Add(19 * time.Second), Period: time.Minute, Slot: 100}
		p := Peer{Address: far, Candidates: cands}
		if seed%5 == 0 {
			p.Candidates = nil // a row with nothing to aim at yet; a refresh may bring an endpoint (adopt)
		}
		switch seed % 3 {
		case 0:
			p.Window = w // a direct row with the pair's window, what the plane sends today
		case 1:
			p.Rendezvous = w // a relayed pair, punched only in its windows
		}
		now := base
		var prelude, armedAt, promotedAt time.Time
		promoted := false
		tr := newPunchTrainFor(p, self, now, punchCarry{}, rearm)
		if !tr.preludeAt.IsZero() {
			prelude = tr.preludeAt
		}
		armedAt = now
		for i := 0; i < 400; i++ {
			now = now.Add(time.Duration(r.Int64N(int64(2 * tick))))
			switch k := r.IntN(20); {
			case k == 0 && !promoted:
				// A handshake landed: promoted, and the hold (if any) is over.
				promoted, promotedAt = true, now
				tr.holdUntil = time.Time{}
				if len(tr.cands) > 0 {
					tr.winner, tr.won = tr.cands[r.IntN(len(tr.cands))], true
				}
			case k <= 2 && promoted && now.Sub(promotedAt) >= dead:
				// The path stopped answering: the demotion, as reconcile makes it.
				promoted = false
				fresh := now.Sub(promotedAt) >= 2*time.Minute || prelude.IsZero() || now.Sub(prelude) >= rearm
				tr.restartFor(now, tr.winner, fresh)
				if fresh && tr.canFallBack() {
					prelude = now
				}
				tr.holdFor(now.Add(40 * time.Second))
				tr.withdrawnAt = now
				armedAt = now
			case k == 3:
				// A refresh re-armed the row: a new train for the key, carrying what the old one left.
				c := tr.carry()
				c.preludeAt, c.holdUntil, c.withdrawnAt = prelude, tr.holdUntil, tr.withdrawnAt
				if !prelude.IsZero() && now.Sub(prelude) >= rearm {
					c.preludeAt = time.Time{}
				}
				tr = newPunchTrainFor(p, self, now, c, rearm)
				if !tr.preludeAt.IsZero() && tr.preludeAt.Equal(now) {
					prelude = now
				}
				promoted, armedAt = false, now
			case k == 4:
				// A refresh carried the window placed a little differently, or the far end's mapping moved.
				moved := w
				moved.At = moved.At.Add(time.Duration(r.Int64N(int64(time.Second))))
				tr.adoptWindow(moved)
				tr.adoptFallback(moved)
				if r.IntN(2) == 0 {
					tr.freshEvidence()
				}
			case k == 5 && tr.timed():
				// quietDirectPeer's fresh read saw a packet that landed after the tick decided to silence.
				tr.deferQuiet(now, punchPeriod)
			case k == 6:
				// A refresh of the same peer carried a different candidate list: adopted, not re-armed.
				tr.adopt(cands[r.IntN(len(cands)):])
			case !promoted:
				// One monitor pass over an unpromoted peer, in reconcile's order.
				switch {
				case tr.timed():
					if act, _, _ := tr.windowStep(now, punchPeriod, tick+tick/10, uint64(r.IntN(3))); act == punchSend {
						armedAt = now
					}
				case tr.spent() && tr.canFallBack():
					tr.fallBack()
				default:
					if tr.spent() && now.Sub(armedAt) > rearm {
						tr.restart(now, tr.winner)
					}
					if _, due := tr.due(now, punchPeriod); due {
						armedAt = now
					}
				}
			}
			if tr.gaveUp && tr.attempts == 0 {
				t.Fatalf("seed %d step %d (row timed=%v window=%v): a train is spent with no attempt behind it: %+v",
					seed, i, tr.timed(), !tr.fallback.IsZero(), tr.info(promoted))
			}
			if in := tr.info(promoted); in.Phase == PunchGaveUp && in.Attempts == 0 {
				t.Fatalf("seed %d step %d: the train reads gave-up with no attempt: %+v", seed, i, in)
			}
		}
	}
}
