// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// direct_firstarm_test.go is two ends of a pair that arm their untimed trains within a round trip of
// each other, on real devices, on the shared relaying box of direct_oneway_test.go.

// crossed reports whether both ends answered the other's handshake initiation since the arm: a handshake
// response from each to the other. Only a crossing makes both ends responders; a first initiation that is
// answered makes exactly one.
func crossed(t *testing.T, p *sharedPair, since time.Time) bool {
	t.Helper()
	responded := func(n, far *natNode) bool {
		n.nat.mu.Lock()
		defer n.nat.mu.Unlock()
		for _, k := range n.nat.kinds[far.endpoint(t)] {
			if k.typ == 2 && k.at.After(since) {
				return true
			}
		}
		return false
	}
	return responded(p.a, p.b) && responded(p.b, p.a)
}

// TestFirstArm_TwoUntimedTrainsArmedTogetherMeet: both ends of a direct pair are handed each other's row in
// the same instant, as two agents spawned together are. Every packet takes 300 ms to arrive, so the two first
// handshake initiations cross: each end answers the other's, and neither answer matches the initiation its
// receiver is now waiting on. At the production keepalive (five seconds, WireGuard's RekeyTimeout) the
// retries that follow are re-armed by the same crossing and stay in step, so the pair never meets. The end
// that does not open the pair's windows (the higher address) punches with a keepalive one second longer, so
// after the crossing the opener's retry usually arrives first and is answered: the pair meets within an
// interval or a few, and no first attempt waits.
//
// The crossing is checked, not assumed: two arms can land more than the delay apart (each publishes its
// record before it arms), and such a pair meets on its first exchange with or without the fix. So can a
// pair whose ends both answered: the device consumes handshake messages on several workers, so one end can
// take the other's answer before the crossing initiation, complete, and answer the late one too. A try
// whose crossing did not hold (no answer from both ends, or a meet sooner than any retry can come) is built
// again, and ten that never hold fail, because they prove nothing. Once with the fast test tick, and once at
// production's tick ratio, where a train's punches land on five-second ticks.
//
// Without the longer keepalive a held crossing can still drift apart by scheduling chance (one run in eight
// met, at 13.7 s, when this was measured), so this test shows that the fix works but is not the only guard on
// it: TestPunchTrain_TheKeepaliveAnUntimedTrainPunchesWith pins the keepalive itself.
func TestFirstArm_TwoUntimedTrainsArmedTogetherMeet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device first-arm test in -short")
	}
	for _, tc := range []struct {
		name string
		tick time.Duration
	}{
		{"the fast tick", 0},
		{"production's tick ratio", 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			production := func(dir string) Options {
				o := onewayOpts(dir)
				o.DirectKeepalive, o.DirectDeadAfter, o.PunchEvery = 0, 0, 0 // 5 s, 20 s, 5 s
				if tc.tick > 0 {
					o.HealthInterval = tc.tick
				}
				return o
			}
			tick := production("").HealthInterval
			for try := 1; ; try++ {
				p := startSharedPairDelayed(t, production, 300*time.Millisecond)
				forA, forB := directRowTo(t, p.b), directRowTo(t, p.a)
				var wg sync.WaitGroup
				var errA, errB error
				armed := time.Now()
				wg.Add(2)
				go func() { defer wg.Done(); errA = p.a.tun.SetDirectPeers([]Peer{forA}) }()
				go func() { defer wg.Done(); errB = p.b.tun.SetDirectPeers([]Peer{forB}) }()
				wg.Wait()
				if errA != nil || errB != nil {
					t.Fatalf("arm: a %v, b %v", errA, errB)
				}
				time.Sleep(1500 * time.Millisecond) // the two first initiations and their answers, at 300 ms a crossing
				// About one try in five does not cross on an idle box, more on a loaded one; a try that does not
				// costs a few seconds, so ten keep a spurious failure rare without hiding one.
				again := func(why string) bool {
					p.a.tun.Stop()
					p.b.tun.Stop()
					if try == 10 {
						t.Fatal("the two arms never crossed and held in ten tries, so this proves nothing about a crossing")
					}
					t.Logf("try %d: %s; building the pair again", try, why)
					return true
				}
				if !crossed(t, p, armed) && again("the arms did not cross (they landed more than a delay apart)") {
					continue
				}
				// A crossing usually costs one keepalive interval, and the other end's jittered retransmit, or at
				// production's tick a punch, can cross the opener's retry again before the order comes back: the
				// bound allows several re-crossings (each about an interval), the three 300 ms crossings of the
				// final exchange, and a tick for promotion. Without the second's difference the pair never meets.
				if !waitFor(8*device.RekeyTimeout+2*tick, func() bool { return p.directEverywhere(t) }) {
					t.Fatalf("%v after both ends armed together and crossed, the pair has not met: %s",
						time.Since(armed).Round(time.Millisecond), p.devices(t))
				}
				took := time.Since(armed)
				if took < device.RekeyTimeout-500*time.Millisecond &&
					again(fmt.Sprintf("both ends answered, but the pair met %v after the arm, sooner than any retry can come, so the crossing did not hold", took.Round(time.Millisecond))) {
					continue
				}
				t.Logf("try %d: crossed, then direct %v after both ends armed together", try, took.Round(time.Millisecond))
				// Promotion writes the tunnel's keepalive back: the extra second is for punching only.
				if _, ka, _ := peerSection(t, p.b.tun, p.a.pubHex); ka != strconv.Itoa(directKeepalive) {
					t.Fatalf("the promoted peer at the end that does not open the pair keeps keepalive %q, want %d", ka, directKeepalive)
				}
				// The device routes and both records say direct (directEverywhere); the data the direct peers then
				// carry is the one-way tests' to prove, at a delay that does not make every packet wait 300 ms.
				return
			}
		})
	}
}
