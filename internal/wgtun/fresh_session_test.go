// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A tunnel whose box no longer holds its peer has to ask for a fresh session.
//
// Re-pointing the endpoint and re-opening the socket are the right answers when the path is at
// fault. When the box has dropped this tunnel's peer (a re-key, a restart, a reaper), every
// handshake initiation lands on a box that does not know the key and answers nothing, so the
// monitor repeated both rungs for hours, thousands of attempts, while the session still looked
// up. Only a fresh connect puts the peer back. The tunnel cannot run one itself (it holds no
// client), so it raises a flag the session's holder acts on.
//
// The flag keys on the box's clock, not on a count of our attempts. The box reaps a peer whose
// last handshake is 180 s old and sweeps every 60 s, so once our last handshake is older than
// both together the peer is gone whatever we do locally. A count restarts after a host sleeps;
// the age of the last handshake does not.

var freshNow = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

// stalled is a tunnel whose last handshake with the box was age ago.
func stalled(age time.Duration) *Tunnel {
	return &Tunnel{lastH: freshNow.Add(-age), started: freshNow.Add(-age - time.Hour)}
}

func TestASilenceShorterThanTheReapWindowDoesNotAskForAFreshSession(t *testing.T) {
	tun := stalled(renewAfterSilence - 30*time.Second)
	_ = tun.escalateIfStuck(rebindAfterAttempts, rebindAfterAttempts) // one socket re-open
	for n := 1; n <= 20; n++ {
		tun.noteFruitless(n, freshNow)
	}
	if tun.NeedsFreshSession() {
		t.Fatalf("asked for a fresh session at a silence of %s; the box still holds the peer until %s",
			renewAfterSilence-30*time.Second, renewAfterSilence)
	}
}

func TestASilencePastTheReapWindowAsksOnceASocketReopenHasBeenTried(t *testing.T) {
	tun := stalled(renewAfterSilence + time.Second)
	tun.noteFruitless(1, freshNow)
	_ = tun.escalateIfStuck(rebindAfterAttempts, rebindAfterAttempts)
	tun.noteFruitless(2, freshNow) // the re-open came in this same attempt: not yet tried
	if tun.NeedsFreshSession() {
		t.Fatal("asked for a fresh session in the same attempt as the socket re-open, before it could help")
	}
	tun.noteFruitless(3, freshNow)
	if !tun.NeedsFreshSession() {
		t.Fatal("no fresh session after the reap window, with a socket re-open tried and failed")
	}
	// It is a latch: further attempts keep it raised until a handshake clears it.
	tun.noteFruitless(4, freshNow)
	if !tun.NeedsFreshSession() {
		t.Fatal("the request dropped on a later fruitless attempt, with no handshake in between")
	}
}

func TestNoSocketReopenMeansNoFreshSession(t *testing.T) {
	tun := stalled(time.Hour)
	for n := 1; n <= 20; n++ {
		tun.noteFruitless(n, freshNow)
	}
	if tun.NeedsFreshSession() {
		t.Fatal("asked for a fresh session before the cheaper rung (re-opening the socket) was tried")
	}
}

func TestTheAttemptFloorHolds(t *testing.T) {
	tun := stalled(time.Hour)
	tun.reboundBefore, tun.stallRebinds = true, 1
	tun.noteFruitless(renewMinAttempts-1, freshNow)
	if tun.NeedsFreshSession() {
		t.Fatalf("asked after %d attempt(s); the floor is %d", renewMinAttempts-1, renewMinAttempts)
	}
}

func TestAHostWakingFromSleepAsksWithinSecondsNotMinutes(t *testing.T) {
	// Asleep for two hours: the box reaped the peer long ago. The monitor's count starts again
	// at one, but the last handshake is two hours old, so the fresh session should follow the
	// first socket re-open rather than another reap window of local attempts.
	tun := stalled(2 * time.Hour)
	sinceRebind := 0
	for n := 1; n <= rebindAfterAttempts+2; n++ {
		sinceRebind = tun.escalateIfStuck(sinceRebind, rebindAfterAttempts)
		tun.noteFruitless(n, freshNow)
	}
	if !tun.NeedsFreshSession() {
		t.Fatalf("no fresh session after %d attempts on a two-hour-old handshake", rebindAfterAttempts+2)
	}
}

func TestAHandshakeClearsTheRequestAndTheStall(t *testing.T) {
	tun := stalled(time.Hour)
	_ = tun.escalateIfStuck(rebindAfterAttempts, rebindAfterAttempts)
	tun.noteFruitless(2, freshNow)
	tun.noteFruitless(3, freshNow)
	if !tun.NeedsFreshSession() {
		t.Fatal("setup: the request was not raised")
	}
	tun.noteRecovered()
	if tun.NeedsFreshSession() {
		t.Fatal("a tunnel that handshaked again still asks for a fresh session")
	}
	// The next stall has to earn the request again, socket re-open included.
	tun.noteFruitless(2, freshNow)
	tun.noteFruitless(3, freshNow)
	if tun.NeedsFreshSession() {
		t.Fatal("a stall after a recovery raised the request without a socket re-open of its own")
	}
}

func TestTheRebindCounterGrowsOnEveryReopen(t *testing.T) {
	tun := &Tunnel{}
	n := 0
	for i := 0; i < 3*(rebindAfterAttempts+1); i++ {
		n = tun.escalateIfStuck(n, rebindAfterAttempts)
	}
	if got := tun.Rebinds(); got != 3 {
		t.Fatalf("Rebinds() = %d after three re-opens", got)
	}
}

func TestHandshakeAge(t *testing.T) {
	tun := &Tunnel{lastH: time.Now().Add(-90 * time.Second)}
	if age := tun.HandshakeAge(); age < 89*time.Second || age > 120*time.Second {
		t.Fatalf("HandshakeAge() = %s for a handshake 90s ago", age)
	}
	// Never handshaked: the age runs from when the tunnel started.
	tun = &Tunnel{started: time.Now().Add(-10 * time.Minute)}
	if age := tun.HandshakeAge(); age < 9*time.Minute {
		t.Fatalf("HandshakeAge() = %s for a tunnel that started 10m ago and never handshaked", age)
	}
	var none *Tunnel
	if none.HandshakeAge() != 0 || none.NeedsFreshSession() || none.Rebinds() != 0 {
		t.Fatal("a nil tunnel reported something")
	}
}

func TestTheReapWindowCoversTheBoxsReaper(t *testing.T) {
	// The box reaps at 180 s of silence and sweeps every 60 s, so a peer can survive until 240 s.
	// Asking before that would re-run a connect the box did not need.
	if renewAfterSilence < 240*time.Second {
		t.Fatalf("renewAfterSilence = %s is inside the box's reap window (180 s + a 60 s sweep)", renewAfterSilence)
	}
}

// The monitor must feed the latch, or every test above passes over a mechanism that never runs.
func TestTheMonitorFeedsTheFreshSessionLatch(t *testing.T) {
	src, err := os.ReadFile("health.go")
	if err != nil {
		t.Fatalf("read health.go: %v", err)
	}
	for _, want := range []string{"t.noteFruitless(stall.consecutive, now)", "t.noteRecovered()"} {
		if !hasLiveStatement(string(src), want) {
			t.Fatalf("the monitor no longer calls %s, so a tunnel the box has dropped is re-handshaked forever", want)
		}
	}
	if strings.Count(string(src), "escalateIfStuck(sinceRebind, rebindAfter)") != 1 {
		t.Fatal("the socket re-open rung is no longer driven from the monitor")
	}
	dev, err := os.ReadFile("device.go")
	if err != nil {
		t.Fatalf("read device.go: %v", err)
	}
	if !hasLiveStatement(string(dev), "started:") {
		t.Fatal("Start no longer stamps when the tunnel started, so a tunnel that never handshakes has no age")
	}
}
