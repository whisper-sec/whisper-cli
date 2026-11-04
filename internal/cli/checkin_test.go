// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

func wgAnswer(endpoint, serverKey string) *client.Result {
	return &client.Result{Columns: []string{"tier", "address", "server_public_key", "endpoint"},
		Rows: [][]any{{"wireguard", renewAddr, serverKey, endpoint}}}
}

// A held Tier-1 session that stays healthy for days still makes a signed connect at most every 6
// hours, the only thing that lets the bound device veto an owner's pending clear of its binding.
func TestAHealthySessionChecksInAtMostEverySixHours(t *testing.T) {
	h := newRenewHarness(t)
	h.res = wgAnswer("198.51.100.7:51820", "c2VydmVy")
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	h.advance(5 * time.Second) // schedules the first
	if h.registers != 0 {
		t.Fatal("no check-in on the first look")
	}
	for i := 0; i < 4; i++ {
		h.advance(checkInEvery)
	}
	if h.registers != 4 || len(h.bringUps) != 0 {
		t.Fatalf("four check-ins in a day, none touching the tunnel: %d registers, %d bring-ups", h.registers, len(h.bringUps))
	}
	if h.sup.current().local != h.first {
		t.Fatal("the same box keeps the same tunnel")
	}
	h.advance(5 * time.Second)
	h.advance(time.Hour)
	if h.registers != 4 {
		t.Fatal("after a check-in the next is six hours away, never on the next look")
	}
	for i := 1; i < len(h.regNows); i++ {
		if gap := h.regNows[i].Sub(h.regNows[i-1]); gap > checkInEvery {
			t.Fatalf("check-ins %s apart, more than %s", gap, checkInEvery)
		}
	}
}

func TestACheckInThatMovedThePeerFollowsIt(t *testing.T) {
	h := newRenewHarness(t)
	h.res = wgAnswer("203.0.113.9:51820", "b3RoZXI=")
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	h.advance(5 * time.Second)
	h.advance(checkInEvery)
	if len(h.bringUps) != 1 || h.registers < 1 {
		t.Fatalf("a check-in answered by another box brings the tunnel to it: %d bring-ups", len(h.bringUps))
	}
	if !strings.Contains(strings.Join(h.said, "\n"), "moved its tunnel") {
		t.Fatalf("and says so: %v", h.said)
	}
}

func TestAFailedCheckInLeavesAWorkingTunnelAlone(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = &client.ProblemError{Status: 503, Detail: "busy"}
	h.sup.sess.peer = "x|y"
	h.advance(5 * time.Second)
	h.advance(checkInEvery)
	if h.registers != 1 || len(h.bringUps) != 0 || h.sup.current().local != h.first {
		t.Fatal("a failed check-in is retried at the next one, never by touching the tunnel")
	}
	// a session with no Tier-1 peer (an egress tier) never checks in
	h2 := newRenewHarness(t)
	h2.advance(5 * time.Second)
	h2.advance(2 * checkInEvery)
	if h2.registers != 0 {
		t.Fatal("no peer, no check-in")
	}
}
