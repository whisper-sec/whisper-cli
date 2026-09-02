// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// A tunnel that could not come up said "re-handshaking (attempt 1…2…3…)" and nothing else,
// forever. On one host that line ran while a second `whisper connect` for the same address had
// taken the peer slot on the box, so the first session's local proxy kept accepting
// connections and the tunnel underneath was never coming back. A counter is a symptom; these
// tests hold the monitor to naming the two causes and the remedy, once.

package wgtun

import (
	"strings"
	"testing"
)

func TestStallTrackerSaysNothingBeforeTheThreshold(t *testing.T) {
	var s stallTracker
	for i := 1; i < stallNoteAfter; i++ {
		if note, ok := s.attemptFailed(); ok {
			t.Fatalf("attempt %d escalated before the threshold: %q", i, note)
		}
	}
}

func TestStallTrackerNamesBothCausesAndTheRemedyExactlyOnce(t *testing.T) {
	var s stallTracker
	var said []string
	for i := 0; i < stallNoteAfter+5; i++ {
		if note, ok := s.attemptFailed(); ok {
			said = append(said, note)
		}
	}
	if len(said) != 1 {
		t.Fatalf("the stall was explained %d times, want exactly 1: %v", len(said), said)
	}
	note := said[0]
	for _, want := range []string{
		"no handshake",          // what is actually wrong
		"UDP",                   // cause one: the network is not carrying the tunnel
		"taken the tunnel over", // cause two: another connect holds this address
		"whisper connect",       // the remedy
	} {
		if !strings.Contains(note, want) {
			t.Fatalf("the stall note does not mention %q: %q", want, note)
		}
	}
}

// TestStallTrackerReArmsOnlyAfterRecovery is the control: without it, "exactly once" could be
// satisfied by a tracker that never speaks again at all, which would be silence dressed up as
// restraint. A tunnel that comes back and stalls a second time gets explained a second time.
func TestStallTrackerReArmsOnlyAfterRecovery(t *testing.T) {
	var s stallTracker
	drive := func() int {
		n := 0
		for i := 0; i < stallNoteAfter+2; i++ {
			if _, ok := s.attemptFailed(); ok {
				n++
			}
		}
		return n
	}
	if n := drive(); n != 1 {
		t.Fatalf("first stall explained %d times, want 1", n)
	}
	if n := drive(); n != 0 {
		t.Fatalf("the same unbroken stall was explained again %d times, want 0", n)
	}
	s.recovered()
	if n := drive(); n != 1 {
		t.Fatalf("after a recovery the next stall was explained %d times, want 1", n)
	}
}
