// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import "testing"

// TestBasePort_DeterministicAndInRange: the same project path always hashes to the same base
// port, different paths (usually) differ, and every base lands in [portBase, portBase+portSpan).
func TestBasePort_DeterministicAndInRange(t *testing.T) {
	a := "/home/kaveh/projects/alpha"
	b := "/home/kaveh/projects/beta"

	if BasePort(a) != BasePort(a) {
		t.Fatal("BasePort must be deterministic for the same path")
	}
	if BasePort(a) == BasePort(b) {
		// Not strictly required (hash collisions exist), but these two must differ for the
		// design to be meaningful; if this ever flakes, pick different fixtures.
		t.Fatal("distinct project paths should hash to distinct base ports")
	}
	for _, path := range []string{a, b, "", "/", "x"} {
		p := BasePort(path)
		if p < portBase || p >= portBase+portSpan {
			t.Fatalf("BasePort(%q) = %d, out of [%d,%d)", path, p, portBase, portBase+portSpan)
		}
	}
}

// TestProbeFreePort_ReturnsBaseWhenFree: when the deterministic base is free, the probe
// returns exactly it (same project → same port, the common case).
func TestProbeFreePort_ReturnsBaseWhenFree(t *testing.T) {
	saved := portFreeFn
	defer func() { portFreeFn = saved }()
	portFreeFn = func(int) bool { return true } // everything free

	path := "/tmp/proj/whatever"
	got, err := ProbeFreePort(path)
	if err != nil {
		t.Fatalf("ProbeFreePort: %v", err)
	}
	if got != BasePort(path) {
		t.Fatalf("ProbeFreePort = %d, want the base %d when the base is free", got, BasePort(path))
	}
}

// TestProbeFreePort_StepsPastTaken: when the base (and the next few) are taken, the probe steps
// upward to the first free port — deterministic AND collision-avoiding.
func TestProbeFreePort_StepsPastTaken(t *testing.T) {
	saved := portFreeFn
	defer func() { portFreeFn = saved }()

	path := "/tmp/proj/busy"
	base := BasePort(path)
	taken := map[int]bool{base: true, base + 1: true, base + 2: true}
	portFreeFn = func(p int) bool { return !taken[p] }

	got, err := ProbeFreePort(path)
	if err != nil {
		t.Fatalf("ProbeFreePort: %v", err)
	}
	if got != base+3 {
		t.Fatalf("ProbeFreePort = %d, want base+3 (%d) — should step past the taken ports", got, base+3)
	}
}

// TestProbeFreePort_ExhaustedErrors: a fully-congested window is a clear error, not a hang.
func TestProbeFreePort_ExhaustedErrors(t *testing.T) {
	saved := portFreeFn
	defer func() { portFreeFn = saved }()
	portFreeFn = func(int) bool { return false } // nothing free

	if _, err := ProbeFreePort("/tmp/proj/congested"); err == nil {
		t.Fatal("a fully-congested window must error, not hang or return 0")
	}
}
