// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// A containment takes its mark off the sockets its release ended once the tunnel has stopped, and
// still under the agent's lock: close runs afterStop before it lets the lock go, so the agent's next
// containment cannot be sweeping the same sockets meanwhile.
func TestCloseRunsAfterStopWhileTheAgentIsStillHeld(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the agent lock files are root's")
	}
	old := enforce.LockDir
	parent := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	enforce.LockDir = filepath.Join(parent, "locks")
	t.Cleanup(func() { enforce.LockDir = old })
	agent := netip.MustParseAddr("2a04:2a01:8000::b")
	l, err := enforce.LockExclusive(agent)
	if err != nil {
		t.Fatal(err)
	}
	ran, heldDuring := false, false
	u := &enforcedUp{lock: l, afterStop: func() {
		ran = true
		heldDuring = l.HoldsExclusive(agent)
	}}
	u.close()
	if !ran || !heldDuring {
		t.Fatalf("afterStop ran %v, with the agent still held %v; it must run before the lock is let go", ran, heldDuring)
	}
	again, err := enforce.LockExclusive(agent)
	if err != nil {
		t.Fatalf("close did not let the agent go: %v", err)
	}
	again.Release()
	u.close() // twice is safe, and afterStop runs once
}
