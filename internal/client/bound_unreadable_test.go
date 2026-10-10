// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The three states must be three answers. Collapsing "cannot read" into
// "not there" is what turned a working sensor into an unbreakable loop: the
// remediation for absence is to run enroll, and running enroll is what created
// the unreadable file.
func TestBoundFileUnreadableSeparatesCannotReadFromNotThere(t *testing.T) {
	dir := t.TempDir()

	absent := filepath.Join(dir, "no-such-bound")
	if BoundFileUnreadable(absent) {
		t.Fatal("an absent marker must NOT report as unreadable - the two need opposite fixes")
	}

	readable := filepath.Join(dir, "bound-ok")
	if err := os.WriteFile(readable, []byte("address=2a04:2a01::1\n"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if BoundFileUnreadable(readable) {
		t.Fatal("a readable marker reported as unreadable")
	}
	if _, ok := ReadBoundFile(readable); !ok {
		t.Fatal("the readable fixture did not parse, so the negative above proves nothing")
	}

	// The real case. Two ways this fixture passes without testing anything, and
	// both have bitten this repo before, so both are refusals rather than skips
	// hidden inside a green run.
	if runtime.GOOS == "windows" {
		t.Skip("mode 0 is not how Windows denies access; the DACL path needs its own fixture")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a mode-0 file, so this arm cannot discriminate")
	}
	shut := filepath.Join(dir, "bound-shut")
	if err := os.WriteFile(shut, []byte("address=2a04:2a01::1\n"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.Chmod(shut, 0o000); err != nil {
		t.Fatalf("fixture chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shut, 0o600) })

	if _, ok := ReadBoundFile(shut); ok {
		t.Fatal("the fixture is readable after chmod 000, so it is not the state under test")
	}
	if !BoundFileUnreadable(shut) {
		t.Fatal("a marker that exists but cannot be opened must report as unreadable, not absent")
	}
}
