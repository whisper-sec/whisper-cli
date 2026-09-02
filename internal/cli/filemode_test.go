// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// filemode_test.go is where the suite says what "only its owner can read this"
// means, once, instead of asserting a unix number everywhere and being wrong on
// a third of the fleet.
//
// It used to say something weaker. Until secfile landed, both helpers below
// returned early on Windows, because the property they name was not held there:
// Go's os.OpenFile ignores the permission argument except for the read-only
// bit, so a file created 0600 simply inherited the containing directory's ACL,
// and under %ProgramData% that ACL grants BUILTIN\Users read. The exemption was
// written down here, in one place, with a doc comment saying it existed only
// until the DACL work landed and that this helper was the one thing that would
// have to change when it did.
//
// This is that change. The helpers now ask secfile.Verify, which reads the real
// object on every platform: the mode bits on unix, the actual DACL on Windows.
// The assertion is not circular, because Verify never writes; a check that
// re-applied the fix before measuring could not fail when the fix was missing.

// assertPrivateFile asserts that a file we wrote to hold a credential exists
// and that only its owner can read it.
func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the file was never written: %v", err)
	}
	if fi.IsDir() {
		t.Fatalf("%s is a directory, not the file we wrote", path)
	}
	if err := secfile.Verify(path); err != nil {
		t.Fatalf("%s holds a credential and is not owner-only: %v", path, err)
	}
}

// assertOwnerOnlyDir is the directory twin of assertPrivateFile.
func assertOwnerOnlyDir(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the directory was never created: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
	if err := secfile.VerifyDir(path); err != nil {
		t.Fatalf("%s is not owner-only: %v", path, err)
	}
}
