// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"runtime"
	"testing"
)

// A gate for assertions on Unix mode bits.
//
// The Windows lane runs this package, and Windows has no mode bits: Go reports
// 0666 for every file whatever the DACL says. Secret files are protected there
// by an explicit DACL instead, applied in internal/secfile and asserted by its
// own //go:build windows tests (TestWindowsVerifyCatchesTheInheritedRead,
// TestWindowsHardenDropsRatherThanMerges, TestWindowsHardenDirMakesChildrenStartPrivate).
// So gating these does not leave the Windows behaviour unasserted; it points at
// where it IS asserted.
//
// The convention already existed on exactly one file in this package,
// bound_write_umask_test.go, which carries //go:build !windows and has a
// _windows_test.go twin. It was applied there and not to the class, so the
// remaining mode assertions ran on Windows and failed. They only surfaced now
// because the Windows job's earlier steps failed first and this one never ran.
func skipWithoutPOSIXPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("asserts Unix mode bits, which Windows does not have (Go reports 0666 regardless). " +
			"The Windows equivalent is the DACL, asserted by internal/secfile's //go:build windows tests")
	}
}
