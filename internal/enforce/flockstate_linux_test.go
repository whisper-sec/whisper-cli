// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import "testing"

// withoutKernelLockTable makes liveHolder take its fallback path (the holder file's pid), as on darwin.
func withoutKernelLockTable(t *testing.T) {
	t.Helper()
	old := procLocks
	procLocks = "/nonexistent/proc-locks"
	t.Cleanup(func() { procLocks = old })
}
