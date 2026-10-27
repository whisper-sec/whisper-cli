// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import "os"

// readTrustedRecord on Windows reads a regular record file. Ownership there is enforced by the directory's
// ACL, and locking down the ProgramData registry directory is tracked separately.
func readTrustedRecord(_ string, path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	b, err := os.ReadFile(path)
	return b, err == nil
}

// pidAlive on Windows asks the process table whether pid exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid) // on Windows this opens the process, so it fails for a pid that is gone
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
