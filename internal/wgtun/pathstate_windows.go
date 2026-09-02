//go:build windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import "os"

// processIsAlive on Windows leans on FindProcess, which opens a real handle and fails for a pid
// that is gone. There is no signal-0 equivalent, so this is the honest maximum - and it errs the
// same way the unix form does, towards believing a record rather than deleting a true one.
func processIsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
