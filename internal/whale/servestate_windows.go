//go:build windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import "os"

// processAlive on Windows leans on FindProcess, which opens a real handle and fails for a
// pid that is gone. There is no signal-0 equivalent, so this is the honest maximum.
func processAlive(pid int) bool {
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

// stopProcess on Windows has no SIGTERM to send, so the holder is killed. The state record
// is cleared by the caller either way, so `funnel off` still ends with the exposure gone
// and the record gone - which is the promise the verb makes.
func stopProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Kill(); err != nil && err != os.ErrProcessDone {
		return err
	}
	return nil
}
