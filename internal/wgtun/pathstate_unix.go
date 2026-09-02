//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"os"
	"syscall"
)

// processIsAlive asks the kernel whether pid is still there, with signal 0 - the standard no-op
// probe. A pid we may not signal (another user's) counts as ALIVE: deciding a published path
// record is abandoned because we merely cannot see its holder would delete a true record, and a
// deleted true record renders as "no direct paths", which is the failure this file exists to
// avoid. It mirrors the serve record's own liveness rule, for the same reason.
func processIsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return err == os.ErrPermission || err == syscall.EPERM
}
