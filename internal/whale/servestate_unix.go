//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"os"
	"syscall"
)

// processAlive asks the kernel whether pid is still there, with signal 0 - the standard
// no-op probe. A pid we may not signal (a different user's) counts as alive: claiming an
// exposure is gone when we merely cannot see it would be the wrong way to be wrong.
func processAlive(pid int) bool {
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

// stopProcess asks the holder to stop the way it expects to be asked: SIGTERM, which its
// own signal handler turns into a clean teardown (listener closed, record cleared).
func stopProcess(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		if err == os.ErrProcessDone {
			return nil
		}
		return err
	}
	return nil
}
