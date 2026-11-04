// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"path/filepath"
	"syscall"
	"testing"
)

// makeFIFO makes a named pipe in dir, which the fleets reader must refuse before it opens it
// (an open would block with no deadline). "" when the host cannot make one.
func makeFIFO(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		return ""
	}
	return p
}
