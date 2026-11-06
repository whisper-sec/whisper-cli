// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"io"
	"os"
	"syscall"
)

// readTrustedRecord reads a record file only if recordOwnerTrusted allows it. One open, no symlink
// followed, ownership taken from the open descriptor, so the file cannot be swapped between the check
// and the read.
func readTrustedRecord(dir, path string) ([]byte, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	di, err := os.Stat(dir)
	if err != nil {
		return nil, false
	}
	fs, ok1 := fi.Sys().(*syscall.Stat_t)
	ds, ok2 := di.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || !recordOwnerTrusted(fs.Uid, uint32(os.Getuid()), ds.Uid) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<16))
	return b, err == nil
}

// pidAlive reports whether a process with this pid exists (EPERM means it does, under another user).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// hardenSessionsDir is a no-op where MkdirAll's mode already restricts the directory; the Windows
// half sets a protected DACL.
func hardenSessionsDir(string, bool) error { return nil }
