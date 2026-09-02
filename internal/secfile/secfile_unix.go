// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package secfile

import (
	"errors"
	"fmt"
	"os"
)

// secfile_unix.go is the mode-bit half of the seam. Here the guarantee IS the
// permission argument: the kernel applies it at create time, chmod makes it
// umask-independent, and os.Stat reads back what is actually on the inode. The
// Windows half of the same seam has to build a DACL to say the same sentence.

// ErrExposed is returned by Verify and VerifyDir when the object on disk is
// reachable by someone other than its owner. Callers match it with errors.Is to
// tell "this host cannot keep a credential private" apart from an ordinary
// filesystem failure.
var ErrExposed = errors.New("a principal other than the owner can read or alter it")

// Harden makes an existing FILE owner-only.
//
// A chmod, and the reason it is a separate call from the write is the same on
// both platforms: umask can only take bits away, but a file that already
// existed carries whatever mode it was left with, and an earlier version of
// this binary (or an operator's cp) may have left it 0644.
//
// The two guards are not ceremony. Chmod follows the path to whatever is at the
// end of it, so a Harden aimed at a directory would strip its execute bit and
// make it untraversable, and a Harden aimed at a fifo or a device node would
// re-permission something that is not ours. Both are refused or skipped here
// rather than discovered afterwards by Verify, which can only report damage
// already done.
func Harden(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory: HardenDir is the one that takes those", path)
	}
	if !fi.Mode().IsRegular() {
		// A fifo, socket or device the operator chose deliberately. Verify
		// exempts these for the same reason, so the two agree.
		return nil
	}
	return os.Chmod(path, FileMode)
}

// HardenDir makes an existing DIRECTORY owner-only.
func HardenDir(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory: Harden is the one that takes files", path)
	}
	return os.Chmod(path, DirMode)
}

// Verify reports whether the file at path is owner-only, reading the inode
// rather than trusting that a write happened. It never modifies anything.
//
// The property asserted is "no group or other bits", not "exactly 0600": 0400
// and 0600 are both owner-only and both fine, while 0640 and 0644 are the
// regression this catches.
func Verify(path string) error { return verify(path, false) }

// VerifyDir is Verify for a directory.
func VerifyDir(path string) error { return verify(path, true) }

func verify(path string, wantDir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: cannot be shown private: %w", path, err)
	}
	if fi.IsDir() != wantDir {
		if wantDir {
			return fmt.Errorf("%s is not a directory", path)
		}
		return fmt.Errorf("%s is a directory, not a file", path)
	}
	// A device, fifo or socket has no mode bits of ours to judge: an operator
	// who points an output file at /dev/stdout has made an explicit choice, and
	// chmod-ing a device node would be us editing something we do not own.
	if !wantDir && !fi.Mode().IsRegular() {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s is mode %04o: %w", path, perm, ErrExposed)
	}
	return nil
}
