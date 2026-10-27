// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// procLocks is the kernel's table of held file locks. A var so a test can point it elsewhere.
var procLocks = "/proc/locks"

// exclusiveFlockHeld reports whether an exclusive flock is held on the lock file name in the directory
// dfd, from the kernel's lock table. known is false when the table cannot be read or the file cannot be
// stat'ed, and the caller then falls back to the holder file's pid. The table is readable by every
// account (it is not under /proc/<pid>), so root and any other user get the same answer.
func exclusiveFlockHeld(dfd int, name string) (held, known bool) {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, false
	}
	f, err := os.Open(procLocks)
	if err != nil {
		return false, false
	}
	defer f.Close()
	major, minor := uint64(unix.Major(uint64(st.Dev))), uint64(unix.Minor(uint64(st.Dev)))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// "1: FLOCK  ADVISORY  WRITE 4242 fd:01:131074 0 EOF"; a "->" line is a waiter, not a holder.
		fs := strings.Fields(sc.Text())
		if len(fs) < 6 || fs[1] == "->" || fs[1] != "FLOCK" || fs[3] != "WRITE" {
			continue
		}
		id := strings.Split(fs[5], ":")
		if len(id) != 3 {
			continue
		}
		maj, e1 := strconv.ParseUint(id[0], 16, 64)
		mn, e2 := strconv.ParseUint(id[1], 16, 64)
		ino, e3 := strconv.ParseUint(id[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && maj == major && mn == minor && ino == uint64(st.Ino) {
			return true, true
		}
	}
	if sc.Err() != nil {
		return false, false
	}
	return false, true
}
