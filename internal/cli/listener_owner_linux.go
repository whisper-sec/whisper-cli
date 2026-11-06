// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"os"
	"strconv"
)

// procRootForListener is /proc; a var so tests point it at a fixture tree.
var procRootForListener = "/proc"

// listenerOwnedBy on Linux finds the LISTEN socket inodes for port in /proc/net/tcp and tcp6, and
// checks whether pid's own fd table holds one of them. Reading another user's /proc/<pid>/fd needs
// that user or root, so an unreadable table is unknown, never a mismatch; so is a port with no
// visible listener row.
func listenerOwnedBy(port, pid int) (owned, known bool) {
	if port <= 0 || pid <= 0 {
		return false, false
	}
	var exact, wildcard []uint64
	for _, t := range []string{"/net/tcp", "/net/tcp6"} {
		b, err := os.ReadFile(procRootForListener + t)
		if err != nil {
			continue
		}
		e, w := procNetListenInodes(b, port)
		exact, wildcard = append(exact, e...), append(wildcard, w...)
	}
	want := exact
	if len(want) == 0 {
		want = wildcard
	}
	if len(want) == 0 {
		return false, false
	}
	fdDir := procRootForListener + "/" + strconv.Itoa(pid) + "/fd"
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false, false
	}
	set := make(map[string]bool, len(want))
	for _, ino := range want {
		set["socket:["+strconv.FormatUint(ino, 10)+"]"] = true
	}
	for _, fd := range fds {
		if link, err := os.Readlink(fdDir + "/" + fd.Name()); err == nil && set[link] {
			return true, true
		}
	}
	return false, true
}
