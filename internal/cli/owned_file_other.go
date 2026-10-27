// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// ownedRegularFile reports whether p is a regular file, not a link, owned by uid. The enforced
// run reads the invoker's identity key through it, so it lives beside the client rather than
// with the host service's identity ladder, which reads it too.
func ownedRegularFile(p string, uid int) bool {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}
