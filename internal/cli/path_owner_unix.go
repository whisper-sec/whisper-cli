// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/whisper-sec/whisper-cli/internal/peerid"
)

// pathOwner names the user that owns path: "u:<uid>" and the account name when it resolves.
func pathOwner(path string) (peerid.ID, string, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return peerid.Unknown, "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return peerid.Unknown, "", false
	}
	id := peerid.UID(st.Uid)
	if id == peerid.Unknown {
		return peerid.Unknown, "", false
	}
	name := "uid " + strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil && u.Username != "" {
		name = u.Username
	}
	return id, name, true
}
