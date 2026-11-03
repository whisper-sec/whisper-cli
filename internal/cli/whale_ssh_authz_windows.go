// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"fmt"
	"os"
)

// logSSHAuthz writes the decision to stderr; Windows has no syslog, and Win32-OpenSSH logs
// what its own debug mode captures.
func logSSHAuthz(admit bool, line string) {
	verdict := "DENY"
	if admit {
		verdict = "ADMIT"
	}
	fmt.Fprintln(os.Stderr, "whisper-ssh-authz: "+verdict+" "+line)
}

// fileOwnerUID: Windows files have an owner SID, not a uid, so there is nothing to compare.
func fileOwnerUID(os.FileInfo) (uint32, bool) { return 0, false }
