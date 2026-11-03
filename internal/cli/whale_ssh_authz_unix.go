// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"fmt"
	"log/syslog"
	"os"
	"syscall"
)

// logSSHAuthz records one decision in the auth log, where sshd's own lines are, because sshd
// throws away an AuthorizedKeysCommand's stderr. stderr gets it too, for `sshd -d` and for a
// person running the check by hand. A syslog that cannot be reached loses only the copy.
func logSSHAuthz(admit bool, line string) {
	verdict, prio := "DENY", syslog.LOG_AUTH|syslog.LOG_NOTICE
	if admit {
		verdict, prio = "ADMIT", syslog.LOG_AUTH|syslog.LOG_INFO
	}
	msg := verdict + " " + line
	fmt.Fprintln(os.Stderr, "whisper-ssh-authz: "+msg)
	if w, err := syslog.New(prio, "whisper-ssh-authz"); err == nil {
		_, _ = w.Write([]byte(msg)) // Write keeps the severity chosen above; Notice would override it
		_ = w.Close()
	}
}

// fileOwnerUID is the owner of a file, which sshd checks along an AuthorizedKeysCommand's path.
func fileOwnerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
