// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// logSSHAuthz records one decision in the auth log, where sshd's own lines are, because sshd
// throws away an AuthorizedKeysCommand's stderr. stderr gets it too, for `sshd -d` and for a
// person running the check by hand. A system log that cannot be reached loses only the copy.
// How the line reaches the system log is per OS (sshAuthzSystemLog): Linux and the BSDs take
// a syslog datagram, macOS needs its unified log.
func logSSHAuthz(admit bool, line string) {
	verdict := "DENY"
	if admit {
		verdict = "ADMIT"
	}
	msg := verdict + " " + line
	fmt.Fprintln(os.Stderr, sshAuthzTag+": "+msg)
	sshAuthzSystemLog(admit, msg)
}

// sshAuthzTag names every line, in the syslog tag and, where the tag may not survive, in the text.
const sshAuthzTag = "whisper-ssh-authz"

// sshAuthzLoggerTimeout bounds the logger(1) child: sshd is waiting on this command, and a copy
// of the decision is never worth stalling a login for.
const sshAuthzLoggerTimeout = 2 * time.Second

// sshAuthzLoggerArgs is the logger(1) argument list for one decision. The message carries the tag
// in its text as well, because macOS's unified log files logger's lines under the process name
// "logger" and a predicate on the text must still find them. Both verdicts go at notice: on macOS
// an info line is kept in memory only and is gone before anybody reads it, so the ADMIT that an
// auditor needs would never be on disk. The message is already one sanitised line
// (sshAuthzLogLine), and "--" ends the options, so no part of it can be read as a flag.
func sshAuthzLoggerArgs(msg string) []string {
	return []string{"-p", "auth.notice", "-t", sshAuthzTag, "--", sshAuthzTag + ": " + msg}
}

// runSSHAuthzLogger runs logger(1) at an absolute path, with no shell and a short deadline, and
// reports whether it exited cleanly. Its own output is discarded: sshd reads this command's
// stdout as authorized_keys lines, so nothing a child prints may reach it.
func runSSHAuthzLogger(path string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), sshAuthzLoggerTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	return c.Run()
}

// fileOwnerUID is the owner of a file, which sshd checks along an AuthorizedKeysCommand's path.
func fileOwnerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
