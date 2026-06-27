//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os/exec"
	"syscall"
)

// detachSysProcAttr returns the SysProcAttr that fully DETACHES a spawned daemon from the
// parent on unix: Setsid:true puts the child in a NEW SESSION (its own process group, no
// controlling terminal), so it keeps running after the parent (`whisper connect --ensure`)
// returns and is not killed by the terminal's SIGHUP/Ctrl-C. This is the rootless,
// no-extra-binary way to hold the #188 userspace tunnel alive for the whole Claude Code
// session. (The Background-rooted proxy lifetime + auto-reconnect already live inside the
// process; this just frees the process itself from the launching shell.)
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// applyDetach stamps the detach attributes onto the daemon command before it is started.
func applyDetach(cmd *exec.Cmd) {
	cmd.SysProcAttr = detachSysProcAttr()
}
