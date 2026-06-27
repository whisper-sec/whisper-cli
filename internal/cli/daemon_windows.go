//go:build windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os/exec"
	"syscall"
)

// Windows process-creation flags (from winbase.h). Go's syscall package on Windows exposes
// CREATE_NEW_PROCESS_GROUP but not DETACHED_PROCESS, so we declare the latter ourselves.
const (
	createNewProcessGroup = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	detachedProcess       = 0x00000008 // DETACHED_PROCESS — no inherited console
)

// applyDetach detaches a spawned daemon from the parent console on Windows:
// DETACHED_PROCESS gives it no inherited console (so it isn't torn down with the launching
// terminal), and CREATE_NEW_PROCESS_GROUP puts it in its own group (so a Ctrl-C / Ctrl-Break
// in the parent's group doesn't propagate to it). HideWindow keeps any transient window from
// flashing. This is the Windows equivalent of unix Setsid for the #188 userspace tunnel
// daemon. NOTE: HideWindow + DETACHED_PROCESS is the documented, robust combination; a future
// caveat to watch is that some AV/EDR setups flag newly-spawned detached processes — if that
// surfaces in the field, fall back to a foreground `whisper claude` launch (run.go), which
// needs no detach at all.
func applyDetach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | detachedProcess,
		HideWindow:    true,
	}
}
