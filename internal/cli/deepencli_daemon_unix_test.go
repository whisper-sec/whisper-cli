//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os/exec"
	"testing"
)

// deepencli_daemon_unix_test.go: the unix daemon-detach attributes. Setsid is what
// keeps the --ensure-spawned daemon alive after the launching shell exits (a new
// session: no controlling terminal, immune to the terminal's SIGHUP) - losing it
// would silently kill every held tunnel when the user closes the shell.

func TestDeepenCLI_DetachSysProcAttrStartsANewSession(t *testing.T) {
	attr := detachSysProcAttr()
	if attr == nil || !attr.Setsid {
		t.Fatalf("the detached daemon must start its own session (Setsid), got %+v", attr)
	}
}

func TestDeepenCLI_ApplyDetachStampsTheCommand(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if cmd.SysProcAttr != nil {
		t.Fatal("precondition: a fresh command carries no SysProcAttr")
	}
	applyDetach(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Fatalf("applyDetach must stamp Setsid onto the command, got %+v", cmd.SysProcAttr)
	}
}
