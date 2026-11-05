// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// The Windows enforced run refuses what it cannot honour before it brings anything up:
// no connect is made, no filter is added.

func runEnforceArgs(t *testing.T, args ...string) error {
	t.Helper()
	testenv.HermeticHome(t)
	defer func() { enforceSeccomp = "" }()
	cmd := newRunCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestWindowsEnforceRefusesUserWithTheReason(t *testing.T) {
	err := runEnforceArgs(t, "--enforce", "--user", "someone", "--", "cmd", "/c", "exit")
	if err == nil || !strings.Contains(err.Error(), "--user is not available on Windows") || !isUsageError(err) {
		t.Fatalf("got %v", err)
	}
}

func TestWindowsEnforceRefusesSeccomp(t *testing.T) {
	err := runEnforceArgs(t, "--enforce", "--seccomp", "strict", "--", "cmd", "/c", "exit")
	if err == nil || !strings.Contains(err.Error(), "Linux namespace only") || !isUsageError(err) {
		t.Fatalf("got %v", err)
	}
}

func TestWindowsEnforceRefusesAProgramThatIsNotThere(t *testing.T) {
	err := runEnforceArgs(t, "--enforce", "--", "no-such-program.exe")
	if err == nil || !isUsageError(err) {
		t.Fatalf("got %v", err)
	}
	// Elevated (a CI runner, an admin shell): the missing program is named. Not elevated: the
	// elevation sentence comes first. Either way nothing was connected.
	if !strings.Contains(err.Error(), "no-such-program.exe") && !strings.Contains(err.Error(), "elevated terminal") {
		t.Fatalf("got %v", err)
	}
}
