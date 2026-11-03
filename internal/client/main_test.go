// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"os"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// TestMain gives the whole package a scratch home and refuses to run unless every per-user
// location (HOME, the XDG base directories, what os.UserHomeDir and os.UserConfigDir return)
// is inside it, so no test here reads or writes the developer's real ~/.config/whisper.
func TestMain(m *testing.M) {
	os.Exit(testenv.Main(m))
}

func TestThePackageRunsInAScratchHome(t *testing.T) {
	home := testenv.ScratchHome()
	if home == "" {
		t.Fatal("no scratch home: TestMain did not run testenv.Main")
	}
	if err := testenv.RequireScratchHome(home); err != nil {
		t.Fatal(err)
	}
}
