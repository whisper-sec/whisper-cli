// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"os"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// TestMain clears the opt-in a developer may have exported, so no test of the name service reads
// this machine's shell: with WHISPER_RESOLVE_ON_HOST=1 set, names would resolve on the host and
// every "names stay in the tunnel" assertion would fail for a reason that is not the code's.
//
// It also gives the package a scratch home: the direct-path tests store what they learn under
// ~/.config/whisper/paths, and without one they wrote the developer's real directory.
func TestMain(m *testing.M) {
	os.Exit(testenv.Main(m, func() { _ = os.Unsetenv(ResolveOnHostEnv) }))
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
