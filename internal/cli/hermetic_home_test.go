// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// The suite runs in a scratch home, and every per-user location resolves inside it. If the
// TestMain that sets this up is ever lost (left out of a copy of the source, renamed, replaced),
// this fails, rather than the suite quietly writing the real ~/.config/whisper.
func TestTheSuiteRunsInAScratchHome(t *testing.T) {
	home := testenv.ScratchHome()
	if home == "" {
		t.Fatal("no scratch home: TestMain did not run testenv.Main, so tests may write the real home")
	}
	if err := testenv.RequireScratchHome(home); err != nil {
		t.Fatal(err)
	}
}
