// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// TestMain gives the whole suite a scratch home and refuses to run unless every per-user
// location (HOME, the XDG base directories, what os.UserHomeDir and os.UserConfigDir return)
// is inside it. A test that does not call testenv.HermeticHome itself then reads and writes a
// scratch directory, never the developer's real ~/.config/whisper.
//
// It lives in this file, which every copy of the source carries. It used to sit in a file the
// public copy leaves out, so `go test ./...` on that copy ran with the real home and wrote a
// fixture address into the real saved agent file, and a test project root into a real projects
// file. Files the public copy leaves out add their own setup through testMainBefore.
func TestMain(m *testing.M) {
	os.Exit(testenv.Main(m, func() {
		for _, f := range testMainBefore {
			f()
		}
	}))
}

// testMainBefore is setup a file adds from its init, run before the scratch home is made.
var testMainBefore []func()
