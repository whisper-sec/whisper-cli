// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"path/filepath"
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
//
// The machine-wide session registry is pointed at a scratch directory too. It is not under
// any home: it is /run/whisper/sessions, and a root holder writes its record THERE first. Run as
// root, every test that held a session through stubSessionsDir wrote into the host's real registry,
// so a later test read the earlier ones' records (35 failures in the root suite's first run), and on
// a box with a real daemon the suite would have written beside its records. Unprivileged, the same
// default let a test read a real daemon's records. stubSessionsDir gives each test a fresh one, and
// the run fails if anything is left in this run-wide directory at the end: a record there is a test
// that held a session without its own registry, which is the leak this closes.
func TestMain(m *testing.M) {
	machine, err := os.MkdirTemp("", "whisper-cli-machine-sessions-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain: refusing to run: no scratch machine registry:", err)
		os.Exit(1)
	}
	machineSessionsDirFn = func() string { return filepath.Join(machine, "sessions") }
	code := testenv.Main(m, func() {
		for _, f := range testMainBefore {
			f()
		}
	})
	if left, _ := os.ReadDir(filepath.Join(machine, "sessions")); len(left) > 0 && code == 0 {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, e.Name())
		}
		fmt.Fprintf(os.Stderr, "TestMain: a test wrote the run-wide machine registry instead of its own (stubSessionsDir): %v\n", names)
		code = 1
	}
	_ = os.RemoveAll(machine)
	os.Exit(code)
}

// testMainBefore is setup a file adds from its init, run before the scratch home is made.
var testMainBefore []func()
