// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"runtime"
	"testing"
)

// Gates for assertions that are POSIX- or macOS-specific.
//
// The Windows lane runs this package, and a handful of tests here assert things
// Windows does not have: Unix mode bits, a POSIX shell to spawn, signal
// delivery, and macOS application paths. Left ungated they fail on Windows while
// asserting nothing true about it.
//
// Each gate names WHY it skips and, where one exists, WHERE the Windows
// behaviour is covered instead, so a skip is never a silent hole. None of these
// gates fire on linux or darwin, so no coverage moves on the platforms that ship
// the assertion.
//
// These went unnoticed for a long time because the Windows job's sensor step ran
// first and failed on an unrelated defect, so this package's step never
// executed. Fixing that revealed the whole set at once.

// skipWithoutPOSIXPerms gates an assertion on Unix mode bits.
func skipWithoutPOSIXPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("asserts Unix mode bits, which Windows does not have (Go reports 0666 for every file). " +
			"Windows protects the same secret files with a DACL instead, asserted in internal/secfile " +
			"and internal/client, which the Windows lane runs as its own step")
	}
}

// skipWithoutPOSIXShell gates a test that spawns a child through `sh -c`.
func skipWithoutPOSIXShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("spawns its child through `sh -c`, which Windows has no interpreter for. The behaviour " +
			"under test is env/endpoint inheritance at spawn, not the shell, but there is no Windows " +
			"child here to inherit anything yet")
	}
}

// skipWithoutPOSIXSignals gates a test that asserts signal delivery.
func skipWithoutPOSIXSignals(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("asserts SIGTERM delivery to a child. Windows has no POSIX signals; os.Process.Signal " +
			"cannot deliver SIGTERM there, so the assertion cannot hold whatever the code does")
	}
}

// skipWithoutPOSIXPaths gates a test that asserts POSIX absolute paths or the
// macOS system-proxy plumbing.
//
// These DO run and pass on Linux, so the gate is Windows-only rather than
// darwin-only. They build and compare absolute paths like /Applications/... and
// /usr/bin/open as plain strings, which is portable logic everywhere except
// Windows, where the path handling rewrites them with backslashes and the
// comparison can never match. Gating on darwin instead would silently drop
// seven passing tests from the Linux lane.
func skipWithoutPOSIXPaths(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("asserts POSIX absolute paths (the /Applications bundle search, /usr/bin/open, the " +
			"sysproxy watchdog log). Windows rewrites separators, so the comparison cannot match " +
			"whatever the code does. Runs normally on linux and darwin")
	}
}
