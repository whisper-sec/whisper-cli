// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package testenv is the one way a test in this module isolates itself from the
// machine it runs on.
//
// It exists because "hermetic" was POSIX-only and nobody noticed. Isolation was
// written by hand at two dozen sites, each of them a `t.Setenv("HOME", tmp)`, and
// on Windows that line isolates NOTHING: os.UserHomeDir reads USERPROFILE,
// os.UserConfigDir reads APPDATA, os.UserCacheDir reads LOCALAPPDATA, and none of
// the three looks at HOME. The first native Windows run of the CLI suite found
// the real user's config, picked up a real API key, and a unit test asserting a
// clean 401 instead reached the LIVE control plane and listed 358 production
// agents. The suite took 1438 seconds, all of it network.
//
// That is a correctness bug and a safety bug at once, so the answer is not to fix
// the sites one at a time. It is one helper, used everywhere, with a gate that
// fails the build if a twenty-fourth site sets HOME by hand (ci/hermeticenv).
//
// The helpers are deliberately not clever. They set the whole family of variables
// together, because the failure mode is always a variable somebody did not think
// of, on a platform they were not testing on.
package testenv

import (
	"path/filepath"
	"testing"
)

// credentialEnv is every variable that can hand a test a real credential. It is
// cleared alongside the home directories: a temp HOME stops the key FILE being
// found, and does nothing at all about a key sitting in the environment of the
// shell that ran `go test`.
var credentialEnv = []string{
	"WHISPER_API_KEY",
	"WHISPER_KEY",
	"WHISPER_BEARER",
	"WHISPER_TOKEN",
}

// HermeticHome points every per-user directory this module can resolve at a fresh
// temp directory and clears the credential environment. It returns the temp home.
//
// Set together, and always together:
//
//	HOME os.UserHomeDir on unix; the XDG base
//	USERPROFILE os.UserHomeDir on Windows
//	APPDATA os.UserConfigDir on Windows
//	LOCALAPPDATA os.UserCacheDir on Windows
//	XDG_CONFIG_HOME cleared, so os.UserConfigDir falls back to $HOME/.config
//	XDG_CACHE_HOME cleared, so os.UserCacheDir falls back to $HOME/.cache
//	XDG_STATE_HOME cleared, so the sensor's state dir falls back under $HOME
//
// A test that wants one of the XDG variables set to something specific sets it
// AFTER calling this, which reads the way it behaves.
//
// t.Setenv makes this incompatible with t.Parallel, which is the standard library
// being right: a process has one environment, and two tests rewriting it at once
// isolate neither.
func HermeticHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	setHome(t, home)
	return home
}

// NoHome is HermeticHome's negative twin: it clears the home variables outright,
// for the tests that assert what happens when a home directory cannot be
// resolved at all. It clears the SAME family, so the "no home" branch is really
// reached on Windows rather than quietly falling back to the real USERPROFILE.
func NoHome(t *testing.T) {
	t.Helper()
	setHome(t, "")
}

// setHome is the single point that knows the whole family. Everything that
// isolates a test goes through it, so a variable added here is added everywhere.
func setHome(t *testing.T, home string) {
	t.Helper()
	appData, localAppData := "", ""
	if home != "" {
		appData = filepath.Join(home, "AppData", "Roaming")
		localAppData = filepath.Join(home, "AppData", "Local")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", appData)
	t.Setenv("LOCALAPPDATA", localAppData)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	for _, k := range credentialEnv {
		t.Setenv(k, "")
	}
}
