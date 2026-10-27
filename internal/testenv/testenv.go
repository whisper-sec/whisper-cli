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
	"os"
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
// UseHome points every per-user directory at dir, the way HermeticHome does for a fresh one.
// A child process a test starts uses it to share its parent's home: on Windows the home is
// USERPROFILE, not HOME, so setting HOME alone leaves the child in a different home.
func UseHome(t *testing.T, dir string) {
	t.Helper()
	setHome(t, dir)
}

// FileIdentity stats path through an open handle, so the identity is read now. os.Stat on
// Windows reads the file index lazily, when os.SameFile first asks, which makes two stats of
// one path taken before and after a replace compare equal. Through a handle it is read at once
// on every platform.
func FileIdentity(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

func NoHome(t *testing.T) {
	t.Helper()
	setHome(t, "")
}

// ProcessHome points the whole test PROCESS at a fresh home, for a package's TestMain, and
// returns a cleanup that removes it. A test that forgot HermeticHome then reads and writes a
// scratch directory instead of the developer's real ~/.config/whisper: the CLI suite used to
// overwrite the real saved agent file with a fixture address on every run. The Go toolchain's
// own caches are pinned to where they already were first, so a test that runs `go` neither
// starts cold nor downloads modules into the scratch home.
func ProcessHome() (cleanup func(), err error) {
	for k, v := range toolchainDirs() {
		if os.Getenv(k) == "" && v != "" {
			_ = os.Setenv(k, v)
		}
	}
	home, err := os.MkdirTemp("", "whisper-test-home-")
	if err != nil {
		return func() {}, err
	}
	for k, v := range homeFamily(home) {
		_ = os.Setenv(k, v)
	}
	return func() { _ = os.RemoveAll(home) }, nil
}

// toolchainDirs is where the Go caches live under the CURRENT home, spelled out so that moving
// the home does not move them.
func toolchainDirs() map[string]string {
	out := map[string]string{}
	if d, err := os.UserCacheDir(); err == nil {
		out["GOCACHE"] = filepath.Join(d, "go-build")
	}
	if h, err := os.UserHomeDir(); err == nil {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = filepath.Join(h, "go")
			out["GOPATH"] = gopath
		}
		out["GOMODCACHE"] = filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
	}
	return out
}

// homeFamily is every variable setHome sets, as values, for a caller without a *testing.T.
func homeFamily(home string) map[string]string {
	appData, localAppData := "", ""
	if home != "" {
		appData = filepath.Join(home, "AppData", "Roaming")
		localAppData = filepath.Join(home, "AppData", "Local")
	}
	m := map[string]string{
		"HOME": home, "USERPROFILE": home, "APPDATA": appData, "LOCALAPPDATA": localAppData,
		"XDG_CONFIG_HOME": "", "XDG_CACHE_HOME": "", "XDG_STATE_HOME": "",
	}
	for _, k := range credentialEnv {
		m[k] = ""
	}
	return m
}

// setHome is the single point that knows the whole family. Everything that
// isolates a test goes through it, so a variable added here is added everywhere.
func setHome(t *testing.T, home string) {
	t.Helper()
	for k, v := range homeFamily(home) {
		t.Setenv(k, v)
	}
}
