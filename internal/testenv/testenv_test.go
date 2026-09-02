// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testenv_test.go holds the helper to its own promise. Every assertion here fails
// if one member of the family is dropped, which is precisely how the isolation
// came to be POSIX-only in the first place.

func TestHermeticHomeSetsTheWholeFamily(t *testing.T) {
	// Seed the environment with values that would send a resolver somewhere real,
	// so a variable the helper forgets shows up as itself and not as an empty
	// string that happens to be harmless.
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(k, filepath.Join("nope", "the-real-user"))
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join("nope", "xdg-config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join("nope", "xdg-cache"))
	t.Setenv("XDG_STATE_HOME", filepath.Join("nope", "xdg-state"))

	home := HermeticHome(t)
	if home == "" {
		t.Fatal("the helper must return the temp home it created")
	}
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		got := os.Getenv(k)
		if got == "" {
			t.Fatalf("%s is empty; the whole point is that no per-user directory resolves to the real user", k)
		}
		if !strings.HasPrefix(got, home) {
			t.Fatalf("%s = %q, which is outside the temp home %q", k, got, home)
		}
	}
	for _, k := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"} {
		if got := os.Getenv(k); got != "" {
			t.Fatalf("%s = %q, want cleared so the resolution falls back under the temp home", k, got)
		}
	}
}

func TestHermeticHomeIsWhereTheStandardLibraryLooks(t *testing.T) {
	// The failure being prevented was never about the variables as such: it was
	// that os.UserHomeDir and os.UserConfigDir read DIFFERENT ones per platform.
	// Assert through those functions, on whichever platform this runs.
	home := HermeticHome(t)
	got, err := os.UserHomeDir()
	if err != nil || got != home {
		t.Fatalf("os.UserHomeDir() = %q (err %v), want the temp home %q", got, err, home)
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir(): %v", err)
	}
	if !strings.HasPrefix(cfg, home) {
		t.Fatalf("os.UserConfigDir() = %q, outside the temp home %q", cfg, home)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("os.UserCacheDir(): %v", err)
	}
	if !strings.HasPrefix(cache, home) {
		t.Fatalf("os.UserCacheDir() = %q, outside the temp home %q", cache, home)
	}
}

func TestHermeticHomeClearsEveryCredentialVariable(t *testing.T) {
	for _, k := range credentialEnv {
		t.Setenv(k, "whisper_live_a_real_looking_key")
	}
	HermeticHome(t)
	for _, k := range credentialEnv {
		if got := os.Getenv(k); got != "" {
			t.Fatalf("%s = %q; a temp home stops the key FILE being found and does nothing at all about a key in the environment", k, got)
		}
	}
}

func TestNoHomeReallyLeavesNoHome(t *testing.T) {
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(k, filepath.Join("nope", "the-real-user"))
	}
	NoHome(t)
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		if got := os.Getenv(k); got != "" {
			t.Fatalf("%s = %q; the no-home branch must be genuinely reached, not faked on one platform", k, got)
		}
	}
	if got, err := os.UserHomeDir(); err == nil && got != "" {
		t.Fatalf("os.UserHomeDir() still resolved to %q", got)
	}
}

func TestEachHelperIsIndependentOfTheLast(t *testing.T) {
	a := HermeticHome(t)
	b := HermeticHome(t)
	if a == b {
		t.Fatal("two calls must not share a directory, or one test's leftovers become another's fixture")
	}
	if got, _ := os.UserHomeDir(); got != b {
		t.Fatalf("the second call must win, got %q want %q", got, b)
	}
}
