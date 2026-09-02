// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_show_test.go covers `whisper panel show`, and it covers it on the lane
// that actually runs: the command is macOS-only, the suite runs on Linux, so everything
// worth asserting is reached through panelShow's seams rather than through the platform
// constant. A test that could only run on a Mac would be a test that runs nowhere.

// TestPanelShowIsARealSubcommand is the measurement the issue was filed on. Before this
// landed the binary answered:
//
//	$ whisper panel show
//	whisper: unknown panel subcommand "show"
//	available: status, system-proxy
//
// The assertion is against cobra's own command tree rather than `--help` output, because
// a cobra binary answers `whisper panel <anything> --help` with exit 0, so a help-based
// presence check passes for every string including one that does not exist.
func TestPanelShowIsARealSubcommand(t *testing.T) {
	panel := newPanelCmd()

	found, _, err := panel.Find([]string{"show"})
	if err != nil {
		t.Fatalf("`whisper panel show` does not resolve: %v", err)
	}
	if found.Name() != "show" {
		t.Fatalf("`show` resolved to %q, so the verb is not wired", found.Name())
	}
	// `open` is what a person types half the time, and Postel says accept it.
	if alias, _, err := panel.Find([]string{"open"}); err != nil || alias.Name() != "show" {
		t.Fatalf("`whisper panel open` must reach the same verb, got %v / %v", alias, err)
	}

	// The control. Find falls back to the parent for an unknown argument, so the check
	// above only means something if a name that does NOT exist fails to resolve to a
	// subcommand of its own.
	if bogus, _, err := panel.Find([]string{"there-is-no-such-verb"}); err == nil && bogus.Name() == "there-is-no-such-verb" {
		t.Fatal("an invented subcommand resolved, so this test cannot tell a wired verb from an unwired one")
	}

	// And it is listed, because a verb nobody can discover is barely a verb.
	var listed []string
	for _, c := range panel.Commands() {
		listed = append(listed, c.Name())
	}
	if !hasString(listed, "show") {
		t.Fatalf("`show` is not among the panel subcommands: %v", listed)
	}
}

// hasString reports whether a slice holds v. The package already has a `contains` for
// substrings, so this one is named for what it does rather than shadowing that.
func hasString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// stageBundle writes a bundle that looks installed: a directory with the executable
// build-pkg.sh insists on inside it.
func stageBundle(t *testing.T, root string) string {
	t.Helper()
	app := filepath.Join(root, panelBundleName)
	exe := filepath.Join(app, panelBundleExecutable)
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return app
}

// TestPanelBundleInstalledNeedsTheExecutableNotJustTheName pins the check against the
// state an uninstall leaves behind. A directory with the right name and nothing in it
// would otherwise be opened, and macOS would refuse with a message about the bundle
// rather than about the install.
func TestPanelBundleInstalledNeedsTheExecutableNotJustTheName(t *testing.T) {
	root := t.TempDir()
	full := stageBundle(t, root)
	if !panelBundleInstalled(full) {
		t.Fatal("a bundle with its executable in it must read as installed")
	}

	empty := filepath.Join(root, "empty", panelBundleName)
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if panelBundleInstalled(empty) {
		t.Fatal("a bundle directory with no executable in it must not read as installed")
	}
	if panelBundleInstalled(filepath.Join(root, "nothing-here.app")) {
		t.Fatal("a path that does not exist must not read as installed")
	}
	// A DIRECTORY where the executable should be is not an executable.
	dirWhereExeShouldBe := filepath.Join(root, "weird", panelBundleName)
	if err := os.MkdirAll(filepath.Join(dirWhereExeShouldBe, panelBundleExecutable), 0o755); err != nil {
		t.Fatal(err)
	}
	if panelBundleInstalled(dirWhereExeShouldBe) {
		t.Fatal("a directory standing where the executable should be must not read as installed")
	}
}

// TestFindPanelAppSearchesInOrderAndSaysWhereItLooked covers the search: the env
// override, the order of the candidates, and the refusal a person reads when the panel
// is not installed anywhere.
func TestFindPanelAppSearchesInOrderAndSaysWhereItLooked(t *testing.T) {
	installedSet := func(paths ...string) func(string) bool {
		return func(p string) bool { return hasString(paths, p) }
	}
	candidates := panelAppCandidates("/Users/someone")
	// The paths and their ORDER, by name. The subtests below say "the first candidate
	// wins", which stays true however the list is shuffled, so on its own it pins
	// nothing about WHICH bundle a Mac with two of them opens. The pkg install path has
	// to be first: a copy somebody dragged to /Applications from an older release would
	// otherwise win over the one the current package just installed.
	want := []string{
		"/opt/whisper/" + panelBundleName,
		"/Applications/" + panelBundleName,
		"/Users/someone/Applications/" + panelBundleName,
	}
	if len(candidates) != len(want) {
		t.Fatalf("want the three search paths, got %v", candidates)
	}
	for i := range want {
		if candidates[i] != want[i] {
			t.Fatalf("search order is %v, want %v", candidates, want)
		}
	}

	t.Run("the pkg install path wins when both exist", func(t *testing.T) {
		got, err := findPanelApp("", candidates, installedSet(candidates[0], candidates[1]))
		if err != nil || got != candidates[0] {
			t.Fatalf("got %q, %v; want %q", got, err, candidates[0])
		}
	})

	t.Run("a bundle somebody dragged to Applications is found", func(t *testing.T) {
		got, err := findPanelApp("", candidates, installedSet(candidates[1]))
		if err != nil || got != candidates[1] {
			t.Fatalf("got %q, %v; want %q", got, err, candidates[1])
		}
	})

	t.Run("the per-user Applications directory is searched too", func(t *testing.T) {
		got, err := findPanelApp("", candidates, installedSet(candidates[2]))
		if err != nil || got != candidates[2] {
			t.Fatalf("got %q, %v; want %q", got, err, candidates[2])
		}
	})

	t.Run("no home means no per-user candidate, not an empty prefix", func(t *testing.T) {
		none := panelAppCandidates("")
		if len(none) != 2 {
			t.Fatalf("want two candidates with no home, got %v", none)
		}
		for _, c := range none {
			if strings.HasPrefix(c, "Applications/") || c == "" {
				t.Fatalf("a rootless path leaked into the search: %v", none)
			}
		}
	})

	t.Run("the env override wins outright", func(t *testing.T) {
		mine := "/Users/someone/tools/" + panelBundleName
		got, err := findPanelApp("  "+mine+"  ", candidates, installedSet(mine, candidates[0]))
		if err != nil || got != mine {
			t.Fatalf("got %q, %v; want %q", got, err, mine)
		}
	})

	t.Run("an env override that names nothing is a named mistake, not a fallback", func(t *testing.T) {
		_, err := findPanelApp("/tmp/not-a-bundle", candidates, installedSet(candidates[0]))
		if err == nil {
			t.Fatal("a wrong WHISPER_PANEL_APP must be reported, not silently ignored")
		}
		if !strings.Contains(err.Error(), panelAppEnv) || !strings.Contains(err.Error(), "/tmp/not-a-bundle") {
			t.Fatalf("the refusal must name the variable and its value: %v", err)
		}
	})

	t.Run("not installed anywhere names every path it tried", func(t *testing.T) {
		_, err := findPanelApp("", candidates, installedSet())
		if err == nil {
			t.Fatal("want a refusal when nothing is installed")
		}
		for _, c := range candidates {
			if !strings.Contains(err.Error(), c) {
				t.Fatalf("the refusal does not name %s: %v", c, err)
			}
		}
		var pe *client.ProblemError
		if !errors.As(err, &pe) || pe.Status != 404 {
			t.Fatalf("want a 404 problem a caller can key on, got %#v", err)
		}
	})
}

// TestPanelOpenArgvIsTheCommandThatOpensTheRunningPanel pins the argv, because it is
// the whole contract with macOS and every part of it is load-bearing.
func TestPanelOpenArgvIsTheCommandThatOpensTheRunningPanel(t *testing.T) {
	app := "/opt/whisper/" + panelBundleName
	got := panelOpenArgv(app)
	want := []string{"/usr/bin/open", "-a", app, "--args", "--open"}
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	}
	if !filepath.IsAbs(got[0]) {
		t.Fatalf("open must be resolved absolutely, not through $PATH: %q", got[0])
	}
	// -n would start a SECOND copy of an app whose whole shape is one status item, so
	// a machine would end up with two glyphs and two pollers.
	if hasString(got, "-n") {
		t.Fatal("-n opens a second instance; the panel is a singleton")
	}
}

// TestPanelShowOpensWhatItFound drives the real decision function end to end with the
// platform, the filesystem and the exec all injected, which is the only way any of this
// runs on the lane the suite runs on.
func TestPanelShowOpensWhatItFound(t *testing.T) {
	root := t.TempDir()
	app := stageBundle(t, root)

	var ran [][]string
	open := func(argv []string) error {
		ran = append(ran, argv)
		return nil
	}

	res, err := panelShow(true, app, "", panelBundleInstalled, open)
	if err != nil {
		t.Fatalf("panelShow: %v", err)
	}
	if !res.Opened || res.App != app {
		t.Fatalf("result = %+v, want opened with %s", res, app)
	}
	if len(ran) != 1 {
		t.Fatalf("want exactly one launch, got %d: %v", len(ran), ran)
	}
	if !hasString(ran[0], app) || !hasString(ran[0], "--open") {
		t.Fatalf("the launch did not carry the bundle and --open: %v", ran[0])
	}
}

// TestPanelShowRefusesOffMacOSBeforeItLooksForABundle keeps the two refusals in the
// right order. "The panel is not installed" on Linux would send somebody to download an
// installer that has no panel for them.
func TestPanelShowRefusesOffMacOSBeforeItLooksForABundle(t *testing.T) {
	opened := false
	_, err := panelShow(false, "", "", func(string) bool {
		t.Fatal("the bundle search ran on a platform that has no panel")
		return false
	}, func([]string) error { opened = true; return nil })
	if err == nil {
		t.Fatal("want a refusal on a platform with no panel")
	}
	if opened {
		t.Fatal("nothing may be launched on a platform with no panel")
	}
	var pe *client.ProblemError
	if !errors.As(err, &pe) || pe.Status != 501 {
		t.Fatalf("want a 501 problem, got %#v", err)
	}
	if !strings.Contains(err.Error(), "macOS") {
		t.Fatalf("the refusal must name the platform: %v", err)
	}
}

// TestPanelShowReportsAFailedLaunchRatherThanClaimingItOpened is the honesty rule the
// panel surface is built on: a leg we could not do is never reported as done.
func TestPanelShowReportsAFailedLaunchRatherThanClaimingItOpened(t *testing.T) {
	app := stageBundle(t, t.TempDir())
	boom := errors.New("Unable to find application named 'Whisper Panel'")
	res, err := panelShow(true, app, "", panelBundleInstalled, func([]string) error { return boom })
	if err == nil {
		t.Fatal("a failed launch must be an error")
	}
	if res.Opened {
		t.Fatalf("a failed launch must not report opened: %+v", res)
	}
	if !errors.Is(err, boom) && !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("the reason from macOS must survive to the caller: %v", err)
	}
}
