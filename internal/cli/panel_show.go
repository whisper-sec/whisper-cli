// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_show.go is `whisper panel show`, the scriptable way to bring the menu bar
// panel up.
//
// The panel already had a door: the app takes `--open` and shows itself instead of
// waiting to be clicked, which is how the installer makes the first thing a person
// sees be the product working. A comment in the app's main.swift said
// `whisper panel show` came through that same door. It did not, and the comment was
// corrected rather than left describing a command nobody had written. This is
// the command.
//
// It is worth having for the reason the comment assumed it existed: "run
// `whisper panel show`" is a sentence you can put in a support reply, a runbook or a
// doc page, and "click the Whisper glyph in your menu bar, if you can find it" is
// not.
//
// Two states, one verb. If the panel is not running, `open` launches it with
// `--open` and the panel appears. If it IS running, launchd's KeepAlive means it
// usually is, `open` sends the running instance a reopen event and
// applicationShouldHandleReopen shows the panel. Passing `--args --open` to an
// already-running app would do nothing at all: macOS delivers launch arguments once,
// at launch, so the running case needs the app to answer an event rather than read a
// flag. Both halves are needed and neither is sufficient.
//
// Everything here that can be decided without a Mac is decided without one: which
// bundle to open, and the exact argv. Only the exec itself is behind a build tag.
// That is deliberate. The Windows lesson in ci/windowslane is the same lesson, and a
// path-search that could only be exercised on the platform nobody runs tests on is
// how it starts.

// panelAppSupported says whether this build can open the panel at all. The panel is
// the macOS menu bar extra; there is no Linux or Windows one to open yet, and
// pretending otherwise would send somebody looking for a window that does not exist.
// Declared per platform beside the exec that needs it.

// panelBundleName is the app the pkg installs. Named once: the search path below and
// every message a person reads have to agree about what they are looking for.
const panelBundleName = "Whisper Panel.app"

// panelBundleExecutable is the path inside the bundle that makes it a real app rather
// than a directory with the right name. build-pkg.sh asserts the same file before it
// will ship the payload, and this asserts it before claiming the panel is installed.
const panelBundleExecutable = "Contents/MacOS/WhisperPanel"

// panelAppEnv lets an unusual install, or a test, name the bundle outright. Liberal in
// what we accept: a person who put the app somewhere of their own is not wrong.
const panelAppEnv = "WHISPER_PANEL_APP"

// panelAppCandidates is where the panel is looked for, best first.
//
// /opt/whisper is where the pkg puts it, and it is first because it is the answer for
// almost everybody. The two Applications directories are next because a bundle is a
// thing people drag, and refusing to find one a person moved would be friction we
// created. home may be empty, in which case the per-user directory is simply not a
// candidate rather than a path with an empty prefix.
func panelAppCandidates(home string) []string {
	out := []string{
		filepath.Join("/opt/whisper", panelBundleName),
		filepath.Join("/Applications", panelBundleName),
	}
	if home != "" {
		out = append(out, filepath.Join(home, "Applications", panelBundleName))
	}
	return out
}

// panelBundleInstalled reports whether path is a bundle with an executable in it. A
// leftover directory, or one an uninstall emptied, is not an installed panel: opening
// it would fail with a message about the bundle rather than about the install.
func panelBundleInstalled(path string) bool {
	info, err := os.Stat(filepath.Join(path, panelBundleExecutable))
	return err == nil && info.Mode().IsRegular()
}

// findPanelApp picks the bundle to open. env wins outright, because somebody who set
// it meant it, and an env var that pointed at nothing installed is a mistake worth
// naming rather than silently falling back from.
//
// installed is injected so the whole search is exercised on any host. The candidates
// are absolute macOS paths, so a test that needed a real /opt/whisper could only run
// on the platform this command already only runs on.
func findPanelApp(env string, candidates []string, installed func(string) bool) (string, error) {
	if env = strings.TrimSpace(env); env != "" {
		if installed(env) {
			return env, nil
		}
		return "", &client.ProblemError{Status: 404, Detail: fmt.Sprintf(
			"%s is set to %s, and there is no %s in it. Unset %s to look in the usual places",
			panelAppEnv, env, panelBundleExecutable, panelAppEnv)}
	}
	for _, c := range candidates {
		if installed(c) {
			return c, nil
		}
	}
	return "", &client.ProblemError{Status: 404, Detail: fmt.Sprintf(
		"the menu bar panel is not installed. Looked for %s in: %s. It ships with the macOS "+
			"package - install it from https://whisper.online/download - or set %s if you keep "+
			"it somewhere else",
		panelBundleName, strings.Join(candidates, ", "), panelAppEnv)}
}

// panelOpenArgv is the command that brings the panel up, and it is one line of data so
// that a test can read it rather than take it on trust.
//
//	/usr/bin/open -a <bundle> --args --open
//
// Absolute, for the same reason the system-proxy writer resolves networksetup
// absolutely: this launches a signed app bundle, and finding `open` through $PATH
// would let anything earlier on the path be the thing that runs.
//
// `-a` rather than `-b security.whisper.panel`: the bundle we found on disk is the one
// we mean, and a bundle-id lookup would open whatever Launch Services happens to have
// registered under that identifier, including a stale copy from an old install.
//
// `--args --open` is delivered on a LAUNCH. When the app is already running, `open`
// sends it a reopen event instead and the flag is ignored, which is why the app
// answers applicationShouldHandleReopen as well as reading the flag.
func panelOpenArgv(app string) []string {
	return []string{"/usr/bin/open", "-a", app, "--args", "--open"}
}

// panelShowResult is what the command reports. It says which bundle it opened, because
// on a machine that has been through more than one install that is the question.
type panelShowResult struct {
	Opened bool   `json:"opened"`
	App    string `json:"app"`
	Detail string `json:"detail,omitempty"`
}

// newPanelShowCmd is declared here rather than in a darwin-only file so the command
// surface is identical on every platform: `whisper panel --help` names the same verbs
// wherever it runs, and the non-macOS answer is a sentence rather than a missing verb.
// command_surface_test.go pins that premise one level up.
func newPanelShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "show",
		Aliases: []string{"open"},
		Short:   "Open the menu bar panel (macOS)",
		Long: "Bring the resident Whisper panel up in front of you, without hunting for the\n" +
			"glyph in the menu bar.\n\n" +
			"If the panel is not running yet this starts it and opens it. If it is already\n" +
			"running, the running one comes forward: there is only ever one panel, and this\n" +
			"never adds a second glyph.\n\n" +
			"The panel itself is the macOS menu bar extra that ships with the package. On\n" +
			"other platforms `whisper status` is the same read, rendered for a terminal.",
		Args: cobraNoArgs,
		RunE: func(*cobra.Command, []string) error { return runPanelShow() },
	}
}

// panelShow refuses on a platform with no panel, finds the bundle, and opens it.
//
// The order matters: on Linux the answer is "there is no menu bar panel here", never
// "the panel is not installed", which would send somebody looking for an installer that
// has nothing for them.
//
// Every input is a parameter, and that is the point rather than a style: panelAppSupported
// is false on the platform CI runs the suite on, so a version that read the constant
// itself would have a body no test could ever enter. The seams are what let the whole
// decision be exercised on the ubuntu lane, and the real values are supplied one function
// up.
func panelShow(supported bool, env, home string, installed func(string) bool,
	open func([]string) error) (panelShowResult, error) {
	if !supported {
		return panelShowResult{}, &client.ProblemError{Status: 501, Detail: "the menu bar panel is a " +
			"macOS app, so there is nothing to open on this platform. `whisper status` is the same " +
			"read for a terminal, and `whisper panel status` is it as JSON"}
	}
	app, err := findPanelApp(env, panelAppCandidates(home), installed)
	if err != nil {
		return panelShowResult{}, err
	}
	if err := open(panelOpenArgv(app)); err != nil {
		return panelShowResult{}, err
	}
	return panelShowResult{Opened: true, App: app,
		Detail: "if the panel was already running, the running one came forward"}, nil
}

// runPanelShow supplies the real seams and renders the answer.
func runPanelShow() error {
	home, _ := os.UserHomeDir()
	res, err := panelShow(panelAppSupported, os.Getenv(panelAppEnv), home, panelBundleInstalled, openPanelApp)
	if err != nil {
		return err
	}
	if g.jsonOut {
		emitJSONValue(res)
		return nil
	}
	fmt.Fprintf(os.Stderr, "opened the Whisper panel (%s)\n", res.App)
	return nil
}
