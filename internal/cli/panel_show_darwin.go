// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package cli

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_show_darwin.go is the exec half of `whisper panel show`, and nothing else. The
// bundle search and the argv live in panel_show.go so they are exercised on every lane;
// what is left here genuinely needs a Mac.
//
// This file declares no newXxxCmd: the command surface is identical on every platform.

// panelAppSupported: this is the platform the panel is for.
const panelAppSupported = true

// panelOpenTimeout bounds the shell-out. `open` returns as soon as Launch Services has
// taken the request, so this is only ever a ceiling on a wedged launchservicesd rather
// than a wait anybody sees. A var so a test can shorten it.
var panelOpenTimeout = 15 * time.Second

// openPanelApp runs the argv panelOpenArgv built.
//
// The output is captured and returned in the refusal because `open` explains itself
// properly, and a bare exit status here would be the opaque error the Robustness
// Principle exists to keep out of a terminal: "exit status 1" tells a person nothing,
// while "Unable to find application named ..." or a Gatekeeper refusal tells them what
// to do next.
var openPanelApp = func(argv []string) error {
	cx, cancel := context.WithTimeout(context.Background(), panelOpenTimeout)
	defer cancel()
	out, err := exec.CommandContext(cx, argv[0], argv[1:]...).CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	if cx.Err() != nil {
		detail = "macOS did not answer within " + panelOpenTimeout.String() + " (" + detail + ")"
	}
	return &client.ProblemError{Status: 500,
		Detail: "could not open the panel: " + detail}
}
