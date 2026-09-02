// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !darwin

package cli

import "github.com/whisper-sec/whisper-cli/internal/client"

// panel_show_other.go is the non-macOS side of `whisper panel show`.
//
// The verb exists here, and it answers. `whisper panel --help` names the same three
// subcommands wherever it runs, so a doc page or a support reply that says "run
// `whisper panel show`" gets a sentence explaining the platform rather than
// `unknown panel subcommand "show"`, which reads like a broken or outdated install.
//
// runPanelShow refuses on panelAppSupported before it looks for a bundle, so this
// function is unreachable in practice. It is written to refuse rather than to panic
// or to return nil anyway, because "unreachable" is a claim about today's caller and
// a nil here would report a panel opened on a machine that has none.

// panelAppSupported: there is no menu bar panel on this platform to open.
const panelAppSupported = false

// openPanelApp refuses with the platform named, in the same words runPanelShow uses,
// so the two can never disagree about why.
var openPanelApp = func(argv []string) error {
	return &client.ProblemError{Status: 501, Detail: "the menu bar panel is a macOS app, so " +
		"there is nothing to open on this platform"}
}
