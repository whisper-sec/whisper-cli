// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Run starts the full-screen TUI with the given options and blocks until the user
// quits. It uses the alt-screen + mouse cell-motion (so the dashboard owns the screen
// and click/scroll work); on exit it restores the terminal. A start error is returned
// to the caller (cmd/whisper) to render cleanly — never a panic onto the terminal.
func Run(opts Options) error {
	app := New(opts)
	prog := tea.NewProgram(
		app,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := prog.Run()
	return err
}
