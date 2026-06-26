// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Command whisper is the Whisper CLI: a fully scriptable Cobra surface, and a
// btop/k9s-grade full-screen TUI when run on a terminal with no subcommand. Both
// ride the ONE internal/client package.
//
// Install:  curl get.whisper.online | sh   (or `go install
// github.com/whisper-sec/whisper-cli/cmd/whisper@latest`).
package main

import (
	"os"

	"github.com/whisper-sec/whisper-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
