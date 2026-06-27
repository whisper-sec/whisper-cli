// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Command whisper is the v2 Whisper CLI: a fully scriptable Cobra surface today, and
// (added in a later build step) a btop/k9s-grade full-screen TUI when run on a
// terminal with no subcommand. Both ride the ONE internal/client package.
//
// Distribution: cross-compiled (linux/darwin x amd64/arm64), baked into
// whisper-ns-spring.jar behind the Maven `-P cli` profile, and served by
// cli.whisper.online for `curl cli.whisper.online | sh`.
package main

import (
	"os"

	"github.com/whisper-sec/whisper-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
