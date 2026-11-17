// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Command whisper is the v2 Whisper CLI: a fully scriptable Cobra surface today, and
// a btop/k9s-grade full-screen TUI when run on a
// terminal with no subcommand. Both ride the ONE internal/client package.
//
// Distribution: cross-compiled static binaries (linux/darwin x amd64/arm64),
// published to GitHub Releases and served by cli.whisper.online for
// `curl -fsSL https://cli.whisper.online | sh`.
package main

import (
	"os"

	"github.com/whisper-sec/whisper-cli/internal/cli"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

func main() {
	// `whisper run --enforce` re-executes this binary as the agent's init, inside the agent's namespaces, and
	// `whisper contain` as its probes (whether the kernel tells a cgroup's programs about its sockets, and whether it
	// lets a process place a device in a namespace it holds no capability over). None is a command anyone types, so
	// each is dispatched before the command tree.
	if run := enforce.ReexecEntry(os.Args); run != nil {
		run()
	}
	os.Exit(cli.Execute())
}
