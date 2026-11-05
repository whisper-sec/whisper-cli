// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"fmt"
	"os"
)

// InitArg is the argv[1] that selects the Linux init's entry point. Windows has no init: the
// agent is started directly under its own token (run_windows.go), so this only refuses.
const InitArg = "__whisper-enforce-init"

// RunInit is reached only by hand on Windows, and refuses.
func RunInit() {
	fmt.Fprintln(os.Stderr, "whisper: enforce: the init entry point is Linux only")
	os.Exit(125)
}
