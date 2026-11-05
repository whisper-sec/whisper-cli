// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux && !windows

package enforce

import (
	"fmt"
	"os"
)

// InitArg is the argv[1] that selects init's entry point; on this platform it only refuses.
const InitArg = "__whisper-enforce-init"

// InsideEnforced is false wherever there are no network namespaces.
func InsideEnforced() bool { return false }

// RunInit is reached only by hand on this platform, and refuses.
func RunInit() {
	fmt.Fprintln(os.Stderr, "whisper: enforce: network namespaces are Linux only")
	os.Exit(125)
}
