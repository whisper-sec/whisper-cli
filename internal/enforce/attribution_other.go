// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux

package enforce

import (
	"fmt"
	"os"
)

// ProbeArg is the argv[1] that selects the Linux containment's attribution probe; elsewhere it only
// refuses.
const ProbeArg = "__whisper-attribution-probe"

// RunProbe is reached only by hand on this platform, and refuses.
func RunProbe() {
	fmt.Fprintln(os.Stderr, "whisper: contain: the attribution probe is Linux only")
	os.Exit(125)
}

// PlaceProbeArg is the argv[1] that selects the Linux containment's placement probe; elsewhere it only refuses.
const PlaceProbeArg = "__whisper-placement-probe"

// RunPlaceProbe is reached only by hand on this platform, and refuses.
func RunPlaceProbe() {
	fmt.Fprintln(os.Stderr, "whisper: contain: the placement probe is Linux only")
	os.Exit(125)
}
