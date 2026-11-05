// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux && !windows

package cli

import "runtime"

func runEnforced(agent, agentFile, tier, flagUser, name string, childArgs []string) error {
	return enforceUnsupported(runtime.GOOS)
}
