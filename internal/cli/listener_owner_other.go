// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux && !darwin && !windows

package cli

// listenerOwnedBy has no reader on this platform: unknown, the warning path.
func listenerOwnedBy(int, int) (owned, known bool) { return false, false }
