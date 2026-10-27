// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package enforce

// exclusiveFlockHeld has no kernel lock table to read here; the holder file's pid decides.
func exclusiveFlockHeld(int, string) (held, known bool) { return false, false }
