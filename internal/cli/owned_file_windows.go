// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

// ownedRegularFile has no uid to compare on Windows, where there is no sudo invoker whose
// key a bind could borrow; the elevated shell's own ladder already reads the administrator's.
func ownedRegularFile(string, int) bool { return false }
