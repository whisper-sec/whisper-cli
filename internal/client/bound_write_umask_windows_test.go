//go:build windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

// Windows has no umask and no POSIX mode bits; the permission test is a no-op there.
func syscallUmask(mask int) int { return 0 }
