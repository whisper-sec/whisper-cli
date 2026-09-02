//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "golang.org/x/sys/unix"

func syscallUmask(mask int) int { return unix.Umask(mask) }
