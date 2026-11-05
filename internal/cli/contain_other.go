// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux

package cli

import "runtime"

func runContain(pid int, agent, agentFile string) error { return containUnsupported(runtime.GOOS) }

func runContainRelease(pid int) error { return containUnsupported(runtime.GOOS) }
