// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import "testing"

// makeFIFO: Windows has no named pipes in the file system to stand in for one.
func makeFIFO(*testing.T, string) string { return "" }
