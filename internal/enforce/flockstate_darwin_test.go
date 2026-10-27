// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package enforce

import "testing"

// withoutKernelLockTable is the only path there is on darwin.
func withoutKernelLockTable(t *testing.T) { t.Helper() }
