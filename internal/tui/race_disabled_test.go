// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !race

package tui

// raceEnabled is false in a plain build: wall-clock budgets are asserted (see).
const raceEnabled = false
