// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build race

package tui

// raceEnabled reports whether this test binary carries the race detector. Race
// instrumentation slows pure-CPU code ~5-15x, so any wall-clock micro-budget measured
// under it reflects the instrumentation, not the code - the budget assertions skip.
const raceEnabled = true
