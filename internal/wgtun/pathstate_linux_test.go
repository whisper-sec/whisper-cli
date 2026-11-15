// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"os"
	"runtime/debug"
	"testing"
)

// openFDs is how many descriptors this process holds now.
func openFDs(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(e)
}

// A liveness probe gives back the pidfd it opens. os.FindProcess holds one on Linux until
// Release, and ReadPathStates asks about every record's holder, so a loop of reads (a route
// oracle samples every millisecond) ran the test binary out of descriptors before the garbage
// collector closed them. The collector is held off here, so a probe that keeps its descriptor
// shows up as one descriptor per call.
func TestALivenessProbeKeepsNoDescriptor(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	const probes = 500
	before := openFDs(t)
	for i := 0; i < probes; i++ {
		if !processIsAlive(os.Getpid()) {
			t.Fatal("this process reads as not alive")
		}
	}
	if grew := openFDs(t) - before; grew > probes/10 {
		t.Fatalf("%d liveness probes left %d descriptors open: each keeps its pidfd", probes, grew)
	}
}
