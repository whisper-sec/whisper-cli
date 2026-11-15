// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"os"
	"runtime/debug"
	"testing"
)

// The serve-state liveness probe gives back the pidfd os.FindProcess holds on Linux until
// Release. The collector is held off, so a probe that keeps its descriptor shows up as one
// descriptor per call.
func TestAServeStateProbeKeepsNoDescriptor(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	count := func() int {
		e, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatalf("read /proc/self/fd: %v", err)
		}
		return len(e)
	}
	const probes = 500
	before := count()
	for i := 0; i < probes; i++ {
		if !processAlive(os.Getpid()) {
			t.Fatal("this process reads as not alive")
		}
	}
	if grew := count() - before; grew > probes/10 {
		t.Fatalf("%d liveness probes left %d descriptors open: each keeps its pidfd", probes, grew)
	}
}
