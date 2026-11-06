// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package cli

import (
	"context"
	"os/exec"
	"strconv"
	"time"
)

// lsofTimeout bounds the one lsof call, so a slow host costs a warning, never a hang.
const lsofTimeout = 2 * time.Second

// listenerOwnedBy on macOS asks lsof which processes listen on 127.0.0.1:port. libproc's
// proc_pidfdinfo needs cgo and the release builds are CGO_ENABLED=0, so lsof is the cgo-free
// route. lsof sees only what this user may see: no visible owner is unknown, never a mismatch.
func listenerOwnedBy(port, pid int) (owned, known bool) {
	if port <= 0 || pid <= 0 {
		return false, false
	}
	bin, err := exec.LookPath("lsof")
	if err != nil {
		bin = "/usr/sbin/lsof"
	}
	cx, cancel := context.WithTimeout(context.Background(), lsofTimeout)
	defer cancel()
	out, _ := exec.CommandContext(cx, bin, "-nP", "-iTCP@127.0.0.1:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fp").Output()
	if cx.Err() != nil {
		return false, false
	}
	return ownedFromPIDs(lsofListenPIDs(out), pid)
}
