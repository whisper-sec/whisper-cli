// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import "testing"

func TestDevNamesReadsProcNetDev(t *testing.T) {
	dev := "Inter-|   Receive                            |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes\n" +
		"  wsp0:    1000      10    0    0    0     0          0         0     2000\n" +
		"    lo:       0       0    0    0    0     0          0         0        0\n"
	if got := devNames(dev); got != "lo,wsp0" {
		t.Fatalf("devNames = %q", got)
	}
	if got := devNames(dev + "  eth0: 1 2 3\n"); got == "lo,wsp0" {
		t.Fatal("a namespace with a physical interface is not an enforced one")
	}
}
