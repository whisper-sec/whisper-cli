// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestClientTunnelMTU_TracksTheTunnelItDescribes reads the value out of internal/wgtun
// rather than trusting a second copy of the number.
//
// `whale netcheck` reports the client MTU as a fact about this binary's own tunnel. If
// wgtun's default changes and this constant does not, netcheck would report a number no
// interface on the host is using, which is the quietest kind of wrong. Pinning it to the
// source is cheaper than an exported constant we would have to add to a package this test
// does not own.
func TestClientTunnelMTU_TracksTheTunnelItDescribes(t *testing.T) {
	const src = "../wgtun/device.go"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v (this test is the only thing keeping the two MTU values in step)", src, err)
	}
	m := regexp.MustCompile(`defaultMTU\s*=\s*(\d+)`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("could not find defaultMTU in %s; the pin has drifted and this test is asserting nothing", src)
	}
	got, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("defaultMTU in %s is not a number: %q", src, m[1])
	}
	if got != ClientTunnelMTU {
		t.Fatalf("wgtun's defaultMTU is %d but whale.ClientTunnelMTU is %d; "+
			"`whale netcheck` would report an MTU no interface on this host is using", got, ClientTunnelMTU)
	}
}

// TestTunnelMTUsAreReportedSeparately: the two ends are different numbers, and an earlier
// revision of the plan asserted they were equal. One field for both would bring that
// mistake back.
func TestTunnelMTUsAreReportedSeparately(t *testing.T) {
	m := TunnelMTU()
	if m.Client != ClientTunnelMTU || m.Server != ServerTunnelMTU {
		t.Fatalf("TunnelMTU() = %+v, want {%d %d}", m, ClientTunnelMTU, ServerTunnelMTU)
	}
	if m.Client == m.Server {
		t.Fatal("the client and server tunnel MTUs are equal in this build; they are 1280 and 1340 " +
			"on the real fleet, and reporting one number for both is the defect this pair exists to prevent")
	}
	if m.Client > m.Server {
		t.Fatalf("client MTU %d exceeds server MTU %d; the note claims the smaller governs and ours is the smaller",
			m.Client, m.Server)
	}
}
