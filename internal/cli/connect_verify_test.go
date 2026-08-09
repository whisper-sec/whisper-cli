// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

// TestClassifyEgress exercises the pure egress-verify decision: v6 pins the /128, v4-via-NAT64
// passes iff provably tunnelled (proxied source differs from the host's direct source, or the host has
// no direct path), and a genuine leak (proxied == direct) fails closed.
func TestClassifyEgress(t *testing.T) {
	const v6 = "2a04:2a01:0:1::1"
	const v6other = "2a04:2a01:dead:beef:0:0:0:1"
	const edgeSnat = "203.0.113.7" // Whisper's shared v4 SNAT for v4 destinations
	const hostDirect = "198.51.100.10"

	cases := []struct {
		name           string
		observed, want string
		direct         string
		haveDirect     bool
		expect         egressVerdictKind
	}{
		{"v6 pinned exact", v6, v6, "", false, egressPinned},
		{"v6 pinned adopt (no wantAddr)", v6, "", "", false, egressPinned},
		{"v6 but wrong /128", v6, v6other, "", false, egressMismatch},
		{"v4 SNAT differs from direct -> tunnelled", edgeSnat, v6, hostDirect, true, egressTunnelled},
		{"v4 SNAT, no direct path -> tunnelled", edgeSnat, v6, "", false, egressTunnelled},
		{"v4 observed == direct -> leak, fail closed", hostDirect, v6, hostDirect, true, egressNotThroughWhisper},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyEgress(c.observed, c.want, c.direct, c.haveDirect).kind
			if got != c.expect {
				t.Fatalf("classifyEgress(%q,%q,%q,%v) = %v, want %v",
					c.observed, c.want, c.direct, c.haveDirect, got, c.expect)
			}
		})
	}
}
