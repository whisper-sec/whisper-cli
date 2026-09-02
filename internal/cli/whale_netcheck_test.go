// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_netcheck_test.go covers the rendering half. The measurement half is tested in
// internal/whale with a fake prober; what is asserted here is that the report reaches a
// reader without losing the parts that stop it being misread.

func netcheckFixture() whale.NetcheckReport {
	return whale.NetcheckReport{
		IPv6: false, IPv4: true, UDP: true,
		Anchor: "ns2.example", AnchorMs: 33.2,
		MTU:      whale.TunnelMTU(),
		MTUNote:  whale.MTUNote(),
		PathNote: whale.PathNote(),
		JoinNote: "A v4-only host can still join.",
		Boxes: []whale.BoxReport{{
			Host: "ns1.example",
			IPv6: whale.FamilyProbe{Family: "ipv6", Addr: "2001:db8::1", Present: true,
				Note: "no ipv6 path to 2001:db8::1: timed out"},
			IPv4: whale.FamilyProbe{Family: "ipv4", Addr: "198.51.100.1", Present: true,
				DNSUDP: true, DNSMs: 34.5, TCP443: true, TCPMs: 33.9},
		}},
		Warnings: []string{"could not resolve ns3.example: no such host"},
	}
}

// TestRenderNetcheck_ReportsBothMTUsSeparately: one number for both ends is the exact
// mistake this pair exists to prevent.
func TestRenderNetcheck_ReportsBothMTUsSeparately(t *testing.T) {
	stdout, stderr := captureStd(t, func() { renderNetcheck(netcheckFixture()) })
	if !strings.Contains(stdout, "mtu client") || !strings.Contains(stdout, "mtu server") {
		t.Fatalf("the two MTUs are not reported separately:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1280") || !strings.Contains(stdout, "1340") {
		t.Fatalf("the MTU values are missing:\n%s", stdout)
	}
	if !strings.Contains(stderr, "tunnel interface on the other end") {
		t.Fatalf("the note does not say which end each number describes:\n%s", stderr)
	}
}

// TestRenderNetcheck_AFailedLegRendersAsNoWithItsReason: a blank cell reads as "not
// applicable" when it means "it failed".
func TestRenderNetcheck_AFailedLegRendersAsNoWithItsReason(t *testing.T) {
	stdout, _ := captureStd(t, func() { renderNetcheck(netcheckFixture()) })
	if !strings.Contains(stdout, "no") {
		t.Fatalf("a failed leg did not render as a plain no:\n%s", stdout)
	}
	if !strings.Contains(stdout, "timed out") {
		t.Fatalf("the reason a leg failed was dropped:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ipv6") || !strings.Contains(stdout, "ipv4") {
		t.Fatalf("the per-family breakdown is missing, which is the whole point:\n%s", stdout)
	}
}

// TestRenderNetcheck_WarningsReachTheReader: a box we could not even resolve must not
// vanish between the report and the screen.
func TestRenderNetcheck_WarningsReachTheReader(t *testing.T) {
	_, stderr := captureStd(t, func() { renderNetcheck(netcheckFixture()) })
	if !strings.Contains(stderr, "could not resolve ns3.example") {
		t.Fatalf("a warning never reached the reader:\n%s", stderr)
	}
}

// TestRenderNetcheck_NeverImpliesADirectPathExists. netcheck measures reachability to the
// boxes; nothing in it is evidence about a path between two agents.
func TestRenderNetcheck_NeverImpliesADirectPathExists(t *testing.T) {
	stdout, stderr := captureStd(t, func() { renderNetcheck(netcheckFixture()) })
	out := stdout + stderr
	if !strings.Contains(out, whale.PathRelayed) {
		t.Fatalf("the report does not state that east-west is relayed:\n%s", out)
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "direct path exists") || strings.Contains(lower, "peer-to-peer available") {
		t.Fatalf("the report implies a direct path:\n%s", out)
	}
}

// TestRenderNetcheck_AnchorIsNamedOrItsAbsenceIs.
func TestRenderNetcheck_AnchorIsNamedOrItsAbsenceIs(t *testing.T) {
	stdout, _ := captureStd(t, func() { renderNetcheck(netcheckFixture()) })
	if !strings.Contains(stdout, "anchor box") || !strings.Contains(stdout, "ns2.example") {
		t.Fatalf("the anchor box was not named:\n%s", stdout)
	}
	dark := netcheckFixture()
	dark.Anchor, dark.AnchorMs = "", 0
	stdout2, _ := captureStd(t, func() { renderNetcheck(dark) })
	if !strings.Contains(stdout2, "none answered") {
		t.Fatalf("a report with no anchor left the cell blank instead of saying so:\n%s", stdout2)
	}
}

// TestProbeCell_NeverBlank.
func TestProbeCell_NeverBlank(t *testing.T) {
	if got := probeCell(false, 0); got != "no" {
		t.Fatalf("probeCell(false) = %q, want a plain no", got)
	}
	if got := probeCell(true, 12.34); got != "12.3 ms" {
		t.Fatalf("probeCell(true, 12.34) = %q", got)
	}
}
