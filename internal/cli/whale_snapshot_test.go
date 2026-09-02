// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// TestFleetZone_TakesTheZoneTheFleetActuallyShares. The zone to date is the apex the SOA
// and the signing live at, which is the parent of the tenant label, not the tenant subtree
// and not the agent's own name. Getting this wrong would date a zone that has no SOA of its
// own and report every node as undatable, which reads as a fault in the fleet.
func TestFleetZone_TakesTheZoneTheFleetActuallyShares(t *testing.T) {
	peers := []whalePeer{
		{Name: "a", FQDN: "a141a459a.tED67D6.agents.whisper.online."},
		{Name: "b", FQDN: "b2b2b2b2b.tED67D6.agents.whisper.online"},
	}
	if got := fleetZone(peers); got != "agents.whisper.online" {
		t.Fatalf("fleetZone = %q, want the apex agents.whisper.online", got)
	}
}

// TestFleetZone_ABYODFleetLandsOnTheCustomersOwnDomain: a hosted identity is not the only
// kind. The rule is structural, not a hardcoded suffix, so a fleet under a customer domain
// gets its own zone dated rather than nothing.
func TestFleetZone_ABYODFleetLandsOnTheCustomersOwnDomain(t *testing.T) {
	peers := []whalePeer{
		{Name: "a", FQDN: "db-01.acme.example.com."},
		{Name: "b", FQDN: "db-02.acme.example.com."},
	}
	if got := fleetZone(peers); got != "example.com" {
		t.Fatalf("fleetZone = %q, want example.com", got)
	}
}

// TestFleetZone_AMixedFleetYieldsNothing. THE reason this returns a zone rather than a
// guess: dating one zone when half the fleet lives in another would put a confident,
// irrelevant sentence on the screen. Saying nothing is the honest answer.
func TestFleetZone_AMixedFleetYieldsNothing(t *testing.T) {
	peers := []whalePeer{
		{Name: "a", FQDN: "a.t1.agents.whisper.online."},
		{Name: "b", FQDN: "db-02.acme.example.com."},
	}
	if got := fleetZone(peers); got != "" {
		t.Fatalf("a mixed fleet must yield no zone, got %q", got)
	}
	if got := fleetZone(nil); got != "" {
		t.Fatalf("no peers must yield no zone, got %q", got)
	}
	// A peer with no name in DNS contributes nothing rather than breaking the read.
	if got := fleetZone([]whalePeer{{Name: "a"}, {Name: "b", FQDN: "x.t1.agents.whisper.online"}}); got != "agents.whisper.online" {
		t.Fatalf("a nameless peer must not veto the zone, got %q", got)
	}
}

// TestWhaleStatus_RendersTheSnapshotLine. THE anti-unreachable gate. A SnapshotAge that
// nothing renders is the defect this repo ships most often, so this drives the real
// renderer and asserts the sentence reached the screen. Remove the block from
// renderWhaleStatus and this fails.
func TestWhaleStatus_RendersTheSnapshotLine(t *testing.T) {
	whaleTestIsolation(t)
	now := time.Unix(1_788_239_069, 0)
	ages := []whale.SnapshotAge{
		whale.AgeOf("ns1.whisper.online", uint32(now.Unix()-120), now),
		whale.AgeOf("ns2.whisper.online", uint32(now.Unix()-120), now),
	}
	view := whaleStatusView{
		Self:         whaleSelf{Host: "h", Address: "2a04:2a01:1::1", Connection: "connected"},
		PathNote:     whale.PathNote(),
		Snapshot:     ages,
		SnapshotNote: whale.SnapshotNote("agents.whisper.online", ages),
	}
	// whaleNote writes to stderr, the same channel the path footnote uses.
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	for _, want := range []string{"agents.whisper.online snapshot age", "ns1.whisper.online 2m", "ns2.whisper.online 2m"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("the snapshot line must carry %q:\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
		}
	}
}

// TestWhaleStatus_TheDivergenceWarningReachesTheScreen: the agreeing case is the one that
// prints all day, so a test that only covered it would pass on a renderer that dropped the
// warning. This is the state the line exists for and it must be impossible to miss.
func TestWhaleStatus_TheDivergenceWarningReachesTheScreen(t *testing.T) {
	whaleTestIsolation(t)
	now := time.Unix(1_788_239_069, 0)
	ages := []whale.SnapshotAge{
		whale.AgeOf("ns1.whisper.online", uint32(now.Unix()-60), now),
		whale.AgeOf("ns2.whisper.online", uint32(now.Unix()-400_000), now),
	}
	view := whaleStatusView{
		Self:         whaleSelf{Host: "h", Connection: "not connected"},
		PathNote:     whale.PathNote(),
		Snapshot:     ages,
		SnapshotNote: whale.SnapshotNote("agents.whisper.online", ages),
	}
	_, stderr := captureStd(t, func() { renderWhaleStatus(view, true, false, false) })
	if !strings.Contains(stderr, "THE NODES DISAGREE") {
		t.Fatalf("a divergent pair must be warned about on screen:\n%s", stderr)
	}
	if !strings.Contains(stderr, "may still be admitted") {
		t.Fatalf("the consequence must reach the screen, not just the fact:\n%s", stderr)
	}
}

// TestWhaleStatus_NoSnapshotPrintsNoLine: the control. A run that could read nothing must
// not leave an empty or half-formed footnote behind, and it must not warn about a fleet it
// never measured.
func TestWhaleStatus_NoSnapshotPrintsNoLine(t *testing.T) {
	whaleTestIsolation(t)
	view := whaleStatusView{
		Self:     whaleSelf{Host: "h", Connection: "not connected"},
		PathNote: whale.PathNote(),
	}
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, false, false) })
	if strings.Contains(stdout+stderr, "snapshot age") {
		t.Fatalf("nothing was read, so no snapshot line may be printed:\n%s\n%s", stdout, stderr)
	}
}

// TestReadZoneSnapshot_AnEmptyZoneIsNotAQuery: the guard in front of the network. `whale
// status` runs constantly, and a node with no name in DNS must cost zero DNS traffic
// rather than a lookup for the empty name.
func TestReadZoneSnapshot_AnEmptyZoneIsNotAQuery(t *testing.T) {
	if got := readZoneSnapshot(t.Context(), "", time.Now()); got != nil {
		t.Fatalf("an empty zone must read nothing, got %+v", got)
	}
	if got := readZoneSnapshot(t.Context(), "   ", time.Now()); got != nil {
		t.Fatalf("a blank zone must read nothing, got %+v", got)
	}
}
