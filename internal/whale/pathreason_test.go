// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// pathreason_test.go pins the sentence beside the PATH cell.
//
// The property under test is not the prose. It is that the four ways a peer can end up relayed
// are four DIFFERENT sentences, because collapsing them is what turns a diagnosable problem into
// a shrug: "no endpoint was offered", "the traversal is still running", "the traversal ran and
// failed", and "nothing on this host has anything to say" have four different next steps.

func punchedRecord(phase string, attempts, cands int, endpoint, source string, promoted bool) wgtun.PathPeerRecord {
	return wgtun.PathPeerRecord{
		Address:  "2a04:2a01:4::7",
		Path:     PathDirectPunched,
		Endpoint: endpoint,
		Promoted: promoted,
		Punch: wgtun.PathPunchRecord{
			Phase: phase, Attempts: attempts, Candidates: cands,
			Winner: endpoint, WinnerSource: source, Since: time.Now(),
		},
	}
}

func TestReasonFor_RelayedBecauseThePunchFailedIsAFindingNotAnAbsence(t *testing.T) {
	obs := ObservationFor(punchedRecord(string(wgtun.PunchGaveUp), 12, 2, "203.0.113.7:41234", "observed", false), time.Second, false)
	if got := PathFor(obs); got != PathRelayed {
		t.Fatalf("path = %q, want %q - nothing established a direct path", got, PathRelayed)
	}
	why := ReasonFor(obs)
	for _, want := range []string{"punch failed", "12 attempts", "2 endpoints", "tried again"} {
		if !strings.Contains(why, want) {
			t.Fatalf("ReasonFor = %q, missing %q", why, want)
		}
	}
}

func TestReasonFor_AnInFlightTraversalSaysTrafficIsUnaffected(t *testing.T) {
	obs := ObservationFor(punchedRecord(string(wgtun.PunchTrying), 3, 2, "203.0.113.7:41234", "", false), time.Second, false)
	why := ReasonFor(obs)
	for _, want := range []string{"being opened", "3 attempts", "Traffic is unaffected", "203.0.113.7:41234"} {
		if !strings.Contains(why, want) {
			t.Fatalf("ReasonFor = %q, missing %q", why, want)
		}
	}
}

func TestReasonFor_NoEndpointOfferedIsNotAFailedPunch(t *testing.T) {
	rec := wgtun.PathPeerRecord{Address: "2a04:2a01:4::7", Path: PathRelayed,
		Punch: wgtun.PathPunchRecord{Phase: string(wgtun.PunchIdle)}}
	why := ReasonFor(ObservationFor(rec, time.Second, false))
	if !strings.Contains(why, "no endpoint was offered") {
		t.Fatalf("ReasonFor = %q, want the idle case named as its own thing", why)
	}
	if strings.Contains(why, "failed") {
		t.Fatalf("a peer nothing was ever tried for was reported as a failure: %q", why)
	}
}

func TestReasonFor_AnEstablishedPathNamesTheEndpointAndWhyItWorked(t *testing.T) {
	obs := ObservationFor(punchedRecord(string(wgtun.PunchEstablished), 3, 2, "203.0.113.7:41234", string(wgtun.SourceObserved), true), time.Second, false)
	if got := PathFor(obs); got != PathDirectPunched {
		t.Fatalf("path = %q, want %q", got, PathDirectPunched)
	}
	why := ReasonFor(obs)
	for _, want := range []string{"direct via 203.0.113.7:41234", "a Whisper box saw it arrive from", "3 attempts", "fallback"} {
		if !strings.Contains(why, want) {
			t.Fatalf("ReasonFor = %q, missing %q", why, want)
		}
	}
}

func TestReasonFor_NothingPublishedIsSaidPlainly(t *testing.T) {
	why := ReasonFor(Observation{})
	if !strings.Contains(why, "no tunnel on this host has published") {
		t.Fatalf("ReasonFor = %q, want the unpublished case named rather than implied", why)
	}
	if strings.Contains(why, "failed") {
		t.Fatalf("an absent record was reported as a failure: %q", why)
	}
}

// TestObservationFor_AStaleRecordCannotCarryADirectClaim: a live holder that stopped updating
// is a fault. Its last known "direct" is not evidence of anything now, and the sentence has to
// say how old the reading is rather than presenting it as current.
func TestObservationFor_AStaleRecordCannotCarryADirectClaim(t *testing.T) {
	rec := punchedRecord(string(wgtun.PunchEstablished), 3, 2, "203.0.113.7:41234", "observed", true)
	obs := ObservationFor(rec, 12*time.Minute, true)
	if obs.Direct {
		t.Fatal("a stale record carried a direct claim")
	}
	if got := PathFor(obs); got != PathRelayed {
		t.Fatalf("path = %q, want %q", got, PathRelayed)
	}
	if why := ReasonFor(obs); !strings.Contains(why, "12m old") {
		t.Fatalf("ReasonFor = %q, want the age said out loud", why)
	}
}

// TestWithProbe_AMeasuredSilenceRetractsTheDirectClaim: the device can be routing a /128 to a
// peer that has just stopped answering - that is the window the demote closes. Printing
// direct-punch beside a peer this command could not reach would be the surface lying on the
// device's behalf for those few seconds.
func TestWithProbe_AMeasuredSilenceRetractsTheDirectClaim(t *testing.T) {
	obs := ObservationFor(punchedRecord(string(wgtun.PunchEstablished), 3, 1, "203.0.113.7:41234", "observed", true), time.Second, false)
	if got := PathFor(obs.WithProbe(true, false)); got != PathNoPath {
		t.Fatalf("path = %q, want %q after a probe that got nothing back", got, PathNoPath)
	}
	// An answered probe leaves it alone, and so does not probing at all.
	if got := PathFor(obs.WithProbe(true, true)); got != PathDirectPunched {
		t.Fatalf("path = %q, want the direct claim to survive an answered probe", got)
	}
	if got := PathFor(obs.WithProbe(false, false)); got != PathDirectPunched {
		t.Fatalf("path = %q: not probing is not evidence, so it must not retract anything", got)
	}
}

func TestPunchEvidence_InFlightIsTheOnlyStateWorthWaitingFor(t *testing.T) {
	settled := []string{string(wgtun.PunchIdle), string(wgtun.PunchGaveUp), string(wgtun.PunchEstablished), ""}
	for _, phase := range settled {
		if (PunchEvidence{Found: true, Phase: phase}).InFlight() {
			t.Fatalf("phase %q reported as in flight, so --until-direct would wait on a settled answer", phase)
		}
	}
	if !(PunchEvidence{Found: true, Phase: string(wgtun.PunchTrying)}).InFlight() {
		t.Fatal("a running traversal is not reported as in flight, so --until-direct would never wait")
	}
	if (PunchEvidence{Phase: string(wgtun.PunchTrying)}).InFlight() {
		t.Fatal("evidence that was never found reported as in flight")
	}
}

// TestPing_CarriesTheEvidenceIntoThePathAndTheReason: the measurement and the published record
// have to end up in ONE observation. Before this, a --probe run rebuilt the path from the probe
// alone, so a peer the device had proved direct printed as relayed because nothing happened to
// be listening on the port that was probed.
func TestPing_CarriesTheEvidenceIntoThePathAndTheReason(t *testing.T) {
	ev := EvidenceFor(punchedRecord(string(wgtun.PunchEstablished), 3, 2,
		"203.0.113.7:41234", string(wgtun.SourceObserved), true), time.Second, false)
	p := &scriptedProbe{rtt: 2 * time.Millisecond}
	sum := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 1, Interval: time.Microsecond, Evidence: ev,
	}, p, nil)

	if sum.Path != PathDirectPunched {
		t.Fatalf("path = %q, want the device's own verdict %q", sum.Path, PathDirectPunched)
	}
	if !strings.Contains(sum.Why, "direct via 203.0.113.7:41234") {
		t.Fatalf("why = %q, want the endpoint that carried it", sum.Why)
	}
	if !strings.Contains(sum.Note, "did not go through a box") {
		t.Fatalf("note = %q, want it to stop claiming every round trip is relayed", sum.Note)
	}
	// And the control plane's offer is only used when this host published nothing of its own.
	sum2 := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 1, Interval: time.Microsecond, DirectClass: PathDirectLocal,
	}, &scriptedProbe{rtt: time.Millisecond}, nil)
	if sum2.Path != PathDirectLocal {
		t.Fatalf("path = %q, want the control plane class as the fallback", sum2.Path)
	}
}
