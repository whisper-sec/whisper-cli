// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"net"
	"net/netip"
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

// punchedRecord is a record as a current holder writes it: a promoted peer carries the epoch of the
// routed period the device was read holding it in.
func punchedRecord(phase string, attempts, cands int, endpoint, source string, promoted bool) wgtun.PathPeerRecord {
	rec := wgtun.PathPeerRecord{
		Address:  "2a04:2a01:4::7",
		Path:     PathDirectPunched,
		Endpoint: endpoint,
		Promoted: promoted,
		Punch: wgtun.PathPunchRecord{
			Phase: phase, Attempts: attempts, Candidates: cands,
			Winner: endpoint, WinnerSource: source, Since: time.Now(),
		},
	}
	if promoted {
		rec.RouteEpoch, rec.RoutedSince = 7, time.Now()
	}
	return rec
}

// TestObservationFor_APromotedRecordWithoutAnEpochIsNotEvidence: an older holder wrote its own decision
// as "promoted" and never read the device back. That is the claim that was caught saying direct-local
// over a relayed round trip, so it may not be rendered as a path, and the sentence says why.
func TestObservationFor_APromotedRecordWithoutAnEpochIsNotEvidence(t *testing.T) {
	rec := punchedRecord(string(wgtun.PunchEstablished), 3, 2, "192.168.122.131:35709", string(wgtun.SourceLocal), true)
	rec.RouteEpoch, rec.RoutedSince = 0, time.Time{}
	obs := ObservationFor(rec, time.Second, false)
	if obs.Direct || PathFor(obs) != PathRelayed {
		t.Fatalf("a promoted record with no epoch was rendered as %q", PathFor(obs))
	}
	if why := ReasonFor(obs); !strings.Contains(why, "older whisper") || !strings.Contains(why, "Restart") {
		t.Fatalf("ReasonFor = %q, want the unverified holder named with the fix", why)
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

// TestReasonFor_AWithdrawnPathRestingSaysWhy: after a withdrawal the tunnel is deliberately silent towards
// the peer. That is neither a punch in flight nor a punch that failed, and reading it as either
// would send the reader after the wrong cause. Nor may it promise the box is carrying the traffic: for
// about half a minute the far end may still route this node directly, and a probe that gets nothing back
// then is that, not a pair split across two boxes.
func TestReasonFor_AWithdrawnPathRestingSaysWhy(t *testing.T) {
	rec := punchedRecord(string(wgtun.PunchResting), 0, 1, "192.168.122.131:35709", "", false)
	rec.Punch.Since = time.Now().Add(-12 * time.Second)
	obs := ObservationFor(rec, time.Second, false)
	if got := PathFor(obs); got != PathRelayed {
		t.Fatalf("path = %q, want %q while the path is withdrawn", got, PathRelayed)
	}
	why := ReasonFor(obs)
	for _, want := range []string{"stopped answering 12s ago", "quiet towards the peer", "the far end lets go",
		"may not get through in either direction", "tried again about a minute after the withdrawal"} {
		if !strings.Contains(why, want) {
			t.Fatalf("ReasonFor = %q, missing %q", why, want)
		}
	}
	for _, wrong := range []string{"punch failed", "being opened", "keeps going through the box"} {
		if strings.Contains(why, wrong) {
			t.Fatalf("ReasonFor = %q says %q of a deliberate silence", why, wrong)
		}
	}
	// A pair punched in the plane's windows is tried again at its next window after the hold, which can be
	// well past a minute: the sentence says that rather than a minute.
	rec.Punch.Timed = true
	timed := ReasonFor(ObservationFor(rec, time.Second, false))
	if !strings.Contains(timed, "in the pair's first window after that") || strings.Contains(timed, "about a minute after the withdrawal") {
		t.Fatalf("a resting timed pair reads %q", timed)
	}
	probed := ReasonFor(obs.WithProbe(true, false))
	if !strings.HasPrefix(probed, "nothing answered. The direct path to this peer stopped answering") ||
		strings.Contains(probed, "two boxes") {
		t.Fatalf("a probe that got nothing back while resting reads %q", probed)
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
	settled := []string{string(wgtun.PunchIdle), string(wgtun.PunchGaveUp), string(wgtun.PunchEstablished),
		string(wgtun.PunchResting), ""}
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
	reads := 0
	tun := &PingTunnel{From: "2a04:2a01:4::9", Read: func() PunchEvidence { reads++; return ev }}
	p := &scriptedProbe{rtt: 2 * time.Millisecond}
	sum := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 2, Interval: time.Microsecond, Tunnel: tun,
	}, p, nil)

	if sum.Path != PathDirectPunched || sum.From != "2a04:2a01:4::9" {
		t.Fatalf("path = %q from %q, want the device's own verdict %q from the tunnel's /128", sum.Path, sum.From, PathDirectPunched)
	}
	if reads != 3 {
		t.Fatalf("the record was read %d times, want once before and once after each of 2 answers", reads)
	}
	for _, a := range sum.Attempts {
		if a.Path != PathDirectPunched {
			t.Fatalf("attempt %d path = %q, want it placed on the direct path", a.Seq, a.Path)
		}
	}
	if !strings.Contains(sum.Why, "direct via 203.0.113.7:41234") {
		t.Fatalf("why = %q, want the endpoint that carried it", sum.Why)
	}
	if !strings.Contains(sum.Note, "did not go through a box") {
		t.Fatalf("note = %q, want it to stop claiming every round trip is relayed", sum.Note)
	}
}

// TestPing_FromTheHostsOwnAddressIsAnEdgeAnswerNeverAPath is. On two LAN nodes the ping dialled from
// the host's own stack, the box delivered it, and the summary printed the tunnel's direct-local. A run
// with no tunnel reads no record, so it can never be direct; and it is not `relayed` either, because the
// box nearest the host answers for an agent address itself, so the answer says nothing about the path
// between two nodes. The sentence names the address it left from.
func TestPing_FromTheHostsOwnAddressIsAnEdgeAnswerNeverAPath(t *testing.T) {
	src := netip.MustParseAddr("fd42:7723:aa:0:5054:ff:fe85:c62c")
	sum := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 3, Interval: time.Microsecond, HostSource: src,
	}, &scriptedProbe{rtt: 25 * time.Millisecond}, nil)
	if sum.Path != PathEdge || sum.From != "" {
		t.Fatalf("a probe from the host's own address reported path %q from %q", sum.Path, sum.From)
	}
	for _, a := range sum.Attempts {
		if a.Path != PathEdge {
			t.Fatalf("attempt %d path = %q, want edge", a.Seq, a.Path)
		}
	}
	if !strings.Contains(sum.Why, src.String()) || !strings.Contains(sum.Why, "outside any Whisper tunnel") {
		t.Fatalf("why = %q, want the source named and the vantage said", sum.Why)
	}
	if strings.Contains(sum.Note, "did not go through a box") || !strings.Contains(sum.Note, "neither that the node is up") {
		t.Fatalf("note = %q, want the edge note and no direct claim", sum.Note)
	}
	// From an agent address: a tunnel this CLI does not hold carried it, and nothing is claimed.
	agent := netip.MustParseAddr("2a04:2a01:9::50")
	sum = Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 1, Interval: time.Microsecond, HostSource: agent,
	}, &scriptedProbe{rtt: 25 * time.Millisecond}, nil)
	if sum.Path != PathEdge || !strings.Contains(sum.Why, "a tunnel this CLI does not hold") {
		t.Fatalf("a probe from an agent address this CLI does not hold: path %q why %q", sum.Path, sum.Why)
	}
	// Silence from the host's own address is no path, and the sentence still says where it left from.
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	sum = Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 1, Interval: time.Microsecond, HostSource: src,
	}, &scriptedProbe{steps: []error{timeout}}, nil)
	if sum.Path != PathNoPath || !strings.Contains(sum.Why, src.String()) {
		t.Fatalf("a silent probe from the host's own address: path %q why %q", sum.Path, sum.Why)
	}
}

// TestPing_AProbeThatKnowsItsOutcomeIsTakenAtItsWord: the tunnel probe reports a local failure to reach
// its proxy as could-not-send and a SOCKS failure other than a refusal as no reply. Neither is an answer,
// whatever the text of the error says.
func TestPing_AProbeThatKnowsItsOutcomeIsTakenAtItsWord(t *testing.T) {
	sum := run(t, []error{
		&OutcomeError{Outcome: OutcomeNoRoute, Detail: "this host's tunnel did not take the probe: connection refused"},
		&OutcomeError{Outcome: OutcomeNoReply, Detail: "the tunnel reported the address unreachable"},
	}, 2)
	if sum.Answered != 0 || sum.Attempts[0].Outcome != OutcomeNoRoute || sum.Attempts[1].Outcome != OutcomeNoReply {
		t.Fatalf("attempts = %+v, want could-not-send then no reply, and no answers", sum.Attempts)
	}
	if !strings.Contains(sum.Note, "did not take the probe") {
		t.Fatalf("note = %q, want the local reason said", sum.Note)
	}
}

// TestPing_ARouteThatMovesMidRunIsRelayed: the record names one routed period before the run and
// another (or none) after an answer. That answer cannot be placed on the direct path, so neither it
// nor the run is called direct, and the reason says the route moved.
func TestPing_ARouteThatMovesMidRunIsRelayed(t *testing.T) {
	before := EvidenceFor(punchedRecord(string(wgtun.PunchEstablished), 1, 1, "192.168.122.131:35709", string(wgtun.SourceLocal), true), time.Second, false)
	before.Instance = "tunnel-one"
	reread := before
	reread.Epoch++ // demoted and promoted again in between
	unrouted := before
	unrouted.Direct, unrouted.Epoch = false, 0
	renewed := before
	renewed.Instance = "tunnel-two" // a renewal in the same process, whose count happens to meet the old one
	for name, after := range map[string]PunchEvidence{"re-routed": reread, "withdrawn": unrouted, "record gone": {},
		"another tunnel at the same epoch": renewed} {
		n := 0
		tun := &PingTunnel{From: "2a04:2a01:4::9", Read: func() PunchEvidence {
			n++
			if n <= 2 { // before the run, and after the first answer
				return before
			}
			return after
		}}
		sum := Ping(context.Background(), pingAddr, PingOptions{
			Address: pingAddr.String(), Count: 3, Interval: time.Microsecond, Tunnel: tun,
		}, &scriptedProbe{rtt: time.Millisecond}, nil)
		if sum.Path != PathRelayed {
			t.Fatalf("%s: path = %q, want relayed when the route moved mid-run", name, sum.Path)
		}
		if sum.Attempts[0].Path != PathDirectPunched || sum.Attempts[1].Path != PathRelayed {
			t.Fatalf("%s: attempts = %+v, want the first direct and the second not", name, sum.Attempts)
		}
		if !strings.Contains(sum.Why, "changed while the probe ran") {
			t.Fatalf("%s: why = %q", name, sum.Why)
		}
	}
}

// TestPing_ATunnelWithoutAnEpochNeverMakesADirectClaim: an older holder's record says promoted with no
// epoch. A probe through it is relayed, with the older holder named.
func TestPing_ATunnelWithoutAnEpochNeverMakesADirectClaim(t *testing.T) {
	rec := punchedRecord(string(wgtun.PunchEstablished), 1, 1, "192.168.122.131:35709", string(wgtun.SourceLocal), true)
	rec.RouteEpoch = 0
	ev := EvidenceFor(rec, time.Second, false)
	sum := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 2, Interval: time.Microsecond,
		Tunnel: &PingTunnel{From: "2a04:2a01:4::9", Read: func() PunchEvidence { return ev }},
	}, &scriptedProbe{rtt: time.Millisecond}, nil)
	if sum.Path != PathRelayed || !strings.Contains(sum.Why, "older whisper") {
		t.Fatalf("path %q why %q, want relayed and the older holder named", sum.Path, sum.Why)
	}
}

// TestPing_SilenceOverARoutedDirectPathNamesTheCausesThatFit: through the tunnel, with the peer routed
// direct before the run, nothing answering is not "a pair split across two boxes": the box is not in
// the path. It is a far node that does not route this one directly yet, or a path that just died.
func TestPing_SilenceOverARoutedDirectPathNamesTheCausesThatFit(t *testing.T) {
	ev := EvidenceFor(punchedRecord(string(wgtun.PunchEstablished), 1, 1, "192.168.122.58:40013", string(wgtun.SourceLocal), true), time.Second, false)
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	sum := Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 2, Interval: time.Microsecond,
		Tunnel: &PingTunnel{From: "2a04:2a01:4::9", Read: func() PunchEvidence { return ev }},
	}, &scriptedProbe{steps: []error{timeout, timeout}}, nil)
	if sum.Path != PathNoPath || !strings.Contains(sum.Why, "on one side only") || !strings.Contains(sum.Why, "just died") {
		t.Fatalf("path %q why %q", sum.Path, sum.Why)
	}
}

// TestPing_AHostWithNoIPv6RouteSaysSo: no source address and nothing sent is a local fact, said as one.
func TestPing_AHostWithNoIPv6RouteSaysSo(t *testing.T) {
	sum := Ping(context.Background(), pingAddr, PingOptions{Address: pingAddr.String(), Count: 1, Interval: time.Microsecond},
		&scriptedProbe{steps: []error{&OutcomeError{Outcome: OutcomeNoRoute, Detail: "network is unreachable"}}}, nil)
	if !strings.Contains(sum.Why, "no IPv6 route") {
		t.Fatalf("why = %q", sum.Why)
	}
}
