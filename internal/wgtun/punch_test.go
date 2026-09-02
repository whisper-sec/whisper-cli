// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"strings"
	"testing"
	"time"
)

// punch_test.go covers the traversal machinery without a device: the candidate list, the
// schedule, and the one document a punch writes. The parts that need real packets - promotion
// on a real handshake, and the invariant that a failed punch never costs reachability - are in
// whale_punch_test.go against two real wireguard-go devices.

// ==========================================================================================
// Candidates. A candidate list is a list of places this node will emit UDP at, so the rules
// about what may be in it are a security property, not a tidiness one.
// ==========================================================================================

func TestParseCandidates_OrdersByEvidenceAndCheapness(t *testing.T) {
	got, err := ParseCandidates([]Candidate{
		{Endpoint: "203.0.113.7:41234", Source: SourceObserved},
		{Endpoint: "198.51.100.9:51820", Source: SourcePublic},
		{Endpoint: "192.168.1.5:51820", Source: SourceLocal},
		{Endpoint: "203.0.113.7:9999", Source: SourceRoamed},
	})
	if err != nil {
		t.Fatalf("a well-formed candidate list was refused: %v", err)
	}
	want := []CandidateSource{SourceRoamed, SourceLocal, SourcePublic, SourceObserved}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Source != want[i] {
			t.Fatalf("candidate %d is %q, want %q (order: %+v)", i, got[i].Source, want[i], got)
		}
	}
}

func TestParseCandidates_CollapsesADuplicateOntoItsStrongerSource(t *testing.T) {
	// The observed endpoint and the declared public one are routinely the same string. Punching
	// the same place twice in a train wastes a round out of twelve, and the report should name
	// the better evidence for it.
	got, err := ParseCandidates([]Candidate{
		{Endpoint: "203.0.113.7:51820", Source: SourceObserved},
		{Endpoint: "203.0.113.7:51820", Source: SourcePublic},
	})
	if err != nil {
		t.Fatalf("ParseCandidates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("a duplicate endpoint was kept twice: %+v", got)
	}
	if got[0].Source != SourcePublic {
		t.Fatalf("the duplicate kept the weaker source %q", got[0].Source)
	}
}

func TestParseCandidates_DropsEveryEndpointWeMustNeverAimAt(t *testing.T) {
	// Same list as the single-endpoint check, because a candidate list must not be a way around
	// it. A control plane that has been lied to or replaced must not be able to turn a node into
	// a packet source aimed at its own loopback, at our overlay, or at the internal network.
	bad := []Candidate{
		{Endpoint: "127.0.0.1:51820"},
		{Endpoint: "[::1]:51820"},
		{Endpoint: "[2a04:2a01:4::9]:51820"},
		{Endpoint: "100.64.0.1:51820"},
		{Endpoint: "[fe80::1]:51820"},
		{Endpoint: "239.1.1.1:51820"},
		{Endpoint: "0.0.0.0:51820"},
		{Endpoint: "peer.example.com:51820"},
		{Endpoint: "192.168.1.2"},
		{Endpoint: "192.168.1.2:0"},
		{Endpoint: ""},
	}
	if got, err := ParseCandidates(bad); err == nil {
		t.Fatalf("a list of endpoints we must never dial produced candidates: %+v", got)
	}
	// One good entry survives a list that is otherwise all refusals - Postel: one bad row must
	// not cost a peer the path it could have had.
	got, err := ParseCandidates(append(bad, Candidate{Endpoint: "192.168.1.5:51820", Source: SourceLocal}))
	if err != nil {
		t.Fatalf("one good candidate among bad ones was refused: %v", err)
	}
	if len(got) != 1 || got[0].Endpoint != "192.168.1.5:51820" {
		t.Fatalf("the surviving candidate is wrong: %+v", got)
	}
}

func TestParseCandidates_CapsTheList(t *testing.T) {
	var in []Candidate
	for i := 0; i < maxPunchCandidates*3; i++ {
		in = append(in, Candidate{Endpoint: "192.168.1.5:" + itoa(51820+i), Source: SourceLocal})
	}
	got, err := ParseCandidates(in)
	if err != nil {
		t.Fatalf("ParseCandidates: %v", err)
	}
	if len(got) != maxPunchCandidates {
		t.Fatalf("got %d candidates, want the cap of %d", len(got), maxPunchCandidates)
	}
}

func TestParsePeerCandidates_KeepsThePreciseErrorForASingleBadEndpoint(t *testing.T) {
	// The one-endpoint message is what a person debugging one bad control-plane row reads, so
	// the multi-candidate form must not have flattened it into a generic refusal.
	_, err := ParsePeer(testPeerKeyB64, "127.0.0.1:51820", "2a04:2a01:4::7", "x", "")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("a loopback endpoint lost its specific error: %v", err)
	}
}

func TestParsePeerCandidates_TheFirstCandidateBecomesTheEndpoint(t *testing.T) {
	p, err := ParsePeerCandidates(testPeerKeyB64, []Candidate{
		{Endpoint: "203.0.113.7:41234", Source: SourceObserved},
		{Endpoint: "192.168.1.5:51820", Source: SourceLocal},
	}, "2a04:2a01:4::7", "db-01", "direct-punch")
	if err != nil {
		t.Fatalf("ParsePeerCandidates: %v", err)
	}
	if p.Endpoint != "192.168.1.5:51820" {
		t.Fatalf("Endpoint = %q, want the best candidate to be the one we arm at", p.Endpoint)
	}
	if len(p.Candidates) != 2 {
		t.Fatalf("candidates were lost: %+v", p.Candidates)
	}
	if p.Path != "direct-punch" {
		t.Fatalf("the row's class was dropped: %q", p.Path)
	}
}

func TestPeer_CandidateListFallsBackToTheSingleEndpoint(t *testing.T) {
	// A Peer built by pre-punch code must behave exactly as it did: one endpoint, one candidate.
	p := Peer{Endpoint: "192.168.1.5:51820"}
	got := p.candidateList()
	if len(got) != 1 || got[0].Endpoint != "192.168.1.5:51820" {
		t.Fatalf("candidateList() = %+v", got)
	}
	if len(Peer{}.candidateList()) != 0 {
		t.Fatal("a peer with no endpoint at all offered a candidate")
	}
}

// ==========================================================================================
// The schedule. These numbers are the difference between a punch that lands and a train of
// packets nobody is listening for, so they are asserted rather than left to the constants.
// ==========================================================================================

func TestPunchTrain_FirstAttemptIsImmediateThenPaced(t *testing.T) {
	now := time.Now()
	tr := newPunchTrain([]Candidate{{Endpoint: "a:1"}, {Endpoint: "b:2"}}, now)

	// Immediately: the peer was just installed, and waiting a period before the first packet is
	// a period the far side spends unable to reach us for no reason at all.
	if _, due := tr.due(now, time.Second); !due {
		t.Fatal("the first attempt was not due immediately")
	}
	// Not again within the period.
	if _, due := tr.due(now.Add(500*time.Millisecond), time.Second); due {
		t.Fatal("a second attempt fired inside one period")
	}
	// Due again a period later. The slack matters: the caller is a ticker of the same order, and
	// two equal timers beating against each other would silently halve the punch rate.
	if _, due := tr.due(now.Add(950*time.Millisecond), time.Second); !due {
		t.Fatal("the next attempt was not due after a period (the tick slack is missing)")
	}
}

func TestPunchTrain_RotatesThroughEveryCandidate(t *testing.T) {
	now := time.Now()
	cands := []Candidate{{Endpoint: "a:1"}, {Endpoint: "b:2"}, {Endpoint: "c:3"}}
	tr := newPunchTrain(cands, now)
	seen := map[string]int{}
	for i := 0; i < len(cands); i++ {
		c, due := tr.due(now.Add(time.Duration(i)*time.Second), time.Second)
		if !due {
			t.Fatalf("attempt %d was not due", i)
		}
		seen[c.Endpoint]++
	}
	// Round-robin, not "spend the whole train on the first one": the winner may be last in the
	// list, and only one direction has to get through for WireGuard's roaming to finish the job.
	if len(seen) != len(cands) {
		t.Fatalf("the train did not reach every candidate: %v", seen)
	}
}

func TestPunchTrain_GivesUpAfterAFullTrainAndSaysSo(t *testing.T) {
	now := time.Now()
	tr := newPunchTrain([]Candidate{{Endpoint: "a:1"}}, now)
	for i := 0; i < punchTrainAttempts; i++ {
		if _, due := tr.due(now.Add(time.Duration(i)*time.Second), time.Second); !due {
			t.Fatalf("attempt %d of the train was not due", i)
		}
	}
	if _, due := tr.due(now.Add(time.Hour), time.Second); due {
		t.Fatal("the train kept punching past its own length")
	}
	if !tr.spent() {
		t.Fatal("a spent train does not report itself as spent, so the rearm window would never restart it")
	}
	in := tr.info(false)
	if in.Phase != PunchGaveUp {
		t.Fatalf("phase = %q, want %q", in.Phase, PunchGaveUp)
	}
	if in.Attempts != punchTrainAttempts {
		t.Fatalf("attempts = %d, want %d", in.Attempts, punchTrainAttempts)
	}
}

func TestPunchTrain_RestartsAtTheEndpointThatWorkedLastTime(t *testing.T) {
	now := time.Now()
	cands := []Candidate{{Endpoint: "a:1"}, {Endpoint: "b:2"}, {Endpoint: "c:3"}}
	tr := newPunchTrain(cands, now)
	tr.restart(now, Candidate{Endpoint: "c:3"})
	c, due := tr.due(now, time.Second)
	if !due || c.Endpoint != "c:3" {
		t.Fatalf("a restart did not resume at the winning endpoint: %+v due=%v", c, due)
	}
	if tr.trains != 2 {
		t.Fatalf("trains = %d, want the restart to have been counted", tr.trains)
	}
	// A winner that is no longer in the list must not send the rotation off the end of it.
	tr.restart(now, Candidate{Endpoint: "gone:9"})
	if c, due := tr.due(now, time.Second); !due || c.Endpoint != "a:1" {
		t.Fatalf("a restart at an unknown endpoint did not fall back to the top: %+v due=%v", c, due)
	}
}

func TestPunchTrain_APeerWithNoCandidatesIsIdleNotPunching(t *testing.T) {
	tr := newPunchTrain(nil, time.Now())
	if _, due := tr.due(time.Now(), time.Second); due {
		t.Fatal("a peer with nowhere to aim produced a punch attempt")
	}
	if in := tr.info(false); in.Phase != PunchIdle {
		t.Fatalf("phase = %q, want %q - an attempt count for packets never sent is a lie", in.Phase, PunchIdle)
	}
}

// TestPunchTrain_EstablishedOnlyEverComesFromTheDevice is the report's own honesty rule. The
// train's opinion that it won is not evidence; the phase says established only when the caller
// passes the DEVICE's promoted flag, which is set only after a real handshake.
func TestPunchTrain_EstablishedOnlyEverComesFromTheDevice(t *testing.T) {
	tr := newPunchTrain([]Candidate{{Endpoint: "a:1"}}, time.Now())
	tr.won = true
	tr.winner = Candidate{Endpoint: "a:1", Source: SourceObserved}
	if in := tr.info(false); in.Phase == PunchEstablished {
		t.Fatal("the train reported an established path while the device was not routing to it")
	}
	in := tr.info(true)
	if in.Phase != PunchEstablished {
		t.Fatalf("phase = %q, want %q", in.Phase, PunchEstablished)
	}
	if in.Winner != "a:1" || in.WinnerSource != SourceObserved {
		t.Fatalf("the winning endpoint was not reported: %+v", in)
	}
}

// ==========================================================================================
// The document. What a punch does NOT write is the whole safety argument.
// ==========================================================================================

// TestPunchDoc_NeverTouchesCryptokeyRouting is the invariant at the write level. Promotion and
// demotion are the only two things in this package allowed to move a /128; if a punch could
// move one, a punch aimed at a dead endpoint would black-hole that destination instead of
// leaving it on the relay - which is exactly the failure the two-phase install exists to avoid.
func TestPunchDoc_NeverTouchesCryptokeyRouting(t *testing.T) {
	p := Peer{PublicKeyHex: strings.Repeat("33", 32)}
	doc := punchDoc(p, Candidate{Endpoint: "203.0.113.7:41234", Source: SourceObserved})

	if strings.Contains(doc, "allowed_ip") {
		t.Fatalf("a punch wrote an allowed-ip:\n%s", doc)
	}
	if strings.Contains(doc, "replace_allowed_ips") {
		t.Fatalf("a punch cleared the allowed-ips, which would demote a promoted peer:\n%s", doc)
	}
	if !strings.Contains(doc, "update_only=true\n") {
		t.Fatalf("a punch could create a peer the control plane had removed:\n%s", doc)
	}
	if !strings.Contains(doc, "endpoint=203.0.113.7:41234\n") {
		t.Fatalf("the punch did not aim at its candidate:\n%s", doc)
	}
	// The keepalive toggled off and on again IS the trigger: wireguard-go sends an immediate
	// keepalive when the interval goes from zero to non-zero, and a keepalive with no live
	// session is a handshake initiation. Without the zero line first, nothing is sent at all.
	if !strings.Contains(doc, "persistent_keepalive_interval=0\n") {
		t.Fatalf("the keepalive was not toggled off first, so no packet would be sent:\n%s", doc)
	}
	if !strings.Contains(doc, "persistent_keepalive_interval=5\n") {
		t.Fatalf("the keepalive was not turned back on:\n%s", doc)
	}
	if strings.Contains(doc, "private_key") {
		t.Fatalf("a punch document carried key material:\n%s", doc)
	}
}

// ==========================================================================================
// Reading back where a peer actually is, which is how the hard NAT case is learned at all.
// ==========================================================================================

func TestEndpointFromDump_ReadsTheRightPeersSection(t *testing.T) {
	box := strings.Repeat("22", 32)
	peer := strings.Repeat("33", 32)
	dump := "private_key=" + strings.Repeat("11", 32) + "\n" +
		"listen_port=51820\n" +
		"public_key=" + box + "\n" +
		"endpoint=[2001:db8::1]:51826\n" +
		"public_key=" + peer + "\n" +
		"endpoint=203.0.113.7:41234\n"

	if got := endpointFromDump(dump, peer); got != "203.0.113.7:41234" {
		t.Fatalf("peer endpoint = %q", got)
	}
	if got := endpointFromDump(dump, box); got != "[2001:db8::1]:51826" {
		t.Fatalf("box endpoint = %q", got)
	}
	if got := endpointFromDump(dump, strings.Repeat("44", 32)); got != "" {
		t.Fatalf("an absent peer reported an endpoint: %q", got)
	}
}

func TestSourceOf_AnEndpointNobodyOfferedIsARoamedOne(t *testing.T) {
	cands := []Candidate{{Endpoint: "192.168.1.5:51820", Source: SourceLocal}}
	if got := sourceOf(cands, "192.168.1.5:51820"); got != SourceLocal {
		t.Fatalf("got %q, want %q", got, SourceLocal)
	}
	// The symmetric-NAT case: WireGuard roamed the peer to a mapped source nothing could have
	// predicted, and reporting that as unknown would hide the one case this work exists for.
	if got := sourceOf(cands, "203.0.113.7:60122"); got != SourceRoamed {
		t.Fatalf("got %q, want %q", got, SourceRoamed)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
