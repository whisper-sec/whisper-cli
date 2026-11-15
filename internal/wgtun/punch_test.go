// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net/netip"
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
	// a packet source aimed at its own loopback, at our overlay, or at a tailnet.
	bad := []Candidate{
		{Endpoint: "127.0.0.1:51820"},
		{Endpoint: "[::1]:51820"},
		{Endpoint: "[2a04:2a01:4::9]:51820"},
		{Endpoint: "100.64.0.1:51820"},
		{Endpoint: "[fd7a:115c:a1e0:1::7]:51820"},
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
	doc := punchDoc(p, Candidate{Endpoint: "203.0.113.7:41234", Source: SourceObserved}, directKeepalive)

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

// TestPunchTrain_NothingIsSentInsideTheQuietHold is the quiet hold's train half: after a withdrawal
// neither an untimed train nor a timed one sends before the hold ends, a window inside the hold is neither
// joined nor counted as missed, and both resume once it is over, the untimed one at once.
func TestPunchTrain_NothingIsSentInsideTheQuietHold(t *testing.T) {
	now := time.Now()
	hold := 40 * time.Second

	untimed := newPunchTrain([]Candidate{{Endpoint: "a:1"}}, now)
	untimed.holdFor(now.Add(hold))
	for at := time.Duration(0); at < hold; at += time.Second {
		if _, due := untimed.due(now.Add(at), time.Second); due {
			t.Fatalf("an untimed attempt was due %v into a %v hold", at, hold)
		}
	}
	if untimed.attempts != 0 || untimed.info(false).Phase != PunchResting {
		t.Fatalf("a held train reads %+v, want resting", untimed.info(false))
	}
	if _, due := untimed.due(now.Add(hold), time.Second); !due {
		t.Fatal("the untimed train did not resume the moment its hold ended")
	}

	// A timed train with windows at base+10s, +50s, +90s (timedTrain): the hold covers the windows at 10 s
	// and 50 s, and the one at 90 s is the first attended, from the first rung of the backoff.
	timed := timedTrain(now, true)
	timed.holdFor(now.Add(55 * time.Second))
	got := stepUntil(timed, now, 0, 55*time.Second, time.Second, 0)
	if len(got) != 0 || timed.attended || timed.missed != 0 || timed.trains != 0 {
		t.Fatalf("a timed train acted inside its hold: %v (attended %v missed %d trains %d)", got, timed.attended, timed.missed, timed.trains)
	}
	if act, _, at := timed.windowStep(now.Add(89*time.Second+500*time.Millisecond), time.Second, time.Second, 0); act != punchSend || !at.Equal(now.Add(90*time.Second)) {
		t.Fatalf("the first window after the hold was not attended: %v at %v", act, at.Sub(now))
	}

	// A window whose send point falls just after the hold is scheduled at its own point, by the tick before
	// it, not joined late by the tick after: the opener's half-window lead is what makes the punch land.
	edge := timedTrain(now, true)
	edge.holdFor(now.Add(9*time.Second + 800*time.Millisecond))
	if act, _, at := edge.windowStep(now.Add(9*time.Second+500*time.Millisecond), time.Second, time.Second, 0); act != punchSend || !at.Equal(now.Add(10*time.Second)) {
		t.Fatalf("a window opening just after the hold was not scheduled at its start: %v at %v", act, at.Sub(now))
	}

	// A hold is only ever lengthened, and a train started inside one carries it.
	timed.holdFor(now.Add(time.Second))
	if !timed.holding(now.Add(50 * time.Second)) {
		t.Fatal("a shorter hold shortened the one running")
	}
	carried := newPunchTrainFor(Peer{Address: netip.MustParseAddr("2a04:2a01:4::b"), Candidates: []Candidate{{Endpoint: "a:1"}}},
		netip.MustParseAddr("2a04:2a01:4::a"), now, punchCarry{holdUntil: now.Add(hold)}, directRearmAfter)
	if _, due := carried.due(now.Add(time.Second), time.Second); due || !carried.holding(now.Add(hold-time.Millisecond)) {
		t.Fatal("a train started inside a hold did not keep it")
	}
}

// TestQuietHold_OutlastsTheFarEndsDetection pins the invariant the hold rests on. The far end lets go of
// its half once nothing has arrived for directDeadAfter, which it notices on a monitor tick, so the hold
// must outlast the dead-path window and two ticks with room, at the production defaults and with a slow
// monitor alike.
func TestQuietHold_OutlastsTheFarEndsDetection(t *testing.T) {
	for _, tn := range []*Tunnel{
		{},
		{directDead: 20 * time.Second, healthEvery: 15 * time.Second},
		{directDead: 3 * time.Second, healthEvery: 50 * time.Millisecond},
	} {
		dead, tick := orDur(tn.directDead, directDeadAfter), orDur(tn.healthEvery, 5*time.Second)
		if hold := tn.quietHold(); hold < dead+2*tick+tick/2 {
			t.Fatalf("dead %v, tick %v: a hold of %v does not outlast the far end's detection with room", dead, tick, hold)
		}
	}
	if (&Tunnel{}).quietHold() != 40*time.Second {
		t.Fatalf("the production hold is %v, want 40s", (&Tunnel{}).quietHold())
	}
	// After a path cut both ways, with the two ends withdrawing in one tick, the opener's first untimed
	// attempt comes first by at least half a punch period: the jitter is the pair's, so it is the same at
	// both ends, and each end takes its first attempt on the first tick after its hold, up to a tick late.
	// The two ends of one pair compute the same jitter; a timed train gets no difference (its window orders
	// the two ends).
	lo, hi := netip.MustParseAddr("2a04:2a01:4::a"), netip.MustParseAddr("2a04:2a01:4::b")
	for _, tn := range []*Tunnel{
		{cfg: Config{Address: lo}},
		{cfg: Config{Address: lo}, directDead: 4 * time.Second, healthEvery: 50 * time.Millisecond, punchEvery: 200 * time.Millisecond},
		{cfg: Config{Address: lo}, directDead: 4 * time.Second, healthEvery: time.Second, punchEvery: time.Second},
	} {
		far := &Tunnel{cfg: Config{Address: hi}, directDead: tn.directDead, healthEvery: tn.healthEvery, punchEvery: tn.punchEvery}
		tick, period := orDur(tn.healthEvery, 5*time.Second), orDur(tn.punchEvery, punchPeriod)
		// The opener withdraws up to a tick after the other end and takes its first attempt up to a tick after
		// its hold; the other end, at the earliest, a tick before it and on the dot.
		openerLatest := tn.holdLength(true, true, hi) + tick
		other := far.holdLength(false, true, lo) - tick
		if gap := other - openerLatest; gap < period/2 {
			t.Fatalf("tick %v: the other end's first attempt can come only %v after the opener's, want half a punch period", tick, gap)
		}
		// keepHeard keeps every gap between two sends at kickEvery and a tick, which the far end must see well
		// inside its window, less the tick on which it notices.
		if dead := orDur(tn.directDead, directDeadAfter); tn.kickEvery()+tick > dead-tick-tick/2 {
			t.Fatalf("tick %v, window %v: keepHeard's gap of %v and a tick leaves the far end no margin", tick, dead, tn.kickEvery())
		}
		if tn.holdLength(true, false, hi) != far.holdLength(false, false, lo) {
			t.Fatal("the two ends of a timed pair hold differently, which their window does not need")
		}
	}
	for _, rank := range []uint64{0, 1, 1 << 40, ^uint64(0)} {
		if j := holdJitter(40*time.Second, rank); j < 0 || j >= 5*time.Second {
			t.Fatalf("a jitter of %v is outside [0, 5s)", j)
		}
	}
}

// TestPunchTrain_TheKeepaliveAnUntimedTrainPunchesWith: one second more at the end that does not open the
// pair, the tunnel's own everywhere else.
func TestPunchTrain_TheKeepaliveAnUntimedTrainPunchesWith(t *testing.T) {
	now := time.Now()
	lo, hi := netip.MustParseAddr("2a04:2a01:4::a"), netip.MustParseAddr("2a04:2a01:4::b")
	untimed := func(self, peer netip.Addr) *punchTrain {
		return newPunchTrainFor(Peer{Address: peer, Candidates: []Candidate{{Endpoint: "a:1"}}}, self, now, punchCarry{}, directRearmAfter)
	}
	for _, tc := range []struct {
		name string
		tr   *punchTrain
		want int
	}{
		{"no train", nil, 5},
		{"a timed train", timedTrain(now, false), 5},
		{"an untimed train at the opener", untimed(lo, hi), 5},
		{"an untimed train at the other end", untimed(hi, lo), 6},
	} {
		if got := tc.tr.keepalive(5); got != tc.want {
			t.Errorf("%s: keepalive %d, want %d", tc.name, got, tc.want)
		}
	}
}
