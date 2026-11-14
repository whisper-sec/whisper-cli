// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net/netip"
	"testing"
	"time"
)

// whale_local_fallback_test.go covers a direct-local row that also carries the endpoint a box observed.
// A shared segment is only the two nodes' claim, so when the local endpoint never answers the train goes
// on to the observed one, and a path won there is reported as the punch it was.

func TestSameCandidates_TheObservedEndpointIsNotAMaterialChange(t *testing.T) {
	local := Candidate{Endpoint: "192.168.1.9:51820", Source: SourceLocal}
	seen := Candidate{Endpoint: "198.51.100.4:51820", Source: SourceObserved}
	withSeen := Peer{Candidates: []Candidate{local, seen}}
	without := Peer{Candidates: []Candidate{local}}
	moved := Peer{Candidates: []Candidate{{Endpoint: "192.168.1.10:51820", Source: SourceLocal}, seen}}

	// One box saw the peer arrive and the other did not: the same peer, as far as re-arming goes.
	if !sameCandidates(withSeen, without) || !sameCandidates(without, withSeen) {
		t.Fatal("an observed endpoint appearing or going was read as a new peer")
	}
	// The declared endpoint moving is a real change.
	if sameCandidates(withSeen, moved) {
		t.Fatal("a moved local endpoint was not read as a change")
	}
}

func TestPathClass_OnlyAWinOffTheLocalPathIsReportedAsAPunch(t *testing.T) {
	peer := func(path string, winner Candidate) *directPeer {
		return &directPeer{peer: Peer{Path: path}, punch: &punchTrain{won: true, winner: winner}}
	}
	for _, c := range []struct {
		path   string
		winner Candidate
		want   string
	}{
		{"direct-local", Candidate{Endpoint: "192.168.1.9:51820", Source: SourceLocal}, "direct-local"},
		{"direct-local", Candidate{Endpoint: "198.51.100.4:51820", Source: SourceObserved}, "direct-punch"},
		{"direct-local", Candidate{Endpoint: "198.51.100.4:40001", Source: SourceRoamed}, "direct-punch"},
		// A LAN peer answering from its second private address, or renumbered: still the local path.
		{"direct-local", Candidate{Endpoint: "192.168.1.10:51820", Source: SourceRoamed}, "direct-local"},
		{"direct-local", Candidate{Endpoint: "[fd12::9]:51820", Source: SourceRoamed}, "direct-local"},
		// A row with one endpoint and no list classes it public; a win there is the path offered.
		{"direct-local", Candidate{Endpoint: "192.168.1.9:51820", Source: SourcePublic}, "direct-local"},
		{"direct-public", Candidate{Endpoint: "198.51.100.4:51820", Source: SourceObserved}, "direct-public"},
		{"", Candidate{Endpoint: "198.51.100.4:51820", Source: SourceObserved}, "direct"},
	} {
		if got := peer(c.path, c.winner).pathClass(); got != c.want {
			t.Fatalf("%q won at %+v reported %q, want %q", c.path, c.winner, got, c.want)
		}
	}
	if got := (&directPeer{peer: Peer{Path: "direct-local"}}).pathClass(); got != "direct-local" {
		t.Fatalf("a peer with no train reported %q", got)
	}
}

func TestReservedIpv4IsNeverDialled(t *testing.T) {
	for _, ep := range []string{"255.255.255.255:51820", "240.0.0.1:51820", "[::ffff:250.1.2.3]:51820"} {
		if err := checkUnderlayEndpoint(ep); err == nil {
			t.Fatalf("%s was accepted as a peer endpoint", ep)
		}
	}
	if err := checkUnderlayEndpoint("223.255.255.254:51820"); err != nil {
		t.Fatalf("the last unicast /8 was refused: %v", err)
	}
}

// startLocalFallbackTunnel is a tunnel, a relay box and one real peer, with the punch paced fast.
func startLocalFallbackTunnel(t *testing.T, echoPort int) (*Tunnel, *peerSide, netip.Addr) {
	t.Helper()
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	peerIP := mustAddr(t, "2a04:2a01:4::7")
	box := startRelayBox(t, clientPubHex, clientIP, []netip.Addr{mustAddr(t, "2a04:2a01:0:53::1")}, echoPort)
	other := startPeerSide(t, clientPubHex, clientIP)
	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	tun, err := Start(cfg, Options{
		HealthInterval:  100 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 10 * time.Second,
		PunchEvery:      150 * time.Millisecond,
		PathStateDir:    PathStateOff,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)
	return tun, other, peerIP
}

func TestPunch_ALocalPathThatNeverAnswersFallsToTheObservedEndpointAndSaysPunch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake punch test in -short")
	}
	tun, other, peerIP := startLocalFallbackTunnel(t, 7031)
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	live := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String()

	// The plane offered direct-local: a shared /24 that is really two sites. The row also carries where the
	// box saw the peer arrive from.
	peer := Peer{
		Address:      peerIP,
		PublicKeyHex: other.pubHex,
		Endpoint:     dead,
		Name:         "db-01",
		Path:         "direct-local",
		Candidates: []Candidate{
			{Endpoint: dead, Source: SourceLocal},
			{Endpoint: live, Source: SourceObserved},
		},
	}
	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	if !waitFor(15*time.Second, func() bool { return tun.PathTo(peerIP) != "relayed" }) {
		t.Fatalf("the train never reached the observed endpoint: %+v", tun.DirectPeers())
	}
	if !routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("the tunnel reported a direct path the device was not routing")
	}
	// Won at the observed endpoint, so it is a punch, not the shared segment the plane offered.
	if got := tun.PathTo(peerIP); got != "direct-punch" {
		t.Fatalf("PathTo = %q, want direct-punch for a path the local endpoint never carried", got)
	}
	st := tun.DirectPeers()[0]
	if st.Path != "direct-punch" || st.Punch.WinnerSource != SourceObserved || st.Endpoint != live {
		t.Fatalf("state = %+v, want direct-punch won at the observed endpoint %s", st, live)
	}
}

func TestSetDirectPeers_AnObservedEndpointComingAndGoingDoesNotRestartTheTrain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	tun, other, peerIP := startLocalFallbackTunnel(t, 7032)
	deadLocal := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	deadSeen := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	row := func(cands ...Candidate) Peer {
		return Peer{Address: peerIP, PublicKeyHex: other.pubHex, Endpoint: cands[0].Endpoint,
			Path: "direct-local", Candidates: cands}
	}
	local := Candidate{Endpoint: deadLocal, Source: SourceLocal}
	seen := Candidate{Endpoint: deadSeen, Source: SourceObserved}
	train := func() (int, int) {
		tun.mu.Lock()
		defer tun.mu.Unlock()
		d := tun.direct[other.pubHex]
		if d == nil || d.punch == nil {
			return -1, -1
		}
		return d.punch.trains, d.punch.attempts
	}

	if err := tun.SetDirectPeers([]Peer{row(local, seen)}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { _, a := train(); return a >= 3 }) {
		t.Fatal("the train never got going")
	}
	trains, attempts := train()

	// The next refresh is answered by the box that has not seen the peer: no observed endpoint.
	if err := tun.SetDirectPeers([]Peer{row(local)}); err != nil {
		t.Fatalf("SetDirectPeers (other box): %v", err)
	}
	if tr, at := train(); tr != trains || at < attempts {
		t.Fatalf("train restarted on an observed endpoint going away: trains %d->%d, attempts %d->%d",
			trains, tr, attempts, at)
	}
	// And back again.
	if err := tun.SetDirectPeers([]Peer{row(local, seen)}); err != nil {
		t.Fatalf("SetDirectPeers (first box): %v", err)
	}
	if tr, at := train(); tr != trains || at < attempts {
		t.Fatalf("train restarted on an observed endpoint coming back: trains %d->%d, attempts %d->%d",
			trains, tr, attempts, at)
	}

	// The control: the declared endpoint moving IS a new peer, re-armed from the top.
	moved := Candidate{Endpoint: netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String(), Source: SourceLocal}
	if err := tun.SetDirectPeers([]Peer{row(moved, seen)}); err != nil {
		t.Fatalf("SetDirectPeers (moved): %v", err)
	}
	if _, at := train(); at >= attempts {
		t.Fatalf("a moved local endpoint did not re-arm the peer (attempts %d, was %d)", at, attempts)
	}
}
