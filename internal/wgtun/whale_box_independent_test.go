// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"
)

// whale_box_independent_test.go is the client half of making a pair's direct path independent of which
// box answers a read, and of bounding what a direct path that never answers costs:
//
//   - a promoted peer whose key the plane vouches for (the row's tunnel_key) is held on a read with no
//     other evidence for as long as the plane vouches for it, and removed on the read that names another
//     key;
//   - a direct row that carries the pair's window stops sending once its first train is spent and tries
//     again only inside the window, where a row without one keeps the device sending every five seconds;
//   - the timed peers past the cap are chosen by a rank both ends of a pair compute alike.
//
// "Box one" and "box two" are the two answers a read can get from the front door. Every case alternates
// them, because the defect was always a difference between two answers, never one wrong answer.

// vouchedListed is a box's row for an address with no evidence about the pair: verdict "unknown", and the
// key the plane binds to the address (empty for none), as tunnel_key.
func vouchedListed(addr netip.Addr, keyHex string) Peer {
	l, _ := ListedPeer(addr.String(), "")
	l.Hold = true
	l.Vouched = true
	l.VouchedKeyHex = keyHex
	return l
}

// promotedDirect installs a direct peer at a dead endpoint and marks it promoted, which is what a handshake
// would have done: the hold rule reads the state, not how it came about.
func promotedDirect(t *testing.T, tun *Tunnel, p Peer) *directPeer {
	t.Helper()
	if err := tun.SetDirectPeers([]Peer{p}); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	defer tun.mu.Unlock()
	d := tun.direct[p.PublicKeyHex]
	if d == nil {
		t.Fatal("the direct peer was not installed")
	}
	d.promoted = true
	return d
}

func TestVouchedKey_APromotedPeerIsHeldForAsLongAsThePlaneVouchesForItsKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a := startNatNode(t, "2a04:2a01:4::a", nil, nil, 7060, fastOpts())
	farIP := mustAddr(t, "2a04:2a01:4::b")
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	key := strings.Repeat("6b", 32)
	direct := Peer{Address: farIP, PublicKeyHex: key, Endpoint: dead, Path: "direct-public",
		Candidates: []Candidate{{Endpoint: dead, Source: SourcePublic}}}
	tracked := func() *directPeer {
		a.tun.mu.Lock()
		defer a.tun.mu.Unlock()
		return a.tun.direct[key]
	}
	first := promotedDirect(t, a.tun, direct)

	// Box one has the evidence and sends the direct row; box two has none and vouches for the key. Far past
	// maxHeldReads, and far past maxHeldAge, the proven path stays.
	for i := 0; i < 4*maxHeldReads; i++ {
		read := direct
		if i%4 != 0 {
			read = vouchedListed(farIP, key)
		}
		if err := a.tun.SetDirectPeers([]Peer{read}); err != nil {
			t.Fatal(err)
		}
		if tracked() != first {
			t.Fatalf("read %d: a promoted peer the plane vouches for was removed or re-armed", i)
		}
	}
	for i := 0; i < 3*maxHeldReads; i++ {
		_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, key)})
	}
	a.tun.mu.Lock()
	first.heldSince = time.Now().Add(-2 * maxHeldAge)
	a.tun.mu.Unlock()
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, key)})
	if tracked() != first {
		t.Fatal("a promoted peer the plane vouches for was dropped by the read or age bound")
	}

	// The plane names another key for the address (the node re-keyed): removed on that very read.
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, strings.Repeat("6c", 32))})
	if present, _, _ := peerSection(t, a.tun, key); present || tracked() != nil {
		t.Fatal("a peer survived a read naming another key for its address")
	}

	// A key this client cannot read reads as another key.
	promotedDirect(t, a.tun, direct)
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, VouchedUnreadable)})
	if tracked() != nil {
		t.Fatal("a peer survived a read whose tunnel_key is not a key")
	}

	// The address has no key at all any more (the node disconnected, or its key was revoked): gone at once.
	promotedDirect(t, a.tun, direct)
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, VouchedNone)})
	if tracked() != nil {
		t.Fatal("a peer survived a read saying its address has no key")
	}

	// No key named (two keys the plane cannot choose between, say): no evidence either way, so the bounded
	// hold of a plane that names nothing, and gone after maxHeldReads.
	promotedDirect(t, a.tun, direct)
	for i := 1; i <= maxHeldReads; i++ {
		_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, "")})
		if tracked() == nil {
			t.Fatalf("removed after %d reads naming no key, want %d kept", i, maxHeldReads)
		}
	}
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, "")})
	if tracked() != nil {
		t.Fatal("a peer outlived maxHeldReads reads that named no key")
	}

	// A plane from before tunnel_key: the bounded hold, as it was.
	promotedDirect(t, a.tun, direct)
	old, _ := ListedPeer(farIP.String(), "")
	old.Hold = true
	for i := 0; i < maxHeldReads; i++ {
		_ = a.tun.SetDirectPeers([]Peer{old})
	}
	_ = a.tun.SetDirectPeers([]Peer{old})
	if tracked() != nil {
		t.Fatal("an older plane's reads held a peer past maxHeldReads")
	}

	// A refusal ("unlikely", which a pair no longer permitted both ways gets) removes it whatever it vouches.
	promotedDirect(t, a.tun, direct)
	refused, _ := ListedPeer(farIP.String(), "")
	refused.Vouched, refused.VouchedKeyHex = true, key
	_ = a.tun.SetDirectPeers([]Peer{refused})
	if tracked() != nil {
		t.Fatal("a refused pair kept its direct peer because the row carried its key")
	}
}

func TestVouchedKey_AnUnpromotedTimedPeerKeepsTheBoundedHoldEvenWhenVouched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a := startNatNode(t, "2a04:2a01:4::a", nil, nil, 7061, fastOpts())
	farIP := mustAddr(t, "2a04:2a01:4::b")
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	key := strings.Repeat("6b", 32)
	advised := Peer{Address: farIP, PublicKeyHex: key, Endpoint: dead, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: farWindow()}
	if err := a.tun.SetDirectPeers([]Peer{advised}); err != nil {
		t.Fatal(err)
	}
	// Its endpoint is advice that expires: a vouched key does not keep an unproven path past the bound.
	for i := 0; i < maxHeldReads; i++ {
		_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, key)})
	}
	_ = a.tun.SetDirectPeers([]Peer{vouchedListed(farIP, key)})
	a.tun.mu.Lock()
	gone := a.tun.direct[key] == nil
	a.tun.mu.Unlock()
	if !gone {
		t.Fatal("an unpromoted timed peer outlived maxHeldReads on vouched reads")
	}
}

// TestWindowedDirectRow_StopsSendingOnceItsFirstTrainIsSpent: a direct row whose far end never
// answers. Two nodes side by side, each with such a peer at a dead endpoint: one row carries the pair's
// window, the other (a plane from before windows) does not. Both run their first train at once. Then the
// windowed one is silenced and sends nothing until its window, and inside the window it sends; the other
// keeps the device initiating every five seconds, which is the cost the window removes, measured here so
// the silence cannot be a quiet the test failed to see.
func TestWindowedDirectRow_StopsSendingOnceItsFirstTrainIsSpent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	windowed := startNatNode(t, "2a04:2a01:4::a", newNatBind(time.Second), nil, 7062, fastOpts())
	plain := startNatNode(t, "2a04:2a01:4::c", newNatBind(time.Second), nil, 7063, fastOpts())
	farIP := mustAddr(t, "2a04:2a01:4::b")
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	key := strings.Repeat("6b", 32)
	base := time.Now()
	w := Rendezvous{At: base.Add(16 * time.Second), Until: base.Add(22 * time.Second), Period: time.Hour, Slot: 9}
	row := func(window Rendezvous) Peer {
		return Peer{Address: farIP, PublicKeyHex: key, Endpoint: dead, Path: "direct-public",
			Candidates: []Candidate{{Endpoint: dead, Source: SourcePublic}}, Window: window}
	}
	if err := windowed.tun.SetDirectPeers([]Peer{row(w)}); err != nil {
		t.Fatal(err)
	}
	if err := plain.tun.SetDirectPeers([]Peer{row(Rendezvous{})}); err != nil {
		t.Fatal(err)
	}
	// The first train: punchTrainAttempts at PunchEvery (200 ms here), so about 2.4 s, at once.
	if !waitFor(10*time.Second, func() bool {
		present, ka, allowed := peerSection(t, windowed.tun, key)
		st := windowed.tun.DirectPeers()
		return present && ka == "0" && len(allowed) == 0 && len(st) == 1 && st[0].Punch.Phase == PunchGaveUp
	}) {
		present, ka, _ := peerSection(t, windowed.tun, key)
		t.Fatalf("the spent first train was not silenced: present=%v keepalive=%q %+v", present, ka, windowed.tun.DirectPeers())
	}
	if n := len(windowed.nat.sendsTo(dead)); n == 0 {
		t.Fatal("the first train sent nothing: it must try at once, before any window")
	}
	quietFrom := time.Now()
	time.Sleep(time.Until(w.At.Add(-500 * time.Millisecond)))
	quietTo := time.Now()
	for _, at := range windowed.nat.sendsTo(dead) {
		if at.After(quietFrom) && at.Before(quietTo) {
			t.Fatalf("a packet went to a silenced peer %v after the silence, before its window", at.Sub(quietFrom))
		}
	}
	var plainQuiet int
	for _, at := range plain.nat.sendsTo(dead) {
		if at.After(quietFrom) && at.Before(quietTo) {
			plainQuiet++
		}
	}
	if plainQuiet < 2 {
		t.Fatalf("the control (a direct row with no window) sent %d packets over %v; the device should keep initiating every 5 s",
			plainQuiet, quietTo.Sub(quietFrom))
	}
	// And inside the window it sends again, which is what lets the far end meet it.
	if !waitFor(12*time.Second, func() bool {
		for _, at := range windowed.nat.sendsTo(dead) {
			if !at.Before(w.At) {
				return true
			}
		}
		return false
	}) {
		t.Fatal("the silenced peer sent nothing in its window")
	}
	if windowed.tun.PathTo(farIP) != "relayed" || routedTo(t, windowed.tun, key, farIP) {
		t.Fatal("a direct path that never answered holds the /128")
	}
}

func TestWindowedDirectRow_ATrainIsNotBoughtAgainByReArmingOrReinstalling(t *testing.T) {
	addr := netip.MustParseAddr("2a04:2a01:4::b")
	self := netip.MustParseAddr("2a04:2a01:4::a")
	now := time.Now()
	w := Rendezvous{At: now.Add(time.Minute), Until: now.Add(time.Minute + 6*time.Second), Period: time.Minute, Slot: 5}
	p := Peer{Address: addr, Candidates: []Candidate{{Endpoint: "192.168.1.9:51820", Source: SourceLocal},
		{Endpoint: "198.51.100.4:51820", Source: SourceObserved}}, Window: w}

	fresh := newPunchTrainFor(p, self, now, punchCarry{}, directRearmAfter)
	if fresh.timed() || !fresh.canFallBack() || fresh.preludeAt != now {
		t.Fatal("a direct row with a window and no history must run its first train at once")
	}
	// The same key re-armed (or installed again after a removal) 30 s later: straight onto the window, and
	// with the backoff it had earned.
	again := newPunchTrainFor(p, self, now.Add(30*time.Second), punchCarry{missed: 3, preludeAt: now}, directRearmAfter)
	if !again.timed() || again.missed != 3 || !again.preludeAt.Equal(now) {
		t.Fatalf("re-armed: timed=%v missed=%d prelude=%v, want on the window, missed 3, the old train's start",
			again.timed(), again.missed, again.preludeAt)
	}
	// After directRearmAfter a first train is allowed again.
	later := newPunchTrainFor(p, self, now.Add(directRearmAfter), punchCarry{missed: 3, preludeAt: now}, directRearmAfter)
	if later.timed() {
		t.Fatal("a first train was refused directRearmAfter after the last one")
	}
	// Once fallen back, every window aims at the same endpoint: the observed one, whichever end asks.
	fresh.fallBack()
	for i := 0; i < 4; i++ {
		if c := fresh.aimWindow(now); c.Source != SourceObserved {
			t.Fatalf("window %d aimed at %+v, want the observed endpoint every time", i, c)
		}
	}
	// A path that was up and died runs a first train again at once, from the endpoint that carried it.
	fresh.missed = 2
	fresh.restart(now, Candidate{Endpoint: "192.168.1.9:51820", Source: SourceLocal})
	if fresh.timed() || fresh.missed != 0 {
		t.Fatal("a demoted direct row must try again at once, with its backoff reset")
	}
	// ...unless it lasted less than a rekey and a first train ran lately: back to the window, backoff kept.
	fresh.fallBack()
	fresh.missed = 2
	fresh.restartFor(now, Candidate{}, false)
	if !fresh.timed() || fresh.missed != 2 {
		t.Fatalf("a short-lived path bought a fresh train: timed=%v missed=%d", fresh.timed(), fresh.missed)
	}
	// A slower read's placement of the same schedule does not replace a more precise one; a no worse one does.
	precise := w
	precise.ReadError = 50 * time.Millisecond
	sloppy := w
	sloppy.At, sloppy.Until, sloppy.ReadError = w.At.Add(4*time.Second), w.Until.Add(4*time.Second), 5*time.Second
	tr := newPunchTrainFor(Peer{Address: addr, Candidates: p.Candidates, Window: precise}, self, now, punchCarry{}, directRearmAfter)
	tr.adoptFallback(sloppy)
	if !tr.fallback.At.Equal(precise.At) {
		t.Fatal("a slow read's placement replaced a precise one")
	}
	better := w
	better.ReadError = 10 * time.Millisecond
	tr.adoptFallback(better)
	if tr.fallback.ReadError != better.ReadError {
		t.Fatal("a more precise placement was not taken")
	}
	// A re-armed row whose read carried no window keeps the pair's last one.
	noWindow := p
	noWindow.Window = Rendezvous{}
	kept := newPunchTrainFor(noWindow, self, now, punchCarry{window: w}, directRearmAfter)
	if !kept.canFallBack() {
		t.Fatal("a re-armed direct row lost the pair's window because one read carried none")
	}
}

// TestPairRank_BothEndsKeepMostOfTheSamePairsPastTheCap: a full mesh of 300 NATed nodes, each
// advised a punch for every other one, each keeping maxTimedPeers of them. A pair is attended only when
// BOTH ends keep it. By the rule this replaces (each node's lowest peer addresses), the 171 nodes whose
// address sorts above the cap kept 128 peers that all dropped them, and went direct with nobody; by the
// pair's rank every node keeps most of its pairs reciprocated.
func TestPairRank_BothEndsKeepMostOfTheSamePairsPastTheCap(t *testing.T) {
	const n = 300
	nodes := make([]netip.Addr, n)
	for i := range nodes {
		nodes[i] = netip.AddrFrom16([16]byte{0x2a, 0x04, 0x2a, 0x01, 0, 7, 14: byte(i >> 8), 15: byte(i)})
	}
	keepBy := func(less func(self, x, y netip.Addr) bool) []map[netip.Addr]bool {
		out := make([]map[netip.Addr]bool, n)
		for i, self := range nodes {
			var others []netip.Addr
			for _, o := range nodes {
				if o != self {
					others = append(others, o)
				}
			}
			sort.Slice(others, func(a, b int) bool { return less(self, others[a], others[b]) })
			out[i] = map[netip.Addr]bool{}
			for _, o := range others[:maxTimedPeers] {
				out[i][o] = true
			}
		}
		return out
	}
	reciprocated := func(keep []map[netip.Addr]bool) (worst, zero int) {
		worst = n
		index := map[netip.Addr]int{}
		for i, a := range nodes {
			index[a] = i
		}
		for i, self := range nodes {
			c := 0
			for o := range keep[i] {
				if keep[index[o]][self] {
					c++
				}
			}
			if c < worst {
				worst = c
			}
			if c == 0 {
				zero++
			}
		}
		return worst, zero
	}

	_, zeroByAddress := reciprocated(keepBy(func(_, x, y netip.Addr) bool { return x.Less(y) }))
	if zeroByAddress != n-maxTimedPeers-1 {
		t.Fatalf("the rule this replaces left %d nodes with no reciprocated pair, want %d (the measurement is off)",
			zeroByAddress, n-maxTimedPeers-1)
	}

	// Through capTimed itself, the code under test, not a copy of its rule.
	keep := make([]map[netip.Addr]bool, n)
	for i, self := range nodes {
		var timed []Peer
		for _, o := range nodes {
			if o != self {
				timed = append(timed, Peer{Address: o, PublicKeyHex: o.String()})
			}
		}
		keep[i] = map[netip.Addr]bool{}
		for _, p := range capTimed(timed, nil, self) {
			keep[i][p.Address] = true
		}
	}
	worst, zero := reciprocated(keep)
	t.Logf("by address: %d nodes with no reciprocated pair; by pair rank: worst node keeps %d of %d reciprocated",
		zeroByAddress, worst, maxTimedPeers)
	if zero != 0 || worst < maxTimedPeers*3/4 {
		t.Fatalf("by pair rank: %d nodes with no reciprocated pair, worst node %d of %d", zero, worst, maxTimedPeers)
	}
	for _, x := range nodes[:10] {
		for _, y := range nodes[10:20] {
			if pairRank(x, y) != pairRank(y, x) {
				t.Fatalf("pairRank(%s, %s) is not symmetric", x, y)
			}
		}
	}
}
