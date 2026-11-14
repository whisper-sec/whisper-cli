// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// whale_relayed_punch_test.go is a RELAYED pair punched through two NATs, against real devices.
//
// Each node is our own Tunnel, with its own box, and with a NAT in front of it. The NAT is a stateful
// filter in the node's UDP bind: a packet from an address this node has not sent to within the mapping
// lifetime is dropped, which is what a port-preserving NAT with endpoint-dependent filtering does (the
// common consumer NAT, and the one a punch exists for). The mapping is the node's own socket, so the
// endpoint the box would observe is the socket itself. With that filter, ONE side's handshake can never
// get through on its own: the far NAT drops it. Only both ends sending inside one mapping lifetime does,
// which is exactly the property the plane's shared window is there to give.
//
// TestRelayedPunch_TwoNatsMissedWindowsNeverMeet is the control that proves the filter is real: the same
// two nodes, given windows that do not overlap, never handshake.

// natBind is a node's NAT: the platform bind with a stateful filter on what it receives. It also keeps
// every send per destination, so a test can say WHEN this node sent at its peer.
type natBind struct {
	conn.Bind
	life  time.Duration
	delay time.Duration // how long a packet takes to arrive, which is what lets two handshakes cross

	mu      sync.Mutex
	sentTo  map[string]time.Time
	sends   map[string][]time.Time
	dropped map[string]int
}

func newNatBind(life time.Duration) *natBind {
	return &natBind{
		Bind: conn.NewDefaultBind(), life: life,
		sentTo: map[string]time.Time{}, sends: map[string][]time.Time{}, dropped: map[string]int{},
	}
}

func (n *natBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	now := time.Now()
	dst := ep.DstToString()
	n.mu.Lock()
	n.sentTo[dst] = now
	for range bufs {
		n.sends[dst] = append(n.sends[dst], now)
	}
	n.mu.Unlock()
	return n.Bind.Send(bufs, ep)
}

// Open wraps every receive function. A filtered packet is left in the batch with size zero, which
// wireguard-go skips as too short to be a message: the device reads its packets from its own buffers by
// index, so the batch cannot be compacted.
func (n *natBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := n.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			cnt, rerr := fn(packets, sizes, eps)
			if cnt > 0 && n.delay > 0 {
				time.Sleep(n.delay)
			}
			now := time.Now()
			n.mu.Lock()
			for j := 0; j < cnt; j++ {
				src := eps[j].DstToString()
				if last, ok := n.sentTo[src]; !ok || now.Sub(last) > n.life {
					sizes[j] = 0
					n.dropped[src]++
				}
			}
			n.mu.Unlock()
			return cnt, rerr
		}
	}
	return out, actual, nil
}

func (n *natBind) sendsTo(dst string) []time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]time.Time(nil), n.sends[dst]...)
}

func (n *natBind) droppedFrom(src string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dropped[src]
}

// natNode is one node: a keypair, an overlay /128, its box, its NAT and its tunnel.
type natNode struct {
	tun    *Tunnel
	nat    *natBind
	addr   netip.Addr
	pubHex string
	box    *relayBox
}

// endpoint is where the node's NAT maps it, which is what a box observes and hands to the far side.
func (n *natNode) endpoint(t *testing.T) string {
	t.Helper()
	return netip.AddrPortFrom(mustAddr(t, "::1"), uint16(n.tun.ListenPort())).String()
}

// startNatNode brings up one NATed node. serve is what its box answers for besides its own address:
// pass the far node's /128 to give the relay a path to it, or nothing to make any traffic that reaches
// the far node prove the DIRECT path carried it.
func startNatNode(t *testing.T, addr string, nat *natBind, serve []netip.Addr, echoPort int, opts Options) *natNode {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	self := mustAddr(t, addr)
	box := startRelayBox(t, pubHex, self, append([]netip.Addr{mustAddr(t, "2a04:2a01:0:53::1")}, serve...), echoPort)
	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		self.String(), box.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	cfg.Keepalive = 1
	if nat != nil {
		opts.Listen = holdOn(nat)
		if opts.Listen == nil {
			t.Fatal("could not open the NATed bind")
		}
	}
	tun, err := Start(cfg, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)
	return &natNode{tun: tun, nat: nat, addr: self, pubHex: pubHex, box: box}
}

// echoOn serves an echo on the node's own /128 inside its tunnel, which a direct peer reaches.
func (n *natNode) echoOn(t *testing.T, port int) {
	t.Helper()
	ln, err := n.tun.tnet.ListenTCP(&net.TCPAddr{IP: n.addr.AsSlice(), Port: port})
	if err != nil {
		t.Fatalf("listen on the node's own /128: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
}

// relayedPeer is the peer a relayed row with punch advice becomes: the far node's key, the endpoint the
// box saw it arrive from, and the shared window.
func relayedPeer(t *testing.T, far *natNode, w Rendezvous) Peer {
	return Peer{
		Address:      far.addr,
		PublicKeyHex: far.pubHex,
		Endpoint:     far.endpoint(t),
		Name:         "far",
		Path:         pathDirectPunch,
		Candidates:   []Candidate{{Endpoint: far.endpoint(t), Source: SourceObserved}},
		Rendezvous:   w,
	}
}

// peerSection reads one peer's lines out of the device's own dump: its keepalive and its allowed-ips,
// and whether it is on the device at all.
func peerSection(t *testing.T, tun *Tunnel, peerHex string) (present bool, keepalive string, allowed []string) {
	t.Helper()
	dump, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	in := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch {
		case k == "public_key":
			in = v == peerHex
			present = present || in
		case in && k == "persistent_keepalive_interval":
			keepalive = v
		case in && k == "allowed_ip":
			allowed = append(allowed, v)
		}
	}
	return present, keepalive, allowed
}

// fastOpts are the timings of a test: the production ratios, compressed.
func fastOpts() Options {
	return Options{
		HealthInterval:  50 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 20 * time.Second,
		PunchEvery:      200 * time.Millisecond,
		PathStateDir:    PathStateOff,
	}
}

// TestRelayedPunch_TwoNatsMeetInTheSharedWindowAndGoDirect is the feature: two nodes behind two NATs,
// each given the other's key and observed endpoint and the SAME window, as the plane gives a relayed
// pair. Neither sends before the window; both send in it; the handshake lands; both report
// direct-punch; and traffic for the far /128 flows over the direct path, because the near node's box
// does not carry that address at all.
func TestRelayedPunch_TwoNatsMeetInTheSharedWindowAndGoDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake NAT punch test in -short")
	}
	const echoPort = 7040
	a := startNatNode(t, "2a04:2a01:4::a", newNatBind(2*time.Second), nil, 7041, fastOpts())
	b := startNatNode(t, "2a04:2a01:4::b", newNatBind(2*time.Second), nil, 7042, fastOpts())
	b.echoOn(t, echoPort)

	base := time.Now()
	w := Rendezvous{At: base.Add(700 * time.Millisecond), Until: base.Add(2200 * time.Millisecond), Period: 30 * time.Second, Slot: 1000}
	if err := a.tun.SetDirectPeers([]Peer{relayedPeer(t, b, w)}); err != nil {
		t.Fatalf("SetDirectPeers on a: %v", err)
	}
	if err := b.tun.SetDirectPeers([]Peer{relayedPeer(t, a, w)}); err != nil {
		t.Fatalf("SetDirectPeers on b: %v", err)
	}
	// Armed silent: on the device, no keepalive, nothing routed.
	if present, ka, allowed := peerSection(t, a.tun, b.pubHex); !present || ka != "0" || len(allowed) != 0 {
		t.Fatalf("a timed peer was not armed silent: present=%v keepalive=%q allowed=%v", present, ka, allowed)
	}

	if !waitFor(15*time.Second, func() bool {
		return a.tun.PathTo(b.addr) == pathDirectPunch && b.tun.PathTo(a.addr) == pathDirectPunch
	}) {
		t.Fatalf("the pair never went direct: a=%+v b=%+v", a.tun.DirectPeers(), b.tun.DirectPeers())
	}
	// The plane's timing was respected, in the order the ends take: a (the lower address) opens the
	// window at its start, b sends half a window later, and neither sent at the other before its turn.
	stagger := w.Until.Sub(w.At) / 2
	for _, n := range []struct {
		name  string
		self  *natNode
		far   *natNode
		after time.Time
	}{{"a", a, b, w.At}, {"b", b, a, w.At.Add(stagger)}} {
		sends := n.self.nat.sendsTo(n.far.endpoint(t))
		if len(sends) == 0 {
			t.Fatalf("%s never sent at its peer, so this test proves nothing about the punch", n.name)
		}
		if sends[0].Before(n.after) {
			t.Fatalf("%s sent at its peer %v BEFORE its turn in the window", n.name, n.after.Sub(sends[0]))
		}
	}
	// And the first handshake landed: a's packet was dropped by b's NAT, b's arrived at an open door.
	if b.nat.droppedFrom(a.endpoint(t)) == 0 {
		t.Fatal("b's NAT never dropped a's opening packet, so the NAT was not in the way and this proves nothing")
	}
	if !routedTo(t, a.tun, b.pubHex, b.addr) || !boxStillHasDefaultRoute(t, a.tun) {
		t.Fatal("the direct path is not what the device routes, or the relay lost ::/0")
	}
	st := a.tun.DirectPeers()[0]
	if st.Punch.Phase != PunchEstablished || st.Punch.WinnerSource != SourceObserved {
		t.Fatalf("state = %+v, want established at the observed endpoint", st)
	}
	// Traffic for b's /128 reaches b. a's box does not answer for that address, so only the direct path
	// can carry it.
	if err := echoThroughTunnel(t, a.tun, net.JoinHostPort(b.addr.String(), strconv.Itoa(echoPort)), 10*time.Second); err != nil {
		t.Fatalf("the direct path carries nothing: %v", err)
	}
	// Promoted with its own keepalive, so the far side keeps seeing it on an idle path.
	if _, ka, _ := peerSection(t, a.tun, b.pubHex); ka != strconv.Itoa(directKeepalive) {
		t.Fatalf("a promoted peer's keepalive is %q, want %d", ka, directKeepalive)
	}

	// The cross-box read: the box that has not observed the pair lists b with no advice. A proven path
	// survives it.
	listed, _ := ListedPeer(b.addr.String(), "")
	listed.Hold = true // the verdict a box with no observation gives: unknown
	if err := a.tun.SetDirectPeers([]Peer{listed}); err != nil {
		t.Fatalf("SetDirectPeers (no advice): %v", err)
	}
	if a.tun.PathTo(b.addr) != pathDirectPunch || !routedTo(t, a.tun, b.pubHex, b.addr) {
		t.Fatalf("a read with no advice tore down a proven path: %+v", a.tun.DirectPeers())
	}
	// A read that names a different key for that /128 does not keep it: the plane says the address is
	// someone else's key now.
	other, _ := ListedPeer(b.addr.String(), testPeerKeyB64)
	other.Hold = true
	if err := a.tun.SetDirectPeers([]Peer{other}); err != nil {
		t.Fatalf("SetDirectPeers (another key): %v", err)
	}
	if present, _, _ := peerSection(t, a.tun, b.pubHex); present || a.tun.PathTo(b.addr) != "relayed" {
		t.Fatal("a peer survived a read that names another key for its address")
	}
	// And on b, a read without the row at all is a revocation, promoted or not.
	if err := b.tun.SetDirectPeers(nil); err != nil {
		t.Fatalf("SetDirectPeers (revoked): %v", err)
	}
	if present, _, _ := peerSection(t, b.tun, a.pubHex); present || len(b.tun.DirectPeers()) != 0 {
		t.Fatal("a revoked peer is still on the device")
	}
}

// TestRelayedPunch_TheOrderInTheWindowLandsTheFirstHandshakeOverASlowPath is the case the order exists
// for. Each NAT takes 250 ms to deliver, longer than the 50 ms the two monitors can be apart, so two ends
// that sent together would both have a handshake on the wire before either arrived: each would pass the
// far NAT, each end would turn responder, neither answer would match an initiation, and the pair would
// wait for WireGuard's retry, whose third of a second of jitter cannot separate two ends a quarter of a
// second apart. Sending in the window's order, the opener's packet is dropped and the far end's lands,
// so the pair goes direct at the first attempt, long before any retry.
func TestRelayedPunch_TheOrderInTheWindowLandsTheFirstHandshakeOverASlowPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake NAT punch test in -short")
	}
	natA, natB := newNatBind(10*time.Second), newNatBind(10*time.Second)
	natA.delay, natB.delay = 250*time.Millisecond, 250*time.Millisecond
	a := startNatNode(t, "2a04:2a01:4::a", natA, nil, 7048, fastOpts())
	b := startNatNode(t, "2a04:2a01:4::b", natB, nil, 7049, fastOpts())

	base := time.Now()
	w := Rendezvous{At: base.Add(700 * time.Millisecond), Until: base.Add(2200 * time.Millisecond), Period: 30 * time.Second, Slot: 5000}
	if err := a.tun.SetDirectPeers([]Peer{relayedPeer(t, b, w)}); err != nil {
		t.Fatal(err)
	}
	if err := b.tun.SetDirectPeers([]Peer{relayedPeer(t, a, w)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(15*time.Second, func() bool {
		return a.tun.PathTo(b.addr) == pathDirectPunch && b.tun.PathTo(a.addr) == pathDirectPunch
	}) {
		t.Fatalf("the pair never went direct over a slow path: a=%+v b=%+v", a.tun.DirectPeers(), b.tun.DirectPeers())
	}
	if took := time.Since(w.At); took > 4*time.Second {
		t.Fatalf("direct only after %v: the first handshakes crossed and it took a retry", took)
	}
}

// TestRelayedPunch_TwoNatsMissedWindowsNeverMeet is the control. Same nodes, same NATs, but the two ends
// are given windows that do not overlap, so each one's handshake reaches the other's NAT after the
// mapping its own last send opened has expired. If the filter were not real, this pair would go direct
// anyway and the test above would prove nothing.
func TestRelayedPunch_TwoNatsMissedWindowsNeverMeet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake NAT punch test in -short")
	}
	// A mapping lifetime of half a second, and windows half a period apart: each end's handshakes, and
	// the device's retries of them, land on the far NAT long after the far end last sent.
	a := startNatNode(t, "2a04:2a01:4::a", newNatBind(500*time.Millisecond), nil, 7043, fastOpts())
	b := startNatNode(t, "2a04:2a01:4::b", newNatBind(500*time.Millisecond), nil, 7044, fastOpts())

	base := time.Now()
	period := 14 * time.Second
	wa := Rendezvous{At: base.Add(500 * time.Millisecond), Until: base.Add(time.Second), Period: period, Slot: 2000}
	wb := Rendezvous{At: base.Add(7500 * time.Millisecond), Until: base.Add(8 * time.Second), Period: period, Slot: 2000}
	if err := a.tun.SetDirectPeers([]Peer{relayedPeer(t, b, wa)}); err != nil {
		t.Fatal(err)
	}
	if err := b.tun.SetDirectPeers([]Peer{relayedPeer(t, a, wb)}); err != nil {
		t.Fatal(err)
	}
	deadline := base.Add(period + 2*time.Second)
	for time.Now().Before(deadline) {
		if a.tun.PathTo(b.addr) != "relayed" || b.tun.PathTo(a.addr) != "relayed" {
			t.Fatalf("two NATs with disjoint windows went direct, so the NAT filter is not filtering: %+v", a.tun.DirectPeers())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if b.nat.droppedFrom(a.endpoint(t)) == 0 || a.nat.droppedFrom(b.endpoint(t)) == 0 {
		t.Fatalf("neither NAT dropped the other's handshake (b dropped %d, a dropped %d): the punch was never tried",
			b.nat.droppedFrom(a.endpoint(t)), a.nat.droppedFrom(b.endpoint(t)))
	}
}

// TestRelayedPunch_ATimedOutPunchStaysRelayedSilentAndLeaksNothing: the far side never answers. The train
// attends its window, waits out the grace, and silences the device: the peer stays on it with no
// allowed-ips and no keepalive, the relay keeps carrying the /128, and nothing at all is sent at the
// peer outside the windows the train attends. When the advice is withdrawn, the peer goes.
func TestRelayedPunch_ATimedOutPunchStaysRelayedSilentAndLeaksNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake NAT punch test in -short")
	}
	const echoPort = 7045
	farIP := mustAddr(t, "2a04:2a01:4::b")
	// The box carries the far /128, so the relay is a real path to it.
	a := startNatNode(t, "2a04:2a01:4::a", newNatBind(time.Second), []netip.Addr{farIP}, echoPort, fastOpts())

	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	base := time.Now()
	w := Rendezvous{At: base.Add(400 * time.Millisecond), Until: base.Add(900 * time.Millisecond), Period: 12 * time.Second, Slot: 3000}
	farKey := strings.Repeat("5a", 32)
	peer := Peer{
		Address: farIP, PublicKeyHex: farKey, Endpoint: dead, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: w,
	}
	if err := a.tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	if !waitFor(15*time.Second, func() bool {
		st := a.tun.DirectPeers()
		return len(st) == 1 && st[0].Punch.Phase == PunchGaveUp
	}) {
		t.Fatalf("the missed window never ended in a give-up: %+v", a.tun.DirectPeers())
	}
	quietSeen := time.Now()
	// Silent and unrouted, on the device's own word. The quiet is written right after the phase moves,
	// so it is waited for rather than read once.
	if !waitFor(2*time.Second, func() bool {
		present, ka, allowed := peerSection(t, a.tun, farKey)
		return present && ka == "0" && len(allowed) == 0
	}) {
		present, ka, allowed := peerSection(t, a.tun, farKey)
		t.Fatalf("after the window: present=%v keepalive=%q allowed=%v, want on the device, silent, unrouted", present, ka, allowed)
	}
	if a.tun.PathTo(farIP) != "relayed" || routedTo(t, a.tun, farKey, farIP) || !boxStillHasDefaultRoute(t, a.tun) {
		t.Fatal("a peer that never answered holds the /128, or the relay lost ::/0")
	}
	if err := echoThroughTunnel(t, a.tun, net.JoinHostPort(farIP.String(), strconv.Itoa(echoPort)), 10*time.Second); err != nil {
		t.Fatalf("the relay stopped carrying a peer whose punch timed out: %v", err)
	}

	// Bounded: the window cost the aimed handshake and the device's retry, nothing went out before the
	// window, and after the silence nothing goes out at all. Slot 3001 (at 12.4 s) is odd, so a train
	// that missed once skips it; the next one it attends is 3002 at 24.4 s, past this test.
	time.Sleep(time.Until(base.Add(w.Period + 2*time.Second)))
	sends := a.nat.sendsTo(dead)
	if len(sends) == 0 || len(sends) > 3 {
		t.Fatalf("%d packets went to the peer for one window, want one to three", len(sends))
	}
	for _, at := range sends {
		if at.Before(w.At) || at.After(quietSeen) {
			t.Fatalf("a packet went to the peer at %v from the window's opening, outside the attended window (silenced by %v)",
				at.Sub(w.At), quietSeen.Sub(w.At))
		}
	}

	// The plane stops advising (or the other box answers): an unpromoted peer is removed, entirely.
	listed, _ := ListedPeer(farIP.String(), "")
	if err := a.tun.SetDirectPeers([]Peer{listed}); err != nil {
		t.Fatalf("SetDirectPeers (advice withdrawn): %v", err)
	}
	if present, _, _ := peerSection(t, a.tun, farKey); present || len(a.tun.DirectPeers()) != 0 {
		t.Fatal("an unpromoted peer outlived the advice it was installed from")
	}
}

// TestRelayedPunch_APublicHostAnswersANattedPeerFromTheAdvice is the one-sided PUBLIC pair. The node behind
// the NAT is offered direct-public for the host whose observed endpoint is its declared one, and dials
// it untimed, as it always has. The public host's row for the NATed node is relayed, and its only
// statement of that node's key is the punch advice. Without it the public host's device does not know
// the key and drops the handshake, which is what this pair did before the advice was read. With it, the
// public host holds the peer silent, answers, and both ends go direct.
func TestRelayedPunch_APublicHostAnswersANattedPeerFromTheAdvice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake NAT punch test in -short")
	}
	natted := startNatNode(t, "2a04:2a01:4::a", newNatBind(2*time.Second), nil, 7046, fastOpts())
	public := startNatNode(t, "2a04:2a01:4::b", nil, nil, 7047, fastOpts())

	// The NATed node's direct-public row: the public host's declared endpoint, untimed.
	if err := natted.tun.SetDirectPeers([]Peer{{
		Address: public.addr, PublicKeyHex: public.pubHex, Endpoint: public.endpoint(t), Path: "direct-public",
		Candidates: []Candidate{{Endpoint: public.endpoint(t), Source: SourcePublic}},
	}}); err != nil {
		t.Fatal(err)
	}
	// The public host has not read the advice yet: it does not know the key, and the pair stays relayed.
	time.Sleep(1500 * time.Millisecond)
	if natted.tun.PathTo(public.addr) != "relayed" {
		t.Fatal("a handshake completed with a host that holds no peer for this key")
	}
	// Now it does, from the relayed row's advice, with a window that is a whole period away. It does not
	// need the window: it is not behind a NAT, so the NATed node's own initiation reaches it and it answers.
	base := time.Now()
	far := Rendezvous{At: base.Add(30 * time.Second), Until: base.Add(31 * time.Second), Period: time.Minute, Slot: 4000}
	if err := public.tun.SetDirectPeers([]Peer{relayedPeer(t, natted, far)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(15*time.Second, func() bool {
		return natted.tun.PathTo(public.addr) == "direct-public" && public.tun.PathTo(natted.addr) == pathDirectPunch
	}) {
		t.Fatalf("the public host never answered: natted=%+v public=%+v", natted.tun.DirectPeers(), public.tun.DirectPeers())
	}
	// Promoted by the far side's handshake while silent, it now keeps the path alive itself.
	if _, ka, _ := peerSection(t, public.tun, natted.pubHex); ka != strconv.Itoa(directKeepalive) {
		t.Fatalf("a silent peer promoted by the far side's handshake has keepalive %q, want %d", ka, directKeepalive)
	}
}

// farWindow is a window that will not open during a test, so a timed peer is armed and tracked and
// sends nothing.
func farWindow() Rendezvous {
	at := time.Now().Add(time.Hour)
	return Rendezvous{At: at, Until: at.Add(6 * time.Second), Period: 2 * time.Hour, Slot: 7}
}

// TestRelayedPunch_ReadsAlternatingBetweenBoxesKeepTheTrainAndItsBackoff: the front door picks a box per
// read, and only the box that observed both tunnels advises the pair, so a timed peer's advice comes and
// goes. A read whose verdict is "unknown" keeps the peer, its place on the window schedule and its
// backoff; ten such reads in a row, a refusal, or a row that is gone removes it.
func TestRelayedPunch_ReadsAlternatingBetweenBoxesKeepTheTrainAndItsBackoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a := startNatNode(t, "2a04:2a01:4::a", nil, nil, 7050, fastOpts())
	farIP := mustAddr(t, "2a04:2a01:4::b")
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	key := strings.Repeat("6b", 32)
	advised := Peer{Address: farIP, PublicKeyHex: key, Endpoint: dead, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: farWindow()}
	unknown, _ := ListedPeer(farIP.String(), "")
	unknown.Hold = true
	refused, _ := ListedPeer(farIP.String(), "") // "unlikely": listed, but not a hold

	if err := a.tun.SetDirectPeers([]Peer{advised}); err != nil {
		t.Fatal(err)
	}
	tracked := func() *directPeer {
		a.tun.mu.Lock()
		defer a.tun.mu.Unlock()
		return a.tun.direct[key]
	}
	first := tracked()
	if first == nil {
		t.Fatal("the advised peer was not installed")
	}
	a.tun.mu.Lock()
	first.punch.missed = 3 // a backoff earned over earlier windows
	a.tun.mu.Unlock()

	for i := 0; i < 40; i++ {
		next := advised
		if i%2 == 1 {
			next = unknown
		}
		if err := a.tun.SetDirectPeers([]Peer{next}); err != nil {
			t.Fatal(err)
		}
		d := tracked()
		if d != first {
			t.Fatalf("read %d: the peer was re-armed or removed by a read from the other box", i)
		}
		a.tun.mu.Lock()
		missed := d.punch.missed
		a.tun.mu.Unlock()
		if missed != 3 {
			t.Fatalf("read %d: the backoff was reset (missed %d) by reads flapping between boxes", i, missed)
		}
	}
	// Bounded: ten reads in a row with no evidence keep it, the eleventh does not. An advised read first,
	// which is what resets the count.
	_ = a.tun.SetDirectPeers([]Peer{advised})
	for i := 1; i <= maxHeldReads; i++ {
		_ = a.tun.SetDirectPeers([]Peer{unknown})
		if tracked() == nil {
			t.Fatalf("removed after %d reads with no evidence, want %d kept", i, maxHeldReads)
		}
	}
	_ = a.tun.SetDirectPeers([]Peer{unknown})
	if present, _, _ := peerSection(t, a.tun, key); present || tracked() != nil {
		t.Fatal("a peer outlived maxHeldReads reads with no evidence")
	}
	// And in time, whatever the refresh interval: held once, then aged past maxHeldAge.
	_ = a.tun.SetDirectPeers([]Peer{advised})
	_ = a.tun.SetDirectPeers([]Peer{unknown})
	a.tun.mu.Lock()
	aged := a.tun.direct[key]
	aged.heldSince = aged.heldSince.Add(-maxHeldAge)
	a.tun.mu.Unlock()
	_ = a.tun.SetDirectPeers([]Peer{unknown})
	if tracked() != nil {
		t.Fatal("a peer outlived maxHeldAge on rows with no evidence")
	}
	// A refusal removes at once.
	_ = a.tun.SetDirectPeers([]Peer{advised})
	_ = a.tun.SetDirectPeers([]Peer{refused})
	if present, _, _ := peerSection(t, a.tun, key); present || tracked() != nil {
		t.Fatal("a peer survived a read that refused the pair")
	}
}

// TestRelayedPunch_APunchedPathThatDiesIsWithdrawnSilencedAndRescheduled: demoting a timed peer withdraws
// the /128 and silences it in one write, and puts it back on the window schedule from the first rung,
// rather than leaving a keepalive initiating every five seconds for ever.
func TestRelayedPunch_APunchedPathThatDiesIsWithdrawnSilencedAndRescheduled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake punch test in -short")
	}
	opts := fastOpts()
	opts.DirectDeadAfter = 3 * peerSideKeepalive * time.Second
	a := startNatNode(t, "2a04:2a01:4::9", nil, nil, 7051, opts)
	other := startPeerSide(t, a.pubHex, a.addr) // the far agent, at 2a04:2a01:4::7

	live := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String()
	base := time.Now()
	w := Rendezvous{At: base.Add(300 * time.Millisecond), Until: base.Add(800 * time.Millisecond), Period: 10 * time.Second, Slot: 6000}
	peer := Peer{Address: mustAddr(t, "2a04:2a01:4::7"), PublicKeyHex: other.pubHex, Endpoint: live, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: live, Source: SourceObserved}}, Rendezvous: w}
	if err := a.tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(10*time.Second, func() bool { return a.tun.PathTo(peer.Address) == pathDirectPunch }) {
		t.Fatalf("never went direct: %+v", a.tun.DirectPeers())
	}
	other.dev.Close()
	if !waitFor(10*time.Second, func() bool { return a.tun.PathTo(peer.Address) == "relayed" }) {
		t.Fatalf("a dead punched path was never withdrawn: %+v", a.tun.DirectPeers())
	}
	if !waitFor(2*time.Second, func() bool {
		present, ka, allowed := peerSection(t, a.tun, other.pubHex)
		return present && ka == "0" && len(allowed) == 0
	}) {
		present, ka, allowed := peerSection(t, a.tun, other.pubHex)
		t.Fatalf("after the demotion: present=%v keepalive=%q allowed=%v, want withdrawn and silent", present, ka, allowed)
	}
	a.tun.mu.Lock()
	d := a.tun.direct[other.pubHex]
	missed, attending := d.punch.missed, d.punch.attending
	a.tun.mu.Unlock()
	if missed != 0 || attending {
		t.Fatalf("a demoted timed peer was not put back on the schedule from the first rung: missed %d attending %v", missed, attending)
	}
}

// TestSetDirectPeers_CapsTimedPeersAndRefusesOurOwnKey: a peer map of more advised rows than the cap
// installs the pairs with the lowest pairRank up to it, the same set on every read; a row naming this
// tunnel's own key, or its own address, installs nothing.
func TestSetDirectPeers_CapsTimedPeersAndRefusesOurOwnKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a := startNatNode(t, "2a04:2a01:4::a", nil, nil, 7052, fastOpts())
	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	var peers []Peer
	for i := maxTimedPeers + 10; i > 0; i-- { // highest address first: the order of the read must not matter
		addr := netip.AddrFrom16([16]byte{0x2a, 0x04, 0x2a, 0x01, 0, 5, 14: byte(i >> 8), 15: byte(i)})
		key := strings.Repeat("0", 60) + strconv.FormatInt(int64(0x1000+i), 16)
		peers = append(peers, Peer{Address: addr, PublicKeyHex: key, Endpoint: dead, Path: pathDirectPunch,
			Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: farWindow()})
	}
	self := Peer{Address: mustAddr(t, "2a04:2a01:4::c"), PublicKeyHex: a.pubHex, Endpoint: dead, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: farWindow()}
	ownAddr := Peer{Address: a.addr, PublicKeyHex: strings.Repeat("7c", 32), Endpoint: dead, Path: pathDirectPunch,
		Candidates: []Candidate{{Endpoint: dead, Source: SourceObserved}}, Rendezvous: farWindow()}
	ranked := append([]Peer(nil), peers...)
	sort.Slice(ranked, func(i, j int) bool { return pairRank(a.addr, ranked[i].Address) < pairRank(a.addr, ranked[j].Address) })
	want := map[netip.Addr]bool{}
	for _, p := range ranked[:maxTimedPeers] {
		want[p.Address] = true
	}
	for round := 0; round < 2; round++ {
		if err := a.tun.SetDirectPeers(append([]Peer{self, ownAddr}, peers...)); err != nil {
			t.Fatal(err)
		}
		st := a.tun.DirectPeers()
		if len(st) != maxTimedPeers {
			t.Fatalf("round %d: %d timed peers installed, want the cap of %d", round, len(st), maxTimedPeers)
		}
		for _, p := range st {
			if p.Address.As16()[15] == 0 && p.Address.As16()[14] == 0 {
				t.Fatalf("round %d: our own key was installed as a peer", round)
			}
			if !want[p.Address] {
				t.Fatalf("round %d: %s is not among the %d pairs with the lowest pair rank", round, p.Address, maxTimedPeers)
			}
		}
	}
	if present, _, _ := peerSection(t, a.tun, a.pubHex); present {
		t.Fatal("a row naming our own key reached the device")
	}
	if present, _, _ := peerSection(t, a.tun, ownAddr.PublicKeyHex); present {
		t.Fatal("a row naming our own address reached the device")
	}
}
