// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// whale_punch_test.go is the traversal against REAL devices: two wireguard-go instances on
// loopback, a real handshake, and the device's own UAPI dump as the source of every assertion.
// Nothing here asserts against a mock of our own bookkeeping - a data structure that says
// "promoted" proves nothing about where a packet will actually go.
//
// The headline is TestFailedPunch_CostsLatencyNotReachability, which is the invariant the whole
// design is arranged around and the one that must never be allowed to regress.

// relayBox is a box-side device that ALSO answers on addresses other than its own - which is
// what a Whisper box does for every agent /128 it delivers, and what makes it possible to prove
// that traffic for a peer's /128 is being carried by the relay rather than by a direct peer.
type relayBox struct {
	dev      *device.Device
	pubB64   string
	udpPort  int
	serverIP netip.Addr
}

func startRelayBox(t *testing.T, clientPubHex string, clientTunnelIP netip.Addr, serve []netip.Addr, echoPort int) *relayBox {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("box keypair: %v", err)
	}
	tunDev, tnet, err := netstack.CreateNetTUN(serve, nil, defaultMTU)
	if err != nil {
		t.Fatalf("box netstack: %v", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	udpPort := freeUDPPort(t)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", kp.PrivateKeyHex, udpPort)
	uapi += fmt.Sprintf("public_key=%s\nallowed_ip=%s/128\n", clientPubHex, clientTunnelIP.String())
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("box IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("box Up: %v", err)
	}
	t.Cleanup(dev.Close)
	// One echo listener per address the box delivers, so a dial to a PEER's /128 that was
	// relayed is answered exactly as the live box's AnyIP delivery answers it.
	for _, addr := range serve {
		ln, lerr := tnet.ListenTCP(&net.TCPAddr{IP: addr.AsSlice(), Port: echoPort})
		if lerr != nil {
			t.Fatalf("box listen on %s: %v", addr, lerr)
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
	return &relayBox{dev: dev, pubB64: kp.PublicKeyBase64, udpPort: udpPort, serverIP: serve[0]}
}

// deadUDPPort returns a loopback port nothing is listening on: an endpoint that will never
// answer a handshake, which is what a failed punch looks like from the inside. Loopback keeps
// the test from emitting a single packet at the internet.
func deadUDPPort(t *testing.T) int { return freeUDPPort(t) }

// echoThroughTunnel proves the tunnel actually carries traffic to target right now.
func echoThroughTunnel(t *testing.T, tun *Tunnel, target string, within time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		c, err := socks5Dial(tun.Addr(), target)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		msg := "still-reachable"
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, werr := c.Write([]byte(msg)); werr != nil {
			_ = c.Close()
			lastErr = werr
			continue
		}
		buf := make([]byte, len(msg))
		_, rerr := io.ReadFull(c, buf)
		_ = c.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if string(buf) != msg {
			return fmt.Errorf("echo returned %q", buf)
		}
		return nil
	}
	return fmt.Errorf("nothing came back through the tunnel: %v", lastErr)
}

// TestFailedPunch_CostsLatencyNotReachability IS the invariant.
//
// A peer is installed whose every candidate endpoint is dead. The punch runs its full train and
// fails, exactly as it would for a pair behind two NATs that vary their ports. Throughout, and
// afterwards, traffic to that peer's /128 must keep flowing - through the box, which is what
// carries it.
//
// This test fails if the /128 is ever handed to the direct peer before a handshake has landed.
// That is not a hypothetical ordering bug: WireGuard has no failover between peers, so a
// destination routed to a peer that never answers is DROPPED, not relayed. Move the promotion
// ahead of the handshake check - or let a punch write an allowed-ip - and the echo below stops
// coming back, which is precisely what a user would experience.
func TestFailedPunch_CostsLatencyNotReachability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake punch test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	peerIP := mustAddr(t, "2a04:2a01:4::7")
	const echoPort = 7020

	// The box delivers its own address AND the peer's /128, which is what makes the relay a real
	// path to that peer rather than a stand-in for one.
	box := startRelayBox(t, clientPubHex, clientIP, []netip.Addr{mustAddr(t, "2a04:2a01:0:53::1"), peerIP}, echoPort)

	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	cfg.Keepalive = 1
	stateDir := t.TempDir()
	tun, err := Start(cfg, Options{
		HealthInterval:  100 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 10 * time.Second,
		PunchEvery:      120 * time.Millisecond, // a whole train in about a second and a half
		PathStateDir:    stateDir,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	// Two candidates, both loopback ports nothing is listening on. This is a punch that cannot
	// possibly succeed, which is the case we have to be safe in.
	dead1 := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	dead2 := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	peer := Peer{
		Address:      peerIP,
		PublicKeyHex: strings.Repeat("5a", 32),
		Endpoint:     dead1,
		Name:         "db-01",
		Path:         "direct-punch",
		Candidates: []Candidate{
			{Endpoint: dead1, Source: SourceObserved},
			{Endpoint: dead2, Source: SourcePublic},
		},
	}
	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}

	// WHILE the punch is in flight, the peer's /128 is still reachable. This is the assertion
	// that catches a promotion moved ahead of the handshake check.
	if err := echoThroughTunnel(t, tun, net.JoinHostPort(peerIP.String(), strconv.Itoa(echoPort)), 15*time.Second); err != nil {
		t.Fatalf("the peer became unreachable while its punch was still being attempted: %v", err)
	}
	if routedTo(t, tun, peer.PublicKeyHex, peerIP) {
		t.Fatal("the /128 was routed to a peer that has never handshaked - that destination would black-hole")
	}

	// The train runs out and says so, rather than reporting the absence of a direct path.
	if !waitFor(20*time.Second, func() bool {
		for _, st := range tun.DirectPeers() {
			if st.Address == peerIP && st.Punch.Phase == PunchGaveUp {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the punch never reported giving up: %+v", tun.DirectPeers())
	}
	st := tun.DirectPeers()[0]
	if st.Promoted || st.Path != "relayed" {
		t.Fatalf("a peer that never handshaked claims a path: %+v", st)
	}
	if st.Punch.Attempts != punchTrainAttempts {
		t.Fatalf("attempts = %d, want a full train of %d", st.Punch.Attempts, punchTrainAttempts)
	}
	if st.Punch.Candidates != 2 {
		t.Fatalf("candidates = %d, want both endpoints to have been tried", st.Punch.Candidates)
	}

	// And AFTER the failure, the peer is still reachable. A failed punch costs latency. It does
	// not cost reachability, and this is the line that says so in packets.
	if err := echoThroughTunnel(t, tun, net.JoinHostPort(peerIP.String(), strconv.Itoa(echoPort)), 10*time.Second); err != nil {
		t.Fatalf("the peer became unreachable after its punch failed: %v", err)
	}
	if !boxStillHasDefaultRoute(t, tun) {
		t.Fatal("the box peer lost ::/0, so the relay would not have been there to fall back to")
	}
	if routedTo(t, tun, peer.PublicKeyHex, peerIP) {
		t.Fatal("the /128 ended up routed to a peer that never answered")
	}

	// The published record says the same thing, because a surface in another process has to be
	// able to tell "relayed because the punch failed" from "relayed, nothing was tried".
	//
	// Waited for, not read once. The assertion above is about the state in THIS process; the
	// record is written by the health monitor on its next reconcile, so between the phase
	// advancing and the file catching up there is a window that exists by design. Reading
	// inside it caught a record still saying `punching` and called the product broken, on a
	// loaded box, twice in three runs. The sibling test below has always waited here.
	if !waitFor(10*time.Second, func() bool {
		rec := readPublishedRecord(t, stateDir, clientIP.String())
		pr, ok := rec.PeerFor(peerIP.String())
		return ok && !pr.Promoted && pr.Punch.Phase == string(PunchGaveUp)
	}) {
		rec := readPublishedRecord(t, stateDir, clientIP.String())
		pr, ok := rec.PeerFor(peerIP.String())
		if !ok {
			t.Fatalf("the peer is missing from the published path record: %+v", rec)
		}
		t.Fatalf("the published record never reported the failure: %+v", pr)
	}
}

// TestPunch_RotatesToAWorkingCandidateAndPromotesOnTheHandshake: the first endpoint is dead and
// the second is a real peer, which is the shape of every real candidate list (a private address
// that may or may not be on our segment, and the endpoint a box observed). The train has to
// reach the second one, and the /128 may move only once a handshake has actually landed.
func TestPunch_RotatesToAWorkingCandidateAndPromotesOnTheHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake punch test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	peerIP := mustAddr(t, "2a04:2a01:4::7")

	box := startRelayBox(t, clientPubHex, clientIP, []netip.Addr{mustAddr(t, "2a04:2a01:0:53::1")}, 7021)
	other := startPeerSide(t, clientPubHex, clientIP)

	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	stateDir := t.TempDir()
	tun, err := Start(cfg, Options{
		HealthInterval:  100 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 10 * time.Second,
		PunchEvery:      150 * time.Millisecond,
		PathStateDir:    stateDir,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	dead := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(deadUDPPort(t))).String()
	live := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String()
	peer := Peer{
		Address:      peerIP,
		PublicKeyHex: other.pubHex,
		Endpoint:     dead,
		Name:         "db-01",
		Path:         "direct-punch",
		Candidates: []Candidate{
			{Endpoint: dead, Source: SourceLocal},    // a private address that is not on our segment
			{Endpoint: live, Source: SourceObserved}, // what a box saw the peer arrive from
		},
	}
	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	// Armed at the first candidate, and nothing is routed to it.
	if routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("a freshly armed peer already holds the /128")
	}

	if !waitFor(15*time.Second, func() bool { return tun.PathTo(peerIP) == "direct-punch" }) {
		t.Fatalf("the punch never reached the working candidate: %+v", tun.DirectPeers())
	}
	if !routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("the tunnel reported a direct path the device was not actually routing")
	}
	if !boxStillHasDefaultRoute(t, tun) {
		t.Fatal("the box peer lost ::/0 while a direct path was up")
	}
	st := tun.DirectPeers()[0]
	if st.Punch.Phase != PunchEstablished {
		t.Fatalf("phase = %q, want %q", st.Punch.Phase, PunchEstablished)
	}
	if st.Punch.Attempts < 2 {
		t.Fatalf("attempts = %d: the path came up without the train ever rotating off the dead "+
			"candidate, so this test is not proving rotation", st.Punch.Attempts)
	}
	if st.Punch.Winner != live {
		t.Fatalf("winner = %q, want the endpoint that actually carried the handshake (%q)", st.Punch.Winner, live)
	}
	if st.Endpoint != live {
		t.Fatalf("the reported endpoint is %q, not the one carrying the path", st.Endpoint)
	}

	// A refresh that re-orders the candidate list must NOT reset a working path. The control
	// plane republishes this map every minute; if a re-ordered list tore the peer down and
	// re-armed it, every direct pair in a fleet would flap on that interval.
	reordered := peer
	reordered.Candidates = []Candidate{
		{Endpoint: live, Source: SourceObserved},
		{Endpoint: dead, Source: SourceLocal},
	}
	reordered.Endpoint = live
	reordered.Name = "db-01-renamed"
	if err := tun.SetDirectPeers([]Peer{reordered}); err != nil {
		t.Fatalf("SetDirectPeers (refresh): %v", err)
	}
	if got := tun.PathTo(peerIP); got != "direct-punch" {
		t.Fatalf("a refresh with a re-ordered candidate list dropped a working path: %q", got)
	}
	if !routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("a refresh withdrew the /128 from a peer whose path was up")
	}
	if tun.DirectPeers()[0].Name != "db-01-renamed" {
		t.Fatal("the refresh did not update the label it was supposed to")
	}

	// And the published record carries the same verdict, with the endpoint that won it.
	if !waitFor(5*time.Second, func() bool {
		rec := readPublishedRecord(t, stateDir, clientIP.String())
		pr, ok := rec.PeerFor(peerIP.String())
		return ok && pr.Promoted && pr.Punch.Phase == string(PunchEstablished) && pr.Punch.Winner == live
	}) {
		t.Fatalf("the published record never caught up with the direct path: %+v",
			readPublishedRecord(t, stateDir, clientIP.String()))
	}
}

// TestPunch_ADeadDirectPathFallsBackAndIsPunchedAgain: the demote is the same move backwards,
// and the next train starts at the endpoint that worked rather than at the top of the list.
func TestPunch_ADeadDirectPathFallsBackAndIsPunchedAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake punch test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	peerIP := mustAddr(t, "2a04:2a01:4::7")
	const echoPort = 7022

	box := startRelayBox(t, clientPubHex, clientIP, []netip.Addr{mustAddr(t, "2a04:2a01:0:53::1"), peerIP}, echoPort)
	other := startPeerSide(t, clientPubHex, clientIP)

	cfg, _ := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", kp.PrivateKeyHex)
	tun, err := Start(cfg, Options{
		HealthInterval:  100 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 700 * time.Millisecond,
		PunchEvery:      150 * time.Millisecond,
		PathStateDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	live := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String()
	peer := Peer{
		Address:      peerIP,
		PublicKeyHex: other.pubHex,
		Endpoint:     live,
		Path:         "direct-punch",
		Candidates:   []Candidate{{Endpoint: live, Source: SourceObserved}},
	}
	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	if !waitFor(10*time.Second, func() bool { return tun.PathTo(peerIP) == "direct-punch" }) {
		t.Fatalf("the path never came up: %+v", tun.DirectPeers())
	}

	other.dev.Close() // the direct path dies

	if !waitFor(10*time.Second, func() bool { return tun.PathTo(peerIP) == "relayed" }) {
		t.Fatalf("a dead direct path was never withdrawn - that /128 would black-hole: %+v", tun.DirectPeers())
	}
	// The traffic keeps flowing, over the relay, because the box never stopped holding ::/0.
	if err := echoThroughTunnel(t, tun, net.JoinHostPort(peerIP.String(), strconv.Itoa(echoPort)), 10*time.Second); err != nil {
		t.Fatalf("the peer was unreachable after its direct path died: %v", err)
	}
	// And it is being punched again rather than left relayed forever.
	if !waitFor(10*time.Second, func() bool {
		for _, st := range tun.DirectPeers() {
			if st.Address == peerIP && st.Punch.Trains >= 2 {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("no second punch train was started after the path died: %+v", tun.DirectPeers())
	}
}

// readPublishedRecord reads the record the tunnel publishes for one node address.
func readPublishedRecord(t *testing.T, dir, address string) PathStateRecord {
	t.Helper()
	name := strings.ReplaceAll(address, ":", "_") + ".json"
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return PathStateRecord{}
	}
	var rec PathStateRecord
	if uerr := json.Unmarshal(b, &rec); uerr != nil {
		t.Fatalf("the published path record is not readable JSON: %v", uerr)
	}
	return rec
}
