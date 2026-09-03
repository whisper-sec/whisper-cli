// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// whale_peermap_test.go is the direct-path half on the client side.
//
// The promote/demote test is a REAL second wireguard-go device on loopback, handshaking for
// real, exactly as tunnel_test.go does for the box side. Nothing here asserts against a mock of
// our own code: the promotion is read back out of the DEVICE's own UAPI dump, so a change that
// stopped actually installing the /128 fails this test even if every one of our data structures
// still said "promoted".

// ==========================================================================================
// ParsePeer: the client re-checks everything the server checked, because this is the side that
// sends the packets and a peer entry is a routing grant.
// ==========================================================================================

const testPeerKeyB64 = "YTItcGVlci1rZXktMzItYnl0ZXMtbG9uZy1wYWQhISE="

func TestParsePeer_AcceptsAWellFormedRow(t *testing.T) {
	p, err := ParsePeer(testPeerKeyB64, "192.168.122.31:51820", "2a04:2a01:4::7", "db-01", "direct-local")
	if err != nil {
		t.Fatalf("a well-formed peer row was refused: %v", err)
	}
	if p.Address.String() != "2a04:2a01:4::7" {
		t.Fatalf("address: got %q", p.Address.String())
	}
	if len(p.PublicKeyHex) != 64 {
		t.Fatalf("the public key should be 32 bytes of hex, got %d chars", len(p.PublicKeyHex))
	}
	if p.Path != "direct-local" || p.Name != "db-01" {
		t.Fatalf("the row's own labels were dropped: %+v", p)
	}
}

func TestParsePeer_RefusesAnAddressOutsideTheAgentBlock(t *testing.T) {
	// The load-bearing check. A peer whose AllowedIPs sat outside 2a04:2a01::/32 - or covered
	// more than one address - could, by cryptokey routing, source traffic as everything it
	// covered. That is the entire property the tunnel exists to provide.
	for _, bad := range []string{"2001:db8::1", "::/0", "2a04:2a01::/32", "10.0.0.1"} {
		if _, err := ParsePeer(testPeerKeyB64, "192.168.1.2:51820", bad, "x", ""); err == nil {
			t.Fatalf("accepted a peer address outside one agent /128: %q", bad)
		}
	}
}

func TestParsePeer_RefusesEveryEndpointWeMustNotAimATunnelAt(t *testing.T) {
	cases := map[string]string{
		"loopback v4":      "127.0.0.1:51820",
		"loopback v6":      "[::1]:51820",
		"our own overlay":  "[2a04:2a01:4::9]:51820",
		"internal tailnet": "100.64.0.1:51820",
		"link-local":       "[fe80::1]:51820",
		"multicast":        "239.1.1.1:51820",
		"unspecified":      "0.0.0.0:51820",
		"a hostname":       "peer.example.com:51820",
		"no port":          "192.168.1.2",
		"port zero":        "192.168.1.2:0",
		"port too large":   "192.168.1.2:70000",
		"bare v6 literal":  "fd00::1:51820",
		"empty":            "",
	}
	for why, endpoint := range cases {
		if _, err := ParsePeer(testPeerKeyB64, endpoint, "2a04:2a01:4::7", "x", ""); err == nil {
			t.Fatalf("accepted an endpoint we must never dial (%s): %q", why, endpoint)
		}
	}
}

func TestParsePeer_RefusesAKeyThatIsNotAWireGuardKey(t *testing.T) {
	for _, bad := range []string{"", "not-base64!!", "c2hvcnQ="} {
		if _, err := ParsePeer(bad, "192.168.1.2:51820", "2a04:2a01:4::7", "x", ""); err == nil {
			t.Fatalf("accepted a non-key: %q", bad)
		}
	}
}

// ==========================================================================================
// The UAPI document: direct peers are ARMED, never promoted, at bring-up.
// ==========================================================================================

func TestUapiConfig_ArmsDirectPeersWithoutRoutingAnythingToThem(t *testing.T) {
	peer, err := ParsePeer(testPeerKeyB64, "192.168.122.31:51820", "2a04:2a01:4::7", "db-01", "direct-local")
	if err != nil {
		t.Fatalf("ParsePeer: %v", err)
	}
	cfg := Config{
		PrivateKeyHex:      strings.Repeat("11", 32),
		ServerPublicKeyHex: strings.Repeat("22", 32),
		Endpoint:           "[::1]:51826",
		Address:            netip.MustParseAddr("2a04:2a01:4::9"),
		Peers:              []Peer{peer},
	}

	doc := uapiConfig(cfg)

	// The box peer still holds the default route, and it is still written first.
	if !strings.Contains(doc, "public_key="+cfg.ServerPublicKeyHex+"\n") {
		t.Fatal("the box peer is missing")
	}
	if !strings.Contains(doc, "allowed_ip=::/0\n") {
		t.Fatal("the box peer lost its default route - every relayed destination would black-hole")
	}
	// The direct peer is present with its endpoint and the short keepalive...
	if !strings.Contains(doc, "public_key="+peer.PublicKeyHex+"\n") {
		t.Fatal("the direct peer is missing from the device config")
	}
	if !strings.Contains(doc, "endpoint=192.168.122.31:51820\n") {
		t.Fatal("the direct peer's endpoint is missing")
	}
	if !strings.Contains(doc, fmt.Sprintf("persistent_keepalive_interval=%d\n", directKeepalive)) {
		t.Fatal("the direct peer has no keepalive, so nothing would ever trigger its handshake")
	}
	// ...and NOTHING is routed to it yet. A /128 on an unproven peer is a black hole, because
	// WireGuard has no failover: a packet routed to a dead peer is dropped, not relayed.
	if strings.Contains(doc, "allowed_ip="+peer.Address.String()) {
		t.Fatal("a direct peer was promoted at bring-up, before anything proved the path")
	}
}

func TestUapiConfig_APeerRowCanNeverRewriteTheBoxPeer(t *testing.T) {
	boxKey := strings.Repeat("22", 32)
	cfg := Config{
		PrivateKeyHex:      strings.Repeat("11", 32),
		ServerPublicKeyHex: boxKey,
		Endpoint:           "[::1]:51826",
		Address:            netip.MustParseAddr("2a04:2a01:4::9"),
		// A row that reuses the box's key would not add a path beside the default route, it
		// would REPLACE it - and take every relayed destination with it.
		Peers: []Peer{{PublicKeyHex: boxKey, Endpoint: "192.168.1.2:51820", Address: netip.MustParseAddr("2a04:2a01:4::7")}},
	}

	doc := uapiConfig(cfg)

	if strings.Count(doc, "public_key="+boxKey+"\n") != 1 {
		t.Fatal("a peer row was allowed to rewrite the box peer")
	}
	if !strings.Contains(doc, "endpoint=[::1]:51826\n") {
		t.Fatal("the box endpoint was overwritten by a peer row")
	}
}

// ==========================================================================================
// The dump parse: one device, several peers, and the tunnel's own health must ride on the BOX.
// ==========================================================================================

func TestParseHandshakeDump_KeepsEachPeersSectionSeparate(t *testing.T) {
	box := strings.Repeat("22", 32)
	peer := strings.Repeat("33", 32)
	dump := "private_key=" + strings.Repeat("11", 32) + "\n" +
		"listen_port=51820\n" +
		"public_key=" + box + "\n" +
		"endpoint=[::1]:51826\n" +
		"last_handshake_time_sec=1756400000\n" +
		"last_handshake_time_nsec=5\n" +
		"persistent_keepalive_interval=25\n" +
		"public_key=" + peer + "\n" +
		"endpoint=192.168.122.31:51820\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n"

	got := parseHandshakeDump(dump)

	if len(got) != 2 {
		t.Fatalf("expected two peer sections, got %d: %v", len(got), got)
	}
	// The BOX is healthy. Before direct paths this parse was whole-dump and last-wins, so the dead direct
	// peer below would have been reported as the tunnel's own handshake - a healthy link read as
	// dead, driving a pointless reconnect every cycle.
	if got[box].Unix() != 1756400000 {
		t.Fatalf("the box's handshake was misread: %v", got[box])
	}
	if !got[peer].IsZero() {
		t.Fatalf("a never-handshaked peer must read as the zero time, got %v", got[peer])
	}
}

func TestParseHandshakeDump_IsEmptyForAnEmptyDump(t *testing.T) {
	if got := parseHandshakeDump(""); len(got) != 0 {
		t.Fatalf("expected nothing, got %v", got)
	}
}

// ==========================================================================================
// The real thing: promote on a real handshake, demote when the path dies, relay throughout.
// ==========================================================================================

// peerSide is a second real wireguard-go device standing in for another AGENT (not the box): its
// own keypair, a real UDP socket on loopback, and our client registered as its peer.
type peerSide struct {
	dev     *device.Device
	pubHex  string
	udpPort int
}

func startPeerSide(t *testing.T, clientPubHex string, clientTunnelIP netip.Addr) *peerSide {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("peer keypair: %v", err)
	}
	pubHex, err := keyBase64ToHex(kp.PublicKeyBase64)
	if err != nil {
		t.Fatalf("peer pub hex: %v", err)
	}
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{mustAddr(t, "2a04:2a01:4::7")}, nil, defaultMTU)
	if err != nil {
		t.Fatalf("peer netstack: %v", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	udpPort := freeUDPPort(t)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", kp.PrivateKeyHex, udpPort)
	uapi += fmt.Sprintf("public_key=%s\nallowed_ip=%s/128\n", clientPubHex, clientTunnelIP.String())
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("peer IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("peer Up: %v", err)
	}
	t.Cleanup(dev.Close)
	return &peerSide{dev: dev, pubHex: pubHex, udpPort: udpPort}
}

func TestDirectPeer_PromotesOnARealHandshakeAndFallsBackToTheRelayWhenItDies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path timing test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	peerIP := mustAddr(t, "2a04:2a01:4::7")

	box := startServerSide(t, clientPubHex, clientIP, 7010)
	other := startPeerSide(t, clientPubHex, clientIP)

	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	tun, err := Start(cfg, Options{
		HealthInterval:  100 * time.Millisecond,
		DeadAfter:       30 * time.Second,
		DirectDeadAfter: 700 * time.Millisecond, // far below the 20s default so the test is quick
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	// The peer's endpoint is loopback here, which ParsePeer rightly refuses for a real row (see
	// TestParsePeer_RefusesEveryEndpointWeMustNotAimATunnelAt). This test is about the
	// promote/demote mechanics, so the Peer is built directly - the validation has its own test.
	peer := Peer{
		Address:      peerIP,
		PublicKeyHex: other.pubHex,
		Endpoint:     netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String(),
		Name:         "db-01",
		Path:         "direct-local",
	}

	// Before anything is installed, the honest answer for that /128 is the relay.
	if got := tun.PathTo(peerIP); got != "relayed" {
		t.Fatalf("path before any peer was installed: got %q, want %q", got, "relayed")
	}

	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}

	// Armed, not promoted: the peer is on the device, and NOTHING is routed to it yet.
	if got := tun.PathTo(peerIP); got != "relayed" {
		t.Fatalf("a freshly armed peer already claims a direct path: %q", got)
	}
	if routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("a /128 was routed to a peer that had not handshaked - that destination would black-hole")
	}

	// A real handshake lands (the keepalive we set on arming forces one), and the monitor
	// promotes on that evidence and no other.
	if !waitFor(3*time.Second, func() bool { return tun.PathTo(peerIP) == "direct-local" }) {
		t.Fatalf("no direct path after a real handshake (state: %+v)", tun.DirectPeers())
	}
	if !routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("the tunnel reported a direct path the device was not actually routing")
	}
	// The box keeps the default route throughout - the relay is the fallback, always installed.
	if !boxStillHasDefaultRoute(t, tun) {
		t.Fatal("the box peer lost ::/0 while a direct path was up")
	}

	// The direct path dies. The /128 must go back to the box within the health window, and the
	// tunnel itself must NOT be reported as unhealthy: a dead peer is not a dead tunnel.
	other.dev.Close()
	if !waitFor(6*time.Second, func() bool { return tun.PathTo(peerIP) == "relayed" }) {
		t.Fatalf("a dead direct path was never withdrawn - that /128 would black-hole (state: %+v)", tun.DirectPeers())
	}
	if routedTo(t, tun, other.pubHex, peerIP) {
		t.Fatal("the /128 is still routed to the dead peer on the device")
	}
	if !boxStillHasDefaultRoute(t, tun) {
		t.Fatal("the box peer lost ::/0 during the fallback")
	}
}

func TestSetDirectPeers_RemovingARowRemovesThePeerFromTheDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	box := startServerSide(t, clientPubHex, clientIP, 7011)
	other := startPeerSide(t, clientPubHex, clientIP)

	cfg, _ := FromWgQuick(box.pubB64, netip.AddrPortFrom(mustAddr(t, "::1"), uint16(box.udpPort)).String(),
		clientIP.String(), box.serverIP.String(), "", "", kp.PrivateKeyHex)
	tun, err := Start(cfg, Options{HealthInterval: 100 * time.Millisecond, DirectDeadAfter: time.Second})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)

	peer := Peer{
		Address:      mustAddr(t, "2a04:2a01:4::7"),
		PublicKeyHex: other.pubHex,
		Endpoint:     netip.AddrPortFrom(mustAddr(t, "::1"), uint16(other.udpPort)).String(),
	}
	if err := tun.SetDirectPeers([]Peer{peer}); err != nil {
		t.Fatalf("SetDirectPeers: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return len(tun.DirectPeers()) == 1 }) {
		t.Fatal("the peer was never installed")
	}

	// The control plane stops listing it. This is what revocation looks like from our side - and
	// it is the COOPERATIVE half of the boundary: it removes the peer from THIS client. It does
	// nothing about a modified client that keeps an entry it already holds, because once a pair
	// is direct their packets never touch a box.
	if err := tun.SetDirectPeers(nil); err != nil {
		t.Fatalf("SetDirectPeers(nil): %v", err)
	}
	if len(tun.DirectPeers()) != 0 {
		t.Fatalf("the peer survived being dropped from the map: %+v", tun.DirectPeers())
	}
	dump, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if strings.Contains(dump, "public_key="+other.pubHex) {
		t.Fatal("the peer is still on the device after being revoked")
	}
	if !strings.Contains(dump, "public_key="+tun.cfg.ServerPublicKeyHex) {
		t.Fatal("the box peer was removed along with the direct peer")
	}
}

// routedTo reads the DEVICE's own dump and answers whether addr/128 is currently in that peer's
// AllowedIPs. This is the assertion that matters: our own bookkeeping saying "promoted" proves
// nothing about where the kernel of the userspace stack will actually send a packet.
func routedTo(t *testing.T, tun *Tunnel, peerHex string, addr netip.Addr) bool {
	t.Helper()
	dump, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	inPeer := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			inPeer = strings.TrimSpace(v) == peerHex
			continue
		}
		if inPeer && k == "allowed_ip" && strings.TrimSpace(v) == addr.String()+"/128" {
			return true
		}
	}
	return false
}

// boxStillHasDefaultRoute asserts the relay is always there to fall back to.
func boxStillHasDefaultRoute(t *testing.T, tun *Tunnel) bool {
	t.Helper()
	dump, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	inBox := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			inBox = strings.TrimSpace(v) == tun.cfg.ServerPublicKeyHex
			continue
		}
		if inBox && k == "allowed_ip" && strings.TrimSpace(v) == "::/0" {
			return true
		}
	}
	return false
}

func waitFor(within time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}
