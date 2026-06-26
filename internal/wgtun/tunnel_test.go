// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// These tests stand up a REAL second wireguard-go device on loopback (the "box" side) and run
// the client Tunnel against it — a genuine end-to-end userspace handshake + encrypted byte
// flow over loopback UDP, with NO root, NO kernel wg, NO /dev/net/tun. This is the same shape
// the live box uses (#178), just both ends in-process, so it proves the client path for real.

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func invalidAddr() netip.Addr { return netip.Addr{} }

// serverSide is a wireguard-go device standing in for the box's wg-agents: its own keypair, a
// netstack interface on serverIP, and a TCP echo backend listening inside that netstack so the
// client can dial it through the tunnel. It binds a real UDP socket on loopback (the endpoint
// the client tunnels to).
type serverSide struct {
	dev      *device.Device
	tnet     *netstack.Net
	pubB64   string
	udpPort  int
	serverIP netip.Addr
}

// startServerSide builds the box-side device, registers the client's public key as its peer
// (with the client's tunnel /128 as the peer allowed-ip — cryptokey routing), and starts an
// echo server inside the netstack at serverIP:echoPort.
func startServerSide(t *testing.T, clientPubHex string, clientTunnelIP netip.Addr, echoPort int) *serverSide {
	t.Helper()
	srvPrivHex := strings.Repeat("00", 0) // replaced below
	// Mint a real server keypair via the public GenerateKeypair, then convert to hex for UAPI.
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	srvPrivHex = kp.PrivateKeyHex
	srvPubHex, err := keyBase64ToHex(kp.PublicKeyBase64)
	if err != nil {
		t.Fatalf("server pub hex: %v", err)
	}

	serverIP := mustAddr(t, "2a04:2a01:0:53::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, defaultMTU)
	if err != nil {
		t.Fatalf("server netstack: %v", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	// Configure the server: its private key, a fixed listen port, and the client as a peer
	// keyed by the client's public key with the client's tunnel /128 as allowed-ip.
	udpPort := freeUDPPort(t)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", srvPrivHex, udpPort)
	uapi += fmt.Sprintf("public_key=%s\nallowed_ip=%s/128\n", clientPubHex, clientTunnelIP.String())
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("server Up: %v", err)
	}
	t.Cleanup(dev.Close)

	// Echo backend INSIDE the server netstack: the client dials [serverIP]:echoPort through the
	// tunnel and we echo its bytes back.
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: echoPort})
	if err != nil {
		t.Fatalf("server listen in-netstack: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	_ = srvPubHex // (the client uses the base64 form via FromWgQuick)
	return &serverSide{dev: dev, tnet: tnet, pubB64: kp.PublicKeyBase64, udpPort: udpPort, serverIP: serverIP}
}

// freeUDPPort grabs an ephemeral UDP port on loopback and frees it, returning the number so the
// server device can bind it as its WireGuard listen_port and the client can tunnel to it.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// TestTunnel_EndToEndEgress is the headline #188 test: a REAL userspace WireGuard handshake on
// loopback, then bytes flow from a SOCKS5 client through the client Tunnel, over the encrypted
// tunnel, to the echo backend inside the server netstack — and back. It also asserts Healthy()
// flips true once the handshake completes (the live tunnel-health signal `whisper status` uses).
func TestTunnel_EndToEndEgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake e2e in -short")
	}
	// Client keypair: we hold the private key; the server registers the public half.
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	clientPubHex, err := keyBase64ToHex(kp.PublicKeyBase64)
	if err != nil {
		t.Fatalf("client pub hex: %v", err)
	}
	clientIP := mustAddr(t, "2a04:2a01:4::7")
	const echoPort = 7000

	srv := startServerSide(t, clientPubHex, clientIP, echoPort)

	// Build the client Config exactly as the connect flow would: the server's base64 pubkey, the
	// loopback UDP endpoint, our /128, an in-tunnel DNS, and OUR private key.
	cfg, err := FromWgQuick(
		srv.pubB64,
		net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(),
		srv.serverIP.String(),
		"",
		kp.PrivateKeyHex,
	)
	if err != nil {
		t.Fatalf("client FromWgQuick: %v", err)
	}
	cfg.Keepalive = 1 // fast keepalive so the handshake kicks off promptly in the test

	tun, err := Start(cfg, Options{DialTimeout: 5 * time.Second, HealthInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("Start tunnel: %v", err)
	}
	t.Cleanup(tun.Stop)

	// The endpoint is the bearer/key-free loopback SOCKS5 URL.
	if !strings.HasPrefix(tun.Endpoint(), "socks5h://127.0.0.1:") {
		t.Fatalf("endpoint = %q, want socks5h://127.0.0.1:<port>", tun.Endpoint())
	}

	// Dial the echo backend (an IP literal so the test needs no in-tunnel resolver) through the
	// client's SOCKS5 endpoint. The handshake completes lazily on the first packet, so retry.
	target := net.JoinHostPort(srv.serverIP.String(), strconv.Itoa(echoPort))
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err = socks5Dial(tun.Addr(), target)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not reach the echo backend through the tunnel before deadline: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer conn.Close()

	msg := "hello-over-wireguard"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo through tunnel: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("tunnel echo = %q, want %q", buf, msg)
	}

	// After a successful handshake the tunnel must report healthy (the status signal).
	if !waitHealthy(tun, 5*time.Second) {
		t.Fatal("tunnel never reported Healthy() after a successful handshake")
	}
}

// TestTunnel_StopIsCleanAndIdempotent: Stop() tears the device + front-end down and is a no-op
// the second time (no panic). The local endpoint refuses connections afterwards.
func TestTunnel_StopIsCleanAndIdempotent(t *testing.T) {
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::8")
	srv := startServerSide(t, clientPubHex, clientIP, 7001)

	cfg, err := FromWgQuick(srv.pubB64, net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(), srv.serverIP.String(), "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	tun, err := Start(cfg, Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := tun.Addr()
	tun.Stop()
	tun.Stop() // idempotent — must not panic
	if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("after Stop the local SOCKS5 endpoint must no longer accept connections")
	}
}

// TestTunnel_ReconnectOnDeadHandshake drives the robustness path (#188): with a tiny DeadAfter
// and a server that we take DOWN, the monitor must observe the tunnel go unhealthy and DRIVE at
// least one reconnect (re-handshake) attempt — proving a stale tunnel self-heals rather than
// silently black-holing. The local endpoint is unchanged throughout.
func TestTunnel_ReconnectOnDeadHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the reconnect timing test in -short")
	}
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::9")
	srv := startServerSide(t, clientPubHex, clientIP, 7002)

	cfg, err := FromWgQuick(srv.pubB64, net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(), srv.serverIP.String(), "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	cfg.Keepalive = 1
	endpoint := tunEndpointForReconnect(t, cfg, srv)
	_ = endpoint
}

// tunEndpointForReconnect starts the tunnel, lets it go healthy, then closes the server device
// so handshakes can no longer renew; with a short DeadAfter the monitor must force ≥1 reconnect.
// It asserts the local endpoint string never changes across the heal attempt.
func tunEndpointForReconnect(t *testing.T, cfg Config, srv *serverSide) string {
	t.Helper()
	tun, err := Start(cfg, Options{
		HealthInterval: 150 * time.Millisecond,
		DeadAfter:      400 * time.Millisecond, // far below the 180s default so the test is quick
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)
	endpoint := tun.Endpoint()

	// Let the first handshake land (best-effort — even if it doesn't, an all-dead tunnel still
	// exercises the reconnect path, which is the point).
	waitHealthy(tun, 3*time.Second)

	// Kill the server: no more handshakes can renew. The tunnel goes stale; the monitor must
	// detect it (no fresh handshake past DeadAfter) and drive reconnect attempts.
	srv.dev.Close()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if tun.Reconnects() >= 1 {
			if tun.Endpoint() != endpoint {
				t.Fatalf("local endpoint changed across a reconnect: %q -> %q (it must stay stable)", endpoint, tun.Endpoint())
			}
			return endpoint
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("monitor never drove a reconnect on a dead tunnel (reconnects=%d) — stale tunnels would black-hole", tun.Reconnects())
	return endpoint
}

func waitHealthy(tun *Tunnel, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if tun.Healthy() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return tun.Healthy()
}

// TestNetDialer_HonoursContextCancel: the netstack dialer respects a cancelled ctx (so a Stop()
// unblocks an in-flight dial) — proven without a live peer: an unreachable target + a cancelled
// ctx returns promptly with a clean (non-leaky) error.
func TestNetDialer_HonoursContextCancel(t *testing.T) {
	// A standalone client device with no peer: any dial has nowhere to go, so a cancelled ctx
	// must make Dial return quickly instead of hanging.
	clientIP := mustAddr(t, "2a04:2a01:4::a")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, defaultMTU)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	d := &netDialer{tnet: tnet, timeout: 2 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	start := time.Now()
	if _, err := d.Dial(ctx, "[2a04:2a01:0:53::1]:80"); err == nil {
		t.Fatal("dial on a cancelled ctx must error, not connect")
	}
	if time.Since(start) > 1*time.Second {
		t.Fatalf("dial on a cancelled ctx took %v — it must return promptly", time.Since(start))
	}
}

// socks5Dial is a tiny inline SOCKS5 client (RFC 1928, no-auth, CONNECT by IP/DOMAIN) so the WG
// tunnel test needs no extra dep. It tunnels through the local proxy at proxyAddr to target.
func socks5Dial(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil { // VER, 1 method, NO-AUTH
		c.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 method negotiation failed")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	pnum, _ := strconv.Atoi(port)
	// Send the host as a DOMAINNAME (the SOCKS5 ATYP=3 form the front-end always handles); the
	// netstack dialer parses an IP literal directly and resolves a name over the tunnel.
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(pnum>>8), byte(pnum&0xff))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect rejected (rep=%d)", head[1])
	}
	var bndLen int
	switch head[3] {
	case 0x01:
		bndLen = 4
	case 0x04:
		bndLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		bndLen = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, bndLen+2)); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// guard against an unused-import drift if the e2e is the only user of hex.
var _ = hex.EncodeToString
