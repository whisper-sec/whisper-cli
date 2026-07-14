// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package wgtun is the client-side Tier-1 WireGuard egress for the `whisper` CLI
// : a USERSPACE WireGuard tunnel (wireguard-go + gVisor netstack - no root,
// no kernel wg, no /dev/net/tun) bound to the agent's /128, fronted by the SAME local
// SOCKS5/HTTP-CONNECT proxy the Tier-1.5 egress uses. The user's tools point ALL_PROXY /
// http_proxy at socks5h://127.0.0.1:<port> and every connection egresses from the agent's
// routable Whisper /128 over the encrypted tunnel - reverse-DNS of that /128 is identity.
//
//	user's tool ──socks5/http──▶ 127.0.0.1:<freeport>  (egress.Proxy front-end, NO auth)
//	                                     │  tnet.DialContext (gVisor netstack)
//	                                     ▼
//	                       userspace WireGuard device  ──UDP/51826──▶  <box> (wg-agents)
//	                                     │  encrypted; source = the agent's /128
//	                                     ▼
//	                                  internet, sourced from the agent /128
//
// WHY userspace (mirrors wireproxy / the spawned-agent default): no privilege, no TUN
// device, byte-identical across linux/darwin/windows (CGO-free, pure Go). The /128 routes
// because the box registered our public key as a peer with that /128 as its sole AllowedIPs
// (server-side); cryptokey routing confines us to exactly our own identity.
//
// ROBUSTNESS (mirrors the server reaper philosophy - a stale tunnel is frustrating):
//   - PersistentKeepalive 25s keeps the NAT/UDP path warm (set in the device config).
//   - a health monitor polls the device's last-handshake; a tunnel that has had NO handshake
//     past a dead-threshold is reconnected (the peer endpoint is re-set, forcing a fresh
//     handshake) with capped exponential backoff. The local SOCKS5 endpoint NEVER changes
//     across a reconnect - tools keep the same proxy string, the tunnel heals underneath.
//   - clean teardown: Stop() closes the front-end, stops the monitor, and closes the device.
//
// KEY HYGIENE: the private key lives ONLY in this process's memory (the device's IpcSet and
// the in-struct hex). The CLI generates the keypair locally and sends ONLY the public half
// to the control plane (op:connect{tier:wireguard, public_key:…}); the private key never
// leaves the host, is never logged, and never reaches the child environment.
package wgtun

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/whisper-sec/whisper-cli/internal/egress"
)

// Config is the resolved input to bring up a userspace WireGuard tunnel. It is derived from
// the op:connect{tier:wireguard} envelope (see FromWgQuick) plus the locally-held private
// key. Every key is hex (the wireguard-go UAPI form); helpers convert from the base64 the
// wg-quick config uses.
type Config struct {
	PrivateKeyHex      string     // our client private key, hex (in-memory only; never logged)
	ServerPublicKeyHex string     // the box's wg-agents public key, hex
	Endpoint           string     // the box UDP endpoint, host:port (e.g. <box>:51826)
	Address            netip.Addr // the agent's /128 - the tunnel's only source address
	DNS                netip.Addr // the resolver to use inside the tunnel (DNS64/NAT64)
	Keepalive          int        // PersistentKeepalive seconds (server default 25)
	// MTU for the netstack interface. 0 ⇒ a safe default (1280, the IPv6 minimum - robust
	// across every underlay without PMTUD surprises). Conservative-emit (Postel).
	MTU int
}

// Options tunes a tunnel. The zero value is sensible.
type Options struct {
	// DialTimeout bounds a single netstack dial through the tunnel. 0 ⇒ 30s.
	DialTimeout time.Duration
	// HealthInterval is how often the monitor polls the device's handshake. 0 ⇒ 5s.
	HealthInterval time.Duration
	// DeadAfter is how long with NO fresh handshake before the monitor forces a reconnect.
	// 0 ⇒ 180s (~7× the 25s keepalive - the server reaper's own black-hole threshold).
	DeadAfter time.Duration
	// Logf, if set, receives one-line operational notes (reconnects). nil ⇒ silent. It must
	// NEVER be handed a secret - callers pass a plain stderr writer; we only emit safe text.
	Logf func(format string, args ...any)
	// Port pins the LOCAL loopback port the tunnel's front-end proxy listens on. 0 ⇒ a free
	// port (the default). `whisper init --tier wireguard` sets the project's DETERMINISTIC
	// port so a re-ensure reuses the same 127.0.0.1:<port>.
	Port int
}

// Tunnel is a live userspace WireGuard egress: the bearer-free local SOCKS5/HTTP endpoint a
// caller hands to tools, plus the device + health monitor underneath. It satisfies the same
// surface the egress.Proxy does (Endpoint/Addr/Stop) so connect_core can treat both tiers
// uniformly. Healthy() exposes the live handshake state for `whisper status`.
type Tunnel struct {
	proxy  *egress.Proxy
	dev    *device.Device
	tnet   *netstack.Net
	cfg    Config
	dialTO time.Duration

	healthEvery time.Duration
	deadAfter   time.Duration
	logf        func(format string, args ...any)

	mu         sync.Mutex
	lastH      time.Time // last observed handshake (from the device), for Healthy()/monitor
	reconnects int       // re-handshakes the monitor has driven (status/tests); only grows

	// identityLn is the in-tunnel TLS listener (ServeTLS), or nil if never started. Closed by
	// Stop() alongside the rest of the tunnel; guarded by mu (ServeTLS/Stop can race).
	identityLn net.Listener

	stop   chan struct{} // closed by Stop() to end the monitor
	closed sync.Once
}

// Endpoint is the load-bearing connection string: socks5h://127.0.0.1:<port> (bearer-free,
// key-free). socks5h ⇒ the client hands us the hostname and the tunnel's netstack resolver
// (the box's DNS64/NAT64) resolves it sourced from the /128 - never the local box.
func (t *Tunnel) Endpoint() string { return t.proxy.Endpoint() }

// Addr is the bare 127.0.0.1:<port> the local proxy listens on.
func (t *Tunnel) Addr() string { return t.proxy.Addr() }

// Stop tears the whole tunnel down cleanly: the front-end proxy (which drains in-flight
// splices), the health monitor, and the userspace device. Idempotent.
func (t *Tunnel) Stop() {
	if t == nil {
		return
	}
	t.closed.Do(func() { close(t.stop) })
	t.mu.Lock()
	ln := t.identityLn
	t.mu.Unlock()
	if ln != nil {
		_ = ln.Close() // stop serving the identity leaf alongside the rest of the tunnel
	}
	// The proxy's onStop (wired in Start) closes the device AFTER the accept loop + tunnels
	// drain, so no splice is mid-dial on the netstack when it goes away. Stop() blocks on that.
	if t.proxy != nil {
		t.proxy.Stop()
	}
}

// ServeTLS starts a TLS listener bound to the tunnel's OWN /128 (t.cfg.Address) on port, serving cert
// on every accepted connection - the agent-held identity leaf, so a DANE-EE verifier (`whisper
// verify --trustless`) dialing [/128]:port sees the leaf THIS TUNNEL serves, proving the tunnel (not
// a shared/wildcard listener) terminates the port. Runs for the tunnel's lifetime; Stop() closes
// it alongside everything else. A bind failure is returned to the caller (best-effort: the tunnel
// itself is unaffected either way - this is additive proof surface, not the egress data path).
func (t *Tunnel) ServeTLS(cert tls.Certificate, port int) error {
	ln, err := t.tnet.ListenTCP(&net.TCPAddr{IP: net.IP(t.cfg.Address.AsSlice()), Port: port})
	if err != nil {
		return fmt.Errorf("could not bind the identity TLS listener on the tunnel: %w", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	t.mu.Lock()
	t.identityLn = tlsLn
	t.mu.Unlock()
	go func() {
		for {
			c, aerr := tlsLn.Accept()
			if aerr != nil {
				return // listener closed (Stop()) or a transient accept fault ⇒ end quietly
			}
			// A verifier only needs the handshake + the served cert; discard anything sent after.
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	return nil
}

// Healthy reports whether the tunnel has completed a handshake recently (within DeadAfter).
// A tunnel that has never handshaked, or whose last handshake is older than the dead
// threshold, is unhealthy - the monitor is (or will be) reconnecting it. Used by status.
func (t *Tunnel) Healthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.lastH.IsZero() && time.Since(t.lastH) < t.deadAfter
}

// Reconnects returns how many times the monitor has re-handshaked a dead tunnel (for status
// and tests). It only grows; a healthy long-lived tunnel stays at 0.
func (t *Tunnel) Reconnects() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reconnects
}
