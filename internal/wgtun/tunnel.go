// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package wgtun is the client-side Tier-1 WireGuard egress for the `whisper` CLI
// a USERSPACE WireGuard tunnel (wireguard-go + gVisor netstack - no root,
// no kernel wg, no /dev/net/tun) bound to the agent's /128, fronted by the SAME local
// SOCKS5/HTTP-CONNECT proxy the Tier-1.5 egress uses. The user's tools point ALL_PROXY /
// http_proxy at socks5h://127.0.0.1:<port> and every connection egresses from the agent's
// routable Whisper /128 over the encrypted tunnel - reverse-DNS of that /128 is identity.
//
//	user's tool ──socks5/http──▶ 127.0.0.1:<freeport> (egress.Proxy front-end, NO auth)
//	                                     │ tnet.DialContext (gVisor netstack)
//	                                     ▼
//	                       userspace WireGuard device ──UDP/51826──▶ the server
//	                                     │ encrypted; source = the agent's /128
//	                                     ▼
//	                                  internet, sourced from the agent /128
//
// WHY userspace (mirrors wireproxy / the spawned-agent default): no privilege, no TUN
// device, byte-identical across linux/darwin/windows (CGO-free, pure Go). The /128 routes
// because the box registered our public key as a peer with that /128 as its sole AllowedIPs
// (server-side); cryptokey routing confines us to exactly our own identity.
//
// ROBUSTNESS (mirrors the server reaper philosophy - a stale tunnel is frustrating):
// - PersistentKeepalive 25s keeps the NAT/UDP path warm (set in the device config).
// - a health monitor polls the device's last-handshake; a tunnel that has had NO handshake
// past a dead-threshold is reconnected (the peer endpoint is re-set, forcing a fresh
// handshake) with capped exponential backoff. The local SOCKS5 endpoint NEVER changes
// across a reconnect - tools keep the same proxy string, the tunnel heals underneath.
// - clean teardown: Stop() closes the front-end, stops the monitor, and closes the device.
//
// KEY HYGIENE: the private key lives ONLY in this process's memory (the device's IpcSet and
// the in-struct hex). The CLI generates the keypair locally and sends ONLY the public half
// to the control plane (op:connect{tier:wireguard, public_key:…}); the private key never
// leaves the host, is never logged, and never reaches the child environment.
package wgtun

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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
	ServerPublicKeyHex string     // the server's WireGuard public key, hex
	Endpoint           string     // the server UDP endpoint, host:port
	Address            netip.Addr // the agent's /128 - the tunnel's only source address
	DNS                netip.Addr // the resolver to use inside the tunnel (DNS64/NAT64)
	Keepalive          int        // PersistentKeepalive seconds (server default 25)
	// ListenPort pins the UDP port the device binds. 0 ⇒ the kernel picks one, which
	// is what it did before. It has to be pinned for a DECLARED endpoint to mean anything: the
	// ip:port a node tells the control plane it listens on is only true if it actually listens
	// there. A port that cannot be bound is not fatal - see Start.
	ListenPort int
	// Peers are the DIRECT peers known at bring-up: a second WireGuard peer per pair that
	// can reach each other with no box in between. Empty (the default) is one peer and a fully
	// relayed east-west plane, exactly as before direct paths. Peers learned later arrive through
	// Tunnel.SetDirectPeers.
	Peers []Peer
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
	// DirectDeadAfter is how long a PROMOTED direct peer may go without a handshake
	// before its /128 is withdrawn and the box carries it again. 0 ⇒ directDeadAfter (20s, four
	// direct keepalives). Shorter values are for tests; in production the default is the number
	// that decides how long a broken direct path costs a pair.
	DirectDeadAfter time.Duration
	// DirectRearmAfter is how long an armed-but-never-handshaked candidate waits before another
	// handshake attempt is kicked. 0 ⇒ directRearmAfter (2 minutes). After the punch train for a
	// peer has been spent, this is the quiet window before the next train starts.
	DirectRearmAfter time.Duration
	// PathStateDir is where the tunnel PUBLISHES what it knows about each peer's path, so
	// `whale status` and `whale ping` - which run in a different process - can report the path a
	// packet is actually taking rather than the candidacy the control plane claimed. "" ⇒
	// DefaultPathStateDir (~/.config/whisper/paths), which is what production wants and needs no
	// configuration. PathStateOff publishes nothing. Tests point it at a temp directory.
	PathStateDir string
	// PunchEvery is how long one NAT-traversal punch attempt is given before the next candidate
	// endpoint is tried. 0 ⇒ punchPeriod (5s, WireGuard's own handshake retry interval - see
	// punch.go for why that is the right number and not a tunable anybody should reach for).
	// Tests set it short; production should not set it at all.
	PunchEvery time.Duration
	// PeerSource, if set, is asked for this node's direct-peer map on an interval - in production
	// it is one op:list{kind:'whale', view:'peers'} call. nil (the default) means no direct paths
	// are ever learned and every east-west packet keeps being relayed, which is exactly the
	// behaviour before direct paths. It must return the FULL map each time, not a delta: a peer that
	// stops appearing is removed from the device, and that is how a revocation reaches us.
	PeerSource func(ctx context.Context) ([]Peer, error)
	// PeerRefresh is how often PeerSource is polled. 0 ⇒ 60s. It is also the upper bound on how
	// long a revoked peer entry can survive on this client, so it is the number to argue about if
	// the cooperative-boundary window ever matters more than the call volume.
	PeerRefresh time.Duration
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

	// names is what this tunnel settled on for the NAT64 prefix and the in-tunnel resolver
	// (nameservice.go), decided once at bring-up and read-only thereafter. Held here as well
	// as on the dialer so status/verify can report the same verdict the user was told.
	names *nameService

	mu         sync.Mutex
	lastH      time.Time // last observed handshake WITH THE BOX, for Healthy()/monitor
	reconnects int       // re-handshakes the monitor has driven (status/tests); only grows

	// directDead / directRearm are the direct-path windows, resolved once from Options at
	// bring-up; punchEvery is the traversal cadence (see punch.go).
	directDead  time.Duration
	directRearm time.Duration
	punchEvery  time.Duration

	// pathDir / pathFP / pathAt are the published path record (see pathstate.go): where it goes,
	// a fingerprint of what was last written, and when. pathFP and pathAt are guarded by mu.
	pathDir string
	pathFP  string
	pathAt  time.Time

	// peerWrite serialises SetDirectPeers with itself. The map above is guarded by mu, but the
	// device writes that follow a reconcile happen OUTSIDE it (an IpcSet must not be made under a
	// lock the health loop also wants), so two concurrent callers could interleave a remove with
	// an arm and leave a peer on the device that nothing tracks. Production has exactly one
	// caller - the refresh loop - and this keeps that from being a property callers have to know.
	peerWrite sync.Mutex

	// direct is the direct-peer set, keyed by the peer's public key in hex: the
	// second WireGuard peer for a pair that can reach each other without the box. Guarded by mu;
	// everything that reads or writes it lives in peers.go. Empty (the default) is the shipped
	// behaviour before direct paths - one peer, every east-west packet relayed.
	direct peerSet

	// identityLn is the in-tunnel TLS listener (ServeTLS), or nil if never started. Closed by
	// Stop() alongside the rest of the tunnel; guarded by mu (ServeTLS/Stop can race).
	identityLn net.Listener

	// serveH is the `whale serve` / `whale funnel` front end installed BEHIND that same
	// listener (see serve.go): every path the gateway-signed documents do not claim goes to it.
	// nil (the default) leaves the listener documents-only, exactly as shipped it.
	serveH http.Handler

	stop   chan struct{} // closed by Stop() to end the monitor
	closed sync.Once
}

// Endpoint is the load-bearing connection string: socks5h://127.0.0.1:<port> (bearer-free,
// key-free). socks5h ⇒ the client hands us the hostname and the tunnel's netstack resolver
// (the box's DNS64/NAT64) resolves it sourced from the /128 - never the local box.
func (t *Tunnel) Endpoint() string { return t.proxy.Endpoint() }

// Addr is the bare 127.0.0.1:<port> the local proxy listens on.
func (t *Tunnel) Addr() string { return t.proxy.Addr() }

// LastDialFailure forwards the front-end proxy's record of why the most recent dial through
// this tunnel failed, and when (see egress.Proxy.LastDialFailure). netDialer.diagnosis already
// works out which of routing, DNS, or the destination it was and writes a sentence a person
// can act on; SOCKS5 then throws that sentence away with a one-byte REP code. This is how it
// gets back to the surface, so `whisper connect` can say "the tunnel never handshaked, check
// that UDP to the Whisper endpoint is not blocked" instead of blaming a session token.
func (t *Tunnel) LastDialFailure() (string, time.Time) { return t.proxy.LastDialFailure() }

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
// ServedDoc is one static document the in-tunnel identity listener serves over the DANE-pinned TLS
// a gateway-signed identity-doc / JWKS / did:web the agent fetched at connect time. The agent
// is a THIN server here - the bytes are gateway-signed, nothing is signed in-tunnel.
type ServedDoc struct {
	Path        string // exact request path, e.g. "/.well-known/whisper-identity"
	ContentType string
	Body        []byte
}

func (t *Tunnel) ServeTLS(cert tls.Certificate, port int, docs []ServedDoc) error {
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
	// Serve the fetched gateway-signed docs at their well-known paths so a trustless DANE verifier
	// that, after the pinned handshake, GETs /.well-known/whisper-identity is served the signed doc
	// instead of a hung/dropped connection (the identity_doc leg was timing out = 3/4). Unknown paths 404;
	// a verifier that only needs the handshake (the DANE-EE leg) is unaffected either way.
	srv := &http.Server{Handler: t.identityHandler(docs), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		// Serve returns when tlsLn is closed by Stop(); any other accept fault ends it quietly.
		_ = srv.Serve(tlsLn)
	}()
	return nil
}

// docsHandler builds the in-tunnel identity handler: each ServedDoc is served (GET/HEAD) at its exact
// path with its content-type; any other path or method 404s / 405s. Extracted for unit testing.
func docsHandler(docs []ServedDoc) http.Handler {
	mux := http.NewServeMux()
	for _, d := range docs {
		d := d
		mux.HandleFunc(d.Path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			ct := d.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			w.Header().Set("Content-Type", ct)
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(d.Body)
			}
		})
	}
	return mux
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
