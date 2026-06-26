// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/whisper-sec/whisper-cli/internal/egress"
)

// defaultMTU is the IPv6 minimum link MTU. Using it for the netstack interface is the
// conservative, robust default: it works across every underlay (UDP over any path) without
// relying on PMTUD, at a small throughput cost. The agent can raise it via Config.MTU.
const defaultMTU = 1280

// Start brings up a userspace WireGuard tunnel from cfg and returns a live *Tunnel whose
// local SOCKS5/HTTP endpoint egresses from the agent's /128. It:
//  1. builds the gVisor netstack TUN bound to the /128 (+ the in-tunnel resolver),
//  2. starts the wireguard-go device and loads the keypair + peer via the UAPI (IpcSet),
//  3. brings the device up (begins the handshake + 25s keepalive),
//  4. starts the SAME egress front-end (StartWithDialer) over a netstack dialer, and
//  5. starts the health monitor (dead-tunnel detection + reconnect with backoff).
//
// On ANY setup error it tears down whatever it built and returns a clean, non-leaky error
// (never the private key, never a stack trace). The returned tunnel's lifetime is Stop()
// ONLY — the front-end proxy is Background-rooted, so a short control ctx can never kill it.
func Start(cfg Config, opts Options) (*Tunnel, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// wireguard-go's UAPI IpcSet needs a LITERAL ip:port endpoint — it does not resolve DNS.
	// The control plane returns a hostname (e.g. ns1.whisper.online:51826), so resolve it here.
	resolved, rerr := resolveEndpoint(cfg.Endpoint)
	if rerr != nil {
		return nil, fmt.Errorf("could not resolve the WireGuard endpoint — please try again")
	}
	cfg.Endpoint = resolved
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	// 1. The netstack TUN: our /128 is the interface address; the box resolver is the
	//    in-tunnel DNS so socks5h name resolution happens THROUGH the tunnel (sourced /128).
	dnsServers := []netip.Addr{}
	if cfg.DNS.IsValid() {
		dnsServers = append(dnsServers, cfg.DNS)
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, dnsServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("could not start the WireGuard tunnel — please try again")
	}

	// 2. The wireguard-go device. Silent logger — wireguard-go's own logs would be noise and
	//    could surface peer/key detail; we emit only our own safe one-liners via opts.Logf.
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(uapiConfig(cfg)); err != nil {
		dev.Close() // closes the netstack TUN too
		return nil, errors.New("could not configure the WireGuard tunnel — please try again")
	}

	// 3. Bring the device up: this kicks off the handshake and the persistent keepalive.
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errors.New("could not bring up the WireGuard tunnel — please try again")
	}

	t := &Tunnel{
		dev:         dev,
		tnet:        tnet,
		cfg:         cfg,
		dialTO:      orDur(opts.DialTimeout, 30*time.Second),
		healthEvery: orDur(opts.HealthInterval, 5*time.Second),
		deadAfter:   orDur(opts.DeadAfter, 180*time.Second),
		logf:        opts.Logf,
		stop:        make(chan struct{}),
	}

	// 4. The shared egress front-end over a netstack dialer. onStop closes the device AFTER
	//    the accept loop + all splices drain (Stop ordering), so nothing dials a dead netstack.
	proxy, err := egress.StartWithDialer(&netDialer{tnet: tnet, timeout: t.dialTO}, func() {
		dev.Close()
	})
	if err != nil {
		dev.Close()
		return nil, errors.New("could not open the local connection — please try again")
	}
	t.proxy = proxy

	// 5. The health monitor: poll the handshake, reconnect a dead tunnel with backoff.
	go t.monitor()
	return t, nil
}

// validate enforces the minimum a usable tunnel needs: our private key, the server pubkey,
// the endpoint, and a valid /128. A missing piece is a clean error, never a half-built tunnel.
func (c Config) validate() error {
	if strings.TrimSpace(c.PrivateKeyHex) == "" {
		return errors.New("wireguard: missing client private key")
	}
	if strings.TrimSpace(c.ServerPublicKeyHex) == "" {
		return errors.New("wireguard: missing server public key")
	}
	if strings.TrimSpace(c.Endpoint) == "" {
		return errors.New("wireguard: missing endpoint")
	}
	if !c.Address.IsValid() {
		return errors.New("wireguard: missing or invalid tunnel address")
	}
	return nil
}

// uapiConfig renders the wireguard-go UAPI (IpcSet) document for cfg: our private key, then
// the single peer (the box) with its pubkey, the box endpoint, ::/0 + 0.0.0.0/0 allowed-ips
// (route everything out the tunnel; v4 rides DNS64/NAT64 on the box), and the keepalive.
//
// All keys are HEX here (the UAPI form); FromWgQuick converts the base64 the server returns.
// The endpoint is a literal ip:port (Start resolves the hostname first — IpcSet does not do DNS).
// This string holds the private key — it is handed ONLY to dev.IpcSet and never logged.
func uapiConfig(cfg Config) string {
	keepalive := cfg.Keepalive
	if keepalive <= 0 {
		keepalive = 25 // the server default; keeps the NAT/UDP path warm
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKeyHex)
	fmt.Fprintf(&b, "public_key=%s\n", cfg.ServerPublicKeyHex)
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	// Route all v6 AND v4 through the peer — the box egresses both (v4 via DNS64/NAT64),
	// exactly as the wg-quick AllowedIPs=::/0 config does for the SOCKS/kernel paths.
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String()
}

// resolveEndpoint turns a host:port WireGuard endpoint into a literal ip:port, which is what
// wireguard-go's UAPI IpcSet requires (ParseAddr does NOT resolve DNS). The control plane hands
// out a hostname (e.g. ns1.whisper.online:51826); "udp" lets v4-only or v6 clients each get a
// reachable family. Resolved once at Start; the box endpoint IP is stable across a reconnect.
func resolveEndpoint(hostPort string) (string, error) {
	ua, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return "", err
	}
	return ua.String(), nil
}

// setPeerEndpoint re-sets ONLY the peer endpoint via the UAPI without dropping the peer or
// the keys — this is how a reconnect forces a fresh handshake on a dead tunnel: update_only
// keeps the existing peer/keys, and re-asserting the endpoint nudges wireguard-go to send a
// new handshake initiation. It does NOT carry the private key, so it is cheap and safe.
func (t *Tunnel) setPeerEndpoint() error {
	cfg := "public_key=" + t.cfg.ServerPublicKeyHex + "\n" +
		"update_only=true\n" +
		"endpoint=" + t.cfg.Endpoint + "\n"
	return t.dev.IpcSet(cfg)
}

// netDialer is the egress.Dialer that dials a target THROUGH the userspace tunnel's netstack
// (so the connection sources from the agent's /128). It is the ONE WG-specific seam; every
// other front-end property (SOCKS5/HTTP parse, half-close splice, Stop-drain, lifetime) is
// the shared egress code. The ctx it receives is the PROXY'S OWN lifetime (p.life), so a
// Stop() unblocks any in-flight dial.
type netDialer struct {
	tnet    *netstack.Net
	timeout time.Duration
}

// Dial dials target ("host:port") over the tunnel. A bare IP literal dials directly; a
// hostname is resolved by the netstack resolver (the box's in-tunnel DNS) so the lookup, too,
// sources from the /128 — never the local box (Postel: we accept a name and resolve it remotely,
// the socks5h contract). It honours the proxy ctx (cancel on Stop) AND a per-dial timeout.
func (d *netDialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	dctx := ctx
	if d.timeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	c, err := d.tnet.DialContext(dctx, "tcp", target)
	if err != nil {
		// Non-leaky: never echo the target (it can name a sensitive host) or the netstack error.
		return nil, errors.New("could not reach the target over the Whisper tunnel")
	}
	return c, nil
}

// compile-time assertion: a *netDialer is an egress.Dialer (so StartWithDialer accepts it).
var _ egress.Dialer = (*netDialer)(nil)

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
