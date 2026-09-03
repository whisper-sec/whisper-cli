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
// 1. builds the gVisor netstack TUN bound to the /128 (+ the in-tunnel resolver),
// 2. starts the wireguard-go device and loads the keypair + peer via the UAPI (IpcSet),
// 3. brings the device up (begins the handshake + 25s keepalive),
// 4. settles names and IPv4 against the far end (nameservice.go: the NAT64 prefix RFC 7050
// discovery reads off the resolver, and whether that resolver is usable at all),
// 5. starts the SAME egress front-end (StartWithDialer) over a netstack dialer, and
// 6. starts the health monitor (dead-tunnel detection + reconnect with backoff).
//
// On ANY setup error it tears down whatever it built and returns a clean, non-leaky error
// (never the private key, never a stack trace). The returned tunnel's lifetime is Stop()
// ONLY - the front-end proxy is Background-rooted, so a short control ctx can never kill it.
func Start(cfg Config, opts Options) (*Tunnel, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// wireguard-go's UAPI IpcSet needs a LITERAL ip:port endpoint - it does not resolve DNS.
	// The control plane returns a hostname (e.g. ns1.whisper.online:51826), so resolve it here.
	resolved, rerr := resolveEndpoint(cfg.Endpoint)
	if rerr != nil {
		return nil, fmt.Errorf("could not resolve the WireGuard endpoint - please try again")
	}
	cfg.Endpoint = resolved
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	// 1. The netstack TUN: our /128 is the interface address; the box resolver is the
	// in-tunnel DNS so socks5h name resolution happens THROUGH the tunnel (sourced /128).
	dnsServers := []netip.Addr{}
	if cfg.DNS.IsValid() {
		dnsServers = append(dnsServers, cfg.DNS)
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, dnsServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("could not start the WireGuard tunnel - please try again")
	}

	// 2. The wireguard-go device. Silent logger - wireguard-go's own logs would be noise and
	// could surface peer/key detail; we emit only our own safe one-liners via opts.Logf.
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(uapiConfig(cfg)); err != nil {
		// the one part of that document that can fail for an environmental reason is
		// the pinned listen_port - something else may have taken it since PickListenPort released
		// it. Losing the port costs this session's direct paths and nothing else, so retry once
		// without it rather than fail a whole connect over a latency optimisation. Conservative
		// in what we do: a node that could not bind its declared port stops claiming it, so
		// cfg.ListenPort is cleared and the declaration it already sent is simply never used (the
		// peer never handshakes, and the monitor never promotes it).
		retried := false
		if cfg.ListenPort > 0 {
			cfg.ListenPort = 0
			retried = dev.IpcSet(uapiConfig(cfg)) == nil
		}
		if !retried {
			dev.Close() // closes the netstack TUN too
			return nil, errors.New("could not configure the WireGuard tunnel - please try again")
		}
	}

	// 3. Bring the device up: this kicks off the handshake and the persistent keepalive.
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, errors.New("could not bring up the WireGuard tunnel - please try again")
	}

	t := &Tunnel{
		dev:         dev,
		tnet:        tnet,
		cfg:         cfg,
		dialTO:      orDur(opts.DialTimeout, 30*time.Second),
		healthEvery: orDur(opts.HealthInterval, 5*time.Second),
		deadAfter:   orDur(opts.DeadAfter, 180*time.Second),
		directDead:  orDur(opts.DirectDeadAfter, directDeadAfter),
		directRearm: orDur(opts.DirectRearmAfter, directRearmAfter),
		punchEvery:  orDur(opts.PunchEvery, punchPeriod),
		pathDir:     opts.PathStateDir,
		logf:        opts.Logf,
		stop:        make(chan struct{}),
	}
	t.rebindUDP = dev.BindUpdate

	// 4. Settle names and IPv4 BEFORE the front-end accepts its first connection.
	// Both answers are properties of the far end, not of this process, so we ask rather
	// than assume: RFC 7050 tells us which NAT64 prefix is actually translated, and one
	// probe tells us whether the resolver the box handed us will serve this /128 at all.
	// Bounded and fail-open - a probe that times out costs the refinement and nothing else,
	// and whatever is degraded is said once, here, in a sentence rather than a symptom.
	nameCtx, cancelNames := context.WithTimeout(context.Background(), nameServiceProbeTimeout)
	names := newNameService(nameCtx, tnet, cfg.DNS, cfg.NAT64Prefix)
	cancelNames()
	t.names = names
	if names.verdict != "" {
		t.note("whisper: %s", names.verdict)
	}

	// 5. The shared egress front-end over a netstack dialer. onStop closes the device AFTER
	// the accept loop + all splices drain (Stop ordering), so nothing dials a dead netstack.
	// opts.Port (0 ⇒ a free port) pins the loopback port so `whisper init --tier wireguard`
	// reuses the project's deterministic 127.0.0.1:<port> across re-ensures.
	dialer := &netDialer{stack: tnet, timeout: t.dialTO, names: names, handshake: t.readHandshake}
	proxy, err := egress.StartWithDialerPort(dialer, func() {
		dev.Close()
	}, opts.Port)
	if err != nil {
		dev.Close()
		return nil, errors.New("could not open the local connection - please try again")
	}
	t.proxy = proxy

	// record the peers uapiConfig just ARMED, so the monitor knows to promote them
	// once a handshake lands. They carry no /128 yet, so nothing is routed to them until one does.
	if len(cfg.Peers) > 0 {
		t.direct = peerSet{}
		armedAt := time.Now()
		for _, p := range cfg.Peers {
			if p.PublicKeyHex == "" || p.PublicKeyHex == cfg.ServerPublicKeyHex {
				continue
			}
			t.direct[p.PublicKeyHex] = &directPeer{
				peer:    p,
				armedAt: armedAt,
				punch:   newPunchTrain(p.candidateList(), armedAt),
			}
		}
	}

	// 6. The health monitor: poll the handshake, reconnect a dead tunnel with backoff, and
	// promote or demote the direct peers on the same observation.
	go t.monitor()

	// 7. The direct-path work: the direct-peer map, refreshed from the control plane. Absent a PeerSource
	// nothing here runs and every east-west packet is relayed, exactly as before direct paths.
	if opts.PeerSource != nil {
		go t.refreshPeers(opts.PeerSource, orDur(opts.PeerRefresh, 60*time.Second))
	}
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

// uapiConfig renders the wireguard-go UAPI (IpcSet) document for cfg: our private key, the box
// peer (its pubkey, the box endpoint, the default route for the family this interface can
// actually source, and the keepalive), and then any direct peers known at bring-up.
//
// # The default route is the family the interface HAS, and nothing wider
//
// This peer entry used to claim `0.0.0.0/0` alongside `::/0`, with a comment saying it mirrored
// the server's `AllowedIPs = ::/0`. It did not: the server grants v6 only, and the client was
// widening that grant to the whole IPv4 internet on its own authority. Reading what the claim
// could ever do settles it, and the answer is nothing good:
//
// - OUTBOUND it can never match. CreateNetTUN is handed exactly one address (the agent's
// IPv6 /128, config.go) and adds a default route ONLY for the families it was given an
// address for, so the netstack has no v4 route and refuses a v4 dial before a packet
// exists. An AllowedIPs entry selects a peer for a packet that was built; none is.
// - INBOUND it is a live grant, and the wrong one. Cryptokey routing would accept v4-sourced
// packets from the box and hand them to a stack with no v4 address, which drops them. We
// were accepting a family we cannot use.
//
// v4 destinations do not need it and never did: nat64.go wraps an IPv4 literal into the RFC 6052
// prefix AT THE DIALER, so it leaves as an IPv6 destination and `::/0` carries it. Conservative
// in what we do: the peer carries the one family this interface can source, which is the same
// grant the server made.
//
// # The peer ordering is the fallback, and it is free
//
// WireGuard selects a peer for an outbound packet by LONGEST-PREFIX match over AllowedIPs. The
// box holds the default route, so it carries everything by default; a direct peer holds exactly
// one /128, so it wins for that one destination and nothing else. Removing the /128 hands the
// destination straight back to the box. There is no failover flag, no route table and no second
// decider - the relay is the fallback because the prefixes say so.
//
// Direct peers are written here with NO allowed-ips, only their endpoint and a short keepalive.
// They are ARMED, not promoted: a peer that has not proved a path yet must not have a /128
// routed to it, because a packet routed to a dead peer is dropped rather than relayed. The
// health monitor hands over the /128 once a handshake lands (see peers.go).
//
// All keys are HEX here (the UAPI form); FromWgQuick converts the base64 the server returns.
// The endpoint is a literal ip:port (Start resolves the hostname first - IpcSet does not do DNS).
// This string holds the private key - it is handed ONLY to dev.IpcSet and never logged.
func uapiConfig(cfg Config) string {
	keepalive := cfg.Keepalive
	if keepalive <= 0 {
		keepalive = 25 // the server default; keeps the NAT/UDP path warm
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.PrivateKeyHex)
	if cfg.ListenPort > 0 {
		// pin the port, so the ip:port this node declared at connect is the one it
		// actually listens on. Without this the device binds an ephemeral port and every declared
		// endpoint is a lie by the time the tunnel is up.
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	fmt.Fprintf(&b, "public_key=%s\n", cfg.ServerPublicKeyHex)
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	// The default route for the family this interface can source, and no wider (see above).
	b.WriteString("allowed_ip=" + boxDefaultRoute(cfg.Address) + "\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	for _, p := range cfg.Peers {
		if p.PublicKeyHex == "" || p.PublicKeyHex == cfg.ServerPublicKeyHex {
			continue // never let a peer row rewrite the box peer and take ::/0 with it
		}
		fmt.Fprintf(&b, "public_key=%s\n", p.PublicKeyHex)
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", directKeepalive)
	}
	return b.String()
}

// boxDefaultRoute is the one AllowedIPs entry the box peer gets: the default route of the
// address family this interface can actually source a packet from.
//
// The branch mirrors netstack.CreateNetTUN's own, which is what makes the answer true rather
// than merely plausible: it assigns the address as IPv4 when Is4() and as IPv6 otherwise, and
// installs a default route only for the families it assigned. Claiming the other family here
// would grant the peer a route no packet can ever take, and an inbound accept for a family the
// stack would drop.
func boxDefaultRoute(addr netip.Addr) string {
	if addr.Is4() {
		return "0.0.0.0/0"
	}
	return "::/0"
}

// resolveEndpoint turns a host:port WireGuard endpoint into a literal ip:port, which is what
// wireguard-go's UAPI IpcSet requires (ParseAddr does NOT resolve DNS). The control plane hands
// out a hostname (e.g. ns1.whisper.online:51826); "udp" lets v4-only or v6 clients each get a
// reachable family. Resolved once at Start; the box endpoint IP is stable across a reconnect.
//
// # There is deliberately NO host route around this endpoint, and there must not be one
//
// wg-quick installs a host route excluding the peer endpoint from the tunnel, because on a kernel
// interface an `AllowedIPs` default route really does capture the handshake packets that are trying
// to establish that same tunnel. It is a genuine and well known foot-gun, and the obvious reading of
// "the client claims ::/0 and our endpoint is v6" is that we have it too. We do not, and the reason
// is structural rather than lucky, so it is worth writing down where the endpoint is resolved:
//
// - The device's outer socket is conn.NewDefaultBind() (see Start). That is an ORDINARY host UDP
// socket, created by the Go runtime against the HOST's routing table, and it is what carries
// every handshake and every transport packet to the peer. Nothing in this process can move it.
// - allowed_ip lives inside wireguard-go's own cryptokey routing table. It selects a peer for a
// packet the NETSTACK built and it decides which peer may source an inbound one. It is not a
// system route, it is not visible to the host, and it cannot capture the bind's own traffic.
// - The netstack (netstack.CreateNetTUN) is a self-contained gVisor stack holding exactly the
// agent's /128. Its default route exists only inside that stack. The host's routing table is
// never read and never written by any path this CLI ships.
//
// So on the userspace tier the exclusion is unnecessary by construction. On Tier 1.5 there is no
// tunnel at all, and `whisper panel system-proxy` sets a macOS SOCKS preference and touches no route.
// The one shape that WOULD need the exclusion is a kernel node brought up by hand from the wg-quick
// blob the server returns, and there wg-quick installs it itself.
//
// If a future tier ever does write the host routing table, it owes this exclusion BEFORE it brings
// the tunnel up, and it owes it for the address family the endpoint actually resolved to here.
func resolveEndpoint(hostPort string) (string, error) {
	ua, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return "", err
	}
	return ua.String(), nil
}

// setPeerEndpoint re-sets ONLY the peer endpoint via the UAPI without dropping the peer or
// the keys - this is how a reconnect forces a fresh handshake on a dead tunnel: update_only
// keeps the existing peer/keys, and re-asserting the endpoint nudges wireguard-go to send a
// new handshake initiation. It does NOT carry the private key, so it is cheap and safe.
func (t *Tunnel) setPeerEndpoint() error {
	cfg := "public_key=" + t.cfg.ServerPublicKeyHex + "\n" +
		"update_only=true\n" +
		"endpoint=" + t.cfg.Endpoint + "\n"
	return t.dev.IpcSet(cfg)
}

// netDialer is the egress.Dialer that dials a target THROUGH the userspace tunnel's netstack
// (so the connection sources from the agent's /128), including the IPv4 destinations the
// stack has no address for: those are wrapped into the NAT64 prefix first (see nat64.go).
// It is the ONE WG-specific seam; every
// other front-end property (SOCKS5/HTTP parse, half-close splice, Stop-drain, lifetime) is
// the shared egress code. The ctx it receives is the PROXY'S OWN lifetime (p.life), so a
// Stop() unblocks any in-flight dial.
type netDialer struct {
	stack   tunnelStack
	timeout time.Duration
	// names is what this tunnel settled on for the NAT64 prefix and the in-tunnel resolver
	// (nameservice.go). Settled once at Start, so a dial never probes and never reads the
	// environment, and every dial of one tunnel agrees with every other.
	names *nameService
	// handshake reports the box peer's last handshake, so a failed dial can say whether the
	// tunnel was carrying at the time. A seam, not a dependency on *Tunnel: a test drives the
	// three-way diagnosis without a live device. nil ⇒ the routing leg is simply not claimed.
	handshake func() (time.Time, bool)
}

// nameServiceProbeTimeout bounds the WHOLE bring-up probe (nameservice.go): every rung of the
// resolver ladder and the RFC 7050 discovery share this one budget, so a connect can never pay
// it more than once no matter how many resolvers decline to answer.
//
// The value is chosen against measurements, not taste. A resolver inside the tunnel is one RTT
// away and answers in about 0.1s on the live fleet, and a resolver that refuses or NXDOMAINs
// answers just as fast, so the only case that spends the whole budget is one that black-holes.
// 2.5s covers a handshake still in flight when we ask plus a retransmit, and caps what a silent
// far end costs the user at 2.5 seconds of a one-time bring-up. An earlier 6s was picked for
// headroom and showed up immediately as 6 seconds of silence per tunnel in the suite, which is
// exactly the friction the motto says to remove.
//
// Exceeding it is not a failure: the tunnel comes up on the previous defaults, names fall to
// the next rung, and the verdict says what is degraded.
const nameServiceProbeTimeout = 2500 * time.Millisecond

// tunnelDead is how long without a handshake before a failed dial blames routing rather than
// the destination. It matches the keepalive interval with room for one loss: inside that
// window the tunnel demonstrably carried a packet, so a failure is about the far end.
const tunnelDead = 60 * time.Second

// tunnelStack is the slice of the netstack this dialer uses. It exists so the v4 path can
// be tested against a recorded target rather than a live gVisor stack: a test that could
// only run with a real tunnel up is a test nobody runs. *netstack.Net satisfies it.
type tunnelStack interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	LookupContextHost(ctx context.Context, host string) ([]string, error)
}

// Dial dials target ("host:port") over the tunnel. A bare IP literal dials directly; a
// hostname is resolved by the netstack resolver (the box's in-tunnel DNS) so the lookup, too,
// sources from the /128 - never the local box (Postel: we accept a name and resolve it remotely,
// the socks5h contract). It honours the proxy ctx (cancel on Stop) AND a per-dial timeout.
func (d *netDialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	dctx := ctx
	if d.timeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	// An IPv4 LITERAL has no source address and no route inside this tunnel, so it
	// would fail here silently. Wrap it in the NAT64 prefix (RFC 6052) and dial that - the
	// box unwraps it and completes the connection over v4. A name or a v6 literal is passed
	// through untouched.
	dialTarget := target
	if translated, ok, terr := TranslateTarget(d.nat64(), target); terr != nil {
		// An address on THIS side of the tunnel (a LAN, loopback, link-local). Say which,
		// because a hang here has cost people hours; the sentence is already user-facing.
		return nil, errors.New("could not reach the target over the Whisper tunnel: " + terr.Error())
	} else if ok {
		dialTarget = translated
	}

	// Resolve a NAME ourselves before dialling, on the settled resolver over TCP - the seam every
	// other dial in this file uses.
	//
	// Handing a name to netstack looks equivalent and is not. netstack resolves it with the ONE
	// server the tun was built with (device.go, CreateNetTUN), asks AAAA only because this stack
	// holds a single IPv6 /128 and so hasV4 is false, sends it over UDP only, and on NXDOMAIN or
	// an empty NOERROR returns immediately without trying anything else. None of that is visible
	// from here: the dial just fails, and diagnosis() then blames the destination.
	//
	// Measured through a live tunnel: the in-tunnel resolver answers github.com AAAA over TCP with
	// a synthesised address (NOERROR, ancount=1), while every name dialled through netstack failed.
	// The resolver was never the problem and the fail-open ladder in nameservice.go was never
	// consulted, because it only ever governed the retry below, not this path.
	//
	// So the ladder governs the primary path now. An IP literal still goes straight through.
	if !isIPLiteralTarget(dialTarget) && d.names != nil {
		if conn, ok := d.dialResolved(dctx, dialTarget); ok {
			return conn, nil
		}
	}

	c, err := d.stack.DialContext(dctx, "tcp", dialTarget)
	if err == nil {
		return c, nil
	}
	// A NAME that resolves only to A records lands here: either the in-tunnel resolver did not
	// synthesise a AAAA for it, or it will not answer us at all. Resolve the A ourselves and
	// dial it through NAT64 rather than leave the caller with nothing. Only on the failure
	// path, so the healthy dial pays nothing for it.
	if dialTarget == target {
		if retried, rerr := d.dialV4OnlyName(dctx, target); rerr == nil {
			return retried, nil
		}
	}
	// Non-leaky: never echo the target (it can name a sensitive host) or the netstack error.
	// The diagnosis says which of the three layers failed, which is the whole difference
	// between a user who can act and one who reverts a toggle and files "it killed my
	// network".
	return nil, errors.New("could not reach the target over the Whisper tunnel" + d.diagnosis())
}

// nat64 is the prefix this dialer wraps IPv4 destinations into. It reads through the settled
// name service so there is exactly ONE answer per tunnel and no caller has to remember to
// pass it; a dialer built without one (only a test does that) falls back to the well-known
// prefix rather than wrapping into the zero prefix, which would be silently unroutable.
func (d *netDialer) nat64() netip.Prefix {
	if d.names != nil && d.names.prefix.IsValid() {
		return d.names.prefix
	}
	p, _ := NAT64Prefix()
	return p
}

// diagnosis is the sentence that turns "it did not work" into "here is which of the three
// things it was". It is appended to a failed dial, and it names ONE layer:
//
// - ROUTING - the tunnel has no recent handshake, so nothing is getting through and no
// amount of DNS or destination health would help.
// - DNS - the tunnel is carrying, but the resolver the box handed us is not usable, which
// newNameService already established at bring-up and said once.
// - THE DESTINATION - the tunnel is carrying and names resolve, so the failure is at the
// far end. That is the honest answer, and it stops a user from re-configuring a client
// that was never the problem.
//
// It returns "" when it has nothing to add, so a caller can always concatenate it.
func (d *netDialer) diagnosis() string {
	if d.handshake != nil {
		last, ok := d.handshake()
		if ok && (last.IsZero() || time.Since(last) > tunnelDead) {
			return ". The tunnel has no recent WireGuard handshake, so this is the tunnel" +
				" itself and not the destination - `whisper connect` again, or check that" +
				" UDP to the Whisper endpoint is not blocked on your network"
		}
	}
	if d.names != nil && !d.names.resolverOK {
		return ". The tunnel is carrying traffic, but the in-tunnel resolver is not usable" +
			" (see the note printed when the tunnel came up), so this is name resolution" +
			" rather than routing"
	}
	return ". The tunnel is carrying traffic and names resolve, so this is the destination" +
		" rather than the Whisper connection"
}

// isIPLiteralTarget reports whether "host:port" carries an address rather than a name, so the
// resolve step can be skipped for the socks5 (non-h) path and for anything already translated.
func isIPLiteralTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	_, perr := netip.ParseAddr(strings.Trim(host, "[]"))
	return perr == nil
}

// dialResolved resolves the name on the tunnel's settled resolver and dials the answers in order,
// preferring a native v6 address over a NAT64 synthesis: the native form keeps the agent's own /128
// as the source, while a synthesis egresses from a shared v4 SNAT. Reports ok=false when it cannot
// resolve or cannot connect, so the caller still falls through to the paths below rather than
// turning a resolvable name into a hard failure.
func (d *netDialer) dialResolved(ctx context.Context, target string) (net.Conn, bool) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, false
	}
	prefix := d.nat64()
	aaaa, aerr := d.names.resolve(ctx, d.stack, host, dnsTypeAAAA)
	if aerr != nil || len(aaaa) == 0 {
		return nil, false
	}
	var synth []netip.Addr
	for _, a := range aaaa {
		if prefix.IsValid() && prefix.Contains(a) {
			synth = append(synth, a)
			continue
		}
		if conn, derr := d.stack.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port)); derr == nil {
			return conn, true
		}
	}
	for _, a := range synth {
		if conn, derr := d.stack.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port)); derr == nil {
			return conn, true
		}
	}
	return nil, false
}

// dialV4OnlyName is the second half of the v4 story, and until it was a half that could
// never fire.
//
// The intent was always sound: DNS64 on the resolver covers a name with only an A record by
// synthesising a AAAA, and when it does not - it is off, it is unhealthy, it refuses this
// /128 - we would rather resolve an address ourselves than depend on a service being up. The
// implementation asked netstack's LookupContextHost for that address, and netstack fires the
// A lane ONLY when the stack holds a v4 address. Our stack holds one IPv6 /128 and nothing
// else, so the lookup asked for AAAA, an A-only name came back empty, and this function
// reached "no addresses" for every input it existed to serve. It shipped, it passed its
// tests, and it could not execute.
//
// It now asks the question it always meant to: an A query, to the resolver the tunnel settled
// on, over the tunnel (nameservice.go). When that resolver is not usable at all the same call
// resolves on this host instead, which gives up the socks5h property that the lookup leaves
// from the /128 - said out loud at bring-up, never absorbed silently - and keeps the
// connection working. Fail open, and say which.
//
// Returns an error unless the name really is v4-only and translatable.
func (d *netDialer) dialV4OnlyName(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if _, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr == nil {
		return nil, errors.New("not a name")
	}
	if d.names == nil {
		return nil, errors.New("no name service on this tunnel")
	}
	prefix := d.nat64()

	// Ask the resolver WE settled on, which is not necessarily the one the netstack was built
	// with: when the box's resolver is broken the netstack's first dial failed on a lookup that
	// never had a chance, and re-asking a resolver that works is the whole point of the retry.
	//
	// A AAAA answer is then two different things wearing the same shape, and telling them apart
	// is load-bearing:
	//
	// - INSIDE the NAT64 prefix it is a DNS64 SYNTHESIS, which is to say an IPv4 host written
	// as IPv6. That is the answer we want and we dial it. Treating it as "the name has v6,
	// do not retry" is precisely backwards: it refuses the retry for exactly the names NAT64
	// exists to serve, which is what a live lab guest showed.
	// - OUTSIDE it, it is a NATIVE v6 address. That name failed for a real reason, and going
	// around it over NAT64 would egress from a shared IPv4 SNAT rather than the agent's own
	// /128. Quietly changing which identity a connection presents is the last thing an
	// identity product should do, so the name keeps the error it earned.
	// ONE firstErr across the rungs below. It used to be re-declared per rung, with an early
	// `return nil, firstErr` after the synthesised loop, so a single dead NAT64 address ended the
	// function before the native rung could run - vetoing the very addresses that rung exists to
	// dial. Keep the first error we saw and let every rung have its turn.
	var firstErr error
	var native []netip.Addr
	if aaaa, aerr := d.names.resolve(ctx, d.stack, host, dnsTypeAAAA); aerr == nil {
		for _, a := range aaaa {
			if !prefix.Contains(a) {
				native = append(native, a)
				continue
			}
			conn, derr := d.stack.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
			if derr == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = derr
			}
		}
	}
	// A NATIVE v6 answer used to end here, on the reasoning that the first dial had already
	// tried it and the name had earned its error. That reasoning holds only when the first
	// dial failed at CONNECT. It fails at RESOLUTION for every name on this tunnel: the
	// netstack is built with the box resolver and looks names up over UDP, while everything
	// else here - dnsQuery, the RFC 7050 probe, this retry - goes over TCP through the same
	// seam as any other dial, because that is the seam that works. So the first dial never
	// reached the destination to earn anything, and refusing to dial a perfectly good AAAA
	// condemned every dual-stack name on the tunnel. Measured: github.com, example.com and
	// google.com all failed through socks5h while an IP literal to the same hosts succeeded.
	//
	// Dialling it here does NOT do what the old comment feared. Wrapping a v4 address into
	// NAT64 changes the egress to a shared v4 SNAT, and that is worth refusing. A native v6
	// address is dialled from this stack, sourced from the agent's own /128, which is exactly
	// what the netstack dial would have done had its lookup worked. The identity is unchanged.
	if len(native) > 0 {
		for _, a := range native {
			conn, derr := d.stack.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
			if derr == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = derr
			}
		}
		// Deliberately terminal: falling through from a failed NATIVE dial into A-synthesis
		// would silently move this connection's egress to a shared v4 SNAT. That is the one
		// thing an identity product must not do quietly.
		if firstErr == nil {
			firstErr = errors.New("no native v6 address could be dialled")
		}
		return nil, firstErr
	}

	// No DNS64 on the path, so do the synthesis ourselves from the A record.
	addrs, rerr := d.names.resolve(ctx, d.stack, host, dnsTypeA)
	if rerr != nil {
		return nil, rerr
	}
	for _, v4 := range addrs {
		wrapped, serr := Synthesize(prefix, v4)
		if serr != nil {
			if firstErr == nil {
				firstErr = serr
			}
			continue
		}
		conn, derr := d.stack.DialContext(ctx, "tcp", net.JoinHostPort(wrapped.String(), port))
		if derr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = derr
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no v4 address")
	}
	return nil, firstErr
}

// compile-time assertion: a *netDialer is an egress.Dialer (so StartWithDialer accepts it).
var _ egress.Dialer = (*netDialer)(nil)

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
