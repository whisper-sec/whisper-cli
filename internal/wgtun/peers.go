// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// peers.go is the direct-path half: a second WireGuard peer, so two nodes that can already reach each
// other stop paying for a box in the middle.
//
// # What this does, and what it deliberately does not
//
// Every east-west packet on Whalenet used to be relayed: decrypted on the box and re-encrypted
// on the way out. Measured on the local bridge that is 23.8 to 24.3 ms hairpinned against
// 0.13 to 0.28 ms direct, about 130x.
//
// The first step took the two cases the control plane can see with no traversal machinery at
// all - peers on one segment, and a peer whose public endpoint nothing rewrites - and installs
// the second peer for them. punch.go adds the case those two miss: a peer behind a NAT, reached
// by both ends handshaking at the endpoints the server observed them arriving from. What remains relayed after that is a pair where BOTH ends
// sit behind a NAT that varies its external port per destination, and a pair split across two
// boxes, which has no path at all until inter-box forwarding lands.
//
// This file is unchanged in the part that matters: it still installs, promotes and demotes a
// peer on handshake evidence and nothing else. The punch only decides WHERE the next handshake
// is aimed.
//
// # Why cryptokey routing is the whole mechanism
//
// WireGuard picks a peer for an outbound packet by LONGEST-PREFIX match over AllowedIPs. The
// box peer holds the default route of the family this interface can source (::/0 today, see
// boxDefaultRoute); a direct peer holds exactly one /128. So the moment a
// /128 appears on a direct peer, traffic for it goes direct, and the moment it is removed it
// goes back to the box - with no route table, no flag, and no second decision anywhere. The
// promote and demote below are that one line, and nothing else.
//
// # Promotion is evidence-driven, which is what makes the fallback loss-free
//
// A peer installed with AllowedIPs already set would BLACK-HOLE the /128 for as long as the
// direct path failed to come up: WireGuard has no failover between peers, so a packet routed
// to a dead peer is simply dropped. So a candidate is installed in two phases:
//
// 1. armed: the peer, its endpoint and a short keepalive, with NO allowed-ips. It handshakes
// (or does not) while every packet for that /128 keeps flowing through the box. This
// phase cannot cost anything - there is nothing routed to it to lose.
// 2. promoted: only once a handshake has actually completed do we hand it the /128. Now the
// traffic is direct, and it is direct because something proved the path, not because a
// control-plane row claimed one.
//
// Demotion is the same move backwards: the /128 is withdrawn, the box's ::/0 covers it again
// within the health window, and the peer stays armed so it can re-promote when the path
// returns. Established flows survive it - both ends keep the same overlay addresses, only the
// encryption path underneath changed - modulo the packets in flight during detection.

const (
	// directKeepalive is the PersistentKeepalive for a direct peer, in seconds. Shorter than
	// the 25s we use towards the box, because this is the timer the promote/demote decision
	// rides on: a handshake attempt every 5 seconds means a path that dies is noticed and
	// withdrawn within directDeadAfter rather than within a minute. On a LAN this is one small
	// packet every five seconds; the latency it buys back is three orders of magnitude larger.
	directKeepalive = 5

	// directDeadAfter is how long a promoted peer may go without a handshake before its /128 is
	// withdrawn and the box carries it again. Four keepalives.
	directDeadAfter = 20 * time.Second

	// directRearmAfter is how long a peer whose punch train has been SPENT waits before another
	// train starts. wireguard-go retries an initiation for about 90s and then goes quiet, so
	// without this a peer that was unreachable at install time would stay quiet forever even
	// after the path came back.
	//
	// Two minutes, so the steady state for a pair that genuinely cannot be punched is twelve
	// small packets every two minutes, about a tenth of a packet per second. A pair that cannot
	// go direct must not cost more than the relay it is already using.
	directRearmAfter = 2 * time.Minute
)

// Peer is one direct peer as the control plane describes it: who it is, the key to encrypt to,
// the underlay endpoint to dial, and the single /128 it is allowed to be.
type Peer struct {
	// Address is the peer's overlay /128 - the ONLY address this peer may send or receive as.
	Address netip.Addr
	// PublicKeyHex is the peer's WireGuard public key in the UAPI's hex form.
	PublicKeyHex string
	// Endpoint is a literal ip:port on the underlay. Never a hostname: the UAPI does not resolve.
	Endpoint string
	// Name is the peer's friendly name, for the one operational line we print. Never load-bearing.
	Name string
	// Path is the class the control plane assigned ("direct-local" / "direct-public" /
	// "direct-punch"), carried through so `whale status` can say WHICH case this pair took.
	Path string
	// Candidates are every underlay endpoint we may aim a handshake at for this peer, best
	// first (see punch.go). Empty means "just Endpoint", which is the original shape: one endpoint,
	// one attempt class, no traversal. A peer behind a NAT is reached by punching through this
	// list, and the list is the ONLY thing that grows when the punch is added - the promote,
	// the demote and the fallback are unchanged.
	Candidates []Candidate
}

// candidateList is the endpoints to punch at, in order. A Peer built before the punch (one
// Endpoint, no Candidates) yields exactly one candidate, so nothing about its behaviour changes
// beyond the retry cadence.
func (p Peer) candidateList() []Candidate {
	if len(p.Candidates) > 0 {
		return p.Candidates
	}
	if strings.TrimSpace(p.Endpoint) == "" {
		return nil
	}
	return []Candidate{{Endpoint: p.Endpoint, Source: SourcePublic}}
}

// sameCandidates reports whether two peers offer the same endpoints in the same order. It is
// what decides whether a control-plane refresh may leave a live path alone: an unchanged
// candidate list must never reset a peer that is working.
func sameCandidates(a, b Peer) bool {
	x, y := a.candidateList(), b.candidateList()
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ParsePeer validates one control-plane peer row into a Peer, or explains why it will not be
// installed. The client re-checks everything the server checked, on purpose: this is the side
// that will actually send the packets, and a peer entry is a routing grant. A compromised or
// impersonated control plane must not be able to hand us a peer that can speak as anything
// other than one specific agent.
//
// The load-bearing check is allowedIP: EXACTLY one /128, inside 2a04:2a01::/32. A peer whose
// AllowedIPs were wider would, by cryptokey routing, be permitted to source traffic as every
// address it covers - which is the entire property the tunnel exists to provide.
func ParsePeer(publicKeyB64, endpoint, allowedIP, name, path string) (Peer, error) {
	return ParsePeerCandidates(publicKeyB64, []Candidate{{Endpoint: endpoint}}, allowedIP, name, path)
}

// ParsePeerCandidates is ParsePeer with more than one endpoint to aim at: the punch form. Each
// candidate is validated by the same rules the single endpoint is, and the survivors are ordered
// best-evidence-first. A peer whose candidates ALL fail validation is refused outright, because
// a peer with nowhere to dial is not a peer - it is a relayed row, and the control plane sends
// those with no key and no endpoint at all.
//
// The client re-checks every candidate the server already checked, on purpose. This is the side
// that will actually emit the packets, so it is the side that has to be sure it is not being
// pointed at loopback, at the internal network, at our own overlay, or at multicast.
func ParsePeerCandidates(publicKeyB64 string, cands []Candidate, allowedIP, name, path string) (Peer, error) {
	var p Peer
	keyHex, err := keyBase64ToHex(publicKeyB64)
	if err != nil {
		return p, errors.New("the peer's public key is not a WireGuard key")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(allowedIP, "[]")))
	if err != nil {
		return p, errors.New("the peer's address is not an IP address")
	}
	addr = addr.Unmap()
	if !addr.Is6() || !agentBlock().Contains(addr) {
		return p, errors.New("the peer's address is not a Whisper agent address")
	}
	// A single malformed endpoint keeps its own precise error, because that message is what a
	// person debugging one bad control-plane row reads. A list falls back to the general one.
	if len(cands) == 1 {
		if cerr := checkUnderlayEndpoint(cands[0].Endpoint); cerr != nil {
			return p, cerr
		}
	}
	ordered, err := ParseCandidates(cands)
	if err != nil {
		return p, err
	}
	return Peer{
		Address:      addr,
		PublicKeyHex: keyHex,
		Endpoint:     ordered[0].Endpoint,
		Candidates:   ordered,
		Name:         strings.TrimSpace(name),
		Path:         strings.TrimSpace(path),
	}, nil
}

// agentBlock is 2a04:2a01::/32, the only prefix a peer's overlay address may sit in.
func agentBlock() netip.Prefix {
	p, _ := netip.ParsePrefix("2a04:2a01::/32")
	return p
}

// checkUnderlayEndpoint refuses every endpoint we must never aim a tunnel at. It mirrors the
// server-side sanitiser exactly, and exists separately because trusting the server to have run
// it is not the same as having run it.
//
// - loopback: would aim our handshakes at our own machine's services.
// - our own overlay 2a04:2a01::/32: would aim the tunnel down the tunnel.
// - the internal tailnet 100.64.0.0/10: agents never join it.
// - link-local, multicast, unspecified: not dialable, or not ours to dial.
func checkUnderlayEndpoint(endpoint string) error {
	host, portStr, err := splitHostPortLiteral(strings.TrimSpace(endpoint))
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("the peer's endpoint has no usable port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("the peer's endpoint is not a literal address")
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return errors.New("the peer's endpoint is a loopback address")
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return errors.New("the peer's endpoint is not a dialable unicast address")
	case ip.IsUnspecified():
		return errors.New("the peer's endpoint is the unspecified address")
	case agentBlock().Contains(ip):
		return errors.New("the peer's endpoint is inside the Whisper overlay")
	case tailnetBlock().Contains(ip):
		return errors.New("the peer's endpoint is inside the internal network")
	}
	return nil
}

func tailnetBlock() netip.Prefix {
	p, _ := netip.ParsePrefix("100.64.0.0/10")
	return p
}

// splitHostPortLiteral splits "ip:port" or "[ip]:port". It refuses a bare unbracketed IPv6
// literal rather than guessing which colon was the separator: guessing would silently produce
// a wrong endpoint, and a wrong endpoint here is a packet sent somewhere nobody asked for.
func splitHostPortLiteral(s string) (string, string, error) {
	if s == "" {
		return "", "", errors.New("the peer has no endpoint")
	}
	if s[0] == '[' {
		end := strings.IndexByte(s, ']')
		if end < 0 || end+2 > len(s) || s[end+1] != ':' {
			return "", "", errors.New("the peer's endpoint is malformed")
		}
		return s[1:end], s[end+2:], nil
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || strings.IndexByte(s, ':') != i {
		return "", "", errors.New("the peer's endpoint is malformed")
	}
	return s[:i], s[i+1:], nil
}

// PeerState is what a caller (status, ping) may ask about one direct peer. It reports what is
// TRUE on the device right now, never what the control plane wished for: Promoted is set only
// while the /128 is actually routed to this peer, which only happens after a handshake.
type PeerState struct {
	Address  netip.Addr
	Name     string
	Path     string // the direct class while promoted, "relayed" otherwise
	Endpoint string
	Promoted bool
	LastSeen time.Time
	// Punch is what the traversal machinery did for this peer, so a surface can say "relayed
	// because the punch failed, after 12 attempts at 2 endpoints" rather than printing the
	// absence of a direct path and leaving the reader to guess which of the reasons it was.
	Punch PunchInfo
}

// directPeer is one candidate's live state inside the tunnel.
type directPeer struct {
	peer     Peer
	promoted bool
	lastSeen time.Time // last handshake we observed with this peer
	armedAt  time.Time // when we last kicked a handshake attempt
	demotes  int
	// punch is the traversal train for this peer: which candidate endpoint the next attempt
	// aims at, how many attempts this train has made, and how it ended. It is the ONLY thing
	// the punch adds to this struct, because the promote/demote decision below is unchanged.
	punch *punchTrain
}

// SetDirectPeers installs the candidate set the control plane handed us, replacing whatever was
// there. A peer that disappears from the map is removed from the device outright, which is how
// revocation reaches a direct pair from our side.
//
// It is safe to call repeatedly with the same list: an unchanged peer is left alone, so a
// refresh does not reset a working path. A row that fails ParsePeer is skipped with a note and
// the rest are installed, because one bad row must not cost a fleet its direct paths (Postel).
//
// # The uncomfortable part, said plainly
//
// This is the COOPERATIVE half of the boundary. We remove a peer when the control plane stops
// listing it, and that is a real revocation for an honest client. It is not one for a modified
// client that keeps the entry it already has: once a pair is direct their packets never touch a
// box, so nothing on our side can withdraw the path. Tailscale has the same property and bounds
// it with short netmap lifetimes and node-key expiry; we have neither yet.
func (t *Tunnel) SetDirectPeers(peers []Peer) error {
	if t == nil {
		return errors.New("no tunnel")
	}
	t.peerWrite.Lock()
	defer t.peerWrite.Unlock()

	wanted := make(map[string]Peer, len(peers))
	for _, p := range peers {
		if p.PublicKeyHex == "" || p.PublicKeyHex == t.cfg.ServerPublicKeyHex {
			// Never let a peer row impersonate the box: the box peer holds ::/0, and a row that
			// reused its key would rewrite the default route rather than add a path beside it.
			continue
		}
		wanted[p.PublicKeyHex] = p
	}

	t.mu.Lock()
	if t.direct == nil {
		t.direct = map[string]*directPeer{}
	}
	var remove []string
	var arm []Peer
	for key, cur := range t.direct {
		if next, ok := wanted[key]; !ok {
			remove = append(remove, key)
		} else if next.Address != cur.peer.Address ||
			(!cur.promoted && !sameCandidates(next, cur.peer)) {
			arm = append(arm, next) // the row changed materially: re-arm it from scratch
			delete(t.direct, key)
		} else {
			// Same peer: leave the live path alone and just refresh what the row carries, so a
			// renamed node stops showing its old name without its working path being reset.
			//
			// A PROMOTED peer keeps its path even when the candidate list changed. The list is
			// advice about where to aim a handshake; the path is a handshake that already landed.
			// Tearing down a working direct pair because the control plane re-ordered a list, or
			// added an endpoint we now do not need, would flap every direct pair in a fleet on
			// the refresh interval. The new list is adopted for the NEXT train instead.
			cur.peer.Name = next.Name
			cur.peer.Path = next.Path
			cur.peer.Candidates = next.candidateList()
			cur.punch.adopt(cur.peer.Candidates)
		}
	}
	for _, key := range remove {
		delete(t.direct, key)
	}
	for key, p := range wanted {
		if _, ok := t.direct[key]; !ok {
			arm = append(arm, p)
		}
	}
	t.mu.Unlock()

	var firstErr error
	for _, key := range remove {
		if err := t.dev.IpcSet("public_key=" + key + "\nremove=true\n"); err != nil && firstErr == nil {
			firstErr = errors.New("could not remove a direct peer")
		}
	}
	for _, p := range arm {
		if err := t.armDirectPeer(p); err != nil {
			// Leave nothing half-installed: an untracked peer on the device is one nothing will
			// ever remove, and the reconciler cannot promote or demote what it does not know about.
			_ = t.dev.IpcSet("public_key=" + p.PublicKeyHex + "\nremove=true\n")
			t.note("whisper: direct path to %s not armed (%v) - it stays relayed", peerLabel(p), err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		now := time.Now()
		t.mu.Lock()
		t.direct[p.PublicKeyHex] = &directPeer{
			peer:    p,
			armedAt: now,
			punch:   newPunchTrain(p.candidateList(), now),
		}
		t.mu.Unlock()
	}
	return firstErr
}

// armDirectPeer installs a candidate with its endpoint and keepalive but NO allowed-ips, so it
// can handshake without any traffic being routed to it. replace_allowed_ips with nothing after
// it is what clears the list - both on a first install and on a demote.
//
// Setting the keepalive from 0 to a non-zero value makes wireguard-go send an immediate
// keepalive, which forces a handshake initiation. That is the whole trigger; there is nothing
// else to poke.
func (t *Tunnel) armDirectPeer(p Peer) error {
	endpoint := p.Endpoint
	if cands := p.candidateList(); len(cands) > 0 {
		endpoint = cands[0].Endpoint
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", p.PublicKeyHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("persistent_keepalive_interval=0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", directKeepalive)
	return t.dev.IpcSet(b.String())
}

// promoteDirectPeer hands the peer its /128. From this line on, cryptokey routing sends that
// destination direct instead of to the box, because a /128 beats the box peer's ::/0.
func (t *Tunnel) promoteDirectPeer(p Peer) error {
	cfg := "public_key=" + p.PublicKeyHex + "\n" +
		"update_only=true\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=" + p.Address.String() + "/128\n"
	return t.dev.IpcSet(cfg)
}

// demoteDirectPeer withdraws the /128. The box peer's ::/0 covers it again immediately, so the
// flow continues over the relay rather than stopping. The peer stays installed and armed, so it
// re-promotes on its own when the direct path comes back.
func (t *Tunnel) demoteDirectPeer(p Peer) error {
	cfg := "public_key=" + p.PublicKeyHex + "\n" +
		"update_only=true\n" +
		"replace_allowed_ips=true\n"
	return t.dev.IpcSet(cfg)
}

// reconcileDirectPeers is one pass of the promote/demote decision, called from the tunnel's
// existing health monitor rather than from a second goroutine: there is already a loop that
// reads the device on a timer, and one loop that does both is easier to reason about than two
// that could disagree about what the device said.
func (t *Tunnel) reconcileDirectPeers(now time.Time, seen map[string]time.Time) {
	t.mu.Lock()
	if len(t.direct) == 0 {
		t.mu.Unlock()
		// Still publish: a node whose last direct peer was revoked must stop claiming one, and
		// an empty table published by a live monitor is a different fact from no table at all.
		t.publishPaths()
		return
	}
	type action struct {
		p       Peer
		promote bool
		demote  bool
		punch   bool
		cand    Candidate
	}
	var todo []action
	for key, d := range t.direct {
		hs, ok := seen[key]
		if ok && !hs.IsZero() {
			d.lastSeen = hs
		}
		fresh := !d.lastSeen.IsZero() && now.Sub(d.lastSeen) < orDur(t.directDead, directDeadAfter)
		switch {
		case fresh && !d.promoted:
			d.promoted = true
			todo = append(todo, action{p: d.peer, promote: true})
		case !fresh && d.promoted:
			d.promoted = false
			d.demotes++
			d.armedAt = now
			// Start a fresh punch train at the endpoint that carried the path last time: after a
			// path has been up and died, that is the likeliest place to find it again.
			d.punch.restart(now, d.punch.winner)
			todo = append(todo, action{p: d.peer, demote: true})
		case !fresh && !d.promoted:
			// The traversal. A train of attempts, one candidate endpoint at a time, while every
			// packet for this /128 keeps going through the box - the peer holds no allowed-ips
			// until a handshake actually lands, so none of this can cost reachability.
			if d.punch.spent() && now.Sub(d.armedAt) > orDur(t.directRearm, directRearmAfter) {
				d.punch.restart(now, d.punch.winner)
			}
			if c, due := d.punch.due(now, t.punchEvery); due {
				d.armedAt = now
				todo = append(todo, action{p: d.peer, punch: true, cand: c})
			}
		}
	}
	t.mu.Unlock()

	for _, a := range todo {
		switch {
		case a.promote:
			if err := t.promoteDirectPeer(a.p); err != nil {
				t.mu.Lock()
				if d := t.direct[a.p.PublicKeyHex]; d != nil {
					d.promoted = false
				}
				t.mu.Unlock()
				continue
			}
			// Read back where the device says this peer actually is. It is usually the candidate
			// we aimed at, but NOT always: WireGuard roams a peer to wherever an authenticated
			// packet arrived from, which is the only way to learn the mapped source of a peer
			// behind a NAT that rewrites its port per destination. One device read per promotion.
			won := Candidate{Endpoint: t.peerEndpoint(a.p.PublicKeyHex)}
			t.mu.Lock()
			if d := t.direct[a.p.PublicKeyHex]; d != nil && d.punch != nil {
				if won.Endpoint == "" {
					won.Endpoint = d.punch.lastEP
				}
				won.Source = sourceOf(d.punch.cands, won.Endpoint)
				d.punch.winner, d.punch.won = won, true
			}
			t.mu.Unlock()
			t.note("whisper: %s is now a direct path (%s via %s); the relay is the fallback",
				peerLabel(a.p), orText(a.p.Path, "direct"), orText(won.Endpoint, a.p.Endpoint))
		case a.demote:
			_ = t.demoteDirectPeer(a.p)
			t.note("whisper: the direct path to %s stopped answering - falling back to the relay",
				peerLabel(a.p))
		case a.punch:
			_ = t.punchAt(a.p, a.cand)
		}
	}

	// Publish what the device just told us, so the surfaces in other processes report the path a
	// packet is actually taking rather than the one the control plane offered (see pathstate.go).
	t.publishPaths()
}

// sourceOf names the evidence class of an endpoint that ended up carrying a path. An endpoint
// that is in no candidate list is one WireGuard roamed to on its own, which is exactly what the
// hard NAT case looks like from here, so it is reported as such rather than as unknown.
func sourceOf(cands []Candidate, endpoint string) CandidateSource {
	for _, c := range cands {
		if c.Endpoint == endpoint {
			return c.Source
		}
	}
	return SourceRoamed
}

// DirectPeers reports what is true on the device right now, for `whale status` and `whale ping`.
// A peer that is armed but has never handshaked reports Promoted false and Path "relayed",
// because that is what its traffic is actually doing.
func (t *Tunnel) DirectPeers() []PeerState {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]PeerState, 0, len(t.direct))
	for _, d := range t.direct {
		path := "relayed"
		endpoint := d.peer.Endpoint
		if d.promoted {
			path = orText(d.peer.Path, "direct")
			if d.punch != nil && d.punch.won {
				endpoint = d.punch.winner.Endpoint
			}
		}
		out = append(out, PeerState{
			Address:  d.peer.Address,
			Name:     d.peer.Name,
			Path:     path,
			Endpoint: endpoint,
			Promoted: d.promoted,
			LastSeen: d.lastSeen,
			Punch:    d.punch.info(d.promoted),
		})
	}
	return out
}

// PathTo reports the path to one overlay address: the peer's class while it is promoted, and
// "relayed" for everything else - including an address we hold no peer for at all, which is the
// honest answer, since the box is what carries it.
func (t *Tunnel) PathTo(addr netip.Addr) string {
	if t == nil {
		return "relayed"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.direct {
		if d.peer.Address == addr && d.promoted {
			return orText(d.peer.Path, "direct")
		}
	}
	return "relayed"
}

func peerLabel(p Peer) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Address.String()
}

func orText(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// peerSet is the map the Tunnel holds, guarded by its existing mutex. Aliased here so tunnel.go
// carries one field and none of the direct-path machinery.
type peerSet = map[string]*directPeer

// refreshPeers is the control-plane half of the loop: ask the peer source what this node may
// reach directly, and hand the answer to SetDirectPeers.
//
// It is its OWN goroutine rather than a branch of the health monitor, and that is deliberate
// even though one loop is usually the right answer here. The monitor reads a local device on a
// 5-second tick and must never block; this makes a network call to the control plane on a
// 60-second tick and can. Folding a blocking control call into the device-health loop would
// mean a slow control plane stalling the tunnel's own health detection, which is the one thing
// that loop exists to do.
//
// Fail-open, and loudly enough to be diagnosable but not enough to be noise: a refresh that
// fails changes nothing. The peers already installed keep working, the relay keeps carrying
// everything else, and the next tick tries again. A control plane that is down must never cost
// a node the paths it already has.
func (t *Tunnel) refreshPeers(src func(ctx context.Context) ([]Peer, error), every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	first := time.After(0) // ask once immediately: a node should not wait a minute for its fleet
	for {
		select {
		case <-t.stop:
			return
		case <-first:
			first = nil
			t.refreshPeersOnce(src)
		case <-tick.C:
			t.refreshPeersOnce(src)
		}
	}
}

func (t *Tunnel) refreshPeersOnce(src func(ctx context.Context) ([]Peer, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peers, err := src(ctx)
	if err != nil {
		return // fail-open: keep what we have, keep relaying the rest, try again next tick
	}
	_ = t.SetDirectPeers(peers)
}
