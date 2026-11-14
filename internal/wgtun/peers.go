// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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
// by both ends handshaking at the endpoints the server observed them arriving from. A pair the plane
// can only relay is punched too, inside the shared window the plane hands both ends (rendezvous.go).
// What remains relayed after that is a pair where BOTH ends sit behind a NAT that varies its external
// port per destination, and a pair split across two boxes, which no single box can advise.
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
	// rides on: the far side's keepalive every 5 seconds (it arms us with the same value) is the
	// evidence a promoted path is alive between WireGuard's two-minute rekeys, so a path that dies
	// is noticed and withdrawn within directDeadAfter rather than within a minute. (A keepalive is
	// not a handshake: a live session handshakes only on rekey.) On a LAN this is one small
	// packet every five seconds; the latency it buys back is three orders of magnitude larger.
	directKeepalive = 5

	// directDeadAfter is how long a promoted peer may go with neither a new handshake nor a single
	// authenticated packet from it before its /128 is withdrawn and the box carries it again. Four
	// of the far side's keepalives.
	directDeadAfter = 20 * time.Second

	// directRearmAfter is how long a peer whose untimed punch train has been SPENT waits before
	// another train starts, which rotates the endpoints from the top again. It applies only to a row
	// that carries no window, which is what a control plane from before windows sends.
	//
	// It decides when the endpoints are tried again, not how much is sent. An untimed peer is armed
	// with a keepalive, and wireguard-go starts a fresh round of handshake attempts on every
	// keepalive while it has no session (its attempt counter is reset each time), so such a peer
	// sends an initiation every five seconds for as long as it is armed, train or no train. A row
	// that carries the pair's window (Peer.Window) does not: once its first train is spent it is
	// silenced and tried again only inside the window, like a relayed pair (punch.go, fallBack).
	// It is also the shortest gap between two first trains for one key, however often the row is
	// re-armed or removed and installed again, so a peer that keeps changing its declared endpoints
	// cannot keep this node sending untimed trains at them.
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
	// Rendezvous is the plane's shared punch window, set for a peer the plane could only RELAY and
	// advised a punch for. Such a peer is armed silent and sends only inside the windows its train
	// attends (punchTrain.windowStep), because a punch through two NATs works only if both ends send
	// inside one mapping lifetime. Zero for every other peer, which is punched as before.
	Rendezvous Rendezvous
	// Listed marks a row the plane still lists but that this client installs nothing from on this
	// read: a relayed peer with no punch advice, most often because the box that answered has not
	// observed the pair while the other one had. It is never armed. With Hold set it keeps a peer
	// already installed at the same Address in place (see keepsHeld), with the same key when
	// PublicKeyHex is set. A peer whose row is gone altogether is removed as before, which is how
	// revocation reaches a direct pair.
	Listed bool
	// Hold is set on a Listed row whose punch verdict is "unknown": the box that answered had no
	// evidence about the pair (it has not observed one of the two tunnels, or holds no key for the
	// peer), which is not a refusal. Only such a row keeps a peer in place (keepsHeld). A Listed row
	// without it (a verdict of "unlikely" or "not-needed", or none at all) keeps nothing.
	Hold bool
	// Vouched is set on a Listed row that states the tunnel key the plane binds to the address (the
	// row's tunnel_key), and VouchedKeyHex is that key: empty when the plane binds none it will name
	// (no key, two it cannot choose between, or a pair not permitted both ways), and a value no key
	// can equal when the row's key could not be read. A promoted peer whose key the plane vouches for
	// is held for as long as it does; a row that names another key removes it at once (keepsHeld).
	Vouched       bool
	VouchedKeyHex string
	// Window is the pair's shared window on a DIRECT row (the plane sends it on every pair permitted
	// both ways). Such a peer is punched at once, the untimed way, and once that first train is spent
	// it is silenced and tried again only inside this window, which both ends compute alike, so a
	// direct path that never answers stops costing a packet every five seconds and the two ends still
	// meet when one of them is behind something that drops what it did not ask for. Zero on a row
	// without one, which is punched untimed for as long as it is armed, as before.
	Window Rendezvous
}

// VouchedUnreadable is the VouchedKeyHex of a row whose tunnel_key is not a WireGuard key, and VouchedNone
// that of a row saying the address has no key at all: values no key in hex can equal, so either reads as the
// plane vouching for no installed key, and the peer goes.
const (
	VouchedUnreadable = "!"
	VouchedNone       = "!none"
)

// KeyHex is a WireGuard public key, base64 as the control plane writes it, in the hex form the tunnel keys
// its peers by; false when it is not a WireGuard key.
func KeyHex(publicKeyB64 string) (string, bool) {
	h, err := keyBase64ToHex(publicKeyB64)
	return h, err == nil
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

// sameCandidates reports whether two peers offer the same endpoints in the same order, leaving
// out the observed ones. It is what decides whether a control-plane refresh may leave a peer's
// train alone: an unchanged list must never reset a peer that is working or punching.
//
// The observed endpoints are left out because they are one box's view. An active/active pair
// answers the peer map from either box, and only the box a peer's tunnel lands on has seen where
// it arrives from, so the observed endpoint comes and goes from one refresh to the next. If that
// counted as a change, an unpromoted peer would be re-armed from scratch every other minute and
// its train would never get as far as the observed endpoint, which it tries last. The new list is
// still adopted; it just does not restart the train.
func sameCandidates(a, b Peer) bool {
	if a.Rendezvous.IsZero() != b.Rendezvous.IsZero() {
		return false // a timed peer and an untimed one are punched differently, so re-arm
	}
	x, y := declaredCandidates(a.candidateList()), declaredCandidates(b.candidateList())
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

func declaredCandidates(in []Candidate) []Candidate {
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		if c.Source != SourceObserved {
			out = append(out, c)
		}
	}
	return out
}

// pathClass is the class a promoted peer reports: the one the control plane offered, except that
// a peer offered as direct-local whose handshake landed at the endpoint a box OBSERVED, or that
// WireGuard roamed to a public address nobody offered, did not take the local path. That is a punch
// through a NAT, and the PATH column says so rather than claiming a shared segment that never
// answered. A roam to another private address is a LAN peer answering from a second address (or a
// renumbered one), and stays direct-local; so does a win at a row's single endpoint, which a row
// with no candidate list classes public.
func (d *directPeer) pathClass() string {
	class := orText(d.peer.Path, "direct")
	if class != pathDirectLocal || d.punch == nil || !d.punch.won {
		return class
	}
	switch d.punch.winner.Source {
	case SourceObserved:
		return pathDirectPunch
	case SourceRoamed:
		if ap, err := netip.ParseAddrPort(d.punch.winner.Endpoint); err == nil && !ap.Addr().Unmap().IsPrivate() {
			return pathDirectPunch
		}
	}
	return class
}

// The two path tokens pathClass reads and writes, spelled as the control plane and whale.Path* spell them.
const (
	pathDirectLocal = "direct-local"
	pathDirectPunch = "direct-punch"
)

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
// pointed at loopback, at a tailnet, at our own overlay, or at multicast.
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

// ListedPeer is the marker for a row the plane lists with nothing to install (see Peer.Listed): the
// row's address, which must be one agent /128 like any peer's, and the key it named, when it named a
// WireGuard key. It reports false for an address that is not an agent's, which marks nothing.
func ListedPeer(allowedIP, publicKeyB64 string) (Peer, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(allowedIP, "[]")))
	if err != nil {
		return Peer{}, false
	}
	addr = addr.Unmap()
	if !addr.Is6() || !agentBlock().Contains(addr) {
		return Peer{}, false
	}
	p := Peer{Address: addr, Listed: true}
	if keyHex, kerr := keyBase64ToHex(publicKeyB64); kerr == nil {
		p.PublicKeyHex = keyHex
	}
	return p, true
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
// - a tailnet, either range (tailnet.go): another overlay carries it, so it is not a direct path.
// - link-local, multicast, unspecified, reserved IPv4 (240.0.0.0/4, the limited broadcast with
// it): not dialable, or not ours to dial.
// - a zone (%eth0): it names an interface on one host, and no prefix contains a zoned address.
func checkUnderlayEndpoint(endpoint string) error {
	_, err := parseUnderlayEndpoint(endpoint)
	return err
}

// parseUnderlayEndpoint is checkUnderlayEndpoint that also hands back what passed, so a caller
// stores and writes the canonical form (an IPv4-mapped address as plain IPv4, lower case, no
// leading zeros in the port) and never the text it was given.
func parseUnderlayEndpoint(endpoint string) (netip.AddrPort, error) {
	host, portStr, err := splitHostPortLiteral(strings.TrimSpace(endpoint))
	if err != nil {
		return netip.AddrPort{}, err
	}
	// ParseUint, not Atoi: a port is digits, and Atoi would read "+51820" as one, which let a spelling
	// slip past a check made on the text before it was canonicalised.
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port < 1 {
		return netip.AddrPort{}, errors.New("the peer's endpoint has no usable port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, errors.New("the peer's endpoint is not a literal address")
	}
	if ip.Zone() != "" {
		return netip.AddrPort{}, errors.New("the peer's endpoint carries an interface zone, which only means something on one host")
	}
	ip = ip.Unmap()
	if err := refuseUnderlayAddr(ip); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}

// refuseUnderlayAddr is the address half of parseUnderlayEndpoint, for an unmapped, unzoned address.
func refuseUnderlayAddr(ip netip.Addr) error {
	switch {
	case ip.IsLoopback():
		return errors.New("the peer's endpoint is a loopback address")
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast():
		return errors.New("the peer's endpoint is not a dialable unicast address")
	case ip.IsUnspecified():
		return errors.New("the peer's endpoint is the unspecified address")
	case ip.Is4() && ip.As4()[0] >= 240:
		return errors.New("the peer's endpoint is in reserved IPv4 space")
	case agentBlock().Contains(ip):
		return errors.New("the peer's endpoint is inside the Whisper overlay")
	case InTailnet(ip):
		return errors.New("the peer's endpoint is a tailnet address, which another overlay carries")
	}
	return nil
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
	// lastSeen is when this node last OBSERVED evidence that the path works: a new handshake, or,
	// while promoted, more authenticated bytes from the peer. It is the observation time, not the
	// handshake's own timestamp: WireGuard writes last_handshake_time only on a handshake,
	// which with a live session is every two minutes, so a timestamp-aged window both demoted a
	// healthy path directDeadAfter after each handshake and, read one late tick after a handshake
	// on a loaded box, refused to promote a path that had just been proven.
	lastSeen   time.Time
	lastHS     time.Time // the newest handshake timestamp read from the device for this peer
	rx         uint64    // rx_bytes at the last read
	armedAt    time.Time // when we last kicked a handshake attempt
	promotedAt time.Time // when the path was last promoted (zero when it never was)
	demotes    int
	// punch is the traversal train for this peer: which candidate endpoint the next attempt
	// aims at, how many attempts this train has made, and how it ended. The promote/demote decision
	// below is unchanged by it.
	punch *punchTrain
	// held is how many reads in a row have kept this peer only on rows with no evidence (keepsHeld),
	// and heldSince when the first of them did.
	held      int
	heldSince time.Time
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
	wantedAt := make(map[netip.Addr]bool, len(peers))
	held := map[netip.Addr]heldRow{} // a row the answering box had no evidence for, by address
	var timed []Peer
	for _, p := range peers {
		if p.Listed {
			if p.Hold && p.Address.IsValid() {
				held[p.Address] = heldRow{named: p.PublicKeyHex, vouched: p.Vouched, vouchedKey: p.VouchedKeyHex}
			}
			continue
		}
		if p.PublicKeyHex == "" || p.PublicKeyHex == t.cfg.ServerPublicKeyHex || p.PublicKeyHex == t.selfPubHex ||
			p.Address == t.cfg.Address {
			// Never let a peer row impersonate the box: the box peer holds ::/0, and a row that
			// reused its key would rewrite the default route rather than add a path beside it.
			// Nor our own key, which wireguard-go would quietly turn into a peer that is not one,
			// nor our own address, which would let another key speak as this node once it handshook.
			continue
		}
		if !p.Rendezvous.IsZero() {
			timed = append(timed, p)
			continue
		}
		wanted[p.PublicKeyHex] = p
		wantedAt[p.Address] = true
	}

	t.mu.Lock()
	if t.direct == nil {
		t.direct = map[string]*directPeer{}
	}
	for _, p := range capTimed(timed, t.direct, t.cfg.Address) {
		wanted[p.PublicKeyHex] = p
		wantedAt[p.Address] = true
	}
	var remove []string
	var arm []Peer
	carry := map[string]punchCarry{}
	for key, cur := range t.direct {
		if next, ok := wanted[key]; !ok {
			switch keepsHeld(cur, held, wantedAt, key, time.Now()) {
			case heldVouched:
				cur.held = 0 // the plane vouches for this very key: evidence, as a direct row is
				continue
			case heldBounded:
				if cur.held == 0 {
					cur.heldSince = time.Now()
				}
				cur.held++ // kept on a read with no evidence; maxHeldReads of them, or maxHeldAge, and it goes
				continue
			}
			remove = append(remove, key)
		} else if next.Address != cur.peer.Address ||
			(!cur.promoted && !sameCandidates(next, cur.peer)) {
			arm = append(arm, next) // the row changed materially: re-arm it from scratch
			// ...but not its backoff: a row that keeps changing must not buy a fresh run of attempts each
			// time it does (punchCarry). A handshake is what starts the backoff over, and a promoted peer
			// is never re-armed here.
			carry[key] = cur.punch.carry()
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
			cur.held = 0
			if cur.punch.timed() && !sameEndpoints(cur.peer.candidateList(), next.candidateList()) {
				// The far side's NAT handed it a new mapping: new evidence, so the backoff starts over.
				cur.punch.freshEvidence()
			}
			cur.peer.Name = next.Name
			cur.peer.Path = next.Path
			cur.peer.Candidates = next.candidateList()
			cur.punch.adopt(cur.peer.Candidates)
			if cur.punch.timed() && !next.Rendezvous.IsZero() {
				cur.peer.Rendezvous = next.Rendezvous
				cur.punch.adoptWindow(next.Rendezvous)
			}
			if !next.Window.IsZero() {
				// A row whose window comes and goes (a plane mid-upgrade) keeps the last one it carried:
				// the window is a pure function of the pair, so it does not go stale.
				cur.peer.Window = next.Window
				cur.punch.adoptFallback(next.Window)
			}
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
		now := time.Now()
		c := carry[p.PublicKeyHex]
		t.mu.Lock()
		c.preludeAt = t.lastPrelude(p.PublicKeyHex, now)
		t.mu.Unlock()
		tr := newPunchTrainFor(p, t.cfg.Address, now, c, orDur(t.directRearm, directRearmAfter))
		if err := t.armDirectPeer(p, tr.timed()); err != nil {
			// Leave nothing half-installed: an untracked peer on the device is one nothing will
			// ever remove, and the reconciler cannot promote or demote what it does not know about.
			_ = t.dev.IpcSet("public_key=" + p.PublicKeyHex + "\nremove=true\n")
			t.note("whisper: direct path to %s not armed (%v) - it stays relayed", peerLabel(p), err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		t.mu.Lock()
		if !tr.preludeAt.IsZero() {
			t.notePrelude(p.PublicKeyHex, tr.preludeAt)
		}
		t.direct[p.PublicKeyHex] = &directPeer{
			peer:    p,
			armedAt: now,
			punch:   tr,
		}
		t.mu.Unlock()
	}
	return firstErr
}

// lastPrelude is when a first (untimed) train last started for this key, kept across a removal and a
// re-install for directRearmAfter, so the gap between two first trains for one key holds however the
// key's rows come and go. Zero when there was none that recent. Called with mu held.
func (t *Tunnel) lastPrelude(keyHex string, now time.Time) time.Time {
	at, ok := t.preludes[keyHex]
	if !ok || now.Sub(at) >= orDur(t.directRearm, directRearmAfter) {
		return time.Time{}
	}
	return at
}

// notePrelude records a first train's start for lastPrelude, and drops the ones too old to matter, so
// the map is bounded by the keys that started a train in the last directRearmAfter. Called with mu held.
func (t *Tunnel) notePrelude(keyHex string, at time.Time) {
	if t.preludes == nil {
		t.preludes = map[string]time.Time{}
	}
	for k, v := range t.preludes {
		if at.Sub(v) >= orDur(t.directRearm, directRearmAfter) {
			delete(t.preludes, k)
		}
	}
	t.preludes[keyHex] = at
}

// maxHeldReads and maxHeldAge bound how long a peer may be kept on rows that carry no evidence
// (keepsHeld) before it is removed: ten reads in a row, and ten minutes on the monotonic clock whatever
// the refresh interval is. The bound is how long a rotated-away key can outlive its rotation when no read
// names the new one, so it applies to every peer the plane does not vouch for. A PROMOTED peer whose row
// states its own key as the one the plane binds to the address (tunnel_key) is not bounded: its path is
// proven by handshakes and its key is vouched for on every such read, and the first read that names
// another key removes it.
const (
	maxHeldReads = 10
	maxHeldAge   = 10 * time.Minute
)

// heldRow is what a Listed row with the hold says about its address: the key it named (public_key or
// punch_key), and, when it carries tunnel_key, that the plane vouches for a key and which one.
type heldRow struct {
	named      string
	vouched    bool
	vouchedKey string
}

// holdVerdict is keepsHeld's answer.
type holdVerdict int

const (
	heldNot     holdVerdict = iota // remove it
	heldBounded                    // keep it, counted against maxHeldReads and maxHeldAge
	heldVouched                    // keep it: the plane vouches for its key, which resets the count
)

// keepsHeld is the cross-box rule. A peer the read did not ask for stays when the read lists its address
// with a punch verdict of "unknown" (the answering box has no evidence about the pair: no live
// observation of one of the two tunnels, or no key for the peer; not a refusal), installs no other peer at
// it, and does not name another key for it. Only a peer worth holding is held: a PROMOTED one, whose path a
// handshake proved, and a TIMED one, which keeps its place on the window schedule (a pure function of the
// pair) and its backoff.
//
// Which key the read names decides the rest. A row with tunnel_key states the key the plane binds to the
// address: the peer's own key holds a promoted peer for as long as the plane says so (heldVouched) and a
// timed one within the bounds; an empty one (no key, or none the plane can choose between, or a pair no
// longer permitted both ways, which the verdict already refuses) is no evidence either way and holds
// within the bounds; any other key, or one this client cannot read, removes it at once. A row without
// tunnel_key (a plane from before it) holds within the bounds when it names this key or none. A verdict of
// "unlikely" or "not-needed", a row that is gone, or another peer at the address removes the peer as
// before, which is how a revocation still reaches a direct pair.
func keepsHeld(cur *directPeer, held map[netip.Addr]heldRow, wantedAt map[netip.Addr]bool, key string, now time.Time) holdVerdict {
	if !cur.promoted && !cur.punch.timed() {
		return heldNot
	}
	h, ok := held[cur.peer.Address]
	if !ok || wantedAt[cur.peer.Address] {
		return heldNot
	}
	if h.vouched {
		switch {
		case h.vouchedKey == key && cur.promoted:
			return heldVouched
		case h.vouchedKey != key && h.vouchedKey != "":
			return heldNot
		}
	} else if h.named != "" && h.named != key {
		return heldNot
	}
	if cur.held > 0 && now.Sub(cur.heldSince) >= maxHeldAge {
		return heldNot
	}
	if cur.held >= maxHeldReads {
		return heldNot
	}
	return heldBounded
}

// maxTimedPeers caps how many relayed pairs this node punches. A timed peer is a wireguard-go peer (two
// goroutines and their queues) and up to three handshake initiations per window it attends, so a peer
// map of thousands of advised rows, from a huge fleet or a hostile plane, must not become thousands of
// peers. Past the cap the pairs with the lowest pairRank are kept, so every read picks the same set and
// nothing churns. The worst case at the cap is about 384 initiations of 148 bytes a minute, falling to a
// sixteenth of that as the backoff settles; real fleets are far below it.
const maxTimedPeers = 128

// capTimed returns the timed peers this read may hold: every one already promoted, then the lowest
// pairRank up to maxTimedPeers in all.
//
// The rank is the PAIR's, so both ends of a pair compute the same number and mostly make the same choice.
// A punch needs both ends to attend, so a pair one end keeps and the other drops is a pair that sends and
// never meets. Ranking by the peer's address did exactly that past the cap: a node whose address sorted
// above the 128th attended 128 lower peers whose own sets were full of other low addresses, so none of them
// attended it back, and it went direct with nobody at all. By the pair's rank, only the pairs at the edge of
// one node's 128 and not the other's differ, about the square root of the cap per node.
func capTimed(timed []Peer, cur map[string]*directPeer, self netip.Addr) []Peer {
	if len(timed) <= maxTimedPeers {
		return timed
	}
	rank := make(map[netip.Addr]uint64, len(timed))
	for _, p := range timed {
		rank[p.Address] = pairRank(self, p.Address)
	}
	sort.Slice(timed, func(i, j int) bool {
		ri, rj := rank[timed[i].Address], rank[timed[j].Address]
		if ri != rj {
			return ri < rj
		}
		return timed[i].Address.Less(timed[j].Address)
	})
	out := make([]Peer, 0, maxTimedPeers)
	var rest []Peer
	for _, p := range timed {
		if d := cur[p.PublicKeyHex]; d != nil && d.promoted {
			out = append(out, p)
		} else {
			rest = append(rest, p)
		}
	}
	for _, p := range rest {
		if len(out) >= maxTimedPeers {
			break
		}
		out = append(out, p)
	}
	return out
}

// pairRank is a number for the pair of two overlay addresses that both ends compute the same: the first
// eight bytes of SHA-256 over the lower address's sixteen bytes and then the higher's. It takes nothing from
// the plane, so no reading of a row and no clock can make the two ends disagree, and it spreads a fleet's
// pairs evenly, unlike their windows, which a rank by window would bunch into the first seconds of every
// minute. A cryptographic hash because the addresses of one fleet differ in a few low bytes, and a hash
// without full avalanche (FNV-1a, measured) ranks one node's pairs together and leaves it reciprocated by
// almost nobody.
func pairRank(a, b netip.Addr) uint64 {
	if b.Less(a) {
		a, b = b, a
	}
	x, y := a.As16(), b.As16()
	sum := sha256.Sum256(append(x[:], y[:]...))
	return binary.BigEndian.Uint64(sum[:8])
}

// sameEndpoints reports whether two candidate lists name the same endpoints in the same order.
func sameEndpoints(a, b []Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Endpoint != b[i].Endpoint {
			return false
		}
	}
	return true
}

// armDirectPeer installs a candidate with its endpoint and keepalive but NO allowed-ips, so it
// can handshake without any traffic being routed to it. replace_allowed_ips with nothing after
// it is what clears the list - both on a first install and on a demote.
//
// Setting the keepalive from 0 to a non-zero value makes wireguard-go send an immediate
// keepalive, which forces a handshake initiation. That is the whole trigger; there is nothing
// else to poke.
//
// A peer whose train is timed from the start is armed SILENT instead (quietDoc): no keepalive, so no
// initiation until the first window its train attends. That is a relayed pair, and a direct row whose
// first train for this key ran too recently to run another (see directRearmAfter). Its first packet
// then leaves at the same moment as the far side's, which is the whole of what makes a punch through two
// NATs work. Written with the peer-write lock held, by SetDirectPeers, so the create in it cannot race a
// removal.
func (t *Tunnel) armDirectPeer(p Peer, silent bool) error {
	endpoint := p.Endpoint
	if cands := p.candidateList(); len(cands) > 0 {
		endpoint = cands[0].Endpoint
	}
	if silent {
		return t.dev.IpcSet(quietDoc(p, endpoint))
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
//
// It also sets the keepalive. A silent peer (one with a window, between windows) can be promoted by a
// handshake the FAR side started, and with no keepalive of its own it would send nothing on an idle
// path, so the far side would see no packet from us and withdraw its end within directDeadAfter. For
// a peer that already has the keepalive this line changes nothing and sends nothing extra.
func (t *Tunnel) promoteDirectPeer(p Peer) error {
	cfg := "public_key=" + p.PublicKeyHex + "\n" +
		"update_only=true\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=" + p.Address.String() + "/128\n" +
		fmt.Sprintf("persistent_keepalive_interval=%d\n", directKeepalive)
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
//
// What counts as evidence is deliberately asymmetric. PROMOTION needs a handshake newer than
// any seen before: that is the one thing that proves our packets reach the peer AND its answers
// reach us, and it is what keeps a /128 from being routed at a peer that never answered. STAYING
// promoted also accepts authenticated bytes from the peer: its keepalives (directKeepalive, every
// five seconds from a far side that has armed us) are what prove a live session between the
// two-minute rekeys. Either is stamped with the time this pass observed it, so a late tick cannot
// age a handshake out before the monitor has seen it.
func (t *Tunnel) reconcileDirectPeers(now time.Time, seen map[string]time.Time, received map[string]uint64) {
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
		quiet   bool
		once    bool
		cand    Candidate
		at      time.Time
		slot    int64
	}
	var todo []action
	for key, d := range t.direct {
		if hs, ok := seen[key]; ok && hs.After(d.lastHS) {
			d.lastHS = hs
			d.lastSeen = now
		}
		if rx, ok := received[key]; ok && rx > d.rx {
			d.rx = rx
			if d.promoted {
				d.lastSeen = now
			}
		}
		fresh := !d.lastSeen.IsZero() && now.Sub(d.lastSeen) < orDur(t.directDead, directDeadAfter)
		switch {
		case fresh && !d.promoted:
			d.promoted = true
			d.promotedAt = now
			todo = append(todo, action{p: d.peer, promote: true})
		case !fresh && d.promoted:
			d.promoted = false
			d.demotes++
			d.armedAt = now
			// Start a fresh punch train at the endpoint that carried the path last time: after a
			// path has been up and died, that is the likeliest place to find it again. A direct row whose
			// path lasted less than one rekey, with an untimed train for the key inside directRearmAfter, goes
			// back to its window instead (restartFor), and an untimed train it does run is recorded.
			lasted := now.Sub(d.promotedAt) >= 2*time.Minute
			freshTrain := lasted || t.lastPrelude(key, now).IsZero()
			d.punch.restartFor(now, d.punch.winner, freshTrain)
			if freshTrain && d.punch.canFallBack() {
				t.notePrelude(key, now)
			}
			// A timed peer is demoted by the quiet write, which withdraws the /128 and its keepalive
			// in one: the next packet it sends is at the next window, like the far side's.
			todo = append(todo, action{p: d.peer, demote: true, quiet: d.punch.timed()})
		case !fresh && !d.promoted && d.punch.timed():
			// A relayed pair: punched only inside the plane's windows, silenced between them.
			switch act, c, at := d.punch.windowStep(now, t.punchEvery, t.healthEvery+t.healthEvery/10, d.rx); act {
			case punchSend:
				d.armedAt = now
				todo = append(todo, action{p: d.peer, punch: true, once: true, cand: c, at: at, slot: d.punch.slot})
			case punchQuiet:
				todo = append(todo, action{p: d.peer, quiet: true})
			}
		case !fresh && !d.promoted && d.punch.spent() && d.punch.canFallBack():
			// A direct row's first train is spent and the row carries the pair's window: silence the
			// device and try again only inside the window, like a relayed pair, rather than let the
			// keepalive send an initiation every five seconds for as long as the peer is armed.
			d.punch.fallBack()
			todo = append(todo, action{p: d.peer, quiet: true})
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
			// Under the peer-write lock, like a timed punch fired from its timer (punchAtInstant), so
			// that punch's keepalive-off write can never land after this one's keepalive-on.
			t.peerWrite.Lock()
			err := t.promoteDirectPeer(a.p)
			t.peerWrite.Unlock()
			if err != nil {
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
			if a.quiet {
				t.quietDirectPeer(a.p, true)
			} else {
				_ = t.demoteDirectPeer(a.p)
			}
			t.note("whisper: the direct path to %s stopped answering - falling back to the relay",
				peerLabel(a.p))
		case a.quiet:
			t.quietDirectPeer(a.p, false)
		case a.punch && a.once:
			t.punchAtInstant(a.p, a.cand, a.at, a.slot)
		case a.punch:
			_ = t.punchAt(a.p, a.cand)
		}
	}

	// Publish what the device just told us, so the surfaces in other processes report the path a
	// packet is actually taking rather than the one the control plane offered (see pathstate.go).
	t.publishPaths()
}

// quietDirectPeer silences an unpromoted peer until the next window its train attends (quietDoc), and for
// a timed peer whose path died it is also the demotion: the write back carries no allowed-ips.
//
// It takes the peer-write lock and checks the peer is still tracked and still unpromoted before it
// writes, because quietDoc creates the peer: a quiet that raced SetDirectPeers removing the peer
// would otherwise bring it back as an entry nothing tracks. The promotion write and a timed punch's
// timer take the same lock, so the check cannot go stale between the lock and the write. The device's
// counters start again from zero for a peer written back fresh, so the tracked rx is reset with it;
// left as it was, a session that came up later would have to out-count the old one before its
// keepalives proved anything.
func (t *Tunnel) quietDirectPeer(p Peer, demoting bool) {
	t.peerWrite.Lock()
	defer t.peerWrite.Unlock()
	// One fresh read of what the device has received from this peer, the last moment before the
	// write. A packet that landed after the tick read the device is the far side's initiation, which
	// we have just answered; the silence is put off once rather than throwing that session away. Never
	// for a demotion: that write is what withdraws the /128 from a path that stopped answering, and it
	// must not wait for anything.
	var rxNow uint64
	fresh := false
	if !demoting {
		if dump, err := t.dev.IpcGet(); err == nil {
			rxNow, fresh = parseReceivedDump(dump)[p.PublicKeyHex]
		}
	}
	t.mu.Lock()
	d := t.direct[p.PublicKeyHex]
	if d == nil || d.promoted {
		t.mu.Unlock()
		return
	}
	if fresh && rxNow > d.rx && d.punch.deferQuiet(time.Now(), t.punchEvery) {
		d.rx = rxNow
		t.mu.Unlock()
		return
	}
	d.rx = 0
	cur := d.peer
	endpoint := cur.Endpoint
	if cands := cur.candidateList(); len(cands) > 0 {
		endpoint = cands[0].Endpoint
	}
	t.mu.Unlock()
	_ = t.dev.IpcSet(quietDoc(cur, endpoint))
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
			path = d.pathClass()
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
			return d.pathClass()
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
