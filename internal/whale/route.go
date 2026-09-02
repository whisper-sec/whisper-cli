// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// route.go is the subnet-router half of Whalenet: what happens when someone advertises a
// prefix from a Whalenet node.
//
// The short version, said plainly because a user typing `--advertise-routes` deserves the
// real answer in one screen rather than a support thread:
//
// 1. A Whisper agent peer is bound to EXACTLY one /128. That is not an oversight to be
// relaxed with a flag: WireGuard's cryptokey routing is what stops one agent sourcing
// another agent's identity, and widening a peer's AllowedIPs to a range would hand that
// away. A subnet router therefore cannot be an agent peer with a bigger prefix. It has
// to be a separate class of peer with its own approval and its own audit trail.
// 2. A route peer is DIRECT-PATH ONLY. Two customers will routinely advertise overlapping
// 10.0.0.0/8, 192.168.0.0/16 or fd00::/8, and a shared box has one FIB per table and
// cannot route per source. This is exactly why Tailscale programs subnet routes in the
// CLIENT's cryptokey routing table and not on a relay. So a route peer needs a
// node-to-node path.
// 3. There is no GENERAL node-to-node path in this build. Some pairs have one - peers on a
// shared segment, a peer whose public endpoint nothing rewrites, and now a peer behind
// an ordinary NAT that a punch got through - but a route has to be ridden by EVERY node
// that uses it, not by the ones that happen to get a direct path.
// UniversalDirectPathAvailable in path.go is what that needs, and it is false: a pair
// with a port-varying NAT at both ends still relays, and a pair split across two boxes
// has no path at all.
//
// So this file does the part that is real and useful today - it VALIDATES the prefix, which
// catches the mistakes that would matter most if it were live, and it explains exactly what
// is missing - and it refuses, from the same constant that answers that question everywhere
// else. When traversal lands and flips UniversalDirectPathAvailable, this refusal opens on
// its own. There is one fact about general direct paths and one place it is written.

// RouteScope says whether a prefix is globally unique or private. It is the distinction
// that decides whether a route could EVER ride a shared FIB: a global prefix is unique on
// the internet, while private space names a different network on every customer's site.
type RouteScope string

const (
	// ScopeGlobal: globally unique space. Two customers cannot legitimately hold the same
	// one, so a shared table could carry it without ambiguity.
	ScopeGlobal RouteScope = "global"
	// ScopePrivate: RFC 1918, ULA, RFC 6598 or link-local. Overlapping by design, and
	// therefore direct-path only forever, not merely until a lands.
	ScopePrivate RouteScope = "private"
)

// Route is one validated advertisement.
type Route struct {
	Input string       `json:"input"`
	CIDR  netip.Prefix `json:"cidr"`
	Scope RouteScope   `json:"scope"`
	// Masked is true when the input carried host bits (10.0.0.1/8) and we canonicalised
	// them away. Liberal in what we accept, and we say what we did with it.
	Masked bool `json:"masked,omitempty"`
}

// String renders the canonical form, which is what any later approval would carry.
func (r Route) String() string { return r.CIDR.String() }

// Reserved space nothing may advertise, in EITHER direction: a prefix that contains one of
// these, or sits inside one, is refused. Advertising Whisper's own space is the one that
// matters most - it would let a node claim other agents' identities - and it is refused
// here as well as by the server's own /128 rule, because two independent refusals of the
// same catastrophe is the right number.
var reservedPrefixes = []struct {
	cidr string
	why  string
}{
	{"2a04:2a01::/32", "Whisper agent identity space: advertising it would let this node claim other agents' addresses"},
	{"2a04:2a00::/32", "Whisper infrastructure space"},
	{"100.64.0.0/10", "RFC 6598 shared address space - a carrier NAT and a Tailscale tailnet both live here, so it names a different machine on every network"},
	{"127.0.0.0/8", "loopback"},
	{"::1/128", "loopback"},
	{"169.254.0.0/16", "link-local, which includes the cloud metadata address"},
	{"fe80::/10", "link-local"},
	{"224.0.0.0/4", "multicast"},
	{"ff00::/8", "multicast"},
	{"::ffff:0:0/96", "IPv4-mapped IPv6, which is a way of writing a v4 address rather than a network to route"},
}

// ParseRoute validates one advertised prefix. Postel at the boundary: leading and trailing
// space, any case, and host bits are all accepted and canonicalised; everything that could
// not be a subnet route is refused with the reason, never with "invalid input".
func ParseRoute(raw string) (Route, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Route{}, errors.New("give a prefix, for example 192.168.10.0/24 or 2001:db8:1::/48")
	}
	if !strings.Contains(s, "/") {
		if _, err := netip.ParseAddr(s); err == nil {
			return Route{}, fmt.Errorf("%s is a single address, not a prefix. A subnet router advertises a "+
				"RANGE its LAN sits behind, like %s/24. One address is what your node already has", s, s)
		}
		return Route{}, fmt.Errorf("%q is not a prefix - write it as <network>/<length>, like 192.168.10.0/24", s)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Route{}, fmt.Errorf("%q is not a valid prefix - write it as <network>/<length>, like 192.168.10.0/24", s)
	}
	masked := p.Masked()
	r := Route{Input: s, CIDR: masked, Masked: masked.Addr() != p.Addr(), Scope: scopeOf(masked)}

	if p.Bits() == 0 {
		return Route{}, fmt.Errorf("%s is a default route, not a subnet. Your node already sends everything "+
			"through Whisper: a subnet router advertises the LAN sitting behind it, not the internet", masked)
	}
	if masked.Addr().IsUnspecified() {
		return Route{}, fmt.Errorf("%s starts at the unspecified address, which is not a network anyone "+
			"can be behind. Advertise the LAN prefix itself, like 192.168.10.0/24", masked)
	}
	if p.Addr().Is4In6() {
		return Route{}, fmt.Errorf("%s is an IPv4-mapped IPv6 prefix. Advertise the IPv4 prefix itself", s)
	}
	for _, res := range reservedPrefixes {
		rp := netip.MustParsePrefix(res.cidr)
		if rp.Addr().Is4() != masked.Addr().Is4() {
			continue
		}
		if overlaps(rp, masked) {
			return Route{}, fmt.Errorf("%s overlaps %s (%s), which nothing may advertise", masked, res.cidr, res.why)
		}
	}
	return r, nil
}

// ParseRoutes validates a list, accepting both repeated arguments and comma-separated ones
// because both are what people type. Every entry is reported, not just the first failure:
// a person fixing three typos should learn about all three in one run.
func ParseRoutes(args []string) ([]Route, error) {
	var out []Route
	var bad []string
	seen := map[string]bool{}
	for _, arg := range args {
		for _, field := range strings.Split(arg, ",") {
			if strings.TrimSpace(field) == "" {
				continue
			}
			r, err := ParseRoute(field)
			if err != nil {
				bad = append(bad, err.Error())
				continue
			}
			if seen[r.String()] {
				continue
			}
			seen[r.String()] = true
			out = append(out, r)
		}
	}
	if len(bad) > 0 {
		return out, errors.New(strings.Join(bad, "; "))
	}
	if len(out) == 0 {
		return nil, errors.New("give at least one prefix, for example 192.168.10.0/24")
	}
	return out, nil
}

// overlaps reports whether two prefixes of the same family intersect at all.
func overlaps(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }

func scopeOf(p netip.Prefix) RouteScope {
	a := p.Addr()
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback() {
		return ScopePrivate
	}
	if a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return ScopePrivate
	}
	if a.Is6() && netip.MustParsePrefix("fc00::/7").Contains(a) {
		return ScopePrivate // ULA
	}
	return ScopeGlobal
}

// RouteSupport is the machine-readable answer to "can this node advertise a route", with
// each blocker named separately so a caller can render them and a test can assert on them
// rather than on a sentence.
type RouteSupport struct {
	Supported bool     `json:"supported"`
	Blockers  []string `json:"blockers"`
	Tier      string   `json:"tier"`
}

// The two structural blockers, spelled once so the CLI and the tests read the same words.
const (
	BlockerNoDirectPath  = "no-direct-path"
	BlockerNotKernelTier = "not-kernel-tier"
)

// SupportForRoutes reports whether this build and this node could carry a subnet route.
// tier is the local session tier ("wireguard", "socks5", "" when nothing is connected).
//
// Kernel tier only: the default userspace tier is a gVisor netstack with one address and no
// forwarding path, so it can be neither a subnet router nor an exit node - not "does not
// yet", cannot. The userspace tunnel reports itself as "wireguard"; a kernel wg-quick node
// is not run by this binary at all, which is exactly why the answer says so out loud.
func SupportForRoutes(tier string) RouteSupport {
	s := RouteSupport{Tier: tier}
	// UniversalDirectPathAvailable, not DirectPathAvailable: direct paths gave SOME pairs a
	// direct path (one segment, or an untranslated public endpoint), and a per-peer PATH
	// column can honour that per peer. A route cannot. It is programmed in the other node's
	// cryptokey routing table and has to be ridden by every node that uses it, so it needs
	// the path to exist in GENERAL - which needs traversal, which this build has none of.
	if !UniversalDirectPathAvailable {
		s.Blockers = append(s.Blockers, BlockerNoDirectPath)
	}
	if !isKernelTier(tier) {
		s.Blockers = append(s.Blockers, BlockerNotKernelTier)
	}
	s.Supported = len(s.Blockers) == 0
	return s
}

// isKernelTier: only a kernel WireGuard node (wg-quick, its own interface, a real
// forwarding path) could ever carry a route. This binary's own tunnel is userspace.
func isKernelTier(tier string) bool { return strings.EqualFold(strings.TrimSpace(tier), "kernel") }

// ExplainRouteBlocker turns one blocker into the paragraph a person can act on. Kept beside
// the constant so a new blocker cannot be added without a sentence to go with it.
func ExplainRouteBlocker(b string) string {
	switch b {
	case BlockerNoDirectPath:
		return "There is no direct node-to-node path in this build for the general case. Many pairs have " +
			"one - peers on a shared segment, a peer whose public endpoint nothing rewrites, and a peer " +
			"behind an ordinary NAT that a punch got through - but a subnet route has to be programmed " +
			"in the OTHER node's cryptokey routing table and ridden directly by EVERY node that uses " +
			"it, because two customers routinely advertise the same 10.0.0.0/8 and one shared box " +
			"cannot hold both. A pair with a port-varying NAT at both ends still relays, and a pair " +
			"split across two boxes has no path at all, so for now there is nothing a route could ride."
	case BlockerNotKernelTier:
		return "This node is not on the kernel tier. The default tunnel is a userspace netstack with one " +
			"address and no forwarding path, so it cannot forward for a LAN behind it no matter what it " +
			"advertises. A subnet router has to be a kernel WireGuard node (wg-quick) with real forwarding."
	default:
		return b
	}
}
