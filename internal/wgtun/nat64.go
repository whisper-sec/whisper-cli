// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// nat64.go is IPv4 reachability from inside the tunnel.
//
// THE PROBLEM, precisely. The tunnel gives this node exactly one address, an IPv6 /128,
// because that is what CreateNetTUN is handed. CreateNetTUN installs a default route only
// for the families it was given an address for, so the stack has no v4 address and no v4
// route at all: a dial to an IPv4 destination is refused inside the netstack before a
// packet is ever built. A destination written as an IPv4 literal - a connection string, a
// NO_PROXY entry, a config file somebody wrote in 2011 - therefore fails, and to the
// caller it fails as a bare "could not connect", which is the worst of the three possible
// outcomes. Every v4-only client library on the host breaks the moment the tunnel comes
// up, and nothing says why.
//
// THE FIX is RFC 6052: an IPv4 destination is carried inside an IPv6 address whose top 96
// bits are the NAT64 prefix and whose bottom 32 bits are the v4 address. We dial that, the
// box's translator unwraps it, and the connection completes over v4 with Whisper's shared
// v4 SNAT as its source. That is the same wire form the box's own egress guard already
// decodes (EgressSsrfGuard treats a NAT64-wrapped target by extracting the embedded v4 and
// running the IPv4 reserved/SSRF check on it), so the two ends agree by construction rather
// than by coincidence.
//
// WHY WE SYNTHESISE HERE AND NOT ONLY IN DNS. DNS64 covers a NAME that has only an A
// record. It cannot cover a LITERAL, because there is no lookup to intercept. Doing the
// synthesis at the dialer covers both, and it means v4 works whether or not the resolver's
// DNS64 is healthy - one less thing on the path that has to be up. Deriving the answer from
// what this node already holds beats fetching it from somewhere else.
//
// WHAT THIS IS NOT. It is not a policy decision about where an agent may connect. That
// lives once, on the box, in the egress guard, and this file does not get a vote. The only
// addresses refused here are the ones a translator cannot carry ANYWHERE - your own LAN,
// loopback, link-local, multicast - and the refusal exists so the user is told "that address
// is on your side of the tunnel" instead of watching a connection hang.

// WellKnownNAT64Prefix is the RFC 6052 section 2.1 well-known prefix, and the value the
// box's egress guard defaults to. Both ends must agree on it, so it is spelled once here
// and once there, and NAT64PrefixSource() reports which one this process is using.
const WellKnownNAT64Prefix = "64:ff9b::/96"

// nat64PrefixEnv lets an operator point a node at a network-specific prefix (RFC 7050
// discovery would be the other way in, and can be added behind this same accessor without
// touching any caller). Liberal in what we accept: with or without the /96, any case.
const nat64PrefixEnv = "WHISPER_NAT64_PREFIX"

// ErrNotIPv4 says the target was not an IPv4 literal, so there was nothing to translate.
// It is not a failure: it is the ordinary answer for every v6 destination and every name.
var ErrNotIPv4 = errors.New("not an IPv4 literal")

// NAT64Prefix returns the prefix this process wraps IPv4 destinations into, and the source
// it came from. An unusable override never silently disables v4: it falls back to the
// well-known prefix and says so, because a wrong prefix and no prefix look identical from
// the outside and only one of them is recoverable by the person reading the note.
func NAT64Prefix() (netip.Prefix, string) {
	raw := strings.TrimSpace(os.Getenv(nat64PrefixEnv))
	if raw == "" {
		return netip.MustParsePrefix(WellKnownNAT64Prefix), "the RFC 6052 well-known prefix"
	}
	p, err := ParseNAT64Prefix(raw)
	if err != nil {
		return netip.MustParsePrefix(WellKnownNAT64Prefix),
			fmt.Sprintf("the RFC 6052 well-known prefix (%s=%q was ignored: %s)", nat64PrefixEnv, raw, err)
	}
	return p, nat64PrefixEnv
}

// nat64PrefixOverride reports the operator's pinned prefix, and whether there is a usable one.
// It exists so RFC 7050 discovery (nameservice.go) can tell "nobody said, so we guessed the
// well-known prefix" from "an operator said, and meant it". Discovery refines the first and
// defers to the second, and says so either way - a silently ignored override and a silently
// unrefined guess are the same bug wearing different clothes.
func nat64PrefixOverride() (netip.Prefix, bool) {
	raw := strings.TrimSpace(os.Getenv(nat64PrefixEnv))
	if raw == "" {
		return netip.Prefix{}, false
	}
	p, err := ParseNAT64Prefix(raw)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// ParseNAT64Prefix accepts a NAT64 prefix in the forms a person actually types and returns
// it canonicalised. Only /96 is accepted: RFC 6052 defines five other lengths whose v4
// embedding straddles the reserved byte at offset 8, and a node that guessed the wrong one
// would produce addresses that are valid, routable and wrong. One length, no guessing.
func ParseNAT64Prefix(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, errors.New("empty")
	}
	if !strings.Contains(s, "/") {
		s += "/96"
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not an IPv6 prefix")
	}
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("a NAT64 prefix is IPv6")
	}
	if p.Bits() != 96 {
		return netip.Prefix{}, fmt.Errorf("must be a /96, got /%d", p.Bits())
	}
	return p.Masked(), nil
}

// Synthesize wraps an IPv4 address in a NAT64 /96 (RFC 6052 section 2.2: the v4 address
// occupies the low 32 bits). The result is what actually goes on the wire.
func Synthesize(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, error) {
	if prefix.Bits() != 96 || !prefix.Addr().Is6() {
		return netip.Addr{}, errors.New("nat64: prefix must be an IPv6 /96")
	}
	v4 = v4.Unmap()
	if !v4.Is4() {
		return netip.Addr{}, ErrNotIPv4
	}
	if err := carriable(v4); err != nil {
		return netip.Addr{}, err
	}
	b := prefix.Masked().Addr().As16()
	four := v4.As4()
	copy(b[12:], four[:])
	return netip.AddrFrom16(b), nil
}

// EmbeddedIPv4 is Synthesize's inverse, and exists so a test can prove the round trip
// rather than assert the same byte layout twice. Reports false for anything outside prefix.
func EmbeddedIPv4(prefix netip.Prefix, a netip.Addr) (netip.Addr, bool) {
	if prefix.Bits() != 96 || !a.Is6() || a.Is4In6() || !prefix.Contains(a) {
		return netip.Addr{}, false
	}
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}

// TranslateTarget rewrites a "host:port" dial target whose host is an IPv4 literal into the
// NAT64 form, and reports whether it did. A name, a v6 literal or an address the tunnel
// cannot carry comes back untouched with ok=false; only a hard refusal (an address on this
// side of the tunnel) returns an error, and that error is the sentence the user sees.
func TranslateTarget(prefix netip.Prefix, target string) (string, bool, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, false, nil // not host:port - leave it exactly as it came
	}
	ip, perr := netip.ParseAddr(strings.Trim(host, "[]"))
	if perr != nil {
		return target, false, nil // a name: the resolver decides, not us
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return target, false, nil // already v6 - nothing to do
	}
	v6, serr := Synthesize(prefix, ip)
	if serr != nil {
		return target, false, serr
	}
	return net.JoinHostPort(v6.String(), port), true, nil
}

// carriable refuses the IPv4 addresses a translator cannot carry anywhere, with the reason
// the user needs rather than a timeout. This is a reachability statement, not a policy one:
// the egress policy lives once, on the box. Postel both ways - we accept the address the
// user typed, and we answer with a sentence they can act on.
func carriable(v4 netip.Addr) error {
	switch {
	case v4.IsUnspecified():
		return errors.New("0.0.0.0 is not a destination")
	case v4.IsLoopback():
		return errors.New("127.0.0.0/8 is this host's own loopback, which is on your side of the tunnel, " +
			"not the far side - reach it directly and leave it out of the proxy")
	case v4.IsLinkLocalUnicast():
		return errors.New("169.254.0.0/16 is link-local (it includes the cloud metadata address) and " +
			"means something different on every host, so the tunnel will not carry it")
	case v4.IsMulticast():
		return errors.New("multicast has no path through a NAT64 translator")
	case v4.IsPrivate():
		return errors.New("that is a private RFC 1918 address on your own LAN. The tunnel reaches the " +
			"internet, not the network you are sitting on: reach it directly, or add it to NO_PROXY. " +
			"Advertising a LAN into Whalenet is a subnet router, and `whisper whale route advertise` " +
			"says exactly where that stands today")
	case inPrefix(v4, "100.64.0.0/10"):
		return errors.New("100.64.0.0/10 is RFC 6598 shared address space - it is what a carrier NAT and " +
			"a Tailscale tailnet use, so it names a different machine on every network and cannot be routed here")
	case inPrefix(v4, "0.0.0.0/8"), inPrefix(v4, "240.0.0.0/4"):
		return errors.New("that address is reserved and is not a destination on the public internet")
	}
	return nil
}

func inPrefix(a netip.Addr, cidr string) bool {
	return netip.MustParsePrefix(cidr).Contains(a)
}
