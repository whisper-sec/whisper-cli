// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import "net/netip"

// tailnet.go is the one place this client names a tailnet's address space. Every rule that
// treats a tailnet address specially reads it from here, so the IPv4 and IPv6 halves cannot
// drift apart again: for a while the direct-path filters refused the IPv4 range and passed
// the IPv6 one, which is a ULA and so looked like any other private address.
//
// A Tailscale coordination server numbers its nodes from two ranges, and Headscale defaults
// to the same two:
//
//   - 100.64.0.0/10, RFC 6598 shared address space, which a carrier NAT also uses, and
//   - fd7a:115c:a1e0::/48, a ULA prefix every tailnet numbers from.
//
// An address in either one is an overlay address. It names a node of somebody's tailnet, or
// nothing at all, and it never names a stretch of underlay. That is the property the callers
// rely on: a direct path must not run over another overlay, a policy migrated off a tailnet
// must not carry an address that only meant something inside it, and a subnet route must not
// claim either range (whale/route.go).
//
// The IPv6 address also carries no tailnet identity. A tailnet node's address varies only in
// its low bits, so nodes of unrelated tailnets share one /64, and the same address names a
// different machine, or nothing, in each of them. That is the RFC 6598 property again.

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// TailnetV4 is the IPv4 range a tailnet numbers its nodes from, 100.64.0.0/10.
func TailnetV4() netip.Prefix { return tailnetV4 }

// TailnetV6 is the IPv6 range a tailnet numbers its nodes from, fd7a:115c:a1e0::/48.
func TailnetV6() netip.Prefix { return tailnetV6 }

// InTailnet reports whether an address lies in either tailnet range. An IPv4-mapped IPv6
// address is judged as the IPv4 address it carries, so ::ffff:100.64.0.1 is on a tailnet, and
// a zone is ignored, because netip.Prefix.Contains is false for every zoned address and
// fd7a:115c:a1e0::1%tailscale0 is still a tailnet address. The control plane applies the same
// two ranges to every endpoint it stores and hands out; the two copies change together.
func InTailnet(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	return tailnetV4.Contains(a) || tailnetV6.Contains(a)
}

// TailnetOverlaps reports whether a prefix shares any address with either tailnet range.
func TailnetOverlaps(p netip.Prefix) bool {
	return tailnetV4.Overlaps(p) || tailnetV6.Overlaps(p)
}
