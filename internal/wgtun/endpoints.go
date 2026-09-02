// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"strconv"
)

// endpoints.go is the client half of the direct-path evidence: where THIS node can be dialed
// on the underlay, so the control plane can work out which peers share a segment with it.
//
// This is the entire substitute for NAT traversal at that stage, and it is worth being clear about
// how modest it is. Tailscale learns a node's endpoints from a STUN server, a DERP relay and a
// port mapper, and can therefore find a path between two nodes behind different NATs. We
// enumerate the interfaces we are already on and say so. That is enough for two nodes on one
// LAN, which is the shape most real fleets have, and it is enough for a
// node with a public address and no translation in front of it. It is enough for nothing else,
// and this does not pretend otherwise.

// LocalUnderlayEndpoints reports the endpoints this node can be dialed on, as ip:port strings
// for the given WireGuard listen port. Only PRIVATE addresses are declared - RFC1918 and ULA -
// because those are the ones the LOCAL case is about, and because a global address we declare
// is only ever used when the box's own observation independently agrees with it, so declaring
// one buys nothing the observation does not already carry.
//
// Loopback, link-local, multicast, our own overlay 2a04:2a01::/32 and the internal tailnet are
// all excluded, matching the server's sanitiser: an endpoint in any of them is one we must
// never ask a peer to send packets at.
//
// It never fails. An interface enumeration that errors yields no endpoints, which means this
// node declares nothing, which means it relays - the same as a node with no private address at
// all, and the same as every node before direct paths.
func LocalUnderlayEndpoints(listenPort int) []string {
	if listenPort < 1 || listenPort > 65535 {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !declarable(ip) {
				continue
			}
			ep := net.JoinHostPort(ip.String(), strconv.Itoa(listenPort))
			if !seen[ep] {
				seen[ep] = true
				out = append(out, ep)
			}
			if len(out) >= maxDeclaredEndpoints {
				return out
			}
		}
	}
	return out
}

// maxDeclaredEndpoints caps what we send. A host with many interfaces (containers, bridges,
// VPNs) can have dozens of private addresses and the server caps the list anyway; sending more
// than it will keep is noise on every connect.
const maxDeclaredEndpoints = 8

// declarable answers whether an address is one we are willing to tell a peer to dial.
func declarable(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if agentBlock().Contains(ip) || tailnetBlock().Contains(ip) {
		return false
	}
	return ip.IsPrivate() // RFC1918 for v4, fc00::/7 for v6
}

// PickListenPort reserves an ephemeral UDP port and hands the number back. The tunnel then
// binds it as its WireGuard listen_port, which is what makes a declared endpoint MEAN anything:
// without a fixed port the device would bind a random one and the ip:port we declared at
// connect time would be wrong from the moment the tunnel came up.
//
// There is a race here, and it is the ordinary one every "find a free port" has: something else
// could take the port between our close and the device's bind. Losing it costs the direct paths
// for this session and nothing else - Start still brings the tunnel up on a kernel-chosen port
// and every packet relays, exactly as before direct paths. Returns 0 when no port could be reserved,
// which the caller reads as "declare nothing".
func PickListenPort() int {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return 0
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}
