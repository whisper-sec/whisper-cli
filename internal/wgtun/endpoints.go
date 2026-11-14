// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
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
// for the given WireGuard listen port. The port must be one a socket holds at the time of the
// call, a ListenHold's (listenhold.go) or a running tunnel's ListenPort, never a number that was
// read and let go. Only PRIVATE addresses are declared - RFC1918 and ULA -
// because those are the ones the LOCAL case is about, and because a global address we declare
// is only ever used when the box's own observation independently agrees with it, so declaring
// one buys nothing the observation does not already carry.
//
// Loopback, link-local, multicast, our own overlay 2a04:2a01::/32 and both tailnet ranges
// (tailnet.go) are all excluded, matching the server's sanitiser: an endpoint in any of them is
// one we must never ask a peer to send packets at. A tailnet address is reachable, but over
// another overlay, so a path through it is not a direct path.
//
// Some interfaces are excluded whatever their address (onDeclarableInterface):
//
//   - a point-to-point interface: a tailnet, wg-quick, an OpenVPN tun, a utun, a commercial VPN.
//     Its address belongs to another overlay, and some of those hand every client the same one.
//   - an overlay device: a tun, an L3 tunnel, VXLAN or Geneve where the platform says so (Linux),
//     and ZeroTier by name everywhere. Like a tailnet, a path through it is not a direct path.
//   - an interface that is not running.
//
// A bridge the host keeps for its own containers and VMs (docker0, br-<network id>, virbr0, a CNI,
// Podman, LXC, LXD or Incus bridge, a microVM's tap, a VirtualBox or VMware host-only adapter,
// macOS's vmnet bridges) IS declared, because it is how the host's own guests reach it: an agent on the host and
// one in its container pair over 172.17.0.1 and 172.17.0.2, and nothing else carries that pair
// directly. It is declared after every other address, so the cap never spends a LAN address on
// one. Every Docker host has 172.17.0.1, and two hosts that both declare it are not one segment;
// the control plane tells them apart from what else each declares, and offers the pair the punch
// at the endpoints a box observed if the local path never answers.
//
// It never fails. An interface enumeration that errors yields no endpoints, which means this
// node declares nothing, which means it relays - the same as a node with no private address at
// all, and the same as every node before direct paths.
func LocalUnderlayEndpoints(listenPort int) []string {
	if listenPort < 1 || listenPort > 65535 {
		return nil
	}
	return endpointsOn(hostAddrs(), listenPort)
}

// hostAddr is one address as the gathering sees it: the address, and what is known about the
// interface it sits on. The mask is deliberately not carried, because nothing here may decide on
// it: a cloud VM's real NIC can hold a private /32 (GCE and Hetzner Cloud both do this), and
// refusing a /32 would cost such a fleet its LAN path.
type hostAddr struct {
	Addr  netip.Addr
	Iface string
	Flags net.Flags
	Kind  ifaceKind
}

// ifaceKind is what the platform can say about an interface (endpoints_kind.go). Where it can say,
// it outranks the name, so a LAN bridge OpenWrt calls br-lan is a LAN and a bridge with no way off
// the host is a guest bridge, whatever either is called.
type ifaceKind uint8

const (
	// ifaceUnknown: the platform cannot say, so the name decides (guestBridgeName).
	ifaceUnknown ifaceKind = iota
	// ifaceLAN: a real NIC, or something on or holding one (a VLAN, a bond, a bridge with a NIC in it).
	ifaceLAN
	// ifaceGuestBridge: a bridge none of whose ports leaves the host. Its segment is this machine
	// and its own containers or VMs. Declared, after everything else.
	ifaceGuestBridge
	// ifaceOverlay: a tun or tap, an L3 tunnel, VXLAN or Geneve. Never declared.
	ifaceOverlay
)

// hostAddrs is every address on an interface that is up and is not loopback, in interface order,
// with the interface's name, flags and kind. An interface whose addresses cannot be read is
// skipped, and a failed enumeration yields none.
func hostAddrs() []hostAddr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []hostAddr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		kind := probeIface(ifc.Name, ifc.Index)
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipnet.IP); ok {
				out = append(out, hostAddr{Addr: ip.Unmap(), Iface: ifc.Name, Flags: ifc.Flags, Kind: kind})
			}
		}
	}
	return out
}

// endpointsOn is the gathering itself, over a host's addresses: the declarable ones as ip:port on
// the listen port, first occurrence kept, guest bridges after everything else, capped at
// maxDeclaredEndpoints. It is separate from the enumeration so a test can stand in a host this one
// is not.
func endpointsOn(addrs []hostAddr, listenPort int) []string {
	var out []string
	seen := map[string]bool{}
	for _, wantBridge := range []bool{false, true} {
		for _, a := range addrs {
			ip := a.Addr.Unmap()
			ok, bridge := onDeclarableInterface(a)
			if !ok || bridge != wantBridge || !declarable(ip) {
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

// onDeclarableInterface answers whether an address's interface may be declared at all, and if so
// whether it is a guest bridge, which goes after everything else. None of it is decided by the mask.
//
//   - Not running: an unplugged NIC, a bridge with nothing in it. Nobody reaches it now.
//   - Point-to-point: a tailnet, wg-quick, OpenVPN's tun, macOS's utun and the consumer VPNs are
//     all POINTOPOINT, and their addresses belong to another overlay. Some hand every client the
//     same private address.
//   - An overlay device, by kind where the platform says (Linux).
func onDeclarableInterface(a hostAddr) (ok, guestBridge bool) {
	if a.Flags&net.FlagRunning == 0 || a.Flags&net.FlagPointToPoint != 0 {
		return false, false
	}
	switch a.Kind {
	case ifaceOverlay:
		return false, false
	case ifaceGuestBridge:
		return true, true
	case ifaceLAN:
		return true, false
	}
	if overlayName(a.Iface) {
		return false, false
	}
	return true, guestBridgeName(a.Iface)
}

// overlayName is the overlay half of the name fallback: ZeroTier, whose interface is neither
// point-to-point nor anything else a platform without sysfs can tell apart from a NIC. It is zt* on
// Linux and BSD, a feth pair on macOS and "ZeroTier One [...]" on Windows, and every member of one
// ZeroTier network shares a private /24, so two members at two sites would pair over another overlay.
func overlayName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "zt") || strings.HasPrefix(n, "feth") || strings.HasPrefix(n, "zerotier one")
}

// guestBridgePrefixes are the names the well-known container and VM managers give the bridges and
// adapters they create for their own guests: Docker (docker0, docker_gwbridge), libvirt (virbr0),
// CNI (cni0), Podman (podman0), LXC (lxcbr0), LXD (lxdbr0), Incus (incusbr0), VirtualBox's host-only
// adapters (vboxnet0), VMware's (vmnet1, vmnet8) and Parallels' (vnic0, vnic1).
var guestBridgePrefixes = []string{
	"docker", "virbr", "cni", "podman", "lxcbr", "lxdbr", "incusbr", "vboxnet", "vmnet", "vnic",
}

// guestBridgeWindowsNames are the same adapters as Windows names them: by friendly name, which is
// what Go reports there. "vEthernet (Default Switch)" and WSL's switch are NAT switches for the
// host's own VMs; a vEthernet adapter named for an external switch is the real LAN and is not here.
var guestBridgeWindowsNames = []string{
	"virtualbox host-only", "vmware network adapter vmnet", "vethernet (default switch)", "vethernet (wsl",
}

// guestBridgeName is the fallback for an interface the platform cannot classify. Besides the names
// above it takes Docker's per-network bridges, which are br- and twelve hex digits of the network's
// id (so OpenWrt's br-lan and Open vSwitch's br-ex are not taken), and macOS's vmnet bridges, which
// the system numbers from bridge100 (bridge0 below that is the Thunderbolt bridge, a real link to
// another machine). A wrong guess here only moves an address to the end of the list.
func guestBridgeName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range guestBridgePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, w := range guestBridgeWindowsNames {
		if strings.HasPrefix(n, w) {
			return true
		}
	}
	if id, ok := strings.CutPrefix(n, "br-"); ok && len(id) == 12 && strings.Trim(id, "0123456789abcdef") == "" {
		return true
	}
	if rest, ok := strings.CutPrefix(n, "bridge"); ok {
		if v, err := strconv.Atoi(rest); err == nil && v >= 100 {
			return true
		}
	}
	return false
}

// declarable answers whether an address is one we are willing to tell a peer to dial.
func declarable(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if agentBlock().Contains(ip) || InTailnet(ip) {
		return false
	}
	return ip.IsPrivate() // RFC1918 for v4, fc00::/7 for v6 (less the tailnet's /48, refused above)
}
