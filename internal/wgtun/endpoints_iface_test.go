// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// endpoints_iface_test.go covers which INTERFACES a node declares from: two hosts that each declare
// the same bridge address (every Docker host has 172.17.0.1) were paired as one segment and each
// dialled its own machine. The hosts here are fakes, so the same test runs on every platform and on a
// CI runner whatever its own interfaces are.

// A running Ethernet NIC's flags, as net.Interfaces reports them.
const nicFlags = net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning

// onNIC stands up addresses on a plain running NIC the platform has classified as a LAN interface.
func onNIC(name string, addrs ...string) []hostAddr {
	return on(name, nicFlags, ifaceLAN, addrs...)
}

func on(name string, flags net.Flags, kind ifaceKind, addrs ...string) []hostAddr {
	out := make([]hostAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, hostAddr{Addr: netip.MustParseAddr(a), Iface: name, Flags: flags, Kind: kind})
	}
	return out
}

func host(parts ...[]hostAddr) []hostAddr {
	var out []hostAddr
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func wantEndpoints(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("declared %v, want exactly %v", got, want)
	}
}

func TestEndpointsOn_ADockerHostDeclaresItsLANFirstAndItsBridgeLast(t *testing.T) {
	// A typical Docker host, with docker0 enumerated first on purpose. The bridge is still declared,
	// because it is how the host's own containers reach it, and it goes after the LAN.
	h := host(
		on("docker0", nicFlags, ifaceGuestBridge, "172.17.0.1"),
		onNIC("enp0s1", "192.168.1.20", "fd12:3456:789a:1::20"),
	)
	wantEndpoints(t, endpointsOn(h, 51820),
		"192.168.1.20:51820", "[fd12:3456:789a:1::20]:51820", "172.17.0.1:51820")
}

func TestEndpointsOn_TheCapNeverSpendsALANAddressOnABridge(t *testing.T) {
	// Ten Docker networks enumerated ahead of the LAN: the LAN is declared, then as many bridges as fit.
	var h []hostAddr
	for i := 0; i < 10; i++ {
		h = append(h, on("br-00000000000"+strconv.Itoa(i), nicFlags, ifaceGuestBridge, "172.20."+strconv.Itoa(i)+".1")...)
	}
	h = append(h, onNIC("eth0", "192.168.1.20")...)
	got := endpointsOn(h, 51820)
	if len(got) != maxDeclaredEndpoints || got[0] != "192.168.1.20:51820" || got[1] != "172.20.0.1:51820" {
		t.Fatalf("declared %v, want the LAN first and then bridges up to the cap of %d", got, maxDeclaredEndpoints)
	}
}

func TestEndpointsOn_KindOutranksTheName(t *testing.T) {
	// OpenWrt names its LAN bridge br-lan; a Docker network's bridge is br- and twelve hex digits. Where
	// the platform has classified the interface, the name does not matter.
	h := host(
		on("eth1", nicFlags, ifaceGuestBridge, "10.30.0.5"),
		on("br-lan", nicFlags, ifaceLAN, "192.168.1.1"),
		on("br-0123456789ab", nicFlags, ifaceLAN, "10.20.0.5"),
	)
	wantEndpoints(t, endpointsOn(h, 51820), "192.168.1.1:51820", "10.20.0.5:51820", "10.30.0.5:51820")
}

func TestEndpointsOn_WhereKindIsUnknownTheNameOrdersIt(t *testing.T) {
	// Not Linux, or no sysfs: a well-known guest bridge goes after everything else, and every other
	// interface keeps the host's own order.
	h := host(
		on("bridge100", nicFlags, ifaceUnknown, "192.168.64.1"),
		on("vboxnet0", nicFlags, ifaceUnknown, "192.168.56.1"),
		on("bridge0", nicFlags, ifaceUnknown, "10.40.0.5"), // the Thunderbolt bridge
		on("br-lan", nicFlags, ifaceUnknown, "192.168.1.1"),
		on("en0", nicFlags, ifaceUnknown, "192.168.1.20"),
	)
	wantEndpoints(t, endpointsOn(h, 51820),
		"10.40.0.5:51820", "192.168.1.1:51820", "192.168.1.20:51820", "192.168.64.1:51820", "192.168.56.1:51820")
}

func TestEndpointsOn_ZeroTierIsAnOverlayByNameWhereKindIsUnknown(t *testing.T) {
	// macOS and Windows cannot classify ZeroTier's interface, and it is not point-to-point.
	h := host(
		on("feth3142", nicFlags, ifaceUnknown, "10.147.17.5"),
		on("ZeroTier One [8056c2e21c000001]", nicFlags, ifaceUnknown, "10.147.18.5"),
		on("ztabcdef12", nicFlags, ifaceUnknown, "10.147.19.5"),
		on("en0", nicFlags, ifaceUnknown, "192.168.1.20"),
	)
	wantEndpoints(t, endpointsOn(h, 51820), "192.168.1.20:51820")
}

func TestEndpointsOn_AnOverlayIsNeverDeclared(t *testing.T) {
	// ZeroTier is a tap and an IPIP or VXLAN device is a tunnel: like a tailnet, a path through one is
	// not a direct path, whatever its address.
	h := host(
		on("zt0", nicFlags, ifaceOverlay, "10.147.17.5"),
		on("vxlan.calico", nicFlags, ifaceOverlay, "192.168.30.1"),
		onNIC("eth0", "192.168.1.20"),
	)
	wantEndpoints(t, endpointsOn(h, 51820), "192.168.1.20:51820")
}

func TestEndpointsOn_APointToPointInterfaceIsNeverDeclared(t *testing.T) {
	// tailscale0, wg-quick, OpenVPN's tun and macOS's utun are all POINTOPOINT; a commercial VPN that hands
	// every client one private address is the same-address trap again. Its kind does not rescue it.
	p2p := net.FlagUp | net.FlagPointToPoint | net.FlagMulticast | net.FlagRunning
	h := host(
		on("wg0", p2p, ifaceUnknown, "10.66.66.2"),
		on("utun4", p2p, ifaceUnknown, "172.16.0.2"),
		on("tun0", p2p, ifaceLAN, "10.8.0.6"),
		onNIC("eth0", "192.168.1.20"),
	)
	wantEndpoints(t, endpointsOn(h, 51820), "192.168.1.20:51820")
}

func TestEndpointsOn_AHost32OnARealNICIsKept(t *testing.T) {
	// GCE and Hetzner Cloud put a private /32 on a VM's real, BROADCAST NIC. There is no mask in a hostAddr
	// at all, so nothing can refuse on it, and such a VM keeps its LAN path.
	wantEndpoints(t, endpointsOn(onNIC("ens4", "10.128.0.5"), 51820), "10.128.0.5:51820")
}

func TestEndpointsOn_AnInterfaceThatIsNotRunningIsNotDeclared(t *testing.T) {
	// An unplugged NIC or an empty bridge is administratively up and carries nothing.
	down := net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	h := host(on("eth1", down, ifaceLAN, "10.1.1.5"), on("docker0", down, ifaceGuestBridge, "172.17.0.1"),
		onNIC("eth0", "192.168.1.20"))
	wantEndpoints(t, endpointsOn(h, 51820), "192.168.1.20:51820")
}

func TestEndpointsOn_AContainersOwnInterfaceIsKept(t *testing.T) {
	// Inside a container eth0 is one end of a veth, which sysfs does not classify. Its name decides, and it
	// is kept, so two containers on one bridge (172.17.0.2 and 172.17.0.3) still pair over it, and so do a
	// container and its host's bridge address.
	wantEndpoints(t, endpointsOn(on("eth0", nicFlags, ifaceUnknown, "172.17.0.2"), 51820), "172.17.0.2:51820")
}

func TestGuestBridgeName_TheNamesItTakesAndTheOnesItLeaves(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "docker_gwbridge": true, "virbr0": true, "cni0": true, "cni-podman0": true,
		"podman0": true, "lxcbr0": true, "lxdbr0": true, "incusbr0": true, "vboxnet0": true,
		"vmnet8": true, "vnic0": true,
		"br-0123456789ab": true, "BR-0123456789AB": true,
		"br-0123456789a":                false, // eleven
		"br-0123456789abc":              false, // thirteen
		"br-0123456789ag":               false, // not hex
		"br-":                           false,
		"br-lan":                        false,
		"br-ex":                         false,
		"bridge100":                     true,
		"bridge99":                      false,
		"bridge0":                       false,
		"bridge":                        false,
		"bridgex":                       false,
		"VirtualBox Host-Only Network":  true,
		"VMware Network Adapter VMnet8": true,
		"vEthernet (Default Switch)":    true,
		"vEthernet (WSL)":               true,
		"vEthernet (External LAN)":      false,
		"eth0":                          false,
		"en0":                           false,
		"":                              false,
	} {
		if got := guestBridgeName(name); got != want {
			t.Fatalf("guestBridgeName(%q) = %v, want %v", name, got, want)
		}
	}
}

// ---- the Linux kind probe, over a fake sysfs ----

// fakeSys builds a /sys/class/net under a temp dir. Each interface is a directory with an ifindex;
// extra entries are created as files, `dir:` entries as directories and `lower_x`/`device` as
// symlinks, which is how sysfs presents them.
type fakeSys struct {
	t    *testing.T
	root string
	next int
}

func newFakeSys(t *testing.T) *fakeSys {
	return &fakeSys{t: t, root: t.TempDir(), next: 1}
}

func (f *fakeSys) iface(name string, entries ...string) int {
	f.t.Helper()
	dir := filepath.Join(f.root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	idx := f.next
	f.next++
	f.write(filepath.Join(dir, "ifindex"), strconv.Itoa(idx)+"\n")
	f.write(filepath.Join(dir, "type"), "1\n")
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "brif/"):
			if err := os.MkdirAll(filepath.Join(dir, "brif"), 0o755); err != nil {
				f.t.Fatal(err)
			}
			f.write(filepath.Join(dir, e), "")
		case strings.HasPrefix(e, "dir:"):
			if err := os.MkdirAll(filepath.Join(dir, strings.TrimPrefix(e, "dir:")), 0o755); err != nil {
				f.t.Fatal(err)
			}
		case e == "device" || strings.HasPrefix(e, "lower_"):
			if err := os.Symlink("../somewhere", filepath.Join(dir, e)); err != nil {
				f.t.Fatal(err)
			}
		case strings.Contains(e, "="):
			k, v, _ := strings.Cut(e, "=")
			f.write(filepath.Join(dir, k), v+"\n")
		default:
			f.write(filepath.Join(dir, e), "")
		}
	}
	return idx
}

func (f *fakeSys) write(p, body string) {
	f.t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func TestProbeIfaceAt_ReadsTheKindFromSysfs(t *testing.T) {
	fs := newFakeSys(t)
	nic := fs.iface("enp0s1", "device")
	veth := fs.iface("veth1a2b3c4")
	docker := fs.iface("docker0", "dir:bridge", "dir:brif", "lower_veth1a2b3c4")
	empty := fs.iface("virbr0", "dir:bridge", "dir:brif")
	lanBr := fs.iface("br-lan", "dir:bridge", "dir:brif", "lower_enp0s1")
	vlan := fs.iface("eth0.10", "lower_enp0s1")
	vlanBr := fs.iface("vmbr0", "dir:bridge", "dir:brif", "lower_eth0.10") // a bridge over a VLAN over a NIC
	tun := fs.iface("tailscale0", "tun_flags=0x1001", "type=65534")        // IFF_TUN, as a real tailscale0 shows
	tap := fs.iface("zt0", "tun_flags=0x1002")                             // IFF_TAP, but ZeroTier's
	vmTap := fs.iface("fc-tap0", "tun_flags=0x1002")                       // a Firecracker microVM's tap
	oddFlags := fs.iface("tap9", "tun_flags=garbage")
	ipip := fs.iface("tunl0", "type=768")
	vxlan := fs.iface("vxlan.calico", "uevent=DEVTYPE=vxlan")
	vxBr := fs.iface("br-evpn", "dir:bridge", "dir:brif", "lower_vxlan.calico")
	vbox := fs.iface("vboxnet0")

	oldKernel := fs.iface("br1", "dir:bridge", "brif/enp0s1") // ports in brif/ only, no lower_* links

	for name, c := range map[string]struct {
		idx  int
		want ifaceKind
	}{
		"enp0s1":       {nic, ifaceLAN},
		"veth1a2b3c4":  {veth, ifaceUnknown}, // a container's veth: the name decides, and keeps it first
		"docker0":      {docker, ifaceGuestBridge},
		"virbr0":       {empty, ifaceGuestBridge},
		"br-lan":       {lanBr, ifaceLAN},
		"eth0.10":      {vlan, ifaceLAN},
		"vmbr0":        {vlanBr, ifaceLAN},
		"br1":          {oldKernel, ifaceLAN},
		"tailscale0":   {tun, ifaceOverlay},
		"zt0":          {tap, ifaceOverlay},
		"fc-tap0":      {vmTap, ifaceGuestBridge},
		"tap9":         {oddFlags, ifaceOverlay}, // unreadable flags: the tun device is not a LAN
		"tunl0":        {ipip, ifaceOverlay},
		"vxlan.calico": {vxlan, ifaceOverlay},
		"br-evpn":      {vxBr, ifaceGuestBridge}, // a bridge over VXLAN: its segment never reaches a NIC here
		"vboxnet0":     {vbox, ifaceUnknown},     // the name decides: a host-only adapter, declared last
	} {
		if got := probeIfaceAt(fs.root, name, c.idx); got != c.want {
			t.Fatalf("%s: kind %d, want %d", name, got, c.want)
		}
	}
}

func TestProbeIfaceAt_AnythingItCannotReadIsUnknown(t *testing.T) {
	fs := newFakeSys(t)
	idx := fs.iface("docker0", "dir:bridge", "dir:brif")

	// sysfs for another network namespace: the index disagrees with the enumeration's.
	if got := probeIfaceAt(fs.root, "docker0", idx+40); got != ifaceUnknown {
		t.Fatalf("an index mismatch read as %d, want unknown", got)
	}
	// No sysfs at all, and an interface sysfs does not list.
	if got := probeIfaceAt(filepath.Join(fs.root, "nope"), "docker0", idx); got != ifaceUnknown {
		t.Fatalf("a missing root read as %d", got)
	}
	if got := probeIfaceAt(fs.root, "eth9", 0); got != ifaceUnknown {
		t.Fatalf("an absent interface read as %d", got)
	}
	// A port that sysfs does not show: the chain cannot be followed, so the bridge is not called a guest bridge.
	broken := fs.iface("br0", "dir:bridge", "dir:brif", "lower_ghost")
	if got := probeIfaceAt(fs.root, "br0", broken); got != ifaceUnknown {
		t.Fatalf("a bridge with an unreadable port read as %d, want unknown", got)
	}
	// An unreadable ifindex.
	odd := fs.iface("odd0")
	fs.write(filepath.Join(fs.root, "odd0", "ifindex"), "not-a-number\n")
	if got := probeIfaceAt(fs.root, "odd0", odd); got != ifaceUnknown {
		t.Fatalf("an unreadable ifindex read as %d", got)
	}
}

func TestProbeIfaceAt_ANameIsNeverAPathOrAPattern(t *testing.T) {
	fs := newFakeSys(t)
	fs.iface("enp0s1", "device")
	for _, name := range []string{"", ".", "..", "../enp0s1", "a/b", "x\x00y", "0123456789abcdef"} {
		if got := probeIfaceAt(fs.root, name, 0); got != ifaceUnknown {
			t.Fatalf("name %q read as %d, want unknown", name, got)
		}
	}
	// '*' and '?' are legal Linux interface names. They are read as names, never matched as patterns, so
	// a bridge called br* is judged by its own ports and not by enp0s1's.
	star := fs.iface("br*", "dir:bridge", "dir:brif")
	if got := probeIfaceAt(fs.root, "br*", star); got != ifaceGuestBridge {
		t.Fatalf("br* read as %d, want a guest bridge from its own (empty) port list", got)
	}
	q := fs.iface("e?p0s1", "lower_e?p0s1x")
	if got := probeIfaceAt(fs.root, "e?p0s1", q); got != ifaceUnknown {
		t.Fatalf("e?p0s1 read as %d: its lower is absent, so unknown", got)
	}
}

func TestProbeIfaceAt_ALongChainOrAHugeBridgeStopsAndSaysUnknown(t *testing.T) {
	fs := newFakeSys(t)
	// A bridge with more ports than the walk reads, none of them a NIC.
	var entries []string
	for i := 0; i < maxIfaceReads; i++ {
		name := "veth" + strconv.Itoa(i)
		fs.iface(name)
		entries = append(entries, "lower_"+name)
	}
	big := fs.iface("docker0", append([]string{"dir:bridge", "dir:brif"}, entries...)...)
	if got := probeIfaceAt(fs.root, "docker0", big); got != ifaceUnknown {
		t.Fatalf("a bridge past the read budget read as %d, want unknown (the name then decides)", got)
	}
	// A lower_ loop.
	a := fs.iface("loopa", "lower_loopb")
	fs.iface("loopb", "lower_loopa")
	if got := probeIfaceAt(fs.root, "loopa", a); got != ifaceUnknown {
		t.Fatalf("a lower_ loop read as %d, want unknown", got)
	}
}
