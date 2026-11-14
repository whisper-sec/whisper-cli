// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// endpoints_kind.go reads what kind of interface an address sits on, from Linux's sysfs. It is plain
// file reads under a root directory, so a test can stand a fake /sys/class/net in a temp dir and run
// on any platform; only the Linux build points it at the real one (endpoints_kind_linux.go).
//
// The question is whether a segment on this interface can leave the host, and Linux answers it
// without a name:
//
//   - A real NIC has a `device` link. A VLAN, a bond or a macvlan has `lower_*` links to what it
//     sits on, and a bridge has them to its ports (and lists the ports in brif/, which older
//     kernels without the lower_* links also have). If any chain of those reaches a device, the
//     interface is on a LAN, whatever it is called: a Proxmox vmbr0, OpenWrt's br-lan, a br0 that
//     holds eth0.
//   - A bridge none of whose ports reaches a device is a guest bridge: the host and its own
//     containers or VMs (docker0 with or without containers, libvirt's virbr0, a CNI or Podman
//     bridge, or one built over a VXLAN).
//   - A tun device (`tun_flags` with IFF_TUN), an L3 tunnel (ARPHRD none, IPIP, SIT, GRE), a VXLAN
//     or Geneve device and ZeroTier's tap are overlays. Any other tap (IFF_TAP) is a guest bridge: a
//     Firecracker microVM's tap carries the host's address towards its own guest.
//   - Anything else is not decided here, and the name decides (guestBridgeName). That covers a
//     container's own veth, a VirtualBox or VMware host-only adapter, a dummy interface and Open
//     vSwitch's internal ports.

// maxIfaceReads bounds one probe: every directory listed and every link followed spends from it,
// so a strange sysfs (or a fake one) costs at most this many reads, and running out is "unknown".
const maxIfaceReads = 128

// maxDirPage is the most entries one directory read takes. A page that comes back full may have
// more behind it, so it is read as unknown rather than as complete.
const maxDirPage = 512

// iffTAP is IFF_TAP in /sys/class/net/<if>/tun_flags; IFF_TUN (0x0001) is the L3 kind.
const iffTAP = 0x0002

// Linux ARPHRD_* values for the L3 tunnels, read from /sys/class/net/<if>/type.
var tunnelTypes = map[int]bool{
	65534: true, // ARPHRD_NONE: tun, WireGuard
	768:   true, // ARPHRD_TUNNEL: IPIP
	769:   true, // ARPHRD_TUNNEL6
	776:   true, // ARPHRD_SIT
	778:   true, // ARPHRD_IPGRE
	823:   true, // ARPHRD_IP6GRE
}

// probeIfaceAt answers for one interface under root, which is /sys/class/net on a real host. index is
// the interface index the enumeration reported; when sysfs disagrees (it is mounted for another
// network namespace), the answer is ifaceUnknown. So is anything that cannot be read: the decision
// then falls to the name, never to a guess.
func probeIfaceAt(root, name string, index int) ifaceKind {
	if !plainIfaceName(name) {
		return ifaceUnknown
	}
	dir := filepath.Join(root, name)
	if index > 0 {
		b, err := os.ReadFile(filepath.Join(dir, "ifindex"))
		if err != nil {
			return ifaceUnknown
		}
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err != nil || n != index {
			return ifaceUnknown
		}
	} else if _, err := os.Stat(dir); err != nil {
		return ifaceUnknown
	}
	w := &ifaceWalk{root: root, budget: maxIfaceReads}
	switch w.reachesDevice(name, 0) {
	case reachYes:
		return ifaceLAN
	case reachUnknown:
		return ifaceUnknown
	}
	if isDir(filepath.Join(dir, "bridge")) {
		return ifaceGuestBridge // a bridge, and none of its ports reaches a device
	}
	if b, err := os.ReadFile(filepath.Join(dir, "tun_flags")); err == nil {
		flags, perr := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 32)
		if perr == nil && flags&iffTAP != 0 && !overlayName(name) {
			return ifaceGuestBridge
		}
		return ifaceOverlay
	}
	if b, err := os.ReadFile(filepath.Join(dir, "type")); err == nil {
		if t, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && tunnelTypes[t] {
			return ifaceOverlay
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "DEVTYPE="); ok && (v == "vxlan" || v == "geneve") {
				return ifaceOverlay
			}
		}
	}
	return ifaceUnknown
}

type reach uint8

const (
	reachNo reach = iota
	reachYes
	reachUnknown
)

// ifaceWalk is one probe's walk: where sysfs is, and how many reads it has left.
type ifaceWalk struct {
	root   string
	budget int
}

func (w *ifaceWalk) spend() bool {
	w.budget--
	return w.budget >= 0
}

// reachesDevice reports whether name is a device, or sits on or holds one, through its lower_* links
// and, for a bridge, the ports brif/ lists.
func (w *ifaceWalk) reachesDevice(name string, depth int) reach {
	if depth > 4 || !plainIfaceName(name) || !w.spend() {
		return reachUnknown
	}
	dir := filepath.Join(w.root, name)
	if _, err := os.Lstat(filepath.Join(dir, "device")); err == nil {
		return reachYes
	} else if !errors.Is(err, fs.ErrNotExist) {
		return reachUnknown
	}
	entries, ok := w.list(dir)
	if !ok {
		return reachUnknown
	}
	var next []string
	for _, e := range entries {
		if lower, isLower := strings.CutPrefix(e, "lower_"); isLower {
			next = append(next, lower)
		}
	}
	if isDir(filepath.Join(dir, "bridge")) {
		ports, ok := w.list(filepath.Join(dir, "brif"))
		if !ok {
			return reachUnknown
		}
		next = append(next, ports...)
	}
	out := reachNo
	walked := map[string]bool{}
	for _, n := range next {
		if walked[n] {
			continue // a bridge names each port twice, once as lower_<port> and once in brif/
		}
		walked[n] = true
		switch w.reachesDevice(n, depth+1) {
		case reachYes:
			return reachYes
		case reachUnknown:
			out = reachUnknown
		}
	}
	return out
}

// list reads one directory's names, or says it could not: an error, an exhausted budget, or a page
// that came back full, which may have more behind it.
func (w *ifaceWalk) list(dir string) ([]string, bool) {
	if !w.spend() {
		return nil, false
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	names, err := f.Readdirnames(maxDirPage)
	if (err != nil && !errors.Is(err, io.EOF)) || len(names) >= maxDirPage {
		return nil, false
	}
	return names, true
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// plainIfaceName refuses a name that could walk out of the directory it is joined to. The kernel
// already refuses these ('/', ".", ".." and anything over 15 bytes), so this matters only for a name
// that did not come from the kernel, and then it is the difference between a read and a walk. Names
// with '*', '?' or '[' are legal Linux names and are fine: nothing here treats a name as a pattern.
func plainIfaceName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 15 &&
		!strings.ContainsAny(name, "/\\\x00")
}
