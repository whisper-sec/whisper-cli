// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"strings"
	"testing"
)

// namespaceNsNetwork is systemd 257's 80-namespace-ns.network as Debian 13 ships it (systemd-container 257.13),
// comments left out.
const namespaceNsNetwork = "[Match]\nKind=veth\nName=ns-*\n\n[Network]\nAddress=0.0.0.0/28\nLinkLocalAddressing=yes\n" +
	"DHCPServer=yes\nIPMasquerade=both\nLLDP=yes\nEmitLLDP=customer-bridge\nIPv6AcceptRA=no\nIPv6SendRA=yes\n"

const nsNetworkPath = "usr/lib/systemd/network/80-namespace-ns.network"

func nsrPaths(t *testing.T, extra map[string]string) []placedPath {
	t.Helper()
	files, err := loadNetworkFiles(networkdReader{root: netRoot(t, extra)})
	if err != nil {
		t.Fatal(err)
	}
	return findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, true, []placeKind{nsresourcedKind})
}

// The measured case: systemd-nsresourced's veth is taken by 80-namespace-ns.network, brought up and masqueraded.
func TestNsresourcedsDeviceIsTakenByItsOwnFile(t *testing.T) {
	p, ok := firstPath(nsrPaths(t, map[string]string{nsNetworkPath: namespaceNsNetwork}))
	if !ok {
		t.Fatal("no path for nsresourced's device with 80-namespace-ns.network in place")
	}
	if p.file.path != "/"+nsNetworkPath || !strings.HasPrefix(p.device.name, "ns-") || !p.device.nsresourced ||
		!strings.Contains(p.how, "IPMasquerade=both") {
		t.Fatalf("got %s for %q: %s", p.file.path, p.device.name, p.how)
	}
}

// Without that file no stock file takes a device whose name starts "ns-", although a kernel-placed veth (ve-*) is
// taken: the name constraint is what keeps 80-container-ve.network out.
func TestNoStockFileTakesNsresourcedsDeviceWithoutItsFile(t *testing.T) {
	if ps := nsrPaths(t, nil); len(ps) != 0 {
		t.Fatalf("a stock file took nsresourced's device: %s %q", ps[0].file.path, ps[0].device.name)
	}
}

// The name search starts at "ns-": a pattern that needs another start finds nothing, one that admits "ns-" names finds
// a witness that begins with it, and an inverted pattern that excludes them hides nothing.
func TestTheNsresourcedNameSearchKeepsItsPrefix(t *testing.T) {
	masq := "\n[Network]\nIPMasquerade=both\n"
	for _, c := range []struct {
		match string
		open  bool
	}{
		{"Name=nsx-*", false},
		{"Name=ve-*", false},
		{"Name=n*", true},
		{"Name=ns-?*", true},
		{"Name=!ns-*\nDriver=veth", false},
		{"Name=*-agent0", true}, // the alternative name's last part is the caller's
	} {
		ps := nsrPaths(t, map[string]string{"etc/systemd/network/50-site.network": "[Match]\n" + c.match + masq})
		if (len(ps) > 0) != c.open {
			t.Errorf("%q: open %v, want %v", c.match, len(ps) > 0, c.open)
		}
		for _, p := range ps {
			if !strings.HasPrefix(p.device.name, "ns-") {
				t.Errorf("%q: witness %q does not start ns-", c.match, p.device.name)
			}
		}
	}
}

// The address is the kernel's random one: a file that lists addresses takes no nsresourced device, while it takes a
// kernel-placed veth whose address the request chooses.
func TestAnAddressListDoesNotTakeNsresourcedsDevice(t *testing.T) {
	site := map[string]string{"etc/systemd/network/50-site.network": "[Match]\nName=ns-*\nMACAddress=02:aa:bb:cc:dd:ee\n" +
		"[Network]\nIPMasquerade=both\n"}
	if ps := nsrPaths(t, site); len(ps) != 0 {
		t.Fatalf("an address list took nsresourced's device: %s", ps[0].file.path)
	}
	files, err := loadNetworkFiles(networkdReader{root: netRoot(t, site)})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := firstPath(findPlacedPaths(files, stockTaken, stockHost, hostForwarding{}, true, placeKinds[:1]))
	if !ok || p.file.path != "/etc/systemd/network/50-site.network" {
		t.Fatalf("the same file did not take a kernel-placed veth: %v %s", ok, p.file.path)
	}
}

// Its .link file gives it ID_NET_MANAGED_BY=io.systemd.Network, which a Property= word is judged against.
func TestNsresourcedsDeviceCarriesItsManagedByProperty(t *testing.T) {
	masq := "\n[Network]\nIPMasquerade=both\n"
	for _, c := range []struct {
		prop string
		open bool
	}{
		{"Property=ID_NET_MANAGED_BY=io.systemd.Network", true},
		{"Property=!ID_NET_MANAGED_BY=*", false},
		{"Property=ID_NET_MANAGED_BY=io.example.Other", false},
	} {
		ps := nsrPaths(t, map[string]string{"etc/systemd/network/50-site.network": "[Match]\nName=ns-*\n" + c.prop + masq})
		if (len(ps) > 0) != c.open {
			t.Errorf("%q: open %v, want %v", c.prop, len(ps) > 0, c.open)
		}
	}
}

// The fix follows the device: masking the file that takes it hands it to the next, which is masked too, and a site's
// own file is to be changed by hand.
func TestTheNsresourcedFixFollowsTheDeviceToTheEnd(t *testing.T) {
	extra := map[string]string{
		nsNetworkPath: namespaceNsNetwork,
		"usr/lib/systemd/network/85-vendor.network": "[Match]\nKind=veth\nName=ns-*\n[Network]\nIPMasquerade=ipv4\n",
		"etc/systemd/network/90-site.network":       "[Match]\nName=n*\n[Network]\nIPForward=yes\n",
	}
	files, err := loadNetworkFiles(networkdReader{root: netRoot(t, extra)})
	if err != nil {
		t.Fatal(err)
	}
	masks, edits := nsresourcedFix(files, stockTaken, stockHost, hostForwarding{})
	if strings.Join(masks, " ") != "/usr/lib/systemd/network/80-namespace-ns.network /usr/lib/systemd/network/85-vendor.network" ||
		strings.Join(edits, " ") != "/etc/systemd/network/90-site.network" {
		t.Fatalf("masks %q, edits %q", masks, edits)
	}
	none, _ := nsresourcedFix(files[:1], stockTaken, stockHost, hostForwarding{})
	if len(none) != 0 {
		t.Fatalf("a configuration with no way out was given masks: %q", none)
	}
}

// The refusal for nsresourced alone names it and masks its file, and offers neither the kernel fix nor the file that
// would leave every veth unmanaged; with the kernel too, it says both.
func TestTheNsresourcedRefusal(t *testing.T) {
	p, ok := firstPath(nsrPaths(t, map[string]string{nsNetworkPath: namespaceNsNetwork}))
	if !ok {
		t.Fatal("no path")
	}
	f := placedFinding{where: "in this host's namespace", why: "where it runs as pid 848", host: true, running: true,
		nsresourced: "it runs as pid 4711", paths: []placedPath{p}, nsrMasks: []string{"/" + nsNetworkPath}}
	msg := placedRefusal(4242, "agent", []placedFinding{f}, "")
	for _, want := range []string{"systemd-nsresourced makes a veth", "it runs as pid 4711", "80-namespace-ns.network takes one named \"ns-",
		"\n    sudo ln -s /dev/null /etc/systemd/network/80-namespace-ns.network\n    sudo systemctl restart systemd-networkd",
		"systemctl mask --now systemd-nsresourced.socket systemd-nsresourced.service", "sudo whisper contain 4242"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	for _, not := range []string{unmanagedFixFile, "7b735ef81286", "MAC address of its choosing"} {
		if strings.Contains(msg, not) {
			t.Errorf("an nsresourced-only refusal carries %q:\n%s", not, msg)
		}
	}
	f.kernelToo = true
	both := placedRefusal(4242, "agent", []placedFinding{f}, "this kernel allowed exactly that")
	for _, want := range []string{"MAC address of its choosing (this kernel allowed exactly that)", "systemd-nsresourced makes a veth",
		fixFileCommand, "7b735ef81286"} {
		if !strings.Contains(both, want) {
			t.Errorf("missing %q in:\n%s", want, both)
		}
	}
}

// CapabilityBoundingSet= is read the way systemd reads it, and whether CAP_NET_ADMIN is left decides whether
// nsresourced can make a veth at all (Debian 13's unit leaves it out; every request then fails with EPERM, measured).
func TestBoundingSetIsReadAsSystemdReadsIt(t *testing.T) {
	debian := "[Service]\nCapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON CAP_SETGID " +
		"CAP_SETUID CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER\nExecStart=/usr/lib/systemd/systemd-nsresourced\n"
	for _, c := range []struct {
		name         string
		units        []string
		has, unknown bool
	}{
		{"no line: every capability", []string{"[Service]\nExecStart=/x\n"}, true, false},
		{"debian 257.13", []string{debian}, false, false},
		{"a drop-in adds it", []string{debian, "[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\n"}, true, false},
		{"by number", []string{debian, "[Service]\nCapabilityBoundingSet=12\n"}, true, false},
		{"lower case", []string{debian, "[Service]\nCapabilityBoundingSet=cap_net_admin\n"}, true, false},
		{"an empty value empties it", []string{"[Service]\nCapabilityBoundingSet=\n"}, false, false},
		{"an empty value after a full one", []string{"[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\nCapabilityBoundingSet=\n"}, false, false},
		{"a lone ~ fills it", []string{debian, "[Service]\nCapabilityBoundingSet=~\n"}, true, false},
		{"a lone ~ then a list", []string{"[Service]\nCapabilityBoundingSet=~\nCapabilityBoundingSet=~CAP_NET_ADMIN\n"}, false, false},
		{"a padded number", []string{debian, "[Service]\nCapabilityBoundingSet=012\n"}, true, false},
		{"inverted first", []string{"[Service]\nCapabilityBoundingSet=~CAP_NET_ADMIN\n"}, false, false},
		{"inverted after", []string{"[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN\nCapabilityBoundingSet=~CAP_NET_ADMIN\n"}, false, false},
		{"inverted other", []string{"[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n"}, true, false},
		{"another section", []string{"[Unit]\nCapabilityBoundingSet=CAP_CHOWN\n"}, true, false},
		{"a specifier", []string{"[Service]\nCapabilityBoundingSet=%i\n"}, false, true},
	} {
		has, known := boundingHasNetAdmin(c.units)
		if has != c.has || known == c.unknown {
			t.Errorf("%s: has %v known %v", c.name, has, known)
		}
	}
}
