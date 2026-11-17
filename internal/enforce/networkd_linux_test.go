// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// appliedFile is the file networkd applies to d, as `networkctl status` names it: "n/a" for none, or for a first
// match that leaves the device unmanaged.
func appliedFile(files []networkFile, d placedDevice, h hostFacts) string {
	for i := range files {
		if files[i].constMatch(d.placeKind, d.mac, h) == triTrue && files[i].nameMatch(d.name) {
			if files[i].unmanaged {
				return "n/a"
			}
			return files[i].path
		}
	}
	return "n/a"
}

// What systemd-networkd 255 itself applied, row by row (twenty-one of them), to a veth made with each name and MAC on the Ubuntu 24.04
// host the fixtures come from: the "Network File:" line of `networkctl status`, read back after each row (the names
// here are the measured ones with the prefix changed, which no row's patterns tell apart). The reading of the
// configuration must choose the same file in every row.
func TestNetworkdChoosesWhatTheLabMeasured(t *testing.T) {
	const ve = "/usr/lib/systemd/network/80-container-ve.network"
	rows := []struct {
		label, name, mac string
		files            map[string]string // added under /etc/systemd/network; "" is a mask
		want             string
	}{
		{"stock-ve", "ve-laba", "02:00:00:00:41:0a", nil, ve},
		{"stock-vb", "vb-laba", "02:00:00:00:41:0b", nil, "/usr/lib/systemd/network/80-container-vb.network"},
		{"stock-host0", "host0", "02:00:00:00:41:0c", nil, "n/a"},
		{"empty-match-ignored", "ve-labb", "02:00:00:00:41:0d", map[string]string{"05-site-empty.network": "[Match]\n[Link]\nUnmanaged=yes\n"}, ve},
		{"earlier-unmanaged", "ve-labc", "02:00:00:00:41:0e", map[string]string{"05-site-unm.network": "[Match]\nKind=veth netkit\n[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"false-condition-skipped", "ve-labd", "02:00:00:00:41:0f", map[string]string{"05-site-cond.network": "[Match]\nKind=veth\nKernelVersion=5.*\n[Link]\nUnmanaged=yes\n"}, ve},
		{"inverted-kind", "ve-labe", "02:00:00:00:41:10", map[string]string{"05-site-inv.network": "[Match]\nKind=!veth\nName=ve-lab*\n[Link]\nUnmanaged=yes\n"}, ve},
		{"property-driver", "labp0", "02:00:00:00:41:11", map[string]string{"05-site-prop.network": "[Match]\nProperty=ID_NET_DRIVER=veth\nName=labp*\n[Network]\nLinkLocalAddressing=no\n"}, "/etc/systemd/network/05-site-prop.network"},
		{"inverted-path", "labt0", "02:00:00:00:41:12", map[string]string{"05-site-path.network": "[Match]\nPath=!pci-*\nName=labt*\n[Network]\nLinkLocalAddressing=no\n"}, "/etc/systemd/network/05-site-path.network"},
		{"permanent-mac", "labq0", "02:00:00:00:41:13", map[string]string{"05-site-perm.network": "[Match]\nPermanentMACAddress=02:00:00:00:41:13\n[Network]\nLinkLocalAddressing=no\n"}, "n/a"},
		{"mac-chosen", "labm0", "02:00:00:00:41:14", map[string]string{"05-site-mac.network": "[Match]\nMACAddress=02:00:00:00:41:14\n[Network]\nLinkLocalAddressing=no\n"}, "/etc/systemd/network/05-site-mac.network"},
		{"only-inverted-names", "laby0", "02:00:00:00:41:15", map[string]string{"05-site-names.network": "[Match]\nName=!labx* !enp* !lo\nKind=veth\n[Network]\nLinkLocalAddressing=no\n"}, "/etc/systemd/network/05-site-names.network"},
		{"dropin-unmanaged", "ve-labf", "02:00:00:00:41:16", map[string]string{"80-container-ve.network.d/50-site.conf": "[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"unreadable-by-networkd", "ve-labg", "02:00:00:00:41:17", map[string]string{"05-site-secret.network": "[Match]\nKind=veth\nName=ve-*\n[Link]\nUnmanaged=yes\n"}, ve},
		{"masked-ve", "ve-labh", "02:00:00:00:41:18", map[string]string{"80-container-ve.network": ""}, "n/a"},
		{"fix-file-ve", "ve-labi", "02:00:00:00:41:19", map[string]string{unmanagedFixFile: "[Match]\nKind=veth netkit\n\n[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"fix-file-vb", "vb-labj", "02:00:00:00:41:1a", map[string]string{unmanagedFixFile: "[Match]\nKind=veth netkit\n\n[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"driver-fix-ve", "ve-labm", "02:00:00:00:41:21", map[string]string{unmanagedFixFile: "[Match]\nDriver=veth netkit\n\n[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"driver-fix-vb", "vb-labm", "02:00:00:00:41:22", map[string]string{unmanagedFixFile: "[Match]\nDriver=veth netkit\n\n[Link]\nUnmanaged=yes\n"}, "n/a"},
		{"bad-section-header", "ve-labk", "02:00:00:00:41:1b", map[string]string{"05-site-badhdr.network": "[Match\nKind=veth\n[Link]\nUnmanaged=yes\n"}, ve},
		{"bridge-port", "labb0", "02:00:00:00:41:1c", map[string]string{"05-site-bridge.network": "[Match]\nName=labb*\n[Network]\nBridge=nosuchbr0\n"}, "/etc/systemd/network/05-site-bridge.network"},
	}
	// networkd's own user, which owns none of the test's files.
	networkdUser := modeAccess(uint32(os.Getuid())+1, map[uint32]bool{uint32(os.Getgid()) + 1: true})
	for _, r := range rows {
		t.Run(r.label, func(t *testing.T) {
			extra := map[string]string{}
			var masks []string
			for p, c := range r.files {
				if c == "" {
					masks = append(masks, p)
				} else {
					extra["etc/systemd/network/"+p] = c
				}
			}
			root := netRoot(t, extra)
			for _, m := range masks {
				mask(t, root, "etc/systemd/network/"+m)
			}
			if strings.Contains(r.label, "unreadable") {
				if err := os.Chmod(filepath.Join(root, "etc/systemd/network/05-site-secret.network"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			files, err := loadNetworkFiles(networkdReader{root: root, access: networkdUser})
			if err != nil {
				t.Fatal(err)
			}
			d := placedDevice{placeKind: placeKinds[0], name: r.name, mac: r.mac}
			if got := appliedFile(files, d, stockHost); got != r.want {
				t.Fatalf("networkd applied %s to %s, this reading says %s", r.want, r.name, got)
			}
		})
	}
}

// Whatever changed in the configuration after networkd started is named, however it changed: a file written in place,
// one replaced by a rename (sed -i, an editor, a package), one removed (its directory changes), a mask made, a
// drop-in directory made. What did not change is not.
func TestEveryChangeAfterNetworkdStartedIsNamed(t *testing.T) {
	root := netRoot(t, map[string]string{
		"etc/systemd/network/50-lan.network":   "[Match]\nName=*\n[Network]\nDHCP=yes\n",
		"etc/systemd/network/60-old.network":   "[Match]\nName=x*\n",
		"etc/systemd/network/70-inner.network": "[Match]\nName=y*\n",
	})
	time.Sleep(30 * time.Millisecond)
	if got := changedSince(root, time.Now()); len(got) != 0 {
		t.Fatalf("nothing changed yet, but %v", got)
	}
	start := time.Now()
	time.Sleep(30 * time.Millisecond)
	etc := filepath.Join(root, "etc/systemd/network")
	tmp := filepath.Join(etc, ".50-lan.tmp")
	if err := os.WriteFile(tmp, []byte("[Match]\nName=enp1s0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(etc, "50-lan.network")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "70-inner.network"), []byte("[Match]\nName=z*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(changedSince(root, start), " ")
	for _, want := range []string{"/etc/systemd/network/50-lan.network", "/etc/systemd/network/70-inner.network",
		"/etc/systemd/network"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s changed and was not named: %s", want, got)
		}
	}
	if strings.Contains(got, "60-old") || strings.Contains(got, "/usr/lib/systemd/network/80-container-ve.network") {
		t.Errorf("an unchanged file was named: %s", got)
	}
	// A removal leaves no file to name, only its directory.
	start = time.Now()
	time.Sleep(30 * time.Millisecond)
	if err := os.Remove(filepath.Join(etc, "60-old.network")); err != nil {
		t.Fatal(err)
	}
	if got := changedSince(root, start); len(got) != 1 || got[0] != "/etc/systemd/network" {
		t.Errorf("a removal named %v", got)
	}
	start = time.Now()
	time.Sleep(30 * time.Millisecond)
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/systemd/network/80-container-ve.network.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(changedSince(root, start), " "); !strings.Contains(got, "/usr/lib/systemd/network") {
		t.Errorf("a new drop-in directory was not named: %s", got)
	}
}

// The reader stays inside its root and never waits: a link to an absolute path resolves under the root, a FIFO or a
// device where a file should be is not read, and a file too large to judge is an error.
func TestTheReaderStaysInItsRootAndNeverWaits(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(filepath.Join(root, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "inside/hostname"), []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/inside", etc); err != nil { // an absolute link in the middle of a path
		t.Fatal(err)
	}
	if b, fi, err := readUnder(root, "/etc/hostname"); err != nil || fi == nil || string(b) != "in" {
		t.Fatalf("a link inside the root: %q %v %v", b, fi, err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "inside/zero")); err != nil {
		t.Fatal(err)
	}
	if b, fi, err := readUnder(root, "/etc/zero"); b != nil || fi != nil || err != nil {
		t.Fatalf("a link to /dev/zero outside the root was followed: %d bytes, %v, %v", len(b), fi, err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "inside/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if b, fi, err := readUnder(root, "/etc/fifo"); b != nil || fi == nil || fi.Mode().IsRegular() || err != nil {
			t.Errorf("a FIFO: %q %v %v", b, fi, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO waited")
	}
	big := make([]byte, maxConfFile+1)
	if err := os.WriteFile(filepath.Join(root, "inside/big"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readUnder(root, "/etc/big"); err == nil {
		t.Fatal("a file over the bound was read")
	}
	if names, chain, err := listUnder(root, "/etc"); err != nil || len(chain) != 2 || !contains(names, "hostname") {
		t.Fatalf("listing through a link inside the root: %v %d %v", names, len(chain), err)
	}
}

// What the probe's answer means: a kind is placeable when any way of naming the scratch placed it and the holder saw
// it, refused only when its own control worked, absent when its control says the kernel has no such kind, and unclear
// (counted placeable, never kept) for anything else, an answer that cannot be read included.
func TestTheProbesAnswerIsReadFailClosed(t *testing.T) {
	both := "own-veth=ok own-netkit=ok"
	for _, c := range []struct {
		line          string
		veth, netkit  placeAnswer
		clear         bool
		placeableKind int
	}{
		{"child=9 " + both + " veth=ok,seen veth-pid=ok,seen netkit=ok,seen", placedSeen, placedSeen, true, 3},
		{both + " veth=EPERM veth-pid=EPERM netkit=EPERM", placedRefused, placedRefused, true, 0},
		{both + " veth=EPERM veth-pid=ok,seen netkit=EPERM", placedSeen, placedRefused, true, 1},
		{both + " veth=ok,unseen veth-pid=EPERM netkit=EPERM", placedUnknown, placedRefused, false, 1},
		{"own-veth=ok own-netkit=EOPNOTSUPP veth=EPERM veth-pid=EPERM netkit=EOPNOTSUPP", placedRefused, placedAbsent, true, 0},
		{"own-veth=EPERM own-netkit=ok veth=EPERM veth-pid=EPERM netkit=EPERM", placedUnknown, placedRefused, false, 1},
		{"own-veth=EOPNOTSUPP own-netkit=ok veth=EOPNOTSUPP veth-pid=EOPNOTSUPP netkit=ok,seen", placedAbsent, placedSeen, true, 2},
		{both + " veth=EINVAL veth-pid=EPERM netkit=EPERM", placedUnknown, placedRefused, false, 1},
		{"", placedUnknown, placedUnknown, false, 3},
		{"error the scratch namespace is this command's own", placedUnknown, placedUnknown, false, 3},
		{"garbage", placedUnknown, placedUnknown, false, 3},
	} {
		r := parseProbeLine(c.line)
		if r.kinds["veth"] != c.veth || r.kinds["netkit"] != c.netkit || (r.why == "") != c.clear || len(r.placeable()) != c.placeableKind {
			t.Errorf("%q: veth %v netkit %v why %q placeable %d; want %v %v clear %v %d", c.line, r.kinds["veth"],
				r.kinds["netkit"], r.why, len(r.placeable()), c.veth, c.netkit, c.clear, c.placeableKind)
		}
	}
}

// The check Preflight runs, and how it finds networkd, are the real ones unless a test sets them: the root suite and
// the Preflight tests replace them, so nothing else would notice them left as stubs.
func TestTheCheckIsWiredToTheRealOnes(t *testing.T) {
	if reflect.ValueOf(placedDeviceCheckAtStart).Pointer() != reflect.ValueOf(checkPlacedDevices).Pointer() {
		t.Error("Preflight's placed-device check is not checkPlacedDevices")
	}
	if reflect.ValueOf(findNetworkd).Pointer() != reflect.ValueOf(networkdInstances).Pointer() {
		t.Error("the check does not find networkd with networkdInstances")
	}
	if reflect.ValueOf(readUnder).Pointer() != reflect.ValueOf(readUnderLinux).Pointer() ||
		reflect.ValueOf(listUnder).Pointer() != reflect.ValueOf(listUnderLinux).Pointer() {
		t.Error("the reader is not the one that stays in its root on Linux")
	}
}

// fnmatch answers as glibc's fnmatch(pattern, s, 0) does, over a corpus glibc itself answered (testdata/fnmatch).
func TestFnmatchAgreesWithGlibc(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "fnmatch", "glibc.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	n, bad := 0, 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Fatalf("a corpus line of %d fields: %q", len(f), line)
		}
		n++
		if got := fnmatch(f[0], f[1]); got != (f[2] == "1") {
			bad++
			if bad <= 10 {
				t.Errorf("fnmatch(%q, %q) = %v, glibc says %s", f[0], f[1], got, f[2])
			}
		}
	}
	if n < 1000 || bad > 0 {
		t.Fatalf("%d of %d cases disagree with glibc", bad, n)
	}
}

// A probe that could not make a user namespace says something about every process only when the kernel's own limit
// is zero and no user namespace exists to enter; any other refusal is the command's own, and is never kept as clear.
func TestAProbeWithoutAUserNamespaceClosesOnlyAShutHost(t *testing.T) {
	old := userNamespacesShut
	t.Cleanup(func() { userNamespacesShut = old })
	for _, c := range []struct {
		line  string
		shut  bool
		clear bool
	}{
		{"nouserns ENOSPC", true, true},
		{"nouserns ENOSPC", false, false},
		{"nouserns EPERM", true, false},
		{"nouserns EUSERS", true, false},
	} {
		userNamespacesShut = func() bool { return c.shut }
		r := parseProbeLine(c.line)
		if (r.why == "") != c.clear || (c.clear && len(r.placeable()) != 0) || (!c.clear && len(r.placeable()) != len(placeKinds)) {
			t.Errorf("%q with the host shut %v: why %q, placeable %d", c.line, c.shut, r.why, len(r.placeable()))
		}
	}
}

// A configuration file or drop-in directory that is a link is judged by what it leads to: an edit there after
// networkd started is named, though the link itself did not change.
func TestAChangeBehindALinkIsNamed(t *testing.T) {
	root := netRoot(t, map[string]string{
		"srv/net/50-lab.network": "[Match]\nName=lab*\n[Network]\nIPMasquerade=both\n",
		"srv/net/d/50-x.conf":    "[Network]\nIPMasquerade=both\n",
	})
	etc := filepath.Join(root, "etc/systemd/network")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/srv/net/50-lab.network", filepath.Join(etc, "50-lab.network")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/srv/net/d", filepath.Join(etc, "50-lab.network.d")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	time.Sleep(30 * time.Millisecond)
	if got := changedSince(root, start); len(got) != 0 {
		t.Fatalf("nothing changed yet, but %v", got)
	}
	if err := os.WriteFile(filepath.Join(root, "srv/net/50-lab.network"), []byte("[Match]\nName=lab*\n[Link]\nUnmanaged=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(changedSince(root, start), " "); !strings.Contains(got, "/etc/systemd/network/50-lab.network") {
		t.Errorf("an edit behind a linked file was not named: %q", got)
	}
	start = time.Now()
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "srv/net/d/50-x.conf"), []byte("[Link]\nUnmanaged=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(changedSince(root, start), " "); !strings.Contains(got, "50-lab.network.d/50-x.conf") {
		t.Errorf("an edit inside a linked drop-in directory was not named: %q", got)
	}
}

// The whole check answers within its deadline, whatever it reads: one that cannot finish refuses.
func TestTheCheckRefusesWhenItCannotFinishInTime(t *testing.T) {
	oldFind, oldWait := findNetworkd, placedCheckWait
	release, returned := make(chan struct{}), make(chan struct{})
	// The check left running past its deadline is let go and seen to end (the stub's error ends it at once, before it
	// reads anything more) before anything it might read is put back.
	t.Cleanup(func() {
		close(release)
		<-returned
		findNetworkd, placedCheckWait = oldFind, oldWait
	})
	findNetworkd = func(procStatus) ([]networkdInstance, error) {
		<-release
		close(returned)
		return nil, errors.New("released")
	}
	placedCheckWait = 200 * time.Millisecond
	start := time.Now()
	err := checkPlacedDevices(4242, procStatus{Name: "agent"})
	if err == nil || !strings.Contains(err.Error(), "could not finish judging") || time.Since(start) > 5*time.Second {
		t.Fatalf("a check that cannot finish answered %v after %s", err, time.Since(start))
	}
}

// A chain of links is followed to its end: a file removed at the far end of two links is named.
func TestARemovalAtTheEndOfALinkChainIsNamed(t *testing.T) {
	root := netRoot(t, map[string]string{"opt/b/real.network": "[Match]\nName=lab*\n[Network]\nIPMasquerade=both\n"})
	for _, l := range [][2]string{{"/opt/b/real.network", "opt/a/hop.network"}, {"/opt/a/hop.network", "etc/systemd/network/50-lab.network"}} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l[1])), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	time.Sleep(30 * time.Millisecond)
	if err := os.Remove(filepath.Join(root, "opt/b/real.network")); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(changedSince(root, start), " "); !strings.Contains(got, "50-lab.network (through /opt/b)") {
		t.Errorf("a removal at the end of a link chain was not named: %q", got)
	}
}
