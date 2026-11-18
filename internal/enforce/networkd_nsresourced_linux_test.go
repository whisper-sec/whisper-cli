// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writeUnder(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The unit and its drop-ins come in systemd's order: the unit from the highest directory, then every .conf of the
// unit's own, its prefixes' (longest first) and the type's drop-in directories, a name in a higher directory hiding a
// lower one and a more specific directory hiding a less specific one, sorted by name; a masked unit is no unit, and
// what cannot be read is said.
func TestServiceUnitsReadsDropInsInSystemdsOrder(t *testing.T) {
	root := t.TempDir()
	writeUnder(t, root, map[string]string{
		"usr/lib/systemd/system/x-y-z.service":             "U",
		"usr/lib/systemd/system/x-y-z.service.d/20-b.conf": "hidden by /etc",
		"etc/systemd/system/x-y-z.service.d/20-b.conf":     "B",
		"usr/lib/systemd/system/x-.service.d/10-a.conf":    "A",
		"usr/lib/systemd/system/x-.service.d/40-d.conf":    "hidden by x-y-",
		"usr/lib/systemd/system/x-y-.service.d/40-d.conf":  "D",
		"run/systemd/system/service.d/30-c.conf":           "C",
		"etc/systemd/system/x-y-z.service.d/notes.txt":     "ignored",
		"usr/lib/systemd/system/service.d/40-d.conf":       "hidden by x-y- too",
	})
	units, present, known := serviceUnits(root, "x-y-z.service")
	if !present || !known || strings.Join(units, ",") != "U,A,B,C,D" {
		t.Fatalf("got %q present %v known %v", units, present, known)
	}
	big := strings.Repeat("#", maxConfFile+1)
	writeUnder(t, root, map[string]string{"etc/systemd/system/x-y-z.service.d/50-big.conf": big})
	if _, _, known := serviceUnits(root, "x-y-z.service"); known {
		t.Fatal("a drop-in too large to read was left out as if it were not there")
	}
	writeUnder(t, root, map[string]string{"dev/null": ""}) // what the mask's link reaches under a test's root
	mask(t, root, "etc/systemd/system/x-y-z.service")
	if _, present, known := serviceUnits(root, "x-y-z.service"); present || !known {
		t.Fatal("a masked unit was read")
	}
	if _, present, known := serviceUnits(t.TempDir(), "x-y-z.service"); present || !known {
		t.Fatal("a unit that is not there was read")
	}
}

// nsrProc stands a /proc in for the real one: pid 1 and, when comm is given, one more process, each with network and
// user namespace links (pid 1's targets for both unless otherNS or otherUser) and a status with uid and capBnd.
func nsrProc(t *testing.T, comm, exe string, uid int, capBnd string, otherNS, otherUser bool) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"netns-a", "netns-b", "userns-a", "userns-b"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(pid, comm, exe string, uid int, capBnd, netns, userns string) {
		p := filepath.Join(dir, pid)
		if err := os.MkdirAll(filepath.Join(p, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeUnder(t, p, map[string]string{"comm": comm + "\n",
			"status": "Name:\t" + comm + "\nUid:\t" + strconv.Itoa(uid) + "\t0\t0\t0\nCapBnd:\t" + capBnd + "\n"})
		for kind, target := range map[string]string{"net": netns, "user": userns} {
			if err := os.Symlink(filepath.Join(dir, target), filepath.Join(p, "ns", kind)); err != nil {
				t.Fatal(err)
			}
		}
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(p, "exe")); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(p, "root"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("1", "systemd", "/usr/lib/systemd/systemd", 0, "000001ffffffffff", "netns-a", "userns-a")
	if comm != "" {
		netns, userns := "netns-a", "userns-a"
		if otherNS {
			netns = "netns-b"
		}
		if otherUser {
			userns = "userns-b"
		}
		mk("4711", comm, exe, uid, capBnd, netns, userns)
	}
	old := procRoot
	procRoot = dir
	t.Cleanup(func() { procRoot = old })
	return dir
}

// pid1Says stands PID 1's answers in for systemctl show (none: it cannot answer).
func pid1Says(t *testing.T, answers map[string]map[string]string) {
	t.Helper()
	old := showUnit
	showUnit = func(unit string, props ...string) (map[string]string, bool) {
		v, ok := answers[unit]
		return v, ok
	}
	t.Cleanup(func() { showUnit = old })
}

const nsrBinary = "/usr/lib/systemd/systemd-nsresourced"

// A running nsresourced counts when it is root in PID 1's user namespace, runs systemd's program and holds
// CAP_NET_ADMIN; a copy any user runs, or one in another namespace, is not it.
func TestARunningNsresourcedCountsByWhatItIs(t *testing.T) {
	pid1Says(t, nil)
	for _, c := range []struct {
		name, comm, exe    string
		uid                int
		bnd                string
		otherNS, otherUser bool
		want               string
	}{
		{"with CAP_NET_ADMIN", "systemd-nsresou", nsrBinary, 0, "000001ffffffffff", false, false, "pid 4711"},
		{"a worker", "systemd-nsresou", "/usr/lib/systemd/systemd-nsresourcework", 0, "0000000000001000", false, false, "pid 4711"},
		{"after an upgrade", "systemd-nsresou", nsrBinary + " (deleted)", 0, "000001ffffffffff", false, false, "pid 4711"},
		{"debian 257.13", "systemd-nsresou", nsrBinary, 0, "000000c0012000cd", false, false, ""},
		{"another program", "systemd-nsresou", "/tmp/fake", 0, "000001ffffffffff", false, false, ""},
		{"a user's copy", "systemd-nsresou", "/tmp/x/systemd-nsresourced", 1000, "000001ffffffffff", false, false, ""},
		{"a copy in a user namespace of its own", "systemd-nsresou", "/tmp/x/systemd-nsresourced", 0, "000001ffffffffff", false, true, ""},
		{"another network namespace", "systemd-nsresou", nsrBinary, 0, "000001ffffffffff", true, false, ""},
		{"no status to read", "systemd-nsresou", nsrBinary, 0, "zz", false, false, "pid 4711"},
		{"none", "", "", 0, "", false, false, ""},
	} {
		nsrProc(t, c.comm, c.exe, c.uid, c.bnd, c.otherNS, c.otherUser)
		got := nsresourcedPlaces()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

// A copy that a user runs with its bounding set cut does not hide a listening socket whose service would hold it.
func TestADecoyDoesNotHideAListeningNsresourced(t *testing.T) {
	nsrProc(t, "systemd-nsresou", "/tmp/x/systemd-nsresourced", 0, "000000c0012000cd", false, true)
	pid1Says(t, map[string]map[string]string{
		"systemd-nsresourced.socket":  {"SubState": "listening"},
		"systemd-nsresourced.service": {"LoadState": "loaded", "CapabilityBoundingSet": "cap_chown cap_net_admin cap_sys_admin", "NeedDaemonReload": "no"},
	})
	if got := nsresourcedPlaces(); !strings.Contains(got, "socket listens") {
		t.Fatalf("a decoy hid a listening nsresourced: %q", got)
	}
}

// One that does not run counts by what PID 1 says of its socket and its loaded unit, and by the disk too where PID 1
// has not read it.
func TestAListeningNsresourcedCountsByPid1sAnswer(t *testing.T) {
	debian := "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN\nExecStart=" + nsrBinary + "\n"
	dir := nsrProc(t, "", "", 0, "", false, false)
	root := filepath.Join(dir, "1", "root")
	writeUnder(t, root, map[string]string{"usr/lib/systemd/system/systemd-nsresourced.service": debian})
	loaded := func(bnd, reload string) map[string]string {
		return map[string]string{"LoadState": "loaded", "CapabilityBoundingSet": bnd, "NeedDaemonReload": reload}
	}
	for _, c := range []struct {
		name    string
		socket  string
		service map[string]string
		counts  bool
	}{
		{"not listening", "dead", loaded("cap_net_admin", "no"), false},
		{"listening, loaded without it", "listening", loaded("cap_sys_admin cap_chown", "no"), false},
		{"listening, loaded with it", "listening", loaded("cap_sys_admin cap_net_admin", "no"), true},
		{"listening, an empty set", "listening", loaded("", "no"), false},
		{"listening, masked", "listening", map[string]string{"LoadState": "masked", "CapabilityBoundingSet": "", "NeedDaemonReload": "no"}, false},
	} {
		pid1Says(t, map[string]map[string]string{"systemd-nsresourced.socket": {"SubState": c.socket},
			"systemd-nsresourced.service": c.service})
		if got := nsresourcedPlaces(); (got != "") != c.counts {
			t.Errorf("%s: %q", c.name, got)
		}
	}
	// PID 1 found no unit when it last looked, and one has been installed since: the disk decides
	pid1Says(t, map[string]map[string]string{"systemd-nsresourced.socket": {"SubState": "listening"},
		"systemd-nsresourced.service": {"LoadState": "not-found", "CapabilityBoundingSet": "", "NeedDaemonReload": "no"}})
	if got := nsresourcedPlaces(); got != "" {
		t.Fatalf("a unit on disk without CAP_NET_ADMIN counted: %q", got)
	}
	// PID 1 holds the old unit, without it; the disk has gained it and is not reloaded yet: the next start may read it
	writeUnder(t, root, map[string]string{"etc/systemd/system/systemd-nsresourced.service.d/50-net.conf": "[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\n"})
	pid1Says(t, map[string]map[string]string{"systemd-nsresourced.socket": {"SubState": "listening"},
		"systemd-nsresourced.service": loaded("cap_sys_admin", "yes")})
	if got := nsresourcedPlaces(); got == "" {
		t.Fatal("a drop-in PID 1 has not read yet was not counted")
	}
	pid1Says(t, map[string]map[string]string{"systemd-nsresourced.socket": {"SubState": "listening"},
		"systemd-nsresourced.service": {"LoadState": "not-found", "CapabilityBoundingSet": "", "NeedDaemonReload": "no"}})
	if got := nsresourcedPlaces(); got == "" {
		t.Fatal("a unit installed since PID 1 last looked, with CAP_NET_ADMIN, was not counted")
	}
	// and the other way: PID 1 holds it, the disk has dropped it, not reloaded: PID 1's still counts
	if err := os.Remove(filepath.Join(root, "etc/systemd/system/systemd-nsresourced.service.d/50-net.conf")); err != nil {
		t.Fatal(err)
	}
	pid1Says(t, map[string]map[string]string{"systemd-nsresourced.socket": {"SubState": "listening"},
		"systemd-nsresourced.service": loaded("cap_net_admin", "yes")})
	if got := nsresourcedPlaces(); got == "" {
		t.Fatal("PID 1's loaded unit was overruled by an edit it has not read")
	}
}

// Where systemctl cannot answer the disk decides: a socket file alone may be left from a stop, so it counts only when
// the unit there would hold CAP_NET_ADMIN, and a mask or a unit without it does not count.
func TestWithoutSystemctlTheDiskDecides(t *testing.T) {
	pid1Says(t, nil)
	debian := "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN\nExecStart=" + nsrBinary + "\n"
	dir := nsrProc(t, "", "", 0, "", false, false)
	root := filepath.Join(dir, "1", "root")
	writeUnder(t, root, map[string]string{"usr/lib/systemd/system/systemd-nsresourced.service": debian})
	if got := nsresourcedPlaces(); got != "" {
		t.Fatalf("no socket, yet counted: %q", got)
	}
	sock := filepath.Join(root, "run/systemd/io.systemd.NamespaceResource")
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(sock, unix.S_IFSOCK|0o666, 0); err != nil { // a socket node, as a listening one leaves
		t.Fatal(err)
	}
	if got := nsresourcedPlaces(); got != "" {
		t.Fatalf("a unit without CAP_NET_ADMIN counted: %q", got)
	}
	writeUnder(t, root, map[string]string{"etc/systemd/system/systemd-nsresourced.service.d/50-net.conf": "[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN\n"})
	if got := nsresourcedPlaces(); !strings.Contains(got, "cannot be read") {
		t.Fatalf("a socket file and a unit with CAP_NET_ADMIN did not count: %q", got)
	}
	writeUnder(t, root, map[string]string{"dev/null": ""})
	mask(t, root, "etc/systemd/system/systemd-nsresourced.service")
	if got := nsresourcedPlaces(); got != "" {
		t.Fatalf("a masked service counted: %q", got)
	}
}

// The check on a kernel that places nothing (the probe's answer stood in): nsresourced alone refuses, with
// its own fix; without it the same configuration passes.
func TestTheCheckCountsNsresourcedOnAKernelThatPlacesNothing(t *testing.T) {
	probeMu.Lock()
	oldKept := probeKept
	probeKept = &probeResult{kinds: map[string]placeAnswer{"veth": placedRefused, "netkit": placedRefused}}
	probeMu.Unlock()
	t.Cleanup(func() { probeMu.Lock(); probeKept = oldKept; probeMu.Unlock() })
	root := netRoot(t, map[string]string{nsNetworkPath: namespaceNsNetwork})
	host := []networkdInstance{{host: true, ownNS: true, initNS: true, why: "where a test stands one in",
		reader: networkdReader{root: root}, facts: stockHost, taken: stockTaken}}
	err := judgePlaced(4242, procStatus{Name: "agent"}, host, func() string { return "it runs as pid 4711" })
	if err == nil {
		t.Fatal("nsresourced with its file in place was not refused")
	}
	for _, want := range []string{"systemd-nsresourced makes a veth", "ln -s /dev/null /etc/systemd/network/80-namespace-ns.network"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), unmanagedFixFile) {
		t.Errorf("the refusal leaves every veth unmanaged although the kernel places none:\n%s", err)
	}
	if err := judgePlaced(4242, procStatus{Name: "agent"}, host, func() string { return "" }); err != nil {
		t.Fatalf("refused with neither the kernel nor nsresourced placing anything: %v", err)
	}
	notInit := []networkdInstance{host[0]}
	notInit[0].initNS = false
	if err := judgePlaced(4242, procStatus{Name: "agent"}, notInit, func() string { return "it runs as pid 4711" }); err != nil {
		t.Fatalf("a networkd outside PID 1's namespace was judged for nsresourced's device: %v", err)
	}
}
