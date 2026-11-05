// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// contain_test.go covers the decisions a containment makes, on every platform and without root.

func TestParseStatusReadsPrivilege(t *testing.T) {
	st := parseStatus("Name:\tpython3\nPPid:\t412\nUid:\t1000\t1000\t1000\t1000\nCapPrm:\t0000000000000000\n" +
		"CapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n")
	if st.Name != "python3" || st.PPid != 412 || st.Uids != [4]int{1000, 1000, 1000, 1000} {
		t.Fatalf("parsed %+v", st)
	}
	if why := st.privileged(); why != "" {
		t.Fatalf("an unprivileged process was refused: %s", why)
	}
}

func TestPrivilegedRefusesEveryWayBackToRoot(t *testing.T) {
	cases := map[string]string{
		"effective root":     "Uid:\t1000\t0\t1000\t1000\n",
		"saved root":         "Uid:\t1000\t1000\t0\t1000\n",
		"net admin":          "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000001000\n",
		"permitted only":     "Uid:\t1000\t1000\t1000\t1000\nCapPrm:\t0000000000000080\n",
		"ambient only":       "Uid:\t1000\t1000\t1000\t1000\nCapAmb:\t0000000000000400\n",
		"an unparsable uid":  "Uid:\tgarbage\n",
		"no uid line at all": "Name:\tx\n",
	}
	for name, status := range cases {
		if why := parseStatus(status).privileged(); why == "" {
			t.Errorf("%s: not refused", name)
		}
	}
	if why := parseStatus("Uid:\t5\t5\t5\t5\nCapEff:\t0000000000001000\n").privileged(); !strings.Contains(why, "CAP_NET_ADMIN") {
		t.Errorf("the refusal must name the capability: %q", why)
	}
}

func TestStatPPidFlagsSurvivesAHostileCommandName(t *testing.T) {
	// comm may hold spaces and parentheses; the fields are counted from the last ')'.
	stat := "4242 (evil) 1 2 (x) S 4100 4242 4242 0 -1 4194560 101 0 0 0"
	pp, fl, ok := statPPidFlags(stat)
	if !ok || pp != 4100 || fl != 4194560 {
		t.Fatalf("ppid %d flags %d ok %v", pp, fl, ok)
	}
	if _, _, ok := statPPidFlags("no parens here"); ok {
		t.Fatal("a stat with no command name must not parse")
	}
	if _, _, ok := statPPidFlags("1 (x) S"); ok {
		t.Fatal("a truncated stat must not parse")
	}
}

func TestDescendantsWalksTheWholeTreeOnce(t *testing.T) {
	parent := map[int]int{1: 0, 10: 1, 11: 10, 12: 10, 13: 12, 20: 1, 21: 20, 99: 99}
	if got := descendants(parent, 10); !reflect.DeepEqual(got, []int{11, 12, 13}) {
		t.Fatalf("descendants %v", got)
	}
	if got := descendants(parent, 13); len(got) != 0 {
		t.Fatalf("a leaf has no descendants, got %v", got)
	}
	if got := descendants(parent, 99); len(got) != 0 {
		t.Fatalf("a self-parented pid must not loop, got %v", got)
	}
}

func TestIsAncestorFindsSelfAndParents(t *testing.T) {
	parent := map[int]int{1: 0, 50: 1, 60: 50, 70: 60}
	for _, a := range []int{70, 60, 50, 1} {
		if !isAncestor(parent, a, 70) {
			t.Errorf("%d is an ancestor of 70", a)
		}
	}
	if isAncestor(parent, 80, 70) {
		t.Error("80 is not an ancestor of 70")
	}
	if isAncestor(map[int]int{5: 6, 6: 5}, 9, 5) {
		t.Error("a parent cycle must end, and 9 is not in it")
	}
}

func TestCgroup2MountFindsTheHierarchy(t *testing.T) {
	unified := "25 30 0:22 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw,nsdelegate\n"
	if got, err := cgroup2Mount(unified); err != nil || got != "/sys/fs/cgroup" {
		t.Fatalf("unified: %q %v", got, err)
	}
	hybrid := "25 30 0:22 / /sys/fs/cgroup ro shared:9 - tmpfs tmpfs ro\n" +
		"26 25 0:23 / /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw\n" +
		"27 25 0:24 / /sys/fs/cgroup/memory rw shared:11 - cgroup cgroup rw,memory\n"
	if got, err := cgroup2Mount(hybrid); err != nil || got != "/sys/fs/cgroup/unified" {
		t.Fatalf("hybrid: %q %v", got, err)
	}
	v1only := "25 30 0:22 / /sys/fs/cgroup ro - tmpfs tmpfs ro\n27 25 0:24 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"
	if _, err := cgroup2Mount(v1only); !errors.Is(err, ErrNoCgroup2) {
		t.Fatalf("a v1-only host must report no cgroup v2, got %v", err)
	}
	escaped := "25 30 0:22 / /mnt/cg\\040two rw - cgroup2 cgroup2 rw\n"
	if got, _ := cgroup2Mount(escaped); got != "/mnt/cg two" {
		t.Fatalf("escaped mount point %q", got)
	}
}

func TestCgroupPathReadsTheV2Line(t *testing.T) {
	if p, ok := cgroupPath("12:memory:/x\n0::/user.slice/session-3.scope\n"); !ok || p != "/user.slice/session-3.scope" {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := cgroupPath("12:memory:/x\n"); ok {
		t.Fatal("a v1-only cgroup file has no v2 path")
	}
}

func TestClassifySocket(t *testing.T) {
	lo4, lo6 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
	host := netip.MustParseAddr("192.0.2.10")
	far := netip.MustParseAddr("2001:db8::7")
	any := netip.IPv6Unspecified()
	cases := []struct {
		name               string
		fam                int
		local, peer        netip.Addr
		connected, listens bool
		want               sockAction
	}{
		{"unix", afUnix, netip.Addr{}, netip.Addr{}, true, false, sockKeep},
		{"netlink", afNetlink, netip.Addr{}, netip.Addr{}, false, false, sockKeep},
		{"loopback connection", afInet, lo4, lo4, true, false, sockKeep},
		{"loopback listener", afInet6, lo6, netip.Addr{}, false, true, sockKeep},
		{"connection to elsewhere", afInet6, host, far, true, false, sockCut},
		{"wildcard listener", afInet6, any, netip.Addr{}, false, true, sockPin},
		{"unconnected datagram", afInet, netip.IPv4Unspecified(), netip.Addr{}, false, false, sockPin},
		{"packet socket", afPacket, netip.Addr{}, netip.Addr{}, false, false, sockRefuse},
		{"vsock", 40, netip.Addr{}, netip.Addr{}, true, false, sockRefuse},
	}
	for _, c := range cases {
		if got := classifySocket(c.fam, c.local, c.peer, c.connected, c.listens); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestContainCgroupNameIsStableAndPathSafe(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:9:5::c0de:1")
	n := containCgroupName(a)
	if n != "2a042a010009000500000000c0de0001" || strings.ContainsAny(n, "/.:") {
		t.Fatalf("name %q", n)
	}
	if containCgroupName(netip.MustParseAddr("2a04:2a01::1")) == n {
		t.Fatal("two agents must not share a cgroup")
	}
}

func TestSocketReportReads(t *testing.T) {
	got := SocketReport{Kept: 3, Pinned: 1, Cut: 1}.String()
	if got != "1 existing socket cut, 1 pinned to the tunnel, 3 kept (loopback, unix, netlink)" {
		t.Fatalf("%q", got)
	}
}
