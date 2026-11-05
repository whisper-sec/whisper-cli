// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// hostroute_linux_test.go covers the host-route encoding and the containment refusals that need
// no root: each refusal is reached through the same Preflight the CLI calls.

func TestSlotNamesEverythingTheContainmentOwns(t *testing.T) {
	n, err := slotOf("wsc7")
	if err != nil || n != 7 {
		t.Fatalf("slot %d %v", n, err)
	}
	hr := routeForSlot("wsc7", 31, 7)
	if hr.Mark != hostMarkBase|7 || hr.Table != hostTableBase+7 || hr.Prio != hostRulePrio+7 {
		t.Fatalf("route %+v", hr)
	}
	if hr.Mark&0xff0000 == 0x080000 {
		t.Fatal("the mark must not carry the byte Tailscale's rules match")
	}
	for _, bad := range []string{"wsp0", "wsc", "wsc-1", "wsc256", "eth0"} {
		if _, err := slotOf(bad); err == nil {
			t.Errorf("%q accepted as a slot", bad)
		}
	}
}

func TestV4ReasonRefusesWhatWouldDropOrCollide(t *testing.T) {
	if v4Reason(false, "2") != "" || v4Reason(false, "0\n") != "" || v4Reason(false, "") != "" {
		t.Fatal("loose or no reverse-path filtering carries IPv4")
	}
	if !strings.Contains(v4Reason(false, "1"), "rp_filter") {
		t.Fatal("strict reverse-path filtering must refuse IPv4 and say why")
	}
	if !strings.Contains(v4Reason(true, "0"), "192.0.0.2") {
		t.Fatal("a host CLAT already holding 192.0.0.2 must refuse IPv4 and say why")
	}
}

func TestRuleBodyIsAFwmarkLookup(t *testing.T) {
	b := ruleBody(unix.AF_INET6, 4303, 0x77630003, 4303)
	if b[0] != unix.AF_INET6 || b[7] != frActToTbl {
		t.Fatalf("header % x", b[:12])
	}
	attrs := map[uint16]uint32{}
	for off := 12; off+8 <= len(b); {
		l := int(binary.NativeEndian.Uint16(b[off:]))
		typ := binary.NativeEndian.Uint16(b[off+2:])
		attrs[typ] = binary.NativeEndian.Uint32(b[off+4:])
		off += (l + 3) &^ 3
	}
	want := map[uint16]uint32{fraPriority: 4303, fraFwmark: 0x77630003, fraFwmask: 0xffffffff, fraTable: 4303}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attr %d = %#x, want %#x", k, attrs[k], v)
		}
	}
}

// withFakeHost points Preflight at a fake /proc and mountinfo, as root unless euid says otherwise.
func withFakeHost(t *testing.T, euid int, mountinfo string) string {
	t.Helper()
	dir := t.TempDir()
	mi := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(mi, []byte(mountinfo), 0o600); err != nil {
		t.Fatal(err)
	}
	proc := filepath.Join(dir, "proc")
	if err := os.Mkdir(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	oldProc, oldMI, oldEuid := procRoot, mountinfoPath, geteuid
	procRoot, mountinfoPath, geteuid = proc, mi, func() int { return euid }
	t.Cleanup(func() { procRoot, mountinfoPath, geteuid = oldProc, oldMI, oldEuid })
	return proc
}

func fakeProc(t *testing.T, proc string, pid, ppid int, status string, flags uint64) {
	t.Helper()
	d := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	stat := strconv.Itoa(pid) + " (p) S " + strconv.Itoa(ppid) + " 1 1 0 -1 " + strconv.FormatUint(flags, 10) + " 0 0"
	_ = os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o600)
	_ = os.WriteFile(filepath.Join(d, "status"), []byte(status), 0o600)
}

const v2mount = "25 30 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
const plain = "Name:\tagent\nUid:\t1000\t1000\t1000\t1000\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n"

func refusal(t *testing.T, err error, want string) {
	t.Helper()
	var ce *ContainError
	if err == nil || !errors.As(err, &ce) {
		t.Fatalf("want a ContainError containing %q, got %v", want, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not say %q", err.Error(), want)
	}
}

func TestPreflightRefusesWithoutRoot(t *testing.T) {
	proc := withFakeHost(t, 1000, v2mount)
	fakeProc(t, proc, 4242, 1, plain, 0)
	refusal(t, Preflight(4242), "needs root")
}

func TestPreflightRefusesAnUnknownPid(t *testing.T) {
	withFakeHost(t, 0, v2mount)
	refusal(t, Preflight(4242), "no process with pid 4242")
	refusal(t, Preflight(0), "not a process id")
	refusal(t, Preflight(-3), "not a process id")
}

func TestPreflightRefusesInitAKernelThreadAndAPrivilegedProcess(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	refusal(t, Preflight(1), "init")
	fakeProc(t, proc, 2, 0, "Name:\tkthreadd\nUid:\t0\t0\t0\t0\n", pfKthread)
	refusal(t, Preflight(2), "kernel thread")
	fakeProc(t, proc, 4243, 1, "Name:\tdaemon\nUid:\t0\t0\t0\t0\n", 0)
	refusal(t, Preflight(4243), "uid 0")
	fakeProc(t, proc, 4244, 1, "Name:\tcapd\nUid:\t7\t7\t7\t7\nCapEff:\t0000000000002000\n", 0)
	refusal(t, Preflight(4244), "CAP_NET_RAW")
}

func TestPreflightRefusesAKernelWithoutCgroupV2(t *testing.T) {
	proc := withFakeHost(t, 0, "25 30 0:22 / /sys/fs/cgroup ro - tmpfs tmpfs ro\n27 25 0:24 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n")
	fakeProc(t, proc, 4242, 1, plain, 0)
	refusal(t, Preflight(4242), "no cgroup v2")
}

func TestPreflightRefusesItselfAndItsParents(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	self := os.Getpid()
	fakeProc(t, proc, self, 777, plain, 0)
	fakeProc(t, proc, 777, 1, plain, 0)
	refusal(t, Preflight(self), "cannot contain itself")
	refusal(t, Preflight(777), "cannot contain itself")
}

func TestPreflightPassesAnUnprivilegedProcess(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	fakeProc(t, proc, 4242, 1, plain, 0)
	if err := Preflight(4242); err != nil {
		t.Fatalf("refused: %v", err)
	}
}
