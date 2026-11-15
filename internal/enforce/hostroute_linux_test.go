// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
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
	hr := routeFor("wsc7", 31, 7, 42)
	if hr.Mark != markFor(42) || hr.Gen != 42 || hr.Table != hostTableBase+7 || hr.Prio != hostRulePrio+7 {
		t.Fatalf("route %+v", hr)
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
	b := ruleBody(unix.AF_INET6, 4303, 0x77630003, 0xffffffff, 4303)
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
	// This process, and init, in this process's own namespaces, which stand in for the host's.
	fakeNamespaces(t, proc, "thread-self")
	fakeNamespaces(t, proc, "1")
	oldPid, oldCg := initPidNsIno, initCgroupNsIno
	initPidNsIno, initCgroupNsIno = nsIno(t, "pid"), nsIno(t, "cgroup")
	t.Cleanup(func() { initPidNsIno, initCgroupNsIno = oldPid, oldCg })
	return proc
}

func nsIno(t *testing.T, kind string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/"+kind, &st); err != nil {
		t.Skipf("cannot read this thread's %s namespace: %v", kind, err)
	}
	return st.Ino
}

// fakeNamespaces gives a fake process this test's own network and cgroup namespaces.
func fakeNamespaces(t *testing.T, proc, pid string) {
	t.Helper()
	d := filepath.Join(proc, pid, "ns")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"net", "cgroup", "pid"} {
		_ = os.Symlink("/proc/self/ns/"+kind, filepath.Join(d, kind))
	}
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
	fakeNamespaces(t, proc, strconv.Itoa(pid))
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

// A process in another network namespace (a container's) never meets this host's routes, and a
// command in a cgroup namespace of its own does not see the host's root: both refuse.
func TestPreflightRefusesAnotherNetworkNamespaceAndACgroupNamespace(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	fakeProc(t, proc, 4242, 1, plain, 0)
	other := filepath.Join(t.TempDir(), "netns")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(proc, "4242", "ns", "net")
	_ = os.Remove(link)
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	refusal(t, Preflight(4242), "another network namespace")
	fakeProc(t, proc, 4243, 1, plain, 0)
	cg := filepath.Join(proc, "thread-self", "ns", "cgroup")
	_ = os.Remove(cg)
	if err := os.Symlink(other, cg); err != nil {
		t.Fatal(err)
	}
	refusal(t, Preflight(4243), "cgroup namespace")
}

// A process whose main thread has exited while its other threads run cannot be moved whole, and is
// refused plainly, never as "another network namespace".
func TestPreflightRefusesAProcessWhoseMainThreadExited(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	fakeProc(t, proc, 4242, 1, plain, 0)
	d := filepath.Join(proc, "4242")
	_ = os.WriteFile(filepath.Join(d, "stat"), []byte("4242 (agent) Z 1 1 1 0 -1 0 0 0"), 0o600)
	for _, tid := range []string{"4242", "4250"} {
		if err := os.MkdirAll(filepath.Join(d, "task", tid), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	refusal(t, Preflight(4242), "main thread has exited")
}

// A namespace holding only loopback (a browser's sandboxed child) has no way off the host.
func TestLoopbackOnlyNamespacesAreToldApart(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	head := "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
	write := func(pid, body string) {
		d := filepath.Join(proc, pid, "net")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "dev"), []byte(head+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n")
	write("11", "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
	if !loopbackOnly(10) {
		t.Fatal("a namespace with only lo must count as loopback-only")
	}
	if loopbackOnly(11) || loopbackOnly(12) {
		t.Fatal("a namespace with another interface, or one that cannot be read, is not loopback-only")
	}
}

func TestPreflightPassesAnUnprivilegedProcess(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	fakeProc(t, proc, 4242, 1, plain, 0)
	if err := Preflight(4242); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

// A host device's dial marks and binds its socket inside the namespace's guard against Close, so
// a dial that reaches the socket options after Close is refused there, before it is bound to
// whatever device holds the name by then, and before connect.
func TestHostDialPinsItsSocketOnlyWhileTheDeviceIsOpen(t *testing.T) {
	hr := routeFor("wsc255", 0, 255, 1)
	hr.CarryV4 = true
	calls := 0
	closed := func(func() error) error { calls++; return errNamespaceClosed }
	if _, err := hr.dial(context.Background(), "tcp", "127.0.0.1:9", "127.0.0.1", closed); !errors.Is(err, errNamespaceClosed) || calls != 1 {
		t.Fatalf("a dial after Close: err=%v, guard consulted %d times; want %v from one consultation", err, calls, errNamespaceClosed)
	}
}

// The host dial binds to the device's index: the binding reads back as exactly that index, a
// socket bound to an index no device holds (as one is once its device is gone) reaches nothing,
// not even loopback, and index 0, which would unbind, is refused before it is sent.
func TestBindToDeviceBindsTheIndexAndNothingElse(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface here")
	}
	sock := func() int {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	fd := sock()
	if err := bindToDevice(fd, lo.Index, "lo"); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skip("this kernel lets only CAP_NET_RAW bind a socket to a device")
		}
		t.Fatalf("binding to lo (index %d): %v", lo.Index, err)
	}
	if got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX); err != nil || got != lo.Index {
		t.Fatalf("bound to index %d (%v), want lo's %d", got, err, lo.Index)
	}
	gone := sock()
	if err := bindToDevice(gone, 1<<30, "wsc-gone"); err != nil {
		t.Fatalf("binding to an index no device holds: %v", err)
	}
	if err := unix.Sendto(gone, []byte("x"), 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}); err == nil {
		t.Fatal("a socket bound to an index no device holds must reach nothing, but a datagram to loopback was sent")
	}
	// The same over IPv6, the family the containment's own egress check dials (unless this host
	// has IPv6 turned off, where there is nothing to send it over).
	if gone6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
		t.Logf("no IPv6 socket on this host (%v), so the IPv6 case is not run", err)
	} else {
		t.Cleanup(func() { unix.Close(gone6) })
		if err := bindToDevice(gone6, 1<<30, "wsc-gone"); err != nil {
			t.Fatalf("binding an IPv6 socket to an index no device holds: %v", err)
		}
		if err := unix.Sendto(gone6, []byte("x"), 0, &unix.SockaddrInet6{Port: 9, Addr: [16]byte{15: 1}}); err == nil {
			t.Fatal("an IPv6 socket bound to an index no device holds must reach nothing, but a datagram to ::1 was sent")
		}
	}
	if err := bindToDevice(sock(), 0, "wsc0"); err == nil || !strings.Contains(err.Error(), "no interface index") {
		t.Fatalf("index 0 must be refused before it is sent, got %v", err)
	}
}
