// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The filter is exercised in a child process: once installed it cannot be removed, so the test
// binary itself must never carry it. A filter needs only no_new_privs, not root.
func runUnderFilter(t *testing.T, mode, probe string) (string, *exec.ExitError) {
	t.Helper()
	if _, err := archNumbers(runtime.GOARCH); err != nil {
		t.Skip(err.Error())
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompProbeHelper")
	cmd.Env = append(os.Environ(), "WHISPER_SECCOMP_HELPER=1", "WHISPER_SECCOMP_MODE="+mode, "WHISPER_SECCOMP_PROBE="+probe)
	out, err := cmd.CombinedOutput()
	ee, _ := err.(*exec.ExitError)
	return strings.TrimSpace(string(out)), ee
}

// TestSeccompProbeHelper is the child: it installs the filter as init does, then makes one call.
func TestSeccompProbeHelper(t *testing.T) {
	if os.Getenv("WHISPER_SECCOMP_HELPER") != "1" {
		t.Skip("helper process only")
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Stdout.WriteString("NNP-FAILED\n")
		os.Exit(3)
	}
	if err := installSeccomp(os.Getenv("WHISPER_SECCOMP_MODE")); err != nil {
		os.Stdout.WriteString("INSTALL-FAILED " + err.Error() + "\n")
		os.Exit(3)
	}
	var errno syscall.Errno
	switch os.Getenv("WHISPER_SECCOMP_PROBE") {
	case "vsock":
		// An invalid socket type: the kernel itself answers EINVAL (the type is checked before the family is
		// looked up), whether or not vsock is loaded; only the filter, which reads arg0 alone, answers
		// EAFNOSUPPORT. So this discriminates on every kernel.
		_, _, errno = unix.RawSyscall(unix.SYS_SOCKET, afVsock, 9999, 0)
	case "inet6":
		fd, _, e := unix.RawSyscall(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, 0)
		errno = e
		unix.Close(int(fd))
	case "io_uring":
		// A NULL params pointer: EFAULT (or EPERM with io_uring_disabled) bare, ENOSYS filtered.
		_, _, errno = unix.RawSyscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
	case "exec":
		if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err != nil {
			os.Stdout.WriteString("EXEC-FAILED " + err.Error() + "\n")
			os.Exit(0)
		}
	case "userns":
		_, _, errno = unix.RawSyscall(unix.SYS_UNSHARE, unix.CLONE_NEWUSER, 0, 0)
	case "clone3":
		_, _, errno = unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0)
	case "x32":
		_, _, errno = unix.RawSyscall(x32SyscallBit|unix.SYS_GETPID, 0, 0, 0)
	case "status":
		b, _ := os.ReadFile("/proc/self/status")
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Seccomp:") || strings.HasPrefix(l, "NoNewPrivs:") {
				os.Stdout.WriteString(strings.Join(strings.Fields(l), " ") + "\n")
			}
		}
		os.Exit(0)
	}
	if errno == 0 {
		os.Stdout.WriteString("OK\n")
	} else {
		os.Stdout.WriteString(unix.ErrnoName(errno) + "\n")
	}
	os.Exit(0)
}

// requireControl skips a test whose call fails the same way WITHOUT the filter, which would make
// its assertion pass whether or not the filter did anything (a kernel without vsock or io_uring).
func requireControl(t *testing.T, probe, filtered string) {
	t.Helper()
	if bare, _ := runUnderFilter(t, SeccompOff, probe); bare == filtered {
		t.Skipf("without the filter %s already answers %s on this kernel, so the test cannot discriminate", probe, bare)
	}
}

func TestVsockSocketsAreRefused(t *testing.T) {
	if bare, _ := runUnderFilter(t, SeccompOff, "vsock"); bare == "EAFNOSUPPORT" {
		t.Fatalf("the control must differ from the filtered answer, got %q bare", bare)
	}
	out, _ := runUnderFilter(t, SeccompDefault, "vsock")
	if out != "EAFNOSUPPORT" {
		t.Fatalf("socket(AF_VSOCK) under the filter: got %q, want EAFNOSUPPORT", out)
	}
}

func TestOrdinarySocketsStillWork(t *testing.T) {
	out, _ := runUnderFilter(t, SeccompDefault, "inet6")
	if out != "OK" && out != "EAFNOSUPPORT" { // a kernel without IPv6 answers EAFNOSUPPORT on its own
		t.Fatalf("socket(AF_INET6) under the filter: got %q", out)
	}
	if out == "EAFNOSUPPORT" {
		t.Skip("this kernel has no IPv6, so the control cannot discriminate")
	}
}

func TestIoUringLooksAbsent(t *testing.T) {
	requireControl(t, "io_uring", "ENOSYS") // only a kernel built without io_uring answers ENOSYS bare
	out, _ := runUnderFilter(t, SeccompDefault, "io_uring")
	if out != "ENOSYS" {
		t.Fatalf("io_uring_setup under the filter: got %q, want ENOSYS", out)
	}
}

func TestTheX32AbiKillsTheProcess(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 exists only on amd64")
	}
	out, ee := runUnderFilter(t, SeccompDefault, "x32")
	if ee == nil {
		t.Fatalf("an x32 syscall must kill the process, it returned %q", out)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGSYS {
		t.Fatalf("want death by SIGSYS, got %v (%q)", ee, out)
	}
}

func TestDefaultLeavesUserNamespacesAndStrictRefusesThem(t *testing.T) {
	requireControl(t, "userns", "EPERM")
	if out, _ := runUnderFilter(t, SeccompStrict, "userns"); out != "EPERM" {
		t.Fatalf("strict: unshare(CLONE_NEWUSER) got %q, want EPERM", out)
	}
	if out, _ := runUnderFilter(t, SeccompStrict, "clone3"); out != "ENOSYS" {
		t.Fatalf("strict: clone3 got %q, want ENOSYS", out)
	}
	if out, _ := runUnderFilter(t, SeccompDefault, "clone3"); out == "ENOSYS" {
		t.Fatal("default must not touch clone3")
	}
}

func TestAProcessUnderStrictCanStillStartPrograms(t *testing.T) {
	// clone3 is ENOSYS under strict; glibc and Go's os/exec must fall back to clone and keep working.
	if out, _ := runUnderFilter(t, SeccompStrict, "exec"); out != "OK" {
		t.Fatalf("os/exec under --seccomp=strict: %q", out)
	}
}

func TestAPartialThreadSyncIsAFailureNotASuccess(t *testing.T) {
	old := seccompSyscall
	defer func() { seccompSyscall = old }()
	seccompSyscall = func(op, flags, args uintptr) (uintptr, uintptr, unix.Errno) { return 1234, 0, 0 }
	if err := installSeccomp(SeccompDefault); err == nil || !strings.Contains(err.Error(), "1234") {
		t.Fatalf("a TSYNC failure (TID 1234, errno 0) must fail the install, got %v", err)
	}
}

func TestTheFilterIsReallyInstalled(t *testing.T) {
	out, _ := runUnderFilter(t, SeccompDefault, "status")
	if !strings.Contains(out, "Seccomp: 2") || !strings.Contains(out, "NoNewPrivs: 1") {
		t.Fatalf("/proc/self/status under the filter: %q", out)
	}
	off, _ := runUnderFilter(t, SeccompOff, "status")
	if !strings.Contains(off, "Seccomp: 0") {
		if inherited := inheritedSeccomp(t); inherited != "0" && os.Getenv("WHISPER_CI_KERNEL") == "container" {
			t.Skipf("needs a test process with no seccomp filter of its own: this one already runs under "+
				"Seccomp: %s (WHISPER_CI_KERNEL=container), so --seccomp=off cannot read Seccomp: 0 here; "+
				"the filter half above passed", inherited)
		}
		t.Fatalf("--seccomp=off must install nothing: %q", off)
	}
}

// inheritedSeccomp is this test process's own seccomp mode from /proc/self/status, before any filter of
// ours: "0" on an unconfined host, "2" inside a container runtime that applies its own filter. Only a
// runner that declares WHISPER_CI_KERNEL=container may skip on it; anywhere else a filter the test did
// not expect is still a failure.
func inheritedSeccomp(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("reading /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Seccomp:"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatal("/proc/self/status has no Seccomp: line")
	return ""
}

func TestTheNumbersAreTheKernelsForThisArch(t *testing.T) {
	n, err := archNumbers(runtime.GOARCH)
	if err != nil {
		t.Skip(err.Error())
	}
	want := sysnums{n.arch, n.x32, unix.SYS_SOCKET, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER, unix.SYS_UNSHARE, unix.SYS_CLONE, unix.SYS_CLONE3}
	if n != want {
		t.Fatalf("syscall table for %s: %+v, x/sys says %+v", runtime.GOARCH, n, want)
	}
	if _, err := archNumbers("riscv64"); err == nil {
		t.Fatal("an arch with no table must refuse, not install a filter that means nothing")
	}
}

func TestSeccompModesAreAcceptedLiberally(t *testing.T) {
	for in, want := range map[string]string{"": SeccompDefault, "on": SeccompDefault, "default": SeccompDefault,
		"strict": SeccompStrict, "off": SeccompOff, "none": SeccompOff} {
		got, err := NormalizeSeccomp(in)
		if err != nil || got != want {
			t.Fatalf("%q -> %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeSeccomp("paranoid"); err == nil {
		t.Fatal("an unknown mode must be refused with the choices named")
	}
}
