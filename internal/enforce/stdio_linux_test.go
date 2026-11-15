// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// stdio_linux_test.go checks what init lets through on the agent's stdio: a socket there is handed
// to the agent as it is, and seccomp only stops the agent making one of its own, so the only socket
// family allowed on 0, 1 and 2 is a unix one (a pipe, a terminal or a file is not a socket at all).

const sealProbeArg = "__whisper-seal-probe"

// sealProbe runs init's descriptor seal on the stdio this process was given and says what it did.
func sealProbe() {
	if err := sealDescriptors(); err != nil {
		os.Stdout.WriteString("refused: " + err.Error() + "\n")
		os.Exit(0)
	}
	os.Stdout.WriteString("sealed\n")
	os.Exit(0)
}

func sealWithStdin(t *testing.T, stdin *os.File) string {
	t.Helper()
	cmd := exec.Command("/proc/self/exe", sealProbeArg)
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("seal probe: %v", err)
	}
	return strings.TrimSpace(out.String())
}

func TestOnlyAUnixSocketMayBeTheAgentsStdio(t *testing.T) {
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sp[1])
	u := os.NewFile(uintptr(sp[0]), "unix")
	defer u.Close()
	if got := sealWithStdin(t, u); got != "sealed" {
		t.Fatalf("a unix socket on stdin (socket activation) must be accepted, got %q", got)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if got := sealWithStdin(t, r); got != "sealed" {
		t.Fatalf("a pipe on stdin must be accepted, got %q", got)
	}
	refused := map[string][3]int{
		"IPv4 datagram":   {unix.AF_INET, unix.SOCK_DGRAM, 0},
		"IPv6 datagram":   {unix.AF_INET6, unix.SOCK_DGRAM, 0},
		"netlink (route)": {unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE},
		"vsock":           {unix.AF_VSOCK, unix.SOCK_STREAM, 0},
	}
	for name, s := range refused {
		fd, err := unix.Socket(s[0], s[1]|unix.SOCK_CLOEXEC, s[2])
		if err != nil {
			t.Logf("no %s socket on this host (%v), so that family is not run", name, err)
			continue
		}
		f := os.NewFile(uintptr(fd), name)
		got := sealWithStdin(t, f)
		f.Close()
		if !strings.HasPrefix(got, "refused") {
			t.Errorf("a %s socket on stdin reaches the agent as it is; it must be refused, got %q", name, got)
		}
	}
}
