// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// macOS drops a syslog datagram, so on darwin the ssh-authz decision goes through logger(1).
// The exec half is built on every unix, so these run on Linux CI against a stand-in logger that
// records its argv; the darwin read-back is the live check on a Mac.

// fakeLogger writes a script that records each argument on its own line, then runs body.
func fakeLogger(t *testing.T, body string) (path, argvFile string) {
	t.Helper()
	dir := t.TempDir()
	argvFile = filepath.Join(dir, "argv")
	path = filepath.Join(dir, "logger")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + argvFile + "'\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, argvFile
}

func TestSSHAuthzLoggerArgsCarryTheTagInTheText(t *testing.T) {
	got := sshAuthzLoggerArgs("DENY user=deploy: no PTR")
	want := []string{"-p", "auth.notice", "-t", "whisper-ssh-authz", "--", "whisper-ssh-authz: DENY user=deploy: no PTR"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestSSHAuthzLoggerArgsLogAnAdmitAtNoticeToo(t *testing.T) {
	// An info line on macOS lives in memory only; the ADMIT an auditor needs must reach disk.
	if got := sshAuthzLoggerArgs("ADMIT user=deploy"); got[1] != "auth.notice" {
		t.Fatalf("priority = %q, want auth.notice for an ADMIT as well", got[1])
	}
}

func TestSSHAuthzLoggerRunsTheMessageAsOneArgumentAfterDoubleDash(t *testing.T) {
	path, argvFile := fakeLogger(t, "")
	msg := "DENY user=-x from=2a04:2a01:9::50: a login name that starts with - is refused; $(id) `id`"
	if err := runSSHAuthzLogger(path, sshAuthzLoggerArgs(msg)); err != nil {
		t.Fatalf("logger: %v", err)
	}
	b, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(argv) != 6 || argv[4] != "--" || argv[5] != "whisper-ssh-authz: "+msg {
		t.Fatalf("argv = %q, want the message whole and literal after --", argv)
	}
}

func TestSSHAuthzLoggerOutputNeverReachesSSHD(t *testing.T) {
	// sshd reads the command's stdout as authorized_keys lines.
	path, _ := fakeLogger(t, "echo ssh-ed25519 AAAALEAK; echo LEAK >&2")
	stdout, stderr := captureStd(t, func() { _ = runSSHAuthzLogger(path, sshAuthzLoggerArgs("ADMIT x")) })
	if strings.Contains(stdout+stderr, "LEAK") {
		t.Fatalf("logger output leaked: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestSSHAuthzLoggerIsBoundedInTime(t *testing.T) {
	path, _ := fakeLogger(t, "exec sleep 30")
	start := time.Now()
	if err := runSSHAuthzLogger(path, sshAuthzLoggerArgs("DENY x")); err == nil {
		t.Fatal("a logger killed at the deadline must report an error")
	}
	if d := time.Since(start); d > sshAuthzLoggerTimeout+3*time.Second {
		t.Fatalf("logger took %v, want it cut off near %v", d, sshAuthzLoggerTimeout)
	}
}

func TestSSHAuthzLoggerMissingIsAnErrorNotAPanic(t *testing.T) {
	if err := runSSHAuthzLogger(filepath.Join(t.TempDir(), "nope"), sshAuthzLoggerArgs("DENY x")); err == nil {
		t.Fatal("a missing logger must report an error")
	}
}

func TestLogSSHAuthzStillWritesTheTaggedLineToStderr(t *testing.T) {
	_, stderr := captureStd(t, func() { logSSHAuthz(false, "user=deploy: no PTR") })
	if !strings.Contains(stderr, "whisper-ssh-authz: DENY user=deploy: no PTR") {
		t.Fatalf("stderr = %q, want the tagged decision", stderr)
	}
}
