// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnforceTargetRefusesRootInEverySpelling(t *testing.T) {
	for _, u := range []string{"root", "0"} {
		if _, err := resolveEnforceTarget(u); err == nil || !strings.Contains(err.Error(), "must not run as root") {
			t.Fatalf("--user %s: got %v", u, err)
		}
	}
	t.Setenv("SUDO_USER", "root")
	if _, err := resolveEnforceTarget(""); err == nil || !strings.Contains(err.Error(), "must not run as root") {
		t.Fatalf("SUDO_USER=root: got %v", err)
	}
	t.Setenv("SUDO_USER", "")
	if _, err := resolveEnforceTarget(""); err == nil || !strings.Contains(err.Error(), "--user") {
		t.Fatalf("plain root with no --user: got %v", err)
	}
	if _, err := resolveEnforceTarget("no-such-account-xyzzy"); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("unknown account: got %v", err)
	}
}

func TestInvokerFileIsReadOnlyFromARegularFileTheInvokerOwns(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "whisper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tgt := enforceTarget{home: home, uid: uint32(os.Getuid())}
	missingRoot := filepath.Join(t.TempDir(), "none")
	if got := invokerFile(tgt, missingRoot, "key"); got != "" {
		t.Fatalf("no file yet: got %q", got)
	}
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := invokerFile(tgt, missingRoot, "key"); got != key {
		t.Fatalf("owned regular file: got %q", got)
	}
	rootHas := filepath.Join(t.TempDir(), "rootkey")
	_ = os.WriteFile(rootHas, []byte("r"), 0o600)
	if got := invokerFile(tgt, rootHas, "key"); got != "" {
		t.Fatal("root's own file wins; the invoker's is not read")
	}
	os.Remove(key)
	target := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	if err := os.Symlink(target, key); err != nil {
		t.Fatal(err)
	}
	if got := invokerFile(tgt, missingRoot, "key"); got != "" {
		t.Fatal("a link is never followed")
	}
	other := enforceTarget{home: home, uid: uint32(os.Getuid()) + 1}
	os.Remove(key)
	_ = os.WriteFile(key, []byte("k"), 0o600)
	if got := invokerFile(other, missingRoot, "key"); got != "" {
		t.Fatal("a file someone else owns is not read")
	}
}

// A signal between the connect and the agent's start is held, ends the run with 128 plus its
// number, and does not kill the process.
func TestASignalBeforeTheAgentStartsIsHeldAndReported(t *testing.T) {
	s := armEnforceSignals()
	if err := s.interrupted(); err != nil {
		t.Fatalf("nothing arrived yet: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the signal did not cancel the run's context")
	}
	s.stop()
	s.stop()
	err := s.interrupted()
	code, ok := exitCodeOf(err)
	if !ok || code != 129 || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("got %v (code %d, %v)", err, code, ok)
	}
}

func TestStoppingTheEarlyHandlerWithNothingCaughtIsQuiet(t *testing.T) {
	s := armEnforceSignals()
	s.stop()
	if err := s.interrupted(); err != nil {
		t.Fatalf("nothing arrived: %v", err)
	}
	if s.ctx.Err() != nil {
		t.Fatal("stopping is not an interruption")
	}
}

// Signals reach the agent's init while it runs and never its pid after it was reaped.
func TestSignalsAreForwardedOnlyUntilTheInitIsReaped(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	fwd := make(chan os.Signal, 1)
	reaped := make(chan struct{})
	done := make(chan struct{})
	go func() { forwardSignals(fwd, reaped, child.Process.Pid); close(done) }()
	fwd <- syscall.SIGTERM
	werr := child.Wait()
	var ee *exec.ExitError
	if !errors.As(werr, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("the forwarded SIGTERM did not reach the child: %v", werr)
	}
	close(reaped)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the forwarder outlived the init")
	}

	// After the reap a queued signal is not sent: a fresh process stands in for a recycled pid.
	other := exec.Command("sleep", "30")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- other.Wait() }()
	defer func() { _ = other.Process.Kill(); <-exited }()
	// Both cases of the forwarder's select are ready here, and Go picks between them at random, so
	// one try would pass a forwarder that ignores the reap half the time.
	r2 := make(chan struct{})
	close(r2)
	for i := 0; i < 32; i++ {
		fwd2 := make(chan os.Signal, 1)
		fwd2 <- syscall.SIGTERM
		forwardSignals(fwd2, r2, other.Process.Pid)
	}
	// Signal(0) succeeds on a zombie, so the child's own exit is what is watched.
	select {
	case err := <-exited:
		exited <- err
		t.Fatalf("a signal went to a pid after the reap: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}
