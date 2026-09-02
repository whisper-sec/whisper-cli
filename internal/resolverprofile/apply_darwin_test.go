// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package resolverprofile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// macOS-native tests of the applier seams, plus the LIVE end-to-end (env
// WHISPER_T2_LIVE=1) that stages a real profile and drives networksetup on a
// real Mac. The live dns53 flow accepts BOTH outcomes:
// applied-and-verified, or verify-failed-and-rolled-back (a Mac without a
// global IPv6 route cannot reach the resolver) - and in both cases the Mac
// must still resolve afterwards.

type darwinFake struct {
	cmds        [][]string
	failMatch   string // substring of the joined argv that fails
	failWith    string // stderr-style message for the failure
	dscacheFail bool
}

func (f *darwinFake) run(argv []string) error {
	f.cmds = append(f.cmds, argv)
	joined := strings.Join(argv, " ")
	if f.dscacheFail && strings.Contains(joined, "dscacheutil") {
		return fmt.Errorf("no answer from the system resolver")
	}
	if f.failMatch != "" && strings.Contains(joined, f.failMatch) {
		return fmt.Errorf("%s", f.failWith)
	}
	return nil
}

func (f *darwinFake) sawContaining(marker string) bool {
	for _, c := range f.cmds {
		if strings.Contains(strings.Join(c, " "), marker) {
			return true
		}
	}
	return false
}

func withDarwinFake(t *testing.T, f *darwinFake) {
	t.Helper()
	origRun, origSleep := darwinRunCmd, darwinSleep
	darwinRunCmd = f.run
	darwinSleep = func(time.Duration) {}
	t.Cleanup(func() { darwinRunCmd, darwinSleep = origRun, origSleep })
}

func t2darwinDNS53() Rendered {
	return Profile{Mode: ModeDNS53, OS: "darwin", ResolverIPs: []string{"2a04:2a01:0:53::42"}}.Render(Host{})
}

func TestT2DarwinDNS53AppliedAndVerified(t *testing.T) {
	f := &darwinFake{}
	withDarwinFake(t, f)
	if err := (darwinApplier{}.Apply(t2darwinDNS53())); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !f.sawContaining("networksetup -setdnsservers") {
		t.Fatalf("networksetup never ran: %v", f.cmds)
	}
	if !f.sawContaining("dscacheutil") {
		t.Fatalf("the apply must verify through the system resolver: %v", f.cmds)
	}
}

func TestT2DarwinDNS53VerifyFailureRollsBack(t *testing.T) {
	f := &darwinFake{dscacheFail: true}
	withDarwinFake(t, f)
	err := darwinApplier{}.Apply(t2darwinDNS53())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("failed verification must roll back and say so, got: %v", err)
	}
	if !f.sawContaining("Empty") {
		t.Fatalf("the revert loop (setdnsservers Empty) must have run: %v", f.cmds)
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("the error must explain the likely cause (no global IPv6 route): %v", err)
	}
}

func TestT2DarwinDNS53PrivilegeRefusalIsErrNeedsRoot(t *testing.T) {
	f := &darwinFake{failMatch: "networksetup", failWith: "You must have admin privileges to change the DNS servers"}
	withDarwinFake(t, f)
	err := darwinApplier{}.Apply(t2darwinDNS53())
	if !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("a privilege refusal must map to ErrNeedsRoot (the CLI then prints the sudo block), got: %v", err)
	}
}

func TestT2DarwinDoHOpenFailureStaysStaged(t *testing.T) {
	// Over ssh there is no GUI session; `open` fails but the profile is
	// staged and the error must hand over the exact remaining gesture.
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	f := &darwinFake{failMatch: "open ", failWith: "LSOpenURLsWithRole() failed"}
	withDarwinFake(t, f)
	r := Profile{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"}.Render(Host{})
	err := darwinApplier{}.Apply(r)
	if err == nil || !strings.Contains(err.Error(), "System Settings") {
		t.Fatalf("the open-failure path must point at the manual approval, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, darwinMobileconfigFile)); statErr != nil {
		t.Fatalf("the profile must remain staged: %v", statErr)
	}
}

func TestT2DarwinRevertIdempotentWhenNothingStaged(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	f := &darwinFake{}
	withDarwinFake(t, f)
	r := Profile{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"}.Render(Host{})
	// Nothing was ever applied: the guarded revert must be a clean no-op for
	// the file step and still tolerate the profiles-remove step.
	if err := (darwinApplier{}.Revert(r)); err != nil {
		t.Fatalf("revert on a clean machine must succeed: %v", err)
	}
}

// --- LIVE end-to-end (WHISPER_T2_LIVE=1) ------------------------------------

func TestT2DarwinLiveDoHStage(t *testing.T) {
	if os.Getenv("WHISPER_T2_LIVE") != "1" {
		t.Skip("set WHISPER_T2_LIVE=1 for the live end-to-end")
	}
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	r := Profile{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"}.Render(Host{})
	err := darwinApplier{}.Apply(r)
	t.Logf("live DoH stage -> %v", err)
	// Headless ssh: `open` may fail, but ONLY with the staged-and-guided error.
	if err != nil && !strings.Contains(err.Error(), "System Settings") {
		t.Fatalf("unexpected stage failure: %v", err)
	}
	path := filepath.Join(dir, darwinMobileconfigFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("profile not staged: %v", err)
	}
	// The staged profile must be a valid plist by Apple's own linter.
	if out, lintErr := exec.Command("/usr/bin/plutil", "-lint", path).CombinedOutput(); lintErr != nil {
		t.Fatalf("plutil -lint rejected the staged profile: %v\n%s", lintErr, out)
	} else {
		t.Logf("plutil: %s", strings.TrimSpace(string(out)))
	}
	if err := (darwinApplier{}.Revert(r)); err != nil {
		t.Logf("revert note (profiles remove is GUI-gated on modern macOS): %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("revert must remove the staged file")
	}
}

func TestT2DarwinLiveDNS53(t *testing.T) {
	if os.Getenv("WHISPER_T2_LIVE") != "1" {
		t.Skip("set WHISPER_T2_LIVE=1 for the live end-to-end")
	}
	ip := os.Getenv("WHISPER_T2_RESOLVER")
	if ip == "" {
		t.Skip("set WHISPER_T2_RESOLVER=<dedicated /128> for the live dns53 end-to-end")
	}
	r := Profile{Mode: ModeDNS53, OS: "darwin", ResolverIPs: []string{ip}}.Render(Host{})
	a := darwinApplier{}
	err := a.Apply(r)
	t.Logf("live dns53 apply -> %v", err)
	switch {
	case err == nil:
		// Applied and verified: revert must restore automatic DNS.
		if rerr := a.Revert(r); rerr != nil {
			t.Fatalf("live revert: %v", rerr)
		}
	case strings.Contains(err.Error(), "rolled back"):
		// The honest no-IPv6-route outcome; rollback already restored DNS.
	case errors.Is(err, ErrNeedsRoot):
		t.Skipf("networksetup needs admin rights in this session: %v", err)
	default:
		t.Fatalf("unexpected live apply failure: %v", err)
	}
	// Whatever happened, the Mac must still resolve.
	if !darwinVerifyResolution() {
		t.Fatalf("DNS is broken after the e2e - the never-break contract failed")
	}
}
