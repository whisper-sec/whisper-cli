// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package resolverprofile

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The macOS applier: executes the rendered plan natively, step by step, with
// the linux applier's guard semantics.
//
// DoH is a STAGED apply, honestly so: modern macOS refuses a silent CLI
// `profiles install` (GUI or MDM only - an Apple platform rule, not ours), so
// the plan writes/downloads the .mobileconfig and `open`s it; the one
// remaining gesture lives in System Settings > General > VPN & Device
// Management, and the render's notes say exactly that. We never claim a
// silent apply where the OS forbids one.
//
// dns53 (networksetup -setdnsservers) is the one genuinely no-GUI macOS
// path: applied immediately, VERIFIED through the system resolver, and rolled
// back if the resolver does not answer - a machine is never left with broken
// DNS. networksetup needs admin rights; a privilege refusal comes back as
// ErrNeedsRoot so the CLI prints the exact sudo-able block instead of
// failing opaquely.

// Seams for the unit tests (no real system mutation in tests), mirroring the
// apply_linux.go pattern.
var (
	darwinGeteuid  = os.Geteuid
	darwinRunCmd   = realDarwinRunCmd
	darwinWrite    = os.WriteFile
	darwinMkdirAll = os.MkdirAll
	darwinRemove   = os.Remove
	darwinStat     = os.Stat
	darwinDial     = net.DialTimeout
	darwinSleep    = time.Sleep
)

func init() { Register("darwin", darwinApplier{}) }

type darwinApplier struct{}

// DetectHost: elevation is the only host fact macOS plans consume (forwarder
// and resolved detection are Linux concerns).
func (darwinApplier) DetectHost() Host { return Host{Elevated: darwinGeteuid() == 0} }

func (a darwinApplier) Apply(r Rendered) error {
	if len(r.Apply) == 0 {
		return nil
	}
	if err := a.runSteps(r.Apply); err != nil {
		return err
	}
	if r.Mode == ModeDNS53 {
		// Never leave a Mac with broken DNS: verify, roll back on silence.
		if !darwinVerifyResolution() {
			_ = a.runSteps(r.Revert) // best-effort restore; guards make it safe
			return fmt.Errorf("the dedicated resolver %s did not answer from this Mac (it lives on IPv6 :53 - this host needs a global IPv6 route); every change was rolled back and DNS is as it was", r.ResolverIP)
		}
	}
	return nil
}

func (a darwinApplier) Revert(r Rendered) error { return a.runSteps(r.Revert) }

// runSteps executes plan steps in order with the pre-state guard semantics of
// the linux applier (guards evaluated before the first step runs).
func (darwinApplier) runSteps(steps []Step) error {
	runnable := steps[:0:0]
	for _, s := range steps {
		if darwinGuardsPass(s) {
			runnable = append(runnable, s)
		}
	}
	for _, s := range runnable {
		if err := darwinStep(s); err != nil {
			return err
		}
	}
	return nil
}

func darwinStep(s Step) error {
	var err error
	switch {
	case s.File != nil:
		err = darwinWriteFile(*s.File)
	case s.Remove != "":
		if rmErr := darwinRemove(s.Remove); rmErr != nil && !os.IsNotExist(rmErr) {
			err = rmErr
		}
	case s.WaitFor != "":
		err = darwinWaitAnswers(s.WaitFor)
	case s.Shell != "":
		err = darwinRunCmd([]string{"/bin/sh", "-c", s.Shell})
	case len(s.Cmd) > 0:
		err = darwinRunCmd(s.Cmd)
	}
	if err == nil {
		return nil
	}
	// Postel: a refusal must end in a working next step, never a dead end.
	if strings.Contains(s.Shell, "networksetup") && looksLikePrivilegeError(err) {
		return fmt.Errorf("%w (networksetup refused: %v)", ErrNeedsRoot, err)
	}
	if len(s.Cmd) > 0 && s.Cmd[0] == "open" && len(s.Cmd) > 1 {
		// Headless session (ssh): the profile is staged and valid; the double-
		// click plus the System Settings approval is all that remains.
		return fmt.Errorf("could not open the staged profile (no GUI session?): %v; it is saved at %s - double-click it, then approve it under System Settings > General > VPN & Device Management", err, s.Cmd[len(s.Cmd)-1])
	}
	return fmt.Errorf("step %q failed: %w", s.String(), err)
}

func darwinGuardsPass(s Step) bool {
	if s.IfPresent != "" {
		if _, err := darwinStat(s.IfPresent); err != nil {
			return false
		}
	}
	if s.IfAbsent != "" {
		if _, err := darwinStat(s.IfAbsent); err == nil {
			return false
		}
	}
	return true
}

func darwinWriteFile(f FileSpec) error {
	if dir := filepath.Dir(f.Path); dir != "." && dir != "/" {
		if err := darwinMkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	return darwinWrite(f.Path, []byte(f.Content), mode)
}

// darwinWaitAnswers mirrors the linux bounded connect gate (30 x 1s).
func darwinWaitAnswers(hostPort string) error {
	for i := 0; i < 30; i++ {
		conn, err := darwinDial("tcp", hostPort, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		darwinSleep(time.Second)
	}
	return fmt.Errorf("nothing answered on %s within 30s; DNS was left unchanged", hostPort)
}

// darwinVerifyResolution asks the SYSTEM resolver (dscacheutil goes through
// mDNSResponder, honouring the per-service DNS just applied), bounded: 3
// tries, 2s apart. It asks for a name Whisper is NOT authoritative for on
// purpose: the ns boxes answer whisper.online authoritatively even to a
// client whose recursion they would refuse, so only a neutral name proves
// end-to-end RESOLUTION works.
func darwinVerifyResolution() bool {
	for i := 0; i < 3; i++ {
		if i > 0 {
			darwinSleep(2 * time.Second)
		}
		if err := darwinRunCmd([]string{"/usr/bin/dscacheutil", "-q", "host", "-a", "name", "example.com"}); err == nil {
			return true
		}
	}
	return false
}

// looksLikePrivilegeError spots networksetup's admin-rights refusals.
func looksLikePrivilegeError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"privileg", "permission", "not allowed", "must be run as root", "admin"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// realDarwinRunCmd executes an argv directly (no shell for Cmd steps),
// capturing stderr into the error so a failure is diagnosable, never opaque.
// dscacheutil exits 0 even on a miss, so treat empty output as failure there.
func realDarwinRunCmd(argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil && argv[0] == "/usr/bin/dscacheutil" && !bytes.Contains(stdout.Bytes(), []byte("address:")) {
		return fmt.Errorf("no answer from the system resolver")
	}
	if err != nil {
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}
