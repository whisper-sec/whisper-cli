// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package resolverprofile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The Windows applier: runs the rendered plan as ONE PowerShell script (the
// steps share $ips state, so they must execute in one process - the same
// script ApplyScript renders for --print), adapted to the running build's
// DNS-client capabilities (winsupport.go), then VERIFIES the system resolver
// still answers and rolls the plan back if it does not. A machine is never
// left with broken DNS. Windows NRPT/DoH apply silently under elevation -
// no user gesture - and without elevation Apply returns ErrNeedsRoot so the
// CLI prints the exact elevated block instead of failing opaquely.

// Seams for the unit tests (no real system mutation in tests), mirroring the
// apply_linux.go pattern.
var (
	winRunScript = realWinRunScript
)

func init() { Register("windows", windowsApplier{}) }

type windowsApplier struct{}

// DetectHost probes elevation; NRPT DoH support and the reset cmdlet are
// probed per run in caps() (they are execution details, not render inputs).
func (windowsApplier) DetectHost() Host {
	_, code, err := winRunScript(winElevationProbeScript)
	return Host{Elevated: err == nil && code == 0}
}

func (windowsApplier) caps() winCaps {
	out, code, err := winRunScript(winCapsProbeScript)
	if err != nil || code != 0 {
		return winCaps{} // degrade to "capabilities missing" - always safe
	}
	return parseWinCaps(out)
}

func (a windowsApplier) Apply(r Rendered) error {
	if len(r.Apply) == 0 {
		return nil
	}
	if !a.DetectHost().Elevated {
		return fmt.Errorf("%w (Windows DNS settings need an elevated PowerShell)", ErrNeedsRoot)
	}
	caps := a.caps()
	out, code, err := winRunScript(winWrapScript(adaptWinScript(r.ApplyScript(), caps)))
	if err != nil {
		return fmt.Errorf("could not run PowerShell: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("the apply script failed (exit %d):\n%s", code, strings.TrimSpace(out))
	}
	// Never leave a machine with broken DNS: verify the system resolver still
	// answers; if not, run the revert plan and say exactly what happened.
	if vout, vcode, verr := winRunScript(winVerifyScript); verr != nil || vcode != 0 {
		_, _, _ = winRunScript(winWrapScript(adaptWinScript(r.RevertScript(), caps)))
		hint := "this host may lack the route to the resolver"
		if r.Mode == ModeDoH && !caps.NrptDoh {
			hint = "this Windows build cannot attach DoH to NRPT rules; use the setup script from https://resolver.whisper.online (adapter-wide encrypted form) instead"
		} else if r.Mode == ModeDNS53 {
			hint = "the dedicated resolver answers on IPv6 :53 - this host needs a global IPv6 route"
		}
		return fmt.Errorf("resolution could not be verified after the apply (%s); every change was rolled back and DNS is as it was%s", hint, verifyTail(vout))
	}
	return nil
}

func (a windowsApplier) Revert(r Rendered) error {
	if len(r.Revert) == 0 {
		return nil
	}
	if !a.DetectHost().Elevated {
		return fmt.Errorf("%w (Windows DNS settings need an elevated PowerShell)", ErrNeedsRoot)
	}
	out, code, err := winRunScript(winWrapScript(adaptWinScript(r.RevertScript(), a.caps())))
	if err != nil {
		return fmt.Errorf("could not run PowerShell: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("the revert script failed (exit %d):\n%s", code, strings.TrimSpace(out))
	}
	return nil
}

func verifyTail(out string) string {
	if s := strings.TrimSpace(out); s != "" {
		return "\n" + s
	}
	return ""
}

// realWinRunScript executes a PowerShell script via a private temp file - the
// DoH template inside is a resolve-only credential, and a file keeps it out
// of the process command line (visible to every local process).
func realWinRunScript(script string) (string, int, error) {
	f, err := os.CreateTemp("", "whisper-resolver-*.ps1")
	if err != nil {
		return "", -1, fmt.Errorf("could not stage the script: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return "", -1, fmt.Errorf("could not write the script: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", -1, fmt.Errorf("could not write the script: %w", err)
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	b, err := cmd.CombinedOutput()
	out := string(b)
	var xe *exec.ExitError
	if errors.As(err, &xe) {
		return out, xe.ExitCode(), nil
	}
	if err != nil {
		return out, -1, err
	}
	return out, 0, nil
}
