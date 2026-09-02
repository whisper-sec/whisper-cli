// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package resolverprofile

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Windows-native tests of the applier seams, plus the LIVE end-to-end (env
// WHISPER_T2_LIVE=1, elevated) that proves apply -> NRPT rule present ->
// revert -> rule gone on a real box.

// winFake dispatches scripts by their distinctive markers and records them.
type winFake struct {
	ran      []string
	elevated bool
	caps     string // probe output
	applyRC  int
	verifyRC int
}

func (f *winFake) run(script string) (string, int, error) {
	f.ran = append(f.ran, script)
	switch {
	case strings.Contains(script, "IsInRole"):
		if f.elevated {
			return "", 0, nil
		}
		return "", 1, nil
	case strings.Contains(script, "nrpt-doh="):
		return f.caps, 0, nil
	case strings.Contains(script, "GetHostAddresses"):
		return "", f.verifyRC, nil
	default:
		return "", f.applyRC, nil
	}
}

func withWinFake(t *testing.T, f *winFake) {
	t.Helper()
	orig := winRunScript
	winRunScript = f.run
	t.Cleanup(func() { winRunScript = orig })
}

func (f *winFake) scriptContaining(marker string) string {
	for _, s := range f.ran {
		if strings.Contains(s, marker) {
			return s
		}
	}
	return ""
}

func TestT2WinApplyNotElevated(t *testing.T) {
	f := &winFake{elevated: false}
	withWinFake(t, f)
	err := windowsApplier{}.Apply(t2winDoHProfile().Render(Host{}))
	if !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("not-elevated apply must return ErrNeedsRoot (the CLI then prints the exact block), got: %v", err)
	}
}

func TestT2WinApplyAdaptsForOldBuild(t *testing.T) {
	f := &winFake{elevated: true, caps: "nrpt-doh=False;reset-cmdlet=False"}
	withWinFake(t, f)
	if err := (windowsApplier{}.Apply(t2winDoHProfile().Render(Host{}))); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// "-Namespace" is unique to the executed apply plan (the caps probe also
	// names the cmdlet, via Get-Command).
	script := f.scriptContaining("Add-DnsClientNrptRule -Namespace")
	if script == "" {
		t.Fatalf("the apply script never ran: %v", f.ran)
	}
	if !strings.HasPrefix(script, "$ErrorActionPreference = 'Stop'") {
		t.Fatalf("the executed script must fail fast:\n%s", script)
	}
	if nrpt := findLine(t, script, "Add-DnsClientNrptRule -Namespace"); strings.Contains(nrpt, "-DohTemplate") {
		t.Fatalf("on a build without NRPT DoH the parameter must be stripped: %s", nrpt)
	}
}

func TestT2WinApplyKeepsTemplateOnCapableBuild(t *testing.T) {
	f := &winFake{elevated: true, caps: "nrpt-doh=True;reset-cmdlet=True"}
	withWinFake(t, f)
	if err := (windowsApplier{}.Apply(t2winDoHProfile().Render(Host{}))); err != nil {
		t.Fatalf("apply: %v", err)
	}
	script := f.scriptContaining("Add-DnsClientNrptRule -Namespace")
	if nrpt := findLine(t, script, "Add-DnsClientNrptRule -Namespace"); !strings.Contains(nrpt, "-DohTemplate") {
		t.Fatalf("a capable build keeps the template on the rule: %s", nrpt)
	}
}

func TestT2WinApplyVerifyFailureRollsBack(t *testing.T) {
	f := &winFake{elevated: true, caps: "nrpt-doh=False;reset-cmdlet=False", verifyRC: 1}
	withWinFake(t, f)
	err := windowsApplier{}.Apply(t2winDoHProfile().Render(Host{}))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("a failed verification must roll back and say so, got: %v", err)
	}
	if f.scriptContaining("Remove-DnsClientNrptRule") == "" {
		t.Fatalf("the revert script must have run on verification failure: %v", f.ran)
	}
}

func TestT2WinRevert(t *testing.T) {
	f := &winFake{elevated: true, caps: "nrpt-doh=False;reset-cmdlet=False"}
	withWinFake(t, f)
	if err := (windowsApplier{}.Revert(t2winDoHProfile().Render(Host{}))); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if f.scriptContaining("Remove-DnsClientNrptRule") == "" {
		t.Fatalf("revert must remove our NRPT rule: %v", f.ran)
	}
}

// --- LIVE end-to-end (WHISPER_T2_LIVE=1, elevated PowerShell) ---------------

func TestT2WinLiveApplyRevert(t *testing.T) {
	if os.Getenv("WHISPER_T2_LIVE") != "1" {
		t.Skip("set WHISPER_T2_LIVE=1 (elevated) for the live end-to-end")
	}
	a := windowsApplier{}
	if !a.DetectHost().Elevated {
		t.Fatalf("the live e2e needs an elevated shell")
	}
	caps := a.caps()
	t.Logf("live caps: %+v", caps)

	r := Profile{Mode: ModeDoH, OS: "windows", DohTemplate: "https://doh.whisper.online/dns-query"}.Render(Host{Elevated: true})
	applyErr := a.Apply(r)
	t.Logf("apply -> %v", applyErr)

	out, code, err := winRunScript(`(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'whisper-resolver' } | Measure-Object).Count`)
	t.Logf("nrpt-rule count after apply: %q (code=%d err=%v)", strings.TrimSpace(out), code, err)

	if applyErr == nil {
		// Applied and verified: our rule must exist, then revert must remove it.
		if strings.TrimSpace(out) == "0" {
			t.Errorf("apply reported success but no whisper-resolver NRPT rule exists")
		}
	} else if !strings.Contains(applyErr.Error(), "rolled back") {
		t.Errorf("live apply failed without rolling back: %v", applyErr)
	}

	if err := a.Revert(r); err != nil {
		t.Fatalf("live revert: %v", err)
	}
	out, _, _ = winRunScript(`(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'whisper-resolver' } | Measure-Object).Count`)
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("after revert the whisper-resolver NRPT rule must be gone, count=%q", strings.TrimSpace(out))
	}
	// Whatever happened above, the box must still resolve.
	if _, code, _ := winRunScript(winVerifyScript); code != 0 {
		t.Fatalf("DNS is broken after the e2e - the never-break contract failed")
	}
}

func TestT2WinLiveDNS53(t *testing.T) {
	if os.Getenv("WHISPER_T2_LIVE") != "1" {
		t.Skip("set WHISPER_T2_LIVE=1 (elevated) for the live end-to-end")
	}
	a := windowsApplier{}
	if !a.DetectHost().Elevated {
		t.Fatalf("the live e2e needs an elevated shell")
	}
	ip := os.Getenv("WHISPER_T2_RESOLVER")
	if ip == "" {
		ip = "2a04:2a01:0:53::1" // the shared :53 answer target; on a v4-only host this proves the rollback
	}
	r := Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{ip}}.Render(Host{Elevated: true})
	err := a.Apply(r)
	t.Logf("live dns53 apply -> %v", err)
	switch {
	case err == nil:
		if rerr := a.Revert(r); rerr != nil {
			t.Fatalf("live dns53 revert: %v", rerr)
		}
	case strings.Contains(err.Error(), "rolled back"):
		// The honest no-IPv6-route outcome; the adapted reset restored DHCP DNS.
	default:
		t.Fatalf("unexpected live dns53 failure: %v", err)
	}
	out, _, _ := winRunScript(`(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses -contains '` + ip + `' } | Measure-Object).Count`)
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("an adapter still points at %s after the e2e, count=%q", ip, strings.TrimSpace(out))
	}
	if _, code, _ := winRunScript(winVerifyScript); code != 0 {
		t.Fatalf("DNS is broken after the dns53 e2e - the never-break contract failed")
	}
}
