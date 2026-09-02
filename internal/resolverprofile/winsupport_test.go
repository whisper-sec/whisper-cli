// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"runtime"
	"strings"
	"testing"
)

// The apply-cluster tests for the WINDOWS side of the Tier-2 plan:
// NRPT command construction, revert construction, the Server-2022 capability
// adaptation (grounded live: build 10.0.20348 has no -DohTemplate on
// Add-DnsClientNrptRule and no Reset-DnsClientServerAddress at all), and the
// os-guard registry contract. Pure - they run on every build host.

const t2TestDoH = "https://doh.whisper.online/tok_t2test/dns-query"

func t2winDoHProfile() Profile {
	return Profile{Mode: ModeDoH, OS: "windows", DohTemplate: t2TestDoH}
}

func TestT2ApplyWinNrptConstruction(t *testing.T) {
	r := t2winDoHProfile().Render(Host{})
	script := r.ApplyScript()

	// The DoH template is registered per resolved address, both families,
	// encrypted-only with AutoUpgrade (the WIN_TEMPLATE contract).
	for _, want := range []string{
		"Resolve-DnsName doh.whisper.online -Type A",
		"Resolve-DnsName doh.whisper.online -Type AAAA",
		"Add-DnsClientDohServerAddress -ServerAddress $srv -DohTemplate '" + t2TestDoH + "'",
		"-AllowFallbackToUdp $false",
		"-AutoUpgrade $true",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("windows DoH apply script is missing %q:\n%s", want, script)
		}
	}

	// ONE targeted NRPT rule for the whole namespace, template attached,
	// tagged with our comment so revert removes exactly ours.
	nrpt := findLine(t, script, "Add-DnsClientNrptRule")
	for _, want := range []string{
		"-Namespace '.'",
		"-NameServers $ips",
		"-DohTemplate '" + t2TestDoH + "'",
		"-Comment 'whisper-resolver'",
	} {
		if !strings.Contains(nrpt, want) {
			t.Fatalf("NRPT rule line is missing %q: %s", want, nrpt)
		}
	}
}

func TestT2ApplyWinRevertConstruction(t *testing.T) {
	r := t2winDoHProfile().Render(Host{})
	script := r.RevertScript()
	for _, want := range []string{
		"Get-DnsClientNrptRule | Where-Object Comment -eq 'whisper-resolver' | Remove-DnsClientNrptRule -Force",
		"Get-DnsClientDohServerAddress | Where-Object DohTemplate -eq '" + t2TestDoH + "' | Remove-DnsClientDohServerAddress",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("windows revert script is missing %q:\n%s", want, script)
		}
	}
	// Revert never touches rules or registrations that are not ours.
	if strings.Contains(script, "Remove-DnsClientNrptRule -Force\n") && !strings.Contains(script, "Where-Object Comment") {
		t.Fatalf("revert must select OUR rule by comment before removing:\n%s", script)
	}
}

func TestT2ApplyWinDNS53Construction(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{"2a04:2a01:0:53::42"}}
	r := p.Render(Host{})
	apply := r.ApplyScript()
	if !strings.Contains(apply, "Set-DnsClientServerAddress -ServerAddresses '2a04:2a01:0:53::42'") {
		t.Fatalf("dns53 apply must point adapters at the dedicated /128:\n%s", apply)
	}
	if !strings.Contains(r.RevertScript(), "Reset") {
		t.Fatalf("dns53 revert must reset adapter DNS:\n%s", r.RevertScript())
	}
	// The plaintext tradeoff is stated, never hidden (conservative out).
	if !strings.Contains(strings.Join(r.Notes, "\n"), "unencrypted") {
		t.Fatalf("dns53 notes must state the plaintext tradeoff: %v", r.Notes)
	}
}

func TestT2ApplyWinDNS53KeylessDegradesWithNote(t *testing.T) {
	// Keyless has no dedicated /128: the plan must degrade to a clear note,
	// never an opaque failure (Postel).
	r := Profile{Mode: ModeDNS53, OS: "windows"}.Render(Host{})
	if len(r.Apply) != 0 {
		t.Fatalf("keyless dns53 must not produce apply steps: %v", r.Apply)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "Whisper key") {
		t.Fatalf("keyless dns53 must explain the key path: %v", r.Notes)
	}
}

func TestT2ApplyWinQuoting(t *testing.T) {
	// PowerShell single-quoting doubles embedded quotes - defensive, the
	// grammar is closed (mirrors the server's psSingleQuote).
	p := Profile{Mode: ModeDoH, OS: "windows", DohTemplate: "https://doh.whisper.online/it's/dns-query"}
	script := p.Render(Host{}).ApplyScript()
	if !strings.Contains(script, "'https://doh.whisper.online/it''s/dns-query'") {
		t.Fatalf("embedded quote must be doubled in the PS literal:\n%s", script)
	}
}

// --- the Server-2022 capability adaptation (probed live on 10.0.20348) ------

func TestT2ApplyWinAdaptStripsNrptDohOnOldBuilds(t *testing.T) {
	script := t2winDoHProfile().Render(Host{}).ApplyScript()
	adapted := adaptWinScript(script, winCaps{NrptDoh: false, ResetCmdlet: false})

	nrpt := findLine(t, adapted, "Add-DnsClientNrptRule")
	if strings.Contains(nrpt, "-DohTemplate") || strings.Contains(nrpt, "-AutoUpgrade") {
		t.Fatalf("old-build NRPT line must not carry DoH parameters: %s", nrpt)
	}
	// The rule itself survives, still tagged.
	for _, want := range []string{"-Namespace '.'", "-NameServers $ips", "-Comment 'whisper-resolver'"} {
		if !strings.Contains(nrpt, want) {
			t.Fatalf("adapted NRPT line lost %q: %s", want, nrpt)
		}
	}
	// The per-address registration KEEPS its template - it exists on 20348
	// and stays the encryption anchor.
	reg := findLine(t, adapted, "Add-DnsClientDohServerAddress")
	if !strings.Contains(reg, "-DohTemplate") || !strings.Contains(reg, "-AutoUpgrade $true") {
		t.Fatalf("registration line must keep its DoH parameters: %s", reg)
	}
}

func TestT2ApplyWinAdaptQuotedTemplateWithQuote(t *testing.T) {
	p := Profile{Mode: ModeDoH, OS: "windows", DohTemplate: "https://doh.whisper.online/it's/dns-query"}
	adapted := adaptWinScript(p.Render(Host{}).ApplyScript(), winCaps{})
	nrpt := findLine(t, adapted, "Add-DnsClientNrptRule")
	if strings.Contains(nrpt, "-DohTemplate") || strings.Contains(nrpt, "it''s") {
		t.Fatalf("the doubled-quote template literal must be stripped whole: %s", nrpt)
	}
}

func TestT2ApplyWinAdaptRewritesPhantomResetCmdlet(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{"2a04:2a01:0:53::42"}}
	script := p.Render(Host{}).RevertScript()
	adapted := adaptWinScript(script, winCaps{ResetCmdlet: false})
	if strings.Contains(adapted, "Get-NetAdapter | Reset-DnsClientServerAddress") {
		t.Fatalf("Reset-DnsClientServerAddress does not exist on Server 2022; the universal form must be substituted:\n%s", adapted)
	}
	if !strings.Contains(adapted, "Get-DnsClient | Set-DnsClientServerAddress -ResetServerAddresses") {
		t.Fatalf("the universal reset form is missing:\n%s", adapted)
	}
}

func TestT2ApplyWinAdaptNoOpOnCapableBuilds(t *testing.T) {
	for _, script := range []string{
		t2winDoHProfile().Render(Host{}).ApplyScript(),
		Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{"::1"}}.Render(Host{}).RevertScript(),
	} {
		if got := adaptWinScript(script, winCaps{NrptDoh: true, ResetCmdlet: true}); got != script {
			t.Fatalf("a fully capable build must run the plan unchanged:\n--- want\n%s\n--- got\n%s", script, got)
		}
	}
}

func TestT2ApplyWinCapsParse(t *testing.T) {
	cases := []struct {
		in   string
		want winCaps
	}{
		{"nrpt-doh=False;reset-cmdlet=False", winCaps{}},
		{"nrpt-doh=True;reset-cmdlet=True\r\n", winCaps{NrptDoh: true, ResetCmdlet: true}},
		{"nrpt-doh=True;reset-cmdlet=False", winCaps{NrptDoh: true}},
		{"", winCaps{}},
		{"garbage output", winCaps{}}, // degrade to "missing" - always safe
	}
	for _, c := range cases {
		if got := parseWinCaps(c.in); got != c.want {
			t.Fatalf("parseWinCaps(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestT2ApplyWinWrapScriptStopsOnError(t *testing.T) {
	if !strings.HasPrefix(winWrapScript("x"), "$ErrorActionPreference = 'Stop'\n") {
		t.Fatalf("the executed script must fail fast, never run on past an error")
	}
}

// --- os-guard: appliers register only on their own OS; Print works anywhere -

func TestT2ApplyOSGuardRegistry(t *testing.T) {
	// The RUNNING OS's applier is registered (when it has one); the others are
	// not compiled in - callers fall back to printing the exact plan.
	for _, goos := range []string{"linux", "windows", "darwin"} {
		_, ok := For(goos)
		if goos == runtime.GOOS && !ok {
			t.Fatalf("the %s applier must self-register on %s", goos, runtime.GOOS)
		}
		if goos != runtime.GOOS && ok {
			t.Fatalf("the %s applier must not be registered on %s (build-tag guard)", goos, runtime.GOOS)
		}
	}
	// Cross-OS render stays available from any box (--print --os <other>).
	for _, goos := range []string{"windows", "darwin", "linux"} {
		r := Profile{Mode: ModeDoH, OS: goos, DohTemplate: t2TestDoH}.Render(Host{ForwarderKind: "cloudflared", ForwarderPath: "/usr/bin/cloudflared"})
		if r.OS != goos {
			t.Fatalf("render for %s reported OS %q", goos, r.OS)
		}
		if len(r.Apply) == 0 {
			t.Fatalf("render for %s produced no apply steps", goos)
		}
	}
}

// findLine returns the first script line containing marker.
func findLine(t *testing.T, script, marker string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, marker) {
			return line
		}
	}
	t.Fatalf("no line containing %q in:\n%s", marker, script)
	return ""
}
