// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"regexp"
	"strings"
)

// Windows build-capability adaptation for the rendered PowerShell plan.
//
// The plan (renderWindows) targets the newest DNS client surface; older
// Windows builds lack parts of it, PROBED LIVE on Server 2022 (10.0.20348):
//
// - Add-DnsClientNrptRule has NO -DohTemplate / -AutoUpgrade parameters
// there (they arrived with NRPT DoH on Windows 11 24H2 / Server 2025);
// passing them is a hard ParameterBindingException. On such builds the
// per-address Add-DnsClientDohServerAddress registration (which DOES
// carry -DohTemplate/-AutoUpgrade on 20348) stays the encryption anchor.
// - Reset-DnsClientServerAddress does not exist there at all; the
// documented universal form is
// `Get-DnsClient | Set-DnsClientServerAddress -ResetServerAddresses`.
//
// The applier probes the running build once and rewrites ONLY the affected
// lines, so one rendered plan applies cleanly across builds (liberal in what
// we accept - the OS build - conservative in what we execute). Everything
// here is pure and table-tested; the build-tagged applier just wires it up.

// winCaps are the probed DNS-client capabilities of the running Windows build.
type winCaps struct {
	NrptDoh     bool // Add-DnsClientNrptRule takes -DohTemplate/-AutoUpgrade
	ResetCmdlet bool // Reset-DnsClientServerAddress exists
}

// winCapsProbeScript emits one parseable line, e.g. "nrpt-doh=False;reset-cmdlet=False".
const winCapsProbeScript = `$nrpt = Get-Command Add-DnsClientNrptRule -ErrorAction SilentlyContinue
$hasTpl = ($null -ne $nrpt) -and $nrpt.Parameters.ContainsKey('DohTemplate')
$hasReset = $null -ne (Get-Command Reset-DnsClientServerAddress -ErrorAction SilentlyContinue)
Write-Output ("nrpt-doh=" + $hasTpl + ";reset-cmdlet=" + $hasReset)
`

// parseWinCaps reads the probe output; anything unrecognisable degrades to
// "assume the capability is missing" (the adaptation is always safe to apply).
func parseWinCaps(out string) winCaps {
	var c winCaps
	for _, kv := range strings.Split(strings.TrimSpace(out), ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		val := strings.EqualFold(strings.TrimSpace(v), "true")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "nrpt-doh":
			c.NrptDoh = val
		case "reset-cmdlet":
			c.ResetCmdlet = val
		}
	}
	return c
}

var (
	// The two NRPT-DoH parameters, with their arguments, on a cmdlet call. A
	// PowerShell single-quoted string doubles embedded quotes: '([^']|'')*'.
	winNrptDohTemplateArg = regexp.MustCompile(`(?i)\s+-DohTemplate\s+(?:'(?:[^']|'')*'|[^\s']+)`)
	winNrptAutoUpgradeArg = regexp.MustCompile(`(?i)\s+-AutoUpgrade(?:\s+\$(?:true|false))?\b`)
)

// adaptWinScript rewrites a rendered PowerShell plan for the probed build.
// With full capabilities it returns the script unchanged.
func adaptWinScript(script string, caps winCaps) string {
	if !caps.ResetCmdlet {
		script = strings.ReplaceAll(script,
			"Get-NetAdapter | Reset-DnsClientServerAddress",
			"Get-DnsClient | Set-DnsClientServerAddress -ResetServerAddresses")
	}
	if caps.NrptDoh {
		return script
	}
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		// Strip the unsupported parameters from NRPT lines ONLY; the
		// Add/Set-DnsClientDohServerAddress registrations keep theirs (they
		// exist on every DoH-capable build and stay the encryption anchor).
		if !strings.Contains(line, "Add-DnsClientNrptRule") {
			continue
		}
		line = winNrptDohTemplateArg.ReplaceAllString(line, "")
		line = winNrptAutoUpgradeArg.ReplaceAllString(line, "")
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// winWrapScript hardens a rendered plan for unattended execution: any failing
// step terminates the script with a non-zero exit instead of running on.
func winWrapScript(script string) string {
	return "$ErrorActionPreference = 'Stop'\n" + script
}

// winElevationProbeScript exits 0 only in an elevated shell (the server
// WIN_TEMPLATE's guard, as a probe).
const winElevationProbeScript = `$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }
`

// winVerifyScript exits 0 once the system resolver answers (bounded: 5 tries,
// 2s apart). [System.Net.Dns] goes through the OS resolver, so it honours
// NRPT rules and adapter DNS alike - exactly what the apply changed. Two
// deliberate choices make the probe PROVE resolution rather than assume it:
// the cache is cleared first (a cached answer would pass even with an
// unreachable resolver), and the name is one Whisper is NOT authoritative for
// (the ns boxes answer whisper.online authoritatively even to a client whose
// recursion they would refuse).
const winVerifyScript = `Clear-DnsClientCache -ErrorAction SilentlyContinue
$ok = $false
foreach ($i in 1..5) {
    try { [void][System.Net.Dns]::GetHostAddresses('example.com'); $ok = $true; break } catch { Start-Sleep -Seconds 2 }
}
if ($ok) { exit 0 } else { exit 1 }
`
