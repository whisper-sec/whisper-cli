# -----------------------------------------------------------------------------
# install.ps1 — the ONE Whisper installer (Windows).
#
#   irm get.whisper.online/install.ps1 | iex
#   irm get.whisper.online | iex                 # bare form works too (UA-detected)
#
# This is the SAME installer that get.whisper.online serves — published here, in the
# public whisper-cli repo, so the entire install path is inspectable. By default it
# fetches the SIGNED whisper.exe straight from this repo's GitHub Releases:
#
#   https://github.com/whisper-sec/whisper-cli/releases/latest/download/whisper-windows-<arch>.exe
#
# Mirrors install.sh: get the right whisper.exe onto disk (sha256-VERIFIED, atomic,
# and PGP-checked when gpg is present), put it on the USER PATH (no admin), then run
# `whisper` (the guided flow owns the rest). On ANY failure it prints ONE friendly
# sentence — never a PowerShell stack trace. Requires nothing but PowerShell 5+.
#
# Output contract: mirror POSIX — two lines, then run whisper:
#     whisper: installing…
#     whisper: installed (run: whisper)
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
# Ensure TLS 1.2+ (older .NET defaults to TLS 1.0). Tls13 may be absent on .NET 4.x,
# so OR it in only when the enum value exists — never fail the install over the enum.
try {
    $proto = [Net.SecurityProtocolType]::Tls12
    if ([enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
        $proto = $proto -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $proto
} catch { }

function Say($msg) { [Console]::Error.WriteLine("whisper: $msg") }

try {
    Say 'installing…'

    # --- defaults (overridable via env; zero-config by default) ------------------
    # DEFAULT = this repo's GitHub Releases ("latest"), so the install is public,
    # signed and verifiable. The box can still serve as a fallback mirror via
    # WHISPER_CLI_BASE.
    $cliBase = if ($env:WHISPER_CLI_BASE) { $env:WHISPER_CLI_BASE } else { 'https://github.com/whisper-sec/whisper-cli/releases/latest/download' }
    # The AS219419 release-signing key fingerprint + where its public key is published.
    $pgpFpr    = if ($env:WHISPER_PGP_FPR) { $env:WHISPER_PGP_FPR } else { 'EFF1663D992539682106A5EAD0F70908CF3B7929' }
    $pgpKeyUrl = if ($env:WHISPER_PGP_KEY_URL) { $env:WHISPER_PGP_KEY_URL } else { 'https://as219419.net/whisper-release.asc' }
    $destDir = Join-Path $env:LOCALAPPDATA 'Whisper\bin'
    $dest    = Join-Path $destDir 'whisper.exe'

    # --- arch detect (mirrors platforms.txt: windows-amd64 / windows-arm64) ------
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        'x86'   { throw '64-bit Windows is required — this looks like 32-bit Windows.' }
        default { throw "no Whisper binary for your CPU ($($env:PROCESSOR_ARCHITECTURE)) yet — tell us: hello@whisper.security" }
    }

    # --- download + verify + atomic install --------------------------------------
    $url = "$cliBase/whisper-windows-$arch.exe"
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $tmp = Join-Path $destDir ("whisper.exe.tmp." + [System.Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    } catch {
        throw "couldn't download the whisper binary — check your internet and try again."
    }
    # Fetch the checksum and verify BEFORE we trust it (conservative in what we run).
    $sumTmp = "$tmp.sha256"
    try {
        Invoke-WebRequest -Uri "$url.sha256" -OutFile $sumTmp -UseBasicParsing
    } catch {
        Remove-Item -Force $tmp, $sumTmp -ErrorAction SilentlyContinue
        throw "couldn't fetch the checksum to verify the download safely — try again."
    }
    $want = ((Get-Content -Raw $sumTmp).Trim() -split '\s+')[0].ToLower()
    $got  = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    Remove-Item -Force $sumTmp -ErrorAction SilentlyContinue
    if ($want -ne $got) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        throw "the download didn't verify (checksum mismatch) — refusing to install. Try again."
    }

    # --- best-effort PGP verify of the .asc detached signature -------------------
    # sha256 is the HARD gate above. The PGP check is an EXTRA layer proving the bytes
    # were signed by the AS219419 release key — but it is FAIL-SOFT: if gpg is absent,
    # or the .asc isn't published, or the key can't be fetched, we warn and continue.
    # A signature that IS present but does NOT verify is fatal (refuse).
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if ($gpg) {
        $ascTmp = "$tmp.asc"
        $haveAsc = $false
        try { Invoke-WebRequest -Uri "$url.asc" -OutFile $ascTmp -UseBasicParsing; $haveAsc = $true } catch { }
        if ($haveAsc) {
            $gnupgHome = Join-Path ([System.IO.Path]::GetTempPath()) ("whisper-gpg-" + [System.Guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force -Path $gnupgHome | Out-Null
            $keyTmp = Join-Path $gnupgHome 'whisper-release.asc'
            $keyOk = $false
            try { Invoke-WebRequest -Uri $pgpKeyUrl -OutFile $keyTmp -UseBasicParsing; $keyOk = $true } catch { }
            if ($keyOk) {
                $env:GNUPGHOME = $gnupgHome
                & $gpg.Source --batch --quiet --import $keyTmp 2>$null | Out-Null
                $status = & $gpg.Source --batch --status-fd 1 --verify $ascTmp $tmp 2>$null
                Remove-Item -Recurse -Force $gnupgHome -ErrorAction SilentlyContinue
                Remove-Item -Env:GNUPGHOME -ErrorAction SilentlyContinue
                if ($status -notmatch "VALIDSIG.*$pgpFpr") {
                    Remove-Item -Force $tmp, $ascTmp -ErrorAction SilentlyContinue
                    throw "the download's PGP signature did not verify against the AS219419 release key — refusing to install."
                }
            } else {
                Remove-Item -Recurse -Force $gnupgHome -ErrorAction SilentlyContinue
            }
            Remove-Item -Force $ascTmp -ErrorAction SilentlyContinue
        }
    }

    # Atomic-ish replace: Move-Item -Force over the destination.
    Move-Item -Force -Path $tmp -Destination $dest
    # Clear the Mark-of-the-Web so SmartScreen doesn't block first run.
    Unblock-File -Path $dest -ErrorAction SilentlyContinue

    # --- key handoff: a server-injected $env:WHISPER_KEY → %APPDATA%\whisper-ns\key
    if ($env:WHISPER_KEY) {
        $keyDir = Join-Path $env:APPDATA 'whisper-ns'
        New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
        # -NoNewline so the saved key is byte-for-byte what the binary expects.
        [System.IO.File]::WriteAllText((Join-Path $keyDir 'key'), $env:WHISPER_KEY)
    }

    # --- THE PATH FIX (Windows): append %LOCALAPPDATA%\Whisper\bin to the USER Path
    # (no admin), idempotently + deduped; broadcast WM_SETTINGCHANGE so NEW processes
    # see it; set the CURRENT process Path so the immediate `whisper` below works.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    $parts = $userPath -split ';' | Where-Object { $_ -ne '' }
    $already = $false
    foreach ($p in $parts) {
        if ($p.TrimEnd('\') -ieq $destDir.TrimEnd('\')) { $already = $true; break }
    }
    if (-not $already) {
        $newPath = if ($userPath.TrimEnd(';') -eq '') { $destDir } else { $userPath.TrimEnd(';') + ';' + $destDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        # Broadcast the environment change so already-open Explorer/new shells pick it up.
        try {
            if (-not ('Win32.NativeMethods' -as [type])) {
                Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@
            }
            $HWND_BROADCAST = [System.IntPtr]0xffff
            $WM_SETTINGCHANGE = 0x1a
            $result = [System.UIntPtr]::Zero
            [void][Win32.NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [System.UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
        } catch {
            # Broadcasting is best-effort — new terminals will still pick up the User Path.
        }
    }
    # Make THIS process see it now so the `whisper` call below resolves.
    if (($env:Path -split ';') -notcontains $destDir) { $env:Path = "$env:Path;$destDir" }

    Say 'installed ✓  (run: whisper)'
    Say 'on PATH for new terminals; running it now…'

    # --- hand off to the guided flow (by full path so it never depends on PATH) ---
    & $dest
}
catch {
    # ONE friendly sentence — never a PowerShell stack / ScriptStackTrace.
    Say ([string]$_.Exception.Message)
    exit 1
}
