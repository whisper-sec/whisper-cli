# -----------------------------------------------------------------------------
# install.ps1 - the ONE Whisper installer (Windows).
#
#   irm https://get.whisper.online/install.ps1 | iex
#   irm https://get.whisper.online | iex                 # bare form works too (UA-detected)
#
# This is the SAME installer that get.whisper.online serves - published here, in the
# public whisper-cli repo, so the entire install path is inspectable. By default it
# fetches the SIGNED whisper.exe from our own download endpoint, which is built from
# the same tree as the running service and so cannot lag behind it:
#
#   https://get.whisper.online/dl/windows-<arch>/whisper.exe
#
# To remove it again: irm https://get.whisper.online/uninstall.ps1 | iex
#
# Mirrors install.sh: get the right whisper.exe onto disk (sha256-VERIFIED, atomic,
# and PGP-checked against the pinned AS219419 release key when gpg is present; "the
# PGP layer" below says what each level proves), put it on the USER PATH (no admin), then run
# `whisper` (the guided flow owns the rest). On ANY failure it prints ONE friendly
# sentence - never a PowerShell stack trace. Requires nothing but PowerShell 5+.
#
# Output contract: mirror POSIX - two lines, then run whisper:
#     whisper: installing…
#     whisper: installed (run: whisper)
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
# Ensure TLS 1.2+ (older .NET defaults to TLS 1.0). Tls13 may be absent on .NET 4.x,
# so OR it in only when the enum value exists - never fail the install over the enum.
try {
    $proto = [Net.SecurityProtocolType]::Tls12
    if ([enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
        $proto = $proto -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $proto
} catch { }

function Say($msg) { [Console]::Error.WriteLine("whisper: $msg") }

# --- the PGP layer: what a download is checked against -------------------------
# Two levels, and every run ends at one of them:
#
#   sha256 only     whisper.exe matches the .sha256 published beside it. Both come from the
#                   same host over TLS, so this proves the bytes arrived intact and belong to
#                   that checksum. It does NOT prove who built them: anyone who controls that
#                   host controls both files.
#   sha256 + PGP    as above, and the detached .asc is exactly one good signature, made by the
#                   AS219419 release key whose primary fingerprint is pinned in this script
#                   ($pgpFpr below). That proves the bytes are the ones the holder of that key
#                   signed, wherever they came from. It does not prove the code is free of bugs,
#                   that this is the newest release, or anything about any other key.
#
# The pin is the only thing trusted. The public key is fetched from as219419.net, or from the
# gateway's copy if that is unreachable, and either copy is used only after its fingerprint is
# checked against the pin. Rotating the key changes the pin here and the published key together;
# an older copy of this script then finds a key that is not its pin, says so, and stops at the
# sha256 level. When the signature cannot be checked (no gpg, no .asc, no usable copy of the
# pinned key) the install continues at the sha256 level and prints one line saying so; when it
# CAN be checked and fails, the install is refused. install.sh runs the same checks.
#
# >>> pgp-layer
# Invoke-WhisperGpg: gpg with its stderr discarded and the exit code kept. Windows PowerShell
# 5.1 turns a native command's redirected stderr into errors, which 'Stop' makes fatal, and gpg
# writes its human-readable report to stderr on every run, so the preference is relaxed here only.
function Invoke-WhisperGpg {
    param([string]$Gpg, [string]$GnupgHome, [string[]]$GpgArgs)
    $ErrorActionPreference = 'Continue'
    $saved = $env:GNUPGHOME
    $env:GNUPGHOME = $GnupgHome
    try {
        $out = @(& $Gpg @GpgArgs 2>$null)
        $script:WhisperGpgExit = $LASTEXITCODE
        return ,$out
    } finally {
        if ($null -eq $saved) { Remove-Item -Path Env:GNUPGHOME -ErrorAction SilentlyContinue } else { $env:GNUPGHOME = $saved }
    }
}

# >>> pgp-status-predicate (PowerShell)
# The clauses of pgp_status_ok in install.sh, in the same order, over the same `gpg --status-fd`
# lines. Returns $null for the one good signature we expect, otherwise the reason. Fields are
# compared whole and case-sensitively, never as a regex over the line: GnuPG exits 0 on a signature
# by an EXPIRED key and prints VALIDSIG beside EXPKEYSIG, and a .asc can carry a stranger's
# signature beside a good one.
function Test-WhisperPgpStatus {
    param([string[]]$Lines, [int]$ExitCode, [string]$Fpr)
    $count = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $validsig = $null
    foreach ($line in @($Lines)) {
        $f = @(([string]$line).Trim() -split '\s+')
        if ($f.Count -lt 2 -or $f[0] -cne '[GNUPG:]') { continue }
        if ($count.ContainsKey($f[1])) { $count[$f[1]] += 1 } else { $count[$f[1]] = 1 }
        if ($f[1] -ceq 'VALIDSIG') { $validsig = $f }
    }
    foreach ($tok in @('BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY', 'NODATA', 'KEYEXPIRED', 'KEYREVOKED')) {
        if ($count.ContainsKey($tok)) { return "gpg reports $tok" }
    }
    if ($ExitCode -ne 0) { return "gpg exited $ExitCode" }
    foreach ($tok in @('NEWSIG', 'GOODSIG', 'VALIDSIG')) {
        $n = 0
        if ($count.ContainsKey($tok)) { $n = $count[$tok] }
        if ($n -ne 1) {
            if ($tok -ceq 'NEWSIG') { return "the signature file carries $n signatures, expected exactly one" }
            return "$n $tok lines, expected exactly one"
        }
    }
    $primary = $validsig[$validsig.Count - 1]
    $class = $validsig[$validsig.Count - 2]
    if ($primary -cne $Fpr) { return "signed by primary key $primary, not $Fpr" }
    if ($class -cne '00') { return "signature class $class, expected 00 (a binary detached signature)" }
    return $null
}
# <<< pgp-status-predicate

# Import-WhisperPinnedKey: fetch the key at $Url into a fresh private keyring and keep it only if
# that keyring then holds exactly one primary key, the pinned one. Returns $null when it does,
# otherwise the reason. Never touches the user's own keyring.
function Import-WhisperPinnedKey {
    param([string]$Gpg, [string]$GnupgHome, [string]$Url, [string]$Fpr)
    Remove-Item -Recurse -Force $GnupgHome -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $GnupgHome | Out-Null
    $keyFile = Join-Path $GnupgHome 'release-key.asc'
    try { Invoke-WebRequest -Uri $Url -OutFile $keyFile -UseBasicParsing } catch { return "couldn't fetch the release key from $Url" }
    $null = Invoke-WhisperGpg -Gpg $Gpg -GnupgHome $GnupgHome -GpgArgs @('--batch', '--quiet', '--import', $keyFile)
    if ($script:WhisperGpgExit -ne 0) { return "couldn't import the release key from $Url" }
    $colons = Invoke-WhisperGpg -Gpg $Gpg -GnupgHome $GnupgHome -GpgArgs @('--batch', '--with-colons', '--fingerprint')
    $primaries = @()
    $afterPub = $false
    foreach ($row in $colons) {
        $c = ([string]$row).Split(':')
        if ($c[0] -ceq 'pub') { $afterPub = $true; continue }
        if ($afterPub -and $c[0] -ceq 'fpr') { $primaries += $c[9]; $afterPub = $false }
    }
    $held = $primaries -join ' '
    if ($held -cne $Fpr) {
        if (-not $held) { $held = 'no key' }
        return "the key served at $Url is $held, not the pinned release key $Fpr"
    }
    return $null
}

# Invoke-WhisperPgpCheck: the PGP layer for one downloaded file. Returns normally when the
# signature verified or could not be checked (one line says which); throws when a signature that
# could be checked is not the one good signature we expect.
function Invoke-WhisperPgpCheck {
    param([string]$File, [string]$Url, [string]$Fpr, [string]$KeyUrl, [string]$KeyFallback)
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if (-not $gpg) {
        Say 'verified the sha256 checksum only: gpg is not installed, so the PGP signature was not checked'
        return
    }
    $asc = "$File.asc"
    try { Invoke-WebRequest -Uri "$Url.asc" -OutFile $asc -UseBasicParsing } catch {
        Remove-Item -Force $asc -ErrorAction SilentlyContinue
        Say 'verified the sha256 checksum only: the PGP signature could not be fetched, so it was not checked'
        return
    }
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("whisper-gpg-" + [System.Guid]::NewGuid().ToString('N'))
    try {
        $gpgHome = Join-Path $root 'primary'
        $why = Import-WhisperPinnedKey -Gpg $gpg.Source -GnupgHome $gpgHome -Url $KeyUrl -Fpr $Fpr
        if ($why -and $KeyFallback) {
            $gpgHome = Join-Path $root 'fallback'
            $why2 = Import-WhisperPinnedKey -Gpg $gpg.Source -GnupgHome $gpgHome -Url $KeyFallback -Fpr $Fpr
            if ($why2) { $why = "$why; $why2" } else { $why = $null }
        }
        if ($why) {
            Say "verified the sha256 checksum only: $why, so the PGP signature was not checked"
            return
        }
        $status = Invoke-WhisperGpg -Gpg $gpg.Source -GnupgHome $gpgHome -GpgArgs @('--batch', '--status-fd', '1', '--verify', $asc, $File)
        $why = Test-WhisperPgpStatus -Lines $status -ExitCode $script:WhisperGpgExit -Fpr $Fpr
        if ($why) {
            Remove-Item -Force $File -ErrorAction SilentlyContinue
            throw "the download's PGP signature did not verify against the AS219419 release key ($why) - refusing to install."
        }
    } finally {
        Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
        Remove-Item -Force $asc -ErrorAction SilentlyContinue
    }
}
# <<< pgp-layer

try {
    Say 'installing…'

    # --- defaults (overridable via env; zero-config by default) ------------------
    # DEFAULT = our own /dl. GitHub "latest" only moves when a person pushes a
    # tag, so it sat at v0.210.1 for eight days while /dl served 0.211.0. /dl comes out
    # of the same build as the service we run, so it cannot drift. Both layouts accepted below.
    $cliBase = if ($env:WHISPER_CLI_BASE) { $env:WHISPER_CLI_BASE } else { 'https://get.whisper.online/dl' }
    # Normalise the base exactly as install.sh does (Postel: liberal in what we accept).
    # Someone who exports WHISPER_CLI_BASE reaches for the HOST they know
    # (https://cli.whisper.online), not that host plus the /dl path segment.
    #
    # It is not a cosmetic nicety. Without /dl the request lands on the site catch-all,
    # which answers 200 with the install SCRIPT, so we would save a shell script as
    # whisper.exe, fetch the same script again as its .sha256, and fail with "checksum
    # mismatch" - a confusing error for what is really a wrong URL. The sha256 gate
    # catches it either way; a clear URL beats a caught mistake.
    $cliBase = $cliBase.TrimEnd('/')
    if ($cliBase -notmatch 'github\.com|releases/(download|latest)' -and $cliBase -notmatch '/dl$') {
        $cliBase = "$cliBase/dl"
    }
    # The AS219419 release-signing key fingerprint + where its public key is published.
    $pgpFpr    = if ($env:WHISPER_PGP_FPR) { $env:WHISPER_PGP_FPR } else { 'EFF1663D992539682106A5EAD0F70908CF3B7929' }
    $pgpKeyUrl = if ($env:WHISPER_PGP_KEY_URL) { $env:WHISPER_PGP_KEY_URL } else { 'https://as219419.net/whisper-release.asc' }
    # The gateway's copy of the same key, used only if as219419.net is unreachable, and only after
    # its fingerprint is checked against the pin (see the PGP layer above).
    $pgpKeyFallback = if ($env:WHISPER_PGP_KEY_FALLBACK) { $env:WHISPER_PGP_KEY_FALLBACK } else { 'https://cli.whisper.online/dl/whisper-pgp.asc' }
    # Replacing the pin turns it into a suggestion, so WHISPER_PGP_FPR is refused unless
    # WHISPER_INSTALL_UNSAFE_KEY=1 is set as well, and then every run says the key is not ours.
    if ($env:WHISPER_PGP_FPR) {
        if ($env:WHISPER_INSTALL_UNSAFE_KEY -ne '1') {
            throw "WHISPER_PGP_FPR would replace the pinned release key, so it is refused: unset it, or also set WHISPER_INSTALL_UNSAFE_KEY=1 to install against a key that is not Whisper's."
        }
        Say "WARNING: running with an UNPINNED release key ($pgpFpr, from WHISPER_PGP_FPR): a passing signature check proves only that this key signed the download, not that Whisper did."
    }
    $destDir = Join-Path $env:LOCALAPPDATA 'Whisper\bin'
    $dest    = Join-Path $destDir 'whisper.exe'

    # --- arch detect (mirrors platforms.txt: windows-amd64 / windows-arm64) ------
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        'x86'   { throw '64-bit Windows is required - this looks like 32-bit Windows.' }
        default { throw "no Whisper binary for your CPU ($($env:PROCESSOR_ARCHITECTURE)) yet - tell us: hello@whisper.security" }
    }

    # --- download + verify + atomic install --------------------------------------
    # TWO layouts exist and we accept either (see the note on $cliBase above):
    #   our /dl        <base>/windows-<arch>/whisper.exe
    #   a GH release   <base>/whisper-windows-<arch>.exe
    # Both put .sha256 and .asc beside the binary, so the fetches below are unchanged.
    $url = if ($cliBase -match 'github\.com|releases/(download|latest)') {
        "$cliBase/whisper-windows-$arch.exe"
    } else {
        "$cliBase/windows-$arch/whisper.exe"
    }
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $tmp = Join-Path $destDir ("whisper.exe.tmp." + [System.Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    } catch {
        throw "couldn't download the whisper binary - check your internet and try again."
    }
    # Fetch the checksum and verify BEFORE we trust it (conservative in what we run).
    $sumTmp = "$tmp.sha256"
    try {
        Invoke-WebRequest -Uri "$url.sha256" -OutFile $sumTmp -UseBasicParsing
    } catch {
        Remove-Item -Force $tmp, $sumTmp -ErrorAction SilentlyContinue
        throw "couldn't fetch the checksum to verify the download safely - try again."
    }
    $want = ((Get-Content -Raw $sumTmp).Trim() -split '\s+')[0].ToLower()
    $got  = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    Remove-Item -Force $sumTmp -ErrorAction SilentlyContinue
    if ($want -ne $got) {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
        throw "the download didn't verify (checksum mismatch) - refusing to install. Try again."
    }

    # --- the PGP layer (see "the PGP layer" at the top): sha256 above is the HARD gate;
    # this checks the detached signature against the pinned key when it can, says so in one
    # line when it cannot, and refuses when a signature it could check is not the good one.
    Invoke-WhisperPgpCheck -File $tmp -Url $url -Fpr $pgpFpr -KeyUrl $pgpKeyUrl -KeyFallback $pgpKeyFallback

    # Atomic-ish replace: Move-Item -Force over the destination.
    Move-Item -Force -Path $tmp -Destination $dest
    # Clear the Mark-of-the-Web so SmartScreen doesn't block first run.
    Unblock-File -Path $dest -ErrorAction SilentlyContinue

    # --- key handoff: a server-injected $env:WHISPER_KEY -> the key file the BINARY reads.
    # That file is $HOME\.config\whisper\key on EVERY platform: client.DefaultKeyFile() is
    # os.UserHomeDir() + .config/whisper/key with no Windows branch, and os.UserHomeDir() on
    # Windows is %USERPROFILE%. This used to write %APPDATA%\whisper-ns\key, which nothing has
    # ever read - wrong base AND the pre-2026-08 directory name - so the zero-prompt install
    # asked a Windows user to log in anyway, with their key already on disk.
    if ($env:WHISPER_KEY) {
        $home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
        $keyDir = Join-Path (Join-Path $home_ '.config') 'whisper'
        New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
        # -NoNewline semantics: the saved key is byte-for-byte what the binary expects.
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
            # Broadcasting is best-effort - new terminals will still pick up the User Path.
        }
    }
    # Make THIS process see it now so the `whisper` call below resolves.
    if (($env:Path -split ';') -notcontains $destDir) { $env:Path = "$env:Path;$destDir" }

    Say 'installed ✓  (run: whisper)'

    # --- optional host sensor, same opt-in as POSIX (WHISPER_SENSOR=1) ------------
    # Parity with install.sh, which has had this from the start: an RMM or an MDM that
    # sets one environment variable gets a managed endpoint with no second step and
    # no Terminal session. It runs the very SAME command a human would, through the
    # binary just installed, so the two routes cannot drift. Installing a Windows
    # service needs an elevated session; when the shell is not elevated we say the
    # one command that finishes the job instead of failing the whole install.
    if ($env:WHISPER_SENSOR -and $env:WHISPER_SENSOR -notin @('0', 'no', 'false', 'off')) {
        $sensorOk = $false
        try {
            $null = & $dest service install --now --sensor 2>&1
            $sensorOk = ($LASTEXITCODE -eq 0)
        } catch { $sensorOk = $false }
        if ($sensorOk) {
            Say 'sensor service installed + running (whisper-sensor)'
        } else {
            Say 'couldn''t enable the sensor service - whisper is installed; from an elevated PowerShell run: whisper service install --now --sensor'
        }
    }

    Say 'on PATH for new terminals; running it now…'

    # --- hand off to the guided flow (by full path so it never depends on PATH) ---
    & $dest
}
catch {
    # ONE friendly sentence - never a PowerShell stack / ScriptStackTrace.
    Say ([string]$_.Exception.Message)
    exit 1
}
