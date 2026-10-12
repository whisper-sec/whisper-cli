#!/bin/sh
# -----------------------------------------------------------------------------
# install.sh - the ONE Whisper installer (POSIX).   curl -fsSL https://get.whisper.online | sh
#
#   curl -H "X-API-Key: whisper_live_xxx" https://get.whisper.online | sh   # zero prompts
#   curl https://get.whisper.online | sh -s -- whisper_live_xxx              # key as first arg
#   curl https://get.whisper.online | sh                                     # then: whisper
#
# This is the SAME installer that get.whisper.online serves - it is published here,
# in the public whisper-cli repo, so the entire install path is inspectable. By
# default it fetches the SIGNED binary from our own download endpoint, which is built
# from the same tree as the running service and so cannot lag behind it:
#
#   https://get.whisper.online/dl/<os>-<arch>/whisper
#
# To remove it again: curl -fsSL https://get.whisper.online/uninstall | sh
#
# Its job is SMALL and it does exactly three things, then hands off to the binary:
#   1. get the right `whisper` binary onto disk, sha256-VERIFIED (and PGP-checked
#      against the pinned AS219419 release key when gpg is present; "the PGP layer"
#      below says what each level proves), atomically;
#   2. put it on PATH for real - future shells (rc files) AND this one (live PATH);
#   3. exec `whisper` (the guided flow owns login / agent / connect / verify).
#
# No tiers, no proxychains, no package manager, no python3, no DoH prose - `connect`
# is the binary's job. Requires only: curl (or wget) + sh + a sha256 tool.
#
# Output contract: ALL status to stderr, prefixed `whisper: `. Happy path = at most
# two lines, then it hands off:
#     whisper: installing…
#     whisper: installed ✓  (run: whisper)
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
# -----------------------------------------------------------------------------
set -eu

# --- output: every line to stderr, prefixed; the door speaks plain language ------
say()  { printf 'whisper: %s\n' "$*" >&2; }
# die: ONE friendly sentence, then exit 1. The only fatal on this path is "no key";
# everything else degrades. Never a stack trace, never a wall of text.
die()  { printf 'whisper: %s\n' "$*" >&2; exit 1; }
vsay() { if [ "${VERBOSE:-0}" = "1" ]; then printf 'whisper: %s\n' "$*" >&2; fi; }

# --- defaults (all overridable; zero-config by default) --------------------------
# CLI_BASE is where the binary + sha256 + asc live. DEFAULT = our own /dl, which comes
# out of the same build as the service we run.
#
# It used to default to this repo's GitHub Releases "latest", and that was the bug. That
# pointer only moves when a person pushes a vX.Y.Z tag, so it sat at v0.210.1 for eight
# days while /dl served 0.211.0, and everyone following our own documented one-liner got
# a stale CLI. It was not only a version number: 0.210.1 predates the darwin collectors,
# so every Mac user who followed our instructions got a sensor that collects nothing on
# their machine. /dl is produced by the same build as the service we run, so it cannot
# drift from what we are actually running.
#
# Both URL shapes are accepted (see asset_url), so exporting WHISPER_CLI_BASE at a GitHub
# release base still works as a fallback mirror. Liberal in what we accept.
CLI_BASE="${WHISPER_CLI_BASE:-https://get.whisper.online/dl}"
# The AS219419 release-signing key: its primary fingerprint (THE PIN, the one thing the PGP check
# trusts) and where its public key is published.
PGP_FPR="${WHISPER_PGP_FPR:-EFF1663D992539682106A5EAD0F70908CF3B7929}"
PGP_KEY_URL="${WHISPER_PGP_KEY_URL:-https://as219419.net/whisper-release.asc}"
# A second place to fetch the same public key when as219419.net is unreachable. It is served by
# the same gateway that serves the binary, so on its own it would prove nothing; it is only ever
# used after its fingerprint is checked against the pin above, which makes it a carrier for the
# pinned key's bytes and nothing more. The same check applies to the as219419.net copy.
PGP_KEY_FALLBACK="${WHISPER_PGP_KEY_FALLBACK:-https://cli.whisper.online/dl/whisper-pgp.asc}"
# Replacing the pin turns it into a suggestion: anything that can set this script's environment
# could point it at any key. So WHISPER_PGP_FPR is refused unless WHISPER_INSTALL_UNSAFE_KEY=1 is
# set as well, and then the run says, every time, that the key it checks against is not ours.
if [ -n "${WHISPER_PGP_FPR:-}" ]; then
  if [ "${WHISPER_INSTALL_UNSAFE_KEY:-0}" != "1" ]; then
    die "WHISPER_PGP_FPR would replace the pinned release key, so it is refused: unset it, or also set WHISPER_INSTALL_UNSAFE_KEY=1 to install against a key that is not Whisper's."
  fi
  say "WARNING: running with an UNPINNED release key ($PGP_FPR, from WHISPER_PGP_FPR): a passing signature check proves only that this key signed the download, not that Whisper did."
fi
# Resolved AFTER flag parsing (see below), so --dir and WHISPER_DIR still win. Empty here
# means "nobody has chosen yet".
DEST_DIR="${WHISPER_DIR:-}"
NO_PATH=0
FORCE_SHELL=""
ARG_KEY=""

# --- flags (liberal: any order; unknown ⇒ warn+ignore; first bare token = key) ---
# Every read/shift is guarded - a trailing `--dir` with no value must NOT `shift 2`
# past the end (a fatal error under `set -eu` in dash). Degrade, never crash.
while [ $# -gt 0 ]; do
  case "$1" in
    --key)        if [ $# -ge 2 ]; then ARG_KEY="$2"; shift 2; else shift; fi ;;
    --key=*)      ARG_KEY="${1#--key=}"; shift ;;
    --dir)        if [ $# -ge 2 ]; then DEST_DIR="$2"; shift 2; else shift; fi ;;
    --dir=*)      DEST_DIR="${1#--dir=}"; shift ;;
    --no-path)    NO_PATH=1; shift ;;
    --shell)      if [ $# -ge 2 ]; then FORCE_SHELL="$2"; shift 2; else shift; fi ;;
    --shell=*)    FORCE_SHELL="${1#--shell=}"; shift ;;
    --verbose)    VERBOSE=1; shift ;;
    --shell-cli)  shift ;;   # accepted + ignored: clean-slate has no POSIX-shell CLI
    --)           shift ;;
    -*)           say "ignoring unknown flag: $1"; shift ;;
    *)            [ -n "$ARG_KEY" ] || ARG_KEY="$1"; shift ;;
  esac
done

# --- where the binary lands -----------------------------------------------
# ROOT GETS A SYSTEM PATH. The Tier-1 host sensor is installed by root by necessity, and
# $HOME/.local/bin is /root/.local/bin, which is on no default PATH on Debian or RHEL. The
# installer was honest about that and printed an export line, but the export line IS the extra
# step: the next command an evaluator types is `whisper version`, and it failed.
#
# It also decided where the systemd unit points. A SYSTEM service with
# ExecStart=/root/.local/bin/whisper is fragile in ways that do not show on install day: /root
# may be a separate mount that is not up when the unit starts, a re-provisioned root home wipes
# the binary while the unit survives, and any hardening that sets ProtectHome= breaks it.
#
# So root defaults to /usr/local/bin - on PATH everywhere, in sudo's secure_path, and the
# conventional home for locally installed system binaries. An unprivileged user keeps
# $HOME/.local/bin, which is right and writable for them. An explicit --dir or WHISPER_DIR still
# wins for both, and if /usr/local/bin is somehow not writable we fall back rather than fail:
# the door never refuses to open.
if [ -z "$DEST_DIR" ]; then
  _euid=$(id -u 2>/dev/null || echo 1)
  if [ "$_euid" = 0 ] && mkdir -p /usr/local/bin 2>/dev/null && [ -w /usr/local/bin ]; then
    DEST_DIR=/usr/local/bin
  else
    DEST_DIR="$HOME/.local/bin"
  fi
fi

DEST="$DEST_DIR/whisper"

# --- require curl or wget, and a sha256 tool ------------------------------------
DL=""
if command -v curl >/dev/null 2>&1; then DL=curl
elif command -v wget >/dev/null 2>&1; then DL=wget
else die "needs curl or wget to download - install one and re-run."; fi

# --- ORIGIN PINNING -------------------------------------------------------
# An install reads THREE files from the download host: the binary, its .sha256 and its
# .asc. The download host has more than one origin and deploys roll one at a time, so
# a run can straddle two builds: for the length of every rollout, two origins serve
# different CLI builds, and nothing bound our three requests to one of them.
#
# A run that straddles them gets the binary from one origin and the signature from
# another. That is not a soft failure: sha256 says "checksum mismatch", and gpg says BAD
# signature and we refuse the install, with a message that reads like tampering when
# the truth is that we asked two different machines the same question. It is
# intermittent and depends only on where each request lands.
#
# So the three fetches are made one conversation with ONE origin. It costs no extra round
# trip: the binary download already tells us which address served it (curl's
# %{remote_ip}), and every later fetch is sent back to that address with --resolve.
#
# ORIGIN_PIN holds that curl argument, or is empty when we could not or should not
# pin. Empty means "behave exactly as before", which is what happens under wget (no
# --resolve), behind a redirect to another host (GitHub release assets 302 to a CDN,
# and those are immutable, so they cannot straddle anything), or if curl reports no
# address. The one case a pin can turn a success into a failure is an origin that dies
# in the second between our requests, and "couldn't fetch the checksum, try again" is the
# honest answer there.
ORIGIN_PIN=''

# url_hostport URL → "host:port", filling in the port the scheme implies.
url_hostport() {
  _rest="${1#*://}"; _hp="${_rest%%/*}"
  case "$_hp" in
    \[*)  printf '%s' "$_hp" ;;                     # IPv6 literal - left alone, see below
    *:*)  printf '%s' "$_hp" ;;
    *)    case "$1" in
            http://*) printf '%s:80'  "$_hp" ;;
            *)        printf '%s:443' "$_hp" ;;
          esac ;;
  esac
}

# fetch URL OUTFILE → 0 on a 2xx download, 1 otherwise (never throws). Postel: HTTPS is
# PINNED for production (the default get.whisper.online base is https - a real one-liner
# is always https, so a downgrade can't be forced on a user). We relax the pin ONLY when
# the URL is EXPLICITLY http:// - the only http base is a local/CI test gateway, by hand.
# GitHub release downloads 302-redirect to objects.githubusercontent.com, so we follow
# redirects (-L / wget default) while keeping every hop https.
# ORIGIN_PIN is deliberately unquoted: it is either empty (expands to no argument) or
# the two words `--resolve host:port:addr`.
fetch() {
  case "$1" in
    http://*)   # local / CI test gateway only - no TLS to pin
      # shellcheck disable=SC2086  # ORIGIN_PIN is empty or exactly `--resolve h:p:a`; the split is the point.
      if [ "$DL" = curl ]; then curl -fsSL ${ORIGIN_PIN} "$1" -o "$2"
      else                      wget -q -O "$2" "$1"; fi ;;
    *)          # https:// (production) and anything else - TLS-pinned
      # shellcheck disable=SC2086  # ORIGIN_PIN is empty or exactly `--resolve h:p:a`; the split is the point.
      if [ "$DL" = curl ]; then curl -fsSL --proto '=https' --tlsv1.2 ${ORIGIN_PIN} "$1" -o "$2"
      else                      wget -q --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"; fi ;;
  esac
}

# fetch_pinning URL OUTFILE → same contract as fetch(), and on success sets ORIGIN_PIN
# to the address that actually served THIS response, so every sidecar fetched
# afterwards comes from the same origin. Use it for the first file of a multi-file
# download; use plain fetch() for the rest.
fetch_pinning() {
  ORIGIN_PIN=''
  # wget has no --resolve, so there is nothing to pin with. Fetch normally: the sha256
  # gate still catches a straddle, it just reports it as a checksum mismatch.
  if [ "$DL" != curl ]; then fetch "$1" "$2"; return $?; fi
  case "$1" in
    http://*) _w="$(curl -fsSL -w '%{remote_ip} %{url_effective}' "$1" -o "$2" 2>/dev/null)" || return 1 ;;
    *)        _w="$(curl -fsSL --proto '=https' --tlsv1.2 -w '%{remote_ip} %{url_effective}' "$1" -o "$2" 2>/dev/null)" || return 1 ;;
  esac
  _ip="${_w%% *}"
  _asked="$(url_hostport "$1")"
  _served="$(url_hostport "${_w#* }")"
  # Only pin when the bytes came from the host we asked for. A redirect to a CDN must
  # never pin the original name to the CDN's address.
  [ -n "$_ip" ] && [ "$_asked" = "$_served" ] || return 0
  # An IPv6 literal in the URL is already a single machine; there is no name to pin.
  case "$_asked" in \[*) return 0 ;; esac
  case "$_ip" in
    *:*) ORIGIN_PIN="--resolve ${_asked%:*}:${_asked##*:}:[$_ip]" ;;
    *)   ORIGIN_PIN="--resolve ${_asked%:*}:${_asked##*:}:$_ip" ;;
  esac
  vsay "pinned the checksum and signature to the origin that served the binary ($_ip)"
  return 0
}
# sha256_of FILE → hex digest on stdout, or empty if no tool is available.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else printf ''; fi
}

# --- OS / arch detect (the SINGLE copy; mirrors platforms.txt) -------------------
detect_platform() {  # → sets OS + ARCH, or dies with a kind message
  _os="$(uname -s 2>/dev/null || echo unknown)"
  _arch="$(uname -m 2>/dev/null || echo unknown)"
  case "$_os" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *)      die "no Whisper binary for your system ($_os) yet - we ship Linux and macOS. Tell us: hello@whisper.security" ;;
  esac
  # The map mirrors platforms.txt exactly. The second half is the embedded/router
  # tier: 32-bit ARM, RISC-V, both MIPS endiannesses and legacy x86, which the
  # Tier-A packages (meta-whisper, buildroot, openwrt) are parametric over. Linux
  # reports MIPS endianness in `uname -m` itself (mips vs mipsel), so no probe is
  # needed. armv8l is a 32-bit userland on 64-bit silicon, so it takes the arm
  # binary, not arm64.
  case "$_arch" in
    x86_64|amd64)             ARCH=amd64 ;;
    aarch64|arm64)            ARCH=arm64 ;;
    armv7l|armv7|armv8l|arm)  ARCH=arm ;;
    riscv64)                  ARCH=riscv64 ;;
    mips)                     ARCH=mips ;;
    mipsel|mipsle)            ARCH=mipsle ;;
    i386|i486|i586|i686|x86)  ARCH=386 ;;
    armv[45]*|armv6*)
      # Our arm build is ARMv7 (Go's default GOARM=7), so an ARMv6 or older core
      # would take an illegal instruction. Say that, rather than hand it a binary
      # that dies at the first hard-float opcode.
      die "your CPU ($_arch) is older than ARMv7, and the Whisper arm binary is built for ARMv7 and up. Tell us what you are running: hello@whisper.security" ;;
    *)
      die "no Whisper binary for your CPU ($_arch) yet. We ship amd64, arm64, arm (ARMv7), riscv64, mips, mipsle and 386 on Linux, and amd64 + arm64 on macOS. Tell us: hello@whisper.security" ;;
  esac
  # The embedded tier is Linux-only: platforms.txt has no darwin-arm, darwin-mips
  # and so on, so a mac that somehow reported one of those arches would otherwise
  # be sent to a download path that cannot exist.
  case "$OS-$ARCH" in
    linux-*|darwin-amd64|darwin-arm64) : ;;
    *) die "no Whisper binary for $OS on $_arch yet. On macOS we ship amd64 and arm64. Tell us: hello@whisper.security" ;;
  esac
}

# --- the PGP layer: what a download is checked against ---------------------------
# Two levels, and every run ends at one of them:
#
#   sha256 only     the binary matches the .sha256 published beside it. Both come from the same
#                   host over TLS, so this proves the bytes arrived intact and that the binary and
#                   its checksum belong together (it catches corruption, truncation, and a fetch
#                   that straddled two builds mid-deploy). It does NOT prove who built them: anyone
#                   who controls that host controls both files.
#   sha256 + PGP    as above, and the detached .asc is exactly one good signature, made by the
#                   AS219419 release key whose primary fingerprint is pinned in this script
#                   (PGP_FPR, near the top). That proves the bytes are the ones the holder of that
#                   key signed, wherever they were downloaded from. It does not prove the code is
#                   free of bugs, that this is the newest release, or anything about a key other
#                   than the pinned one.
#
# The pin is the only thing trusted. The public key is fetched from as219419.net, or from the
# gateway's copy if that is unreachable, and either copy is used only after its fingerprint is
# checked against the pin, so a host that serves the binary cannot also serve a key that vouches
# for it. The predicate refuses a revoked or expired key, a second signature beside a good one,
# and a signature by any key but the pinned one (the status parse below, shared with the release
# path). Rotating the key changes the pin here and the published key together, in one release; an
# older copy of this script then finds a key that is not its pin, says so, and stops at the sha256
# level rather than trusting it.
#
# sha256 is the HARD gate: a mismatch is always fatal. When the signature cannot be checked (no
# gpg, no .asc could be fetched, no usable copy of the pinned key) the install continues at the sha256
# level and prints one line saying so. When it CAN be checked and fails, the install is refused.
# A full verification is silent on the happy path; --verbose says it happened.
#
# >>> pgp-status-predicate
# pgp_status_ok <status-file> <gpg-exit> <primary-fpr>: is this the one good signature we expect?
# <status-file> holds what `gpg --status-fd` wrote for one `gpg --verify`, and <gpg-exit> is that
# run's exit code. Prints the reason and returns 1 on refusal. Every clause is required:
#   - none of BADSIG ERRSIG EXPSIG EXPKEYSIG REVKEYSIG NO_PUBKEY NODATA KEYEXPIRED KEYREVOKED;
#   - gpg exited 0 (necessary, never sufficient: GnuPG 2.4.4 exits 0 on a signature by an EXPIRED
#     key and prints VALIDSIG beside EXPKEYSIG, which is why `grep VALIDSIG` is not a check);
#   - exactly one NEWSIG, one GOODSIG and one VALIDSIG (a .asc can carry two signatures, and one
#     good one beside a stranger's must not pass);
#   - VALIDSIG's last field, the PRIMARY key's fingerprint, equals <primary-fpr> as a whole field,
#     and the field before it, the signature class, is 00 (a binary document signature).
# TRUST_UNDEFINED is expected (the key is in nobody's web of trust here) and is not a refusal.
pgp_status_ok() {
    _ps_file="$1"; _ps_rc="$2"; _ps_fpr="$3"
    for _ps_tok in BADSIG ERRSIG EXPSIG EXPKEYSIG REVKEYSIG NO_PUBKEY NODATA KEYEXPIRED KEYREVOKED; do
        if awk -v t="$_ps_tok" '$1 == "[GNUPG:]" && $2 == t { f = 1 } END { exit !f }' "$_ps_file"; then
            echo "gpg reports $_ps_tok"; return 1
        fi
    done
    if [ "$_ps_rc" -ne 0 ]; then echo "gpg exited $_ps_rc"; return 1; fi
    for _ps_tok in NEWSIG GOODSIG VALIDSIG; do
        _ps_n="$(awk -v t="$_ps_tok" '$1 == "[GNUPG:]" && $2 == t { n++ } END { print n + 0 }' "$_ps_file")"
        if [ "$_ps_n" != 1 ]; then
            if [ "$_ps_tok" = NEWSIG ]; then
                echo "the signature file carries $_ps_n signatures, expected exactly one"
            else
                echo "$_ps_n $_ps_tok lines, expected exactly one"
            fi
            return 1
        fi
    done
    _ps_primary="$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $NF }' "$_ps_file")"
    _ps_class="$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $(NF - 1) }' "$_ps_file")"
    [ "$_ps_primary" = "$_ps_fpr" ] || { echo "signed by primary key $_ps_primary, not $_ps_fpr"; return 1; }
    [ "$_ps_class" = 00 ] || { echo "signature class $_ps_class, expected 00 (a binary detached signature)"; return 1; }
    return 0
}
# <<< pgp-status-predicate

# pgp_import_pinned URL GNUPGHOME → 0 when the key fetched from URL, imported into a fresh private
# keyring, is exactly the pinned key: one primary, and its fingerprint is PGP_FPR. Otherwise sets
# _why and returns 1. Never touches the user's own ~/.gnupg.
pgp_import_pinned() {
  rm -rf "$2" 2>/dev/null || true
  if ! mkdir -p "$2" 2>/dev/null || ! chmod 700 "$2" 2>/dev/null; then
    _why="couldn't create a private keyring"; return 1
  fi
  if ! fetch "$1" "$2/release-key.asc" 2>/dev/null; then
    _why="couldn't fetch the release key from $1"; return 1
  fi
  if ! GNUPGHOME="$2" gpg --batch --quiet --import "$2/release-key.asc" >/dev/null 2>&1; then
    _why="couldn't import the release key from $1"; return 1
  fi
  _pk="$(GNUPGHOME="$2" gpg --batch --with-colons --fingerprint 2>/dev/null \
         | awk -F: '$1 == "pub" { w = 1; next } w && $1 == "fpr" { printf "%s%s", s, $10; s = " "; w = 0 }')"
  if [ "$_pk" != "$PGP_FPR" ]; then
    _why="the key served at $1 is ${_pk:-no key}, not the pinned release key $PGP_FPR"; return 1
  fi
  return 0
}

# pgp_verify FILE URL → 0 when verified, or when the signature could not be checked (one line says
# which); dies when a signature that could be checked is not the one good signature we expect.
pgp_verify() {
  _bin="$1"; _asc="$1.asc"
  if ! command -v gpg >/dev/null 2>&1; then
    say "verified the sha256 checksum only: gpg is not installed, so the PGP signature was not checked"
    return 0
  fi
  if ! fetch "$2.asc" "$_asc" 2>/dev/null; then
    rm -f "$_asc" 2>/dev/null || true
    say "verified the sha256 checksum only: the PGP signature could not be fetched, so it was not checked"
    return 0
  fi
  _root="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/whisper-gpg.$$")"
  mkdir -p "$_root" 2>/dev/null || true
  chmod 700 "$_root" 2>/dev/null || true
  _home=""
  if pgp_import_pinned "$PGP_KEY_URL" "$_root/primary"; then
    _home="$_root/primary"
  else
    _why1="$_why"
    if [ -n "$PGP_KEY_FALLBACK" ] && pgp_import_pinned "$PGP_KEY_FALLBACK" "$_root/fallback"; then
      _home="$_root/fallback"
      vsay "took the pinned release key from $PGP_KEY_FALLBACK ($_why1)"
    elif [ -n "$PGP_KEY_FALLBACK" ]; then
      _why1="$_why1; $_why"
    fi
  fi
  if [ -z "$_home" ]; then
    rm -rf "$_root" "$_asc" 2>/dev/null || true
    say "verified the sha256 checksum only: $_why1, so the PGP signature was not checked"
    return 0
  fi
  _rc=0
  GNUPGHOME="$_home" gpg --batch --status-fd 3 --verify "$_asc" "$_bin" 3>"$_root/status" >/dev/null 2>&1 || _rc=$?
  if _why="$(pgp_status_ok "$_root/status" "$_rc" "$PGP_FPR")"; then
    vsay "verified the sha256 checksum and the PGP signature (AS219419 release key $PGP_FPR)"
    rm -rf "$_root" "$_asc" 2>/dev/null || true
    return 0
  fi
  rm -rf "$_root" "$_asc" "$_bin" 2>/dev/null || true
  die "the download's PGP signature did not verify against the AS219419 release key ($_why) - refusing to install."
}

# asset_url OS ARCH -> the URL of that platform's binary on the configured base.
# TWO layouts exist and we accept either, so WHISPER_CLI_BASE works whichever kind of
# mirror it names (Postel: liberal in what we accept):
#   our /dl        <base>/<os>-<arch>/whisper      (also .sha256 / .asc beside it)
#   a GH release   <base>/whisper-<os>-<arch>      (flat, the release-asset naming)
# The caller appends .sha256 and .asc to whatever comes back, and both layouts put those
# sidecars next to the binary, so one rule covers all three fetches.
# Normalise the base before building a URL. A person who exports WHISPER_CLI_BASE
# reaches for the HOST they know (https://cli.whisper.online), not the host plus the
# /dl path segment, and being liberal in what we accept means that has to work.
#
# It is not a cosmetic nicety. Without /dl the request lands on the site's catch-all,
# which answers 200 with the install SCRIPT, so the installer downloads a shell script
# as the binary, downloads the same script as its .sha256, and fails with "checksum
# mismatch" - a confusing error for what is really a wrong URL. The sha256 gate caught
# it, which is the gate working, but a clear message beats a caught mistake.
normalise_base() {
  _b="${1%/}"
  case "$_b" in
    *github.com*|*releases/download*|*releases/latest*) printf '%s' "$_b" ;;
    */dl)                                              printf '%s' "$_b" ;;
    *)                                                 printf '%s/dl' "$_b" ;;
  esac
}
CLI_BASE="$(normalise_base "$CLI_BASE")"

asset_url() {
  case "$CLI_BASE" in
    *github.com*|*releases/download*|*releases/latest*)
      printf '%s/whisper-%s-%s' "$CLI_BASE" "$1" "$2" ;;
    *)
      printf '%s/%s-%s/whisper' "$CLI_BASE" "$1" "$2" ;;
  esac
}

# --- download + verify + atomic install -----------------------------------------
install_binary() {
  detect_platform
  url="$(asset_url "$OS" "$ARCH")"
  mkdir -p "$DEST_DIR" || die "couldn't create $DEST_DIR - pick another with --dir."
  tmp="$DEST.tmp.$$"
  vsay "downloading $url"
  # fetch_pinning, not fetch: this is the first of three files from the same origin, and
  # it pins the checksum + signature to whichever origin serves this one.
  fetch_pinning "$url" "$tmp" || { rm -f "$tmp"; die "couldn't download the whisper binary - check your internet and try again."; }
  # Verify BEFORE we trust it. No sha tool ⇒ refuse (conservative in what we run).
  if ! fetch "$url.sha256" "$tmp.sha256"; then
    rm -f "$tmp" "$tmp.sha256"; die "couldn't fetch the checksum to verify the download safely - try again."
  fi
  want="$(cut -d' ' -f1 "$tmp.sha256")"
  got="$(sha256_of "$tmp")"
  if [ -z "$got" ]; then
    rm -f "$tmp" "$tmp.sha256"; die "can't verify the download safely on this machine (no sha256 tool) - install coreutils and re-run."
  fi
  if [ "$want" != "$got" ]; then
    # Say WHICH mismatch this is. A genuinely corrupt download and a URL that answered
    # with a web page are the same checksum failure and completely different problems,
    # and "try again" is useless advice for the second one. A Mach-O, an ELF and a PE
    # all start with a known magic; anything textual here means we were handed a page.
    if head -c 2 "$tmp" 2>/dev/null | LC_ALL=C grep -q '^#!' 2>/dev/null \
       || LC_ALL=C head -c 400 "$tmp" 2>/dev/null | LC_ALL=C grep -qiE '<!doctype|<html|^#!/' 2>/dev/null; then
      rm -f "$tmp" "$tmp.sha256"
      die "that URL answered with a page or a script, not a binary, so nothing was installed.
     tried:  $url
     Set WHISPER_CLI_BASE to the download host and we add the rest, e.g.
       WHISPER_CLI_BASE=https://cli.whisper.online
     or unset it entirely and the default just works."
    fi
    rm -f "$tmp" "$tmp.sha256"; die "the download didn't verify (checksum mismatch) - refusing to install. Try again."
  fi
  rm -f "$tmp.sha256"
  # Extra layer: best-effort PGP verify of the detached .asc (fail-soft; bad sig = fatal).
  pgp_verify "$tmp" "$url"
  chmod 0755 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$DEST" || { rm -f "$tmp"; die "couldn't write $DEST - pick another dir with --dir, or check permissions."; }
  # macOS Gatekeeper: clear the quarantine xattr + ad-hoc sign so first run isn't blocked.
  if [ "$OS" = darwin ]; then
    xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
    codesign -s - "$DEST" 2>/dev/null || true
  fi
}

# =================================================================================
# THE PATH FIX - never just print a tip.
#   (a) future shells: edit the RIGHT rc files idempotently (removable marker block);
#   (b) this shell now: mutate the live PATH + print the exact reactivation line;
#   (c) self-verify: a fresh login+interactive shell of each type must resolve whisper.
# =================================================================================
MARK_BEGIN='# >>> whisper >>>'
MARK_END='# <<< whisper <<<'

# block_for FILE → the marker block to write into FILE. fish gets fish syntax; every
# other (POSIX) file gets a guarded `export PATH=…` (only prepends if not already on
# PATH, so sourcing it twice is a no-op - no churn, idempotent at runtime too).
block_for() {
  case "$1" in
    *config.fish)
      printf '%s\n%s\n%s\n' "$MARK_BEGIN" "fish_add_path -p $DEST_DIR" "$MARK_END" ;;
    *)
      # shellcheck disable=SC2016  # $PATH is for the shell that reads the rc file, not expanded here
      printf '%s\ncase ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH" ;; esac\n%s\n' \
        "$MARK_BEGIN" "$DEST_DIR" "$DEST_DIR" "$MARK_END" ;;
  esac
}

# edit_rc FILE - write/replace the marker block in FILE, idempotently. If a block is
# already present it is REPLACED (never a second appended); otherwise it is appended.
# Creates the file (and its parent dir) if missing. Liberal: a read-only HOME just
# warns and degrades - the live-PATH + exec path still works (the door never fails).
edit_rc() {
  _f="$1"
  _dir="$(dirname "$_f")"
  mkdir -p "$_dir" 2>/dev/null || { vsay "can't create $_dir - skipping $_f"; return 0; }
  _new="$(block_for "$_f")"
  if [ -f "$_f" ] && grep -qF "$MARK_BEGIN" "$_f" 2>/dev/null; then
    # Replace the existing block (between the markers, inclusive) with the fresh one.
    _t="$_f.whisper.$$"
    if awk -v b="$MARK_BEGIN" -v e="$MARK_END" -v repl="$_new" '
      $0==b {inb=1; print repl; next}
      inb && $0==e {inb=0; next}
      !inb {print}
    ' "$_f" > "$_t" 2>/dev/null && mv -f "$_t" "$_f" 2>/dev/null; then
      EDITED="$EDITED $_f"
    else
      rm -f "$_t" 2>/dev/null || true; vsay "couldn't update $_f (read-only?) - skipping"
    fi
  else
    if { printf '\n%s\n' "$_new" >> "$_f"; } 2>/dev/null; then
      EDITED="$EDITED $_f"
    else
      vsay "couldn't write $_f (read-only?) - skipping"
    fi
  fi
}

# login_shell_name → the user's login shell basename (sh/bash/zsh/fish/dash/…). Honors
# --shell, then $SHELL, then the passwd entry (getent on Linux, dscl on macOS).
login_shell_name() {
  if [ -n "$FORCE_SHELL" ]; then printf '%s' "$FORCE_SHELL"; return; fi
  _s="${SHELL:-}"
  if [ -z "$_s" ] && command -v getent >/dev/null 2>&1; then
    _s="$(getent passwd "$(id -un 2>/dev/null)" 2>/dev/null | cut -d: -f7)"
  fi
  if [ -z "$_s" ] && command -v dscl >/dev/null 2>&1; then
    _s="$(dscl . -read "/Users/$(id -un 2>/dev/null)" UserShell 2>/dev/null | awk '{print $2}')"
  fi
  printf '%s' "$(basename "${_s:-sh}")"
}

# zsh_dir → honor $ZDOTDIR for zsh rc files (falls back to $HOME).
zsh_dir() { printf '%s' "${ZDOTDIR:-$HOME}"; }

# fix_path - edit the right rc set for the detected shell (and any shell whose config
# already exists), always including ~/.profile as a universal floor.
fix_path() {
  EDITED=""
  [ "$NO_PATH" = "1" ] && { say "skipping PATH edits (--no-path)."; return 0; }

  # We deliberately do NOT short-circuit when DEST_DIR is already on the CURRENT PATH.
  # Being on the installer's PATH never implies a brand-new terminal will inherit it.
  # The marker block is idempotent, so always writing it is correct (every future shell
  # of every type resolves) and harmless (a re-run just rewrites it).

  _sh="$(login_shell_name)"
  _zdir="$(zsh_dir)"

  # 1) the universal POSIX floor.
  edit_rc "$HOME/.profile"

  # 2) EVERY common interactive shell - UNCONDITIONALLY, creating the rc file if absent.
  # A user's NEXT shell is often NOT their login shell (a bash-login user opens zsh or
  # fish; a macOS-default-zsh user opens fish), and zsh/fish do NOT read ~/.profile.
  # Gating on the login shell, or on "config already exists", leaves those shells
  # stranded. So cover bash + zsh + fish for EVERYONE. The marker block makes every edit
  # idempotent, so over-covering a shell the user never opens is free and harmless.
  edit_rc "$HOME/.bashrc"
  edit_rc "$HOME/.bash_profile"
  edit_rc "$_zdir/.zshrc"
  edit_rc "$_zdir/.zprofile"
  edit_rc "$HOME/.config/fish/config.fish"
  return 0
}

# reactivation_line → the exact one-liner to make THIS terminal see whisper now.
reactivation_line() {
  case "$(login_shell_name)" in
    fish) printf 'fish_add_path -p %s' "$DEST_DIR" ;;
    *)    # shellcheck disable=SC2016  # $PATH is for the shell the user pastes this into
          printf 'export PATH="%s:$PATH"' "$DEST_DIR" ;;
  esac
}

# _probe SHELLPATH FLAG CMD - spawn the shell ENV-SCRUBBED (DEST_DIR removed from PATH)
# as a fresh login+interactive shell and run CMD. Succeeds ONLY if the installer's rc
# edits put whisper back - never via an inherited live PATH. $_scrub is set by self_verify.
_probe() {
  if [ -n "${ZDOTDIR:-}" ]; then
    env -i HOME="$HOME" TERM="${TERM:-xterm}" ZDOTDIR="$ZDOTDIR" PATH="$_scrub" "$1" "$2" "$3" >/dev/null 2>&1
  else
    env -i HOME="$HOME" TERM="${TERM:-xterm}" PATH="$_scrub" "$1" "$2" "$3" >/dev/null 2>&1
  fi
}

# self_verify - spawn a FRESH login+interactive shell of each available type, with the
# environment SCRUBBED of DEST_DIR, and assert `whisper` resolves. Returns 0 only if every
# spawned shell finds it. (The env-scrub is essential: without it the probe inherits
# main's live PATH and false-passes.)
self_verify() {
  _ok=0   # 0 = success (shell convention); set to 1 the moment any spawned shell fails
  _sh="$(login_shell_name)"
  FAILED_SHELL=""
  # The PATH the probes inherit, with DEST_DIR removed - only an rc edit can re-add it.
  _scrub="$(printf '%s' ":$PATH:" | sed "s|:$DEST_DIR:|:|g; s|^:*||; s|:*\$||")"
  [ -n "$_scrub" ] || _scrub="/usr/local/bin:/usr/bin:/bin"
  _checked=""
  for cand in "$_sh" bash zsh fish sh; do
    case " $_checked " in *" $cand "*) continue ;; esac
    _checked="$_checked $cand"
    _shbin="$(command -v "$cand" 2>/dev/null)" || continue
    [ -n "$_shbin" ] || continue
    case "$cand" in
      fish)        if _probe "$_shbin" -lc 'type -q whisper';        then vsay "verified in fish";  else _ok=1; FAILED_SHELL="$FAILED_SHELL $cand"; fi ;;
      sh|dash|ash) if _probe "$_shbin" -lc 'command -v whisper';     then vsay "verified in $cand"; else _ok=1; FAILED_SHELL="$FAILED_SHELL $cand"; fi ;;
      *)           if _probe "$_shbin" -lic 'command -v whisper';    then vsay "verified in $cand"; else _ok=1; FAILED_SHELL="$FAILED_SHELL $cand"; fi ;;
    esac
  done
  return "$_ok"
}

# --- key handoff: write a valid key to the config so the binary picks it up -------
# Ladder: server-injected WHISPER_KEY > --key/first-token > $WHISPER_API_KEY > existing.
# The installer NEVER prompts for a key - the binary's guided flow does (device-flow too).
# Path: ~/.config/whisper/key is where the binary's own key ladder reads (the 2026-08
# brand rename; the binary migrates a legacy ~/.config/whisper-ns only when the new dir
# is absent, so writing the legacy path here would strand the key on a host that already
# has ~/.config/whisper - we write the real path the binary reads).
save_key() {
  _k="${WHISPER_KEY:-}"
  [ -n "$_k" ] || _k="$ARG_KEY"
  [ -n "$_k" ] || _k="${WHISPER_API_KEY:-}"
  if [ -n "$_k" ]; then
    ( umask 077; mkdir -p "$HOME/.config/whisper" && printf '%s' "$_k" > "$HOME/.config/whisper/key" ) \
      2>/dev/null || vsay "couldn't save the key file - the binary will ask."
    # Belt-and-braces: mirror the key to the legacy pre-rename path too, so an
    # endpoint that ends up with an OLDER cached binary (whose ladder reads only
    # ~/.config/whisper-ns/key) still resolves it from disk with no env present -
    # e.g. the documented no-env `curl -fsSL https://get.whisper.online/uninstall | sh` revoke.
    # uninstall.sh removes both copies; drop this once the renamed release is universal.
    ( umask 077; mkdir -p "$HOME/.config/whisper-ns" && printf '%s' "$_k" > "$HOME/.config/whisper-ns/key" ) \
      2>/dev/null || true
  fi
}

# =================================================================================
# FLEET AUTO-BIND - silent /128 identity for RMM / fleet deploys.
#
# When a fleet tool (NinjaOne, Intune, Jamf, plain SSH-for-loops) runs this installer
# with a key and no terminal, the endpoint should come up with its routable Whisper
# /128 identity bound - zero clicks, zero prompts. Opt-in ladder (liberal in what we
# accept, conservative in what we do):
#
#   WHISPER_AUTOBIND=1|yes|true|on   bind (register-then-identity ladder, any TTY state)
#   WHISPER_AUTOBIND=register        bind via op:register ONLY  (a per-endpoint agent)
#   WHISPER_AUTOBIND=identity        bind via op:identity ONLY  (this key's own /128)
#   WHISPER_AUTOBIND=0|no|off|false  never bind, not even inferred
#   (unset)                          INFERRED only when stdout is NOT a tty AND the
#                                    key was INJECTED on THIS run as WHISPER_KEY (the
#                                    RMM script-variable / X-API-Key header shape).
#                                    A persistent WHISPER_API_KEY export or a --key
#                                    argument NEVER infers a bind - a Dockerfile RUN
#                                    or CI job with the documented env convention
#                                    must not silently mint a routable /128 it never
#                                    asked for. Those callers opt in explicitly with
#                                    WHISPER_AUTOBIND=1. An interactive `curl | sh`
#                                    (tty stdout) is untouched either way.
#
# Semantics: the default ladder first mints a PER-ENDPOINT agent (op:register via
# `whisper create --register`, labelled with this host's name) so a whole site can
# share ONE RMM-injected site key and still get distinct per-endpoint /128s; if the
# key may not register (scope-limited per-device keys), it falls back to the key's own
# op:identity /128 (idempotent server-side: one key = one /128, reused). Idempotent
# across re-runs: a successful bind records a marker (~/.config/whisper/bound) and a
# re-run re-prints the same line without touching the control plane. Fail-soft: any
# bind failure warns and leaves the CLI installed - never a hard fail.
# =================================================================================

# json_field JSON KEY → the value of KEY (or empty). A deliberately tiny, dependency-
# free extractor (no jq on a fleet endpoint) that understands BOTH envelope shapes the
# control plane emits: object records (`"address":"2a04:…"`) and the columnar result
# (`"columns":["agent","address",…],"rows":[["…","2a04:…",…]]` - the shape op:register/
# op:identity return today). The values we pull (address / fqdn / ptr / agent) never
# contain commas, quotes or escapes, so plain comma-splitting the row is sound.
json_field() {
  printf '%s\n' "$1" | awk -v k="$2" '
    { json = json $0 }
    END {
      # Shape 1: an object record - "k":"v" anywhere.
      pat = "\"" k "\"[[:space:]]*:[[:space:]]*\"[^\"]*\""
      if (match(json, pat)) {
        s = substr(json, RSTART, RLENGTH)
        sub(/^"[^"]*"[[:space:]]*:[[:space:]]*"/, "", s)
        sub(/"$/, "", s)
        print s
        exit
      }
      # Shape 2: columnar - find the "columns":[…] array that CONTAINS k (envelopes
      # nest an outer op/ok/status columns array we must skip), then read the first
      # row of the "rows":[[…]] that follows it and print the value at k'\''s index.
      rest = json
      while (match(rest, /"columns"[[:space:]]*:[[:space:]]*\[[^]]*\]/)) {
        cols = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
        if (index(cols, "\"" k "\"") == 0) continue
        if (!match(rest, /"rows"[[:space:]]*:[[:space:]]*\[\[[^]]*\]/)) continue
        row = substr(rest, RSTART, RLENGTH)
        sub(/^"columns"[[:space:]]*:[[:space:]]*\[/, "", cols)
        sub(/\]$/, "", cols)
        sub(/^"rows"[[:space:]]*:[[:space:]]*\[\[/, "", row)
        sub(/\]$/, "", row)
        nc = split(cols, C, ",")
        split(row, R, ",")
        for (i = 1; i <= nc; i++) {
          c = C[i]; gsub(/^[[:space:]]*"/, "", c); gsub(/"[[:space:]]*$/, "", c)
          if (c == k) {
            v = R[i]; gsub(/^[[:space:]]*"/, "", v); gsub(/"[[:space:]]*$/, "", v)
            if (v != "null") print v
            exit
          }
        }
        exit
      }
    }'
}

# autobind_wanted → 0 when this run should silently bind a /128, else 1.
autobind_wanted() {
  # Liberal-accept (Postel): case-fold the token so WHISPER_AUTOBIND=Yes / TRUE / ON
  # (a common env-var convention) is honoured, not silently ignored.
  case "$(printf '%s' "${WHISPER_AUTOBIND:-}" | tr '[:upper:]' '[:lower:]')" in
    0|no|off|false)                  return 1 ;;
    1|yes|true|on|register|identity) return 0 ;;
  esac
  # Unset ⇒ infer the fleet shape: output captured (stdout not a tty) + the key
  # INJECTED on this run as WHISPER_KEY (RMM variable / gateway header bake). The
  # persistent $WHISPER_API_KEY convention and --key/first-token deliberately do
  # NOT infer - conservative in what we do: no surprise identities from a
  # Dockerfile RUN or a redirected install (explicit WHISPER_AUTOBIND=1 covers those).
  [ ! -t 1 ] || return 1
  [ -n "${WHISPER_KEY:-}" ] || return 1
  return 0
}

# fleet_autobind - bind this endpoint's /128 via the binary's own non-interactive
# enroll (`whisper enroll`), then print ONE line:  bound <addr>  (<fcrdns-name>).
# Sets BOUND=1 on success (including the already-bound re-run). Never fails the install.
fleet_autobind() {
  _cfgdir="$HOME/.config/whisper"
  _marker="$_cfgdir/bound"
  # Idempotent re-run: a prior bind is recorded in the marker - re-print it, zero calls.
  if [ -f "$_marker" ]; then
    _addr="$(sed -n 's/^address=//p' "$_marker" | head -n 1)"
    _name="$(sed -n 's/^name=//p' "$_marker" | head -n 1)"
    if [ -n "$_addr" ]; then
      say "bound $_addr  (${_name:-no name}) [already bound]"
      BOUND=1
      return 0
    fi
  fi
  [ -x "$DEST" ] || { say "auto-bind skipped: no whisper binary at $DEST"; return 0; }
  # The agent's human name: this endpoint's hostname, with a safe fallback.
  _host="$(hostname 2>/dev/null || uname -n 2>/dev/null || printf 'endpoint')"
  [ -n "$_host" ] || _host="endpoint"
  # the bind ladder lives in the BINARY now (`whisper enroll`), not here. One
  # implementation, one marker format, one place to fix - the shell half of this used to
  # be reimplemented in the macOS first-run agent too, and a host bound by any third route
  # got no marker at all and shipped nothing.
  #
  # The probe is not ceremony: WHISPER_CLI_BASE can point this installer at any mirror or
  # release base, including one that serves a CLI older than the verb, and that binary still
  # binds through the legacy ladder below. Delete the fallback once no base we accept can
  # serve a CLI older than 0.212.0.
  if "$DEST" enroll --help >/dev/null 2>&1; then
    if "$DEST" enroll --name "$_host" >/dev/null 2>&1; then
      # enroll wrote the marker; read back what it recorded rather than re-deriving it.
      _addr="$(sed -n 's/^address=//p' "$_marker" 2>/dev/null | head -n 1)"
      _name="$(sed -n 's/^name=//p' "$_marker" 2>/dev/null | head -n 1)"
      if [ -n "$_addr" ]; then
        say "bound $_addr  (${_name:-no reverse name yet})"
        BOUND=1
        return 0
      fi
    fi
    say "couldn't bind a /128 identity (key refused or control plane unreachable) - whisper is installed; bind later with: whisper enroll"
    return 0
  fi

  # --- legacy ladder: pre-0.212.0 binaries, which have no `enroll` ------------------
  # The binary resolves the key itself (env WHISPER_KEY/WHISPER_API_KEY, else the file
  # save_key just wrote) - the key never appears on argv.
  _out=""
  _mode=""
  # Bind-mode ladder. Compute the mode list with a STANDALONE case, never a `case` inside
  # $(...): macOS /bin/sh is bash 3.2, whose command-substitution parser misreads the `)` in
  # the case patterns and dies with "syntax error near `;;`". A plain var + word-split
  # for-loop is POSIX-portable to every shell (bash 3.2, dash, busybox ash, zsh).
  case "${WHISPER_AUTOBIND:-}" in
    register) _modes='register' ;;
    identity) _modes='identity' ;;
    *)        _modes='register identity' ;;
  esac
  # --reuse makes the register bind IDEMPOTENT on the endpoint name. A re-run
  # of this installer (a sensor/binary upgrade, a re-imaged box, a lost marker, a
  # different $HOME than the first bind) re-finds the agent already registered under
  # this hostname and returns its EXISTING /128, instead of minting a duplicate that
  # strands the old identity and moves the telemetry. A genuinely fresh endpoint
  # still mints; the identity mode below is server-side idempotent already (one key,
  # one /128).
  for _m in $_modes; do
    case "$_m" in
      register) _out="$("$DEST" create --register --reuse --name "$_host" --json 2>/dev/null)" || _out="" ;;
      identity) _out="$("$DEST" create --name "$_host" --json 2>/dev/null)" || _out="" ;;
    esac
    _addr="$(json_field "$_out" address)"
    [ -z "$_addr" ] && _addr="$(json_field "$_out" addr128)"
    if [ -n "$_addr" ]; then _mode="$_m"; break; fi
  done
  if [ -z "${_addr:-}" ]; then
    say "couldn't bind a /128 identity (key refused or control plane unreachable) - whisper is installed; bind later with: whisper create --name $_host"
    return 0
  fi
  # FCrDNS name: the forward fqdn (which is also the PTR's target - dig -x <addr>
  # answers exactly this name); the envelope's `ptr` field is the ip6.arpa OWNER name.
  _fcrdns="$(json_field "$_out" fqdn)"
  [ -n "$_fcrdns" ] || _fcrdns="$(json_field "$_out" ptr)"
  _fcrdns="${_fcrdns%.}"
  _agent="$(json_field "$_out" agent)"
  # NOTE: an op:register envelope also carries the minted agent's own api_key (shown
  # once). It lives only in this shell's memory: we parse what we need and drop it -
  # never printed, never persisted (the endpoint keeps ONLY the key the RMM injected).
  _out=""
  # Record the bind (no secrets) so a re-run is idempotent and uninstall can revoke.
  ( umask 077; mkdir -p "$_cfgdir" && printf 'mode=%s\naddress=%s\nname=%s\nagent=%s\nbound_at=%s\n' \
      "$_mode" "$_addr" "$_fcrdns" "$_agent" "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)" \
      > "$_marker" ) 2>/dev/null || vsay "couldn't write the bind marker - re-runs will re-check with the server"
  # Pin the binary's chosen agent to THIS identity (so a later `whisper connect` binds
  # it with zero config) - but never clobber an agent a human already picked.
  if [ -n "$_agent" ] && [ ! -f "$_cfgdir/agent" ]; then
    ( umask 077; printf '%s' "$_agent" > "$_cfgdir/agent" ) 2>/dev/null || true
  fi
  say "bound $_addr  (${_fcrdns:-no reverse name yet})"
  BOUND=1
  return 0
}

# =================================================================================
# main
# =================================================================================
say "installing…"
install_binary
save_key
fix_path

# capture whether the PARENT shell already had DEST_DIR, BEFORE the line
# below adds it to ours. fix_path only edits rc files and never assigns a live
# PATH, so this is still genuinely the caller's environment.
#
# fix_path's own comment states the converse of this and has done all along:
# "Being on the installer's PATH never implies a brand-new terminal will inherit
# it." The mirror is what bit us. Editing an rc file never implies THIS terminal
# can see it either, and a `curl | sh` install has no way to change the shell
# that invoked it. Saying "run: whisper" to a shell that cannot run it is the
# whole of the bug.
PARENT_HAD_DEST=0
case ":$PATH:" in *":$DEST_DIR:"*) PARENT_HAD_DEST=1 ;; esac

# Make THIS shell's child (the exec below) see DEST_DIR even before any rc runs.
case ":$PATH:" in *":$DEST_DIR:"*) ;; *) PATH="$DEST_DIR:$PATH"; export PATH ;; esac

# Self-verify in a fresh shell BEFORE we claim success (the headline-bug oracle).
if [ "${NO_PATH:-0}" != "1" ]; then
  if ! self_verify; then
    say "installed to $DEST, but a fresh ${FAILED_SHELL:-shell} didn't see it on PATH."
    say "to use it in THIS terminal now, run:  $(reactivation_line)"
    say "new terminals should already work; if not, re-run the installer."
    # Not fatal: the binary still works by absolute path; the door never fails.
  fi
fi

# Success line + handoff. On a TTY, exec the guided flow (by ABSOLUTE path so it never
# depends on PATH). No TTY ⇒ print the one-line next step.
# only promise what this terminal can actually do. A TTY run execs the
# guided flow below by absolute path, so it is fine either way; a piped run
# returns to a shell whose PATH we could not touch.
if [ "$PARENT_HAD_DEST" = "1" ] || { [ -t 0 ] && [ -t 1 ]; }; then
  say "installed ✓  (run: whisper)"
else
  # One line, per the lean-output contract (at most two status lines on the happy
  # path): the command that works HERE, plus what new terminals will do.
  #
  # The second clause is NOT a constant. With --no-path (or NO_PATH=1) no rc file
  # was edited, so promising that new terminals already work would be the same
  # untrue-by-default claim this whole change exists to remove, just moved one
  # sentence along.
  if [ "${NO_PATH:-0}" = "1" ]; then
    say "installed ✓  (not on PATH: $(reactivation_line) - and add it to your shell rc yourself, --no-path was passed)"
  else
    say "installed ✓  (this shell: $(reactivation_line) - new terminals already work)"
  fi
fi

# Fleet auto-bind: silent, idempotent, fail-soft - see the section above. Runs
# before the TTY handoff so an explicit WHISPER_AUTOBIND=1 binds even on a terminal
# (the guided flow then simply finds its identity already in place).
BOUND=0
if autobind_wanted; then
  fleet_autobind || true
fi

# Host sensor - OPT-IN ONLY, never default-on. The bare one-liner mints
# identity + resolver and NOTHING more; observing a host is an explicit choice,
# never a side effect of minting a /128, so this is deliberately NOT inferred
# from WHISPER_AUTOBIND or the fleet shape. Set WHISPER_SENSOR=1 (or yes/true/on)
# to ALSO install + enable + start the separate whisper-sensor service via the
# binary's own installer. Fail-soft: a sensor failure warns with the one command
# to run later and NEVER fails the install.
case "$(printf '%s' "${WHISPER_SENSOR:-}" | tr '[:upper:]' '[:lower:]')" in
  1|yes|true|on)
    # One identity for mint → sensor. The sensor ships its telemetry under this
    # endpoint's OWN /128 (keyless-on-/128, else keyed-fallback), so a bound /128
    # is a PRECONDITION. If this run has not already bound one (an interactive
    # one-liner, where autobind_wanted is false), bind it now: enabling the sensor
    # is an explicit opt-in, so binding the identity it needs is a precondition,
    # not a surprise. fleet_autobind is idempotent and fail-soft.
    if [ "$BOUND" != 1 ]; then
      fleet_autobind || true
    fi
    if [ -x "$DEST" ] && "$DEST" service install --now --sensor >/dev/null 2>&1; then
      say "sensor service installed + running (whisper-sensor)"
    else
      say "couldn't enable the sensor service - whisper is installed; enable later with: whisper service install --now --sensor"
    fi
    ;;
esac

if [ -t 0 ] && [ -t 1 ] && [ -x "$DEST" ]; then
  exec "$DEST"
elif [ "$BOUND" != 1 ] && [ "$PARENT_HAD_DEST" = "1" ]; then
  # "run: whisper" only to a shell that can actually run it. When the
  # parent lacks DEST_DIR the success line above has already given the command
  # that works here, so repeating a second, wrong instruction would be worse
  # than saying nothing.
  say "installed to $DEST - run: whisper"
fi
