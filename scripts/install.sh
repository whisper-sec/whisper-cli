#!/bin/sh
# -----------------------------------------------------------------------------
# install.sh — the ONE Whisper installer (POSIX).   curl get.whisper.online | sh
#
#   curl -H "X-API-Key: whisper_live_xxx" https://get.whisper.online | sh   # zero prompts
#   curl https://get.whisper.online | sh -s -- whisper_live_xxx              # key as first arg
#   curl https://get.whisper.online | sh                                     # then: whisper
#
# This is the SAME installer that get.whisper.online serves — it is published here,
# in the public whisper-cli repo, so the entire install path is inspectable. By
# default it fetches the SIGNED binary straight from this repo's GitHub Releases:
#
#   https://github.com/whisper-sec/whisper-cli/releases/latest/download/whisper-<os>-<arch>
#
# Its job is SMALL and it does exactly three things, then hands off to the binary:
#   1. get the right `whisper` binary onto disk, sha256-VERIFIED (and PGP-checked
#      when gpg is present), atomically;
#   2. put it on PATH for real — future shells (rc files) AND this one (live PATH);
#   3. exec `whisper` (the guided flow owns login / agent / connect / verify).
#
# No tiers, no proxychains, no package manager, no python3, no DoH prose — `connect`
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
vsay() { [ "${VERBOSE:-0}" = "1" ] && printf 'whisper: %s\n' "$*" >&2 || true; }

# --- defaults (all overridable; zero-config by default) --------------------------
# CLI_BASE is where the binary + sha256 + asc live. DEFAULT = this repo's GitHub
# Releases ("latest"), so the install is public, signed and verifiable. The box can
# still serve as a fallback mirror by exporting WHISPER_CLI_BASE.
CLI_BASE="${WHISPER_CLI_BASE:-https://github.com/whisper-sec/whisper-cli/releases/latest/download}"
# The AS219419 release-signing key fingerprint + where its public key is published.
PGP_FPR="${WHISPER_PGP_FPR:-EFF1663D992539682106A5EAD0F70908CF3B7929}"
PGP_KEY_URL="${WHISPER_PGP_KEY_URL:-https://as219419.net/whisper-release.asc}"
DEST_DIR="${WHISPER_DIR:-$HOME/.local/bin}"
NO_PATH=0
FORCE_SHELL=""
ARG_KEY=""

# --- flags (liberal: any order; unknown ⇒ warn+ignore; first bare token = key) ---
# Every read/shift is guarded — a trailing `--dir` with no value must NOT `shift 2`
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

DEST="$DEST_DIR/whisper"

# --- require curl or wget, and a sha256 tool ------------------------------------
DL=""
if command -v curl >/dev/null 2>&1; then DL=curl
elif command -v wget >/dev/null 2>&1; then DL=wget
else die "needs curl or wget to download — install one and re-run."; fi

# fetch URL OUTFILE → 0 on a 2xx download, 1 otherwise (never throws). Postel: HTTPS is
# PINNED for production (the default github.com base is https — a real one-liner is
# always https, so a downgrade can't be forced on a user). We relax the pin ONLY when
# the URL is EXPLICITLY http:// — the only http base is a local/CI test gateway, by hand.
# GitHub release downloads 302-redirect to objects.githubusercontent.com, so we follow
# redirects (-L / wget default) while keeping every hop https.
fetch() {
  case "$1" in
    http://*)   # local / CI test gateway only — no TLS to pin
      if [ "$DL" = curl ]; then curl -fsSL "$1" -o "$2"
      else                      wget -q -O "$2" "$1"; fi ;;
    *)          # https:// (production) and anything else — TLS-pinned
      if [ "$DL" = curl ]; then curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
      else                      wget -q --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"; fi ;;
  esac
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
    *)      die "no Whisper binary for your system ($_os) yet — we ship Linux and macOS. Tell us: hello@whisper.security" ;;
  esac
  case "$_arch" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *)              die "no Whisper binary for your CPU ($_arch) yet — we ship amd64 and arm64. Tell us: hello@whisper.security" ;;
  esac
}

# --- best-effort PGP verify of the .asc detached signature -----------------------
# sha256 is the HARD gate (a mismatch is fatal). The PGP check is an EXTRA layer that
# proves the bytes were signed by the AS219419 release key — but it is FAIL-SOFT: if
# gpg is absent, or the .asc isn't published yet, or the key can't be fetched, we warn
# and continue (the sha256 already proved integrity against the release manifest). When
# gpg IS present and the signature IS present, a BAD signature is fatal (refuse).
# Args: $1 = binary file, $2 = the binary's download URL (we derive "$url.asc").
pgp_verify() {  # → 0 = verified or skipped-cleanly; dies on a present-but-BAD signature
  command -v gpg >/dev/null 2>&1 || { vsay "gpg not found — skipping PGP verification (sha256 already verified)"; return 0; }
  _bin="$1"; _ascurl="$2.asc"
  _asc="$_bin.asc"
  if ! fetch "$_ascurl" "$_asc" 2>/dev/null; then
    vsay "no PGP signature published for this asset — skipping (sha256 already verified)"
    rm -f "$_asc" 2>/dev/null || true
    return 0
  fi
  # Import the release public key into an EPHEMERAL keyring so we never touch the
  # user's real ~/.gnupg. Fetch the key from as219419.net; skip-soft if unreachable.
  _gnupghome="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/whisper-gpg.$$")"
  mkdir -p "$_gnupghome" 2>/dev/null || true
  chmod 700 "$_gnupghome" 2>/dev/null || true
  _keyfile="$_gnupghome/whisper-release.asc"
  if ! fetch "$PGP_KEY_URL" "$_keyfile" 2>/dev/null; then
    vsay "couldn't fetch the AS219419 release key from $PGP_KEY_URL — skipping PGP (sha256 already verified)"
    rm -rf "$_gnupghome" "$_asc" 2>/dev/null || true
    return 0
  fi
  if ! GNUPGHOME="$_gnupghome" gpg --batch --quiet --import "$_keyfile" 2>/dev/null; then
    vsay "couldn't import the release key — skipping PGP (sha256 already verified)"
    rm -rf "$_gnupghome" "$_asc" 2>/dev/null || true
    return 0
  fi
  if GNUPGHOME="$_gnupghome" gpg --batch --status-fd 1 --verify "$_asc" "$_bin" 2>/dev/null \
       | grep -q "VALIDSIG.*$PGP_FPR"; then
    vsay "PGP signature verified (AS219419 key $PGP_FPR)"
    rm -rf "$_gnupghome" "$_asc" 2>/dev/null || true
    return 0
  fi
  # A signature WAS present but did not verify against the expected key → refuse.
  rm -rf "$_gnupghome" "$_asc" "$_bin" 2>/dev/null || true
  die "the download's PGP signature did not verify against the AS219419 release key — refusing to install."
}

# --- download + verify + atomic install -----------------------------------------
install_binary() {
  detect_platform
  url="$CLI_BASE/whisper-$OS-$ARCH"
  mkdir -p "$DEST_DIR" || die "couldn't create $DEST_DIR — pick another with --dir."
  tmp="$DEST.tmp.$$"
  vsay "downloading $url"
  fetch "$url" "$tmp" || { rm -f "$tmp"; die "couldn't download the whisper binary — check your internet and try again."; }
  # Verify BEFORE we trust it. No sha tool ⇒ refuse (conservative in what we run).
  if ! fetch "$url.sha256" "$tmp.sha256"; then
    rm -f "$tmp" "$tmp.sha256"; die "couldn't fetch the checksum to verify the download safely — try again."
  fi
  want="$(cut -d' ' -f1 "$tmp.sha256")"
  got="$(sha256_of "$tmp")"
  if [ -z "$got" ]; then
    rm -f "$tmp" "$tmp.sha256"; die "can't verify the download safely on this machine (no sha256 tool) — install coreutils and re-run."
  fi
  if [ "$want" != "$got" ]; then
    rm -f "$tmp" "$tmp.sha256"; die "the download didn't verify (checksum mismatch) — refusing to install. Try again."
  fi
  rm -f "$tmp.sha256"
  # Extra layer: best-effort PGP verify of the detached .asc (fail-soft; bad sig = fatal).
  pgp_verify "$tmp" "$url"
  chmod 0755 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$DEST" || { rm -f "$tmp"; die "couldn't write $DEST — pick another dir with --dir, or check permissions."; }
  # macOS Gatekeeper: clear the quarantine xattr + ad-hoc sign so first run isn't blocked.
  if [ "$OS" = darwin ]; then
    xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
    codesign -s - "$DEST" 2>/dev/null || true
  fi
}

# =================================================================================
# THE PATH FIX (§2.5) — never just print a tip.
#   (a) future shells: edit the RIGHT rc files idempotently (removable marker block);
#   (b) this shell now: mutate the live PATH + print the exact reactivation line;
#   (c) self-verify: a fresh login+interactive shell of each type must resolve whisper.
# =================================================================================
MARK_BEGIN='# >>> whisper >>>'
MARK_END='# <<< whisper <<<'

# block_for FILE → the marker block to write into FILE. fish gets fish syntax; every
# other (POSIX) file gets a guarded `export PATH=…` (only prepends if not already on
# PATH, so sourcing it twice is a no-op — no churn, idempotent at runtime too).
block_for() {
  case "$1" in
    *config.fish)
      printf '%s\n%s\n%s\n' "$MARK_BEGIN" "fish_add_path -p $DEST_DIR" "$MARK_END" ;;
    *)
      printf '%s\ncase ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH" ;; esac\n%s\n' \
        "$MARK_BEGIN" "$DEST_DIR" "$DEST_DIR" "$MARK_END" ;;
  esac
}

# edit_rc FILE — write/replace the marker block in FILE, idempotently. If a block is
# already present it is REPLACED (never a second appended); otherwise it is appended.
# Creates the file (and its parent dir) if missing. Liberal: a read-only HOME just
# warns and degrades — the live-PATH + exec path still works (the door never fails).
edit_rc() {
  _f="$1"
  _dir="$(dirname "$_f")"
  mkdir -p "$_dir" 2>/dev/null || { vsay "can't create $_dir — skipping $_f"; return 0; }
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
      rm -f "$_t" 2>/dev/null || true; vsay "couldn't update $_f (read-only?) — skipping"
    fi
  else
    if { printf '\n%s\n' "$_new" >> "$_f"; } 2>/dev/null; then
      EDITED="$EDITED $_f"
    else
      vsay "couldn't write $_f (read-only?) — skipping"
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

# fix_path — edit the right rc set for the detected shell (and any shell whose config
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

  # 2) EVERY common interactive shell — UNCONDITIONALLY, creating the rc file if absent.
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
    *)    printf 'export PATH="%s:$PATH"' "$DEST_DIR" ;;
  esac
}

# _probe SHELLPATH FLAG CMD — spawn the shell ENV-SCRUBBED (DEST_DIR removed from PATH)
# as a fresh login+interactive shell and run CMD. Succeeds ONLY if the installer's rc
# edits put whisper back — never via an inherited live PATH. $_scrub is set by self_verify.
_probe() {
  if [ -n "${ZDOTDIR:-}" ]; then
    env -i HOME="$HOME" TERM="${TERM:-xterm}" ZDOTDIR="$ZDOTDIR" PATH="$_scrub" "$1" "$2" "$3" >/dev/null 2>&1
  else
    env -i HOME="$HOME" TERM="${TERM:-xterm}" PATH="$_scrub" "$1" "$2" "$3" >/dev/null 2>&1
  fi
}

# self_verify — spawn a FRESH login+interactive shell of each available type, with the
# environment SCRUBBED of DEST_DIR, and assert `whisper` resolves. Returns 0 only if every
# spawned shell finds it. (The env-scrub is essential: without it the probe inherits
# main's live PATH and false-passes.)
self_verify() {
  _ok=0   # 0 = success (shell convention); set to 1 the moment any spawned shell fails
  _sh="$(login_shell_name)"
  FAILED_SHELL=""
  # The PATH the probes inherit, with DEST_DIR removed — only an rc edit can re-add it.
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
# The installer NEVER prompts for a key — the binary's guided flow does (device-flow too).
save_key() {
  _k="${WHISPER_KEY:-}"
  [ -n "$_k" ] || _k="$ARG_KEY"
  [ -n "$_k" ] || _k="${WHISPER_API_KEY:-}"
  if [ -n "$_k" ]; then
    ( umask 077; mkdir -p "$HOME/.config/whisper-ns" && printf '%s' "$_k" > "$HOME/.config/whisper-ns/key" ) \
      2>/dev/null || vsay "couldn't save the key file — the binary will ask."
  fi
}

# =================================================================================
# main
# =================================================================================
say "installing…"
install_binary
save_key
fix_path

# Make THIS shell's child (the exec below) see DEST_DIR even before any rc runs.
case ":$PATH:" in *":$DEST_DIR:"*) ;; *) PATH="$DEST_DIR:$PATH"; export PATH ;; esac

# Self-verify in a fresh shell BEFORE we claim success (the headline-bug oracle).
if [ "${NO_PATH:-0}" != "1" ] && [ "${ALREADY_ON_PATH:-0}" != "1" ]; then
  if ! self_verify; then
    say "installed to $DEST, but a fresh ${FAILED_SHELL:-shell} didn't see it on PATH."
    say "to use it in THIS terminal now, run:  $(reactivation_line)"
    say "new terminals should already work; if not, re-run the installer."
    # Not fatal: the binary still works by absolute path; the door never fails.
  fi
fi

# Success line + handoff. On a TTY, exec the guided flow (by ABSOLUTE path so it never
# depends on PATH). No TTY ⇒ print the one-line next step.
say "installed ✓  (run: whisper)"
if [ -t 0 ] && [ -t 1 ] && [ -x "$DEST" ]; then
  exec "$DEST"
else
  say "installed to $DEST — run: whisper"
fi
