#!/bin/sh
# -----------------------------------------------------------------------------
# build-all.sh — cross-compile the `whisper` CLI for every supported platform and
# stage the binaries + SHA-256 checksums into a dist/ directory, named exactly the
# way the GitHub release uploads them and the installer downloads them.
#
# The set of targets is NOT hard-coded here — it is read from `platforms.txt` (the
# SINGLE source of truth, also consumed by the installer's os/arch map), so the
# places can never drift.
#
# Output layout (flat, release-asset names; windows ⇒ .exe):
#   <out>/whisper-<os>-<arch>[.exe]          the static binary
#   <out>/whisper-<os>-<arch>[.exe].sha256   "<hex>  whisper-<os>-<arch>[.exe]"
#
# These names match what the release workflow uploads and what install.sh /
# install.ps1 request:
#   https://github.com/whisper-sec/whisper-cli/releases/latest/download/whisper-<os>-<arch>
#
# Usage:  build-all.sh [OUTPUT_DIR] [VERSION]
#   OUTPUT_DIR defaults to ./dist
#   VERSION    defaults to "dev" (CI / the release workflow stamps the real tag)
#
# Self-contained: needs only `go` on PATH. CGO is disabled so every binary is a
# single static file that runs on a bare host (zero config — the install one-liner
# just works). Stripped (-s -w) to keep the binaries lean.
#
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
# -----------------------------------------------------------------------------
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/dist}"
VERSION="${2:-dev}"
PLATFORMS_FILE="$HERE/platforms.txt"
PKG="github.com/whisper-sec/whisper-cli/internal/cli"
LDFLAGS="-s -w -X ${PKG}.Version=${VERSION}"

command -v go >/dev/null 2>&1 || {
  echo "build-all.sh: 'go' not found on PATH — install Go 1.24+ (https://go.dev/dl/) and retry." >&2
  exit 1
}
[ -f "$PLATFORMS_FILE" ] || {
  echo "build-all.sh: platforms.txt not found at $PLATFORMS_FILE" >&2
  exit 1
}

# sha256 helper: prefer sha256sum (Linux), fall back to shasum -a 256 (macOS).
sha256() {  # $1 = file → stdout: the hex digest
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Resolve OUT to an ABSOLUTE path before we cd into the module dir. `go build` with a
# package import path (./cmd/whisper) discovers the module from the CWD, so we must run
# from the module root — but the -o output dir must then still resolve correctly.
# (mkdir -p first so the path is realpath-able.)
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# Build from the module root so `go build ./cmd/whisper` finds go.mod.
cd "$HERE"

echo "build-all.sh: building whisper ${VERSION} -> ${OUT}" >&2
# Read platforms.txt line by line, skipping blanks and `#` comments. The windows targets
# emit `whisper-<os>-<arch>.exe`; everything else `whisper-<os>-<arch>`.
while IFS= read -r line || [ -n "$line" ]; do
  # Strip a trailing comment + surrounding whitespace; skip blank/comment-only lines.
  platform="${line%%#*}"
  platform="$(printf '%s' "$platform" | tr -d '[:space:]')"
  [ -n "$platform" ] || continue
  os="${platform%-*}"
  arch="${platform##*-}"
  [ -n "$os" ] && [ -n "$arch" ] || { echo "build-all.sh: skipping malformed platform '$line'" >&2; continue; }
  asset="whisper-${os}-${arch}"
  [ "$os" = "windows" ] && asset="${asset}.exe"
  echo "  -> ${asset}" >&2
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "${OUT}/${asset}" ./cmd/whisper
  ( cd "$OUT" && printf '%s  %s\n' "$(sha256 "$asset")" "$asset" > "${asset}.sha256" )
done < "$PLATFORMS_FILE"
echo "build-all.sh: done." >&2
