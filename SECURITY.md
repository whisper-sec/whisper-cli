# Security Policy

## Verifying releases

Every `whisper` release is published as a set of signed, checksummed artifacts on the
[Releases page](https://github.com/whisper-sec/whisper-cli/releases). For each platform
binary you get:

- `whisper-<os>-<arch>` (or `whisper-<os>-<arch>.exe` on Windows) — the binary
- `whisper-<os>-<arch>.sha256` — its SHA-256 checksum
- `whisper-<os>-<arch>.asc` — a detached PGP signature
- `checksums.txt` — the SHA-256 of every asset in the release, in one file

The one-line installer (`curl get.whisper.online | sh`) verifies the SHA-256 as a **hard
gate** — a mismatch aborts the install — and additionally verifies the PGP signature when
`gpg` is available on the host.

### Manual verification

**1. SHA-256 checksum**

```sh
sha256sum -c whisper-linux-amd64.sha256
# or check against the release-wide manifest:
grep whisper-linux-amd64 checksums.txt | sha256sum -c -
```

**2. PGP signature**

Releases are signed with the **AS219419** signing key:

```
Fingerprint: EFF1663D992539682106A5EAD0F70908CF3B7929
```

The public key is published at <https://as219419.net/> (and at
<https://as219419.net/whisper-release.asc>). Import it and verify the detached signature:

```sh
curl -fsSL https://as219419.net/whisper-release.asc | gpg --import
gpg --verify whisper-linux-amd64.asc whisper-linux-amd64
```

Confirm the output reports a **good signature** from a key whose fingerprint matches the
one above. If either the checksum or the signature does not verify, do not run the
binary — report it (see below).

## Reporting a vulnerability

Please report security issues responsibly and privately to:

**security@whisper.security**

Include enough detail to reproduce the issue. We will acknowledge your report, work with
you on a fix and disclosure timeline, and credit you if you wish. Please do not open a
public issue for security-sensitive reports.

## Supported versions

Security fixes target the latest released version. Please upgrade to the most recent
release before reporting an issue.
