# AGENTS.md

Instructions for AI coding agents working in this repository. Humans want
[CONTRIBUTING.md](CONTRIBUTING.md), which this does not replace: everything there still
applies, and this file adds what an agent needs that a human would infer.

## The one-line summary

`whisper` is a single static Go binary: the command-line client for Whisper. It gives an
agent a real, routable IPv6 `/128` on AS219419, wires egress so traffic sources from that
address, and verifies the result end to end against public DNSSEC, DANE and RDAP.

## Build and test

Requires Go 1.25+. Run all four before proposing a change; CI runs the same set and a
failure in any one of them is a failure.

```sh
go build ./...     # everything compiles
go vet ./...       # no vet findings
go test ./...      # all tests pass
gofmt -l .         # MUST print nothing; if it lists a file, run gofmt -w on it
```

Run the binary from source with `go run ./cmd/whisper --help`. Cross-compiling every
shipped platform is `./build-all.sh`, driven by `platforms.txt`.

## Layout

```
cmd/whisper      the entry point, thin
internal/cli     one file per command, Cobra wiring and the TUI
internal/...     the client core: config, transport, identity, verification
skills/          SKILL.md files describing what the tool can do, for agent runtimes
scripts/         install.sh and install.ps1, the published installers
```

A new command is a file under `internal/cli`, registered with the root command. Keep the
command file small and put real logic in a sibling package so it can be tested without a
terminal.

## Invariants, and why

These are not style preferences. Breaking one breaks the product.

- **Be conservative in what you emit, liberal in what you accept.** Accept the form a user
  would naturally reach for (an address with or without brackets, a name with or without a
  trailing dot, a flag or a positional). Emit something strict and predictable.
- **An error is one clear sentence that says what to do next**, never a stack trace and
  never an opaque code. If a command needs a key, say so and say how to get one.
- **The keyless half must stay keyless.** A large part of this tool works with no account:
  verification, RDAP, encryption to an agent's DANE-discovered key, public graph reads. Do
  not add a key check to a path that does not need one, and never let a keyless path fall
  back to some ambient credential.
- **Never print, log, or embed a credential.** Not a key, not a token, not in a debug
  branch, not in a test fixture that looks real. Tests use obvious placeholders.
- **CGO stays disabled and the binary stays static.** A new third-party dependency has to
  earn its place; prefer the standard library.
- **Tests are self-contained.** No live network and no external service, ever. Use an
  in-process server and fixtures. A test that reaches the internet is a flaky test and a CI
  outage waiting to happen.
- Every Go file carries the SPDX header:
  ```go
  // SPDX-License-Identifier: MIT
  // Copyright (c) 2026 viaGraph B.V. (Whisper Security)
  ```

## Things that have bitten people here

- **Adding a command is not finishing a command.** A command nobody can discover is the
  same as one that does not exist. A new command needs its one-line summary (it appears in
  `whisper --help`), and if it is part of the product surface it belongs in the docs too.
- **Windows is a supported platform, and it is not POSIX.** A fixture that relies on
  `chmod` to make something unreadable does nothing against a Windows DACL, so a test built
  that way passes everywhere and proves nothing on the platform it was written for.
- **Do not weaken a check to make a build pass.** No skipped test, no lowered threshold, no
  deleted assertion. If a check is wrong, fix the check and say why in the commit.

## Commits and pull requests

Conventional commits: `feat:`, `fix:`, `perf:`, `docs:`, `refactor:`, `test:`, `chore:`.
Write the subject in the imperative and say in the body what changed and why, not what the
diff already shows.

Do not add co-author trailers, tool names, or generation notices to commits, pull requests,
or release notes.
