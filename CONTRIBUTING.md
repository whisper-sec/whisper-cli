# Contributing to whisper

Thanks for your interest in improving the Whisper CLI. Contributions of all sizes are
welcome — bug reports, fixes, docs, and features.

## Getting started

Requires **Go 1.24+**.

```sh
git clone https://github.com/whisper-sec/whisper-cli
cd whisper-cli
go build ./...
go test ./...
```

Run the binary:

```sh
go run ./cmd/whisper --help
```

## Before you open a pull request

The CI checks (see `.github/workflows/ci.yml`) must pass. Run them locally first:

```sh
go build ./...     # everything compiles
go vet ./...       # no vet findings
go test ./...      # all tests pass
gofmt -l .         # prints nothing → formatting is clean
```

`gofmt -l .` must print nothing. If it lists a file, run `gofmt -w <file>` (or `gofmt -w
.`).

## Guidelines

- **Be conservative in what you emit, liberal in what you accept.** Output should be
  strict and predictable; input should be handled gracefully, and errors should be one
  clear, helpful sentence — never an opaque stack trace.
- Keep the binary **static and dependency-light**. CGO stays disabled; new third-party
  dependencies should earn their place.
- Add tests for new behavior. Tests must be **self-contained** — no live network, no
  external services. Use in-process servers and fixtures.
- Match the existing style. Every Go file carries the SPDX header:
  ```go
  // SPDX-License-Identifier: MIT
  // Copyright (c) 2026 viaGraph B.V. (Whisper Security)
  ```
- One logical change per pull request, with a clear description of what and why.

## Reporting bugs

Open a [GitHub issue](https://github.com/whisper-sec/whisper-cli/issues) with steps to
reproduce, what you expected, and what happened. Include your OS/arch and the output of
`whisper --version`.

For **security** issues, do not open a public issue — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
