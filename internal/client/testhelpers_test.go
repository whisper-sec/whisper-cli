// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

// testhelpers_test.go holds the fixtures more than one test file in this package needs.
// They live here rather than in whichever file happened to declare them first, so moving
// or removing a test file never takes another file's fixture with it.

// deadBase is a base URL nothing listens on, so a dial to it fails fast rather than
// hanging: the "this endpoint is unreachable" fixture.
const deadBase = "http://127.0.0.1:1"
