// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
package buildid

import "testing"

// The point of SourceRef is that it is present on a release and ABSENT
// everywhere else, so both halves are asserted. A test that only checks the
// present case passes on a build that stamps the tag unconditionally, which is
// the defect: a development binary claiming a mirror tag that does not exist is
// a worse pointer than no pointer, and it is the same class of invention the
// build id was added to stop.
func TestSourceIsAbsentUnlessStamped(t *testing.T) {
	prev := SourceRef
	t.Cleanup(func() { SourceRef = prev })

	SourceRef = ""
	if got := Source(); got != "" {
		t.Fatalf("an unstamped build must report no source, got %q", got)
	}

	// Whitespace is not a value either: a linker flag that resolved to nothing
	// must read as absent rather than as a blank pointer a caller would print.
	SourceRef = "   "
	if got := Source(); got != "" {
		t.Fatalf("a blank stamp must report no source, got %q", got)
	}

	SourceRef = "github.com/whisper-sec/whisper-cli@v0.214.0"
	if got := Source(); got != "github.com/whisper-sec/whisper-cli@v0.214.0" {
		t.Fatalf("a stamped build must report its public source, got %q", got)
	}
}

// Source answers a different question from ID, and the two must not be wired to
// the same value. This fails if someone later "simplifies" one into the other.
func TestSourceIsNotTheBuildID(t *testing.T) {
	prevS, prevStamp := SourceRef, Stamped
	t.Cleanup(func() { SourceRef, Stamped = prevS, prevStamp })

	SourceRef = "github.com/whisper-sec/whisper-cli@v0.214.0"
	if Source() == ID() {
		t.Fatal("source and build id must stay distinct: one is the public tree, the other is the commit that built these bytes")
	}
}
