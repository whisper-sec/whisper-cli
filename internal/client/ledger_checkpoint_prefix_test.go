// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"strings"
	"testing"
)

// REGRESSION: the C2SP signed-note prefix was once served as an ASCII hyphen rather than U+2014,
// so the live /checkpoint carried a "\n\n- " separator instead of the conformant "\n\n\u2014 ". A strict reader keyed only on U+2014 fails to find the body/signature
// split, mis-slices the note, and rejects it with "checkpoint root is not a 32-byte base64 hash" -
// a fleet-wide `whisper verify --trustless` = NOT proven. Per Postel we now PARSE both prefixes while
// still EMITTING only the conformant one. These fixtures are REAL bytes captured live from
// https://ns1.whisper.online/checkpoint (a public, keyless endpoint), signed by the published g2 key.

// liveHyphenNote is the exact hyphen-scrubbed note the server used to serve, on the wire.
const liveHyphenNote = "whisper.online/ledger/g2\n177081\n5ZXmBakuMdOXI6tw8TPVnXJQzjHoML3fmNX3aJoK1UU=\n\n- whisper.online/ledger/g2 1A5XOlPQlPs7fPgcblBI694fiopiRMSM6CiKLi2+HwnBMAu7AFer8ZIn9fc1UzDfb9cjMVdOJPL+Pp5slRiAzFoAYgY=\n"

// liveLedgerKey is the published verification key for the g2 log (GET /checkpoint/key).
var liveLedgerKey = &LedgerKey{
	Origin:    "whisper.online/ledger/g2",
	Alg:       "Ed25519",
	KeyID:     "d40e573a",
	PublicKey: "7pSYYInKXm2TMjwAqEsoKon/d3E8SDq34V1VUrgTAm0=",
}

func TestParseCheckpointNote_AcceptsHyphenScrubbedSeparator(t *testing.T) {
	cp, err := ParseCheckpointNote(liveHyphenNote)
	if err != nil {
		t.Fatalf("the hyphen-scrubbed live note must still parse, got: %v", err)
	}
	if cp.Origin != "whisper.online/ledger/g2" {
		t.Errorf("origin = %q, want whisper.online/ledger/g2", cp.Origin)
	}
	if cp.TreeSize != 177081 {
		t.Errorf("tree_size = %d, want 177081", cp.TreeSize)
	}
	if len(cp.Root) != 32 {
		t.Errorf("root len = %d, want 32", len(cp.Root))
	}
	if cp.Sig == nil {
		t.Fatal("the log signature must be parsed from a hyphen-separated note")
	}
	if cp.KeyID != 0xd40e573a {
		t.Errorf("key-id = %08x, want d40e573a", cp.KeyID)
	}
	// The body the signature is over must NOT include the separator/signature block.
	if strings.Contains(string(cp.body), "\n\n- ") || strings.Contains(string(cp.body), "\n\n\u2014 ") {
		t.Error("the signed body must be cut BEFORE the separator, regardless of prefix variant")
	}
}

func TestVerifySignature_LiveHyphenNote(t *testing.T) {
	cp, err := ParseCheckpointNote(liveHyphenNote)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The real, live Ed25519 signature must validate over the reconstructed body - proving the
	// liberal parser sliced the exact signed bytes even though the separator was a hyphen.
	if err := cp.VerifySignature(liveLedgerKey); err != nil {
		t.Fatalf("the live signature must verify through the liberal parser, got: %v", err)
	}
}

// Both prefixes must parse to the IDENTICAL checkpoint and both must verify - the conformant U+2014
// form is what we serve once the server fix is deployed; the hyphen form is the in-flight regression.
func TestParseCheckpointNote_BothPrefixesEquivalent(t *testing.T) {
	conformantNote := strings.Replace(liveHyphenNote, "\n\n- ", "\n\n\u2014 ", 1)
	if conformantNote == liveHyphenNote {
		t.Fatal("fixture setup: the hyphen separator was not found to swap")
	}

	hy, err := ParseCheckpointNote(liveHyphenNote)
	if err != nil {
		t.Fatalf("hyphen parse: %v", err)
	}
	em, err := ParseCheckpointNote(conformantNote)
	if err != nil {
		t.Fatalf("conformant parse: %v", err)
	}
	if hy.Origin != em.Origin || hy.TreeSize != em.TreeSize || string(hy.Root) != string(em.Root) {
		t.Error("both prefix variants must decode to the same origin/size/root")
	}
	if string(hy.body) != string(em.body) {
		t.Error("the signed body bytes must be identical for both prefixes (signature is over the body only)")
	}
	if hy.KeyID != em.KeyID || string(hy.Sig) != string(em.Sig) {
		t.Error("both prefix variants must recover the same log signature")
	}
	// The conformant note (what the deployed server fix emits) must verify too.
	if err := em.VerifySignature(liveLedgerKey); err != nil {
		t.Fatalf("the conformant U+2014 note must verify, got: %v", err)
	}
}
