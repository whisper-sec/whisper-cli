// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"encoding/hex"
	"testing"
)

func TestIANARootAnchors_WellFormed(t *testing.T) {
	anchors := IANARootAnchors()
	if len(anchors) < 2 {
		t.Fatalf("want >=2 root anchors (KSK-2017 + KSK-2024), got %d", len(anchors))
	}
	seen := map[uint16]bool{}
	for _, a := range anchors {
		seen[a.KeyTag] = true
		if a.Algorithm != 8 {
			t.Errorf("anchor %d: algorithm = %d, want 8 (RSASHA256)", a.KeyTag, a.Algorithm)
		}
		if a.DigestType != 2 {
			t.Errorf("anchor %d: digest type = %d, want 2 (SHA-256)", a.KeyTag, a.DigestType)
		}
		b, err := hex.DecodeString(a.Digest)
		if err != nil {
			t.Errorf("anchor %d: digest not hex: %v", a.KeyTag, err)
		}
		if len(b) != 32 {
			t.Errorf("anchor %d: digest = %d bytes, want 32 (SHA-256)", a.KeyTag, len(b))
		}
	}
	// The two currently-published root KSKs.
	if !seen[20326] {
		t.Error("missing KSK-2017 (key tag 20326)")
	}
	if !seen[38696] {
		t.Error("missing KSK-2024 (key tag 38696)")
	}
}

func TestAnchorsAsDS_Preserved(t *testing.T) {
	ds := anchorsAsDS(IANARootAnchors())
	if len(ds) != len(IANARootAnchors()) {
		t.Fatalf("anchorsAsDS lost anchors: %d != %d", len(ds), len(IANARootAnchors()))
	}
	for _, d := range ds {
		if d.Hdr.Name != "." {
			t.Errorf("root anchor DS owner = %q, want .", d.Hdr.Name)
		}
	}
}
