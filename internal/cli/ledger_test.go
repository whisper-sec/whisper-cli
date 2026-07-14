// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// The strong claim string is printed verbatim in PINNED mode; in UNPINNED mode it MUST carry the
// "per server-published witness policy" qualifier so a tool scraping only the `claim` field cannot
// mistake it for an independently-verified guarantee.
const strongLedgerClaim = "publicly verifiable / split-view-resistant"

func TestLedgerClaimRowUnpinnedCarriesQualifier(t *testing.T) {
	got := ledgerClaimRow(false)
	if !strings.HasPrefix(got, strongLedgerClaim) {
		t.Fatalf("unpinned claim must start with the strong claim; got %q", got)
	}
	if !strings.Contains(got, "per server-published witness policy") {
		t.Fatalf("unpinned claim must carry the server-policy qualifier; got %q", got)
	}
	if !strings.Contains(got, "--witness-key") {
		t.Fatalf("unpinned claim must point at --witness-key for independent verification; got %q", got)
	}
	if got == strongLedgerClaim {
		t.Fatalf("unpinned claim must NOT be the bare strong claim (missing the caveat)")
	}
}

func TestLedgerClaimRowPinnedHasNoQualifier(t *testing.T) {
	got := ledgerClaimRow(true)
	if got != strongLedgerClaim {
		t.Fatalf("pinned claim must be the bare strong claim with no qualifier; got %q", got)
	}
}
