// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// whale_whois_test.go holds the conservative half of this verb. whois answers about
// somebody else's address, so the one thing it must never do is present a name it could
// not prove as though it had proved it.

// TestRenderWhaleWhois_AnUnprovenNameIsNotPrintedAsProven.
func TestRenderWhaleWhois_AnUnprovenNameIsNotPrintedAsProven(t *testing.T) {
	view := whaleWhoisView{
		Target:       "2a04:2a01:1:4::b",
		Address:      "2a04:2a01:1:4::b",
		PTRValidated: false,
		PTRNote:      "PTR not validated: no DS at the parent",
		TrustAnchor:  whoisAnchorLine,
		ValidatedBy:  "this client, in-process (our resolver never sets AD)",
	}
	stdout, _ := captureStd(t, func() { renderWhaleWhois(view) })
	if strings.Contains(stdout, "DNSSEC-validated here") {
		t.Fatalf("an unvalidated name was rendered as validated:\n%s", stdout)
	}
	if !strings.Contains(stdout, "not validated") {
		t.Fatalf("the reason the name is missing was not shown:\n%s", stdout)
	}
}

// TestRenderWhaleWhois_AProvenNameSaysWhereTheProofCameFrom. A reader who assumes the
// resolver validated for them will build the wrong thing later, so the answer says where
// the chain was walked.
func TestRenderWhaleWhois_AProvenNameSaysWhereTheProofCameFrom(t *testing.T) {
	view := whaleWhoisView{
		Target:       "2a04:2a01:1:4::b",
		Address:      "2a04:2a01:1:4::b",
		PTR:          "db-01.t9f.agents.whisper.online",
		PTRValidated: true,
		Forward:      "AAAA(db-01.t9f.agents.whisper.online) contains 2a04:2a01:1:4::b",
		TrustAnchor:  whoisAnchorLine,
		ValidatedBy:  "this client, in-process (our resolver never sets AD)",
		RDAPHandle:   "abc", RDAPName: "db-01", RDAPHolder: "Example B.V.",
	}
	stdout, stderr := captureStd(t, func() { renderWhaleWhois(view) })
	if !strings.Contains(stdout, "db-01.t9f.agents.whisper.online") {
		t.Fatalf("the proven name was not printed:\n%s", stdout)
	}
	if !strings.Contains(stdout, "forward confirm") {
		t.Fatalf("the forward confirmation was dropped, so the name rests on the holder's word alone:\n%s", stdout)
	}
	if !strings.Contains(stderr, "IANA") || !strings.Contains(stderr, "never sets AD") {
		t.Fatalf("the trust anchor and where validation happened were not stated:\n%s", stderr)
	}
}

// TestRenderWhaleWhois_AnRDAPOutageIsStated, not rendered as an address nobody holds.
func TestRenderWhaleWhois_AnRDAPOutageIsStated(t *testing.T) {
	view := whaleWhoisView{
		Target: "2a04:2a01:1:4::b", Address: "2a04:2a01:1:4::b",
		PTR: "db-01.example", PTRValidated: true,
		TrustAnchor: whoisAnchorLine, ValidatedBy: "this client",
		RDAPNote: "RDAP did not answer: connection refused",
	}
	_, stderr := captureStd(t, func() { renderWhaleWhois(view) })
	if !strings.Contains(stderr, "RDAP did not answer") {
		t.Fatalf("an RDAP outage was swallowed:\n%s", stderr)
	}
}

// TestFillRDAP_LiftsTheFieldsAPersonReads, and tolerates every one of them being absent.
func TestFillRDAP_LiftsTheFieldsAPersonReads(t *testing.T) {
	body := json.RawMessage(`{
	  "handle":"a126fa16e389f9bf6",
	  "name":"db-ledger-01",
	  "startAddress":"2a04:2a01::1",
	  "endAddress":"2a04:2a01::2",
	  "country":"NL",
	  "status":["active","validated"],
	  "entities":[{"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","viaGraph B.V."]]]}]
	}`)
	var view whaleWhoisView
	fillRDAP(&view, body)
	if view.RDAPHandle != "a126fa16e389f9bf6" || view.RDAPName != "db-ledger-01" {
		t.Fatalf("handle/name not lifted: %+v", view)
	}
	if view.RDAPRange != "2a04:2a01::1 - 2a04:2a01::2" {
		t.Fatalf("range = %q", view.RDAPRange)
	}
	if view.RDAPStatus != "active, validated" {
		t.Fatalf("status = %q", view.RDAPStatus)
	}
	if view.RDAPHolder != "viaGraph B.V." {
		t.Fatalf("holder = %q", view.RDAPHolder)
	}

	// Liberal in what it accepts: an object with none of those fields is not an error.
	var empty whaleWhoisView
	fillRDAP(&empty, json.RawMessage(`{}`))
	if empty.RDAPNote != "" {
		t.Fatalf("an empty but valid RDAP object produced a complaint: %q", empty.RDAPNote)
	}

	// Conservative in what it emits: something that is not an object is said out loud.
	var broken whaleWhoisView
	fillRDAP(&broken, json.RawMessage(`["not","an","object"]`))
	if broken.RDAPNote == "" {
		t.Fatal("a non-object RDAP body was accepted silently")
	}
}

// TestFillRDAP_ASingleAddressRangeIsNotRenderedAsARange.
func TestFillRDAP_ASingleAddressRangeIsNotRenderedAsARange(t *testing.T) {
	var view whaleWhoisView
	fillRDAP(&view, json.RawMessage(`{"startAddress":"2a04:2a01::1","endAddress":"2a04:2a01::1"}`))
	if strings.Contains(view.RDAPRange, "-") {
		t.Fatalf("a single address rendered as a range: %q", view.RDAPRange)
	}
	if view.RDAPRange != "2a04:2a01::1" {
		t.Fatalf("range = %q", view.RDAPRange)
	}
}
