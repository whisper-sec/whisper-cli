// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testChild = "agents.example."
	testLeaf  = "_443._tcp.aa.te.agents.example."
	testTLSA  = "bbf5bdd83ff6a881e30cb0f7632194054d9a19c0cf706d49879d69c820e564da"
)

func TestValidateRRSet_HappyChainToAnchor(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	rrs, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err != nil {
		t.Fatalf("expected the signed TLSA to validate to the anchor, got: %v", err)
	}
	if len(rrs) != 1 {
		t.Fatalf("want 1 TLSA, got %d", len(rrs))
	}
	if tlsa, ok := rrs[0].(*dns.TLSA); !ok || tlsa.Certificate != testTLSA {
		t.Fatalf("validated TLSA rdata mismatch: %+v", rrs[0])
	}
}

func TestValidateRRSet_TamperedTLSAFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Mutate the RDATA AFTER signing — the RRSIG no longer covers it.
	msg := h.res.answers[rkey(testLeaf, dns.TypeTLSA)]
	msg.Answer[0].(*dns.TLSA).Certificate = "deadbeef" + testTLSA[8:]
	if _, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL for a tampered TLSA rdata")
	}
}

func TestValidateRRSet_MissingRRSIGFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Strip the RRSIG from the leaf answer.
	msg := h.res.answers[rkey(testLeaf, dns.TypeTLSA)]
	kept := msg.Answer[:0]
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); !ok {
			kept = append(kept, rr)
		}
	}
	msg.Answer = kept
	if _, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL for an unsigned (no RRSIG) answer")
	}
}

func TestValidateRRSet_WrongAnchorFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// A trust anchor whose digest does not match the served root KSK.
	bad := []AnchorDS{{
		KeyTag:     h.anchors[0].KeyTag,
		Algorithm:  h.anchors[0].Algorithm,
		DigestType: h.anchors[0].DigestType,
		Digest:     "00" + h.anchors[0].Digest[2:],
	}}
	v := NewValidator(h.res, bad, h.now)
	if _, err := v.ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL when the root DNSKEY is not anchored by the trust anchor")
	}
}

func TestValidateRRSet_BrokenDSChainFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Corrupt the child's DS digest — the child DNSKEY is now unanchored.
	msg := h.res.answers[rkey(testChild, dns.TypeDS)]
	msg.Answer[0].(*dns.DS).Digest = "00" + msg.Answer[0].(*dns.DS).Digest[2:]
	if _, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL for a corrupted DS (broken chain of trust)")
	}
}

func TestValidateRRSet_ExpiredSignatureFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Evaluate 30 days in the future — beyond the signature validity window.
	v := NewValidator(h.res, h.anchors, h.now.Add(30*24*time.Hour))
	if _, err := v.ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL for an expired RRSIG")
	}
}

func TestValidateRRSet_InsecureDelegationFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Remove the child's DS entirely — an insecure delegation cannot be proven trustlessly.
	delete(h.res.answers, rkey(testChild, dns.TypeDS))
	if _, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA); err == nil {
		t.Fatal("expected FAIL for an insecure delegation (no DS)")
	}
}
