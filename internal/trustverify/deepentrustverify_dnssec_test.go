// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the stub validator's chain-break branches. Each test
// breaks the chain of trust at one exact link (resolver outage, missing/empty/unsigned
// RRsets, an unknown DS digest, a DNSKEY set not self-signed by its SEP key) and asserts the
// validator refuses with the matching diagnostic - the fail-closed heart of "trustless".

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// deepentrustverify_errResolver injects a transport failure for exactly one (name, qtype)
// and delegates everything else to the signed test hierarchy.
type deepentrustverify_errResolver struct {
	inner   Resolver
	failKey string
}

func (r deepentrustverify_errResolver) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if rkey(name, qtype) == r.failKey {
		return nil, errString("injected resolver outage")
	}
	return r.inner.Query(ctx, name, qtype)
}

func TestDeepenTV_NewValidator_DefaultsToIANAAnchorsAndWallClock(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	v := NewValidator(h.res, nil, time.Time{})
	want := IANARootAnchors()
	if len(v.anchors) != len(want) || len(want) == 0 {
		t.Fatalf("nil anchors must default to the IANA set (%d), got %d", len(want), len(v.anchors))
	}
	for i := range want {
		if v.anchors[i] != want[i] {
			t.Fatalf("anchor %d differs from the IANA set: %+v != %+v", i, v.anchors[i], want[i])
		}
	}
	if v.now.IsZero() {
		t.Fatal("a zero now must default to the wall clock")
	}
}

func TestDeepenTV_ValidateRRSet_ResolverOutageIsAFetchError(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	v := NewValidator(deepentrustverify_errResolver{inner: h.res, failKey: rkey(testLeaf, dns.TypeTLSA)},
		h.anchors, h.now)
	_, err := v.ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "fetching TLSA") {
		t.Fatalf("want the fetch error, got: %v", err)
	}
}

func TestDeepenTV_ValidateRRSet_EmptyAnswerHasNoRecord(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// NOERROR with an empty answer section: there is nothing of the queried type to prove.
	h.res.set(testLeaf, dns.TypeTLSA, nil)
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "no TLSA record") {
		t.Fatalf("want the no-record error, got: %v", err)
	}
}

func TestDeepenTV_KeyForZone_DNSKEYResolverOutage(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	v := NewValidator(deepentrustverify_errResolver{inner: h.res, failKey: rkey(testChild, dns.TypeDNSKEY)},
		h.anchors, h.now)
	_, err := v.ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "fetching DNSKEY") {
		t.Fatalf("want the DNSKEY fetch error, got: %v", err)
	}
}

func TestDeepenTV_KeyForZone_DNSKEYNxdomainBreaksTheChain(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	delete(h.res.answers, rkey(testChild, dns.TypeDNSKEY))
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "did not resolve") {
		t.Fatalf("want the DNSKEY did-not-resolve error, got: %v", err)
	}
}

func TestDeepenTV_KeyForZone_EmptyDNSKEYAnswerBreaksTheChain(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	h.res.set(testChild, dns.TypeDNSKEY, nil)
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "has no DNSKEY") {
		t.Fatalf("want the no-DNSKEY error, got: %v", err)
	}
}

func TestDeepenTV_KeyForZone_UnknownDSDigestTypeIsNotAnAnchor(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// Republish the child DS with an unknown digest type (validly signed by the root). The
	// validator cannot recompute such a digest, so the child stays unanchored - fail closed.
	ds := h.childKSK.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: testChild, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	ds.DigestType = 99
	h.res.set(testChild, dns.TypeDS, []dns.RR{ds, signRRSet(t, h.rootZSK, ".", []dns.RR{ds}, h.now)})
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "not anchored by a valid DS") {
		t.Fatalf("want the unanchored-DNSKEY error, got: %v", err)
	}
}

func TestDeepenTV_KeyForZone_DNSKEYNotSelfSignedBySEPFails(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// The DNSKEY RRset is signed only by a key that is NOT the DS-anchored SEP key. The DS
	// anchors the KSK, and RFC 4035 needs the SEP key itself to sign the set - any other
	// signature must not close the parent->child link. The signing key's tag is forced to
	// differ from the KSK's so the test is deterministic (keys are freshly generated per run).
	foreign := genKey(t, trimDot(testChild), 256)
	for foreign.dnskey.KeyTag() == h.childKSK.dnskey.KeyTag() {
		foreign = genKey(t, trimDot(testChild), 256)
	}
	childKeys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	sig := signRRSet(t, foreign, trimDot(testChild), childKeys, h.now)
	h.res.set(testChild, dns.TypeDNSKEY, append(append([]dns.RR{}, childKeys...), sig))
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "not anchored by a valid DS") {
		t.Fatalf("want the unanchored-DNSKEY error, got: %v", err)
	}
}

func TestDeepenTV_ValidateDS_ResolverOutage(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	v := NewValidator(deepentrustverify_errResolver{inner: h.res, failKey: rkey(testChild, dns.TypeDS)},
		h.anchors, h.now)
	_, err := v.ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "fetching DS") {
		t.Fatalf("want the DS fetch error, got: %v", err)
	}
}

func TestDeepenTV_ValidateDS_EmptyAnswerIsInsecureDelegation(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	// NOERROR with no DS records: an insecure delegation, unprovable trustlessly.
	h.res.set(testChild, dns.TypeDS, nil)
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "INSECURE delegation") {
		t.Fatalf("want the insecure-delegation error, got: %v", err)
	}
}

func TestDeepenTV_ValidateDS_UnsignedDSRejected(t *testing.T) {
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	ds := h.childKSK.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: testChild, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(testChild, dns.TypeDS, []dns.RR{ds}) // no RRSIG
	_, err := h.validator().ValidateRRSet(context.Background(), testLeaf, dns.TypeTLSA)
	if err == nil || !strings.Contains(err.Error(), "is unsigned") {
		t.Fatalf("want the unsigned-DS error, got: %v", err)
	}
}
