// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The KeyTrap bounds, measured as public-key operations (Validator.verifies), never as time.
// The attacker here holds a validly delegated zone, or sits between us and the resolver; either
// way it chooses how many signatures an RRset carries and how many keys share a tag.

const trapOwner = "_443._tcp.a.example."

// chainCost is the verifications a clean validation of trapOwner's TLSA spends: root DNSKEY,
// DS(example.), example. DNSKEY and the TLSA itself. Measured, not assumed.
func chainCost(t *testing.T) int {
	t.Helper()
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	v := h.validator()
	if _, err := v.ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA); err != nil {
		t.Fatalf("control: the real chain must validate, got %v", err)
	}
	return v.verifies
}

// bogusSigs returns n RRSIGs over rrset that name key tag `tag` in zone but were made by an
// unrelated key, so every one costs a verification and every one fails.
func bogusSigs(t *testing.T, h *hierarchy, zone string, rrset []dns.RR, tag uint16, n int) []dns.RR {
	t.Helper()
	stranger := genKey(t, zone, 256)
	out := make([]dns.RR, 0, n)
	for i := 0; i < n; i++ {
		sig := signRRSet(t, stranger, zone, rrset, h.now)
		sig.KeyTag = tag
		out = append(out, sig)
	}
	return out
}

func trapTLSA() *dns.TLSA {
	return &dns.TLSA{Hdr: dns.RR_Header{Name: trapOwner, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: "aa"}
}

// publishChildKeys serves the child DNSKEY set {KSK, ZSK, extra...}, signed by the real KSK,
// so the zone holder's own extra keys are part of a genuinely anchored set.
func publishChildKeys(t *testing.T, h *hierarchy, extra ...testKey) {
	t.Helper()
	keys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	for _, k := range extra {
		keys = append(keys, k.dnskey)
	}
	h.res.set(h.child, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...),
		signRRSet(t, h.childKSK, h.child, keys, h.now)))
}

func twins(t *testing.T, zone string, tag uint16, n int) []testKey {
	t.Helper()
	out := make([]testKey, n)
	for i := range out {
		out[i] = collidingKey(t, zone, tag)
	}
	return out
}

func wantCap(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil {
		t.Fatal("the hostile RRset validated")
	}
	if !strings.Contains(err.Error(), fragment) || !strings.Contains(err.Error(), "CVE-2023-50387") {
		t.Fatalf("want a KeyTrap refusal mentioning %q, got %v", fragment, err)
	}
}

// Many signatures, one key each: the work stops at maxVerifiesPerRRset for the RRset.
func TestKeyTrap_ManySignaturesAreBounded(t *testing.T) {
	base := chainCost(t)
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	tlsa := trapTLSA()
	sigs := bogusSigs(t, h, "example.", []dns.RR{tlsa}, h.childZSK.dnskey.KeyTag(), 200)
	h.res.set(trapOwner, dns.TypeTLSA, append([]dns.RR{tlsa}, sigs...))
	v := h.validator()
	_, err := v.ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA)
	wantCap(t, err, "more than 8 RRSIGs")
	if got, max := v.verifies, base-1+maxVerifiesPerRRset; got > max {
		t.Fatalf("200 signatures cost %d verifications, the bound is %d", got, max)
	}
}

// Colliding tags beyond maxKeysPerTag: the signature is refused before any key is tried.
func TestKeyTrap_TooManySameTagKeysRefuseTheSignature(t *testing.T) {
	base := chainCost(t)
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	publishChildKeys(t, h, twins(t, "example.", h.childZSK.dnskey.KeyTag(), maxKeysPerTag)...)
	tlsa := trapTLSA()
	h.res.set(trapOwner, dns.TypeTLSA, append([]dns.RR{tlsa},
		bogusSigs(t, h, "example.", []dns.RR{tlsa}, h.childZSK.dnskey.KeyTag(), 1)...))
	v := h.validator()
	_, err := v.ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA)
	wantCap(t, err, "share key tag")
	if got := v.verifies; got != base-1 {
		t.Fatalf("a refused signature still cost %d leaf verifications", got-(base-1))
	}
}

// The KeyTrap shape itself: colliding keys (within the per-tag bound) times many signatures.
// Unbounded this is 4 x 200 = 800 verifications; bounded it is 8.
func TestKeyTrap_CollidingKeysTimesSignaturesAreBounded(t *testing.T) {
	base := chainCost(t)
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	tag := h.childZSK.dnskey.KeyTag()
	publishChildKeys(t, h, twins(t, "example.", tag, maxKeysPerTag-1)...) // ZSK + 3 twins = 4
	tlsa := trapTLSA()
	h.res.set(trapOwner, dns.TypeTLSA, append([]dns.RR{tlsa}, bogusSigs(t, h, "example.", []dns.RR{tlsa}, tag, 200)...))
	v := h.validator()
	_, err := v.ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA)
	wantCap(t, err, "needed more than 8 signature verifications")
	if got, max := v.verifies, base-1+maxVerifiesPerRRset; got != max {
		t.Fatalf("colliding keys x signatures cost %d verifications, want exactly %d", got, max)
	}
}

// The same bounds on the DNSKEY self-signature, and the failure is memoised: a second RRset in
// the zone does not pay for the zone again.
func TestKeyTrap_DNSKEYSelfSignaturesAreBoundedAndMemoised(t *testing.T) {
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	keys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	h.res.set(h.child, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...),
		bogusSigs(t, h, "example.", keys, h.childKSK.dnskey.KeyTag(), 200)...))
	v := h.validator()
	_, err := v.keyForZone(context.Background(), "example.")
	wantCap(t, err, "needed more than 8 signature verifications")
	first := v.verifies
	if first > 2+maxVerifiesPerRRset { // root DNSKEY + DS(example.) + the bounded self-signatures
		t.Fatalf("200 DNSKEY self-signatures cost %d verifications", first)
	}
	if _, err := v.ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA); err == nil {
		t.Fatal("a leaf validated under a zone whose DNSKEY set was refused")
	}
	if v.verifies != first {
		t.Fatalf("the refused zone was proved again: %d more verifications", v.verifies-first)
	}
}

// More keys sharing the DS's tag than maxKeysPerTag: the chain is refused before any digest
// work on the excess, even though the real KSK is among them and signs the set.
func TestKeyTrap_TooManyKeysWithTheDSTagRefuseTheChain(t *testing.T) {
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	tag := h.childKSK.dnskey.KeyTag()
	tw := twins(t, "example.", tag, maxKeysPerTag)
	keys := []dns.RR{}
	for _, k := range tw {
		keys = append(keys, k.dnskey) // the twins sort first, so the cap fires before the KSK
	}
	keys = append(keys, h.childKSK.dnskey, h.childZSK.dnskey)
	h.res.set(h.child, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), signRRSet(t, h.childKSK, h.child, keys, h.now)))
	_, err := h.validator().keyForZone(context.Background(), "example.")
	wantCap(t, err, "DNSKEYs with the DS's key tag")
	if !isCapError(err) {
		t.Fatalf("the refusal must carry the KeyTrap bound's type, got %T", err)
	}
}

// The DS RRset gets the same signature bound.
func TestKeyTrap_ManyDSSignaturesAreBounded(t *testing.T) {
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	ds := h.childKSK.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: h.child, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(h.child, dns.TypeDS, append([]dns.RR{ds},
		bogusSigs(t, h, ".", []dns.RR{ds}, h.rootZSK.dnskey.KeyTag(), 200)...))
	v := h.validator()
	_, err := v.keyForZone(context.Background(), "example.")
	wantCap(t, err, "more than 8 RRSIGs")
	if v.verifies > 1+maxVerifiesPerRRset {
		t.Fatalf("200 DS signatures cost %d verifications", v.verifies)
	}
}

// Real chains are untouched: an algorithm-roll style RRset with a broken signature ahead of a
// good one validates, and the good one is found inside the bounds.
func TestKeyTrap_RealMultiSignatureRRsetValidates(t *testing.T) {
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	tlsa := trapTLSA()
	good := signRRSet(t, h.childZSK, "example.", []dns.RR{tlsa}, h.now)
	bad := bogusSigs(t, h, "example.", []dns.RR{tlsa}, h.childZSK.dnskey.KeyTag(), maxVerifiesPerRRset-1)
	h.res.set(trapOwner, dns.TypeTLSA, append(append([]dns.RR{tlsa}, bad...), good))
	if _, err := h.validator().ValidateRRSet(context.Background(), trapOwner, dns.TypeTLSA); err != nil {
		t.Fatalf("a good signature within the bounds must validate, got %v", err)
	}
}

// A DS signature naming a tag the parent's keys share past the bound is refused as a KeyTrap,
// not reported as an ordinary failed DS.
func TestKeyTrap_DSSignatureOverCollidingParentKeysIsRefused(t *testing.T) {
	h := buildHierarchy(t, "example.", trapOwner, "aa")
	tag := h.rootZSK.dnskey.KeyTag()
	keys := []dns.RR{h.rootKSK.dnskey, h.rootZSK.dnskey}
	for _, k := range twins(t, ".", tag, maxKeysPerTag) {
		keys = append(keys, k.dnskey)
	}
	h.res.set(".", dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), signRRSet(t, h.rootKSK, ".", keys, h.now)))
	_, err := h.validator().keyForZone(context.Background(), "example.")
	wantCap(t, err, "share key tag")
}

// The whole Validator stops at maxVerifiesPerValidator, however the work is spread.
func TestKeyTrap_ValidatorCeiling(t *testing.T) {
	z := newWildZone(t)
	v := z.tr.validator(z.tr.res)
	n := maxVerifiesPerValidator
	var last error
	for i := 0; i < n && last == nil; i++ {
		owner := fmt.Sprintf("r%d.whisper.online.", i)
		z.tr.txt(t, owner, z.w)
		_, last = v.ValidateRRSet(context.Background(), owner, dns.TypeTXT)
	}
	if !isCapError(last) || !strings.Contains(last.Error(), "spent its 512 signature verifications") {
		t.Fatalf("want the Validator ceiling, got %v", last)
	}
	if v.verifies != maxVerifiesPerValidator {
		t.Fatalf("the ceiling let %d verifications through", v.verifies)
	}
}
