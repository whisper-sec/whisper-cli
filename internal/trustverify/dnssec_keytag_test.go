// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A key tag is a 16-bit checksum over the DNSKEY RDATA, and the flags word enters it as a
// plain 16-bit addend, so a key that collides with any chosen tag is a search over one key's
// flags. These tests make such keys and use them the way a tampering resolver would.

// collidingKey mints a zone key for zone whose key tag equals target. The ZONE flag stays set
// so the key is one RRSIG.Verify will accept.
func collidingKey(t *testing.T, zone string, target uint16) testKey {
	t.Helper()
	for attempt := 0; attempt < 64; attempt++ {
		k := genKey(t, zone, 256)
		for f := 0; f < 1<<16; f++ {
			k.dnskey.Flags = uint16(f) | dns.ZONE
			if k.dnskey.KeyTag() == target {
				return k
			}
		}
	}
	t.Fatalf("no key for %s collides with tag %d after 64 keys", zone, target)
	return testKey{}
}

func forgedTLSA(t *testing.T, h *hierarchy, owner string, by testKey) {
	t.Helper()
	tlsa := &dns.TLSA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: "bb"}
	h.res.set(owner, dns.TypeTLSA, []dns.RR{tlsa, signRRSet(t, by, h.child, []dns.RR{tlsa}, h.now)})
}

// The forgery: the resolver adds a key that shares the DS-anchored KSK's tag, signs the DNSKEY
// RRset with it, and signs a TLSA of its choosing with it too. The DS authenticates the KSK, so
// only the KSK's own signature may admit the set.
func TestKeyTag_CollidingKeyCannotSignTheDNSKEYSet(t *testing.T) {
	const owner = "_443._tcp.a.example."
	h := buildHierarchy(t, "example.", owner, "aa")
	if _, err := h.validator().ValidateRRSet(context.Background(), owner, dns.TypeTLSA); err != nil {
		t.Fatalf("control: the real chain must validate, got %v", err)
	}

	evil := collidingKey(t, "example.", h.childKSK.dnskey.KeyTag())
	keys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey, evil.dnskey}
	h.res.set("example.", dns.TypeDNSKEY, append(append([]dns.RR{}, keys...),
		signRRSet(t, evil, "example.", keys, h.now)))
	forgedTLSA(t, h, owner, evil)

	rrs, err := h.validator().ValidateRRSet(context.Background(), owner, dns.TypeTLSA)
	if err == nil {
		t.Fatalf("a key colliding with the KSK's tag admitted the DNSKEY set and forged %v", rrs)
	}
	if _, kerr := h.validator().keyForZone(context.Background(), "example."); kerr == nil {
		t.Fatal("the DNSKEY set signed only by the colliding key was accepted as anchored")
	}
}

// A genuine collision is not an attack: the zone holds two real keys that happen to share a
// tag, and the DS-anchored one signs the set. That must keep validating.
func TestKeyTag_BenignCollisionStillValidates(t *testing.T) {
	const owner = "_443._tcp.a.example."
	h := buildHierarchy(t, "example.", owner, "aa")
	twin := collidingKey(t, "example.", h.childKSK.dnskey.KeyTag())
	keys := []dns.RR{twin.dnskey, h.childKSK.dnskey, h.childZSK.dnskey} // the twin first, on purpose
	h.res.set("example.", dns.TypeDNSKEY, append(append([]dns.RR{}, keys...),
		signRRSet(t, h.childKSK, "example.", keys, h.now)))
	if _, err := h.validator().ValidateRRSet(context.Background(), owner, dns.TypeTLSA); err != nil {
		t.Fatalf("a set signed by the anchored KSK must validate beside a same-tag twin, got %v", err)
	}
}

// The DNSKEY self-signature is held to its validity window like every other RRSIG: the
// library's Verify checks the cryptography only, so a lapsed signature would otherwise pass.
func TestKeyTag_ExpiredDNSKEYSelfSignatureIsRefused(t *testing.T) {
	const owner = "_443._tcp.a.example."
	h := buildHierarchy(t, "example.", owner, "aa")
	keys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	sig := signRRSet(t, h.childKSK, "example.", keys, h.now.Add(-30*24*time.Hour)) // lapsed 16 days ago
	if err := sig.Verify(h.childKSK.dnskey, keys); err != nil {
		t.Fatalf("fixture: the lapsed signature must still be cryptographically good, got %v", err)
	}
	h.res.set("example.", dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), sig))
	if _, err := h.validator().ValidateRRSet(context.Background(), owner, dns.TypeTLSA); err == nil {
		t.Fatal("a DNSKEY set whose only self-signature has expired was accepted")
	}
}
