// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the DNS-anchored key parsers and the DANE pin
// extraction edge branches. These records come out of DNS answers an attacker can shape, so
// every skip/reject branch is a security property: a malformed record must be DROPPED (never
// half-trusted), and only an exact whisper1 p256/ed25519 SPKI record may mint a key.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDeepenTV_ParseLedgerKeyTXT_RejectsBadKeyMaterial(t *testing.T) {
	// A P-256 SPKI smuggled into an ed25519 record: parses as DER but is the wrong key type.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	ecSpki, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cases := []struct {
		name string
		txt  string
	}{
		{"badBase64", "v=whisper1; k=ed25519; n=log/x; p=!!!not-base64!!!"},
		{"badDER", "v=whisper1; k=ed25519; n=log/x; p=" + base64.StdEncoding.EncodeToString([]byte("junk"))},
		{"wrongKeyType", "v=whisper1; k=ed25519; n=log/x; p=" + base64.StdEncoding.EncodeToString(ecSpki)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseLedgerKeyTXT(tc.txt); ok {
				t.Fatalf("record must be rejected: %s", tc.txt)
			}
		})
	}
}

func TestDeepenTV_ParseTagList_SkipsMalformedPartsAndKeepsFirstValue(t *testing.T) {
	tags := parseTagList("noequals; =leadingeq; ; v=1; v=2;  K = a ;")
	if tags["v"] != "1" {
		t.Fatalf("first value must win: v=%q", tags["v"])
	}
	if tags["k"] != "a" {
		t.Fatalf("tags must be lowercased + trimmed: k=%q", tags["k"])
	}
	if _, ok := tags[""]; ok {
		t.Fatal("a part with a leading '=' must be skipped, not indexed under \"\"")
	}
	if _, ok := tags["noequals"]; ok {
		t.Fatal("a part without '=' must be skipped")
	}
}

func TestDeepenTV_CrossCheckJWKS_EmptyAnchoredSetIsNoop(t *testing.T) {
	// With no anchored keys there is nothing to cross-check: even a lying JWKS surface must
	// not produce an error (there is no DNS truth to disagree with).
	liar := &fakeFetcher{get: func(string) ([]byte, int, error) {
		return []byte(`{"keys":[{"kid":"x","kty":"EC","crv":"P-256","x":"a","y":"b"}]}`), 200, nil
	}}
	if err := crossCheckJWKS(context.Background(), liar, []string{"https://x/jwks"}, JWKSet{}); err != nil {
		t.Fatalf("empty anchored set must be a no-op, got: %v", err)
	}
}

func TestDeepenTV_CrossCheckJWKS_UnparseableAndForeignKidsIgnored(t *testing.T) {
	_, jwk, set := deepentrustverify_signingKey(t)
	// URL 1 serves garbage (skipped), URL 2 serves a kid OUTSIDE the anchored set (ignored:
	// only same-kid material can disagree). Neither may fail the check.
	other := JWK{Kid: "someone-else", Kty: "EC", Crv: "P-256", X: jwk.X, Y: jwk.Y}
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) {
		if strings.Contains(url, "one") {
			return []byte("garbage"), 200, nil
		}
		return []byte(`{"keys":[` + jwkJSON(other) + `]}`), 200, nil
	}}
	err := crossCheckJWKS(context.Background(), f, []string{"https://one/jwks", "https://two/jwks"}, set)
	if err != nil {
		t.Fatalf("unparseable bodies and foreign kids must be ignored, got: %v", err)
	}
}

func TestDeepenTV_FetchDNSAnchoredKeys_EmptyZoneUsesDefaultAnchorZone(t *testing.T) {
	// A blank zone must fall back to the production DefaultKeyAnchorZone - the note names the
	// looked-up owner, so a mutation of the default is visible here.
	h := buildHierarchy(t, testChild, testLeaf, testTLSA)
	keys, note := fetchDNSAnchoredKeys(context.Background(), h.validator(), "  ")
	if keys != nil {
		t.Fatalf("no anchor TXT exists in this hierarchy; want nil keys, got: %+v", keys)
	}
	if !strings.Contains(note, identityAnchorLabel+"."+DefaultKeyAnchorZone) {
		t.Fatalf("note must reference the default anchor zone owner, got: %s", note)
	}
}

func TestDeepenTV_ExtractDANEEEPin_SkipsNonTLSARecords(t *testing.T) {
	// A validated answer often carries the RRSIG alongside the TLSA; only TLSA records may
	// contribute pins.
	tlsa := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: "x.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage: 3, Selector: 1, MatchingType: 1,
		Certificate: testTLSA,
	}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"noise"}}
	pins, err := ExtractDANEEEPin([]dns.RR{txt, tlsa})
	if err != nil {
		t.Fatalf("ExtractDANEEEPin: %v", err)
	}
	if len(pins) != 1 || pins[0].Hex() != testTLSA {
		t.Fatalf("want exactly the one TLSA pin, got: %+v", pins)
	}
}

func TestDeepenTV_ExtractDANEEEPin_RejectsMalformedAssociation(t *testing.T) {
	cases := []struct {
		name string
		cert string
	}{
		{"notHex", "zz" + testTLSA[2:]},
		{"tooShort", "abcd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tlsa := &dns.TLSA{
				Hdr:   dns.RR_Header{Name: "x.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
				Usage: 3, Selector: 1, MatchingType: 1,
				Certificate: tc.cert,
			}
			if _, err := ExtractDANEEEPin([]dns.RR{tlsa}); err == nil ||
				!strings.Contains(err.Error(), "not a 32-byte SHA-256") {
				t.Fatalf("want the malformed-association error, got: %v", err)
			}
		})
	}
}

func TestDeepenTV_ConstEq_LengthMismatchIsFalse(t *testing.T) {
	if constEq([]byte{1}, []byte{1, 2}) {
		t.Fatal("length mismatch must be false")
	}
	if !constEq([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("equal slices must be true")
	}
	if constEq([]byte{1, 2}, []byte{1, 3}) {
		t.Fatal("differing content must be false")
	}
}
