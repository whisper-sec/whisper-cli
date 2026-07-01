// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// publishAnchorTXT places a SIGNED TXT RRset for owner into the hierarchy's child zone.
func publishAnchorTXT(t *testing.T, h *hierarchy, owner string, values []string) {
	t.Helper()
	rrs := make([]dns.RR, 0, len(values)+1)
	for _, v := range values {
		rrs = append(rrs, &dns.TXT{
			Hdr: dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{v},
		})
	}
	sig := signRRSet(t, h.childZSK, h.child, rrs, h.now)
	h.res.set(owner, dns.TypeTXT, append(rrs, sig))
}

func p256SpkiB64(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal p256 spki: %v", err)
	}
	kid := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(der), hex.EncodeToString(kid[:])
}

func ed25519SpkiB64(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal ed25519 spki: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), pub
}

func TestDNSKeys_HappyPathDerivesKidsAndKeyIDs(t *testing.T) {
	const zone = "agents.example."
	h := buildHierarchy(t, zone, "_unused."+zone, strings.Repeat("ab", 32))

	idB64, wantKid := p256SpkiB64(t)
	edB64, edPub := ed25519SpkiB64(t)
	publishAnchorTXT(t, h, "_whisper-identity."+zone,
		[]string{"v=whisper1; k=p256; p=" + idB64})
	publishAnchorTXT(t, h, "_whisper-ledger."+zone,
		[]string{"v=whisper1; k=ed25519; n=whisper.online/ledger; p=" + edB64})

	keys, note := fetchDNSAnchoredKeys(context.Background(), h.validator(), zone)
	if keys == nil {
		t.Fatalf("expected a key set, got nil (%s)", note)
	}
	if _, ok := keys.JWKS[wantKid]; !ok || len(keys.JWKS) != 1 {
		t.Fatalf("expected exactly the derived kid %s in the JWKS, got %v", wantKid, keys.JWKS)
	}
	if len(keys.Ledger) != 1 {
		t.Fatalf("expected 1 ledger key, got %d (%s)", len(keys.Ledger), note)
	}
	// The derived C2SP key-id must equal the signed-note formula over (n, raw).
	kh := sha256.New()
	kh.Write([]byte("whisper.online/ledger"))
	kh.Write([]byte{'\n', 0x01})
	kh.Write(edPub)
	if want := hex.EncodeToString(kh.Sum(nil)[:4]); keys.Ledger[0].KeyID != want {
		t.Fatalf("ledger key-id = %s, want %s", keys.Ledger[0].KeyID, want)
	}
	if keys.IdentityName != "_whisper-identity.agents.example" ||
		keys.LedgerName != "_whisper-ledger.agents.example" {
		t.Fatalf("anchor names not recorded: %q / %q", keys.IdentityName, keys.LedgerName)
	}
}

func TestDNSKeys_LiveWhisperLedgerKeyIDGolden(t *testing.T) {
	// GOLDEN against the production key derivation: the PUBLIC whisper.online ledger key
	// (served at /checkpoint/key) must derive key-id 8a3a5df0 under its C2SP name -- the
	// exact value the live checkpoint signature line embeds.
	lk, ok := parseLedgerKeyTXT("v=whisper1; k=ed25519; n=whisper.online/ledger;" +
		" p=MCowBQYDK2VwAyEApyTBKL3bSJO7kBbdw4FqJsjREW23jNP07HybKByIabg=")
	if !ok {
		t.Fatal("the live ledger key TXT did not parse")
	}
	if lk.KeyID != "8a3a5df0" {
		t.Fatalf("derived key-id = %s, want 8a3a5df0", lk.KeyID)
	}
	if lk.PublicKey != "pyTBKL3bSJO7kBbdw4FqJsjREW23jNP07HybKByIabg=" {
		t.Fatalf("raw key mismatch: %s", lk.PublicKey)
	}
}

func TestDNSKeys_UnsignedTXTIsUnavailableNotTrusted(t *testing.T) {
	// TXT answers WITHOUT a valid RRSIG chain must never become trust anchors: the arm is
	// unavailable (nil set), NOT accepted.
	const zone = "agents.example."
	h := buildHierarchy(t, zone, "_unused."+zone, strings.Repeat("ab", 32))
	idB64, _ := p256SpkiB64(t)
	// Set the TXT with NO RRSIG at all.
	h.res.set("_whisper-identity."+zone, dns.TypeTXT, []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: "_whisper-identity." + zone, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=whisper1; k=p256; p=" + idB64},
	}})
	keys, note := fetchDNSAnchoredKeys(context.Background(), h.validator(), zone)
	if keys != nil {
		t.Fatalf("expected NO keys from an unsigned RRset, got %+v", keys)
	}
	if !strings.Contains(note, "UNSIGNED") && !strings.Contains(note, "NXDOMAIN") {
		t.Fatalf("expected the note to say why, got: %s", note)
	}
}

func TestDNSKeys_MalformedRecordsAreSkippedValidOnesKept(t *testing.T) {
	const zone = "agents.example."
	h := buildHierarchy(t, zone, "_unused."+zone, strings.Repeat("ab", 32))
	idB64, wantKid := p256SpkiB64(t)
	edB64, _ := ed25519SpkiB64(t)
	publishAnchorTXT(t, h, "_whisper-identity."+zone, []string{
		"v=whisper1; k=p256; p=!!!not-base64!!!",   // undecodable p
		"v=whisper2; k=p256; p=" + idB64,           // wrong version
		"v=whisper1; k=p256",                       // missing p
		"v=whisper1; k=p256; p=" + edB64,           // WRONG algorithm under k=p256
		"v=whisper1;  K=P256 ;  p=" + idB64 + "  ", // liberal spacing/case -- the ONE valid record
	})
	keys, note := fetchDNSAnchoredKeys(context.Background(), h.validator(), zone)
	if keys == nil {
		t.Fatalf("expected the valid record to survive, got nil (%s)", note)
	}
	if len(keys.JWKS) != 1 {
		t.Fatalf("expected exactly 1 valid key, got %d", len(keys.JWKS))
	}
	if _, ok := keys.JWKS[wantKid]; !ok {
		t.Fatalf("the surviving key is not the valid one: %v", keys.JWKS)
	}
	if len(keys.Ledger) != 0 {
		t.Fatalf("no ledger RRset was published; got %d keys", len(keys.Ledger))
	}
}

func TestDNSKeys_AllMalformedIsUnavailable(t *testing.T) {
	const zone = "agents.example."
	h := buildHierarchy(t, zone, "_unused."+zone, strings.Repeat("ab", 32))
	publishAnchorTXT(t, h, "_whisper-identity."+zone, []string{"v=whisper1; k=p256; p=garbage"})
	publishAnchorTXT(t, h, "_whisper-ledger."+zone, []string{"not even a tag list"})
	keys, note := fetchDNSAnchoredKeys(context.Background(), h.validator(), zone)
	if keys != nil {
		t.Fatalf("expected nil for an all-malformed anchor, got %+v", keys)
	}
	if note == "" {
		t.Fatal("expected a human note explaining the unavailability")
	}
}

func TestDNSKeys_LedgerRecordRequiresTheKeyName(t *testing.T) {
	// n= is load-bearing (the C2SP key-id is derived from it) -- a record without it is skipped.
	edB64, _ := ed25519SpkiB64(t)
	if _, ok := parseLedgerKeyTXT("v=whisper1; k=ed25519; p=" + edB64); ok {
		t.Fatal("a ledger record without n= must not parse")
	}
}

func TestDNSKeys_CrossCheckJWKSSemantics(t *testing.T) {
	idB64, kid := p256SpkiB64(t)
	anchored := JWKSet{}
	jwk, _ := parseIdentityKeyTXT("v=whisper1; k=p256; p=" + idB64)
	anchored[jwk.Kid] = jwk
	if jwk.Kid != kid {
		t.Fatalf("derived kid mismatch: %s vs %s", jwk.Kid, kid)
	}

	// 1) Agreement (HTTPS serves the same key under the same kid) ⇒ nil.
	agree := &fakeFetcher{get: func(string) ([]byte, int, error) {
		return []byte(`{"keys":[` + jwkJSON(jwk) + `]}`), 200, nil
	}}
	if err := crossCheckJWKS(context.Background(), agree, []string{"https://x/jwks"}, anchored); err != nil {
		t.Fatalf("agreement must pass: %v", err)
	}

	// 2) Disagreement (same kid, different key material) ⇒ explicit error.
	liarPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	liar := jwkFor(liarPriv, jwk.Kid)
	lie := &fakeFetcher{get: func(string) ([]byte, int, error) {
		return []byte(`{"keys":[` + jwkJSON(liar) + `]}`), 200, nil
	}}
	err := crossCheckJWKS(context.Background(), lie, []string{"https://x/jwks"}, anchored)
	if err == nil || !strings.Contains(err.Error(), "DISAGREES") {
		t.Fatalf("expected an explicit disagreement error, got: %v", err)
	}

	// 3) Unavailable HTTPS ⇒ nil (DNS is primary; nothing to cross-check).
	down := &fakeFetcher{get: func(string) ([]byte, int, error) { return nil, 0, errString("down") }}
	if err := crossCheckJWKS(context.Background(), down, []string{"https://x/jwks"}, anchored); err != nil {
		t.Fatalf("an unavailable JWKS must not fail the cross-check: %v", err)
	}
}

func TestDNSKeys_LedgerKeyByID(t *testing.T) {
	edB64, edPub := ed25519SpkiB64(t)
	lk, ok := parseLedgerKeyTXT("v=whisper1; k=ed25519; n=whisper.online/ledger; p=" + edB64)
	if !ok {
		t.Fatal("ledger TXT did not parse")
	}
	set := &DNSAnchoredKeys{}
	set.Ledger = append(set.Ledger, lk)
	kh := sha256.New()
	kh.Write([]byte("whisper.online/ledger"))
	kh.Write([]byte{'\n', 0x01})
	kh.Write(edPub)
	sum := kh.Sum(nil)
	id := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	if set.ledgerKeyByID(id) == nil {
		t.Fatal("the derived key-id must select the key")
	}
	if set.ledgerKeyByID(id+1) != nil {
		t.Fatal("a foreign key-id must select nothing (fail-closed)")
	}
	var nilSet *DNSAnchoredKeys
	if nilSet.ledgerKeyByID(id) != nil {
		t.Fatal("a nil set selects nothing")
	}
}
