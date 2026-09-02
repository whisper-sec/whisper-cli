// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the identity_doc step's verdict shaping. The split
// matters on tens of millions of endpoints: transport/availability trouble is a SKIP (the
// DNSSEC+DANE core still stands), while ANY cryptographic or claim mismatch - a wrong
// signature, a foreign kid, a claim that contradicts a DNSSEC-proven fact - is a FAIL.

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// deepentrustverify_idFixture is a minimal identity_doc world: one ES256 signing key (kid
// derived, as production mints them), one DANE pin, and the DNSSEC-proven facts the doc's
// claims are checked against.
type deepentrustverify_idFixture struct {
	priv *ecdsa.PrivateKey
	jwk  JWK
	kid  string
	pins []TLSAPin
	addr string
	fqdn string
}

func deepentrustverify_newIDFixture(t *testing.T) deepentrustverify_idFixture {
	t.Helper()
	priv, jwk, _ := deepentrustverify_signingKey(t)
	pin := make([]byte, 32)
	pin[0] = 0xAB
	return deepentrustverify_idFixture{
		priv: priv,
		jwk:  jwk,
		kid:  jwk.Kid,
		pins: []TLSAPin{{SHA256: pin}},
		addr: testAddr,
		fqdn: "agent.te.agents.example.",
	}
}

// doc signs an identity document over the given claims.
func (fx deepentrustverify_idFixture) doc(t *testing.T, addr, fqdn, tlsaHex string) string {
	t.Helper()
	payload := fmt.Sprintf(`{"doc":"whisper-identity","v":"1","address":"%s","fqdn":"%s",`+
		`"tenant":"te","tlsa":{"sha256":"%s"}}`, addr, fqdn, tlsaHex)
	return signES256(t, fx.priv, fx.kid, "application/whisper-identity+json", []byte(payload))
}

// fetcher serves docBody over the pinned connection and the fixture's JWKS over HTTPS.
func (fx deepentrustverify_idFixture) fetcher(docBody string, docStatus int) *fakeFetcher {
	jwks := `{"keys":[` + jwkJSON(fx.jwk) + `]}`
	return &fakeFetcher{
		get: func(url string) ([]byte, int, error) {
			if strings.Contains(url, "jwks") {
				return []byte(jwks), 200, nil
			}
			return nil, 404, nil
		},
		pinned: func(_, _, path string) ([]byte, int, error) {
			if !strings.Contains(path, "whisper-identity") {
				return nil, 404, nil
			}
			return []byte(docBody), docStatus, nil
		},
	}
}

func deepentrustverify_runIDDoc(fx deepentrustverify_idFixture, f Fetcher, pinKid string,
	dnsKeys *DNSAnchoredKeys) identityDocResult {
	return verifyIdentityDoc(context.Background(), f, "hostport", fx.fqdn, fx.addr, fx.pins,
		[]string{"https://rdap.example/.well-known/jwks.json"}, pinKid, dnsKeys)
}

func TestDeepenTV_IdentityDoc_HappyPathControl(t *testing.T) {
	// The green control the negatives below hang off: valid signature, claims == proven facts.
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), fx.pins[0].Hex())
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(doc, 200), "", nil)
	if res.status != StatusPass {
		t.Fatalf("want PASS, got %s: %s", res.status, res.detail)
	}
	if res.kid != fx.kid || res.tenant != "te" || res.anchored {
		t.Fatalf("want kid=%s tenant=te anchored=false, got: %+v", fx.kid, res)
	}
}

func TestDeepenTV_IdentityDoc_TransportErrorIsSkip(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	f := fx.fetcher("", 200)
	f.pinned = func(_, _, _ string) ([]byte, int, error) { return nil, 0, errString("conn refused") }
	res := deepentrustverify_runIDDoc(fx, f, "", nil)
	if res.status != StatusSkip || !strings.Contains(res.detail, "identity_doc unavailable over DANE") {
		t.Fatalf("transport failure must be SKIP, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_HTTPErrorIsSkip(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	res := deepentrustverify_runIDDoc(fx, fx.fetcher("not found", 404), "", nil)
	if res.status != StatusSkip || !strings.Contains(res.detail, "identity_doc HTTP 404") {
		t.Fatalf("an HTTP error must be SKIP, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_NonJWSBodyFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	res := deepentrustverify_runIDDoc(fx, fx.fetcher("<html>totally not a jws</html>", 200), "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "not a compact JWS") {
		t.Fatalf("a served non-JWS body is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_SigningKeyUnavailableIsSkip(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), fx.pins[0].Hex())
	f := fx.fetcher(doc, 200)
	f.get = func(string) ([]byte, int, error) { return nil, 404, nil } // no JWKS anywhere
	res := deepentrustverify_runIDDoc(fx, f, "", nil)
	if res.status != StatusSkip || !strings.Contains(res.detail, "signing key unavailable") {
		t.Fatalf("an unfetchable key is a SKIP, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_TamperedSignatureFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), fx.pins[0].Hex())
	parts := strings.Split(doc, ".")
	tampered := parts[0] + "." + parts[1] + "." + b64u(make([]byte, 64))
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(tampered, 200), "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "identity_doc signature") {
		t.Fatalf("a bad signature is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_PinnedKidMismatchFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), fx.pins[0].Hex())
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(doc, 200), "deadbeef", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "does not match the pinned") {
		t.Fatalf("a valid doc under a NON-pinned kid must FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_NonJSONPayloadFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := signES256(t, fx.priv, fx.kid, "application/whisper-identity+json", []byte("not-json"))
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(doc, 200), "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "payload was not JSON") {
		t.Fatalf("a validly-signed non-JSON payload is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_FQDNClaimMismatchFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, "impostor.te.agents.example", fx.pins[0].Hex())
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(doc, 200), "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "claims fqdn") {
		t.Fatalf("a doc claiming another fqdn is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_TLSAClaimMismatchFails(t *testing.T) {
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), hex.EncodeToString(make([]byte, 32)))
	res := deepentrustverify_runIDDoc(fx, fx.fetcher(doc, 200), "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "TLSA sha256 does not match") {
		t.Fatalf("a doc claiming a foreign TLSA pin is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_IdentityDoc_AnchoredHTTPSJwksDisagreementFails(t *testing.T) {
	// The DNS-anchored key set holds the signing kid, but the HTTPS JWKS serves the SAME
	// kid with DIFFERENT key material - the WebPKI surface is lying, an explicit FAIL.
	fx := deepentrustverify_newIDFixture(t)
	doc := fx.doc(t, fx.addr, trimDot(fx.fqdn), fx.pins[0].Hex())
	_, liarJWK, _ := deepentrustverify_signingKey(t)
	liarJWK.Kid = fx.kid // the anchored kid over the wrong key
	f := fx.fetcher(doc, 200)
	f.get = func(url string) ([]byte, int, error) {
		if strings.Contains(url, "jwks") {
			return []byte(`{"keys":[` + jwkJSON(liarJWK) + `]}`), 200, nil
		}
		return nil, 404, nil
	}
	anchored := &DNSAnchoredKeys{JWKS: JWKSet{fx.kid: fx.jwk}, IdentityName: "_whisper-identity.example"}
	res := deepentrustverify_runIDDoc(fx, f, "", anchored)
	if res.status != StatusFail || !strings.Contains(res.detail, "DISAGREES") {
		t.Fatalf("an HTTPS/DNS key disagreement is a FAIL, got %s: %s", res.status, res.detail)
	}
}
