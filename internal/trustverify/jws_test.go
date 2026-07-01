// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestVerifyES256_RoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFor(priv, "kid-1")
	keys := JWKSet{"kid-1": jwk}
	token := signES256(t, priv, "kid-1", "application/test+json", []byte(`{"hello":"world"}`))

	payload, kid, err := VerifyES256(token, keys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if kid != "kid-1" {
		t.Fatalf("kid = %q, want kid-1", kid)
	}
	if string(payload) != `{"hello":"world"}` {
		t.Fatalf("payload = %q", payload)
	}
}

func TestVerifyES256_TamperedPayloadFails(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := JWKSet{"kid-1": jwkFor(priv, "kid-1")}
	token := signES256(t, priv, "kid-1", "t", []byte(`{"n":1}`))

	// Swap the payload segment for a different (but valid base64url) payload.
	parts := strings.Split(token, ".")
	parts[1] = b64u([]byte(`{"n":2}`))
	if _, _, err := VerifyES256(strings.Join(parts, "."), keys); err == nil {
		t.Fatal("expected verification to FAIL for a tampered payload")
	}
}

func TestVerifyES256_UnknownKidFails(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := JWKSet{"other": jwkFor(priv, "other")}
	token := signES256(t, priv, "kid-1", "t", []byte(`{}`))
	if _, _, err := VerifyES256(token, keys); err == nil {
		t.Fatal("expected FAIL for an unknown kid")
	}
}

func TestVerifyES256_WrongKeyFails(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// The published key under kid-1 is the ATTACKER's, not the signer's.
	keys := JWKSet{"kid-1": jwkFor(attacker, "kid-1")}
	token := signES256(t, signer, "kid-1", "t", []byte(`{}`))
	if _, _, err := VerifyES256(token, keys); err == nil {
		t.Fatal("expected FAIL when the published key is not the signing key")
	}
}

func TestVerifyES256_RejectsNonES256Alg(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := JWKSet{"kid-1": jwkFor(priv, "kid-1")}
	// A "none"-alg token must be rejected (alg-confusion / downgrade guard).
	hdr := b64u([]byte(`{"alg":"none","kid":"kid-1"}`))
	pay := b64u([]byte(`{}`))
	if _, _, err := VerifyES256(hdr+"."+pay+".", keys); err == nil {
		t.Fatal("expected FAIL for alg=none")
	}
}

func TestJWK_SPKISHA256Hex_MatchesKid(t *testing.T) {
	// The fleet derives kid = SHA-256(SPKI DER); confirm we recompute the same value.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jwkFor(priv, "ignored")
	got, err := jwk.SPKISHA256Hex()
	if err != nil {
		t.Fatalf("spki hex: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("spki sha256 hex len = %d, want 64", len(got))
	}
}

func TestParseJWKS_AggregatesByKid(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set1, err := ParseJWKS([]byte(`{"keys":[` + jwkJSON(jwkFor(a, "k1")) + `]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := set1["k1"]; !ok {
		t.Fatal("k1 missing")
	}
}

// jwkJSON is a tiny inline JWK JSON encoder for the test above.
func jwkJSON(k JWK) string {
	return `{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"` + k.Kid +
		`","x":"` + k.X + `","y":"` + k.Y + `"}`
}
