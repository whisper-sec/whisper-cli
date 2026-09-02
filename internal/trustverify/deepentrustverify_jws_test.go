// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): JWS / JWK malformed-input negatives. Every test here
// pins a REJECTION branch of the ES256 verifier - the accept-side is covered by jws_test.go,
// so a mutation that loosens any of these checks (alg confusion, kid-less tokens, malformed
// coordinates, non-64-byte signatures) turns at least one of these red.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

// deepentrustverify_signingKey returns a fresh P-256 key with its derived-kid JWK and a
// one-key JWKSet, the standard shape every verifier path in this package consumes.
func deepentrustverify_signingKey(t *testing.T) (*ecdsa.PrivateKey, JWK, JWKSet) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen P-256 key: %v", err)
	}
	jwk := jwkFor(priv, "tmp")
	kid, err := jwk.SPKISHA256Hex()
	if err != nil {
		t.Fatalf("derive kid: %v", err)
	}
	jwk.Kid = kid
	return priv, jwk, JWKSet{kid: jwk}
}

func TestDeepenTV_VerifyES256_TwoPartTokenRejected(t *testing.T) {
	_, _, keys := deepentrustverify_signingKey(t)
	if _, _, err := VerifyES256("a.b", keys); err == nil ||
		!strings.Contains(err.Error(), "not a compact token") {
		t.Fatalf("want the 3-part shape error, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_BadHeaderBase64Rejected(t *testing.T) {
	_, _, keys := deepentrustverify_signingKey(t)
	if _, _, err := VerifyES256("!!!.p.s", keys); err == nil ||
		!strings.Contains(err.Error(), "bad header base64url") {
		t.Fatalf("want the header base64 error, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_NonJSONHeaderRejected(t *testing.T) {
	_, _, keys := deepentrustverify_signingKey(t)
	tok := b64u([]byte("not-json")) + ".p.s"
	if _, _, err := VerifyES256(tok, keys); err == nil ||
		!strings.Contains(err.Error(), "bad header JSON") {
		t.Fatalf("want the header JSON error, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_KidlessHeaderRejected(t *testing.T) {
	_, _, keys := deepentrustverify_signingKey(t)
	tok := b64u([]byte(`{"alg":"ES256"}`)) + "." + b64u([]byte("{}")) + "." + b64u(make([]byte, 64))
	if _, _, err := VerifyES256(tok, keys); err == nil ||
		!strings.Contains(err.Error(), "no kid") {
		t.Fatalf("want the kid-less rejection, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_BadSignatureBase64Rejected(t *testing.T) {
	priv, jwk, keys := deepentrustverify_signingKey(t)
	good := signES256(t, priv, jwk.Kid, "t", []byte("{}"))
	parts := strings.Split(good, ".")
	if _, _, err := VerifyES256(parts[0]+"."+parts[1]+".!!!", keys); err == nil ||
		!strings.Contains(err.Error(), "bad signature base64url") {
		t.Fatalf("want the signature base64 error, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_ShortSignatureRejected(t *testing.T) {
	priv, jwk, keys := deepentrustverify_signingKey(t)
	good := signES256(t, priv, jwk.Kid, "t", []byte("{}"))
	parts := strings.Split(good, ".")
	// A DER-ish 10-byte blob instead of the fixed 64-byte JOSE R||S: MUST be rejected before
	// any curve math (a malleable-encoding foot-gun the verifier explicitly closes).
	if _, _, err := VerifyES256(parts[0]+"."+parts[1]+"."+b64u(make([]byte, 10)), keys); err == nil ||
		!strings.Contains(err.Error(), "must be 64 bytes") {
		t.Fatalf("want the 64-byte signature-length rejection, got: %v", err)
	}
}

func TestDeepenTV_VerifyES256_BadPayloadBase64Rejected(t *testing.T) {
	// The signature is VALID over the signing input, but the payload segment is not decodable
	// base64url - the verifier must still reject rather than return garbage bytes.
	priv, jwk, keys := deepentrustverify_signingKey(t)
	h := b64u([]byte(`{"alg":"ES256","kid":"` + jwk.Kid + `"}`))
	p := "#$%" // not base64url
	tok := deepentrustverify_signRaw(t, priv, h, p)
	if _, _, err := VerifyES256(tok, keys); err == nil ||
		!strings.Contains(err.Error(), "bad payload base64url") {
		t.Fatalf("want the payload base64 error, got: %v", err)
	}
}

// deepentrustverify_signRaw signs the exact "h.p" signing input (p may deliberately be
// invalid base64url) and returns the compact token.
func deepentrustverify_signRaw(t *testing.T, priv *ecdsa.PrivateKey, h, p string) string {
	t.Helper()
	return h + "." + p + "." + deepentrustverify_es256Sign(t, priv, h+"."+p)
}

func deepentrustverify_es256Sign(t *testing.T, priv *ecdsa.PrivateKey, signingInput string) string {
	t.Helper()
	digest := deepentrustverify_sha256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("es256 sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return b64u(sig)
}

func deepentrustverify_sha256(s string) []byte {
	return sha256Sum([]byte(s))
}

func TestDeepenTV_VerifyES256_MalformedKeyInSetRejected(t *testing.T) {
	// The kid resolves, but the key material itself is broken - publicKey() must surface the
	// error instead of verifying against a zero key.
	priv, jwk, _ := deepentrustverify_signingKey(t)
	bad := JWK{Kty: "EC", Crv: "P-256", Kid: jwk.Kid, X: "!!!", Y: jwk.Y}
	tok := signES256(t, priv, jwk.Kid, "t", []byte("{}"))
	if _, _, err := VerifyES256(tok, JWKSet{jwk.Kid: bad}); err == nil ||
		!strings.Contains(err.Error(), "bad x coordinate") {
		t.Fatalf("want the bad-x error, got: %v", err)
	}
}

func TestDeepenTV_JWKPublicKey_Negatives(t *testing.T) {
	_, good, _ := deepentrustverify_signingKey(t)
	cases := []struct {
		name string
		jwk  JWK
		want string
	}{
		{"nonEC", JWK{Kty: "RSA", Kid: "k"}, "not an EC P-256 key"},
		{"wrongCurve", JWK{Kty: "EC", Crv: "P-384", Kid: "k"}, "not an EC P-256 key"},
		{"badX", JWK{Kty: "EC", Crv: "P-256", Kid: "k", X: "!!!", Y: good.Y}, "bad x coordinate"},
		{"badY", JWK{Kty: "EC", Crv: "P-256", Kid: "k", X: good.X, Y: "!!!"}, "bad y coordinate"},
		{"shortCoords", JWK{Kty: "EC", Crv: "P-256", Kid: "k",
			X: b64u(make([]byte, 16)), Y: b64u(make([]byte, 16))}, "must be 32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.jwk.publicKey(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got: %v", tc.want, err)
			}
			// SPKISHA256Hex must propagate the same rejection (never hash a broken key).
			if _, err := tc.jwk.SPKISHA256Hex(); err == nil {
				t.Fatalf("SPKISHA256Hex accepted a malformed key: %+v", tc.jwk)
			}
		})
	}
}

func TestDeepenTV_JWKSPKISHA256Hex_OffCurvePointRejected(t *testing.T) {
	// 32-byte coordinates that decode fine but are NOT a point on P-256: the DER marshal step
	// must reject it (Go validates the point), not emit a pinnable hash for a bogus key.
	junk := make([]byte, 32)
	for i := range junk {
		junk[i] = 0xFF
	}
	k := JWK{Kty: "EC", Crv: "P-256", Kid: "k", X: b64u(junk), Y: b64u(junk)}
	if _, err := k.SPKISHA256Hex(); err == nil {
		t.Fatal("want an error for an off-curve point, got a hash")
	}
}

func TestDeepenTV_ParseJWKS_Negatives(t *testing.T) {
	if _, err := ParseJWKS([]byte("not json")); err == nil ||
		!strings.Contains(err.Error(), "not a JSON key set") {
		t.Fatalf("want the not-JSON error, got: %v", err)
	}
	// A kid-less key is skipped (it cannot be addressed), never indexed under "".
	set, err := ParseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]}`))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(set) != 0 {
		t.Fatalf("kid-less keys must be dropped, got %d entries", len(set))
	}
}
