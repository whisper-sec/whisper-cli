// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// JWK is one JSON Web Key (RFC 7517) -- only the EC P-256 signing-key fields the Whisper
// transparency-root and identity-doc signatures use. Anything else is ignored (liberal in).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKSet is a set of JWKs keyed by kid, as aggregated across (possibly load-balanced,
// per-node) JWKS responses. Whisper's fleet serves ONE ES256 key per node behind a shared
// JWKS URL, so a caller aggregates a few fetches to collect every kid it may need.
type JWKSet map[string]JWK

// ParseJWKS decodes a JWKS document ({"keys":[...]}) into a set keyed by kid.
func ParseJWKS(body []byte) (JWKSet, error) {
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks: not a JSON key set: %w", err)
	}
	set := make(JWKSet, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid != "" {
			set[k.Kid] = k
		}
	}
	return set, nil
}

// merge folds src into dst (dst wins on kid collision -- first key seen is kept stable).
func (s JWKSet) merge(src JWKSet) {
	for kid, k := range src {
		if _, ok := s[kid]; !ok {
			s[kid] = k
		}
	}
}

// publicKey builds a crypto/ecdsa P-256 public key from the JWK's x,y coordinates.
func (k JWK) publicKey() (*ecdsa.PublicKey, error) {
	if !strings.EqualFold(k.Kty, "EC") || (k.Crv != "" && k.Crv != "P-256") {
		return nil, fmt.Errorf("jwk %s: not an EC P-256 key (kty=%q crv=%q)", k.Kid, k.Kty, k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
	if err != nil {
		return nil, fmt.Errorf("jwk %s: bad x coordinate: %w", k.Kid, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.Y, "="))
	if err != nil {
		return nil, fmt.Errorf("jwk %s: bad y coordinate: %w", k.Kid, err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		return nil, fmt.Errorf("jwk %s: P-256 coordinates must be 32 bytes", k.Kid)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// SPKISHA256Hex returns the lowercase-hex SHA-256 of the key's DER SubjectPublicKeyInfo.
// Whisper derives each key's kid this way, so this both (a) lets a verifier independently
// recompute + confirm the kid and (b) yields a stable value a relying party can PIN.
func (k JWK) SPKISHA256Hex() (string, error) {
	pub, err := k.publicKey()
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// b64urlDecode decodes base64url, tolerating optional trailing padding (liberal in).
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// jwsHeader is the decoded protected header of a compact JWS we accept (ES256 only).
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// VerifyES256 verifies a compact ES256 JWS (RFC 7515) against the key named by its header
// kid in keys, and returns the raw (decoded) payload plus that kid. Conservative in what we
// accept: alg MUST be ES256 (no "none", no alg confusion), the signature MUST be the fixed
// 64-byte raw R||S JOSE encoding, and the kid MUST resolve to a known key.
func VerifyES256(token string, keys JWKSet) (payload []byte, kid string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("jws: not a compact token (want 3 dot-separated parts)")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("jws: bad header base64url: %w", err)
	}
	var hdr jwsHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, "", fmt.Errorf("jws: bad header JSON: %w", err)
	}
	if hdr.Alg != "ES256" {
		return nil, "", fmt.Errorf("jws: unsupported alg %q (only ES256 is accepted)", hdr.Alg)
	}
	if hdr.Kid == "" {
		return nil, "", fmt.Errorf("jws: header has no kid")
	}
	jwk, ok := keys[hdr.Kid]
	if !ok {
		return nil, "", fmt.Errorf("jws: no published key for kid %s", hdr.Kid)
	}
	pub, err := jwk.publicKey()
	if err != nil {
		return nil, "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("jws: bad signature base64url: %w", err)
	}
	if len(sig) != 64 {
		return nil, "", fmt.Errorf("jws: ES256 signature must be 64 bytes (JOSE R||S), got %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, "", fmt.Errorf("jws: ES256 signature does NOT verify under kid %s", hdr.Kid)
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("jws: bad payload base64url: %w", err)
	}
	return payload, hdr.Kid, nil
}
