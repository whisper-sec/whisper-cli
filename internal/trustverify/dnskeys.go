// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// DNS-anchored signing keys (#260): Whisper publishes the transparency/ledger + identity-doc
// SIGNING KEYS in its DNSSEC-signed zone, so a verifier can anchor them to the same IANA root
// as the TLSA/AAAA/PTR facts -- promoting steps 3-4 of the chain from trust-on-pin to fully
// trustless. The wire contract (DKIM-precedent: RFC 6376 publishes signing keys as p= TXT):
//
//	_whisper-identity.<zone>. IN TXT "v=whisper1; k=p256; p=<base64 X.509-SPKI-DER>"
//	_whisper-ledger.<zone>.   IN TXT "v=whisper1; k=ed25519; n=<C2SP key name>; p=<base64 X.509-SPKI-DER>"
//
// One TXT record per key; the RRset is the whole published key set. No derived value (kid /
// key-id) is published -- the verifier DERIVES both itself (ES256 kid = lowercase-hex
// SHA-256(SPKI); C2SP key-id = first 4 bytes of SHA-256(name ‖ '\n' ‖ 0x01 ‖ raw32)), so
// nothing can disagree by construction.
//
// Semantics (fail-closed where it matters, honest where it degrades):
//
//   - RRset DNSSEC-validates + the signing kid IS in it  → verify against the DNS key; the
//     step is anchored in the DNSSEC root (dnssec-root).
//   - RRset DNSSEC-validates + the signing kid is NOT in it → FAIL (fail-closed: a key
//     outside the DNS-anchored set signed the artifact -- a fraud signal).
//   - HTTPS-served key material DISAGREES with the DNS-anchored key for the same kid →
//     FAIL with an explicit disagreement error (the WebPKI surface is lying).
//   - RRset unavailable (NXDOMAIN / unsigned / resolver error) → the step falls back to the
//     pre-#260 behavior: cryptographically verified against the HTTPS-served keys, honestly
//     labelled trust-on-pin. (A pre-#260 server keeps verifying; a stripped answer degrades
//     the LABEL, never fakes a proof.)

// DefaultKeyAnchorZone is the DNSSEC-signed zone under which Whisper publishes its signing
// keys. It is a convention, not a trust decision -- the records only count once the RRSIG
// chain from the IANA root validates in-process.
const DefaultKeyAnchorZone = "whisper.online"

// identityAnchorLabel / ledgerAnchorLabel are the owner labels under the key-anchor zone.
const (
	identityAnchorLabel = "_whisper-identity"
	ledgerAnchorLabel   = "_whisper-ledger"
)

// DNSAnchoredKeys is the signing-key set recovered from DNSSEC-validated TXT records. Either
// arm may be empty when its RRset was absent -- consumers use what is present and fall back
// (trust-on-pin) for what is not.
type DNSAnchoredKeys struct {
	// JWKS holds the ES256 identity/transparency keys, keyed by DERIVED kid.
	JWKS JWKSet
	// Ledger holds the Ed25519 C2SP checkpoint keys with DERIVED key-ids.
	Ledger []client.LedgerKey
	// IdentityName / LedgerName are the validated owner names (for anchor display).
	IdentityName string
	LedgerName   string
}

// fetchDNSAnchoredKeys DNSSEC-validates the _whisper-identity + _whisper-ledger TXT RRsets
// under zone with the SAME in-process Validator used for the TLSA/AAAA/PTR facts (every RRSIG
// verified locally against the IANA root -- stronger than trusting a resolver's AD bit) and
// parses them into usable keys. Returns (nil, why) when NEITHER arm yielded a key; otherwise
// the set plus a human note describing any arm that was unavailable.
func fetchDNSAnchoredKeys(ctx context.Context, v *Validator, zone string) (*DNSAnchoredKeys, string) {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		zone = DefaultKeyAnchorZone
	}
	out := &DNSAnchoredKeys{JWKS: JWKSet{}}
	var notes []string

	idName := dns.Fqdn(identityAnchorLabel + "." + zone)
	if rrs, err := v.ValidateRRSet(ctx, idName, dns.TypeTXT); err != nil {
		notes = append(notes, "identity keys: "+err.Error())
	} else {
		out.IdentityName = trimDot(idName)
		for _, s := range txtStrings(rrs) {
			if jwk, ok := parseIdentityKeyTXT(s); ok {
				out.JWKS[jwk.Kid] = jwk
			}
		}
		if len(out.JWKS) == 0 {
			notes = append(notes, "identity keys: the validated TXT RRset held no parseable p256 key")
		}
	}

	ledName := dns.Fqdn(ledgerAnchorLabel + "." + zone)
	if rrs, err := v.ValidateRRSet(ctx, ledName, dns.TypeTXT); err != nil {
		notes = append(notes, "ledger key: "+err.Error())
	} else {
		out.LedgerName = trimDot(ledName)
		for _, s := range txtStrings(rrs) {
			if lk, ok := parseLedgerKeyTXT(s); ok {
				out.Ledger = append(out.Ledger, lk)
			}
		}
		if len(out.Ledger) == 0 {
			notes = append(notes, "ledger key: the validated TXT RRset held no parseable ed25519 key")
		}
	}

	note := strings.Join(notes, "; ")
	if len(out.JWKS) == 0 && len(out.Ledger) == 0 {
		return nil, note
	}
	return out, note
}

// ledgerKeyByID selects the DNS-anchored ledger key whose derived C2SP key-id equals keyID,
// or nil when none matches (the fail-closed case for a checkpoint signed outside the set).
func (k *DNSAnchoredKeys) ledgerKeyByID(keyID uint32) *client.LedgerKey {
	if k == nil {
		return nil
	}
	want := fmt.Sprintf("%08x", keyID)
	for i := range k.Ledger {
		if strings.EqualFold(k.Ledger[i].KeyID, want) {
			return &k.Ledger[i]
		}
	}
	return nil
}

// txtStrings flattens the character-strings of every TXT record in rrs (each of our records
// is a single <=255-byte string, but be liberal: concatenate segments per RFC 7208 practice).
func txtStrings(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

// parseIdentityKeyTXT parses one "v=whisper1; k=p256; p=<b64>" record into a JWK whose kid is
// DERIVED (lowercase-hex SHA-256 of the SPKI DER -- exactly how Whisper mints kids). Liberal
// in what we accept: tag order and spacing are free, unknown tags are ignored; a record that
// is not a valid whisper1/p256 key is skipped (never trusted, never fatal).
func parseIdentityKeyTXT(s string) (JWK, bool) {
	tags := parseTagList(s)
	if tags["v"] != "whisper1" || !strings.EqualFold(tags["k"], "p256") {
		return JWK{}, false
	}
	der, err := base64.StdEncoding.DecodeString(tags["p"])
	if err != nil {
		return JWK{}, false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return JWK{}, false
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return JWK{}, false
	}
	kidSum := sha256.Sum256(der)
	return JWK{
		Kty: "EC", Crv: "P-256", Alg: "ES256", Use: "sig",
		Kid: hex.EncodeToString(kidSum[:]),
		X:   base64.RawURLEncoding.EncodeToString(ec.X.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(ec.Y.FillBytes(make([]byte, 32))),
	}, true
}

// parseLedgerKeyTXT parses one "v=whisper1; k=ed25519; n=<name>; p=<b64>" record into a
// LedgerKey whose C2SP key-id is DERIVED from (n, key) per the signed-note spec:
// first 4 bytes of SHA-256(name ‖ '\n' ‖ 0x01 ‖ raw-ed25519-public).
func parseLedgerKeyTXT(s string) (client.LedgerKey, bool) {
	tags := parseTagList(s)
	if tags["v"] != "whisper1" || !strings.EqualFold(tags["k"], "ed25519") || tags["n"] == "" {
		return client.LedgerKey{}, false
	}
	der, err := base64.StdEncoding.DecodeString(tags["p"])
	if err != nil {
		return client.LedgerKey{}, false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return client.LedgerKey{}, false
	}
	raw, ok := pub.(ed25519.PublicKey)
	if !ok || len(raw) != ed25519.PublicKeySize {
		return client.LedgerKey{}, false
	}
	h := sha256.New()
	h.Write([]byte(tags["n"]))
	h.Write([]byte{'\n', 0x01})
	h.Write(raw)
	sum := h.Sum(nil)
	return client.LedgerKey{
		Origin:    tags["n"],
		Alg:       "Ed25519",
		KeyID:     hex.EncodeToString(sum[:4]),
		PublicKey: base64.StdEncoding.EncodeToString(raw),
		SPKI:      base64.StdEncoding.EncodeToString(der),
	}, true
}

// parseTagList splits a "tag=value; tag=value" TXT string into a map (first value wins,
// whitespace-tolerant, tags lowercased -- liberal in what we accept).
func parseTagList(s string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		if _, dup := tags[key]; !dup {
			tags[key] = strings.TrimSpace(part[eq+1:])
		}
	}
	return tags
}

// crossCheckJWKS demotes the HTTPS-served JWKS to a CROSS-CHECK: it fetches each URL once and
// asserts that any kid present in BOTH the HTTPS set and the DNSSEC-anchored set carries
// byte-identical key material. Because a kid is the SPKI hash, a same-kid/different-bytes
// entry means the WebPKI surface is lying about a key -- an explicit, fail-closed error. An
// unreachable JWKS is NOT an error (DNS is the authority now); it returns "" findings.
func crossCheckJWKS(ctx context.Context, f Fetcher, urls []string, anchored JWKSet) error {
	if len(anchored) == 0 {
		return nil
	}
	for _, u := range urls {
		body, status, err := f.Get(ctx, u)
		if err != nil || status != 200 {
			continue // unavailable ⇒ nothing to cross-check against (DNS is primary)
		}
		served, err := ParseJWKS(body)
		if err != nil {
			continue
		}
		for kid, got := range served {
			want, ok := anchored[kid]
			if !ok {
				continue
			}
			if got.X != want.X || got.Y != want.Y {
				return fmt.Errorf(
					"HTTPS-served JWKS (%s) DISAGREES with the DNSSEC-anchored key for kid %s -- refusing",
					u, kid)
			}
		}
	}
	return nil
}
