// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package trustverify proves a Whisper agent's identity with ZERO trust in Whisper's API
// or CA -- anchored only in the DNSSEC root (RFC 4033-4035) and a public transparency log.
//
// It is the trustless counterpart of the keyless /verify-identity surface: that endpoint
// runs the trust chain SERVER-SIDE (you trust Whisper's word); this package runs it
// CLIENT-SIDE against the public internet's own trust anchors, so a relying party need not
// trust Whisper at all. The chain, and the honest trust model of each step:
//
//  1. DNSSEC (fully trustless): validate the RRSIG chain for TLSA _443._tcp.<fqdn>,
//     AAAA <fqdn>, and PTR <addr> from the built-in IANA root anchor, in-process -- we do
//     NOT trust a resolver's AD flag; we verify every signature ourselves (roots.go/dnssec.go).
//  2. DANE-EE (fully trustless): TLS-handshake <addr>:443, assert the served leaf's
//     SPKI-SHA256 == the DNSSEC-validated TLSA 3 1 1 pin, and the cert's IP-SAN/DNS-SAN
//     bind the /128 and the fqdn (RFC 6698/7671) (dane.go).
//  3. Transparency (fully trustless when the DNS key anchor is published, #260): verify the
//     ES256-signed transparency root + the C2SP ledger checkpoint (Ed25519) + RFC-6962
//     inclusion. The signing keys are recovered from the DNSSEC-signed
//     _whisper-identity/_whisper-ledger TXT RRsets (dnskeys.go) and validated to the IANA
//     root in-process; the HTTPS-served JWKS + /checkpoint/key are demoted to cross-checks
//     that FAIL on disagreement. Only when the DNS anchor is unavailable does this step fall
//     back to the WebPKI-served keys -- verified but honestly labelled trust-on-pin
//     (transparency.go).
//  4. identity_doc (same #260 anchoring; DNSSEC-bound claims): verify the identity
//     document's ES256 JWS against the DNSSEC-anchored key set (fail-closed on a foreign
//     kid; trust-on-pin fallback when the anchor is absent), and cross-check its
//     address/fqdn/tlsa claims against the DNSSEC-validated facts -- so the binding is
//     trustless in every mode (identitydoc.go).
package trustverify

// AnchorDS is a DNSSEC trust anchor expressed as a delegation-signer record (RFC 4034 §5).
// A DNSKEY at a zone apex is trusted iff its computed DS (RFC 4034 §5.1.4) matches one of
// these -- the base case of the chain of trust.
type AnchorDS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string // lowercase hex of the key digest
}

// IANARootAnchors returns the current IANA DNSSEC root trust anchors (the published
// root-anchors.xml): KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696), both RSASHA256
// (algorithm 8) with a SHA-256 DS (digest type 2). Shipping BOTH spans the ongoing root KSK
// roll so validation never depends on which KSK is currently the active signer -- the digests
// were cross-checked against the live root DNSKEY at build time (see roots_test.go).
//
// This is the one and only trust root of the whole verifier: everything else chains to it.
func IANARootAnchors() []AnchorDS {
	return []AnchorDS{
		{KeyTag: 20326, Algorithm: 8, DigestType: 2,
			Digest: "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"}, // KSK-2017
		{KeyTag: 38696, Algorithm: 8, DigestType: 2,
			Digest: "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"}, // KSK-2024
	}
}
