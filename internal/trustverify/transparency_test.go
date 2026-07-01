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
	"fmt"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// transparencyFixture builds a fully-signed transparency object (ES256 root + 1 event
// hash-chain + a 1-leaf C2SP Ed25519 ledger) plus a Fetcher that serves it, the JWKS, and
// the checkpoint key. It returns the object JSON and mutable copies so negative tests can
// tamper individual pieces.
type txFixture struct {
	obj       string // the transparency object JSON
	jwks      string // JWKS with the ES256 root key
	esJWKJSON string // just the ES256 root key as a JWK JSON object (for combined key sets)
	ledgerKey string // /checkpoint/key JSON
	esKid     string
	address   string

	// the raw key material, retained so tests can present the SAME keys as a
	// DNSSEC-anchored set (or a DIFFERENT set, for the fail-closed negatives).
	esJWK    JWK
	esSpki   []byte // X.509 SPKI DER of the ES256 root key (for _whisper-identity TXT)
	edPub    ed25519.PublicKey
	edSpki   []byte // X.509 SPKI DER of the Ed25519 ledger key (for _whisper-ledger TXT)
	keyIDHex string // the C2SP key-id embedded in the checkpoint note (8 hex chars)
	origin   string
}

// dnsKeys presents the fixture's OWN keys as the DNSSEC-anchored set (the happy anchored path).
func (fx txFixture) dnsKeys() *DNSAnchoredKeys {
	return &DNSAnchoredKeys{
		JWKS: JWKSet{fx.esJWK.Kid: fx.esJWK},
		Ledger: []client.LedgerKey{{Origin: fx.origin, Alg: "Ed25519", KeyID: fx.keyIDHex,
			PublicKey: base64.StdEncoding.EncodeToString(fx.edPub)}},
		IdentityName: "_whisper-identity.whisper.online",
		LedgerName:   "_whisper-ledger.whisper.online",
	}
}

func buildTxFixture(t *testing.T) txFixture { return buildTxFixtureFor(t, testAddr) }

func buildTxFixtureFor(t *testing.T, addr string) txFixture {
	t.Helper()

	// ES256 root key + signature over the root claims.
	esPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esJWK := jwkFor(esPriv, "es-root")
	kidHex, _ := esJWK.SPKISHA256Hex()
	esJWK.Kid = kidHex

	// One event + its hash-chain proof.
	event := `{"action":"issuance","address":"` + addr + `","holder":"tX","agent":"aX","timestamp":1}`
	proof := sha256Hex("" + event)
	rootHash := proof

	rootPayload := fmt.Sprintf(`{"object":"identity-transparency-root","address":"%s","count":1,"root_hash":"%s"}`,
		addr, rootHash)
	rootSig := signES256(t, esPriv, kidHex, "application/whisper-transparency-root+json", []byte(rootPayload))

	// A 1-leaf C2SP ledger. tree_size=1 ⇒ root == leaf hash; inclusion proof is empty.
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	leaf := sha256.Sum256([]byte("commitment"))
	root := leaf[:]
	origin := "whisper.online/ledger"
	body := origin + "\n1\n" + base64.StdEncoding.EncodeToString(root) + "\n"
	// The REAL C2SP signed-note key-id: SHA-256(name ‖ '\n' ‖ 0x01 ‖ raw32), first 4 bytes --
	// the same derivation the server and the DNS-anchored parser use (C2SP signed-note).
	kh := sha256.New()
	kh.Write([]byte(origin))
	kh.Write([]byte{'\n', 0x01})
	kh.Write(edPub)
	keyID := kh.Sum(nil)
	blob := append(append([]byte{}, keyID[:4]...), ed25519.Sign(edPriv, []byte(body))...)
	note := body + "\n— " + origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"

	obj := fmt.Sprintf(`{"object":"identity-transparency","address":"%s","count":1,`+
		`"events":[{"event":%s,"proof":"%s","prev_proof":""}],`+
		`"root_hash":"%s","root_signature":"%s","root_signature_alg":"ES256",`+
		`"ledger":{"object":"ledger-inclusion","origin":"%s","tree_size":1,"checkpoint":%s,`+
		`"leaves":[{"index":0,"leaf_hash":"%s","inclusion_proof":[]}]}}`,
		addr, event, proof, rootHash, rootSig, origin, jsonQuote(note), hex.EncodeToString(leaf[:]))

	esJWKJSON := jwkJSON(esJWK)
	jwks := `{"keys":[` + esJWKJSON + `]}`
	ledgerKey := fmt.Sprintf(`{"object":"whisper-ledger-key","origin":"%s","alg":"Ed25519","key_id":"%s",`+
		`"public_key":"%s","public_key_spki":""}`,
		origin, hex.EncodeToString(keyID[:4]), base64.StdEncoding.EncodeToString(edPub))

	esSpki, _ := x509.MarshalPKIXPublicKey(&esPriv.PublicKey)
	edSpki, _ := x509.MarshalPKIXPublicKey(edPub)
	return txFixture{obj: obj, jwks: jwks, esJWKJSON: esJWKJSON, ledgerKey: ledgerKey, esKid: kidHex,
		address: addr, esJWK: esJWK, esSpki: esSpki, edPub: edPub, edSpki: edSpki,
		keyIDHex: hex.EncodeToString(keyID[:4]), origin: origin}
}

func (fx txFixture) fetcher(objOverride string) *fakeFetcher {
	obj := fx.obj
	if objOverride != "" {
		obj = objOverride
	}
	return &fakeFetcher{get: func(url string) ([]byte, int, error) {
		switch {
		case strings.HasSuffix(url, "/transparency"):
			return []byte(obj), 200, nil
		case strings.Contains(url, "jwks"):
			return []byte(fx.jwks), 200, nil
		case strings.HasSuffix(url, "/checkpoint/key"):
			return []byte(fx.ledgerKey), 200, nil
		}
		return nil, 404, nil
	}}
}

func runTx(t *testing.T, fx txFixture, objOverride string) transparencyResult {
	t.Helper()
	return runTxAnchored(t, fx, objOverride, nil)
}

func runTxAnchored(t *testing.T, fx txFixture, objOverride string, dnsKeys *DNSAnchoredKeys) transparencyResult {
	t.Helper()
	return verifyTransparency(context.Background(), fx.fetcher(objOverride),
		"https://rdap.example", fx.address, []string{"https://rdap.example/.well-known/jwks.json"}, "", "",
		dnsKeys)
}

func TestTransparency_HappyPath(t *testing.T) {
	fx := buildTxFixture(t)
	res := runTx(t, fx, "")
	if res.status != StatusPass {
		t.Fatalf("expected PASS, got %s: %s", res.status, res.detail)
	}
	if res.leafCount != 1 {
		t.Fatalf("expected 1 verified ledger leaf, got %d (%s)", res.leafCount, res.detail)
	}
}

func TestTransparency_BadCheckpointSigFails(t *testing.T) {
	fx := buildTxFixture(t)
	// Corrupt the checkpoint signature base64 blob inside the note.
	bad := strings.Replace(fx.obj, "— whisper.online/ledger ", "— whisper.online/ledger AAAA", 1)
	res := runTx(t, fx, bad)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for a corrupted checkpoint signature, got %s: %s", res.status, res.detail)
	}
}

func TestTransparency_TamperedRootClaimsFails(t *testing.T) {
	fx := buildTxFixture(t)
	// The object claims count:2 but the signature covers count:1 → binding mismatch.
	bad := strings.Replace(fx.obj, `"count":1,`, `"count":2,`, 1)
	res := runTx(t, fx, bad)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL when count disagrees with the signed root, got %s: %s", res.status, res.detail)
	}
}

func TestTransparency_HashChainBreakFails(t *testing.T) {
	fx := buildTxFixture(t)
	// Tamper the event proof so the recomputed chain no longer matches.
	bad := strings.Replace(fx.obj, `"proof":"`+sha256Hex(`{"action":"issuance"`), `"proof":"deadbeef`, 1)
	if bad == fx.obj {
		// Fallback: blunt-force a proof mutation.
		bad = strings.Replace(fx.obj, `"prev_proof":""`, `"prev_proof":"ff"`, 1)
	}
	res := runTx(t, fx, bad)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for a broken hash-chain, got %s: %s", res.status, res.detail)
	}
}

func TestTransparency_ForgedInclusionFails(t *testing.T) {
	fx := buildTxFixture(t)
	// Replace the leaf hash with one that does not equal the (1-leaf) checkpoint root.
	forged := hex.EncodeToString(sha256Sum([]byte("not-the-leaf")))
	orig := fx.obj
	// find the current leaf_hash and swap it.
	start := strings.Index(orig, `"leaf_hash":"`) + len(`"leaf_hash":"`)
	end := strings.Index(orig[start:], `"`) + start
	bad := orig[:start] + forged + orig[end:]
	res := runTx(t, fx, bad)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for a forged inclusion leaf, got %s: %s", res.status, res.detail)
	}
}

func TestTransparency_EmptySignedFeedPasses(t *testing.T) {
	// A legitimately empty (count:0) feed whose root is signed still PASSes: the signed
	// statement "0 events" is valid. Reuse the ES key by signing an empty-root payload.
	esPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esJWK := jwkFor(esPriv, "es")
	kid, _ := esJWK.SPKISHA256Hex()
	esJWK.Kid = kid
	addr := testAddr
	payload := fmt.Sprintf(`{"object":"identity-transparency-root","address":"%s","count":0,"root_hash":""}`, addr)
	sig := signES256(t, esPriv, kid, "application/whisper-transparency-root+json", []byte(payload))
	obj := fmt.Sprintf(`{"object":"identity-transparency","address":"%s","count":0,"events":[],`+
		`"root_hash":"","root_signature":"%s","root_signature_alg":"ES256"}`, addr, sig)
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) {
		switch {
		case strings.HasSuffix(url, "/transparency"):
			return []byte(obj), 200, nil
		case strings.Contains(url, "jwks"):
			return []byte(`{"keys":[` + jwkJSON(esJWK) + `]}`), 200, nil
		}
		return nil, 404, nil
	}}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", addr,
		[]string{"https://rdap.example/.well-known/jwks.json"}, "", "", nil)
	if res.status != StatusPass {
		t.Fatalf("expected PASS for a signed empty feed, got %s: %s", res.status, res.detail)
	}
}

// --- DNSSEC-anchored key semantics -------------------------------------------------

func TestTransparency_AnchoredHappyPathIsDNSSECRoot(t *testing.T) {
	// The fixture's own keys presented as the DNSSEC-anchored set: everything verifies and the
	// whole step is anchored in the DNSSEC root (no trust-on-pin anywhere).
	fx := buildTxFixture(t)
	res := runTxAnchored(t, fx, "", fx.dnsKeys())
	if res.status != StatusPass {
		t.Fatalf("expected PASS, got %s: %s", res.status, res.detail)
	}
	if !res.rootAnchored || !res.ledgerAnchored || !res.anchoredTrustless() {
		t.Fatalf("expected a fully DNSSEC-anchored result, got root=%v ledger=%v (%s)",
			res.rootAnchored, res.ledgerAnchored, res.detail)
	}
	if res.leafCount != 1 {
		t.Fatalf("expected the ledger leaf still verified, got %d", res.leafCount)
	}
}

func TestTransparency_RootKidOutsideAnchoredSetFailsClosed(t *testing.T) {
	// The DNS-anchored set holds a DIFFERENT ES256 key than the one that signed the root: the
	// root's kid is not in the set ⇒ fail-closed, an explicit FAIL (never a silent fallback).
	fx := buildTxFixture(t)
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherJWK := jwkFor(otherPriv, "other")
	otherKid, _ := otherJWK.SPKISHA256Hex()
	otherJWK.Kid = otherKid
	keys := fx.dnsKeys()
	keys.JWKS = JWKSet{otherKid: otherJWK}
	res := runTxAnchored(t, fx, "", keys)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for a root signed outside the anchored set, got %s: %s", res.status, res.detail)
	}
	if !strings.Contains(res.detail, "NOT in the DNSSEC-anchored key set") {
		t.Fatalf("expected the fail-closed detail, got: %s", res.detail)
	}
}

func TestTransparency_CheckpointKeyOutsideAnchoredSetFailsClosed(t *testing.T) {
	// The anchored ledger set holds a different Ed25519 key: the checkpoint's embedded key-id
	// matches nothing in the set ⇒ fail-closed FAIL.
	fx := buildTxFixture(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := fx.dnsKeys()
	kh := sha256.New()
	kh.Write([]byte(fx.origin))
	kh.Write([]byte{'\n', 0x01})
	kh.Write(otherPub)
	keys.Ledger = []client.LedgerKey{{Origin: fx.origin, Alg: "Ed25519",
		KeyID:     hex.EncodeToString(kh.Sum(nil)[:4]),
		PublicKey: base64.StdEncoding.EncodeToString(otherPub)}}
	res := runTxAnchored(t, fx, "", keys)
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for a checkpoint signed outside the anchored set, got %s: %s",
			res.status, res.detail)
	}
	if !strings.Contains(res.detail, "NOT in the DNSSEC-anchored ledger key set") {
		t.Fatalf("expected the fail-closed detail, got: %s", res.detail)
	}
}

func TestTransparency_HTTPSJwksDisagreementFails(t *testing.T) {
	// The HTTPS JWKS LIES: it serves the anchored kid with DIFFERENT key material. The DNS
	// anchor is authoritative and the disagreement is an explicit FAIL.
	fx := buildTxFixture(t)
	liarPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	liar := jwkFor(liarPriv, fx.esKid) // the anchored kid over the WRONG key
	fx.jwks = `{"keys":[` + jwkJSON(liar) + `]}`
	res := runTxAnchored(t, fx, "", fx.dnsKeys())
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for an HTTPS/DNS key disagreement, got %s: %s", res.status, res.detail)
	}
	if !strings.Contains(res.detail, "DISAGREES") {
		t.Fatalf("expected the explicit disagreement error, got: %s", res.detail)
	}
}

func TestTransparency_HTTPSCheckpointKeyDisagreementFails(t *testing.T) {
	// The HTTPS /checkpoint/key LIES: same key-id, different raw key ⇒ explicit FAIL.
	fx := buildTxFixture(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fx.ledgerKey = fmt.Sprintf(`{"object":"whisper-ledger-key","origin":"%s","alg":"Ed25519",`+
		`"key_id":"%s","public_key":"%s","public_key_spki":""}`,
		fx.origin, fx.keyIDHex, base64.StdEncoding.EncodeToString(otherPub))
	res := runTxAnchored(t, fx, "", fx.dnsKeys())
	if res.status != StatusFail {
		t.Fatalf("expected FAIL for an HTTPS/DNS checkpoint-key disagreement, got %s: %s",
			res.status, res.detail)
	}
	if !strings.Contains(res.detail, "DISAGREES") {
		t.Fatalf("expected the explicit disagreement error, got: %s", res.detail)
	}
}

func TestTransparency_AnchoredWorksWithoutAnyHTTPSKeySurface(t *testing.T) {
	// With the DNS anchor present, the HTTPS JWKS + /checkpoint/key may be entirely DOWN and
	// the step still verifies fully trustlessly (DNS is primary; HTTPS is only a cross-check).
	fx := buildTxFixture(t)
	obj := fx.obj
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) {
		if strings.HasSuffix(url, "/transparency") {
			return []byte(obj), 200, nil
		}
		return nil, 404, nil // no JWKS, no /checkpoint/key
	}}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", fx.address,
		[]string{"https://rdap.example/.well-known/jwks.json"}, "", "", fx.dnsKeys())
	if res.status != StatusPass {
		t.Fatalf("expected PASS with DNS-anchored keys and no HTTPS key surface, got %s: %s",
			res.status, res.detail)
	}
	if !res.anchoredTrustless() {
		t.Fatalf("expected a fully anchored result, got: %+v", res)
	}
}

func TestTransparency_UnavailableIsSkip(t *testing.T) {
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) { return nil, 0, errString("network down") }}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", testAddr, nil, "", "", nil)
	if res.status != StatusSkip {
		t.Fatalf("expected SKIP when the feed is unavailable, got %s", res.status)
	}
}

func jsonQuote(s string) string {
	b := strings.Builder{}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
