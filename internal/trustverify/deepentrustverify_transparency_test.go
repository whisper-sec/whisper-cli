// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the transparency step's verdict shaping - the exact
// SKIP-vs-FAIL split (unavailability degrades honestly, a cryptographic mismatch always
// FAILs), the unsigned-root/verified-ledger upgrade, the pinned-kid gates, and the ledger
// inclusion-proof malformed-input rejections.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// deepentrustverify_signedNote builds a C2SP signed-note checkpoint over (origin, size,
// root) signed by edPriv. The signature line starts with the C2SP-mandated em dash rune,
// built from its escape so this source file stays free of the literal character.
func deepentrustverify_signedNote(origin string, size uint64, root []byte, edPriv ed25519.PrivateKey) string {
	body := origin + "\n" + strconv.FormatUint(size, 10) + "\n" +
		base64.StdEncoding.EncodeToString(root) + "\n"
	pub := edPriv.Public().(ed25519.PublicKey)
	blob := append(deepentrustverify_noteKeyID(origin, pub), ed25519.Sign(edPriv, []byte(body))...)
	return body + "\n\u2014 " + origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
}

// deepentrustverify_noteKeyID derives the C2SP signed-note key-id: the first 4 bytes of
// SHA-256(name || '\n' || 0x01 || raw-ed25519-public).
func deepentrustverify_noteKeyID(origin string, pub ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte(origin))
	h.Write([]byte{'\n', 0x01})
	h.Write(pub)
	return h.Sum(nil)[:4]
}

func deepentrustverify_ledgerKeyJSON(origin string, pub ed25519.PublicKey) string {
	return `{"object":"whisper-ledger-key","origin":"` + origin + `","alg":"Ed25519","key_id":"` +
		hex.EncodeToString(deepentrustverify_noteKeyID(origin, pub)) + `","public_key":"` +
		base64.StdEncoding.EncodeToString(pub) + `","public_key_spki":""}`
}

// deepentrustverify_ledgerObj builds an UNSIGNED-root transparency object carrying only a
// ledger arm - the shape a hash-chain-only node serves - so each test can shape the
// checkpoint and leaves independently of the ES256 root machinery.
func deepentrustverify_ledgerObj(addr, origin, checkpoint string, treeSize uint64, leavesJSON string) string {
	return `{"object":"identity-transparency","address":"` + addr + `","count":0,"events":[],` +
		`"root_hash":"","root_signature":"","root_signature_alg":"",` +
		`"ledger":{"origin":"` + origin + `","tree_size":` + strconv.FormatUint(treeSize, 10) +
		`,"checkpoint":` + jsonQuote(checkpoint) + `,"leaves":[` + leavesJSON + `]}}`
}

func deepentrustverify_ledgerFetcher(obj, keyJSON string) *fakeFetcher {
	return &fakeFetcher{get: func(url string) ([]byte, int, error) {
		switch {
		case strings.HasSuffix(url, "/transparency"):
			return []byte(obj), 200, nil
		case strings.HasSuffix(url, "/checkpoint/key"):
			if keyJSON == "" {
				return nil, 404, nil
			}
			return []byte(keyJSON), 200, nil
		}
		return nil, 404, nil
	}}
}

func deepentrustverify_runLedger(t *testing.T, obj, keyJSON, pinLedgerKeyID string,
	dnsKeys *DNSAnchoredKeys) transparencyResult {
	t.Helper()
	return verifyTransparency(context.Background(), deepentrustverify_ledgerFetcher(obj, keyJSON),
		"https://rdap.example", testAddr, []string{"https://rdap.example/.well-known/jwks.json"},
		"", pinLedgerKeyID, dnsKeys)
}

// --- feed-level SKIP vs FAIL ------------------------------------------------------------

func TestDeepenTV_Transparency_FeedHTTPErrorIsSkip(t *testing.T) {
	f := &fakeFetcher{get: func(string) ([]byte, int, error) { return []byte("gone"), 404, nil }}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", testAddr, nil, "", "", nil)
	if res.status != StatusSkip || !strings.Contains(res.detail, "HTTP 404") {
		t.Fatalf("a feed HTTP error is unavailability (SKIP), got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_NonJSONFeedFails(t *testing.T) {
	f := &fakeFetcher{get: func(string) ([]byte, int, error) { return []byte("<html>"), 200, nil }}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", testAddr, nil, "", "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "not JSON") {
		t.Fatalf("a 200 non-JSON feed is a FAIL (fraud signal), got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_WrongAddressFeedFails(t *testing.T) {
	fx := buildTxFixture(t)
	res := verifyTransparency(context.Background(), fx.fetcher(""), "https://rdap.example",
		"2a04:2a01:9::dead", []string{"https://rdap.example/.well-known/jwks.json"}, "", "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "not the queried") {
		t.Fatalf("a feed for another address is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_SigningKeyUnavailableIsSkip(t *testing.T) {
	// The signed feed is served but every key surface is down (non-anchored): the root cannot
	// be verified (SKIP, not FAIL) and the ledger arm reports its key unavailable too.
	fx := buildTxFixture(t)
	f := &fakeFetcher{get: func(url string) ([]byte, int, error) {
		if strings.HasSuffix(url, "/transparency") {
			return []byte(fx.obj), 200, nil
		}
		return nil, 404, nil
	}}
	res := verifyTransparency(context.Background(), f, "https://rdap.example", fx.address,
		[]string{"https://rdap.example/.well-known/jwks.json"}, "", "", nil)
	if res.status != StatusSkip || !strings.Contains(res.detail, "transparency signing key unavailable") {
		t.Fatalf("want SKIP for an unverifiable root, got %s: %s", res.status, res.detail)
	}
	if !strings.Contains(res.detail, "ledger checkpoint key unavailable") {
		t.Fatalf("want the ledger-key-unavailable note too, got: %s", res.detail)
	}
	if res.rootVerified || res.ledgerVerified {
		t.Fatalf("nothing may count as verified without a key, got: %+v", res)
	}
}

// --- pinned-kid gates ---------------------------------------------------------------------

func TestDeepenTV_Transparency_PinnedRootKidMismatchFails(t *testing.T) {
	fx := buildTxFixture(t)
	res := verifyTransparency(context.Background(), fx.fetcher(""), "https://rdap.example", fx.address,
		[]string{"https://rdap.example/.well-known/jwks.json"}, "deadbeef", "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "does not match the pinned") {
		t.Fatalf("a verified root under a NON-pinned kid must FAIL, got %s: %s", res.status, res.detail)
	}
	if !strings.Contains(res.detail, "transparency root kid") {
		t.Fatalf("the detail must name the root kid gate, got: %s", res.detail)
	}
}

func TestDeepenTV_Transparency_PinnedLedgerKeyIDMismatchFails(t *testing.T) {
	fx := buildTxFixture(t)
	res := verifyTransparency(context.Background(), fx.fetcher(""), "https://rdap.example", fx.address,
		[]string{"https://rdap.example/.well-known/jwks.json"}, "", "00000000", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "does not match the pinned") {
		t.Fatalf("a checkpoint under a NON-pinned ledger key must FAIL, got %s: %s", res.status, res.detail)
	}
	if !strings.Contains(res.detail, "ledger key id") {
		t.Fatalf("the detail must name the ledger key gate, got: %s", res.detail)
	}
}

// --- unsigned root + ledger arm ----------------------------------------------------------

func TestDeepenTV_Transparency_UnsignedRootUpgradedByVerifiedLedger(t *testing.T) {
	// A node serving an unsigned hash-chain but a SIGNED, verifiable C2SP checkpoint: the
	// ledger arm carries the step to PASS (there is a real cryptographic proof), while the
	// detail keeps the unsigned-root honesty note.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	root := sha256.Sum256([]byte("root"))
	note := deepentrustverify_signedNote(origin, 1, root[:], edPriv)
	obj := deepentrustverify_ledgerObj(testAddr, origin, note, 1, "")
	keyJSON := deepentrustverify_ledgerKeyJSON(origin, edPriv.Public().(ed25519.PublicKey))
	res := deepentrustverify_runLedger(t, obj, keyJSON, "", nil)
	if res.status != StatusPass {
		t.Fatalf("a verified checkpoint must upgrade the step to PASS, got %s: %s", res.status, res.detail)
	}
	if !res.ledgerVerified || res.rootVerified {
		t.Fatalf("only the ledger arm verified here, got: %+v", res)
	}
	if !strings.Contains(res.detail, "unsigned") ||
		!strings.Contains(res.detail, "no leaf for this address") {
		t.Fatalf("detail must keep the unsigned-root note and the no-leaf note, got: %s", res.detail)
	}
	if res.treeSize != 1 {
		t.Fatalf("treeSize must come from the checkpoint, got %d", res.treeSize)
	}
}

func TestDeepenTV_Transparency_GarbageCheckpointFails(t *testing.T) {
	obj := deepentrustverify_ledgerObj(testAddr, "example.test/ledger", "garbage-not-a-note", 1, "")
	res := deepentrustverify_runLedger(t, obj, "", "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "transparency checkpoint") {
		t.Fatalf("an unparseable checkpoint is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_UnsignedCheckpointWithAnchoredKeyFailsClosed(t *testing.T) {
	// Fail-closed: a DNSSEC-anchored ledger key is published, so an UNSIGNED checkpoint
	// is a stripping attack, never acceptable.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	root := sha256.Sum256([]byte("root"))
	bareNote := origin + "\n1\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"
	obj := deepentrustverify_ledgerObj(testAddr, origin, bareNote, 1, "")
	anchored := &DNSAnchoredKeys{JWKS: JWKSet{}, Ledger: []client.LedgerKey{{
		Origin: origin, Alg: "Ed25519",
		KeyID:     hex.EncodeToString(deepentrustverify_noteKeyID(origin, pub)),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}}, LedgerName: "_whisper-ledger.example.test"}
	res := deepentrustverify_runLedger(t, obj, "", "", anchored)
	if res.status != StatusFail || !strings.Contains(res.detail, "refusing an unsigned checkpoint") {
		t.Fatalf("want the fail-closed unsigned-checkpoint error, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_NonJSONCheckpointKeyFails(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	root := sha256.Sum256([]byte("root"))
	note := deepentrustverify_signedNote(origin, 1, root[:], edPriv)
	obj := deepentrustverify_ledgerObj(testAddr, origin, note, 1, "")
	res := deepentrustverify_runLedger(t, obj, "<html>not json</html>", "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "checkpoint key was not JSON") {
		t.Fatalf("a 200 non-JSON key surface is a FAIL, got %s: %s", res.status, res.detail)
	}
}

// --- ledger inclusion: malformed proofs + a real 2-leaf audit path -----------------------

func TestDeepenTV_Transparency_MalformedLeafHashFails(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	root := sha256.Sum256([]byte("root"))
	note := deepentrustverify_signedNote(origin, 1, root[:], edPriv)
	obj := deepentrustverify_ledgerObj(testAddr, origin, note, 1,
		`{"index":0,"leaf_hash":"zz","inclusion_proof":[]}`)
	keyJSON := deepentrustverify_ledgerKeyJSON(origin, edPriv.Public().(ed25519.PublicKey))
	res := deepentrustverify_runLedger(t, obj, keyJSON, "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "not a 32-byte hash") {
		t.Fatalf("a malformed leaf_hash is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_MalformedInclusionProofHashFails(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	leaf := sha256.Sum256([]byte("leaf"))
	note := deepentrustverify_signedNote(origin, 2, leaf[:], edPriv)
	obj := deepentrustverify_ledgerObj(testAddr, origin, note, 2,
		`{"index":0,"leaf_hash":"`+hex.EncodeToString(leaf[:])+`","inclusion_proof":["zz"]}`)
	keyJSON := deepentrustverify_ledgerKeyJSON(origin, edPriv.Public().(ed25519.PublicKey))
	res := deepentrustverify_runLedger(t, obj, keyJSON, "", nil)
	if res.status != StatusFail || !strings.Contains(res.detail, "inclusion-proof hash malformed") {
		t.Fatalf("a malformed audit-path hash is a FAIL, got %s: %s", res.status, res.detail)
	}
}

func TestDeepenTV_Transparency_TwoLeafAuditPathVerifies(t *testing.T) {
	// A REAL non-empty RFC 6962 audit path: leaf 0 of a 2-leaf tree, sibling = leaf 1, root =
	// SHA-256(0x01 || l0 || l1). A mutation anywhere in the fold turns this red.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	origin := "example.test/ledger"
	l0 := sha256.Sum256([]byte("leaf-zero"))
	l1 := sha256.Sum256([]byte("leaf-one"))
	inner := sha256.New()
	inner.Write([]byte{0x01})
	inner.Write(l0[:])
	inner.Write(l1[:])
	root := inner.Sum(nil)
	note := deepentrustverify_signedNote(origin, 2, root, edPriv)
	obj := deepentrustverify_ledgerObj(testAddr, origin, note, 2,
		`{"index":0,"leaf_hash":"`+hex.EncodeToString(l0[:])+
			`","inclusion_proof":["`+hex.EncodeToString(l1[:])+`"]}`)
	keyJSON := deepentrustverify_ledgerKeyJSON(origin, edPriv.Public().(ed25519.PublicKey))
	res := deepentrustverify_runLedger(t, obj, keyJSON, "", nil)
	if res.status != StatusPass || res.leafCount != 1 {
		t.Fatalf("want PASS with 1 included leaf, got %s (%d): %s", res.status, res.leafCount, res.detail)
	}
	if res.treeSize != 2 {
		t.Fatalf("treeSize must be the checkpoint's 2, got %d", res.treeSize)
	}
	if !strings.Contains(res.detail, "1 ledger leaf/leaves included") {
		t.Fatalf("detail must report the included leaf, got: %s", res.detail)
	}
}

// --- verifyTransparencyRoot binding negatives (direct) -----------------------------------

func TestDeepenTV_TransparencyRoot_BindingNegatives(t *testing.T) {
	priv, jwk, keys := deepentrustverify_signingKey(t)
	sign := func(payload string) string {
		return signES256(t, priv, jwk.Kid, "application/whisper-transparency-root+json", []byte(payload))
	}
	claims := `{"object":"identity-transparency-root","address":"` + testAddr + `","count":1,"root_hash":"aa"}`

	t.Run("tamperedSignature", func(t *testing.T) {
		obj := transparencyObject{Address: testAddr, Count: 1, RootHash: "aa"}
		tok := sign(claims)
		parts := strings.Split(tok, ".")
		obj.RootSignature = parts[0] + "." + parts[1] + "." + b64u(make([]byte, 64))
		if err := verifyTransparencyRoot(obj, keys); err == nil ||
			!strings.Contains(err.Error(), "transparency root signature") {
			t.Fatalf("want the signature error, got: %v", err)
		}
	})
	t.Run("nonJSONPayload", func(t *testing.T) {
		obj := transparencyObject{Address: testAddr, Count: 1, RootHash: "aa", RootSignature: sign("not-json")}
		if err := verifyTransparencyRoot(obj, keys); err == nil ||
			!strings.Contains(err.Error(), "not JSON") {
			t.Fatalf("want the payload-JSON error, got: %v", err)
		}
	})
	t.Run("addressReplay", func(t *testing.T) {
		// A VALID signature over another address must not be replayable onto this feed.
		obj := transparencyObject{Address: "2a04:2a01:9::dead", Count: 1, RootHash: "aa",
			RootSignature: sign(claims)}
		if err := verifyTransparencyRoot(obj, keys); err == nil ||
			!strings.Contains(err.Error(), "signs address") {
			t.Fatalf("want the address-binding error, got: %v", err)
		}
	})
	t.Run("rootHashMismatch", func(t *testing.T) {
		obj := transparencyObject{Address: testAddr, Count: 1, RootHash: "bb", RootSignature: sign(claims)}
		if err := verifyTransparencyRoot(obj, keys); err == nil ||
			!strings.Contains(err.Error(), "different root_hash") {
			t.Fatalf("want the root_hash-binding error, got: %v", err)
		}
	})
}

// --- verifyHashChain edges (direct) ------------------------------------------------------

func deepentrustverify_chainObj(t *testing.T, jsonStr string) transparencyObject {
	t.Helper()
	var obj transparencyObject
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		t.Fatalf("chain obj: %v", err)
	}
	return obj
}

func TestDeepenTV_HashChain_EmptyEventsWithRootHashFails(t *testing.T) {
	obj := deepentrustverify_chainObj(t, `{"events":[],"root_hash":"aa"}`)
	if err := verifyHashChain(obj); err == nil ||
		!strings.Contains(err.Error(), "no events but a non-empty root_hash") {
		t.Fatalf("want the empty-feed/root mismatch error, got: %v", err)
	}
}

func TestDeepenTV_HashChain_LastProofMustEqualRootHash(t *testing.T) {
	event := `{"action":"issuance"}`
	proof := sha256Hex("" + event)
	obj := deepentrustverify_chainObj(t, `{"events":[{"event":`+event+`,"proof":"`+proof+
		`","prev_proof":""}],"root_hash":"`+sha256Hex("something-else")+`"}`)
	if err := verifyHashChain(obj); err == nil ||
		!strings.Contains(err.Error(), "does not equal the signed root_hash") {
		t.Fatalf("want the chain/root mismatch error, got: %v", err)
	}
}

// --- anchoredTrustless truth table + kidOfJWS edges --------------------------------------

func TestDeepenTV_AnchoredTrustless_TruthTable(t *testing.T) {
	cases := []struct {
		name string
		r    transparencyResult
		want bool
	}{
		{"nothingVerified", transparencyResult{}, false},
		{"rootAnchoredOnly", transparencyResult{rootVerified: true, rootAnchored: true}, true},
		{"rootTrustOnPin", transparencyResult{rootVerified: true}, false},
		{"ledgerAnchoredOnly", transparencyResult{ledgerVerified: true, ledgerAnchored: true}, true},
		{"ledgerTrustOnPin", transparencyResult{ledgerVerified: true}, false},
		{"anchoredRootButPinnedLedger", transparencyResult{rootVerified: true, rootAnchored: true,
			ledgerVerified: true}, false},
		{"bothAnchored", transparencyResult{rootVerified: true, rootAnchored: true,
			ledgerVerified: true, ledgerAnchored: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.anchoredTrustless(); got != tc.want {
				t.Fatalf("anchoredTrustless(%+v) = %v, want %v", tc.r, got, tc.want)
			}
		})
	}
}

func TestDeepenTV_KidOfJWS_MalformedTokensYieldEmpty(t *testing.T) {
	if kid := kidOfJWS("single-part"); kid != "" {
		t.Fatalf("one-part token: want empty kid, got %q", kid)
	}
	if kid := kidOfJWS("!!!.payload"); kid != "" {
		t.Fatalf("bad header base64: want empty kid, got %q", kid)
	}
	if kid := kidOfJWS(b64u([]byte(`{"alg":"ES256"}`)) + ".payload"); kid != "" {
		t.Fatalf("kid-less header: want empty kid, got %q", kid)
	}
}
