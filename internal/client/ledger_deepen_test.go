// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deepenclient_signedTree builds an n-leaf RFC-6962 tree plus a signed C2SP checkpoint
// note over its root, reusing the in-test Merkle helpers from ledger_test.go. It returns
// the leaves, the note, the published key, and the signing keypair.
func deepenclient_signedTree(t *testing.T, origin string, n int) (leaves [][]byte, note string, key *LedgerKey, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	leaves = make([][]byte, n)
	for i := 0; i < n; i++ {
		c := sha256.Sum256([]byte(fmt.Sprintf("commitment-%d", i)))
		leaves[i] = leafHash(c[:])
	}
	root := mth(leaves)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("%s\n%d\n%s\n", origin, n, base64.StdEncoding.EncodeToString(root))
	keyID := computeSignedNoteKeyID(origin, pub)
	sig := ed25519.Sign(priv, []byte(body))
	blob := make([]byte, 4+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(blob[:4], keyID)
	copy(blob[4:], sig)
	note = body + "\n" + sigPrefix + origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
	key = &LedgerKey{
		Origin:    origin,
		Alg:       "Ed25519",
		KeyID:     fmt.Sprintf("%08x", keyID),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	return leaves, note, key, pub, priv
}

// deepenclient_ledgerClient builds a Client whose public ledger surface is srv.
func deepenclient_ledgerClient(srv *httptest.Server) *Client {
	return New(Config{RDAPURL: srv.URL, HTTPClient: srv.Client()})
}

// ---- the keyless fetchers ------------------------------------------------------------

func TestDeepenClientFetchCheckpointParsesAndVerifiesTheServedNote(t *testing.T) {
	_, note, key, _, _ := deepenclient_signedTree(t, "whisper.online/ledger", 5)
	var sawKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkpoint" {
			t.Errorf("path = %q, want /checkpoint", r.URL.Path)
		}
		sawKey = r.Header.Get("X-API-Key")
		_, _ = io.WriteString(w, note)
	}))
	t.Cleanup(srv.Close)

	cp, err := deepenclient_ledgerClient(srv).FetchCheckpoint(context.Background())
	if err != nil {
		t.Fatalf("FetchCheckpoint: %v", err)
	}
	if sawKey != "" {
		t.Fatal("the ledger surface is public - no key may ride the fetch")
	}
	if cp.Origin != "whisper.online/ledger" || cp.TreeSize != 5 || len(cp.Root) != sha256.Size {
		t.Fatalf("checkpoint fields wrong: %+v", cp)
	}
	if cp.Sig == nil {
		t.Fatal("the signature line must be parsed")
	}
	if err := cp.VerifySignature(key); err != nil {
		t.Fatalf("the fetched checkpoint must verify under the published key: %v", err)
	}
}

func TestDeepenClientFetchCheckpointMissingIsAProblem(t *testing.T) {
	srv, _ := deepenclient_server(t, 404, "")
	_, err := deepenclient_ledgerClient(srv).FetchCheckpoint(context.Background())
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 404 || !strings.Contains(pe.Detail, "/checkpoint") {
		t.Fatalf("a missing checkpoint must be a clear problem, got %v", err)
	}
}

func TestDeepenClientFetchCheckpointGarbledNoteIsAClearError(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, "one lonely line")
	_, err := deepenclient_ledgerClient(srv).FetchCheckpoint(context.Background())
	if err == nil || !strings.Contains(err.Error(), "origin, tree_size, root") {
		t.Fatalf("a garbled note must say what a note needs, got %v", err)
	}
}

func TestDeepenClientFetchLedgerKeyDecodesThePublishedKey(t *testing.T) {
	srv, _ := deepenclient_server(t, 200,
		`{"origin":"whisper.online/ledger","alg":"Ed25519","key_id":"d40e573a","public_key":"AAAA"}`)
	k, err := deepenclient_ledgerClient(srv).FetchLedgerKey(context.Background())
	if err != nil {
		t.Fatalf("FetchLedgerKey: %v", err)
	}
	if k.Origin != "whisper.online/ledger" || k.KeyID != "d40e573a" || k.Alg != "Ed25519" {
		t.Fatalf("key fields wrong: %+v", k)
	}
}

func TestDeepenClientFetchLedgerKeyFailures(t *testing.T) {
	missing, _ := deepenclient_server(t, 404, "")
	if _, err := deepenclient_ledgerClient(missing).FetchLedgerKey(context.Background()); err == nil {
		t.Fatal("a 404 must be a problem")
	}
	garbled, _ := deepenclient_server(t, 200, "not json")
	if _, err := deepenclient_ledgerClient(garbled).FetchLedgerKey(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("a non-JSON key reply must be a clear error, got %v", err)
	}
}

func TestDeepenClientFetchWitnessKeysNonJSONIsAClearError(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, "<html>")
	if _, err := deepenclient_ledgerClient(srv).FetchWitnessKeys(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("a non-JSON witness policy must be a clear error, got %v", err)
	}
}

func TestDeepenClientFetchInclusionThenVerifyEndToEnd(t *testing.T) {
	// The full keyless verify chain: fetch the transparency feed, then fold the served
	// proof into the served checkpoint root with stock crypto.
	leaves, note, key, _, _ := deepenclient_signedTree(t, "whisper.online/ledger", 6)
	subject := 4
	path := inclusionPath(subject, leaves)
	proofHex := make([]string, len(path))
	for i, p := range path {
		proofHex[i] = hex.EncodeToString(p)
	}
	feed := map[string]any{
		"ledger": map[string]any{
			"checkpoint": note,
			"leaves": []map[string]any{{
				"index":           subject,
				"leaf_hash":       hex.EncodeToString(leaves[subject]),
				"inclusion_proof": proofHex,
			}},
		},
	}
	feedJSON, _ := json.Marshal(feed)

	const addr = "2a04:2a01::42"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ip/"+addr+"/transparency" {
			t.Errorf("path = %q, want /ip/%s/transparency", r.URL.Path, addr)
		}
		_, _ = w.Write(feedJSON)
	}))
	t.Cleanup(srv.Close)

	incs, cp, err := deepenclient_ledgerClient(srv).FetchInclusion(context.Background(), addr)
	if err != nil {
		t.Fatalf("FetchInclusion: %v", err)
	}
	if len(incs) != 1 || incs[0].Index != uint64(subject) {
		t.Fatalf("inclusions wrong: %+v", incs)
	}
	if cp == nil || cp.TreeSize != 6 {
		t.Fatalf("the embedded proving checkpoint must be parsed, got %+v", cp)
	}
	if err := cp.VerifySignature(key); err != nil {
		t.Fatalf("embedded checkpoint must verify: %v", err)
	}
	if err := VerifyInclusion(incs[0].LeafHash, incs[0].Index, cp.TreeSize, incs[0].ProofPath, cp.Root); err != nil {
		t.Fatalf("the served proof must fold to the signed root: %v", err)
	}
	// And a TAMPERED leaf from the same feed must be rejected.
	bad := append([]byte(nil), incs[0].LeafHash...)
	bad[0] ^= 0x01
	if err := VerifyInclusion(bad, incs[0].Index, cp.TreeSize, incs[0].ProofPath, cp.Root); err == nil {
		t.Fatal("a tampered leaf must FAIL inclusion verification")
	}
}

func TestDeepenClientFetchInclusionNoLedgerBlockIsAClean404(t *testing.T) {
	srv, _ := deepenclient_server(t, 200, `{"rdap":{"handle":"x"}}`)
	_, _, err := deepenclient_ledgerClient(srv).FetchInclusion(context.Background(), "2a04:2a01::1")
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 404 || !strings.Contains(pe.Detail, "no verifiable-ledger inclusion data") {
		t.Fatalf("an address with no ledger data must be a clean, honest 404, got %v", err)
	}
}

func TestDeepenClientFetchInclusionRejectsMalformedHashes(t *testing.T) {
	cases := map[string]string{
		"malformed leaf_hash": `{"ledger":{"leaves":[{"index":0,"leaf_hash":"zz","inclusion_proof":[]}]}}`,
		"malformed inclusion_proof": `{"ledger":{"leaves":[{"index":0,` +
			`"leaf_hash":"` + strings.Repeat("ab", 32) + `","inclusion_proof":["beef"]}]}}`,
	}
	for wantErr, body := range cases {
		srv, _ := deepenclient_server(t, 200, body)
		_, _, err := deepenclient_ledgerClient(srv).FetchInclusion(context.Background(), "2a04:2a01::1")
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("want %q, got %v", wantErr, err)
		}
	}
}

func TestDeepenClientFetchInclusionInputAndTransportFailures(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := deepenclient_ledgerClient(srv)
	if _, _, err := c.FetchInclusion(context.Background(), "   "); err == nil {
		t.Fatal("a blank address must be a clean local 400")
	}
	if len(*reqs) != 0 {
		t.Fatal("no request may be made for a blank address")
	}
	missing, _ := deepenclient_server(t, 500, "")
	if _, _, err := deepenclient_ledgerClient(missing).FetchInclusion(context.Background(), "2a04:2a01::1"); err == nil {
		t.Fatal("a 500 must be a problem")
	}
	garbled, _ := deepenclient_server(t, 200, "<html>")
	if _, _, err := deepenclient_ledgerClient(garbled).FetchInclusion(context.Background(), "2a04:2a01::1"); err == nil ||
		!strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("a non-JSON feed must be a clear error, got %v", err)
	}
}

func TestDeepenClientLedgerGetUnreachableIsWrappedHelpfully(t *testing.T) {
	c := New(Config{RDAPURL: deadBase, HTTPClient: &http.Client{Timeout: 2 * time.Second}})
	if _, err := c.FetchCheckpoint(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "ledger endpoint unreachable") {
		t.Fatalf("a dial failure must say the ledger is unreachable, got %v", err)
	}
}

// ---- VerifySignature: every forgery / misconfiguration path --------------------------

func TestDeepenClientVerifySignatureNegatives(t *testing.T) {
	_, note, key, _, _ := deepenclient_signedTree(t, "whisper.online/ledger", 3)
	cp, err := ParseCheckpointNote(note)
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned note (body only): honestly "unsigned", never a false verify.
	unsigned, err := ParseCheckpointNote(strings.SplitN(note, "\n\n", 2)[0] + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := unsigned.VerifySignature(key); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("an unsigned checkpoint must say so, got %v", err)
	}

	// No published key at all.
	if err := cp.VerifySignature(nil); err == nil || !strings.Contains(err.Error(), "no published key") {
		t.Fatalf("a nil key must be a clear error, got %v", err)
	}

	// A published key that is not a 32-byte Ed25519 key.
	if err := cp.VerifySignature(&LedgerKey{PublicKey: "AAAA"}); err == nil ||
		!strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("a short key must be rejected, got %v", err)
	}

	// A key-id mismatch (rotation guard): the embedded id must match the published one.
	wrongID := &LedgerKey{KeyID: "00000001", PublicKey: key.PublicKey}
	if err := cp.VerifySignature(wrongID); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a key-id mismatch must be rejected, got %v", err)
	}

	// A TAMPERED signature must never verify.
	tampered, err := ParseCheckpointNote(note)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Sig = append([]byte(nil), tampered.Sig...)
	tampered.Sig[0] ^= 0x01
	if err := tampered.VerifySignature(key); err == nil || !strings.Contains(err.Error(), "does NOT verify") {
		t.Fatalf("a tampered signature must be rejected, got %v", err)
	}

	// An unparsable key_id hex SKIPS the id cross-check (liberal-accept) but the
	// signature itself still verifies - the crypto is never weakened, only the label.
	sloppy := &LedgerKey{KeyID: "not-hex", PublicKey: key.PublicKey}
	if err := cp.VerifySignature(sloppy); err != nil {
		t.Fatalf("an unparsable key-id label must not break a valid signature: %v", err)
	}
}

// ---- VerifyInclusion: proof-shape attacks --------------------------------------------

func TestDeepenClientVerifyInclusionRejectsShapeAttacks(t *testing.T) {
	leaves, _, _, _, _ := deepenclient_signedTree(t, "o", 4)
	root := mth(leaves)
	goodPath := inclusionPath(0, leaves)

	if err := VerifyInclusion(leaves[0][:16], 0, 4, goodPath, root); err == nil {
		t.Fatal("a short leaf hash must be rejected")
	}
	if err := VerifyInclusion(leaves[0], 0, 4, goodPath, root[:16]); err == nil {
		t.Fatal("a short root must be rejected")
	}
	if err := VerifyInclusion(leaves[0], 4, 4, goodPath, root); err == nil ||
		!strings.Contains(err.Error(), "out of range") {
		t.Fatalf("index >= treeSize must be rejected, got %v", err)
	}
	// A proof PADDED with an extra sibling (a forged over-long path).
	long := append(append([][]byte(nil), goodPath...), bytes.Repeat([]byte{0xEE}, 32))
	if err := VerifyInclusion(leaves[0], 0, 4, long, root); err == nil ||
		!strings.Contains(err.Error(), "more siblings") {
		t.Fatalf("an over-long proof must be rejected, got %v", err)
	}
	// A proof TRUNCATED below the tree shape.
	if err := VerifyInclusion(leaves[0], 0, 4, goodPath[:1], root); err == nil ||
		!strings.Contains(err.Error(), "too short") {
		t.Fatalf("a truncated proof must be rejected, got %v", err)
	}
	// A proof folding to a DIFFERENT root.
	otherRoot := bytes.Repeat([]byte{0x42}, 32)
	if err := VerifyInclusion(leaves[0], 0, 4, goodPath, otherRoot); err == nil ||
		!strings.Contains(err.Error(), "does NOT fold") {
		t.Fatalf("a wrong root must be rejected, got %v", err)
	}
	// And the honest control: the untampered tuple verifies.
	if err := VerifyInclusion(leaves[0], 0, 4, goodPath, root); err != nil {
		t.Fatalf("the honest proof must verify: %v", err)
	}
}
