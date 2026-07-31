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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A tiny in-test RFC-6962 Merkle implementation so the verifier is checked against an
// INDEPENDENT tree (the real one is the Java engine; this proves cross-impl interop).
func leafHash(commitment []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(commitment)
	return h.Sum(nil)
}

func node(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func largestPow2Below(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return sha256.New().Sum(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestPow2Below(len(leaves))
	return node(mth(leaves[:k]), mth(leaves[k:]))
}

// inclusionPath is RFC 6962 PATH(m, D[0:n]).
func inclusionPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPow2Below(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), mth(leaves[:k]))
}

// TestLedgerVerifierEndToEnd proves the WHOLE release verifier with stock crypto: build a
// signed checkpoint, recompute a leaf from a disclosed (salt, event), and verify inclusion
// against the signed root — then prove a TAMPERED disclosure is rejected.
func TestLedgerVerifierEndToEnd(t *testing.T) {
	const origin = "whisper.online/ledger"

	// Build 9 leaves; leaf #3 is the "subject" whose (salt, event) is disclosed.
	salts := make([][]byte, 9)
	events := make([][]byte, 9)
	commitments := make([][]byte, 9)
	leaves := make([][]byte, 9)
	for i := 0; i < 9; i++ {
		salt := sha256.Sum256([]byte(fmt.Sprintf("salt-%d", i)))
		ev := []byte(fmt.Sprintf("assignment|subject-%d|%d", i, 1000+i))
		salts[i] = salt[:]
		events[i] = ev
		c := sha256.New()
		c.Write(salt[:])
		c.Write(ev)
		commitments[i] = c.Sum(nil)
		leaves[i] = leafHash(commitments[i])
	}
	root := mth(leaves)

	// Sign a C2SP checkpoint note (Ed25519) the way the server does.
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := fmt.Sprintf("%s\n%d\n%s\n", origin, len(leaves), base64.StdEncoding.EncodeToString(root))
	keyID := computeSignedNoteKeyID(origin, pub)
	sig := ed25519.Sign(priv, []byte(body))
	blob := make([]byte, 4+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(blob[:4], keyID)
	copy(blob[4:], sig)
	note := body + "\n" + sigPrefix + origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"

	// --- the verifier path ---
	cp, err := ParseCheckpointNote(note)
	if err != nil {
		t.Fatalf("ParseCheckpointNote: %v", err)
	}
	if cp.TreeSize != 9 {
		t.Fatalf("tree size = %d, want 9", cp.TreeSize)
	}
	key := &LedgerKey{
		Origin:    origin,
		Alg:       "Ed25519",
		KeyID:     fmt.Sprintf("%08x", keyID),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	if err := cp.VerifySignature(key); err != nil {
		t.Fatalf("checkpoint signature must verify: %v", err)
	}

	// The SUBJECT recomputes the leaf from their disclosed (salt, event).
	subject := 3
	recomputed := LeafHashFromDisclosure(salts[subject], events[subject])
	if !bytes.Equal(recomputed, leaves[subject]) {
		t.Fatalf("recomputed leaf must equal the published leaf")
	}
	path := inclusionPath(subject, leaves)
	if err := VerifyInclusion(recomputed, uint64(subject), cp.TreeSize, path, cp.Root); err != nil {
		t.Fatalf("inclusion must verify against the signed root: %v", err)
	}

	// A TAMPERED disclosure (wrong salt) recomputes to a different leaf → inclusion REJECTED.
	badSalt := append([]byte(nil), salts[subject]...)
	badSalt[0] ^= 0x01
	tampered := LeafHashFromDisclosure(badSalt, events[subject])
	if bytes.Equal(tampered, leaves[subject]) {
		t.Fatalf("a tampered salt must NOT reproduce the leaf")
	}
	if err := VerifyInclusion(tampered, uint64(subject), cp.TreeSize, path, cp.Root); err == nil {
		t.Fatalf("a tampered leaf must FAIL inclusion verification")
	}

	// A WRONG signing key must fail signature verification (split-key / forgery guard).
	otherPub, _, _ := ed25519.GenerateKey(nil)
	badKey := &LedgerKey{Alg: "Ed25519", KeyID: key.KeyID, PublicKey: base64.StdEncoding.EncodeToString(otherPub)}
	if err := cp.VerifySignature(badKey); err == nil {
		t.Fatalf("the checkpoint must NOT verify under a different key")
	}
}

// computeSignedNoteKeyID mirrors the server's C2SP key-id: first 4 bytes of
// SHA-256(name || '\n' || 0x01 || raw-ed25519-public), big-endian.
func computeSignedNoteKeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', 0x01})
	h.Write(pub)
	d := h.Sum(nil)
	return binary.BigEndian.Uint32(d[:4])
}

// ---- witness cosignature verification -----------------------------------------

// computeCosignatureKeyID mirrors the server's C2SP COSIGNATURE key-id (the 0x04 flavour):
// first 4 bytes of SHA-256(name || '\n' || 0x04 || raw-ed25519-public), big-endian.
func computeCosignatureKeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', 0x04})
	h.Write(pub)
	d := h.Sum(nil)
	return binary.BigEndian.Uint32(d[:4])
}

// cosignLine builds the C2SP cosignature/v1 signed-note line the way the server (and a
// stock tlog-witness) does: "— <name> <b64(keyId[4]||time[8]||sig[64])>", where sig is
// Ed25519 over "cosignature/v1\ntime <ts>\n" + note body.
func cosignLine(name string, priv ed25519.PrivateKey, pub ed25519.PublicKey, ts uint64, body []byte) string {
	msg := append([]byte(fmt.Sprintf("cosignature/v1\ntime %d\n", ts)), body...)
	sig := ed25519.Sign(priv, msg)
	blob := make([]byte, 4+8+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(blob[:4], computeCosignatureKeyID(name, pub))
	binary.BigEndian.PutUint64(blob[4:12], ts)
	copy(blob[12:], sig)
	return sigPrefix + name + " " + base64.StdEncoding.EncodeToString(blob)
}

// signedNote builds a log-signed C2SP checkpoint note over an arbitrary 9-leaf tree and
// returns (note, body) — the shared fixture for the cosignature tests.
func signedNote(t *testing.T, origin string) (string, []byte, *LedgerKey) {
	t.Helper()
	leaves := make([][]byte, 9)
	for i := range leaves {
		c := sha256.Sum256([]byte(fmt.Sprintf("commitment-%d", i)))
		leaves[i] = leafHash(c[:])
	}
	root := mth(leaves)
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := fmt.Sprintf("%s\n%d\n%s\n", origin, len(leaves), base64.StdEncoding.EncodeToString(root))
	keyID := computeSignedNoteKeyID(origin, pub)
	sig := ed25519.Sign(priv, []byte(body))
	blob := make([]byte, 4+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(blob[:4], keyID)
	copy(blob[4:], sig)
	note := body + "\n" + sigPrefix + origin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
	key := &LedgerKey{Origin: origin, Alg: "Ed25519",
		KeyID: fmt.Sprintf("%08x", keyID), PublicKey: base64.StdEncoding.EncodeToString(pub)}
	return note, []byte(body), key
}

// TestCosignatureParsingDiscriminatesBlobWidths proves the 76-byte cosignature blobs are
// separated from the 68-byte log-signature blob on the SAME note — and that appending
// cosignature lines never disturbs the log signature or the parsed root.
func TestCosignatureParsingDiscriminatesBlobWidths(t *testing.T) {
	const origin = "whisper.online/ledger"
	note, body, key := signedNote(t, origin)

	extPub, extPriv, _ := ed25519.GenerateKey(nil)
	ns2Pub, ns2Priv, _ := ed25519.GenerateKey(nil)
	ts := uint64(1_700_000_000)
	cosigned := note +
		cosignLine("witness.example.org/sigsum", extPriv, extPub, ts, body) + "\n" +
		cosignLine("whisper.online/witness/ns2", ns2Priv, ns2Pub, ts, body) + "\n"

	cp, err := ParseCheckpointNote(cosigned)
	if err != nil {
		t.Fatalf("ParseCheckpointNote: %v", err)
	}
	if len(cp.Cosigs) != 2 {
		t.Fatalf("cosignatures parsed = %d, want 2 (the 68-byte log line must NOT count)", len(cp.Cosigs))
	}
	if cp.Cosigs[0].Name != "witness.example.org/sigsum" || cp.Cosigs[0].Timestamp != ts {
		t.Fatalf("first cosignature parsed wrong: %+v", cp.Cosigs[0])
	}
	// The log signature is intact and still verifies — cosignature lines are additive.
	if err := cp.VerifySignature(key); err != nil {
		t.Fatalf("the log signature must survive appended cosignature lines: %v", err)
	}
	// And the message recompute matches the C2SP shape exactly.
	want := "cosignature/v1\ntime 1700000000\n" + string(body)
	if string(cp.CosignatureMessage(ts)) != want {
		t.Fatalf("CosignatureMessage mismatch:\n got %q\nwant %q", cp.CosignatureMessage(ts), want)
	}
}

// TestIndependentCosignatureVerdict proves the HONEST CLI verdict: "publicly
// verifiable" requires a FRESH, VERIFYING cosignature from an INDEPENDENT witness — a stale
// cosignature, an availability-only witness, a tampered signature, or a wrong key never count.
func TestIndependentCosignatureVerdict(t *testing.T) {
	const origin = "whisper.online/ledger"
	note, body, _ := signedNote(t, origin)

	extPub, extPriv, _ := ed25519.GenerateKey(nil)
	ns2Pub, ns2Priv, _ := ed25519.GenerateKey(nil)
	now := int64(1_700_100_000)
	maxAge := int64(86_400)
	policy := &WitnessPolicy{
		Threshold:     1,
		MaxAgeSeconds: maxAge,
		Witnesses: []WitnessEntry{
			{Name: "whisper.online/witness/ns2", PublicKey: base64.StdEncoding.EncodeToString(ns2Pub),
				Independent: false, Role: "availability-cross-check"},
			{Name: "witness.example.org/sigsum", PublicKey: base64.StdEncoding.EncodeToString(extPub),
				Independent: true, Role: "independent"},
		},
	}
	parse := func(cosigned string) *LedgerCheckpoint {
		cp, err := ParseCheckpointNote(cosigned)
		if err != nil {
			t.Fatalf("ParseCheckpointNote: %v", err)
		}
		return cp
	}

	// (a) A FRESH independent cosignature ⇒ 1 (publicly verifiable).
	fresh := note + cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now-60), body) + "\n"
	if got := parse(fresh).VerifyIndependentCosignatures(policy, now); got != 1 {
		t.Fatalf("fresh independent cosignature: got %d, want 1", got)
	}
	// (b) A STALE independent cosignature (past max-age) ⇒ 0 — the verdict self-revokes.
	stale := note + cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now-maxAge-1), body) + "\n"
	if got := parse(stale).VerifyIndependentCosignatures(policy, now); got != 0 {
		t.Fatalf("stale independent cosignature must NOT count: got %d", got)
	}
	// (c) An AVAILABILITY-only cosignature (independent=false), fresh + verifying ⇒ 0.
	avail := note + cosignLine("whisper.online/witness/ns2", ns2Priv, ns2Pub, uint64(now-60), body) + "\n"
	if got := parse(avail).VerifyIndependentCosignatures(policy, now); got != 0 {
		t.Fatalf("the ns1<->ns2 availability peer must NEVER count: got %d", got)
	}
	// (d) A TAMPERED cosignature ⇒ 0.
	line := cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now-60), body)
	blobStart := len(sigPrefix + "witness.example.org/sigsum ")
	blob, _ := base64.StdEncoding.DecodeString(line[blobStart:])
	blob[12] ^= 0x01 // flip a signature bit
	tampered := note + line[:blobStart] + base64.StdEncoding.EncodeToString(blob) + "\n"
	if got := parse(tampered).VerifyIndependentCosignatures(policy, now); got != 0 {
		t.Fatalf("a tampered cosignature must NOT count: got %d", got)
	}
	// (e) A cosignature from a WRONG (unpinned) key ⇒ 0.
	roguePub, roguePriv, _ := ed25519.GenerateKey(nil)
	rogue := note + cosignLine("witness.example.org/sigsum", roguePriv, roguePub, uint64(now-60), body) + "\n"
	if got := parse(rogue).VerifyIndependentCosignatures(policy, now); got != 0 {
		t.Fatalf("an unpinned key must NOT count: got %d", got)
	}
	// (f) A SLIGHTLY future-dated cosignature (witness clock ahead, within the bounded tolerance)
	// is FRESH — never over-revoke on a slow local clock. Exactly AT the tolerance still counts.
	future := note + cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now+maxForwardSkewSeconds), body) + "\n"
	if got := parse(future).VerifyIndependentCosignatures(policy, now); got != 1 {
		t.Fatalf("a future-dated cosignature within the skew tolerance is fresh: got %d, want 1", got)
	}
	// (f2) BEYOND the tolerance a future-dated cosignature must NOT count — an unbounded future
	// timestamp would keep the verdict alive forever on a frozen tree (self-revocation defeated).
	farFuture := note + cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now+maxForwardSkewSeconds+1), body) + "\n"
	if got := parse(farFuture).VerifyIndependentCosignatures(policy, now); got != 0 {
		t.Fatalf("a far-future-dated cosignature must NOT count: got %d", got)
	}
	// (g) TWO distinct independent witnesses ⇒ 2 (counted distinctly).
	ext2Pub, ext2Priv, _ := ed25519.GenerateKey(nil)
	policy2 := &WitnessPolicy{MaxAgeSeconds: maxAge, Witnesses: append(policy.Witnesses,
		WitnessEntry{Name: "witness2.example.net/tlog", PublicKey: base64.StdEncoding.EncodeToString(ext2Pub),
			Independent: true, Role: "independent"})}
	two := note +
		cosignLine("witness.example.org/sigsum", extPriv, extPub, uint64(now-60), body) + "\n" +
		cosignLine("witness2.example.net/tlog", ext2Priv, ext2Pub, uint64(now-60), body) + "\n"
	if got := parse(two).VerifyIndependentCosignatures(policy2, now); got != 2 {
		t.Fatalf("two distinct independent witnesses: got %d, want 2", got)
	}
	// (h) A zero/absent max-age falls back to 24h (liberal accept).
	noBound := &WitnessPolicy{Witnesses: policy.Witnesses}
	if got := parse(fresh).VerifyIndependentCosignatures(noBound, now); got != 1 {
		t.Fatalf("absent max-age must default to 24h: got %d, want 1", got)
	}
}

// TestPinnedWitnessVerdict proves the OUT-OF-BAND pinned mode ( review): with
// --witness-key pins the verdict counts ONLY cosignatures verifying under a pinned key — a
// key the ORIGIN lists as independent:true but the verifier did not pin gains nothing (the
// compromised-origin scenario), and all three accepted pin encodings decode to the same key.
func TestPinnedWitnessVerdict(t *testing.T) {
	const origin = "whisper.online/ledger"
	note, body, _ := signedNote(t, origin)
	now := int64(1_700_100_000)

	pinnedPub, pinnedPriv, _ := ed25519.GenerateKey(nil)
	unpinnedPub, unpinnedPriv, _ := ed25519.GenerateKey(nil)

	parse := func(cosigned string) *LedgerCheckpoint {
		cp, err := ParseCheckpointNote(cosigned)
		if err != nil {
			t.Fatalf("ParseCheckpointNote: %v", err)
		}
		return cp
	}

	// (a) A fresh cosignature under the PINNED key counts.
	pins := [][]byte{[]byte(pinnedPub)}
	pinnedPolicy := PinnedWitnessPolicy(pins, 0) // 0 ⇒ the 24h default inside the verifier
	fresh := note + cosignLine("witness.example.org/sigsum", pinnedPriv, pinnedPub, uint64(now-60), body) + "\n"
	if got := parse(fresh).VerifyIndependentCosignatures(pinnedPolicy, now); got != 1 {
		t.Fatalf("a fresh cosignature under the pinned key must count: got %d, want 1", got)
	}
	// (b) A cosignature under a key the SERVER calls independent but the verifier did NOT pin
	// counts for NOTHING in pinned mode — the malicious-origin scenario the pin defeats.
	rogue := note + cosignLine("evil.example.com/self", unpinnedPriv, unpinnedPub, uint64(now-60), body) + "\n"
	if got := parse(rogue).VerifyIndependentCosignatures(pinnedPolicy, now); got != 0 {
		t.Fatalf("an unpinned 'independent' key must gain nothing in pinned mode: got %d", got)
	}
	// (c) The three accepted pin encodings decode to the identical raw key: base64 raw,
	// base64 SPKI (the /witness/keys public_key_spki form), and hex.
	rawB64 := base64.StdEncoding.EncodeToString(pinnedPub)
	spki := append(append([]byte(nil), ed25519SPKIPrefix...), pinnedPub...)
	spkiB64 := base64.StdEncoding.EncodeToString(spki)
	hexForm := fmt.Sprintf("%x", []byte(pinnedPub))
	for _, form := range []string{rawB64, spkiB64, hexForm, "0x" + hexForm} {
		got, err := ParseWitnessKeyPin(form)
		if err != nil {
			t.Fatalf("ParseWitnessKeyPin(%q): %v", form, err)
		}
		if !bytes.Equal(got, pinnedPub) {
			t.Fatalf("pin form %q decoded to the wrong key", form)
		}
	}
	// (d) A malformed pin is a clean error (never silently unpinned).
	for _, bad := range []string{"", "not-a-key", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseWitnessKeyPin(bad); err == nil {
			t.Fatalf("ParseWitnessKeyPin(%q) must fail", bad)
		}
	}
	// (e) The pinned policy inherits the freshness gate: a stale cosignature self-revokes.
	stale := note + cosignLine("witness.example.org/sigsum", pinnedPriv, pinnedPub, uint64(now-86_400-1), body) + "\n"
	if got := parse(stale).VerifyIndependentCosignatures(pinnedPolicy, now); got != 0 {
		t.Fatalf("a stale cosignature must self-revoke in pinned mode too: got %d", got)
	}
}

// TestFetchWitnessKeys proves the /witness/keys decode — and that a 404
// (witnessing off) surfaces as a clean ProblemError the CLI treats as "no policy".
func TestFetchWitnessKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/witness/keys" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"object":"whisper-witness-policy","threshold":1,`+
			`"claim":"tamper-evident, signed transparency log","publicly_verifiable":false,`+
			`"publicly_verifiable_max_age_seconds":86400,"witnesses":[`+
			`{"name":"whisper.online/witness/ns2","key_id":"0a0b0c0d","public_key":"cHVi",`+
			`"public_key_spki":"c3BraQ==","independent":false,"role":"availability-cross-check"}]}`)
	}))
	defer srv.Close()

	c := New(Config{RDAPURL: srv.URL, HTTPClient: srv.Client()})
	p, err := c.FetchWitnessKeys(context.Background())
	if err != nil {
		t.Fatalf("FetchWitnessKeys: %v", err)
	}
	if p.Threshold != 1 || p.PubliclyVerifiable || p.MaxAgeSeconds != 86400 {
		t.Fatalf("policy decoded wrong: %+v", p)
	}
	if len(p.Witnesses) != 1 || p.Witnesses[0].Independent || p.Witnesses[0].Name != "whisper.online/witness/ns2" {
		t.Fatalf("witness entry decoded wrong: %+v", p.Witnesses)
	}

	// Witnessing off (404) → a ProblemError, which the checkpoint command treats as "no policy".
	off := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer off.Close()
	c2 := New(Config{RDAPURL: off.URL, HTTPClient: off.Client()})
	if _, err := c2.FetchWitnessKeys(context.Background()); err == nil {
		t.Fatalf("a 404 must surface as an error the caller downgrades to 'no policy'")
	}
}
