// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
