// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// testAgentKey returns a P-256 identity key and the 65-octet uncompressed point (0x04||X||Y) the
// OPENPGPKEY would publish for it - the same form circl's KEM uses as the public key.
func testAgentKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := make([]byte, 65)
	point[0] = 0x04
	key.X.FillBytes(point[1:33])
	key.Y.FillBytes(point[33:65])
	return key, point
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// encodeOpenpgpP256 mirrors the OpenPGP public-key packet encoding used in the OPENPGPKEY record
// (RFC 4880): a v4 ECDSA-over-P-256 transferable public-key packet. Used to prove openpgpP256Point
// is its exact inverse (the published OPENPGPKEY wire contract).
func encodeOpenpgpP256(point []byte) []byte {
	oid := []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07} // NIST P-256
	body := []byte{0x04, 0x69, 0x54, 0x5A, 0x00, 19, byte(len(oid))}
	body = append(body, oid...)
	body = append(body, 0x02, 0x03) // MPI bit-length 515 (0x04||X||Y)
	body = append(body, point...)
	return append([]byte{0xC6, byte(len(body))}, body...)
}

// The whole seal->open path round-trips: encrypt to the agent's published point, decrypt with its
// private key, recover the exact plaintext. Also proves the recipient is bound (a different key
// cannot open) and that tampering the ciphertext fails closed.
func TestHPKESealOpenRoundTrip(t *testing.T) {
	recipient := "a1b2c3.agents.whisper.online"
	key, point := testAgentKey(t)

	pkR, err := wencKEM.Scheme().UnmarshalBinaryPublicKey(point)
	if err != nil {
		t.Fatalf("unmarshal pub: %v", err)
	}
	plaintext := []byte("the launch codes are in the second drawer\n")
	blob, err := hpkeSeal(recipient, pkR, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	skR, err := ecPrivToKem(keyPEM(t, key))
	if err != nil {
		t.Fatalf("priv->kem: %v", err)
	}
	msg, err := parseWenc(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.recipient != recipient {
		t.Fatalf("recipient = %q, want %q", msg.recipient, recipient)
	}
	got, err := hpkeOpen(msg, skR)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}

	// A different identity's key cannot open it.
	otherKey, _ := testAgentKey(t)
	otherSk, _ := ecPrivToKem(keyPEM(t, otherKey))
	if _, err := hpkeOpen(msg, otherSk); err == nil {
		t.Fatal("a foreign key unexpectedly opened the message")
	}

	// Tampering the ciphertext fails closed.
	tampered := *msg
	tampered.ct = append([]byte{}, msg.ct...)
	tampered.ct[len(tampered.ct)-1] ^= 0xff
	if _, err := hpkeOpen(&tampered, skR); err == nil {
		t.Fatal("tampered ciphertext unexpectedly opened")
	}
}

// The .wenc container round-trips through the armored (PEM) and raw forms, and the recipient/suite
// are bound into the AEAD aad (flipping the recipient in the header breaks the open).
func TestWencContainerAndAAD(t *testing.T) {
	recipient := "x.agents.whisper.online"
	key, point := testAgentKey(t)
	pkR, _ := wencKEM.Scheme().UnmarshalBinaryPublicKey(point)
	blob, err := hpkeSeal(recipient, pkR, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}

	// Armor -> dearmor is identity; raw is also accepted (Postel).
	armored := pem.EncodeToMemory(&pem.Block{Type: wencArmorType, Bytes: blob})
	back, err := dearmorWenc(armored)
	if err != nil || string(back) != string(blob) {
		t.Fatalf("armor round-trip failed: %v", err)
	}
	if _, err := dearmorWenc(blob); err != nil {
		t.Fatalf("raw container rejected: %v", err)
	}

	// Corrupt the recipient bytes inside the header -> AEAD aad mismatch -> open fails.
	skR, _ := ecPrivToKem(keyPEM(t, key))
	bad := append([]byte{}, blob...)
	bad[13] ^= 0xff // header: magic(4) ver(1) kem(2) kdf(2) aead(2) rlen(2) recipient[0]@13
	badMsg, err := parseWenc(bad)
	if err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	if _, err := hpkeOpen(badMsg, skR); err == nil {
		t.Fatal("recipient tamper unexpectedly opened")
	}
}

// openpgpP256Point is the exact inverse of the packet encoder: encode a known point, parse it back,
// get the same 65 octets. Guards the OPENPGPKEY wire contract (RFC 4880 / RFC 7929).
func TestOpenpgpP256PointRoundTrip(t *testing.T) {
	_, point := testAgentKey(t)
	rdata := encodeOpenpgpP256(point)
	got, err := openpgpP256Point(rdata)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(got) != string(point) {
		t.Fatalf("point mismatch after round-trip")
	}
	// A truncated / malformed packet is rejected, not mis-parsed.
	if _, err := openpgpP256Point(rdata[:20]); err == nil {
		t.Fatal("truncated packet unexpectedly parsed")
	}
}

// parseWenc and openpgpP256Point must never panic and must fail closed on hostile input.
func TestParserRejectsHostileInput(t *testing.T) {
	bad := [][]byte{
		nil, {}, []byte("WENC"), []byte("XXXX\x01"),
		[]byte("WENC\x02"), // unsupported version
		append([]byte("WENC\x01"), 0xff, 0xff, 0, 1, 0, 2),             // unsupported suite ids
		append([]byte("WENC\x01\x00\x10\x00\x01\x00\x02"), 0xff, 0xff), // rlen claims 65535, no bytes
	}
	for i, b := range bad {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseWenc panicked on case %d: %v", i, r)
				}
			}()
			if _, err := parseWenc(b); err == nil {
				t.Errorf("parseWenc(case %d) should have errored", i)
			}
		}()
	}
	for i, b := range [][]byte{nil, {0xC6}, {0xC6, 0x52}, {0x00, 0x01}, make([]byte, 90)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("openpgpP256Point panicked on case %d: %v", i, r)
				}
			}()
			if _, err := openpgpP256Point(b); err == nil {
				t.Errorf("openpgpP256Point(case %d) should have errored", i)
			}
		}()
	}
}

// A corrupted KEM encapsulation (enc) - e.g. an off-curve point - must be rejected by HPKE Setup,
// not silently accepted (guards the invalid-curve property the review verified by reading circl).
func TestCorruptEncRejected(t *testing.T) {
	recipient := "y.agents.whisper.online"
	key, point := testAgentKey(t)
	pkR, _ := wencKEM.Scheme().UnmarshalBinaryPublicKey(point)
	blob, err := hpkeSeal(recipient, pkR, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := parseWenc(blob)
	skR, _ := ecPrivToKem(keyPEM(t, key))
	// Corrupt the enc (the ephemeral public key) into a non-point.
	msg.enc[1] ^= 0xff
	msg.enc[2] ^= 0xff
	if _, err := hpkeOpen(msg, skR); err == nil {
		t.Fatal("a corrupted (off-curve) enc unexpectedly opened")
	}
}
