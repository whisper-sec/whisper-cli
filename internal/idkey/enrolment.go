// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"strconv"
	"time"
)

// The node-enrolment proof: the client half of a challenge the server derives
// independently. Both sides build the SAME bytes from facts they already
// share - this /128, the WireGuard public key being enrolled, and a coarse time window -
// so a routed connect proves possession of the persisted identity key in ONE call, with
// no challenge round trip and, crucially, without resending identity_public_key.
//
// That last point is not a detail. The server's zone-write classifier treats
// identity_public_key as re-authoring (it is: a rotated pin rewrites the zone), so a
// connect carrying it is forwarded to the primary. Resend the key on every reconnect and
// every Tier-1 tunnel in the fleet terminates on one box. The signature is a different
// argument for exactly that reason.
const (
	// enrolmentDomain separates this signature from every other use of the same key.
	// It is part of the signed bytes; changing the preimage shape changes this string.
	enrolmentDomain = "whisper-node-enrolment/v1"
	// EnrolmentWindowSeconds is the window quantum, matching the server's.
	EnrolmentWindowSeconds = 300
)

// EnrolmentWindow is the window number for an instant - the same floor division the
// server does, so a correct clock on both ends needs no search at all.
func EnrolmentWindow(t time.Time) int64 {
	return t.Unix() / EnrolmentWindowSeconds
}

// EnrolmentChallenge builds the exact bytes both sides sign. The address rides as its 16
// RAW BYTES, never as text: Go compresses IPv6 zero runs and Java does not, and a
// canonicalization disagreement would be indistinguishable from a wrong key. wgPublicKey
// is sent exactly as the caller will send it (empty when the server mints the tunnel key -
// a signature cannot cover a key the client has not seen).
func EnrolmentChallenge(addr netip.Addr, wgPublicKey string, window int64) []byte {
	a := addr.As16()
	out := make([]byte, 0, len(enrolmentDomain)+1+16+1+len(wgPublicKey)+1+20)
	out = append(out, enrolmentDomain...)
	out = append(out, 0)
	out = append(out, a[:]...)
	out = append(out, 0)
	out = append(out, wgPublicKey...)
	out = append(out, 0)
	out = append(out, strconv.FormatInt(window, 10)...)
	return out
}

// SignEnrolment returns the base64 (standard) ECDSA-P256/SHA-256 signature, ASN.1 DER
// encoded, over the derived challenge - the value of op:connect's identity_signature arg.
// The private key never leaves this process; only this signature does.
func (k *Keypair) SignEnrolment(addr netip.Addr, wgPublicKey string, window int64) (string, error) {
	if k == nil || k.Private == nil {
		return "", errors.New("no identity key to sign with")
	}
	if !addr.IsValid() {
		return "", errors.New("no address to bind the signature to")
	}
	digest := sha256.Sum256(EnrolmentChallenge(addr, wgPublicKey, window))
	sig, err := ecdsa.SignASN1(rand.Reader, k.Private, digest[:])
	if err != nil {
		return "", errors.New("could not sign the enrolment challenge")
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
