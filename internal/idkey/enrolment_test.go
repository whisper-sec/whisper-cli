// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The client half of the node-enrolment proof.

// The CROSS-LANGUAGE contract: the server derives this challenge independently, and
// asserts the identical vector on its own side. If either preimage drifts, one of the
// two fails. Go compresses IPv6 zero runs and Java
// does not, which is precisely why the address rides as raw bytes and why this vector exists.
func TestEnrolmentChallengeMatchesTheServerByteForByte(t *testing.T) {
	c := EnrolmentChallenge(
		netip.MustParseAddr("2a04:2a01:0:1::a1"),
		"HIgo9xNzJMWLKASShiTqIybxih1+dh1V/2K8E6xZ8Lc=",
		5000000)

	if len(c) != 95 {
		t.Fatalf("challenge length = %d, want 95", len(c))
	}
	d := sha256.Sum256(c)
	const want = "42f74892ca2695503a7add8728da3c661630ee177445f2800abf1289c276d67d"
	if got := hex.EncodeToString(d[:]); got != want {
		t.Fatalf("challenge digest = %s, want %s (the server derives the same bytes; one of us drifted)", got, want)
	}
	if !strings.HasPrefix(string(c), "whisper-node-enrolment/v1\x00") {
		t.Fatalf("the challenge must be domain-separated: %q", string(c[:32]))
	}
}

func TestChallengeBindsAddressTunnelKeyAndWindow(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:0:1::a1")
	base := EnrolmentChallenge(a, "wg", 7)

	cases := map[string][]byte{
		"another address":    EnrolmentChallenge(netip.MustParseAddr("2a04:2a01:0:1::a2"), "wg", 7),
		"another tunnel key": EnrolmentChallenge(a, "wg2", 7),
		"another window":     EnrolmentChallenge(a, "wg", 8),
	}
	for name, other := range cases {
		if string(other) == string(base) {
			t.Errorf("%s must produce a different challenge", name)
		}
	}
	if string(EnrolmentChallenge(a, "wg", 7)) != string(base) {
		t.Error("the challenge must be deterministic")
	}
}

func TestSignEnrolmentVerifiesUnderTheKeysOwnPublicHalf(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("2a04:2a01:0:1::a1")
	window := EnrolmentWindow(time.Now())

	sigB64, err := kp.SignEnrolment(a, "wg-pub", window)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("the signature must be standard base64: %v", err)
	}
	digest := sha256.Sum256(EnrolmentChallenge(a, "wg-pub", window))
	if !ecdsa.VerifyASN1(&kp.Private.PublicKey, digest[:], sig) {
		t.Fatal("the signature must verify under the signing key's own public half (ASN.1 DER, as Java reads it)")
	}
	// And it must NOT verify for a different window - the binding is real, not decorative.
	other := sha256.Sum256(EnrolmentChallenge(a, "wg-pub", window+1))
	if ecdsa.VerifyASN1(&kp.Private.PublicKey, other[:], sig) {
		t.Fatal("a signature must not verify for another window")
	}
}

func TestSignEnrolmentRefusesWithoutAKeyOrAnAddress(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kp.SignEnrolment(netip.Addr{}, "wg", 1); err == nil {
		t.Error("an invalid address must be a clear error, never a signature bound to nothing")
	}
	var nilKp *Keypair
	if _, err := nilKp.SignEnrolment(netip.MustParseAddr("2a04:2a01::1"), "wg", 1); err == nil {
		t.Error("no key must be a clear error")
	}
}

func TestEnrolmentWindowIsTheSameFloorDivisionTheServerDoes(t *testing.T) {
	if got := EnrolmentWindow(time.Unix(1_500_000_000, 0)); got != 1_500_000_000/EnrolmentWindowSeconds {
		t.Fatalf("window = %d", got)
	}
	// Two instants inside one quantum share a window; the next one does not.
	base := time.Unix(1_500_000_000, 0)
	if EnrolmentWindow(base) != EnrolmentWindow(base.Add(299*time.Second)) {
		t.Error("299s apart must be the same window")
	}
	if EnrolmentWindow(base) == EnrolmentWindow(base.Add(301*time.Second)) {
		t.Error("301s apart must not be the same window")
	}
}
