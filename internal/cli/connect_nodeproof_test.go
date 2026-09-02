// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// What a routed connect actually puts on the wire.
//
// The row that matters most is the second one: a RECONNECT to a /128 whose key we already
// hold stops sending identity_public_key. That argument is what the server's zone-write
// classifier reads as re-authoring, and a connect carrying it is forwarded to the primary -
// resent on every reconnect it lands every Tier-1 tunnel in the fleet on one box. The proof
// replaces it rather than joining it.

func TestFirstConnectPinsTheKeyAndSignsNothing(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()

	args := map[string]any{"public_key": "wg-pub"}
	kp, err := prepareIdentityKey("wireguard", args, "2a04:2a01:0:1::a1")
	if err != nil {
		t.Fatal(err)
	}
	if kp == nil {
		t.Fatal("the routed tier must prepare an identity key")
	}
	if args["identity_public_key"] != kp.MarshalSPKIBase64() {
		t.Fatal("a first connect must carry the SPKI - there is no pin to prove yet (trust on first use)")
	}
	if _, signed := args["identity_signature"]; signed {
		t.Fatal("a first connect cannot sign against a pin that does not exist")
	}
}

func TestReconnectProvesPossessionAndStopsResendingTheKey(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()
	const addr = "2a04:2a01:0:1::a1"

	first := map[string]any{"public_key": "wg-pub"}
	kp, err := prepareIdentityKey("wireguard", first, addr) // mints + persists
	if err != nil {
		t.Fatal(err)
	}

	second := map[string]any{"public_key": "wg-pub"}
	kp2, err := prepareIdentityKey("wireguard", second, addr)
	if err != nil {
		t.Fatal(err)
	}
	if kp2.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatal("a reconnect must reuse the SAME persisted key, never rotate the published pin")
	}
	if _, resent := second["identity_public_key"]; resent {
		t.Fatal("a proven reconnect must NOT resend identity_public_key (it is what forwards the connect)")
	}
	sigB64, ok := second["identity_signature"].(string)
	if !ok || sigB64 == "" {
		t.Fatal("a reconnect must carry identity_signature")
	}
	window, ok := second["identity_signature_window"].(int64)
	if !ok {
		t.Fatalf("identity_signature_window must be a whole number, got %T", second["identity_signature_window"])
	}

	// And the signature is over the challenge the SERVER will rebuild, not over something else.
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(idkey.EnrolmentChallenge(netip.MustParseAddr(addr), "wg-pub", window))
	if !ecdsa.VerifyASN1(&kp.Private.PublicKey, digest[:], sig) {
		t.Fatal("the signature must verify over (address, wg public key, window) - exactly what the server derives")
	}
}

func TestAnAgentIdSelectorKeepsTheUnchangedBirthPinPath(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()

	// An agent id is not an address, so there is nothing to bind a signature to: the behaviour
	// is exactly what shipped before that work, rather than a guess about which /128 is meant.
	args := map[string]any{"public_key": "wg-pub"}
	if _, err := prepareIdentityKey("wireguard", args, "agent-db-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareIdentityKey("wireguard", args, "agent-db-01"); err != nil {
		t.Fatal(err)
	}
	if _, signed := args["identity_signature"]; signed {
		t.Fatal("an agent-id selector must not produce a signature")
	}
	if args["identity_public_key"] == nil {
		t.Fatal("an agent-id selector keeps the birth-pin behaviour")
	}
}

func TestNonRoutedTiersCarryNeitherKeyNorSignature(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()

	for _, tier := range []string{"socks5", "anyip", ""} {
		args := map[string]any{}
		kp, err := prepareIdentityKey(tier, args, "2a04:2a01:0:1::a1")
		if err != nil || kp != nil {
			t.Fatalf("tier %q must be a no-op (kp=%v err=%v)", tier, kp, err)
		}
		if len(args) != 0 {
			t.Fatalf("tier %q must leave the args untouched: %v", tier, args)
		}
	}
}
