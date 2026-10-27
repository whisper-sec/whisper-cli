// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// A signed connect never carries an identity key.
//
// The service lets a signature move an identity's published key only when the signed statement
// names that key. This client signs the statement that names no key, which is safe exactly
// because it never sends a key beside a signature: every path that signs leaves
// identity_public_key out, and the one path that adds a key takes the signature away first. If a
// path ever sent both, the service would refuse the key move, and the connect would fail. These
// rows keep it that way.

func assertSignedCarriesNoKey(t *testing.T, where string, args map[string]any) {
	t.Helper()
	_, signed := args["identity_signature"]
	_, keyed := args["identity_public_key"]
	if signed && keyed {
		t.Fatalf("%s: a connect carries identity_signature and identity_public_key together", where)
	}
}

func TestEverySignedConnectPathLeavesTheKeyOut(t *testing.T) {
	restore := idkey.SetIdentityDirForTest(t.TempDir())
	defer restore()
	const addr = "2a04:2a01:0:1::b15"
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := idkey.Link(addr, kp); err != nil {
		t.Fatal(err)
	}

	// a reconnect to an address this host holds a key for
	reconnect := map[string]any{"public_key": "wg-pub"}
	if _, err := prepareIdentityKey("wireguard", reconnect, addr); err != nil {
		t.Fatal(err)
	}
	if _, signed := reconnect["identity_signature"]; !signed {
		t.Fatal("the reconnect row must be a signed one, or it proves nothing")
	}
	assertSignedCarriesNoKey(t, "reconnect", reconnect)

	// a held session's renewal, with a base that still carries a key from an earlier connect
	base := map[string]any{"identity_public_key": kp.MarshalSPKIBase64(), "public_key": "old"}
	renewal := renewalArgs(base, &connectKeys{identity: kp}, addr, time.Now())
	if _, signed := renewal["identity_signature"]; !signed {
		t.Fatal("the renewal row must be a signed one, or it proves nothing")
	}
	assertSignedCarriesNoKey(t, "renewal", renewal)

	// the self-heal that answers "no pin to verify against" swaps the signature for the key
	heal := map[string]any{}
	for k, v := range reconnect {
		heal[k] = v
	}
	if !retryAsBirthPin(heal, kp) {
		t.Fatal("a signed connect must be rewritable as a first enrolment")
	}
	if _, keyed := heal["identity_public_key"]; !keyed {
		t.Fatal("the self-heal must carry the key")
	}
	assertSignedCarriesNoKey(t, "self-heal", heal)

	// an explicit adopt sends the key and never a signature
	adopt := map[string]any{"public_key": "wg-pub", "adopt_identity_key": true}
	if _, err := prepareIdentityKey("wireguard", adopt, addr); err != nil {
		t.Fatal(err)
	}
	assertSignedCarriesNoKey(t, "adopt", adopt)
}
