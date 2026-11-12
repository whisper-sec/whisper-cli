// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

// A birth is always signed by the key it introduces: the signature is the proof that this host
// holds the private key, and a public key sent without it is not published. When the next key
// cannot be kept the birth is signed sealed ("none"), never sent unsigned.

func birthSignatureVerifies(t *testing.T, kp *idkey.Keypair, args map[string]any, commit string) {
	t.Helper()
	sigB64, _ := args["key_event_signature"].(string)
	nonce, _ := args["key_event_nonce"].(string)
	if sigB64 == "" || nonce == "" {
		t.Fatalf("the birth is not signed: %v", args)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	st := kel.Statement{Kind: kel.ICP, Authority: kel.Birth, Sequence: 0, Prior: kel.Genesis, NewKey: kp.Digest(),
		NextCommit: commit, BindNonce: nonce}
	b, err := st.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := kel.VerifySignature(kp.SPKI(), b, sig); got != kel.SigValid {
		t.Fatalf("the birth signature does not verify: %s", got)
	}
}

func TestBirthArgsCommitToTheStoredNextKey(t *testing.T) {
	custodyStore(t)
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{}
	birthArgs(args, kp, time.Now())
	commit, _ := args["next_key_commitment"].(string)
	if commit == "" || commit == "none" {
		t.Fatalf("a birth with a stored next key commits to it, got %q", commit)
	}
	birthSignatureVerifies(t, kp, args, commit)
}

func TestBirthArgsSignSealedWhenTheNextKeyCannotBeKept(t *testing.T) {
	dir := custodyStore(t)
	// a file where the key directory belongs: nothing can be stored there, whoever runs the test
	if err := os.WriteFile(filepath.Join(dir, "kel"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{}
	birthArgs(args, kp, time.Now())
	if got := args["next_key_commitment"]; got != "none" {
		t.Fatalf("next_key_commitment = %v, want the sealed spelling none", got)
	}
	birthSignatureVerifies(t, kp, args, "")
}
