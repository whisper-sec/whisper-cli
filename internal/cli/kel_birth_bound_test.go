// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

// A signed birth is bound to the API key this client presents: the seed travels beside the
// statement, and the statement's nonce is the one the key derives from it, so the service can
// re-derive it and a copy of the statement is of no use with another key.

func TestBindBirthSignsOverTheNonceTheKeyDerives(t *testing.T) {
	custodyStore(t)
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{}
	birthArgs(args, kp, time.Now())
	unbound := args["key_event_nonce"]
	bindBirth(args, kp, " whisper_live_example ", time.Now())

	seed, _ := args["key_event_nonce_seed"].(string)
	if len(seed) != 32 {
		t.Fatalf("a bound birth carries a 32 hex seed, got %q", seed)
	}
	want, err := kel.BoundClientNonce(kel.BirthCallerKey("whisper_live_example"), seed)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := args["key_event_nonce"].(string)
	if nonce == unbound || len(nonce) < 32 || nonce[len(nonce)-32:] != want {
		t.Fatalf("the nonce %q is not the one the key derives from the seed (%s)", nonce, want)
	}
	if !kel.BirthWindowAccepted(nonce, time.Now().UnixMilli()) {
		t.Fatalf("the bound nonce names a window the service would refuse: %q", nonce)
	}
	commit, _ := args["next_key_commitment"].(string)
	if commit == "none" {
		commit = ""
	}
	birthSignatureVerifies(t, kp, args, commit)
}

func TestBindBirthLeavesAConnectWithNoBirthOrNoKeyAsItIs(t *testing.T) {
	custodyStore(t)
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	none := map[string]any{"tier": "wireguard"}
	bindBirth(none, kp, "whisper_live_example", time.Now())
	if _, ok := none["key_event_nonce_seed"]; ok {
		t.Fatal("a connect with no signed birth gained a seed")
	}
	args := map[string]any{}
	birthArgs(args, kp, time.Now())
	before := args["key_event_signature"]
	bindBirth(args, kp, "  ", time.Now())
	if _, ok := args["key_event_nonce_seed"]; ok || args["key_event_signature"] != before {
		t.Fatal("a client with no key changed the birth")
	}
}

func TestTheBoundNonceMatchesTheServiceVector(t *testing.T) {
	// the vector the service pins too
	got, err := kel.BoundClientNonce(kel.BirthCallerKey("whisper_live_example"), "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if got != "46da1a9b942e8547f710684384311ac6" {
		t.Fatalf("BoundClientNonce = %s", got)
	}
	if _, err := kel.BoundClientNonce(kel.BirthCallerKey("k"), "00112233445566778899AABBCCDDEEFF"); err == nil {
		t.Fatal("an uppercase seed is not the canonical spelling")
	}
}

func TestAnOlderServiceThatRefusesTheSeedGetsTheSameBirthUnbound(t *testing.T) {
	args := map[string]any{"key_event_signature": "s", "key_event_nonce": "birth:1:" + "00112233445566778899aabbccddeeff",
		"key_event_nonce_seed": "00112233445566778899aabbccddeeff"}
	old := &client.ProblemError{Status: 400, Detail: "op:connect does not read key_event_nonce_seed"}
	if !dropUnreadSeed(old, args) {
		t.Fatal("the unread-argument refusal should drop the seed")
	}
	if _, ok := args["key_event_nonce_seed"]; ok || args["key_event_signature"] == nil || args["key_event_nonce"] == nil {
		t.Fatalf("only the seed goes: %v", args)
	}
	if dropUnreadSeed(old, args) {
		t.Fatal("nothing left to drop")
	}
	args["key_event_nonce_seed"] = "00112233445566778899aabbccddeeff"
	ours := &client.ProblemError{Status: 400, Title: "KEY_EVENT_INVALID", Detail: "key_event_nonce_seed ..."}
	if dropUnreadSeed(ours, args) {
		t.Fatal("a key-event refusal is the service's answer, never an unread argument")
	}
	if !stripBirthArgs(args) {
		t.Fatal("a signed birth was there to strip")
	}
	if _, ok := args["key_event_nonce_seed"]; ok {
		t.Fatal("stripping a birth strips its seed too")
	}
}
