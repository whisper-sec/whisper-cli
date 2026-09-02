// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// The self-heal these cover, and why it exists.
//
// We stopped resending identity_public_key on a reconnect to an address we already
// hold a key for, and proved possession with a signature instead. That rests on an
// assumption nothing checked: that the pin is already published on the box this connect
// lands on. When it is not, the server answers "no identity key is pinned for this address
// to verify against" and Tier 1 fails for that agent FOREVER, because every retry makes the
// same unprovable claim. Measured on real hardware: a `--tier wireguard` that had worked an
// hour earlier failed on every later attempt, and plain `whisper connect` silently
// downgraded to Tier 1.5 with the reason visible only under WHISPER_DEBUG.
//
// The answer is to say who we are when the server says it has nothing to check against, and
// ONLY then. The tests below drive both sides of that "only then", because a broad match
// would turn every enrolment refusal into a re-pin attempt, which is the thing the
// narrow match exists to prevent.

func TestServerHoldsNoPin_MatchesOnlyThatRefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the server's own sentence", errors.New(
			"no identity key is pinned for this address to verify against"), true},
		{"wrapped in a ProblemError, as the envelope delivers it", &client.ProblemError{
			Status: 403,
			Detail: "no identity key is pinned for this address to verify against",
		}, true},
		{"case-insensitive, because a server may capitalise", errors.New(
			"No identity key is pinned for this address to verify against"), true},
		{"a DIFFERENT enrolment refusal must NOT re-pin", &client.ProblemError{
			Status: 403,
			Detail: "identity_signature does not verify against the pinned key",
		}, false},
		{"a window refusal must NOT re-pin", errors.New(
			"identity_signature_window 42 is 9 windows from this server's 51"), false},
		{"an empty signature must NOT re-pin", errors.New("identity_signature is empty"), false},
		{"an unrelated failure", errors.New("agent not found"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverHoldsNoPin(tc.err); got != tc.want {
				t.Fatalf("serverHoldsNoPin(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryAsBirthPin_SwapsTheProofForTheKey(t *testing.T) {
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatalf("could not generate an identity key: %v", err)
	}
	args := map[string]any{
		"tier":                      "wireguard",
		"public_key":                "wg-public-key",
		"identity_signature":        "a-signature",
		"identity_signature_window": int64(51),
	}
	if !retryAsBirthPin(args, kp) {
		t.Fatal("retryAsBirthPin refused a proof-of-possession connect it should have rewritten")
	}
	if _, still := args["identity_signature"]; still {
		t.Error("identity_signature survived the rewrite; the server would verify it against nothing again")
	}
	if _, still := args["identity_signature_window"]; still {
		t.Error("identity_signature_window survived the rewrite")
	}
	got, ok := args["identity_public_key"].(string)
	if !ok || got == "" {
		t.Fatal("the rewrite did not put an identity_public_key in, so the retry says nothing new")
	}
	if want := kp.MarshalSPKIBase64(); got != want {
		t.Errorf("the key sent is not the key we hold:\n got %q\nwant %q", got, want)
	}
	// Everything else has to survive untouched: the retry is the SAME connect with a
	// different way of proving who we are, not a different connect.
	if args["tier"] != "wireguard" || args["public_key"] != "wg-public-key" {
		t.Errorf("the rewrite disturbed the rest of the request: %v", args)
	}
}

// The control. Without it, an implementation that rewrote EVERY request would pass the
// test above and would resend the key on a first connect that had already sent it, which
// the zone-write classifier reads as re-authoring and forwards to the primary: resent on
// every connect, that lands every Tier-1 tunnel in the fleet on one box.
func TestRetryAsBirthPin_RefusesWhenThereWasNoProofToReplace(t *testing.T) {
	kp, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatalf("could not generate an identity key: %v", err)
	}
	args := map[string]any{
		"tier":                "wireguard",
		"identity_public_key": "already-a-birth-pin",
	}
	if retryAsBirthPin(args, kp) {
		t.Fatal("retryAsBirthPin rewrote a request that was already a first enrolment; " +
			"the caller would retry a request it did not change")
	}
	if args["identity_public_key"] != "already-a-birth-pin" {
		t.Error("it overwrote the key on a request it claimed not to have touched")
	}
}
