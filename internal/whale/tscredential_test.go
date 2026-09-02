// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// tscredential_test.go asserts the one property that cannot be allowed to regress: the
// Tailscale credential must not be able to leave this process. Every test here is written
// so that it FAILS if the protection is removed, rather than passing on a promise.

const testSecret = "tskey-api-notarealkey-000000000000000000"

func TestCredentialRefusesToBeSerialised(t *testing.T) {
	c := NewAPIKeyCredential(testSecret)
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("a credential serialised to JSON. Anything that can be marshalled can be written into a plan file")
	}
	// And inside a struct, which is how it would actually happen by accident.
	type holder struct {
		Cred Credential `json:"cred"`
	}
	if _, err := json.Marshal(holder{Cred: c}); err == nil {
		t.Fatal("a credential nested in a struct serialised to JSON")
	}
}

func TestCredentialStringNeverContainsTheSecret(t *testing.T) {
	c := NewOAuthCredential("client-id-123", testSecret)
	for _, rendered := range []string{
		c.String(),
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%s", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprintf("%+v", c),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Fatalf("a rendering of the credential contained the secret: %q", rendered)
		}
		if !strings.Contains(rendered, c.Fingerprint()) {
			t.Fatalf("a rendering carried no fingerprint, so it identifies nothing: %q", rendered)
		}
	}
}

func TestFingerprintIsTwelveHexAndStable(t *testing.T) {
	a := NewAPIKeyCredential(testSecret).Fingerprint()
	b := NewOAuthCredential("other-client", testSecret).Fingerprint()
	if a != b {
		t.Fatal("the fingerprint depends on something other than the secret, so it cannot identify a credential across kinds")
	}
	if len(a) != 12 {
		t.Fatalf("the fingerprint is %d hex, and the plan format says 12", len(a))
	}
	if strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("the fingerprint %q is not lower-case hex", a)
	}
	if NewAPIKeyCredential("a-different-secret").Fingerprint() == a {
		t.Fatal("two different secrets fingerprinted the same")
	}
}

func TestZeroCredential(t *testing.T) {
	var c Credential
	if !c.IsZero() {
		t.Fatal("the zero credential does not report itself as absent")
	}
	if c.Fingerprint() != "" {
		t.Fatalf("the zero credential has fingerprint %q", c.Fingerprint())
	}
	if !strings.Contains(c.String(), "no tailscale credential") {
		t.Fatalf("the zero credential renders as %q", c.String())
	}
}

func TestScrubRemovesEverySecretSpelling(t *testing.T) {
	cases := []string{
		"failed for tskey-api-abcdef123456 while reading",
		"tskey-auth-kABCD1234CNTRL-abcdefghijklmno expired",
		"{\"message\":\"invalid key tskey-client-abcdefgh1234\"}",
	}
	for _, in := range cases {
		out := Scrub(in)
		if strings.Contains(out, "tskey-api-abcdef123456") ||
			strings.Contains(out, "kABCD1234CNTRL") ||
			strings.Contains(out, "abcdefgh1234") {
			t.Errorf("Scrub left a secret in %q -> %q", in, out)
		}
		if !strings.Contains(out, "REDACTED") {
			t.Errorf("Scrub silently dropped the whole thing from %q -> %q; the reader must see that something was removed", in, out)
		}
	}
}

func TestScrubLeavesOrdinaryTextAlone(t *testing.T) {
	in := "reading the device list of tailnet example.com returned status 403"
	if got := Scrub(in); got != in {
		t.Fatalf("Scrub rewrote ordinary text:\n  in  %q\n  out %q", in, got)
	}
}

// Postel, literally: a node auth key in the API-credential slot gets the sentence that
// unblocks the person, not a 401 from an API that was never going to accept it.
func TestLooksLikeTailscaleAuthKeyTellsTheTwoApart(t *testing.T) {
	authKeys := []string{
		"tskey-auth-kABCD1234-xyz", "TSKEY-AUTH-kABCD1234-xyz", "  tskey-auth-k1-abc  ",
		"tskey-kSomethingElse",
	}
	for _, k := range authKeys {
		if !LooksLikeTailscaleAuthKey(k) {
			t.Errorf("%q was not recognised as a node auth key, so the user gets an opaque 401 instead of the fix", k)
		}
	}
	apiCreds := []string{"tskey-api-abcdef", "tskey-client-abcdef", "", "not-a-key"}
	for _, k := range apiCreds {
		if LooksLikeTailscaleAuthKey(k) {
			t.Errorf("%q was refused as a node auth key, so a valid API credential would be rejected", k)
		}
	}
}
