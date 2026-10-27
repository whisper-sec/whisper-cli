// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// A connect signed by an identity key other than the one pinned for the /128 is refused with
// 403 IDENTITY_SIGNATURE_INVALID. That is not a rejected API key, and "run: whisper login" cannot fix
// it: the line must name the identity key and where it was read from.
func identityRefusal() *client.ProblemError {
	return &client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_INVALID", Type: "IDENTITY_SIGNATURE_INVALID",
		Detail: "identity_signature does not verify against the identity key pinned for " +
			"2a04:2a01:9:1d::b77d. A connect signed by a DIFFERENT key than the pin is " +
			"refused (and audited): rotate deliberately by signing with the OUTGOING key."}
}

func TestAMismatchedIdentityKeyNamesTheKeyNotTheLogin(t *testing.T) {
	restore := idkey.SetIdentityDirForTest("/tmp/some-home/.config/whisper/identity")
	defer restore()
	saved := sudoContext
	sudoContext = func() (string, bool) { return "", false }
	defer func() { sudoContext = saved }()

	got := mapProblem(identityRefusal())
	if strings.Contains(got, "whisper login") || strings.Contains(got, "key was not accepted") {
		t.Fatalf("an identity-key refusal must not send the person to whisper login: %q", got)
	}
	for _, want := range []string{"identity key", "2a04:2a01:9:1d::b77d",
		"/tmp/some-home/.config/whisper/identity"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "sudo") {
		t.Errorf("no sudo hint outside sudo: %q", got)
	}
}

func TestUnderSudoTheIdentityLineSaysWhoseDirectoryWasRead(t *testing.T) {
	restore := idkey.SetIdentityDirForTest("/root/.config/whisper/identity")
	defer restore()
	saved := sudoContext
	sudoContext = func() (string, bool) { return "labops", true }
	defer func() { sudoContext = saved }()

	got := mapProblem(identityRefusal())
	for _, want := range []string{"root", "labops", "sudo --preserve-env=HOME"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestAnyOtherForbiddenStillGetsTheLoginLine(t *testing.T) {
	got := mapProblem(&client.ProblemError{Status: 403, Title: "forbidden", Detail: "invalid api key"})
	if got != "your key was not accepted - run: whisper login" {
		t.Fatalf("a rejected key keeps its line: %q", got)
	}
}
