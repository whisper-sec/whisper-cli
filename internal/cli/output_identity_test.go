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

// An identity pin the service could not publish is answered with the same two codes for an
// account key and an agent key. The retryable 503 keeps its own sentence (what was pinned, retry),
// never a generic "busy"; the 409 that would repeat passes its detail through, which names the repair.
func TestPinPublishAnswersKeepTheServicesOwnSentence(t *testing.T) {
	failed := &client.ProblemError{Status: 503, Title: "PIN_PUBLISH_FAILED", Type: "PIN_PUBLISH_FAILED",
		Detail: "the identity key could not be published for 2a04:2a01::1, and nothing was pinned - retry shortly"}
	if got := mapProblem(failed); got != "" {
		t.Fatalf("PIN_PUBLISH_FAILED must pass its own detail through, got %q", got)
	}
	if got := friendly(failed); !strings.Contains(got, "nothing was pinned") || !strings.Contains(got, "retry") {
		t.Fatalf("the rendered line must say nothing was pinned and to retry: %q", got)
	}
	incomplete := &client.ProblemError{Status: 503, Type: "PIN_PUBLISH_INCOMPLETE",
		Detail: "the identity key for 2a04:2a01::1 is stored but its DNS records may not be published yet"}
	if got := friendly(incomplete); !strings.Contains(got, "may not be published yet") {
		t.Fatalf("PIN_PUBLISH_INCOMPLETE keeps its sentence: %q", got)
	}
	refused := &client.ProblemError{Status: 409, Title: "PIN_PUBLISH_REFUSED", Type: "PIN_PUBLISH_REFUSED",
		Detail: "the zone refused the identity key records for 2a04:2a01::1 (record_cap), and a retry would be " +
			"refused the same way; nothing was pinned. Repair the identity's records with op:identity{op:'repair', address}."}
	if got := friendly(refused); !strings.Contains(got, "op:'repair'") || strings.Contains(got, "busy") {
		t.Fatalf("PIN_PUBLISH_REFUSED must name the repair and never read as busy: %q", got)
	}
	// a 503 that is not about a pin still gets the generic line (the control for the rule above)
	other := &client.ProblemError{Status: 503, Type: "STORE_UNAVAILABLE", Detail: "Durable store unavailable"}
	if got := mapProblem(other); !strings.Contains(got, "busy") {
		t.Fatalf("an unrelated 503 keeps the generic line: %q", got)
	}
}

// A reverse with nothing on record is a 404 about the audit trail, not the agent, and a reverse the state
// forbids is a 409. Both keep the service's own sentence; neither becomes "that agent isn't in your account".
func TestReversalAnswersKeepTheServicesOwnSentence(t *testing.T) {
	nothing := &client.ProblemError{Status: 404, Title: "NOTHING_TO_REVERSE", Type: "NOTHING_TO_REVERSE",
		Detail: "nothing to reverse for agent-a1b2c3: this account has no revoke of it on record (it was never " +
			"done by this account, or it is older than the 90-day audit retention). Nothing was changed. To bring it " +
			"back, mint a new identity with op:identity or op:register; op:list{kind:'audit'} shows this account's " +
			"containment history."}
	if got := mapProblem(nothing); got != "" {
		t.Fatalf("NOTHING_TO_REVERSE must pass its own detail through, got %q", got)
	}
	if got := friendly(nothing); !strings.Contains(got, "nothing to reverse") || !strings.Contains(got, "op:register") ||
		strings.Contains(got, "isn't in your account") {
		t.Fatalf("the rendered line must say there is nothing to reverse and what to do: %q", got)
	}
	again := &client.ProblemError{Status: 409, Title: "ALREADY_RECONNECTED", Type: "ALREADY_RECONNECTED",
		Detail: "the most recent containment action on 2a04:2a01::1 was already a reconnect, so there is nothing " +
			"left to restore. If it is not connected now, connect it again with op:connect"}
	if got := friendly(again); !strings.Contains(got, "nothing left to restore") || strings.Contains(got, "busy") {
		t.Fatalf("ALREADY_RECONNECTED keeps its sentence: %q", got)
	}
	// the control: a 404 from an agent lookup still gets the account nudge
	lookup := &client.ProblemError{Status: 404, Type: "NOT_FOUND", Detail: "agent 'db-01' not found"}
	if got := mapProblem(lookup); !strings.Contains(got, "isn't in your account") {
		t.Fatalf("an agent lookup 404 keeps the account nudge: %q", got)
	}
}
