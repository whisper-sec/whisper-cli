// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// token_revoke_agent_test.go: an AGENT key's revoke drops
// only the tokens that key minted and answers agent, status, tokens_remaining, with
// status one of revoked, none_of_yours or not_found. An owner's reply is unchanged
// (agent, status). The CLI must say what happened in words, show what remains, and
// leave the owner's output exactly as it was.

func revokeReply(cols []string, row ...any) *client.Result {
	return &client.Result{Columns: cols, Rows: [][]any{row}}
}

func TestTokenRevoke_OwnerOutputIsUnchanged(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	for _, status := range []string{"revoked", "not_found"} {
		_, stderr := captureStd(t, func() {
			renderToken(revokeReply([]string{"agent", "status"}, "ag-1", status), true)
		})
		if want := "whisper: ag-1 - " + status + "\n"; stderr != want {
			t.Fatalf("owner %s: got %q, want %q", status, stderr, want)
		}
	}
}

func TestTokenRevoke_AgentKeyNoneOfYoursIsASentence(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	for _, n := range []any{float64(2), json.Number("2")} {
		_, stderr := captureStd(t, func() {
			renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "none_of_yours", n), true)
		})
		if strings.Contains(stderr, "none_of_yours") {
			t.Fatalf("the raw status leaked to the user: %q", stderr)
		}
		for _, want := range []string{"none of the tokens on ag-1 were minted by this key", "2 remain", "owner can revoke them"} {
			if !strings.Contains(stderr, want) {
				t.Fatalf("missing %q in %q", want, stderr)
			}
		}
	}
}

func TestTokenRevoke_AgentKeyRevokedShowsWhatRemains(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	_, stderr := captureStd(t, func() {
		renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "revoked", float64(1)), true)
	})
	for _, want := range []string{"ag-1", "revoked the tokens this key minted", "1 remains", "owner can revoke"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("missing %q in %q", want, stderr)
		}
	}
	// Nothing left over: the reply says so in one clause, without a "0 remain".
	_, stderr = captureStd(t, func() {
		renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "revoked", float64(0)), true)
	})
	if !strings.Contains(stderr, "revoked the tokens this key minted") || strings.Contains(stderr, "remain") {
		t.Fatalf("a revoke that left nothing behind: %q", stderr)
	}
}

func TestTokenRevoke_AgentKeyNotFoundIsUnchanged(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	_, stderr := captureStd(t, func() {
		renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "not_found", float64(0)), true)
	})
	if stderr != "whisper: ag-1 - not_found\n" {
		t.Fatalf("not_found: %q", stderr)
	}
}

func TestTokenRevoke_HelpNamesBothKeyKinds(t *testing.T) {
	cmd := newTokenCmd()
	long := cmd.Long
	if strings.Contains(long, "drops all tokens") {
		t.Fatalf("the help still promises every token is dropped: %q", long)
	}
	for _, want := range []string{"account key", "agent key", "only the tokens it minted"} {
		if !strings.Contains(long, want) {
			t.Fatalf("help is missing %q: %q", want, long)
		}
	}
	usage := cmd.Flags().Lookup("revoke").Usage
	if strings.Contains(usage, "revoke all") {
		t.Fatalf("--revoke usage still says all: %q", usage)
	}
}

// A count the CLI cannot read is left out rather than printed wrong, and the sentence
// still stands on its own.
func TestTokenRevoke_AnUnreadableCountIsLeftOut(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	for _, n := range []any{nil, "lots", float64(-1), 1.5} {
		_, stderr := captureStd(t, func() {
			renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "none_of_yours", n), true)
		})
		if !strings.Contains(stderr, "none of the tokens on ag-1 were minted by this key") ||
			strings.Contains(stderr, "remain") || strings.Contains(stderr, "none_of_yours") {
			t.Fatalf("count %v: %q", n, stderr)
		}
	}
}

// The server answers none_of_yours only while other tokens remain. If one ever arrived
// with a count of 0, the line must not claim "0 remain" or that an owner has something
// to revoke: it says only what is true.
func TestTokenRevoke_NoneOfYoursWithNothingLeftClaimsNothingMore(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	_, stderr := captureStd(t, func() {
		renderToken(revokeReply([]string{"agent", "status", "tokens_remaining"}, "ag-1", "none_of_yours", float64(0)), true)
	})
	if stderr != "whisper: none of the tokens on ag-1 were minted by this key, so none were revoked\n" {
		t.Fatalf("got %q", stderr)
	}
}
