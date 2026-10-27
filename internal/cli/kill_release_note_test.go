// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// kill_release_note_test.go: a plain `whisper kill` releases the /128 and leaves the
// agent's key working. The help text says so, and the success output names the one
// command that cuts the key off, with the agent's real id in it so it can be pasted.

// releaseServer answers op:list with one row and op:identity / op:revoke with a status.
func releaseServer(t *testing.T, row string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch sniffOp(string(raw)) {
		case "identity":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["status"],"rows":[["released"]]}}`))
		case "revoke":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","status"],"rows":[["agent-a00000000000000aa","revoked"]]}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["agent",` + row + `]]}}`))
		}
	}))
}

const releaseRow = `{"agent":"agent-a00000000000000aa","label":"field-laptop","address":"2a04:2a01:9::aa"}`

func TestKillHelpSaysReleaseKeepsTheKey(t *testing.T) {
	long := newKillCmd().Long
	for _, want := range []string{
		"Releasing an identity does not cut off the device's key",
		"To cut off a lost or stolen device, revoke it with --revoke.",
	} {
		if !strings.Contains(long, want) {
			t.Errorf("kill's help must say %q:\n%s", want, long)
		}
	}
}

func TestKillReleaseNamesTheRevokeCommandWithTheRealAgent(t *testing.T) {
	const want = "whisper: the agent's key still works; to cut it off: whisper kill --revoke agent-a00000000000000aa\n"
	for _, target := range []string{"field-laptop", "2a04:2a01:9::aa"} {
		t.Run(target, func(t *testing.T) {
			srv := releaseServer(t, releaseRow)
			defer srv.Close()
			deepencli_keyedGlobals(t, srv.URL)
			_, stderr := captureStd(t, func() {
				if err := deepencli_exec(t, newKillCmd(), "--yes", target); err != nil {
					t.Errorf("kill --yes %s: %v", target, err)
				}
			})
			if !strings.Contains(stderr, "whisper: "+target+" - released\n"+want) {
				t.Fatalf("a release must be followed by the revoke line naming the agent id, got:\n%s", stderr)
			}
			if strings.Count(stderr, "\n") != 2 {
				t.Fatalf("a release says two lines, no more, got:\n%s", stderr)
			}
		})
	}
}

func TestKillReleaseWithoutAnAgentIdNamesTheTarget(t *testing.T) {
	// A row with no agent id: the line names what the user typed, which --revoke accepts.
	srv := releaseServer(t, `{"label":"field-laptop","address":"2a04:2a01:9::aa"}`)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)
	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newKillCmd(), "--yes", "field-laptop"); err != nil {
			t.Errorf("kill --yes: %v", err)
		}
	})
	if !strings.Contains(stderr, "to cut it off: whisper kill --revoke field-laptop\n") {
		t.Fatalf("with no agent id the line must name the target, got:\n%s", stderr)
	}
}

func TestKillRevokeSaysNothingAboutTheKey(t *testing.T) {
	srv := releaseServer(t, releaseRow)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)
	_, stderr := captureStd(t, func() {
		if err := deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "agent-a00000000000000aa"); err != nil {
			t.Errorf("kill --revoke: %v", err)
		}
	})
	if strings.Contains(stderr, "still works") || strings.Contains(stderr, "to cut it off") {
		t.Fatalf("--revoke already cut the key off; it must not suggest doing it again:\n%s", stderr)
	}
}
