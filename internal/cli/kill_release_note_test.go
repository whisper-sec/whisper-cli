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

// `whisper kill --revoke` sends what the person typed (trimmed) as op:revoke's agent, in
// every form `whisper list` and `whisper create` print, and a revoke that matched nothing never
// reads as success: the plane's NOT_FOUND exits non-zero, and so does an older plane's ok row
// whose status is not_found.
func revokeServer(t *testing.T, reply string, sent *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if sniffOp(string(raw)) == "revoke" {
			*sent = append(*sent, string(raw))
			_, _ = w.Write([]byte(reply))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["agent",` + releaseRow + `]]}}`))
	}))
}

func TestKillRevokeSendsEveryIdFormTrimmed(t *testing.T) {
	ok := `{"ok":true,"status":200,"result":{"columns":["agent","status"],"rows":[["agent-a00000000000000aa","revoked"]]}}`
	for _, tc := range []struct{ typed, sent string }{
		{"agent-a00000000000000aa", "agent-a00000000000000aa"},
		{"a00000000000000aa", "a00000000000000aa"},
		{"  a00000000000000aa\n", "a00000000000000aa"},
		{"AGENT-A00000000000000AA", "AGENT-A00000000000000AA"},
		{"2a04:2a01:9::aa", "2a04:2a01:9::aa"},
		{"field-laptop", "field-laptop"},
	} {
		t.Run(tc.typed, func(t *testing.T) {
			var sent []string
			srv := revokeServer(t, ok, &sent)
			defer srv.Close()
			deepencli_keyedGlobals(t, srv.URL)
			_, stderr := captureStd(t, func() {
				if err := deepencli_exec(t, newKillCmd(), "--yes", "--revoke", tc.typed); err != nil {
					t.Errorf("kill --revoke %q: %v", tc.typed, err)
				}
			})
			if len(sent) != 1 || !strings.Contains(sent[0], "agent:'"+tc.sent+"'") {
				t.Fatalf("op:revoke carries agent:'%s', got %v", tc.sent, sent)
			}
			if !strings.Contains(stderr, "- revoked") {
				t.Fatalf("the revoke is reported: %s", stderr)
			}
		})
	}
}

func TestKillRevokeThatMatchedNothingNeverReadsAsSuccess(t *testing.T) {
	for _, tc := range []struct{ name, reply string }{
		{"the plane's NOT_FOUND", `{"ok":false,"status":404,"result":null,"error":{"code":"NOT_FOUND","message":"nothing was revoked: no agent of yours matches 'x'","retryable":false}}`},
		{"an older plane's not_found row", `{"ok":true,"status":200,"result":{"columns":["agent","status"],"rows":[["x","not_found"]]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent []string
			srv := revokeServer(t, tc.reply, &sent)
			defer srv.Close()
			deepencli_keyedGlobals(t, srv.URL)
			var err error
			_, stderr := captureStd(t, func() { err = deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "x") })
			if err == nil {
				t.Fatalf("a revoke that matched nothing exits non-zero (stderr=%s)", stderr)
			}
			if !strings.Contains(err.Error(), "nothing was revoked") {
				t.Fatalf("the error says nothing was revoked, got %v", err)
			}
			if code, ok := exitCodeOf(err); !ok || code != killExitNothingMatched {
				t.Fatalf("it exits %d, the verdict a script reads as already gone, got %d (%v)", killExitNothingMatched, code, ok)
			}
			if strings.Contains(stderr, "- revoked") || strings.Contains(stderr, "- not_found") {
				t.Fatalf("no success-shaped line: %s", stderr)
			}
		})
	}
}

func TestKillRefusesABlankTarget(t *testing.T) {
	deepencli_keyedGlobals(t, "http://127.0.0.1:1")
	err := deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "   ")
	if err == nil || !isUsageError(err) {
		t.Fatalf("a blank target is a usage error, got %v", err)
	}
}

// The --json path decides the same way: an older plane's not_found row is the verdict exit,
// after the verbatim envelope is emitted.
func TestKillRevokeJSONThatMatchedNothingIsTheVerdictExit(t *testing.T) {
	var sent []string
	srv := revokeServer(t, `{"ok":true,"status":200,"result":{"columns":["agent","status"],"rows":[["x","not_found"]]}}`, &sent)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)
	g.jsonOut = true
	var err error
	stdout, _ := captureStd(t, func() { err = deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "x") })
	if code, ok := exitCodeOf(err); !ok || code != killExitNothingMatched {
		t.Fatalf("--json: exit %d, got %v", killExitNothingMatched, err)
	}
	if !strings.Contains(stdout, `"not_found"`) {
		t.Fatalf("--json still emits the envelope verbatim: %s", stdout)
	}
}

// A failure that is not a match-nothing keeps exit 1, so the verdict code means only that.
func TestKillRevokeOtherFailuresAreNotTheVerdict(t *testing.T) {
	var sent []string
	srv := revokeServer(t, `{"ok":false,"status":503,"result":null,"error":{"code":"STORE_UNAVAILABLE","message":"retry"}}`, &sent)
	defer srv.Close()
	deepencli_keyedGlobals(t, srv.URL)
	var err error
	_, _ = captureStd(t, func() { err = deepencli_exec(t, newKillCmd(), "--yes", "--revoke", "x") })
	if err == nil {
		t.Fatalf("a 503 is a failure")
	}
	if _, ok := exitCodeOf(err); ok {
		t.Fatalf("a 503 is not the nothing-matched verdict: %v", err)
	}
}
