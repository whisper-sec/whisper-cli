// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// TestFriendlyMapsKnownProblems asserts the §3.3 mapping: known server problems collapse
// to ONE plain sentence — and never leak anything trace-shaped. We fuzz a few error shapes
// for each status so the mapping is robust to detail-text/type variation.
func TestFriendlyMapsKnownProblems(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // substring the friendly line must contain
	}{
		{"401 rejected key", &client.ProblemError{Status: 401, Detail: "invalid api key"}, "whisper login"},
		{"403 forbidden", &client.ProblemError{Status: 403, Title: "FORBIDDEN", Detail: "scope missing"}, "whisper login"},
		{"404 not owned", &client.ProblemError{Status: 404, Detail: "agent xyz not found"}, "isn't in your account"},
		{"503 egress disabled by type", &client.ProblemError{Status: 503, Type: "EGRESS_DISABLED", Detail: "off"}, "egress isn't enabled"},
		{"503 egress disabled by detail", &client.ProblemError{Status: 503, Detail: "EGRESS is disabled for this agent"}, "egress isn't enabled"},
		{"503 generic busy", &client.ProblemError{Status: 503, Detail: "temporarily unavailable"}, "try again"},
		{"egress type at any status", &client.ProblemError{Status: 409, Type: "EGRESS_DISABLED"}, "egress isn't enabled"},
		{"no-key keeps its own helpful detail", &client.ProblemError{Status: 401, Title: "no key", Detail: "no API key yet — set WHISPER_API_KEY or run: whisper login"}, "WHISPER_API_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := friendly(tc.err)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("friendly(%s) = %q, want it to contain %q", tc.name, got, tc.want)
			}
			assertNoStackTrace(t, got)
			// One sentence: never a multi-line wall.
			if strings.Count(got, "\n") != 0 {
				t.Fatalf("friendly(%s) = %q, want a single line", tc.name, got)
			}
		})
	}
}

// TestFriendlyNeverLeaksStackTrace fuzzes the error SHAPES the CLI actually returns —
// control-plane *ProblemError*s and our own wrapped/transport errors — through friendly()
// and asserts the result is always a single, non-empty, plain line: never multi-line, never
// a goroutine/file:line dump (§3.3 "never a Go stack trace"). It does NOT feed a naked
// runtime trace as an error message, because the CLI never constructs one: every returned
// error is a ProblemError or a deliberately-worded wrap (the actual attack surface).
func TestFriendlyNeverLeaksStackTrace(t *testing.T) {
	shapes := []error{
		&client.ProblemError{Status: 500, Detail: "internal error"},
		&client.ProblemError{Status: 502, Title: "bad gateway"},
		&client.ProblemError{Status: 429, Type: "RATE_LIMITED"},
		&client.ProblemError{}, // empty problem — must still produce a safe, non-empty line
		fmt.Errorf("control plane unreachable at %s: %w", "https://x", errors.New("dial tcp: timeout")),
		fmt.Errorf("reading control-plane reply: %w", errors.New("unexpected EOF")),
	}
	for i, e := range shapes {
		got := friendly(e)
		if got == "" {
			t.Fatalf("case %d: friendly produced an empty line", i)
		}
		assertNoStackTrace(t, got)
		if strings.Contains(got, "\n") {
			t.Fatalf("case %d: friendly must be one line, got %q", i, got)
		}
	}
}

// assertNoStackTrace fails if s looks like a Go stack trace / runtime dump.
func assertNoStackTrace(t *testing.T, s string) {
	t.Helper()
	for _, marker := range []string{"goroutine ", "\tpanic(", "runtime.gopanic", ".go:"} {
		if strings.Contains(s, marker) {
			t.Fatalf("output looks like a stack trace (%q): %q", marker, s)
		}
	}
}
