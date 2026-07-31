// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// --- create must SIGNAL an idempotent reuse, never silently return it ---------

// TestCreate_ReusedIdentity_SignalsReuse: op:identity is idempotent on the server (one
// key = one /128) - when the caller already holds the returned /128, create must say
// "reusing existing agent ..." (with the EXISTING agent's name) instead of claiming a
// fresh create. The stub's pre-list returns the same /128 op:identity then echoes.
func TestCreate_ReusedIdentity_SignalsReuse(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "old-scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	_, stderr := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--name", "fresh-name"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "reusing existing agent old-scout - 2a04:2a01:9::abcd") {
		t.Fatalf("a reused identity must be signalled with the existing agent; stderr=%q", stderr)
	}
	if strings.Contains(stderr, "created") {
		t.Fatalf("a reuse must never also claim \"created\"; stderr=%q", stderr)
	}
	// The signal needs the look-before-leap listing AND the create itself.
	ops := opsSeen(seen)
	if !containsOp(ops, "list") || !containsOp(ops, "identity") {
		t.Fatalf("reuse detection needs op:list then op:identity, ops=%v", ops)
	}
}

// TestCreate_FreshAccount_NoReuseNote: a genuinely fresh mint keeps the plain
// "created" line - no reuse note when the /128 was not held before the call.
func TestCreate_FreshAccount_NoReuseNote(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen) // nil => the pre-list sees no identities
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	_, stderr := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--name", "scout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create errored: %v", err)
		}
	})
	if !strings.Contains(stderr, "created") {
		t.Fatalf("a fresh mint must report created; stderr=%q", stderr)
	}
	if strings.Contains(stderr, "reusing") {
		t.Fatalf("a fresh mint must carry NO reuse note; stderr=%q", stderr)
	}
}

// TestCreate_ReusedIdentity_QuietStaysBare: under --quiet the contract is EXACTLY the
// load-bearing value on stdout and zero chrome - the reuse note included.
func TestCreate_ReusedIdentity_QuietStaysBare(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "old-scout", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--name", "fresh-name"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != "2a04:2a01:9::abcd" {
		t.Fatalf("quiet create stdout = %q, want ONLY the address", stdout)
	}
	if stderr != "" {
		t.Fatalf("quiet create must emit NO chrome (reuse note included), got %q", stderr)
	}
}
