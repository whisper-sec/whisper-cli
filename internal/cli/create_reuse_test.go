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

// --- `create --register --reuse` must NOT mint a duplicate for a known name ----

// TestCreateRegister_Reuse_ReusesExistingAgentByName: the installer's fleet
// auto-bind re-runs on every upgrade; with --reuse the register bind is
// idempotent on the endpoint's name - an agent already registered under --name
// is returned VERBATIM (same /128), op:register never fires, and the --json
// envelope carries the reuse marker so install.sh's json_field reads the same
// address it bound last time. This is the fix: a binary swap + restart
// must never strand the old /128 by minting a fresh one.
func TestCreateRegister_Reuse_ReusesExistingAgentByName(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "runner-3", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", jsonOut: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--register", "--reuse", "--name", "runner-3"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --register --reuse errored: %v", err)
		}
	})
	ops := opsSeen(seen)
	if containsOp(ops, "register") {
		t.Fatalf("--reuse with an existing agent must NOT mint (no op:register), ops=%v", ops)
	}
	if !containsOp(ops, "list") {
		t.Fatalf("--reuse needs the op:list lookup, ops=%v", ops)
	}
	if !strings.Contains(stdout, "2a04:2a01:9::abcd") {
		t.Fatalf("the reuse envelope must carry the EXISTING /128; stdout=%q", stdout)
	}
	if !strings.Contains(stdout, `"reused":true`) {
		t.Fatalf("the reuse envelope must be marked reused; stdout=%q", stdout)
	}
	if strings.Contains(stdout, "api_key") {
		t.Fatalf("a reuse can never re-show an API key; stdout=%q", stdout)
	}
}

// TestCreateRegister_Reuse_MintsWhenNoneExists: a genuinely fresh endpoint (no
// agent under this name) still mints - reuse changes NOTHING for first contact.
func TestCreateRegister_Reuse_MintsWhenNoneExists(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen) // nil => the account has no agents yet
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", jsonOut: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--register", "--reuse", "--name", "runner-3"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --register --reuse (fresh) errored: %v", err)
		}
	})
	ops := opsSeen(seen)
	if !containsOp(ops, "list") || !containsOp(ops, "register") {
		t.Fatalf("a fresh endpoint must look first THEN mint, ops=%v", ops)
	}
	if !strings.Contains(stdout, "2a04:2a01:9::beef") {
		t.Fatalf("the fresh mint must return the register envelope; stdout=%q", stdout)
	}
}

// TestCreateRegister_NoReuse_AlwaysMints pins the documented --register contract
// unchanged: WITHOUT --reuse, register mints unconditionally and performs no
// listing - "mint a genuinely new agent" stays exactly that.
func TestCreateRegister_NoReuse_AlwaysMints(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "runner-3", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--register", "--name", "runner-3"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --register errored: %v", err)
		}
	})
	ops := opsSeen(seen)
	if !containsOp(ops, "register") {
		t.Fatalf("plain --register must mint, ops=%v", ops)
	}
	if containsOp(ops, "list") {
		t.Fatalf("plain --register must NOT run the reuse lookup, ops=%v", ops)
	}
}

// TestCreateRegister_Reuse_QuietStaysBare: --quiet on a reuse emits EXACTLY the
// existing address on stdout and zero chrome, mirroring the mint path's quiet
// contract - so scripted callers read one value either way.
func TestCreateRegister_Reuse_QuietStaysBare(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "runner-3", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--register", "--reuse", "--name", "runner-3"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --register --reuse --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != "2a04:2a01:9::abcd" {
		t.Fatalf("quiet reuse stdout = %q, want ONLY the existing address", stdout)
	}
	if stderr != "" {
		t.Fatalf("quiet reuse must emit NO chrome, got %q", stderr)
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
