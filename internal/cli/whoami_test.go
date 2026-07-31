// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- whoami + version - the commands an agent naturally guesses ---------------

// TestWhoami_NoKey_FriendlyAnswer: keyless `whisper whoami` answers helpfully (key not
// set + the login nudge) and exits 0 - an identity question is never an error, and it
// must not touch the network.
func TestWhoami_NoKey_FriendlyAnswer(t *testing.T) {
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	savedG := g
	g = globalFlags{keyFile: filepath.Join(t.TempDir(), "absent-key"), timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("keyless whoami must not error: %v", err)
		}
	})
	if !strings.Contains(stdout, "not set - run: whisper login") {
		t.Fatalf("keyless whoami must nudge to login; stdout=%q", stdout)
	}
}

// TestWhoami_WithKey_ShowsFleet: with a key, whoami reports the key state and the
// fleet size from op:list (best-effort, tenant-confined).
func TestWhoami_WithKey_ShowsFleet(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{
		{name: "scout", addr: "2a04:2a01:9::1"},
		{name: "probe", addr: "2a04:2a01:9::2"},
	}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newWhoamiCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent-file", filepath.Join(t.TempDir(), "absent-agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("whoami errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "set (flag)") {
		t.Fatalf("whoami must report the key source; stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "2") {
		t.Fatalf("whoami must count the caller's agents; stdout=%q", stdout)
	}
	if !containsOp(opsSeen(seen), "list") {
		t.Fatalf("whoami must ask op:list for the fleet, ops=%v", opsSeen(seen))
	}
	// The key VALUE must never be printed.
	if strings.Contains(stdout, "whisper_live_test") {
		t.Fatalf("whoami must NEVER print the key value; stdout=%q", stdout)
	}
}

// TestWhoami_Aliases: the guessed spellings (who / me / self) resolve to whoami, and
// `version` resolves as a real command - never "unknown command".
func TestWhoami_Aliases(t *testing.T) {
	root := NewRootCommand()
	for _, alias := range []string{"whoami", "who", "me", "self"} {
		cmd, _, err := root.Find([]string{alias})
		if err != nil || cmd == nil || cmd.Name() != "whoami" {
			t.Fatalf("%q must resolve to the whoami command (got %v, err %v)", alias, cmd, err)
		}
	}
	cmd, _, err := root.Find([]string{"version"})
	if err != nil || cmd == nil || cmd.Name() != "version" {
		t.Fatalf("`version` must be a real command (got %v, err %v)", cmd, err)
	}
}

// TestVersion_PrintsVersion: `whisper version` prints the same answer as --version;
// --quiet prints the bare value (the load-bearing form for scripts).
func TestVersion_PrintsVersion(t *testing.T) {
	savedG := g
	g = globalFlags{}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newVersionCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "whisper version "+Version) {
		t.Fatalf("version output = %q, want it to carry %q", stdout, Version)
	}

	g = globalFlags{quiet: true}
	stdout, _ = captureStd(t, func() {
		cmd := newVersionCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != Version {
		t.Fatalf("quiet version stdout = %q, want ONLY %q", stdout, Version)
	}
}
