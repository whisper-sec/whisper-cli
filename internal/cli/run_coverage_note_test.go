// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// `whisper run` without --enforce reaches the child only through the *_PROXY variables,
// and the local proxy carries TCP only (it answers UDP ASSOCIATE with "command not supported").
// So a program's UDP, and any program that dials directly, leaves from this host's own address
// on every tier, wireguard included. Measured on a Linux test guest: 20 NTP queries under
// `whisper run --tier wireguard` all answered and none crossed the box. The run printed
// "✓ verified" and nothing else, so the person had every reason to think the program's traffic
// carried the /128. These tests hold the run to saying what it covers.

// runCoverageMustSay is what the note has to carry, on every platform: what IS covered, what
// is NOT, and where the uncovered traffic actually goes.
var runCoverageMustSay = []string{"TCP", "*_PROXY", "UDP", "this host's own address"}

func TestRunCoverageNote_NamesTheGapAndTheWayAround(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd"} {
		note := runCoverageNote(goos, runEnforceForm(goos, "python3", false))
		for _, want := range runCoverageMustSay {
			if !strings.Contains(note, want) {
				t.Errorf("%s: the coverage note must say %q, got %q", goos, want, note)
			}
		}
		if !strings.Contains(note, "--enforce") {
			t.Errorf("%s: the note must name --enforce as the full-capture path, got %q", goos, note)
		}
		if strings.Contains(note, "\n") {
			t.Errorf("%s: the note is ONE line, got %q", goos, note)
		}
	}
	// On Linux --enforce is a command the person can run, so the note gives it to them whole,
	// spelled as the command they ran.
	if n := runCoverageNote("linux", runEnforceForm("linux", "python3", false)); !strings.Contains(n, "sudo whisper run --enforce -- python3") {
		t.Errorf("linux run: the note must give the runnable --enforce form, got %q", n)
	}
	if n := runCoverageNote("linux", runEnforceForm("linux", "claude", true)); !strings.Contains(n, "sudo whisper claude --enforce") {
		t.Errorf("linux claude: the note must give `whisper claude --enforce`, got %q", n)
	}
	// On Windows it is runnable too, from an elevated terminal, with no sudo to type.
	if n := runCoverageNote("windows", runEnforceForm("windows", "python3", false)); !strings.Contains(n, "whisper run --enforce -- python3") ||
		!strings.Contains(n, "elevated terminal") || strings.Contains(n, "sudo") {
		t.Errorf("windows run: the note must give the elevated --enforce form without sudo, got %q", n)
	}
	if n := runCoverageNote("windows", runEnforceForm("windows", "claude", true)); !strings.Contains(n, "whisper claude --enforce (from an elevated terminal)") {
		t.Errorf("windows claude: got %q", n)
	}
	// Elsewhere it must not offer a command that only refuses: it says where --enforce runs.
	for _, goos := range []string{"darwin", "freebsd"} {
		n := runCoverageNote(goos, runEnforceForm(goos, "python3", false))
		if strings.Contains(n, "sudo whisper") || strings.Contains(n, "whisper run --enforce") {
			t.Errorf("%s: the note offers --enforce as runnable where it is refused: %q", goos, n)
		}
		if !strings.Contains(n, "Linux or Windows") {
			t.Errorf("%s: the note must say --enforce needs Linux or Windows, got %q", goos, n)
		}
	}
}

// runOnce drives the real run path with the egress tail stubbed and returns what the child
// printed and what the run printed. The child echoes a marker, so a caller can tell a run that
// happened from one that failed before it spawned anything.
func runOnce(t *testing.T, tier string, quiet, viaClaude bool) (stdout, stderr string) {
	t.Helper()
	testenv.HermeticHome(t) // no real session registry, saved agent or key
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEgressTail(t)()
	if isWireGuardTier(tier) {
		// No real key generation in a unit test; the stubbed tail never uses the keys.
		savedPrep := prepareWireGuard
		prepareWireGuard = func(string, map[string]any) (*wgtun.Keypair, error) { return nil, nil }
		defer func() { prepareWireGuard = savedPrep }()
	}
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: quiet, timeout: 5 * time.Second}
	defer func() { g = savedG }()
	return captureStd(t, func() {
		if err := runWithEgress("2a04:2a01:9::abcd", "", tier, "sh", []string{"-c", "echo child-ran"}, viaClaude); err != nil {
			t.Errorf("tier %q: run failed: %v", tier, err)
		}
	})
}

// TestRun_SaysWhatItCoversNextToVerified drives the real run path: the success line is printed,
// and right after it the coverage note, so "✓ verified" is never the whole story. The negotiated
// tier and both forced tiers are run, wireguard included because the leak was measured on it,
// and the gap is the same on each.
func TestRun_SaysWhatItCoversNextToVerified(t *testing.T) {
	skipWithoutPOSIXShell(t)
	for _, tier := range []string{"", "socks5", "wireguard"} {
		stdout, stderr := runOnce(t, tier, false, false)
		if !strings.Contains(stdout, "child-ran") {
			t.Fatalf("tier %q: the child never ran, stdout=%q stderr=%q", tier, stdout, stderr)
		}
		v := strings.Index(stderr, "✓ verified")
		if v < 0 {
			t.Fatalf("tier %q: no success line, stderr=%q", tier, stderr)
		}
		rest := stderr[v:]
		for _, want := range runCoverageMustSay {
			if !strings.Contains(rest, want) {
				t.Errorf("tier %q: after \"✓ verified\" the run must say %q, stderr=%q", tier, want, stderr)
			}
		}
		if runtime.GOOS == "linux" && !strings.Contains(rest, "sudo whisper run --enforce -- sh") {
			t.Errorf("tier %q: the note must name the command that was run, stderr=%q", tier, stderr)
		}
	}
}

// TestClaudeDoor_NamesItsOwnEnforceForm drives `whisper claude` through its cobra command, with a
// stand-in `claude` first on PATH (the real one is never launched by a test), so the door itself
// is proved to pass its name through to the note.
func TestClaudeDoor_NamesItsOwnEnforceForm(t *testing.T) {
	skipWithoutPOSIXShell(t)
	if runtime.GOOS != "linux" {
		t.Skip("the runnable --enforce form is printed on Linux only")
	}
	testenv.HermeticHome(t) // never the real user's saved agent or key
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho child-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEgressTail(t)()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()
	cmd := newClaudeCmd()
	if err := cmd.Flags().Set("agent", "2a04:2a01:9::abcd"); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := captureStd(t, func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Errorf("whisper claude failed: %v", err)
		}
	})
	if !strings.Contains(stdout, "child-ran") {
		t.Fatalf("the stand-in claude never ran: stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "sudo whisper claude --enforce") {
		t.Errorf("whisper claude: the note must say `sudo whisper claude --enforce`, stderr=%q", stderr)
	}
}

// TestRun_QuietStaysQuiet: --quiet promises the child owns the terminal, so the note is
// suppressed with the success line it qualifies, never printed on its own. The child's marker
// proves the run happened, so this cannot pass on a run that failed before the print site.
func TestRun_QuietStaysQuiet(t *testing.T) {
	skipWithoutPOSIXShell(t)
	stdout, stderr := runOnce(t, "", true, false)
	if !strings.Contains(stdout, "child-ran") {
		t.Fatalf("the child never ran, so this proves nothing: stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(stderr, "UDP") || strings.Contains(stdout, "UDP") {
		t.Fatalf("--quiet printed the coverage note: stdout=%q stderr=%q", stdout, stderr)
	}
}

// TestRunHelp_DoesNotPromiseMoreThanTheProxy: the help is read before anything runs, so it
// carries the same limit. The wireguard example used to say "(routed /128)" and nothing more,
// and `whisper init claude` said "all its traffic" over the same TCP-only proxy.
func TestRunHelp_DoesNotPromiseMoreThanTheProxy(t *testing.T) {
	for _, c := range []struct {
		name string
		long string
	}{{"run", newRunCmd().Long}, {"claude", newClaudeCmd().Long}, {"init claude", newInitClaudeCmd().Long}} {
		for _, want := range []string{"UDP", "this host's own address", "--enforce"} {
			if !strings.Contains(c.long, want) {
				t.Errorf("%s --help must say %q, got:\n%s", c.name, want, c.long)
			}
		}
		if strings.Contains(c.long, "all its traffic") || strings.Contains(c.long, "routes all") {
			t.Errorf("%s --help still promises all traffic:\n%s", c.name, c.long)
		}
	}
	if !strings.Contains(runTierUsage, "TCP") {
		t.Errorf("--tier help must say the proxy carries TCP only, got %q", runTierUsage)
	}
	if !strings.Contains(enforceUnsupported("darwin").Error(), "TCP") {
		t.Errorf("the --enforce refusal must not claim the proxy covers more than TCP: %q", enforceUnsupported("darwin"))
	}
}

// TestInitHelpAndSummary_SayWhatTheProxyCovers: `whisper init claude` and every env-tool init
// wire the same TCP-only proxy, so their help and the init claude summary carry the same limit.
func TestInitHelpAndSummary_SayWhatTheProxyCovers(t *testing.T) {
	for _, prof := range envToolProfiles() {
		long := newInitEnvToolCmd(prof).Long
		for _, want := range []string{"TCP", "UDP", "this host's own address", "--enforce"} {
			if !strings.Contains(long, want) {
				t.Errorf("init %s --help must say %q, got:\n%s", prof.name, want, long)
			}
		}
	}
	savedG := g
	g = globalFlags{}
	defer func() { g = savedG }()
	_, stderr := captureStd(t, func() {
		printInitSummary(projcfg.Paths{}, projcfg.Config{Agent: "2a04:2a01:9::abcd", Port: 41000}, projcfg.SettingsResult{}, nil, true, "")
	})
	if !strings.Contains(stderr, "wired for Claude Code") {
		t.Fatalf("the summary never printed, so this proves nothing: %q", stderr)
	}
	if strings.Contains(stderr, "all its traffic") {
		t.Errorf("the init claude summary still promises all traffic: %q", stderr)
	}
	for _, want := range runCoverageMustSay {
		if !strings.Contains(stderr, want) {
			t.Errorf("the init claude summary must say %q, got %q", want, stderr)
		}
	}
}
