// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// whale_wiring_test.go is the anti-unreachable gate for `whisper whale`.
//
// The defect this file exists to prevent is the one this codebase keeps hitting: code
// that compiles, passes its own unit tests, and can never execute because nothing in
// production reaches it. A test that calls newWhaleStatusCmd() directly proves only that
// the constructor works. These tests start where a user starts, at NewRootCommand(), and
// walk down. Remove the one line in root.go that registers the subtree and every test
// here fails.

// whaleSubcommand walks the real tree from the root the binary builds.
func whaleSubcommand(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	cur := NewRootCommand()
	walked := []string{"whisper"}
	for _, want := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == want {
				next = c
				break
			}
			for _, a := range c.Aliases {
				if a == want {
					next = c
					break
				}
			}
		}
		if next == nil {
			t.Fatalf("`%s %s` does not exist: nothing under %q registers it, so no user can ever "+
				"reach that code", strings.Join(walked, " "), want, strings.Join(walked, " "))
		}
		cur = next
		walked = append(walked, want)
	}
	return cur
}

// TestWhaleIsRegisteredOnTheRoot is the single line in root.go, asserted.
func TestWhaleIsRegisteredOnTheRoot(t *testing.T) {
	whale := whaleSubcommand(t, "whale")
	if whale.Hidden {
		t.Fatal("`whisper whale` is hidden, so it is absent from --help and from the channel parity gate")
	}
	if whale.Short == "" || whale.Long == "" {
		t.Fatal("`whisper whale` ships with no help text")
	}
}

// TestWhaleShipsExactlyTheVerbsThatHaveSomethingBehindThem pins the surface. A verb added
// here without the behind it, or a verb quietly dropped, both show up. Add a
// name to this list ONLY together with the that implements it.
func TestWhaleShipsExactlyTheVerbsThatHaveSomethingBehindThem(t *testing.T) {
	whale := whaleSubcommand(t, "whale")
	got := map[string]bool{}
	for _, c := range whale.Commands() {
		got[c.Name()] = true
	}
	// Every verb below arrived with the code behind it: route and exit-node with the
	// subnet-router and exit-node halves, ip with its v4 answer, serve and funnel with
	// the front end, and acl with the document, its compiler, its CAS and its
	// enforcement at the CONNECT choke.
	want := []string{"status", "ip", "ping", "netcheck", "whois", "dns", "ssh", "migrate", "route",
		"exit-node", "serve", "funnel", "syspolicy", "acl"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("`whisper whale %s` is not registered", w)
		}
		delete(got, w)
	}
	for extra := range got {
		t.Errorf("`whisper whale %s` is registered with nothing behind it. A verb must arrive "+
			"with the code that implements it", extra)
	}
}

// TestWhaleUnbuiltVerbsAreAbsentOnPurpose: a half-working join is worse than none, so the
// tailscale verbs people will reach for must not exist yet rather than exist and fail.
func TestWhaleUnbuiltVerbsAreAbsentOnPurpose(t *testing.T) {
	whale := whaleSubcommand(t, "whale")
	for _, c := range whale.Commands() {
		switch c.Name() {
		// serve, funnel and acl LEFT this list, each with the code that implements it.
		case "up", "down", "login", "logout", "set":
			t.Errorf("`whisper whale %s` is registered with nothing behind it", c.Name())
		}
	}
}

// TestWhaleDNSSubtreeIsReachable walks two levels down, because `dns query` is the one
// verb that is nested and therefore the one a broken AddCommand would silently orphan.
func TestWhaleDNSSubtreeIsReachable(t *testing.T) {
	for _, sub := range []string{"status", "query", "record"} {
		c := whaleSubcommand(t, "whale", "dns", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale dns %s` has no RunE, so reaching it does nothing", sub)
		}
	}
}

// TestWhaleDNSRecordSubtreeIsReachable walks THREE levels, to `whale dns record list`.
// Depth is where an orphan hides: `record` hangs off `dns`, which hangs
// off `whale`, so two AddCommand lines have to hold for a person to reach it.
func TestWhaleDNSRecordSubtreeIsReachable(t *testing.T) {
	for _, sub := range []string{"list", "set", "delete"} {
		c := whaleSubcommand(t, "whale", "dns", "record", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale dns record %s` has no RunE, so reaching it does nothing", sub)
		}
	}
}

// TestWhaleSysPolicySubtreeIsReachable walks two levels down to `syspolicy list` and
// `syspolicy template`, the pair the acceptance criterion names. Nesting is where a
// broken AddCommand orphans a whole without breaking anything that compiles.
func TestWhaleSysPolicySubtreeIsReachable(t *testing.T) {
	for _, sub := range []string{"list", "template"} {
		c := whaleSubcommand(t, "whale", "syspolicy", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale syspolicy %s` has no RunE, so reaching it does nothing", sub)
		}
	}
}

// TestWhaleStatusDoesNotCollideWithWhisperStatus: `whisper status` and `whisper whale
// status` are different commands and both must keep working.
func TestWhaleStatusDoesNotCollideWithWhisperStatus(t *testing.T) {
	root := NewRootCommand()
	var top *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "status" {
			top = c
		}
	}
	if top == nil {
		t.Fatal("`whisper status` disappeared")
	}
	whaleStatus := whaleSubcommand(t, "whale", "status")
	if top == whaleStatus {
		t.Fatal("`whisper status` and `whisper whale status` resolved to the same command")
	}
}

// TestWhaleIPMinusFourExecutesThroughTheRealTree is the end-to-end wiring proof: the
// argv a user types, parsed by the real root, reaching the real RunE, producing the real
// answer. It is deliberately the -4 case because that path returns before any I/O.
func TestWhaleIPMinusFourExecutesThroughTheRealTree(t *testing.T) {
	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetArgs([]string{"whale", "ip", "-4"})
	var err error
	stdout, _ := captureStd(t, func() { err = root.Execute() })
	if err == nil {
		t.Fatal("`whisper whale ip -4` exited 0; Whalenet is IPv6-only and it must exit non-zero")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("`whisper whale ip -4` printed %q on stdout; a script must never read an "+
			"address-shaped blank from it", stdout)
	}
	// The assertion is on the FACT the message must carry, not on one wording of it:
	// Whalenet has no IPv4 identity. Pinning an exact sentence here made an unrelated
	// improvement to that message look like a wiring regression.
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("`whisper whale ip -4` said %q, which does not explain that a Whalenet identity is IPv6", err.Error())
	}
	if isUsageError(err) {
		t.Fatal("`whisper whale ip -4` reported a usage error; -4 is a real flag with a real answer")
	}
}

// TestWhaleHelpListsEveryVerbItShips: the help text is the first place anyone looks, so
// a verb that exists but is not named there is a verb nobody finds.
func TestWhaleHelpListsEveryVerbItShips(t *testing.T) {
	whale := whaleSubcommand(t, "whale")
	for _, c := range whale.Commands() {
		if !strings.Contains(whale.Long, c.Name()) {
			t.Errorf("`whisper whale --help` does not mention the %q verb it ships", c.Name())
		}
	}
}
