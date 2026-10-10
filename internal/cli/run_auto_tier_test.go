// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// `whisper run` from a COLD (disconnected) state must negotiate tiers the
// way `whisper connect` does.
//
// The reproduction: a fresh user connects successfully over Tier-1, stops the
// foreground connection cleanly, and the same standalone `whisper run` then fails
// with "egress CONNECT reply unreadable" and exit 1 - while `whisper connect` on
// the identical agent recovers immediately by falling back to Tier-1.5. Two
// commands, one account, one agent, opposite outcomes, because only one of them
// negotiated: run had its own thinner copy of the connect body that tried a
// single tier and returned the first error it met.
//
// So the assertion is not "run works". It is that run ATTEMPTS BOTH TIERS and
// lands, which is the behaviour connect_auto_tier_test.go pins for connect.
// runRunCmd drives the real `run` command against a stub control plane, with a
// harmless child. It mirrors runAutoConnect so the two commands are exercised the
// same way.
func runRunCmd(t *testing.T, url string, extra ...string) (err error) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: url, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent")
	args := append([]string{"--agent-file", af}, extra...)
	args = append(args, "--", "true") // /bin/true: exits 0, writes nothing
	cmd := newRunCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	_, _ = captureStd(t, func() { err = cmd.Execute() })
	return err
}

func TestRunAuto_WireGuardRejected_DowngradesAndStillRuns(t *testing.T) {
	rejectedWg := `{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`

	var seen []recordedCall
	srv := autoTierServer(t, &seen, rejectedWg, s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	if err := runRunCmd(t, srv.URL); err != nil {
		t.Fatalf("cold run must downgrade to Tier-1.5 and succeed, got: %v", err)
	}

	var wg, s5 int
	for _, c := range seen {
		if c.op != "connect" {
			continue
		}
		if strings.Contains(c.body, "tier:'wireguard'") {
			wg++
		} else {
			s5++
		}
	}
	if wg == 0 {
		t.Error("run must TRY Tier-1 first, like connect does")
	}
	if s5 == 0 {
		t.Error("run must fall back to Tier-1.5 when Tier-1 is refused; this is the cold-start regression")
	}
}

// An explicit --tier is still honoured with no silent downgrade: a person who
// names a tier is owed that tier or a clear failure. Without this the fix could
// have turned every failure into a fallback, which is a different bug.
func TestRunExplicitTier_IsNotSilentlyDowngraded(t *testing.T) {
	rejectedWg := `{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`

	var seen []recordedCall
	srv := autoTierServer(t, &seen, rejectedWg, s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	err := runRunCmd(t, srv.URL, "--tier", "wireguard")
	if err == nil {
		t.Fatal("an explicitly requested tier that the box refuses must fail, not quietly become another tier")
	}
	for _, c := range seen {
		if c.op == "connect" && !strings.Contains(c.body, "tier:'wireguard'") {
			t.Error("a forced --tier wireguard must never issue a socks5 op:connect")
		}
	}
}
