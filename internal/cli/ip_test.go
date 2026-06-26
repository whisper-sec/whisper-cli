// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// ip_test.go covers `whisper ip`: a verified /128 → green line + exit 0; a mismatch /
// out-of-range egress → the remediation + a non-zero exit; --json shape. The live-egress
// tail (local proxy + network echo) is replaced via the connectAndVerify seam so the test
// runs offline and deterministically — the verify ASSERTIONS themselves (range + ==/128)
// are covered directly in TestVerifyRange (connect_test.go).

// ipStub installs a connectAndVerify that simulates an echo returning observedIP, applies
// the SAME range + ==/128 assertions the live verify does, and returns the verified
// session or the matching friendly error. Returns a restore func.
func ipStub(t *testing.T, observedIP string) func() {
	t.Helper()
	saved := connectAndVerify
	connectAndVerify = func(_ context.Context, _ *client.Client, res *client.Result, name string, _ *wgtun.Keypair) (*egressSession, error) {
		ce, err := parseConnectEnvelope(res)
		if err != nil {
			return nil, err
		}
		sess := &egressSession{endpoint: "socks5h://127.0.0.1:1080", addr: ce.address, name: name}
		// Mirror verifyEgress's assertions against the simulated observed source IP.
		if !inWhisperRange(observedIP) {
			return nil, &client.ProblemError{Status: 502, Detail: "your traffic isn't going through Whisper yet — please try `whisper connect` again"}
		}
		if sess.addr != "" && !sameIP(observedIP, sess.addr) {
			return nil, &client.ProblemError{Status: 502, Detail: "connected, but the address didn't match your agent — please try `whisper connect` again"}
		}
		sess.verified = true
		return sess, nil
	}
	return func() { connectAndVerify = saved }
}

// TestIP_VerifiedExit0: echo returns a 2a04:2a01 addr == the agent → green line, exit 0.
func TestIP_VerifiedExit0(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer ipStub(t, "2a04:2a01:9::abcd")() // observed == the agent /128

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newIPCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("verified ip must exit 0, got %v", err)
		}
	})
	if !strings.Contains(stdout, "2a04:2a01:9::abcd") || !strings.Contains(stdout, "✓ egress verified") {
		t.Fatalf("expected the green verified line, stdout=%q", stdout)
	}
}

// TestIP_MismatchExit1: echo returns a DIFFERENT (still in-range) /128 → not verified,
// a non-zero exit + a plain remediation (never a stack trace).
func TestIP_MismatchExit1(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer ipStub(t, "2a04:2a01:9::dead")() // a different /128 → mismatch

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newIPCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a mismatch must exit non-zero")
	}
	if pe, ok := client.AsProblem(err); !ok || !strings.Contains(pe.Error(), "didn't match") {
		t.Fatalf("expected a plain mismatch remediation, got %v", err)
	}
}

// TestIP_NotWhisperRangeExit1: echo returns a NON-2a04:2a01 address → verification fails
// (the egress isn't a Whisper /128).
func TestIP_NotWhisperRangeExit1(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer ipStub(t, "203.0.113.9")() // a non-Whisper source

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newIPCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a non-Whisper egress must exit non-zero")
	}
}

// TestIP_JSONShape: --json emits {ip,verified,agent} with verified=true on the happy path.
func TestIP_JSONShape(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer ipStub(t, "2a04:2a01:9::abcd")()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", jsonOut: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newIPCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("json verified must exit 0, got %v", err)
		}
	})
	for _, want := range []string{`"ip"`, `"verified"`, `"agent"`, `true`, "2a04:2a01:9::abcd"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("--json output missing %q: %s", want, stdout)
		}
	}
}
