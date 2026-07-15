// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// The policy setters let `whisper policy` SET the per-tenant resolution mode and
// log-retention window that the backend already stores + reads back. These tests assert the
// call SHAPE (which op, which args) against a stub control plane, plus the Postel-correct
// input handling: liberal accept (case/underscore variants), strict emit (canonical token),
// clear errors on bad input, and - critically - that an UNSET flag never clobbers a value.

// runPolicy drives `whisper policy` with args against a recording stub, returning the recorded
// calls and any command error. It never touches the network beyond the stub.
func runPolicy(t *testing.T, args ...string) ([]recordedCall, error) {
	t.Helper()
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newPolicyCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return seen, err
}

// TestPolicy_Mode_Canonical: a canonical --mode is sent verbatim in the op:policy args.
func TestPolicy_Mode_Canonical(t *testing.T) {
	for _, m := range []string{"graph-only", "hybrid", "always-forward"} {
		t.Run(m, func(t *testing.T) {
			seen, err := runPolicy(t, "--mode", m)
			if err != nil {
				t.Fatalf("policy --mode %s errored: %v", m, err)
			}
			body, ok := bodyForOp(seen, "policy")
			if !ok {
				t.Fatalf("--mode %s must fire op:policy, ops=%v", m, opsSeen(seen))
			}
			if want := "mode:'" + m + "'"; !strings.Contains(body, want) {
				t.Fatalf("--mode %s must send %s; body=%q", m, want, body)
			}
		})
	}
}

// TestPolicy_Mode_LiberalAccept: Postel - accept case-insensitive + underscore variants, but
// EMIT the strict canonical hyphenated token.
func TestPolicy_Mode_LiberalAccept(t *testing.T) {
	cases := []struct{ in, want string }{
		{"GRAPH-ONLY", "graph-only"},
		{"graph_only", "graph-only"},
		{"Graph_Only", "graph-only"},
		{"  hybrid  ", "hybrid"},
		{"Always_Forward", "always-forward"},
		{"ALWAYS-FORWARD", "always-forward"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			seen, err := runPolicy(t, "--mode", c.in)
			if err != nil {
				t.Fatalf("policy --mode %q errored: %v", c.in, err)
			}
			body, _ := bodyForOp(seen, "policy")
			if want := "mode:'" + c.want + "'"; !strings.Contains(body, want) {
				t.Fatalf("--mode %q must canonicalise to %s; body=%q", c.in, want, body)
			}
		})
	}
}

// TestPolicy_Mode_Invalid: an unknown mode is a clear usage error and NOTHING is sent.
func TestPolicy_Mode_Invalid(t *testing.T) {
	for _, bad := range []string{"graphonly", "forward", "off", "graph only", ""} {
		t.Run(bad, func(t *testing.T) {
			seen, err := runPolicy(t, "--mode", bad)
			if err == nil {
				t.Fatalf("--mode %q must error", bad)
			}
			if len(seen) != 0 {
				t.Fatalf("--mode %q must not call the control plane; ops=%v", bad, opsSeen(seen))
			}
			if !strings.Contains(err.Error(), "--mode") {
				t.Fatalf("--mode %q error must name the flag; got %v", bad, err)
			}
		})
	}
}

// TestPolicy_Retention_InRange: a valid day count is sent as an unquoted integer.
func TestPolicy_Retention_InRange(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0", "retention:0"},
		{"30", "retention:30"},
		{"365", "retention:365"},
		{"3650", "retention:3650"},
		{" 7 ", "retention:7"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			seen, err := runPolicy(t, "--retention", c.in)
			if err != nil {
				t.Fatalf("policy --retention %q errored: %v", c.in, err)
			}
			body, ok := bodyForOp(seen, "policy")
			if !ok {
				t.Fatalf("--retention %q must fire op:policy, ops=%v", c.in, opsSeen(seen))
			}
			if !strings.Contains(body, c.want) {
				t.Fatalf("--retention %q must send %s (unquoted int); body=%q", c.in, c.want, body)
			}
		})
	}
}

// TestPolicy_Retention_Invalid: non-integers and out-of-range values fail with a clear error
// and NOTHING is sent.
func TestPolicy_Retention_Invalid(t *testing.T) {
	for _, bad := range []string{"-1", "3651", "9999", "thirty", "30d", "1.5", ""} {
		t.Run(bad, func(t *testing.T) {
			seen, err := runPolicy(t, "--retention", bad)
			if err == nil {
				t.Fatalf("--retention %q must error", bad)
			}
			if len(seen) != 0 {
				t.Fatalf("--retention %q must not call the control plane; ops=%v", bad, opsSeen(seen))
			}
			if !strings.Contains(err.Error(), "--retention") {
				t.Fatalf("--retention %q error must name the flag; got %v", bad, err)
			}
		})
	}
}

// TestPolicy_UnsetFlagsNeverClobber: passing ONE setter must not send the other, so an unset
// flag can never overwrite a value already stored server-side.
func TestPolicy_UnsetFlagsNeverClobber(t *testing.T) {
	seen, err := runPolicy(t, "--mode", "hybrid")
	if err != nil {
		t.Fatalf("policy --mode hybrid errored: %v", err)
	}
	body, _ := bodyForOp(seen, "policy")
	if strings.Contains(body, "retention") {
		t.Fatalf("--mode alone must NOT send retention; body=%q", body)
	}

	seen, err = runPolicy(t, "--retention", "30")
	if err != nil {
		t.Fatalf("policy --retention 30 errored: %v", err)
	}
	body, _ = bodyForOp(seen, "policy")
	if strings.Contains(body, "mode:") {
		t.Fatalf("--retention alone must NOT send mode; body=%q", body)
	}
}

// TestPolicy_ReadBack: with no flags, policy READS - the op:policy args carry neither setter.
func TestPolicy_ReadBack(t *testing.T) {
	seen, err := runPolicy(t)
	if err != nil {
		t.Fatalf("policy (read) errored: %v", err)
	}
	body, ok := bodyForOp(seen, "policy")
	if !ok {
		t.Fatalf("bare policy must fire op:policy, ops=%v", opsSeen(seen))
	}
	if strings.Contains(body, "mode:") || strings.Contains(body, "retention") {
		t.Fatalf("bare policy must send no setters; body=%q", body)
	}
}

// TestPolicy_ModeAndRetentionTogether: both setters in one call are both carried.
func TestPolicy_ModeAndRetentionTogether(t *testing.T) {
	seen, err := runPolicy(t, "--mode", "graph-only", "--retention", "30")
	if err != nil {
		t.Fatalf("policy --mode --retention errored: %v", err)
	}
	body, _ := bodyForOp(seen, "policy")
	if !strings.Contains(body, "mode:'graph-only'") || !strings.Contains(body, "retention:30") {
		t.Fatalf("both setters must be carried; body=%q", body)
	}
}

// TestDeviceAdd_Retention: `whisper device add --retention` carries it on op:register.
func TestDeviceAdd_Retention(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newDeviceAddCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--retention", "14"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("device add --retention errored: %v", err)
	}
	body, ok := bodyForOp(seen, "register")
	if !ok {
		t.Fatalf("device add must fire op:register, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "retention:14") {
		t.Fatalf("device add --retention must send retention:14; body=%q", body)
	}
}

// TestCreateRegister_Retention: `whisper create --register --retention` carries it on op:register.
func TestCreateRegister_Retention(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--register", "--name", "throwaway", "--retention", "90"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("create --register --retention errored: %v", err)
	}
	body, ok := bodyForOp(seen, "register")
	if !ok {
		t.Fatalf("create --register must fire op:register, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "retention:90") {
		t.Fatalf("create --register --retention must send retention:90; body=%q", body)
	}
}

// TestCreate_RetentionWithoutRegister: --retention on the plain op:identity path is a clear
// usage error (nothing to attach it to) and NOTHING is created.
func TestCreate_RetentionWithoutRegister(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newCreateCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "obj", "--retention", "30"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("create --retention without --register must error")
	}
	if len(seen) != 0 {
		t.Fatalf("create --retention without --register must create nothing; ops=%v", opsSeen(seen))
	}
	if !strings.Contains(err.Error(), "--register") {
		t.Fatalf("error must guide the user to --register; got %v", err)
	}
}
