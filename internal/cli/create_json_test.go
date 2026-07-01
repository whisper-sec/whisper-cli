// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCreate_JSON_EmitsEnvelopeToStdout is the #256 regression test: under --json, the default
// (op:identity) `whisper create` MUST write the machine JSON envelope — carrying the routable
// /128 address — to STDOUT so a programmatic caller (the whisper-id Node+Python SDKs'
// register()) can JSON-parse it. Human chrome stays on stderr. Without the fix, create prints
// only a human line to stderr and emits ZERO bytes to stdout, so this test fails (empty stdout,
// which is not valid JSON).
func TestCreate_JSON_EmitsEnvelopeToStdout(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", jsonOut: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--name", "scout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --json errored: %v", err)
		}
	})

	// The default create path must fire op:identity (never op:register).
	if !containsOp(opsSeen(seen), "identity") {
		t.Fatalf("create must fire op:identity, ops=%v", opsSeen(seen))
	}

	// STDOUT must be VALID JSON — a programmatic caller parses exactly these bytes.
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		t.Fatalf("create --json emitted 0 bytes to stdout; want the machine JSON envelope")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("create --json stdout is not valid JSON: %v\nstdout=%q", err, stdout)
	}

	// …and it must contain the load-bearing /128 address the recordingServer returns for op:identity.
	if !strings.Contains(stdout, "2a04:2a01:9::abcd") {
		t.Fatalf("create --json stdout must contain the /128 address; stdout=%q", stdout)
	}
}
