// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// status_connection_test.go: `whisper status` reports the REAL connection state from the
// The session registry (probe-confirmed), never a hardcoded "not connected". The status
// command is the one debugging tool a user has when a connect path misbehaves - it must
// tell the truth in both directions.

// statusJSON runs `whisper status --json` hermetically and decodes the view.
func statusJSON(t *testing.T) map[string]any {
	t.Helper()
	deepencli_globals(t, globalFlags{jsonOut: true})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	var st map[string]any
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("status --json must be valid JSON: %v (%q)", err, stdout)
	}
	return st
}

// TestStatus_ReportsALiveSession: a registered session whose proxy answers the probe is
// reported as connected, with the bearer-free endpoint, the /128, the tier, and the port.
func TestStatus_ReportsALiveSession(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard"))

	st := statusJSON(t)
	if st["connection"] != "connected" {
		t.Fatalf("a live session must report connected, got %v", st["connection"])
	}
	sessions, ok := st["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("want exactly one session in the view, got %v", st["sessions"])
	}
	s := sessions[0].(map[string]any)
	if s["endpoint"] != "socks5h://127.0.0.1:41080" || s["address"] != "2a04:2a01:9::abcd" ||
		s["tier"] != "wireguard" || s["port"] != float64(41080) {
		t.Fatalf("session fields wrong: %v", s)
	}
}

// TestStatus_NotConnectedWithoutSessions: an empty registry is a calm "not connected" -
// fail-open, never an error.
func TestStatus_NotConnectedWithoutSessions(t *testing.T) {
	stubSessionsDir(t)
	st := statusJSON(t)
	if st["connection"] != "not connected" {
		t.Fatalf("no sessions must report not connected, got %v", st["connection"])
	}
	if _, present := st["sessions"]; present {
		t.Fatalf("no sessions must omit the sessions field, got %v", st["sessions"])
	}
}

// TestStatus_DeadRecordIsSweptAndNotConnected: a record whose proxy no longer answers is a
// crashed holder - status must report not connected AND sweep the stale record (the same
// lazy hygiene findLiveSession applies), so it never haunts the next run.
func TestStatus_DeadRecordIsSweptAndNotConnected(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, false, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))

	st := statusJSON(t)
	if st["connection"] != "not connected" {
		t.Fatalf("a dead record must report not connected, got %v", st["connection"])
	}
	if got := readSessionRecords(); len(got) != 0 {
		t.Fatalf("the dead record must be swept, still have %+v", got)
	}
}

// TestStatus_HumanTableNamesTheConnection: the human table carries the live endpoint +
// /128 + tier on the connection row, and the not-connected state points at the remedy.
func TestStatus_HumanTableNamesTheConnection(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))

	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "connected - 2a04:2a01:9::abcd via socks5h://127.0.0.1:41080 (socks5)") {
		t.Fatalf("the human connection row must carry endpoint + /128 + tier, got %q", stdout)
	}
}

// TestStatus_HumanTableNotConnectedPointsAtConnect: the empty state is actionable.
func TestStatus_HumanTableNotConnectedPointsAtConnect(t *testing.T) {
	stubSessionsDir(t)
	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	if !strings.Contains(stdout, "not connected - run: whisper connect") {
		t.Fatalf("the not-connected state must point at whisper connect, got %q", stdout)
	}
}
