// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// `whisper run` reused a registry session after a bare SOCKS5 handshake on its port. A
// handshake proves something speaks SOCKS5 there, not whose /128 it egresses as, so a stale record
// whose port another agent's forwarder now holds sent the child out as that other agent. These pin
// the proof: reuse only a session whose egress was OBSERVED as the target /128.

const (
	proofTarget = "2a04:2a01:9:1d::b77d"
	proofOther  = "2a04:2a01:1111:2222:3333:4444:5555:6666"
)

// plantPID is the holder pid a planted record names: 0 by default, a holder that is not running.
var plantPID = 0

func plantRecord(t *testing.T, dir, addr string, port int) string {
	t.Helper()
	rec := sessionRecord{Addr: addr, Endpoint: "socks5h://127.0.0.1:" + itoa(port), Tier: "wireguard", Port: port,
		PID: plantPID}
	b, _ := json.Marshal(rec)
	p := filepath.Join(dir, flattenAddr(addr)+"-"+itoa(port)+".json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// stubProof isolates both registries and the network reads the proof makes.
func stubProof(t *testing.T, observe func() (string, error)) (dir string, calls *int) {
	t.Helper()
	dir = stubSessionsDir(t)
	savedM := machineSessionsDirFn
	machineSessionsDirFn = func() string { return "" }
	t.Cleanup(func() { machineSessionsDirFn = savedM })
	stubProbe(t, true, nil)
	n := 0
	calls = &n
	savedO, savedD := observeEgress, directEgress
	observeEgress = func(context.Context, *client.Client, string) (string, error) { n++; return observe() }
	directEgress = func(context.Context, *client.Client) (string, error) { return "198.51.100.7", nil }
	t.Cleanup(func() { observeEgress, directEgress = savedO, savedD })
	return dir, calls
}

func TestRunReusesOnlyASessionObservedAsTheTarget(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return proofTarget, nil })
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if err != nil || sess == nil {
		t.Fatalf("a session observed as the target is reused: sess=%v err=%v", sess, err)
	}
	if !sess.verified || sess.local != nil || sess.addr != proofTarget {
		t.Fatalf("reused session must be verified and not owned: %+v", sess)
	}
}

func TestAForwarderThatEgressesAsAnotherAgentIsNeverReused(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return proofOther, nil })
	p := plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if sess != nil || err != nil {
		t.Fatalf("another agent's forwarder must not be reused, and a fresh session is safe: sess=%v err=%v", sess, err)
	}
	if _, serr := os.Stat(p); !os.IsNotExist(serr) {
		t.Fatalf("the stale record is swept")
	}
}

func TestAForwarderThatIsNotWhisperIsNeverReused(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return "198.51.100.7", nil }) // the host's own address
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if sess != nil || err != nil {
		t.Fatalf("a non-Whisper forwarder is not ours: sess=%v err=%v", sess, err)
	}
}

func TestAnUnansweredProofStopsTheRunRatherThanReplacingALiveSession(t *testing.T) {
	dir, calls := stubProof(t, func() (string, error) { return "", errors.New("echo timed out") })
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if sess != nil {
		t.Fatalf("an unproven session is not reused")
	}
	var unproven *unprovenSessionError
	if !errors.As(err, &unproven) {
		t.Fatalf("an unanswered proof must stop the run with a clear error, got %v", err)
	}
	if *calls != 2 {
		t.Fatalf("the proof is retried once: %d calls", *calls)
	}
	if unproven.port != 1080 || unproven.addr != proofTarget {
		t.Fatalf("the error names the session: %+v", unproven)
	}
}

func TestAnUnansweredProofReusesAHolderThatIsStillRunningWithAWarning(t *testing.T) {
	// the echo itself may be down: a trusted record whose holder runs is reused, never replaced
	dir, _ := stubProof(t, func() (string, error) { return "", errors.New("echo unreachable") })
	plantPID = os.Getpid()
	defer func() { plantPID = 0 }()
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, proofTarget, true)
	if err != nil || sess == nil || sess.verified || sess.local != nil {
		t.Fatalf("a running holder is reused, unverified: sess=%+v err=%v", sess, err)
	}
}

func TestWithNoTargetAnExplicitWireguardRunReusesNothing(t *testing.T) {
	dir, calls := stubProof(t, func() (string, error) { return proofTarget, nil })
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, "", true)
	if sess != nil || err != nil || *calls != 0 {
		t.Fatalf("nothing to prove against: sess=%v err=%v calls=%d", sess, err, *calls)
	}
}

func TestWithNoSelectorTheRecordIsProvedAgainstItsOwnAddress(t *testing.T) {
	dir, _ := stubProof(t, func() (string, error) { return proofOther, nil })
	plantRecord(t, dir, proofTarget, 1080)
	sess, err := findProvenSession(context.Background(), nil, "", false)
	if sess != nil || err != nil {
		t.Fatalf("a record whose port egresses as some other /128 is not reused: sess=%v err=%v", sess, err)
	}
}

func TestARecordIsTrustedOnlyFromRootTheCallerOrTheDirectoryOwner(t *testing.T) {
	cases := []struct {
		file, caller, dir uint32
		ok                bool
	}{
		{0, 1000, 0, true},       // the machine service's record
		{1000, 1000, 1000, true}, // the caller's own
		{1000, 0, 1000, true},    // root under sudo with the user's HOME kept
		{1001, 1000, 0, false},   // planted by another user in the machine directory
		{1001, 1000, 1000, false},
	}
	for _, c := range cases {
		if got := recordOwnerTrusted(c.file, c.caller, c.dir); got != c.ok {
			t.Errorf("recordOwnerTrusted(%d, %d, %d) = %v, want %v", c.file, c.caller, c.dir, got, c.ok)
		}
	}
}

// stubObserved makes the reuse proof observe addr through any local endpoint, for the run tests that
// exercise reuse itself rather than the proof.
func stubObserved(t *testing.T, addr string) {
	t.Helper()
	savedO := observeEgress
	observeEgress = func(context.Context, *client.Client, string) (string, error) { return addr, nil }
	t.Cleanup(func() { observeEgress = savedO })
}
