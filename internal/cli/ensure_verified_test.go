// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// ensure_verified_test.go: the verified-handshake gate behind `--ensure` / `init claude`.
// The historical defect: the daemon's proxy binds the pinned port BEFORE its egress verify
// runs, so a bare port-probe could see "live" during a verify that was about to fail - the
// parent printed "connection: up" (exit 0) for a port that died moments later. The gate:
// "up" needs the port probe AND the session-registry record, which every holder writes
// only AFTER verify passes. Plus: the daemon retries a failed connect/verify with bounded
// backoff instead of dying on the first fault.

// shrinkEnsureBudget makes the parent's bounded wait fast for tests.
func shrinkEnsureBudget(t *testing.T, d time.Duration) {
	t.Helper()
	saved := ensureStartupBudget
	ensureStartupBudget = d
	t.Cleanup(func() { ensureStartupBudget = saved })
}

// TestEnsureDaemon_PortLiveMidVerifyIsNotUp is THE false-"up" regression test: a whisper
// proxy answers the port (the daemon is mid-verify) but NO verified session record exists.
// ensure must NOT report up - and must not spawn a duplicate onto the held port either.
func TestEnsureDaemon_PortLiveMidVerifyIsNotUp(t *testing.T) {
	stubSessionsDir(t)
	shrinkEnsureBudget(t, 300*time.Millisecond)
	savedProbe := probeWhisperProxy
	savedSpawn := spawnConnectDaemon
	defer func() { probeWhisperProxy = savedProbe; spawnConnectDaemon = savedSpawn }()

	probeWhisperProxy = func(int) bool { return true } // the port answers... but is mid-verify
	spawned := false
	spawnConnectDaemon = func(projcfg.Paths) error { spawned = true; return nil }

	p := projcfg.PathsFor(t.TempDir())
	_, _, err := ensureDaemon(p, projcfg.Config{Port: 27171, Agent: "2a04:2a01::7", Tier: "socks5"})
	if err == nil {
		t.Fatal("a live-but-unverified port must NOT be reported up (the false-\"up\" race)")
	}
	if !strings.Contains(err.Error(), "verified") {
		t.Fatalf("the not-up error must say the connection didn't come up VERIFIED, got %q", err.Error())
	}
	if spawned {
		t.Fatal("ensure must not spawn a duplicate daemon onto a held port")
	}
}

// TestEnsureDaemon_MidVerifyThatCompletesBecomesUp: the port is live (mid-verify) and the
// verified record lands while the parent is waiting - ensure returns success once BOTH hold.
func TestEnsureDaemon_MidVerifyThatCompletesBecomesUp(t *testing.T) {
	stubSessionsDir(t)
	shrinkEnsureBudget(t, 5*time.Second)
	savedProbe := probeWhisperProxy
	savedSpawn := spawnConnectDaemon
	defer func() { probeWhisperProxy = savedProbe; spawnConnectDaemon = savedSpawn }()

	probes := 0
	probeWhisperProxy = func(int) bool {
		probes++
		if probes == 3 { // the "daemon" finishes its verify while the parent polls
			writeSessionRecord(ownedSession("2a04:2a01::8", "socks5h://127.0.0.1:27272", "socks5"))
		}
		return true
	}
	spawnConnectDaemon = func(projcfg.Paths) error {
		t.Fatal("the port is held - ensure must wait, never spawn")
		return nil
	}

	p := projcfg.PathsFor(t.TempDir())
	port, alreadyLive, err := ensureDaemon(p, projcfg.Config{Port: 27272, Agent: "2a04:2a01::8", Tier: "socks5"})
	if err != nil {
		t.Fatalf("a verify that completes within the budget must be up, got %v", err)
	}
	if port != 27272 || alreadyLive {
		t.Fatalf("want (27272, alreadyLive=false), got (%d, %v)", port, alreadyLive)
	}
}

// TestEnsureDaemon_StaleRecordNeverSatisfiesTheGate: a record left by a crashed holder
// (port dead) must be swept BEFORE the spawn, so a freshly-spawned daemon that binds the
// port but has not verified yet can never be reported up on the strength of the stale
// record. This is the crash-then-respawn variant of the false-"up" race.
func TestEnsureDaemon_StaleRecordNeverSatisfiesTheGate(t *testing.T) {
	dir := stubSessionsDir(t)
	shrinkEnsureBudget(t, 300*time.Millisecond)
	savedProbe := probeWhisperProxy
	savedSpawn := spawnConnectDaemon
	defer func() { probeWhisperProxy = savedProbe; spawnConnectDaemon = savedSpawn }()

	// The stale leftover: a record claiming the port, with nothing serving it.
	writeSessionRecord(ownedSession("2a04:2a01::dead", "socks5h://127.0.0.1:27373", "socks5"))

	live := false
	probeWhisperProxy = func(int) bool { return live }
	spawnConnectDaemon = func(projcfg.Paths) error {
		live = true // the fresh daemon binds the port... and is still MID-VERIFY (no record)
		return nil
	}

	p := projcfg.PathsFor(t.TempDir())
	_, _, err := ensureDaemon(p, projcfg.Config{Port: 27373, Agent: "2a04:2a01::dead", Tier: "socks5"})
	if err == nil {
		t.Fatal("a stale record must never stand in as the verified marker for a mid-verify daemon")
	}
	if got := readSessionRecords(); len(got) != 0 {
		t.Fatalf("the stale record must be swept before the spawn, still have %+v (dir %s)", got, dir)
	}
}

// --- the daemon's bounded retry --------------------------------------------------------

// shrinkDaemonBackoff makes the daemon's retry schedule instant for tests, with n backoffs
// (so n+1 attempts).
func shrinkDaemonBackoff(t *testing.T, n int) {
	t.Helper()
	saved := daemonRetryBackoff
	daemonRetryBackoff = make([]time.Duration, n)
	for i := range daemonRetryBackoff {
		daemonRetryBackoff[i] = time.Millisecond
	}
	t.Cleanup(func() { daemonRetryBackoff = saved })
}

// stubVerifyEgress replaces the network verify with a scripted verdict per attempt.
func stubVerifyEgress(t *testing.T, verdict func(attempt int) error) *int {
	t.Helper()
	saved := verifyEgress
	calls := 0
	verifyEgress = func(_ context.Context, _ *client.Client, s *egressSession) error {
		calls++
		if err := verdict(calls); err != nil {
			return err
		}
		s.verified = true
		return nil
	}
	t.Cleanup(func() { verifyEgress = saved })
	return &calls
}

// TestRunConnectDaemon_RetriesFailedVerifyThenHolds: a daemon whose first verifies fail must
// NOT die - it retries (bounded) and, once verify passes, holds the session as normal. This is
// the companion half of the false-"up" fix: the parent gates on the verified marker, and the
// daemon keeps working toward it instead of exiting after one transient fault.
func TestRunConnectDaemon_RetriesFailedVerifyThenHolds(t *testing.T) {
	stubSessionsDir(t)
	shrinkDaemonBackoff(t, 4)
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second})

	verifies := stubVerifyEgress(t, func(attempt int) error {
		if attempt <= 2 {
			return &client.ProblemError{Status: 502, Detail: "your traffic isn't going through Whisper yet"}
		}
		return nil
	})
	var held *egressSession
	savedHold := holdDaemonUntilSignal
	holdDaemonUntilSignal = func(_ projcfg.Paths, sess *egressSession) { held = sess; sess.Stop() }
	t.Cleanup(func() { holdDaemonUntilSignal = savedHold })

	p := projcfg.PathsFor(t.TempDir())
	port := freeEphemeralPort(t)
	if err := runConnectDaemon(p, projcfg.Config{Port: port, Agent: "2a04:2a01:9::abcd", Tier: "socks5"}); err != nil {
		t.Fatalf("the daemon must retry a failed verify and succeed, got %v", err)
	}
	if *verifies != 3 {
		t.Fatalf("want 3 verify attempts (2 failures + 1 success), got %d", *verifies)
	}
	if held == nil || !held.verified {
		t.Fatalf("the daemon must hold a VERIFIED session after the retry, held=%+v", held)
	}
}

// TestRunConnectDaemon_RetryIsBounded: a verify that never passes must exhaust the schedule
// and return the last error - bounded, never an unbounded spin, and the error stays the real
// verify verdict (diagnosable), not a generic wrapper.
func TestRunConnectDaemon_RetryIsBounded(t *testing.T) {
	stubSessionsDir(t)
	shrinkDaemonBackoff(t, 2) // 3 attempts total
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	deepencli_globals(t, globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second})

	verifies := stubVerifyEgress(t, func(int) error {
		return &client.ProblemError{Status: 502, Detail: "your traffic isn't going through Whisper yet"}
	})
	savedHold := holdDaemonUntilSignal
	holdDaemonUntilSignal = func(_ projcfg.Paths, _ *egressSession) {
		t.Fatal("a daemon that never verified must not hold")
	}
	t.Cleanup(func() { holdDaemonUntilSignal = savedHold })

	p := projcfg.PathsFor(t.TempDir())
	port := freeEphemeralPort(t)
	err := runConnectDaemon(p, projcfg.Config{Port: port, Agent: "2a04:2a01:9::abcd", Tier: "socks5"})
	if err == nil {
		t.Fatal("an exhausted retry schedule must surface the failure")
	}
	if !strings.Contains(err.Error(), "through Whisper") {
		t.Fatalf("the surfaced error must stay the real verify verdict, got %q", err.Error())
	}
	if *verifies != 3 {
		t.Fatalf("retry must be bounded to len(backoff)+1 = 3 attempts, got %d", *verifies)
	}
}
