// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// session_renew_round2_test.go: a refused holder that can recover, a service that never
// stands down into nothing, records that are believed only while their holder is demonstrably
// alive, and a record that survives the rebuild window.

// failBringUp makes the harness's first renewal leave nothing serving.
func failBringUp(t *testing.T, h *renewHarness) {
	t.Helper()
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.sup.current() != nil {
		t.Fatal("setup: the bring-up did not fail")
	}
	h.upErr = nil
}

func TestARefusedRecordIsNeverReusedOrTakenAsVerified(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil) // a dead tunnel's proxy still answers its port
	sess := ownedSession(renewAddr, renewEP, "wireguard")
	writeSessionRecord(sess)
	updateOwnRecord(sess.recordPath, func(r *sessionRecord) { r.TunnelState = tunnelRefused })
	if verifiedSessionOnPort(renewPort) {
		t.Fatal("--ensure took a refused session as a verified one and would never start a replacement")
	}
	if got, ok := findLiveSession(context.Background(), nil, renewAddr); ok {
		t.Fatalf("a refused session was handed out for reuse: %+v", got)
	}
}

func TestARefusedHolderStillStandsDownForItsReplacement(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = &client.ProblemError{Status: 403, Detail: "agent revoked"}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	// The account is fixed and an --ensure starts a replacement on the port.
	h.foreign = true
	writeForeignRecord(t, renewAddr, renewPort, os.Getpid()+100000)
	h.advance(renewMaxBackoff)
	if !h.done || h.registers != 1 {
		t.Fatalf("done=%v registers=%d: a refused holder must stand down for a replacement serving its address", h.done, h.registers)
	}
}

func TestAServiceMovesToAFreePortRatherThanStandDown(t *testing.T) {
	// A service manager reports the service active for as long as the process lives, so a
	// service that stood down would be an active service with no egress in it.
	h := newRenewHarness(t)
	h.sup.renew.supervised = true
	failBringUp(t, h)
	h.foreign = true // some other proxy took the port while this one served nothing
	h.advance(renewMaxBackoff)
	if h.done {
		t.Fatal("a service stood down; it would sit active with no egress")
	}
	if last := h.bringUps[len(h.bringUps)-1]; last != 0 {
		t.Fatalf("the service asked for port %d again, want a free one (0)", last)
	}
}

func TestAHolderDoesNotStandDownForAProxyServingAnotherAddress(t *testing.T) {
	h := newRenewHarness(t)
	failBringUp(t, h)
	h.foreign = true
	writeForeignRecord(t, "2a04:2a01:9::abcd", renewPort, os.Getpid()+100000)
	h.advance(renewMaxBackoff)
	if h.done {
		t.Fatal("stood down for a proxy that serves a different agent; the tools on this port would egress from the wrong /128")
	}
	if h.registers != 1 {
		t.Fatalf("re-registered while its port is held by something else (%d registers)", h.registers)
	}
}

func TestABetweenSessionsRecordIsBelievedOnlyWhileFresh(t *testing.T) {
	saved := holderAlive
	holderAlive = func(int) bool { return true } // a reused pid, or Windows, where every pid exists
	t.Cleanup(func() { holderAlive = saved })
	rec := sessionRecord{NoProxy: true, PID: 4242, ReconnectingAt: time.Now().Add(time.Minute)}
	if !heldWithoutProxy(rec) {
		t.Fatal("a fresh between-sessions record was not believed")
	}
	rec.ReconnectingAt = time.Now().Add(-holderStaleAfter - time.Minute)
	if heldWithoutProxy(rec) {
		t.Fatal("a record whose holder stopped refreshing it was believed because its pid exists")
	}
	rec.ReconnectingAt = time.Time{}
	if heldWithoutProxy(rec) {
		t.Fatal("a record with no next try was believed")
	}
}

func TestAWaitingHolderKeepsItsRecordFresh(t *testing.T) {
	h := newRenewHarness(t)
	failBringUp(t, h)
	holderAlive = func(int) bool { return true }
	writeForeignRecord(t, renewAddr, 42000, 1) // another holder of the address is up
	for i := 0; i < 12; i++ {
		h.advance(renewMaxBackoff / 4)
	}
	rec := onlyOwnRecord(t)
	if rec.ReconnectingAt.Before(h.clock.Add(-holderStaleAfter / 2)) {
		t.Fatalf("a holder waiting on another let its record go stale: next try %s, now %s", rec.ReconnectingAt, h.clock)
	}
}

func TestTheYieldRuleNeedsALiveRenewingHolder(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renews    bool
		answering bool
	}{
		{"a dead holder's record (no proxy, not between sessions)", true, false},
		{"a session that never renews (a guided front door)", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRenewHarness(t)
			holderAlive = func(int) bool { return true }
			prev := probeWhisperProxy
			probeWhisperProxy = func(port int) bool {
				if port == 42000 {
					return tc.answering
				}
				return prev(port)
			}
			other := sessionRecord{Addr: renewAddr, Endpoint: "socks5h://127.0.0.1:42000", Tier: "wireguard",
				Port: 42000, PID: 1, TunnelState: tunnelHandshaking, Renews: tc.renews}
			writeRecordFile(t, "other.json", other)
			h.first.set(false, true)
			h.advance(5 * time.Second)
			if h.registers != 1 {
				t.Fatalf("waited on %s", tc.name)
			}
		})
	}
}

func TestAHolderThatCannotRenewSaysSo(t *testing.T) {
	stubSessionsDir(t)
	ft := &fakeTunnel{endpoint: renewEP}
	ft.set(false, false)
	sess := &egressSession{endpoint: renewEP, addr: renewAddr, tier: "wireguard", verified: true, local: ft}
	writeSessionRecord(sess)
	newSessionSupervisor(sess, nil).step(context.Background())
	if rec := onlyRecord(t); rec.TunnelState != tunnelHandshaking || rec.Renews {
		t.Fatalf("a session with no renewer published %+v; others would wait on it for ever", rec)
	}
	h := newRenewHarness(t)
	h.first.set(false, false)
	h.advance(5 * time.Second)
	if !onlyRecord(t).Renews {
		t.Fatal("a renewing holder does not say it renews")
	}
}

func TestTheRecordSaysNoProxyThroughoutTheRebuild(t *testing.T) {
	h := newRenewHarness(t)
	var during sessionRecord
	up := h.sup.renew.bringUp
	h.sup.renew.bringUp = func(cx context.Context, res *client.Result, name string, port int) (*egressSession, error) {
		during = onlyRecord(t)
		// a status or --ensure sweep in this window removes whatever it does not believe
		for _, rec := range readSessionRecords() {
			if !probeWhisperProxy(rec.Port) && !heldWithoutProxy(rec) {
				removeSessionRecordAt(rec.path)
			}
		}
		if len(readSessionRecords()) != 1 {
			t.Error("a sweep during the rebuild deleted the live holder's record")
		}
		_ = os.Remove(during.path) // and even if something removes it anyway
		return up(cx, res, name, port)
	}
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if !during.NoProxy || during.TunnelState != tunnelDown {
		t.Fatalf("during the rebuild the record said %+v, want no proxy and down", during)
	}
	if rec := onlyRecord(t); !rec.NoProxy {
		t.Fatalf("the holder did not write its record back after the rebuild failed: %+v", rec)
	}
}

func TestStandingDownLeavesTheReplacementsPIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid()+100000)+"\n"), 0o600)
	removeOwnPIDFile(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("removed a pidfile that names another process")
	}
	_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	removeOwnPIDFile(path)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("left its own pidfile behind")
	}
}

func TestTheRefusalReasonCarriesNoControlCharacters(t *testing.T) {
	got := refusalReason(&client.ProblemError{Status: 403, Detail: "agent\x1b[31m revoked\x07 by\u200b admin\ttoday"})
	for _, r := range got {
		if r < 0x20 || r == 0x7f || r == '\u200b' {
			t.Fatalf("control character %U in the published reason %q", r, got)
		}
	}
	if !strings.Contains(got, "revoked") {
		t.Fatalf("the reason lost its words: %q", got)
	}
}

func TestAProxyConnectFailureNeverReachedTheControlPlane(t *testing.T) {
	err := fmt.Errorf("control plane unreachable at x: %w", &net.OpError{Op: "proxyconnect", Net: "tcp", Err: syscall.ECONNREFUSED})
	if classifyRenewErr(err) != renewUnreached {
		t.Fatal("a refused HTTPS_PROXY dial grew the backoff as if the control plane had answered")
	}
}

func TestAStopWithoutASignalEndsTheHold(t *testing.T) {
	// The Windows service manager calls Stop and sends no signal.
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	holdInputs(t)
	g.quiet = true
	ft := &fakeTunnel{healthy: true, endpoint: renewEP}
	sess := &egressSession{endpoint: renewEP, addr: renewAddr, tier: "wireguard", verified: true, local: ft}
	done := make(chan struct{})
	go func() { holdUntilSignalLive(sess); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(readSessionRecords()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stopAllHolds()
	waitDone(t, done, 3*time.Second, "a hold stopped without a signal")
	if !ft.isStopped() || len(readSessionRecords()) != 0 {
		t.Fatal("the hold did not stop its tunnel and clear its record")
	}
}

// onlyOwnRecord is the one record this process wrote.
func onlyOwnRecord(t *testing.T) sessionRecord {
	t.Helper()
	for _, rec := range readSessionRecords() {
		if rec.PID == os.Getpid() {
			return rec
		}
	}
	t.Fatal("no record of this holder")
	return sessionRecord{}
}

func writeRecordFile(t *testing.T, name string, rec sessionRecord) {
	t.Helper()
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(sessionsDirFn(), name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
