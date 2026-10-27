// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// session_renew_test.go: a held Tier 1 session whose box has dropped its peer must come back on
// its own, and every surface must say what the tunnel is doing in the meantime.
//
// What happened: the box lost the WireGuard peer of an installed service. The tunnel
// re-handshaked thousands of times into a box that no longer knew its key, nothing ever re-ran
// the connect that would have put the peer back, and `whisper status` said "connected" the
// whole time because the local proxy still answered. These tests drive the holder's supervisor
// with a fake tunnel, so no device and no network are needed.

// fakeTunnel is a local endpoint that reports tunnel health, as a Tier 1 tunnel does.
type fakeTunnel struct {
	mu       sync.Mutex
	healthy  bool
	fresh    bool
	stopped  bool
	age      time.Duration
	rebinds  int
	endpoint string
}

func (f *fakeTunnel) Endpoint() string { return f.endpoint }
func (f *fakeTunnel) Addr() string     { return strings.TrimPrefix(f.endpoint, "socks5h://") }
func (f *fakeTunnel) Stop()            { f.mu.Lock(); f.stopped = true; f.mu.Unlock() }
func (f *fakeTunnel) Healthy() bool    { f.mu.Lock(); defer f.mu.Unlock(); return f.healthy }
func (f *fakeTunnel) NeedsFreshSession() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fresh
}
func (f *fakeTunnel) HandshakeAge() time.Duration { f.mu.Lock(); defer f.mu.Unlock(); return f.age }
func (f *fakeTunnel) Rebinds() int                { f.mu.Lock(); defer f.mu.Unlock(); return f.rebinds }
func (f *fakeTunnel) isStopped() bool             { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }
func (f *fakeTunnel) set(healthy, fresh bool) {
	f.mu.Lock()
	f.healthy, f.fresh = healthy, fresh
	if !healthy && f.age == 0 {
		f.age = 7 * time.Minute
	}
	f.mu.Unlock()
}

var _ tunnelHealth = (*fakeTunnel)(nil)

const renewAddr = "2a04:2a01:9::beef"
const renewEP = "socks5h://127.0.0.1:41555"
const renewPort = 41555

// renewHarness is a supervisor over a fake tunnel, with a scripted control plane and clock.
type renewHarness struct {
	sup       *sessionSupervisor
	first     *fakeTunnel
	clock     time.Time
	registers int
	regNows   []time.Time
	bringUps  []int // the ports each bring-up was asked for
	res       *client.Result
	regErr    error
	upErr     error
	upAddr    string // the address a bring-up comes back for, renewAddr when empty
	built     []*fakeTunnel
	said      []string
	foreign   bool // another Whisper proxy answers this holder's port while it serves nothing
	done      bool // the last step said to stand down
}

func newRenewHarness(t *testing.T) *renewHarness {
	t.Helper()
	stubSessionsDir(t)
	// The real clock's date, because a between-sessions record is judged fresh against it.
	h := &renewHarness{clock: time.Now().UTC().Truncate(time.Second), res: &client.Result{}}
	savedProbe := probeWhisperProxy
	probeWhisperProxy = func(port int) bool {
		if port == renewPort {
			return (h.sup != nil && h.sup.current() != nil) || h.foreign
		}
		return true
	}
	savedAlive := holderAlive
	holderAlive = func(pid int) bool { return pid == os.Getpid() }
	t.Cleanup(func() { probeWhisperProxy, holderAlive = savedProbe, savedAlive })
	h.first = &fakeTunnel{healthy: true, endpoint: renewEP}
	sess := &egressSession{endpoint: renewEP, addr: renewAddr, tier: "wireguard", verified: true, local: h.first}
	sess.renew = &sessionRenewer{
		port: renewPort,
		register: func(_ context.Context, now time.Time) (*client.Result, string, error) {
			h.registers++
			h.regNows = append(h.regNows, now)
			return h.res, "scout", h.regErr
		},
		bringUp: func(_ context.Context, _ *client.Result, _ string, port int) (*egressSession, error) {
			h.bringUps = append(h.bringUps, port)
			if h.upErr != nil {
				return nil, h.upErr
			}
			ft := &fakeTunnel{healthy: true, endpoint: renewEP}
			h.built = append(h.built, ft)
			return &egressSession{endpoint: renewEP, addr: firstNonBlank(h.upAddr, renewAddr), tier: "wireguard", verified: true, local: ft}, nil
		},
	}
	writeSessionRecord(sess)
	h.sup = newSessionSupervisor(sess, func(f string, a ...any) { h.said = append(h.said, f) })
	h.sup.now = func() time.Time { return h.clock }
	h.sup.jitter = func(time.Duration) time.Duration { return 0 }
	return h
}

func (h *renewHarness) advance(d time.Duration) {
	h.clock = h.clock.Add(d)
	h.done = h.sup.step(context.Background())
}

// recordState reads the tunnel state the holder published into its own session record.
func recordState(t *testing.T) string {
	t.Helper()
	return onlyRecord(t).TunnelState
}

func onlyRecord(t *testing.T) sessionRecord {
	t.Helper()
	recs := readSessionRecords()
	if len(recs) != 1 {
		t.Fatalf("want exactly one session record, have %d", len(recs))
	}
	return recs[0]
}

func TestAHealthyTunnelIsLeftAloneAndPublishedUp(t *testing.T) {
	h := newRenewHarness(t)
	h.advance(5 * time.Second)
	if h.registers != 0 {
		t.Fatalf("a healthy tunnel was renewed (%d registers)", h.registers)
	}
	if got := recordState(t); got != tunnelUp {
		t.Fatalf("published %q for a healthy tunnel, want %q", got, tunnelUp)
	}
}

func TestAStalledTunnelIsPublishedHandshakingBeforeItAsksForMore(t *testing.T) {
	h := newRenewHarness(t)
	h.first.set(false, false)
	h.advance(5 * time.Second)
	if h.registers != 0 {
		t.Fatal("renewed a tunnel that has not asked for a fresh session yet")
	}
	if got := recordState(t); got != tunnelHandshaking {
		t.Fatalf("published %q for a stalled tunnel, want %q", got, tunnelHandshaking)
	}
}

func TestATunnelAskingForAFreshSessionIsReconnectedOnTheSamePort(t *testing.T) {
	// THE fix: the connect runs again, so the box re-adds the peer, and the new tunnel serves
	// the same loopback port every tool already holds.
	h := newRenewHarness(t)
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.registers != 1 || len(h.bringUps) != 1 {
		t.Fatalf("registers=%d bringUps=%d, want one of each", h.registers, len(h.bringUps))
	}
	if h.bringUps[0] != 41555 {
		t.Fatalf("the fresh tunnel was brought up on port %d, want the same 41555", h.bringUps[0])
	}
	if !h.first.stopped {
		t.Fatal("the dead tunnel was not stopped before its replacement took the port")
	}
	if h.sup.current() == nil || h.sup.current().local != h.built[0] {
		t.Fatal("the supervisor is not holding the fresh session")
	}
	if h.sup.current().renew == nil {
		t.Fatal("the fresh session cannot be renewed in its turn")
	}
	if got := recordState(t); got != tunnelUp {
		t.Fatalf("published %q after a successful fresh session, want %q", got, tunnelUp)
	}
}

func TestAControlPlaneFailureKeepsTheOldSessionAndBacksOff(t *testing.T) {
	// Fail open: a connect that could not be made must not tear down the tunnel we have.
	h := newRenewHarness(t)
	h.regErr = errors.New("control plane unreachable")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.first.stopped {
		t.Fatal("a failed connect tore down the existing tunnel")
	}
	if len(h.bringUps) != 0 {
		t.Fatal("a bring-up ran after the connect failed")
	}
	h.advance(5 * time.Second)
	if h.registers != 1 {
		t.Fatalf("retried after 5s (%d registers); the backoff is %s", h.registers, renewBaseBackoff)
	}
	h.advance(renewBaseBackoff)
	if h.registers != 2 {
		t.Fatalf("no retry once the backoff passed (%d registers)", h.registers)
	}
}

func TestAFailedBringUpHoldsNothingAndTriesAgainFromTheConnect(t *testing.T) {
	h := newRenewHarness(t)
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.sup.current() != nil {
		t.Fatal("the supervisor still claims a session after its bring-up failed")
	}
	if rec := onlyRecord(t); !rec.NoProxy || rec.TunnelState != tunnelDown {
		t.Fatalf("the holder's record must stay, saying nothing serves and it is down: %+v", rec)
	}
	h.upErr = nil
	h.advance(renewBaseBackoff + time.Second)
	if h.registers != 2 || len(h.bringUps) != 2 {
		t.Fatalf("registers=%d bringUps=%d after the backoff, want a full second attempt", h.registers, len(h.bringUps))
	}
	if h.sup.current() == nil {
		t.Fatal("the second attempt did not leave a held session")
	}
}

func TestTheBackoffDoublesToItsCap(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = errors.New("still unreachable")
	h.first.set(false, true)
	h.advance(time.Second)
	waits := []time.Duration{}
	for i := 0; i < 12; i++ {
		before := h.registers
		var waited time.Duration
		for h.registers == before {
			h.advance(time.Second)
			waited += time.Second
			if waited > 2*renewMaxBackoff {
				t.Fatalf("no retry within %s", 2*renewMaxBackoff)
			}
		}
		waits = append(waits, waited)
	}
	if waits[1] < 2*waits[0]-time.Second {
		t.Fatalf("the backoff did not double: %v", waits)
	}
	if last := waits[len(waits)-1]; last > renewMaxBackoff+time.Second {
		t.Fatalf("the backoff passed its cap: %s > %s", last, renewMaxBackoff)
	}
}

func TestAFreshSessionThatStallsAgainIsReportedDown(t *testing.T) {
	// A fresh session that did not bring it back is a different fact from a tunnel still
	// re-handshaking, and the user is owed that difference.
	h := newRenewHarness(t)
	h.first.set(false, true)
	h.advance(5 * time.Second)
	h.built[0].set(false, false)
	h.advance(renewGrace + 5*time.Second)
	if got := recordState(t); got != tunnelDown {
		t.Fatalf("published %q for a tunnel a fresh session did not revive, want %q", got, tunnelDown)
	}
}

func TestAnotherLiveHolderOfTheSameAddressIsNotFought(t *testing.T) {
	// The box binds one tunnel to one address and the newest connect wins. If another holder on
	// this host has the address's tunnel up, taking it back would start a tug of war.
	h := newRenewHarness(t)
	other := sessionRecord{Addr: renewAddr, Endpoint: "socks5h://127.0.0.1:42000", Tier: "wireguard",
		Port: 42000, PID: os.Getpid() + 100000, TunnelState: tunnelUp}
	b, _ := json.Marshal(other)
	if err := os.WriteFile(filepath.Join(sessionsDirFn(), "other.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.registers != 0 {
		t.Fatal("renewed over another live holder of the same address")
	}
}

func TestCloseStopsAndClearsWhateverIsCurrent(t *testing.T) {
	h := newRenewHarness(t)
	h.first.set(false, true)
	h.advance(5 * time.Second)
	h.sup.close()
	if !h.built[0].stopped {
		t.Fatal("close left the fresh tunnel running")
	}
	if len(readSessionRecords()) != 0 {
		t.Fatal("close left the session record behind")
	}
}

func TestASessionWithNoTunnelIsNeverTouched(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	sess := ownedSession(renewAddr, renewEP, "socks5")
	writeSessionRecord(sess)
	sup := newSessionSupervisor(sess, nil)
	sup.step(context.Background())
	if got := recordState(t); got != "" {
		t.Fatalf("published a tunnel state %q for a session with no tunnel", got)
	}
}

// --- status ---------------------------------------------------------------------------------

func writeRecordWithState(t *testing.T, state string, since time.Time) {
	t.Helper()
	sess := ownedSession(renewAddr, renewEP, "wireguard")
	writeSessionRecord(sess)
	if state != "" && !publishTunnelState(sess, state, since) {
		t.Fatal("could not publish the tunnel state")
	}
}

func TestStatusSaysHandshakingNotConnectedForAStalledTunnel(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeRecordWithState(t, tunnelHandshaking, time.Now().Add(-7*time.Minute))
	st := statusJSON(t)
	if st["connection"] != tunnelHandshaking {
		t.Fatalf("connection = %v for a tunnel with no handshake, want %q", st["connection"], tunnelHandshaking)
	}
	s := st["sessions"].([]any)[0].(map[string]any)
	if s["tunnel"] != tunnelHandshaking {
		t.Fatalf("session tunnel = %v, want %q", s["tunnel"], tunnelHandshaking)
	}
}

func TestStatusSaysDownWhenAFreshSessionDidNotHelp(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeRecordWithState(t, tunnelDown, time.Now().Add(-20*time.Minute))
	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		if err := deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent")); err != nil {
			t.Errorf("status errored: %v", err)
		}
	})
	if strings.Contains(stdout, "connected - ") {
		t.Fatalf("a down tunnel was rendered connected: %q", stdout)
	}
	if !strings.Contains(stdout, "down - "+renewAddr) || !strings.Contains(stdout, "20m") {
		t.Fatalf("the row must say down, the address and for how long, got %q", stdout)
	}
}

func TestStatusStillSaysConnectedForAnUpTunnelAndForOlderRecords(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeRecordWithState(t, tunnelUp, time.Now())
	if st := statusJSON(t); st["connection"] != "connected" {
		t.Fatalf("an up tunnel reads %v, want connected", st["connection"])
	}
	// A record written by an older holder has no state; it keeps the answer it always had.
	stubSessionsDir(t)
	writeRecordWithState(t, "", time.Time{})
	if st := statusJSON(t); st["connection"] != "connected" {
		t.Fatalf("a record with no tunnel state reads %v, want connected", st["connection"])
	}
}

func TestPublishingIsOwnerCheckedAndAtomic(t *testing.T) {
	stubSessionsDir(t)
	sess := ownedSession(renewAddr, renewEP, "wireguard")
	writeSessionRecord(sess)
	// A record that names another process is not ours to rewrite.
	b, _ := os.ReadFile(sess.recordPath)
	var rec sessionRecord
	_ = json.Unmarshal(b, &rec)
	rec.PID = os.Getpid() + 100000
	b, _ = json.Marshal(rec)
	_ = os.WriteFile(sess.recordPath, b, 0o600)
	if publishTunnelState(sess, tunnelDown, time.Now()) {
		t.Fatal("rewrote a session record another process owns")
	}
	// and no temporary file is left in the registry either way
	ents, _ := os.ReadDir(sessionsDirFn())
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			t.Fatalf("a stray file %s was left in the registry", e.Name())
		}
	}
}

func TestServiceStatusLineNamesAStalledTunnel(t *testing.T) {
	line := tunnelStatusLine(statusSession{Tunnel: tunnelHandshaking, TunnelSince: time.Now().Add(-3 * time.Minute)})
	if !strings.Contains(line, "handshaking") || !strings.Contains(line, "3m") {
		t.Fatalf("the service tunnel line = %q", line)
	}
	if tunnelStatusLine(statusSession{Tunnel: tunnelUp}) != "" || tunnelStatusLine(statusSession{}) != "" {
		t.Fatal("an up tunnel, or a record with no state, must add no line")
	}
}

// Both holders must run the supervisor, or the mechanism above is never reached.
func TestBothHoldersRunTheSupervisor(t *testing.T) {
	for _, f := range []string{"connect.go", "daemon.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "superviseUntilSignal(") {
			t.Fatalf("%s holds its session without the supervisor, so a dropped peer is never reconnected", f)
		}
		if !strings.Contains(string(src), ".renew = renewerFor(") {
			t.Fatalf("%s does not renew through the shared renewerFor", f)
		}
	}
}
