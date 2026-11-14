// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// session_renew_minors_test.go: the five renewal behaviours a review of the hold left open: a
// service manager's stop without a signal, a refusal's pace, the machine registry's mode, a
// service's port after a move, and a record across a long sleep.

// 1. The Windows service manager calls Stop and delivers no signal. A renewal in flight must end
// with it, or a 30 s connect outlasts the 10 s stop grace and the process exits without close().
func TestAStopWithoutASignalCancelsARenewalInFlight(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	tick, _ := holdInputs(t)
	entered := make(chan struct{}, 1)
	srv, _ := renewServer(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
	})
	c := testClient(t, srv.URL)
	g.quiet = true
	sess, ft := latchedSession(t)
	sess.renew = renewerFor(c, map[string]any{"tier": "wireguard"}, sess, false, "")
	done := make(chan struct{})
	p := projcfg.PathsFor(t.TempDir())
	go func() { holdDaemonUntilSignalLive(p, sess); close(done) }()
	tick <- time.Now()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the renewal never reached the control plane")
	}
	stopAllHolds()
	waitDone(t, done, 3*time.Second, "a hold stopped without a signal mid-renewal")
	if !ft.isStopped() {
		t.Fatal("the hold returned without stopping its tunnel")
	}
}

// 2. A standing refusal is asked again at the slowest pace, and the two scheduling paths that do
// not ask the control plane (a yield, a busy port) cannot bring that ask forward.
func TestARefusalsReAskIsNeverBroughtForward(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = &client.ProblemError{Status: 403, Detail: "agent revoked"}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.sup.refused == "" || h.registers != 1 {
		t.Fatalf("setup: refused=%q registers=%d", h.sup.refused, h.registers)
	}
	due := h.sup.refusedNext
	if !due.Equal(h.clock.Add(renewMaxBackoff)) {
		t.Fatalf("the refusal's re-ask is %s, want %s", due, h.clock.Add(renewMaxBackoff))
	}
	early := h.clock.Add(time.Minute)
	if w := h.sup.scheduleRetry(early, false); !h.sup.nextTry.Equal(due) || w != due.Sub(early) {
		t.Fatalf("a busy-port retry moved the re-ask to %s (wait %s), want %s", h.sup.nextTry, w, due)
	}
	if got := h.sup.notBeforeRefusal(early.Add(renewBaseBackoff)); !got.Equal(due) {
		t.Fatalf("a yield moved the re-ask to %s, want %s", got, due)
	}
	// Control: once the refusal is lifted the ordinary backoff applies again.
	h.sup.refused = ""
	if got := h.sup.notBeforeRefusal(early.Add(renewBaseBackoff)); !got.Equal(early.Add(renewBaseBackoff)) {
		t.Fatalf("with no refusal standing the yield's next try is %s, want %s", got, early.Add(renewBaseBackoff))
	}
}

// And through the real loop: a port held by another proxy at the moment the re-ask falls due
// defers the ask, but the refusal is asked again on its own pace, and only once in it.
func TestARefusedHolderFacingABusyPortKeepsTheSlowPace(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = &client.ProblemError{Status: 403, Detail: "agent revoked"}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	for i := 0; i < 14; i++ {
		h.advance(time.Minute)
	}
	if h.registers != 1 {
		t.Fatalf("a refusal was asked again %d times inside its 15 minutes", h.registers-1)
	}
}

// 3. A root service that has to recreate the machine registry makes it readable, as the first
// write did: other users' `whisper status` read the service's record there.
func TestAMissingMachineRegistryIsRecreatedReadable(t *testing.T) {
	h := newRenewHarness(t)
	machine := filepath.Join(t.TempDir(), "machine")
	savedM := machineSessionsDirFn
	machineSessionsDirFn = func() string { return machine }
	t.Cleanup(func() { machineSessionsDirFn = savedM })
	failBringUp(t, h)
	h.sup.recordPath = filepath.Join(machine, "rec.json")
	h.sup.published = ""
	h.sup.publishHolder(tunnelDown, "", h.clock)
	fi, err := os.Stat(machine)
	if err != nil {
		t.Fatalf("the machine registry was not recreated: %v", err)
	}
	// Windows has no POSIX permission bits: os.Stat reports 0777 for every directory and 0666 for every
	// file whatever the code asked for, so the modes are read on POSIX hosts only. The recreation itself,
	// and the record landing in it, are checked everywhere.
	posix := runtime.GOOS != "windows"
	if got := fi.Mode().Perm(); posix && got != 0o755 {
		t.Fatalf("the machine registry was recreated %o, want 755", got)
	}
	if fi, err := os.Stat(h.sup.recordPath); err != nil || (posix && fi.Mode().Perm() != 0o644) {
		t.Fatalf("the record there is not world-readable: %v %v", fi, err)
	}
	// Control: the login's own registry stays private.
	own := filepath.Join(sessionsDirFn(), "sub")
	savedS := sessionsDirFn
	sessionsDirFn = func() string { return own }
	t.Cleanup(func() { sessionsDirFn = savedS })
	h.sup.recordPath = filepath.Join(own, "rec.json")
	h.sup.published = ""
	h.sup.publishHolder(tunnelDown, "", h.clock)
	if fi, err := os.Stat(own); err != nil || (posix && fi.Mode().Perm() != 0o700) {
		t.Fatalf("the login's registry was recreated %v (%v), want 700", fi, err)
	}
}

// 4a. A service that moved off its pinned port goes back at its next fresh session once the port
// is free, and stays where it is while something still holds it.
func TestAMovedServiceReturnsToItsPinnedPortWhenItIsFree(t *testing.T) {
	const moved = 41999
	// The pinned port is really bound, so the "still held" half sees it held, and it is released
	// halfway through. Another process could bind it in that moment, before the service looks
	// again, so the scenario runs under testenv.NumberedPort and starts over on a fresh number
	// when the released port turns out to be held.
	pinned := testenv.NumberedPort(t, func(pinned int) error {
		hold, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pinned)))
		if err != nil {
			return fmt.Errorf("%w: %w", testenv.ErrPortTaken, err)
		}
		defer hold.Close()
		h := newRenewHarness(t)
		h.sup.renew.supervised = true
		h.sup.pinned, h.sup.listen = pinned, pinned
		h.sup.renew.bringUp = func(_ context.Context, _ *client.Result, _ string, port int) (*egressSession, error) {
			h.bringUps = append(h.bringUps, port)
			p := port
			if p == 0 {
				p = moved
			}
			ep := "socks5h://127.0.0.1:" + strconv.Itoa(p)
			ft := &fakeTunnel{healthy: true, endpoint: ep}
			h.built = append(h.built, ft)
			return &egressSession{endpoint: ep, addr: renewAddr, tier: "wireguard", verified: true, local: ft}, nil
		}
		h.sup.listen = 0 // the move: the service found its port taken and asked for a free one
		h.first.set(false, true)
		h.advance(5 * time.Second)
		if h.sup.listen != moved {
			t.Fatalf("setup: the service serves %d, want the free port %d", h.sup.listen, moved)
		}
		// Still held: the next fresh session stays on the free port.
		h.built[len(h.built)-1].set(false, true)
		h.advance(renewSettled + time.Minute)
		if last := h.bringUps[len(h.bringUps)-1]; last != moved {
			t.Fatalf("asked for %d while the pinned port is still held, want %d", last, moved)
		}
		// Freed: the next fresh session asks for the pinned port again.
		_ = hold.Close()
		h.built[len(h.built)-1].set(false, true)
		h.advance(renewSettled + time.Minute)
		if last := h.bringUps[len(h.bringUps)-1]; last != pinned {
			return fmt.Errorf("%w: asked for %d once the pinned port %d was released, want the pinned port",
				testenv.ErrPortTaken, last, pinned)
		}
		return nil
	})
	// Control: a holder that is not a service never moves back on its own.
	h2 := newRenewHarness(t)
	h2.sup.pinned, h2.sup.listen = pinned, moved
	h2.first.set(false, true)
	h2.advance(5 * time.Second)
	if last := h2.bringUps[len(h2.bringUps)-1]; last != moved {
		t.Fatalf("a non-service holder asked for %d, want the port it serves (%d)", last, moved)
	}
}

// The mark reaches the record, from the hold's own writes.
func TestAServiceHoldMarksItsRecord(t *testing.T) {
	h := newRenewHarness(t)
	h.sup.renew.supervised = true
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if rec := onlyOwnRecord(t); !rec.Service {
		t.Fatal("a service's renewed session did not mark its record")
	}
	h.upErr = context.DeadlineExceeded
	h.built[len(h.built)-1].set(false, true)
	h.advance(renewSettled + time.Minute)
	if h.sup.current() != nil {
		t.Fatal("setup: the second bring-up did not fail")
	}
	if rec := onlyOwnRecord(t); !rec.Service || !rec.NoProxy {
		t.Fatalf("a service between sessions lost its mark: %+v", rec)
	}
	h2 := newRenewHarness(t)
	h2.first.set(false, true)
	h2.advance(5 * time.Second)
	if rec := onlyOwnRecord(t); rec.Service {
		t.Fatal("a holder that is not a service marked its record as one")
	}
}

// 5. A host that slept past holderStaleAfter wakes with a between-sessions record that reads as a
// dead holder's. The record is refreshed before the attempt, so it is believed throughout it.
func TestARecordIsFreshDuringTheAttemptAfterALongSleep(t *testing.T) {
	h := newRenewHarness(t)
	failBringUp(t, h)
	var during sessionRecord
	reg := h.sup.renew.register
	h.sup.renew.register = func(ctx context.Context, now time.Time) (*client.Result, string, error) {
		during = onlyOwnRecord(t)
		return reg(ctx, now)
	}
	h.advance(3*holderStaleAfter + time.Hour) // the lid was shut
	if during.PID == 0 {
		t.Fatal("no attempt was made on wake")
	}
	if h.clock.After(during.ReconnectingAt.Add(holderStaleAfter)) {
		t.Fatalf("during the attempt the record's next try was %s at %s: a stale record, which status reads as no holder",
			during.ReconnectingAt, h.clock)
	}
}
