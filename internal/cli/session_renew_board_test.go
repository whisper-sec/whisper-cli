// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// session_renew_board_test.go: what a held session does when its renewal is refused, raced,
// signalled, or answered for the wrong address, and the proof it sends each time.

func renewKeys(t *testing.T) *connectKeys {
	t.Helper()
	wg, err := wgtun.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	id, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return &connectKeys{wg: &wg, identity: id}
}

func verifiesEnrolment(t *testing.T, kp *idkey.Keypair, addr, wgPub, sigB64 string, window int64) bool {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(idkey.EnrolmentChallenge(netip.MustParseAddr(addr), wgPub, window))
	return ecdsa.VerifyASN1(&kp.Private.PublicKey, digest[:], sig)
}

// --- the proof a renewal sends ----------------------------------------------------------------

func TestARenewalHoursLaterSignsAFreshWindowForTheHeldAddress(t *testing.T) {
	// The daemon used to replay the proof it signed at start. The box accepts a window within a
	// few of its own, so every renewal after about an hour was refused.
	keys := renewKeys(t)
	start := time.Date(2026, 10, 22, 6, 0, 0, 0, time.UTC)
	staleWindow := idkey.EnrolmentWindow(start)
	base := map[string]any{
		"tier": "wireguard", "public_key": keys.wg.PublicKeyBase64,
		"identity_signature": "signed-at-start", "identity_signature_window": staleWindow,
	}
	later := start.Add(13 * idkey.EnrolmentWindowSeconds * time.Second)
	args := renewalArgs(base, keys, renewAddr, later)
	w, _ := args["identity_signature_window"].(int64)
	if w != idkey.EnrolmentWindow(later) || w-staleWindow < 13 {
		t.Fatalf("window %v, want the window of the renewal (%d), not the one from start (%d)", args["identity_signature_window"], idkey.EnrolmentWindow(later), staleWindow)
	}
	sig, _ := args["identity_signature"].(string)
	if sig == "signed-at-start" || !verifiesEnrolment(t, keys.identity, renewAddr, keys.wg.PublicKeyBase64, sig, w) {
		t.Fatal("the renewal's signature is not a fresh proof over the held address, the kept WireGuard key and its window")
	}
	if args["agent"] != renewAddr {
		t.Fatalf("agent = %v, want the held address %s", args["agent"], renewAddr)
	}
	if args["public_key"] != keys.wg.PublicKeyBase64 {
		t.Fatal("the renewal changed the WireGuard key; the box would add a peer the device does not hold")
	}
	if _, sent := args["identity_public_key"]; sent {
		t.Fatal("the renewal re-sent identity_public_key, which routes every renewal to the primary")
	}
	if _, touched := base["agent"]; touched {
		t.Fatal("renewalArgs mutated the base args")
	}
}

func TestAConnectFirstSessionRenewsWithAProofNotTheKey(t *testing.T) {
	// A foreground connect that named no agent pinned its key by sending it. Its renewal knows
	// the address now, so it proves the key instead of sending it again.
	keys := renewKeys(t)
	base := map[string]any{"tier": "wireguard", "identity_public_key": keys.identity.MarshalSPKIBase64()}
	args := renewalArgs(base, keys, renewAddr, time.Now())
	if _, sent := args["identity_public_key"]; sent {
		t.Fatal("a connect-first renewal re-sent the identity key")
	}
	if args["agent"] != renewAddr || args["identity_signature"] == nil {
		t.Fatalf("a connect-first renewal must name the held address and prove the key: %v", args)
	}
}

// renewServer is a control plane that records each op:connect query and answers from replies,
// repeating the last one.
func renewServer(t *testing.T, replies ...func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct{ Query string }
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		queries = append(queries, body.Query)
		n := len(queries)
		mu.Unlock()
		reply := replies[len(replies)-1]
		if n <= len(replies) {
			reply = replies[n-1]
		}
		reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), queries...) }
}

func problemReply(status int, detail string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"ok":false,"status":%d,"error":{"status":%d,"detail":%q}}`, status, status, detail)
	}
}

func TestARenewalHealsAMissingPinAsAConnectDoes(t *testing.T) {
	keys := renewKeys(t)
	srv, queries := renewServer(t,
		problemReply(403, "no identity key is pinned for this address to verify against"),
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(wgConnectReplyJSON()))
		})
	c := testClient(t, srv.URL)
	sess := &egressSession{endpoint: renewEP, addr: "2a04:2a01:9::abcd", tier: "wireguard", keys: keys}
	r := renewerFor(c, map[string]any{"tier": "wireguard"}, sess, false, "")
	if _, _, err := r.register(context.Background(), time.Now()); err != nil {
		t.Fatalf("the renewal did not heal a missing pin: %v", err)
	}
	q := queries()
	if len(q) != 2 || !strings.Contains(q[0], "identity_signature:") || !strings.Contains(q[1], "identity_public_key:") {
		t.Fatalf("want a signed connect, then one first enrolment; got %q", q)
	}
}

// --- refusals are final, transient faults are retried ------------------------------------------

func TestAFinalRefusalStopsRenewingAndSaysWhy(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			h := newRenewHarness(t)
			h.regErr = &client.ProblemError{Status: status, Detail: "IDENTITY_SIGNATURE_INVALID: the signature does not verify"}
			h.first.set(false, true)
			h.advance(5 * time.Second)
			for i := 0; i < 9; i++ {
				h.advance(renewMaxBackoff / 10)
			}
			if h.registers != 1 {
				t.Fatalf("a %d refusal was asked again %d times inside %s", status, h.registers-1, renewMaxBackoff)
			}
			if h.done {
				t.Fatal("a refused holder exited; a service manager would respawn it into the same refusal")
			}
			rec := onlyRecord(t)
			if rec.TunnelState != tunnelRefused || !strings.Contains(rec.TunnelReason, "signature does not verify") {
				t.Fatalf("record = %q (%q), want refused with the server's reason", rec.TunnelState, rec.TunnelReason)
			}
			if !rec.NoProxy || !h.first.isStopped() {
				t.Fatal("a refused holder kept the dead tunnel's proxy answering, which reads as a live session")
			}
			// The account gets fixed: the slow re-check brings the session back.
			h.regErr = nil
			h.advance(renewMaxBackoff / 5)
			if h.registers != 2 || h.sup.current() == nil || recordState(t) != tunnelUp {
				t.Fatalf("no recovery after the refusal was lifted (registers=%d)", h.registers)
			}
		})
	}
}

func TestTransientFaultsAreRetried(t *testing.T) {
	for _, status := range []int{408, 429, 500, 502, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			h := newRenewHarness(t)
			h.regErr = &client.ProblemError{Status: status, Detail: "busy"}
			h.first.set(false, true)
			h.advance(5 * time.Second)
			h.advance(renewBaseBackoff)
			if h.registers != 2 {
				t.Fatalf("a %d was not retried (%d registers)", status, h.registers)
			}
		})
	}
}

func TestTheRefusalReasonCarriesNoKeyAndNoEndpoint(t *testing.T) {
	err := &client.ProblemError{Status: 409, Detail: "WG_KEY_IN_USE: key q0Zr8m3Yt1x0gk5V9lJ0pQe2Hc7uWb4NsLdAaFfEeRk= is bound at box.example.net:51826"}
	got := refusalReason(err)
	if strings.Contains(got, "q0Zr8m3Yt1x0gk5V9lJ0pQe2Hc7uWb4NsLdAaFfEeRk") || strings.Contains(got, "box.example.net:51826") {
		t.Fatalf("the published reason leaks a key or an endpoint: %q", got)
	}
	if !strings.Contains(got, "WG_KEY_IN_USE") {
		t.Fatalf("the reason lost the server's own words: %q", got)
	}
}

func TestStatusSaysRefusedAndWhatToDo(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	sess := ownedSession(renewAddr, renewEP, "wireguard")
	writeSessionRecord(sess)
	updateOwnRecord(sess.recordPath, func(r *sessionRecord) {
		r.TunnelState, r.TunnelSince, r.TunnelReason = tunnelRefused, time.Now().Add(-2*time.Minute), "agent revoked"
	})
	if st := statusJSON(t); st["connection"] != tunnelRefused {
		t.Fatalf("connection = %v, want %q", st["connection"], tunnelRefused)
	}
	deepencli_globals(t, globalFlags{})
	stdout, _ := captureStd(t, func() {
		_ = deepencli_exec(t, newStatusCmd(), "--agent-file", filepath.Join(t.TempDir(), "absent"))
	})
	if !strings.Contains(stdout, "refused - ") || !strings.Contains(stdout, "agent revoked") || !strings.Contains(stdout, "whisper connect") {
		t.Fatalf("the refused row must say refused, why, and what to do: %q", stdout)
	}
}

func TestTheFailureLinesSayWhatIsTrue(t *testing.T) {
	h := newRenewHarness(t)
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second) // the bring-up fails: nothing is serving now
	h.upErr = nil
	h.regErr = errors.New("busy")
	h.advance(renewMaxBackoff)
	for _, line := range h.said {
		if strings.Contains(line, "stays up") {
			t.Fatalf("a log line claims a session stays up when none is serving: %q", line)
		}
	}
	if !strings.Contains(h.said[0], "no handshake for %s") {
		t.Fatalf("the first line must say how long the tunnel has been silent: %q", h.said[0])
	}
}

// --- a holder that serves nothing must not fight another for the address -----------------------

func TestAHolderWithNothingServingStandsDownWhenAnotherProxyHasItsPort(t *testing.T) {
	h := newRenewHarness(t)
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	h.foreign = true // an --ensure spawn brought a fresh daemon up on the port meanwhile
	writeForeignRecord(t, renewAddr, renewPort, os.Getpid()+100000)
	h.advance(renewMaxBackoff)
	if h.registers != 1 {
		t.Fatalf("re-registered over another live proxy on its port (%d registers)", h.registers)
	}
	if !h.done {
		t.Fatal("the holder did not stand down for the proxy that now serves its port")
	}
}

func TestAPortTakenDuringTheRebuildByAWhisperProxyMeansStandDown(t *testing.T) {
	h := newRenewHarness(t)
	h.upErr = errors.New("egress: local port 41555 is already in use - is another whisper proxy running?")
	up := h.sup.renew.bringUp
	h.sup.renew.bringUp = func(cx context.Context, res *client.Result, name string, port int) (*egressSession, error) {
		// a replacement daemon takes the port while this one rebuilds
		h.foreign = true
		writeForeignRecord(t, renewAddr, renewPort, os.Getpid()+100000)
		return up(cx, res, name, port)
	}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if !h.done {
		t.Fatal("a bring-up that lost its port to another Whisper proxy did not stand down")
	}
}

func TestTheLowerPidRenewsWhenTwoHoldersAreBothDown(t *testing.T) {
	h := newRenewHarness(t)
	holderAlive = func(int) bool { return true }
	write := func(pid int) {
		other := sessionRecord{Addr: renewAddr, Endpoint: "socks5h://127.0.0.1:42000", Tier: "wireguard",
			Port: 42000, PID: pid, TunnelState: tunnelHandshaking, Renews: true}
		b, _ := json.Marshal(other)
		if err := os.WriteFile(filepath.Join(sessionsDirFn(), "other.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(1) // an older holder: it renews, this one waits
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.registers != 0 {
		t.Fatal("the higher pid renewed while a lower-pid holder of the same address was renewing too")
	}
	write(os.Getpid() + 1)
	h.advance(renewMaxBackoff)
	if h.registers != 1 {
		t.Fatal("the lower pid did not renew")
	}
}

// --- the backoff ---------------------------------------------------------------------------------

func TestTheBackoffIsForgivenOnceAFreshSessionHasSettled(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = errors.New("busy")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	h.advance(renewBaseBackoff)
	if h.sup.backoff <= 2*renewBaseBackoff {
		t.Fatalf("setup: the backoff did not grow (%s)", h.sup.backoff)
	}
	h.regErr = nil
	h.advance(renewMaxBackoff)
	if len(h.built) != 1 {
		t.Fatal("setup: no fresh session")
	}
	h.advance(renewSettled + superviseEvery)
	if h.sup.backoff != renewBaseBackoff || !h.sup.renewedAt.IsZero() {
		t.Fatalf("after %s healthy the backoff is %s, want %s", renewSettled, h.sup.backoff, renewBaseBackoff)
	}
}

func TestTheFirstRenewalIsJitteredAndEachRetryDrawnFromHalfToAll(t *testing.T) {
	h := newRenewHarness(t)
	h.sup.jitter = func(n time.Duration) time.Duration { return n - 1 }
	h.regErr = errors.New("busy")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.registers != 0 {
		t.Fatal("the first renewal after the request was not spread")
	}
	h.advance(renewFirstJitter)
	if h.registers != 1 {
		t.Fatal("the first renewal did not come within its jitter")
	}
	if wait := h.sup.nextTry.Sub(h.clock); wait != renewBaseBackoff {
		t.Fatalf("at the top of the draw the wait is %s, want the full %s", wait, renewBaseBackoff)
	}
	h.sup.jitter = func(time.Duration) time.Duration { return 0 }
	h.advance(renewBaseBackoff)
	if wait := h.sup.nextTry.Sub(h.clock); wait != renewBaseBackoff {
		t.Fatalf("at the bottom of the draw the wait is %s, want half of %s", wait, 2*renewBaseBackoff)
	}
}

func TestAFailureThatNeverReachedTheControlPlaneDoesNotGrowTheBackoff(t *testing.T) {
	h := newRenewHarness(t)
	h.regErr = fmt.Errorf("control plane unreachable at x: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
	h.first.set(false, true)
	for i := 0; i < 5; i++ {
		h.advance(renewBaseBackoff)
	}
	if h.registers < 4 || h.sup.backoff != renewBaseBackoff {
		t.Fatalf("registers=%d backoff=%s; an unreachable control plane must be retried at the base", h.registers, h.sup.backoff)
	}
	// The network moved (the tunnel re-opened its socket): try now, not after the wait.
	before := h.registers
	h.first.mu.Lock()
	h.first.rebinds++
	h.first.mu.Unlock()
	h.advance(time.Second)
	if h.registers != before+1 {
		t.Fatal("a network move did not bring the next try forward")
	}
	for _, err := range []error{&net.DNSError{Err: "no such host", Name: "graph.example"}, syscall.ENETUNREACH, syscall.EHOSTUNREACH} {
		if classifyRenewErr(fmt.Errorf("x: %w", err)) != renewUnreached {
			t.Errorf("%v was not classed as never reaching the control plane", err)
		}
	}
	if classifyRenewErr(errors.New("reading control-plane reply: unexpected EOF")) != renewRetryable {
		t.Error("a reply that broke off reached the control plane and must grow the backoff")
	}
}

// --- a holder between sessions keeps its record ---------------------------------------------------

func TestAHolderBetweenSessionsKeepsAStatusRecord(t *testing.T) {
	h := newRenewHarness(t)
	h.upErr = errors.New("verify failed")
	h.first.set(false, true)
	h.advance(5 * time.Second)
	rec := onlyRecord(t)
	if !rec.NoProxy || rec.TunnelState != tunnelDown || rec.ReconnectingAt.IsZero() || rec.PID != os.Getpid() || rec.Port != renewPort {
		t.Fatalf("holder record = %+v", rec)
	}
	// status, with nothing answering the port, still reports the holder and not "not connected"
	probeWhisperProxy = func(int) bool { return false }
	st := statusJSON(t)
	if st["connection"] != tunnelDown {
		t.Fatalf("connection = %v while the holder retries, want %q", st["connection"], tunnelDown)
	}
	if len(readSessionRecords()) != 1 {
		t.Fatal("status swept the record of a live holder")
	}
	// and a record whose holder died is swept as before
	holderAlive = func(int) bool { return false }
	if st := statusJSON(t); st["connection"] != "not connected" {
		t.Fatalf("a dead holder's record read %v", st["connection"])
	}
}

// --- a renewal for another address is refused -------------------------------------------------------

func TestARenewalForADifferentAddressIsNotAdopted(t *testing.T) {
	h := newRenewHarness(t)
	env, err := client.DecodeEnvelope([]byte(wgConnectReplyJSON()), 200) // names 2a04:2a01:9::abcd
	if err != nil {
		t.Fatal(err)
	}
	h.res = env.Result
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if len(h.bringUps) != 0 || h.first.isStopped() {
		t.Fatal("a connect answered for another address replaced the held tunnel")
	}
	// and one whose verified tunnel turns out to be another address is stopped, not served
	h.res, h.upAddr = &client.Result{}, "2a04:2a01:9::abcd"
	h.advance(renewMaxBackoff)
	if len(h.built) != 1 || !h.built[0].isStopped() {
		t.Fatal("a fresh tunnel for another address was kept")
	}
	if h.sup.current() != nil {
		t.Fatal("the supervisor holds a session for an address it was never asked to hold")
	}
}

// --- no false outage right after a renewal -----------------------------------------------------------

func TestNoDownFlashRightAfterARenewal(t *testing.T) {
	h := newRenewHarness(t)
	h.first.set(false, true)
	h.advance(5 * time.Second)
	h.built[0].set(false, false) // its first reading has not caught up yet
	h.advance(superviseEvery)
	if got := recordState(t); got != tunnelUp {
		t.Fatalf("published %q a tick after a verified renewal", got)
	}
}

// --- the real hold loops ----------------------------------------------------------------------------

// holdInputs replaces the hold's tick and signal with channels a test drives.
func holdInputs(t *testing.T) (chan time.Time, chan os.Signal) {
	t.Helper()
	tick, sig := make(chan time.Time), make(chan os.Signal, 1)
	savedT, savedS, savedJ, savedL := superviseTicker, superviseSignals, renewJitter, daemonLogf
	daemonLogf = func(string, ...any) {}
	superviseTicker = func() (<-chan time.Time, func()) { return tick, func() {} }
	superviseSignals = func() (<-chan os.Signal, func()) { return sig, func() {} }
	renewJitter = func(time.Duration) time.Duration { return 0 }
	t.Cleanup(func() { superviseTicker, superviseSignals, renewJitter, daemonLogf = savedT, savedS, savedJ, savedL })
	return tick, sig
}

func latchedSession(t *testing.T) (*egressSession, *fakeTunnel) {
	t.Helper()
	ft := &fakeTunnel{endpoint: renewEP}
	ft.set(false, true)
	return &egressSession{endpoint: renewEP, addr: renewAddr, tier: "wireguard", verified: true, local: ft, keys: renewKeys(t)}, ft
}

func waitDone(t *testing.T, done chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("%s did not return within %s", what, within)
	}
}

func TestBothRealHoldLoopsRenewWithAFreshProofForTheHeldAddress(t *testing.T) {
	for _, holder := range []string{"daemon", "foreground"} {
		t.Run(holder, func(t *testing.T) {
			stubSessionsDir(t)
			stubProbe(t, true, nil)
			tick, sig := holdInputs(t)
			srv, queries := renewServer(t, problemReply(503, "busy"))
			c := testClient(t, srv.URL)
			g.quiet = true
			sess, ft := latchedSession(t)
			base := map[string]any{"tier": "wireguard", "identity_signature": "signed-at-start", "identity_signature_window": int64(1)}
			done := make(chan struct{})
			if holder == "daemon" {
				sess.renew = renewerFor(c, base, sess, false, "")
				p := projcfg.PathsFor(t.TempDir())
				go func() { holdDaemonUntilSignalLive(p, sess); close(done) }()
			} else {
				sess.renew = renewerFor(c, base, sess, true, "")
				go func() { holdUntilSignalLive(sess); close(done) }()
			}
			tick <- time.Now()
			tick <- time.Now() // a second tick only lands once the first step has finished
			q := queries()
			if len(q) != 1 {
				t.Fatalf("want one renewal connect, got %d", len(q))
			}
			want := idkey.EnrolmentWindow(time.Now())
			if !strings.Contains(q[0], "agent:'"+renewAddr+"'") {
				t.Fatalf("the renewal does not name the held address: %s", q[0])
			}
			if !strings.Contains(q[0], "identity_signature_window:"+strconv.FormatInt(want, 10)) &&
				!strings.Contains(q[0], "identity_signature_window:"+strconv.FormatInt(want-1, 10)) {
				t.Fatalf("the renewal does not carry the current window %d: %s", want, q[0])
			}
			if strings.Contains(q[0], "signed-at-start") || strings.Contains(q[0], "identity_public_key") {
				t.Fatalf("the renewal replayed the start's proof or re-sent the key: %s", q[0])
			}
			sig <- syscall.SIGTERM
			waitDone(t, done, 5*time.Second, "the hold")
			if !ft.isStopped() {
				t.Fatal("the hold left the tunnel running after the signal")
			}
			if len(readSessionRecords()) != 0 {
				t.Fatal("the hold left its record behind")
			}
		})
	}
}

func TestASignalDuringARenewalIsHonouredPromptly(t *testing.T) {
	// launchd allows 20 s between SIGTERM and SIGKILL; a renewal must not hold the exit for its
	// own 30 s deadline.
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	tick, sig := holdInputs(t)
	entered := make(chan struct{}, 1)
	srv, _ := renewServer(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
	})
	c := testClient(t, srv.URL)
	g.quiet = true
	sess, _ := latchedSession(t)
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
	sig <- syscall.SIGTERM
	waitDone(t, done, 3*time.Second, "a hold signalled mid-renewal")
}

func TestANegotiatedSessionFallsBackRatherThanDropThePort(t *testing.T) {
	// A foreground connect that negotiated its tier keeps serving its port through the normal
	// negotiation when Tier 1 will not come back up.
	h := newRenewHarness(t)
	h.upErr = errors.New("the WireGuard handshake did not complete")
	var fellBackOn int
	h.sup.renew.fallback = func(_ context.Context, port int) (*egressSession, error) {
		fellBackOn = port
		return &egressSession{endpoint: renewEP, addr: renewAddr, tier: "socks5", verified: true, negotiated: true, local: &fakeLocal{}}, nil
	}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if fellBackOn != renewPort {
		t.Fatalf("the fallback ran on port %d, want the held %d", fellBackOn, renewPort)
	}
	if cur := h.sup.current(); cur == nil || cur.tier != "socks5" {
		t.Fatal("the supervisor does not hold the fallback session")
	}
	if rec := onlyRecord(t); rec.NoProxy || rec.Tier != "socks5" {
		t.Fatalf("the record does not describe the fallback session: %+v", rec)
	}
}

// writeForeignRecord is another holder's live record for addr on port.
func writeForeignRecord(t *testing.T, addr string, port, pid int) {
	t.Helper()
	rec := sessionRecord{Addr: addr, Endpoint: fmt.Sprintf("socks5h://127.0.0.1:%d", port), Tier: "wireguard",
		Port: port, PID: pid, TunnelState: tunnelUp, Renews: true}
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(sessionsDirFn(), fmt.Sprintf("foreign-%d.json", port)), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
