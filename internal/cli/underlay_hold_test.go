// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// underlay_hold_test.go: every connect that says where this node can be dialed names a port a
// socket of this process holds at that moment, the tunnel that follows binds exactly that socket,
// and a socket no tunnel takes is let go. The port used to be a number read from a socket
// that was then closed, so anything else on the host could take it before the device bound it.

// heldSockets records every socket the CLI opens for a declaration, and pins the underlay to one
// documentation address so the declared endpoint is predictable on any host.
type heldSockets struct {
	mu    sync.Mutex
	holds []*wgtun.ListenHold
}

func recordHolds(t *testing.T) *heldSockets {
	t.Helper()
	rec := &heldSockets{}
	savedHold, savedEps := holdListenPort, underlayEndpoints
	holdListenPort = func() *wgtun.ListenHold {
		h := savedHold()
		if h == nil {
			t.Skip("no UDP socket can be opened on this host")
		}
		rec.mu.Lock()
		rec.holds = append(rec.holds, h)
		rec.mu.Unlock()
		return h
	}
	underlayEndpoints = func(port int) []string { return []string{fmt.Sprintf("192.0.2.11:%d", port)} }
	t.Cleanup(func() {
		holdListenPort, underlayEndpoints = savedHold, savedEps
		for _, h := range rec.all() {
			h.Release()
		}
	})
	return rec
}

func (r *heldSockets) all() []*wgtun.ListenHold {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*wgtun.ListenHold(nil), r.holds...)
}

// declaredPort reads the port a connect's args declare, or 0.
func declaredPort(t *testing.T, args map[string]any) int {
	t.Helper()
	eps, _ := args["endpoints"].([]string)
	if len(eps) == 0 {
		return 0
	}
	if len(eps) != 1 {
		t.Fatalf("declared %v", eps)
	}
	_, port, err := net.SplitHostPort(eps[0])
	if err != nil {
		t.Fatalf("declared %q: %v", eps[0], err)
	}
	var p int
	_, _ = fmt.Sscan(port, &p)
	return p
}

// assertHeldByUs fails unless a bind on port by anything else is refused as in use.
func assertHeldByUs(t *testing.T, port int) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err == nil {
		_ = c.Close()
		t.Fatalf("port %d was declared, and another program could bind it", port)
	}
	// 10048 is WSAEADDRINUSE; 10013 (WSAEACCES) is how Windows refuses a bind over another account's
	// socket.
	if !errors.Is(err, syscall.EADDRINUSE) && !errors.Is(err, syscall.Errno(10048)) && !errors.Is(err, syscall.Errno(10013)) {
		t.Fatalf("a bind on the declared port %d failed for another reason: %v", port, err)
	}
}

func mintWG(t *testing.T) *wgtun.Keypair {
	t.Helper()
	kp, err := wgtun.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return &kp
}

// TestConnectKeys_HoldOneSocketAndHandItOver is the keys' own contract.
func TestConnectKeys_HoldOneSocketAndHandItOver(t *testing.T) {
	rec := recordHolds(t)
	keys := newConnectKeys(mintWG(t), nil, true)
	keys.setLive(fixedPort(40404))
	keys.holdUnderlay()
	keys.holdUnderlay() // a connect sent again declares the same socket, never a second one
	if n := len(rec.all()); n != 1 {
		t.Fatalf("two holds for one pending bring-up: %d", n)
	}
	held := rec.all()[0]
	args := map[string]any{"endpoints": "stale"}
	keys.declareUnderlay(args)
	if got := declaredPort(t, args); got != held.Port() {
		t.Fatalf("declared %d while a bring-up is pending on %d (the running tunnel's 40404 is the wrong one)", got, held.Port())
	}
	assertHeldByUs(t, held.Port())
	if h := keys.takeHold(); h != held {
		t.Fatal("the bring-up was not handed the socket the connect declared")
	}
	keys.releaseHold() // nothing pending: the bring-up owns it now
	if held.Port() == 0 {
		t.Fatal("releasing after the hand-over closed the bring-up's socket")
	}
	held.Release()
	// with nothing pending, a check-in declares the port the running tunnel holds
	args = map[string]any{}
	keys.declareUnderlay(args)
	if got := declaredPort(t, args); got != 40404 {
		t.Fatalf("a check-in declared %d, the running tunnel holds 40404", got)
	}
	// a session that takes no direct peers declares nothing, even with a tunnel running
	nodirect := newConnectKeys(mintWG(t), nil, false)
	nodirect.holdUnderlay()
	nodirect.setLive(fixedPort(40405))
	args = map[string]any{"endpoints": "stale"}
	nodirect.declareUnderlay(args)
	if _, ok := args["endpoints"]; ok {
		t.Fatalf("a session with no direct peers declared %v", args["endpoints"])
	}
	// one with no tunnel key is not a tunnel, and holds nothing; no keys at all declare nothing
	newConnectKeys(nil, nil, true).holdUnderlay()
	var none *connectKeys
	none.holdUnderlay()
	none.setLive(fixedPort(40405))
	args = map[string]any{"endpoints": "stale"}
	none.declareUnderlay(args)
	none.releaseHold()
	if _, ok := args["endpoints"]; ok {
		t.Fatal("no keys declared an underlay")
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("a session that declares nothing opened a socket: %d holds", n)
	}
}

// TestTheConnectDeclaresAPortItHolds: the first connect of a session that takes direct peers
// declares the port of a socket it holds, and the keys carry that socket to the bring-up.
func TestTheConnectDeclaresAPortItHolds(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	rec := recordHolds(t)
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	_, keys, err := connectTierEnvelope(context.Background(), c, map[string]any{}, tierWireGuard, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.releaseHold()
	holds := rec.all()
	if len(holds) != 1 || keys.hold != holds[0] {
		t.Fatalf("the keys do not carry the one socket the connect declared: %d holds", len(holds))
	}
	port := holds[0].Port()
	assertHeldByUs(t, port)
	sent := ""
	for _, call := range seen {
		if call.op == "connect" {
			sent = call.body
		}
	}
	if want := fmt.Sprintf("192.0.2.11:%d", port); !strings.Contains(sent, want) {
		t.Fatalf("the connect did not declare the held port %d: %s", port, sent)
	}
}

// TestTheEnforcedConnectDeclaresNothing: the enforced run's device installs no direct peers, so
// its connect says nowhere to be dialed and holds no socket.
func TestTheEnforcedConnectDeclaresNothing(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	rec := recordHolds(t)
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	_, keys, err := connectTierEnvelope(context.Background(), c, map[string]any{}, tierWireGuard, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.all()) != 0 || keys.hold != nil {
		t.Fatal("the enforced connect opened a socket to declare")
	}
	for _, call := range seen {
		if call.op == "connect" && strings.Contains(call.body, "endpoints") {
			t.Fatalf("the enforced connect declared an underlay: %s", call.body)
		}
	}
	// Control: the server and the stubs do carry a declaration when the session takes direct
	// peers, so the absence above is the flag's doing.
	_, keys2, err := connectTierEnvelope(context.Background(), c, map[string]any{}, tierWireGuard, "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer keys2.releaseHold()
	if !strings.Contains(seen[len(seen)-1].body, "192.0.2.11:") {
		t.Fatal("control failed: a direct session's connect declared nothing either")
	}
}

// TestARefusedConnectLetsItsSocketGo: a connect the box refuses returns no keys, so nothing would
// ever bind the socket it declared; it is closed on the way out.
func TestARefusedConnectLetsItsSocketGo(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	rec := recordHolds(t)
	srv := autoTierServer(t, nil, `{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`, s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	if _, _, err := connectTierEnvelope(context.Background(), c, map[string]any{}, tierWireGuard, "", true); err == nil {
		t.Fatal("the refused connect succeeded")
	}
	holds := rec.all()
	if len(holds) != 1 {
		t.Fatalf("the refused connect opened %d sockets, want 1", len(holds))
	}
	if holds[0].Port() != 0 {
		t.Fatalf("the refused connect left port %d held", holds[0].Port())
	}
}

// TestARenewalDeclaresTheSocketItsFreshTunnelBinds: a fresh session opens its socket before the
// connect that declares it, the bring-up takes exactly that socket, and the running tunnel's port
// is not the one declared: the old tunnel is stopped in between, and its port would be free for
// anyone until the new device bound it again.
func TestARenewalDeclaresTheSocketItsFreshTunnelBinds(t *testing.T) {
	rec := recordHolds(t)
	h := newRenewHarness(t)
	keys := newConnectKeys(mintWG(t), nil, true)
	keys.setLive(fixedPort(40406)) // the tunnel that is about to be replaced
	r := h.sup.renew
	r.keys = keys
	var declared []int
	r.register = func(_ context.Context, now time.Time) (*client.Result, string, error) {
		h.registers++
		declared = append(declared, declaredPort(t, renewalArgs(map[string]any{}, keys, renewAddr, now)))
		return h.res, "scout", h.regErr
	}
	var took []*wgtun.ListenHold
	inner := r.bringUp
	r.bringUp = func(cx context.Context, res *client.Result, name string, port int) (*egressSession, error) {
		took = append(took, keys.takeHold()) // what bringUpWireGuard hands wgtun.Start
		return inner(cx, res, name, port)
	}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	holds := rec.all()
	if len(holds) != 1 || len(declared) != 1 || len(took) != 1 {
		t.Fatalf("holds %d, declarations %v, bring-ups %d", len(holds), declared, len(took))
	}
	if took[0] != holds[0] || declared[0] != holds[0].Port() || declared[0] == 40406 {
		t.Fatalf("declared %d, held %d, the bring-up took the declared socket: %v", declared[0], holds[0].Port(), took[0] == holds[0])
	}
	if keys.hold != nil {
		t.Fatal("a socket was left pending after the bring-up took one")
	}
}

// TestAFailedRenewalConnectLetsItsSocketGo: no bring-up follows a refused renewal, so its socket
// is closed, and the next try opens a new one.
func TestAFailedRenewalConnectLetsItsSocketGo(t *testing.T) {
	rec := recordHolds(t)
	h := newRenewHarness(t)
	keys := newConnectKeys(mintWG(t), nil, true)
	h.sup.renew.keys = keys
	h.regErr = &client.ProblemError{Status: 503, Detail: "not now"}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	holds := rec.all()
	if h.registers != 1 || len(holds) != 1 {
		t.Fatalf("registers %d, holds %d", h.registers, len(holds))
	}
	if holds[0].Port() != 0 || keys.hold != nil {
		t.Fatalf("a refused renewal left port %d held", holds[0].Port())
	}
}

// TestACheckInDeclaresTheRunningTunnelsPortAndHoldsNothing: a check-in that leaves the tunnel in
// place declares the port that tunnel holds now, and opens no socket of its own. Driven through
// the supervisor, so a check-in that started holding a socket would be caught here.
func TestACheckInDeclaresTheRunningTunnelsPortAndHoldsNothing(t *testing.T) {
	rec := recordHolds(t)
	h := newRenewHarness(t)
	h.res = wgAnswer("198.51.100.7:51820", "c2VydmVy")
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	keys := newConnectKeys(mintWG(t), nil, true)
	keys.setLive(fixedPort(40407))
	h.sup.renew.keys = keys
	var declared []int
	h.sup.renew.register = func(_ context.Context, now time.Time) (*client.Result, string, error) {
		h.registers++
		declared = append(declared, declaredPort(t, renewalArgs(map[string]any{}, keys, renewAddr, now)))
		return h.res, "scout", nil
	}
	h.advance(5 * time.Second)
	h.advance(checkInEvery)
	if h.registers != 1 || len(h.bringUps) != 0 {
		t.Fatalf("one check-in that leaves the tunnel alone: %d registers, %d bring-ups", h.registers, len(h.bringUps))
	}
	if declared[0] != 40407 {
		t.Fatalf("the check-in declared %d, the running tunnel holds 40407", declared[0])
	}
	if len(rec.all()) != 0 {
		t.Fatal("a check-in opened a socket")
	}
}

// TestTheDaemonDeclaresAHeldPortOnEveryAttempt: each daemon attempt declares a socket it holds,
// and an attempt that ends before a bring-up lets its socket go, so a retry never resends a port
// that nothing holds.
func TestTheDaemonDeclaresAHeldPortOnEveryAttempt(t *testing.T) {
	rec := recordHolds(t)
	var seen []recordedCall
	srv := autoTierServer(t, &seen, `{"ok":false,"status":503,"error":"busy"}`, s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	keys := newConnectKeys(mintWG(t), nil, true)
	args := map[string]any{"tier": "wireguard"}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := daemonConnectAttempt(c, projcfg.Config{}, keys, args); err == nil {
			t.Fatal("a refused attempt succeeded")
		}
		holds := rec.all()
		if len(holds) != attempt {
			t.Fatalf("attempt %d: %d sockets opened", attempt, len(holds))
		}
		last := holds[attempt-1]
		if want := fmt.Sprintf("192.0.2.11:%d", declaredPort(t, args)); !strings.Contains(seen[len(seen)-1].body, want) {
			t.Fatalf("attempt %d did not send its declaration: %s", attempt, seen[len(seen)-1].body)
		}
		if last.Port() != 0 || keys.hold != nil {
			t.Fatalf("attempt %d left its socket held after the refusal", attempt)
		}
	}
}

// TestWhaleServeDeclaresAHeldPort: `whale serve` brings up its own tunnel through the same keys.
func TestWhaleServeDeclaresAHeldPort(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	rec := recordHolds(t)
	var seen []recordedCall
	srv := autoTierServer(t, &seen, `{"ok":false,"status":503,"error":"busy"}`, s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	if _, _, err := whaleServeConnect(context.Background(), c, ""); err == nil {
		t.Fatal("a refused serve connect succeeded")
	}
	holds := rec.all()
	if len(holds) != 1 {
		t.Fatalf("%d sockets opened, want 1", len(holds))
	}
	if !strings.Contains(seen[len(seen)-1].body, "192.0.2.11:") {
		t.Fatalf("the serve's connect declared nothing: %s", seen[len(seen)-1].body)
	}
	if holds[0].Port() != 0 {
		t.Fatal("the refused serve left its socket held")
	}
}

// TestAHostWithNothingToDeclareHoldsNothing: with no private address there is no endpoint to
// declare, so the socket is let go at once and the device opens its own, with nothing in between.
func TestAHostWithNothingToDeclareHoldsNothing(t *testing.T) {
	rec := recordHolds(t)
	underlayEndpoints = func(int) []string { return nil }
	keys := newConnectKeys(mintWG(t), nil, true)
	keys.holdUnderlay()
	holds := rec.all()
	if len(holds) != 1 || keys.hold != nil || holds[0].Port() != 0 {
		t.Fatalf("a host with nothing to declare kept a socket: %d opened, pending %v", len(holds), keys.hold != nil)
	}
	args := map[string]any{}
	keys.declareUnderlay(args)
	if _, ok := args["endpoints"]; ok {
		t.Fatal("declared an underlay with no address to declare")
	}
	// While that bring-up is pending, the running tunnel's port is not the coming tunnel's, so it
	// is not declared either, even if an address turns up between the hold and the declaration.
	keys.setLive(fixedPort(40409))
	underlayEndpoints = func(port int) []string { return []string{fmt.Sprintf("192.0.2.11:%d", port)} }
	keys.declareUnderlay(args)
	if _, ok := args["endpoints"]; ok {
		t.Fatalf("a pending bring-up with no socket declared %v", args["endpoints"])
	}
	// Once it is over (taken or let go), a check-in declares the running tunnel's port again.
	keys.releaseHold()
	keys.declareUnderlay(args)
	if got := declaredPort(t, args); got != 40409 {
		t.Fatalf("a check-in after the bring-up declared %d, the tunnel holds 40409", got)
	}
}

// TestAnAttemptLetsGoOfASocketItsBringUpNeverTook: connectTierAttempt is the interactive and AUTO
// path. A bring-up that never reaches the tunnel (an answer that is not a tunnel, a config the
// device cannot use, the stubbed tail here) must not leave the declared socket open for the life
// of the process.
func TestAnAttemptLetsGoOfASocketItsBringUpNeverTook(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	rec := recordHolds(t)
	srv := autoTierServer(t, nil, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	saved := connectAndVerify
	defer func() { connectAndVerify = saved }()
	var sawHeld int
	connectAndVerify = func(_ context.Context, _ *client.Client, _ *client.Result, _ string, keys *connectKeys) (*egressSession, error) {
		if keys != nil && keys.hold != nil {
			sawHeld = keys.hold.Port()
		}
		return &egressSession{tier: "wireguard", addr: "2a04:2a01:9::abcd"}, nil
	}
	if _, err := connectTierAttempt(context.Background(), c, map[string]any{}, tierWireGuard, "", 0); err != nil {
		t.Fatal(err)
	}
	holds := rec.all()
	if len(holds) != 1 || sawHeld == 0 {
		t.Fatalf("the bring-up was not reached with the declared socket pending: %d holds, saw port %d", len(holds), sawHeld)
	}
	if holds[0].Port() != 0 {
		t.Fatalf("an attempt whose bring-up never took its socket left port %d open", holds[0].Port())
	}
}

// TestAFallbackOnTier1RenewsWithItsOwnKeys: a renewal whose Tier 1 bring-up fails negotiates again,
// and may land on Tier 1 with keys of its own. The renewer then speaks for those keys: a check-in
// with the replaced tunnel's WireGuard key would put back a peer no tunnel holds.
func TestAFallbackOnTier1RenewsWithItsOwnKeys(t *testing.T) {
	h := newRenewHarness(t)
	k1 := newConnectKeys(mintWG(t), nil, true)
	k2 := newConnectKeys(mintWG(t), nil, true)
	h.sup.renew.keys = k1
	h.upErr = errors.New("the WireGuard peer did not answer")
	h.sup.renew.fallback = func(context.Context, int) (*egressSession, error) {
		ft := &fakeTunnel{healthy: true, endpoint: renewEP}
		return &egressSession{endpoint: renewEP, addr: renewAddr, tier: "wireguard", verified: true, local: ft, keys: k2}, nil
	}
	h.first.set(false, true)
	h.advance(5 * time.Second)
	if h.sup.current() == nil || h.sup.current().keys != k2 {
		t.Fatal("the fallback session was not adopted")
	}
	if h.sup.renew.keys != k2 {
		t.Fatal("the renewer still speaks for the replaced tunnel's keys")
	}

	// And the renewer's own connect reads its keys at the time of the call.
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper_live_test",
		Source: client.SourceFlag}, Timeout: 5 * time.Second})
	r := renewerFor(c, map[string]any{}, &egressSession{addr: renewAddr, endpoint: renewEP, keys: k1}, false, "")
	r.keys = k2
	if _, _, err := r.register(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	body := seen[len(seen)-1].body
	if !strings.Contains(body, k2.wg.PublicKeyBase64) || strings.Contains(body, k1.wg.PublicKeyBase64) {
		t.Fatal("the renewal connect did not name the WireGuard key the renewer now holds")
	}
}

// TestARebindBringsTheCheckInForwardOnce: a tunnel that re-opened its socket (the network moved)
// says where it can be dialed as soon as it is healthy again, not six hours later, and a network
// that keeps moving does not turn that into a check-in on every look.
func TestARebindBringsTheCheckInForwardOnce(t *testing.T) {
	h := newRenewHarness(t)
	h.res = wgAnswer("198.51.100.7:51820", "c2VydmVy")
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	h.advance(5 * time.Second) // schedules the first check-in six hours out
	bump := func() { h.first.mu.Lock(); h.first.rebinds++; h.first.mu.Unlock() }
	bump()
	h.advance(5 * time.Second)
	if h.registers != 1 || len(h.bringUps) != 0 {
		t.Fatalf("a rebind did not bring the check-in forward: %d registers, %d bring-ups", h.registers, len(h.bringUps))
	}
	bump()
	h.advance(time.Minute)
	if h.registers != 1 {
		t.Fatalf("a second rebind within %s checked in again: %d registers", redeclareEvery, h.registers)
	}
	h.advance(redeclareEvery)
	if h.registers != 2 {
		t.Fatalf("the rebind held back by the limit was never declared: %d registers", h.registers)
	}
	h.advance(5 * time.Second)
	h.advance(time.Hour)
	if h.registers != 2 {
		t.Fatalf("with no further rebind the check-ins went back to six-hourly: %d registers", h.registers)
	}
	// A redeclaration that fails, likely just after a move, is tried again after the limit rather
	// than left to the six-hourly check-in, and stops once one goes through.
	h.regErr = &client.ProblemError{Status: 503, Detail: "not yet"}
	bump()
	h.advance(5 * time.Second)
	if h.registers != 3 {
		t.Fatalf("the third rebind was not declared: %d registers", h.registers)
	}
	h.regErr = nil
	h.advance(redeclareEvery)
	if h.registers != 4 {
		t.Fatalf("a failed redeclaration waited for the six-hourly check-in: %d registers", h.registers)
	}
	h.advance(redeclareEvery)
	h.advance(time.Hour)
	if h.registers != 4 {
		t.Fatalf("a redeclaration that went through was made again: %d registers", h.registers)
	}
}

// TestAFreshTunnelIsNotARebind: a renewal brings up a tunnel that counts its own socket re-opens
// from zero, and its connect has just declared where it can be dialed, so nothing is brought
// forward on its account.
func TestAFreshTunnelIsNotARebind(t *testing.T) {
	h := newRenewHarness(t)
	h.res = wgAnswer("198.51.100.7:51820", "c2VydmVy")
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	h.first.mu.Lock()
	h.first.rebinds = 3
	h.first.mu.Unlock()
	h.first.set(false, true)
	h.advance(5 * time.Second) // the stalled tunnel's re-opens are seen, and it is replaced
	if h.registers != 1 || len(h.built) != 1 {
		t.Fatalf("the stalled tunnel was not replaced: %d registers, %d built", h.registers, len(h.built))
	}
	h.sup.sess.peer = wgPeerOf(connectEnvelope{wgEndpoint: "198.51.100.7:51820", wgServerPubKey: "c2VydmVy"})
	for i := 0; i < 3; i++ {
		h.advance(5 * time.Second)
	}
	if h.registers != 1 {
		t.Fatalf("the fresh tunnel was counted as a rebind: %d registers", h.registers)
	}
}
