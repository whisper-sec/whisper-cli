// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// run_enforce_hold_test.go covers an enforced run asking for its peer to be held exclusive,
// checking it was, and letting it go when it ends.

const heldAddr = "2a04:2a01:9::abcd"

// wgConnectReplyWithExclusive is wgConnectReplyJSON with the box's exclusive column appended last,
// as the box sends it.
func wgConnectReplyWithExclusive(v string) string {
	r := wgConnectReplyJSON()
	r = strings.Replace(r, `"nat64_prefix"]`, `"nat64_prefix","exclusive"]`, 1)
	r = strings.Replace(r, `"note"],`, `"note","exclusive"],`, 1)
	return strings.Replace(r, `"Tier-1 routed WireGuard"]]`, `"Tier-1 routed WireGuard",`+v+`]]`, 1)
}

func jsonReply(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func codedProblemReply(status int, code, detail string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"ok":false,"status":%d,"error":{"code":%q,"message":%q,"retryable":false}}`, status, code, detail)
	}
}

const disconnectReply = `{"ok":true,"status":200,"result":{"columns":["agent","status","address","wg_peers_removed","egress_tokens_revoked"],` +
	`"rows":[["2a04:2a01:9::abcd","disconnected","2a04:2a01:9::abcd",1,0]]}}`

// lineLog collects what the hold logs.
type lineLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *lineLog) logf(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
}

func (l *lineLog) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *lineLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

func TestTheEnforcedConnectAsksForAnExclusivePeer(t *testing.T) {
	for _, sel := range []string{"", heldAddr, "scout"} {
		base := enforcedConnectBase(sel)
		if base["exclusive"] != true {
			t.Fatalf("sel %q: the enforced connect does not ask for exclusive: %v", sel, base)
		}
		got, named := base["agent"]
		if (sel != "") != named || (named && got != sel) {
			t.Fatalf("sel %q: agent = %v (named %v)", sel, got, named)
		}
		if q := client.BuildAgentsQuery("connect", base); !strings.Contains(q, "exclusive:true") {
			t.Fatalf("sel %q: the query does not carry exclusive:true: %s", sel, q)
		}
	}
}

func TestTheExclusiveColumnIsReadNotAssumed(t *testing.T) {
	for reply, want := range map[string]bool{
		wgConnectReplyWithExclusive("true"):    true,
		wgConnectReplyWithExclusive(`"true"`):  true,
		wgConnectReplyWithExclusive("false"):   false,
		wgConnectReplyWithExclusive(`"false"`): false,
		wgConnectReplyWithExclusive("null"):    false,
		wgConnectReplyJSON():                   false, // a box built before  has no column at all
	} {
		var env client.Envelope
		if err := json.Unmarshal([]byte(reply), &env); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		if got := exclusiveGranted(env.Result); got != want {
			t.Fatalf("exclusiveGranted = %v, want %v for %s", got, want, reply)
		}
	}
	if exclusiveGranted(nil) {
		t.Fatal("no result is not a grant")
	}
}

// The renewal carries exclusive:true too: by the time a dead tunnel renews, the box's reaper may
// have retired the peer and its mark with it, so the renewal has to ask again.
func TestAnEnforcedRenewalAsksForExclusiveAgain(t *testing.T) {
	srv, queries := renewServer(t, jsonReply(wgConnectReplyWithExclusive("true")))
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, nil)
	if _, err := h.renew(); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if q := queries(); len(q) != 1 || !strings.Contains(q[0], "exclusive:true") {
		t.Fatalf("the renewal did not ask for exclusive: %q", q)
	}
}

// grantedHold is a hold whose connect the box answered with the exclusive mark.
func grantedHold(t *testing.T, url string, logf func(string, ...any)) *enforcedHold {
	t.Helper()
	h := newEnforcedHold(testClient(t, url), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, logf)
	var env client.Envelope
	if err := json.Unmarshal([]byte(wgConnectReplyWithExclusive("true")), &env); err != nil {
		t.Fatal(err)
	}
	if !h.noteGrant(env.Result) {
		t.Fatal("fixture: the grant did not register")
	}
	return h
}

func TestTheRunDisconnectsItsAgentOnceWhenItEnds(t *testing.T) {
	srv, queries := renewServer(t, jsonReply(disconnectReply))
	var log lineLog
	h := grantedHold(t, srv.URL, log.logf)
	stops := 0
	h.release(func() { stops++ })
	h.release(func() { stops++ }) // the deferred call after the explicit one on the way to os.Exit
	if stops != 1 {
		t.Fatalf("the tunnel was stopped %d times", stops)
	}
	q := queries()
	if len(q) != 1 {
		t.Fatalf("want one disconnect, got %d: %q", len(q), q)
	}
	if !strings.Contains(q[0], "op:'disconnect'") || !strings.Contains(q[0], "agent:'"+heldAddr+"'") {
		t.Fatalf("the disconnect does not name the held /128: %s", q[0])
	}
	if got := log.all(); !strings.Contains(got, "disconnected "+heldAddr) {
		t.Fatalf("the disconnect is not reported: %q", got)
	}
}

func TestAFailedDisconnectSaysTheMarkOutlivesTheRun(t *testing.T) {
	srv, _ := renewServer(t, problemReply(503, "busy"))
	var log lineLog
	h := grantedHold(t, srv.URL, log.logf)
	h.release(nil)
	if got := log.all(); !strings.Contains(got, "could not disconnect") || !strings.Contains(got, "3 minutes") {
		t.Fatalf("a failed disconnect is not reported with its consequence: %q", got)
	}
}

// Once the box has said another enforced run holds the /128, this run's disconnect would tear
// down that run's peer, so it does not send one. A later renewal that wins the /128 back undoes it.
func TestARunReplacedByAnotherExclusiveHolderDoesNotDisconnectIt(t *testing.T) {
	srv, queries := renewServer(t,
		codedProblemReply(409, "WG_PEER_EXCLUSIVE", heldAddr+" is held exclusively by an enforced run"),
		jsonReply(disconnectReply))
	var log lineLog
	h := grantedHold(t, srv.URL, log.logf)
	if _, err := h.renew(); !errors.Is(err, enforce.ErrRenewRefused) {
		t.Fatalf("WG_PEER_EXCLUSIVE is a refusal: %v", err)
	}
	h.release(nil)
	if q := queries(); len(q) != 1 {
		t.Fatalf("a replaced run disconnected the new holder: %q", q)
	}
	if got := log.all(); !strings.Contains(got, "not disconnecting") {
		t.Fatalf("the skipped disconnect is not explained: %q", got)
	}

	srv2, queries2 := renewServer(t,
		codedProblemReply(409, "WG_PEER_EXCLUSIVE", heldAddr+" is held exclusively by an enforced run"),
		jsonReply(wgConnectReplyWithExclusive("true")),
		jsonReply(disconnectReply))
	h2 := grantedHold(t, srv2.URL, nil)
	_, _ = h2.renew()
	if _, err := h2.renew(); err != nil {
		t.Fatalf("second renewal: %v", err)
	}
	h2.release(nil)
	if q := queries2(); len(q) != 3 || !strings.Contains(q[2], "op:'disconnect'") {
		t.Fatalf("a run that won its /128 back did not let it go: %q", q)
	}
}

// Without the mark there is nothing to let go, and a disconnect could only take down a peer that
// replaced this run's legitimately.
func TestARunTheBoxNeverMarkedExclusiveSendsNoDisconnect(t *testing.T) {
	srv, queries := renewServer(t, jsonReply(wgConnectReplyJSON()), jsonReply(disconnectReply))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log.logf)
	var env client.Envelope
	_ = json.Unmarshal([]byte(wgConnectReplyJSON()), &env)
	if h.noteGrant(env.Result) {
		t.Fatal("an answer with no exclusive column granted the mark")
	}
	if _, err := h.renew(); err != nil { // a renewal answered without the mark does not grant it either
		t.Fatalf("renewal: %v", err)
	}
	stopped := false
	h.release(func() { stopped = true })
	if q := queries(); len(q) != 1 || strings.Contains(q[0], "disconnect") {
		t.Fatalf("an unmarked run sent a disconnect: %q", q)
	}
	if !stopped || !strings.Contains(log.all(), "never marked") {
		t.Fatalf("stopped=%v, log %q", stopped, log.all())
	}
}

// A renewal that lost the mark, then got it back, ends granted: the last answer is what counts.
func TestTheGrantFollowsTheLatestAnswer(t *testing.T) {
	srv, _ := renewServer(t, jsonReply(wgConnectReplyJSON()), jsonReply(wgConnectReplyWithExclusive("true")))
	h := grantedHold(t, srv.URL, nil)
	_, _ = h.renew()
	if h.granted.Load() {
		t.Fatal("a renewal answered without the mark left the hold granted")
	}
	_, _ = h.renew()
	if !h.granted.Load() {
		t.Fatal("a renewal answered with the mark left the hold ungranted")
	}
}

// After the agent has run, the disconnect waits on proof through the tunnel that the box still
// routes the /128 to this run, and that proof is taken BEFORE the tunnel goes.
func TestTheDisconnectAfterARunNeedsTheTunnelToConfirmThePeer(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		srv, queries := renewServer(t, jsonReply(disconnectReply))
		var log lineLog
		h := grantedHold(t, srv.URL, log.logf)
		var order []string
		h.confirm = func() bool { order = append(order, "confirm"); return confirmed }
		h.release(func() { order = append(order, "stop") })
		if strings.Join(order, ",") != "confirm,stop" {
			t.Fatalf("confirmed=%v: order %v, want the probe before the tunnel stops", confirmed, order)
		}
		sent := len(queries()) == 1
		if sent != confirmed {
			t.Fatalf("confirmed=%v: disconnect sent=%v", confirmed, sent)
		}
		if !confirmed && !strings.Contains(log.all(), "could not confirm") {
			t.Fatalf("the skipped disconnect is not explained: %q", log.all())
		}
	}
}

// A hold that never learnt its /128 has nothing to name.
func TestAHoldWithNoAddressSendsNoDisconnect(t *testing.T) {
	srv, queries := renewServer(t, jsonReply(disconnectReply))
	h := grantedHold(t, srv.URL, nil)
	h.addr = ""
	h.release(nil)
	if q := queries(); len(q) != 0 {
		t.Fatalf("a disconnect with no /128 went out: %q", q)
	}
}

func TestTheExclusiveRefusalIsRecognisedThroughAProxyThatFoldsTheCode(t *testing.T) {
	for _, pe := range []*client.ProblemError{
		{Status: 409, Title: "WG_PEER_EXCLUSIVE", Detail: "held"},
		{Status: 409, Detail: heldAddr + " is held exclusively by an enforced run (whisper run --enforce)"},
		{Status: 500, Detail: "CypherException: WG_PEER_EXCLUSIVE: " + heldAddr},
	} {
		if !wgPeerExclusiveRefusal(pe) {
			t.Fatalf("not recognised: %+v", pe)
		}
	}
	for _, pe := range []*client.ProblemError{
		{Status: 409, Title: "IDENTITY_KEY_PINNED", Detail: "pinned to a different identity key"},
		{Status: 403, Detail: "held exclusively by an enforced run"},
	} {
		if wgPeerExclusiveRefusal(pe) {
			t.Fatalf("recognised wrongly: %+v", pe)
		}
	}
	if wgPeerExclusiveRefusal(errors.New("WG_PEER_EXCLUSIVE")) {
		t.Fatal("a plain error is not the box's answer")
	}
}

// Stopping the tunnel waits out a renewal in flight, and what that renewal learnt counts: a box
// that refused it because another enforced run holds the /128 is not then disconnected.
func TestTheFlagsAreReadAfterTheTunnelStops(t *testing.T) {
	srv, queries := renewServer(t, jsonReply(disconnectReply))
	h := grantedHold(t, srv.URL, nil)
	h.confirm = func() bool { return true }
	h.release(func() { h.replaced.Store(true) }) // the in-flight renewal, refused as the tunnel stopped
	if q := queries(); len(q) != 0 {
		t.Fatalf("a run replaced during the stop disconnected the new holder: %q", q)
	}
}
