// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// Measured live on 2026-11-05: `whisper whale serve 3949 --agent <a fresh agent>` on a host
// that did not hold the agent's identity key printed "Whisper is busy right now - please try again
// in a moment", three times running. Nothing was busy. The in-tunnel listener had not started,
// because the leaf it presents must be signed by the key the TLSA pins, and the serve's own 503
// said so - but the renderer turns every 503 into the busy line, so the one sentence that named
// the cause was the one the user never saw.

// TestAServeOnAHostWithoutTheIdentityKeySaysHowToBecomeTheHolder drives the REAL command with the
// listener down and asserts what a person reads: the adopt that fixes it, for the agent they named
// (as they typed it, not the address it resolved to),
// and the consequence of running it. Not "busy".
func TestAServeOnAHostWithoutTheIdentityKeySaysHowToBecomeTheHolder(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin ok")
	}))
	defer origin.Close()
	control := guidedTestServer(t, []agentChoice{{name: "db-01", addr: "2a04:2a01:9::abcd"}}, nil)
	defer control.Close()
	migrateGlobals(t, control.URL)

	var handler http.Handler
	restore := stubServeSeams(t, &handler, nil)
	defer restore()
	whaleServeListenerUp = func(*wgtun.Tunnel) bool { return false }
	whaleServeConnect = func(context.Context, *client.Client, string) (*egressSession, *wgtun.Tunnel, error) {
		return &egressSession{addr: "2a04:2a01:9::abcd", tier: "wireguard", pinKeyMissing: true}, &wgtun.Tunnel{}, nil
	}
	holdWhaleServe = func() { t.Fatal("a serve with no listener must not hold") }

	dir := t.TempDir()
	_, _, err := runWhale(t, "whale", "serve", origin.URL, "--agent", "db-01", "--state-dir", dir)
	if err == nil {
		t.Fatal("a serve with no listener must fail")
	}
	got := friendly(err)
	if strings.Contains(strings.ToLower(got), "busy") {
		t.Fatalf("a local refusal rendered as the busy line: %q", got)
	}
	for _, want := range []string{"whisper connect --adopt-key --agent db-01", "re-pins", "does not hold that key",
		"any OTHER host already serving this agent stops matching"} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal does not say %q: %q", want, got)
		}
	}
	if handler != nil {
		t.Error("a handler was installed behind a listener that never started")
	}
	if _, recorded := whale.ReadServeStateRaw(dir); recorded {
		t.Error("a serve that never served left a record behind")
	}
}

// TestTheNoListenerSentenceOnlyOffersAnAdoptWhenTheKeyIsMissing: a host that holds the pinned
// key and still has no listener (a leaf it could not mint, a port it could not bind) must not be
// told to move the agent's identity, which fixes nothing and breaks every other holder's match.
func TestTheNoListenerSentenceOnlyOffersAnAdoptWhenTheKeyIsMissing(t *testing.T) {
	held := whaleServeNoListenerDetail(false, "db-01")
	if strings.Contains(held, "adopt") || !strings.Contains(held, "whisper connect --tier wireguard --agent db-01") {
		t.Fatalf("a key holder was sent to re-pin, or not told how to see the cause: %q", held)
	}
	if got := whaleServeNoListenerDetail(true, ""); !strings.Contains(got, "`whisper connect --adopt-key` once") {
		t.Fatalf("with no selector the fix is the plain adopt: %q", got)
	}
}

// TestTheSelectorInTheSentenceCanAlwaysBePasted: a selector that is not one plain token falls back
// to the address, so the command quoted in the sentence never breaks when pasted.
func TestTheSelectorInTheSentenceCanAlwaysBePasted(t *testing.T) {
	cases := []struct{ typed, resolved, addr, want string }{
		{"db-01", "agent-a1", "2a04:2a01:9::abcd", "db-01"},
		{"my `node` $(x)", "agent-a1", "2a04:2a01:9::abcd", "agent-a1"},
		{"two words", "also bad", "2a04:2a01:9::abcd", "2a04:2a01:9::abcd"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		if got := pasteableSelector(c.typed, c.resolved, c.addr); got != c.want {
			t.Errorf("pasteableSelector(%q,%q,%q) = %q, want %q", c.typed, c.resolved, c.addr, got, c.want)
		}
	}
}

// TestLocalProblemsKeepTheirSentenceAtEveryStatus pins the renderer: a problem this CLI built
// itself reaches the user verbatim at any status, and a SERVER 503 still reads as busy (the
// control, so this cannot pass by deleting the busy line).
func TestLocalProblemsKeepTheirSentenceAtEveryStatus(t *testing.T) {
	local := []*client.ProblemError{
		{Status: 503, Type: localActionable, Title: "no listener", Detail: whaleServeNoListenerDetail(true, "db-01")},
		{Status: 503, Type: localActionable, Title: "no routed tunnel", Detail: "this connection did not land on the routed WireGuard tier"},
		{Status: 503, Type: localActionable, Title: "fleet unknown", Detail: "could not read your fleet"},
		{Status: 503, Type: localActionable, Title: "cannot refresh the fleet set", Detail: "your roster could not be read"},
		{Status: 404, Type: localActionable, Detail: "no agent named here; pass --agent"},
	}
	for _, pe := range local {
		if got := friendly(pe); got != pe.Error() {
			t.Errorf("%q: the local sentence was replaced with %q", pe.Title, got)
		}
	}
	server := &client.ProblemError{Status: 503, Title: "Service Unavailable", Detail: "upstream overloaded"}
	if got := friendly(server); !strings.Contains(got, "busy") {
		t.Errorf("control: a server 503 should still read as busy, got %q", got)
	}
}
