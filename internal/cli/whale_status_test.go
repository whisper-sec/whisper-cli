// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_status_test.go covers the verb people run fifty times a day, and in particular
// the two ways its output could lie: a PATH cell claiming a path this build cannot
// carry, and a fleet section that renders a failure as an empty table.

// whaleTestIsolation points the key ladder and the session registry at empty temp state,
// so a developer's real key and real held sessions cannot change what these tests see.
func whaleTestIsolation(t *testing.T) {
	t.Helper()
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	dir := t.TempDir()
	prevSessions := sessionsDirFn
	sessionsDirFn = func() string { return dir + "/sessions" }
	prevG := g
	g = globalFlags{keyFile: dir + "/no-such-key", timeout: 2 * time.Second}
	t.Cleanup(func() {
		sessionsDirFn = prevSessions
		g = prevG
	})
}

// TestWhaleStatus_KeylessAnswersAndSaysWhatIsMissing: an identity question is never an
// error, and the fleet half being absent must be stated, not left as a blank screen.
func TestWhaleStatus_KeylessAnswersAndSaysWhatIsMissing(t *testing.T) {
	whaleTestIsolation(t)
	view := buildWhaleStatus(context.Background(), g.keyFile, true, false)
	if view.Self.Host == "" {
		t.Fatal("the node block came back with no host")
	}
	if view.Self.KeyPresent {
		t.Fatal("a key was found although the ladder was pointed at nothing")
	}
	if len(view.Peers) != 0 {
		t.Fatal("peers were listed with no key")
	}
	if len(view.Notes) == 0 || !strings.Contains(strings.Join(view.Notes, " "), "whisper login") {
		t.Fatalf("notes %v do not say why the fleet is missing", view.Notes)
	}
}

// TestWhaleStatus_AnUnreachableControlPlaneIsANoteNotAnEmptyFleet is the "errors that
// render as empty" guard: with a key present and the control plane dark, the peer table
// must not silently read as "you have no agents".
func TestWhaleStatus_AnUnreachableControlPlaneIsANoteNotAnEmptyFleet(t *testing.T) {
	whaleTestIsolation(t)
	g.key = "whisper_live_not-a-real-key"
	g.controlURL = "http://127.0.0.1:1/api/query" // refused instantly, never dialled anywhere real
	view := buildWhaleStatus(context.Background(), g.keyFile, true, false)
	if !view.Self.KeyPresent {
		t.Fatal("the key set on the flag was not seen")
	}
	if len(view.Peers) != 0 {
		t.Fatal("peers were listed from a control plane that refused the connection")
	}
	joined := strings.Join(view.Notes, " ")
	if !strings.Contains(joined, "could not reach the control plane") {
		t.Fatalf("notes %q do not say the control plane was unreachable; a zero with no reason "+
			"reads as an empty fleet", joined)
	}
}

// TestWhaleStatus_PathColumnRendersExactlyWhatTheEvidenceSaid walks the RENDERING, not the
// helper, so it fails if a renderer ever writes a path word of its own instead of printing
// what whale.PathFor returned.
//
// It used to assert that the word `direct` could never appear at all, which was right while
// no direct path existed and is wrong now that two of these three rows legitimately have
// one. The property that survives - and the one that was always the point - is that the cell
// equals the verdict: a peer with no evidence renders `relayed`, a measured silence renders
// `no path`, and the direct word appears ONLY on the row whose Observation carried evidence
// for it. A renderer that decided for itself would fail one of the three.
func TestWhaleStatus_PathColumnRendersExactlyWhatTheEvidenceSaid(t *testing.T) {
	whaleTestIsolation(t)
	view := whaleStatusView{
		Self:     whaleSelf{Host: "h", Address: "2a04:2a01:1::1", Connection: "connected"},
		PathNote: whale.PathNote(),
		Peers: []whaleStatusPeer{
			{whalePeer: whalePeer{Name: "a", Address: "2a04:2a01:1::2", State: "active"},
				Path: whale.PathFor(whale.Observation{})},
			{whalePeer: whalePeer{Name: "b", Address: "2a04:2a01:1::3", State: "active"},
				Path: whale.PathFor(whale.Observation{Measured: true, Reachable: false})},
			{whalePeer: whalePeer{Name: "c", Address: "2a04:2a01:1::4", State: "active"},
				Path: whale.PathFor(whale.Observation{Measured: true, Reachable: true, Direct: true}), RTTMs: 24.1},
		},
	}
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, true) })
	_ = stderr
	// Row by row: the cell is the verdict, and the peer with NO evidence must not have been
	// upgraded by the renderer on its way to the screen.
	for _, want := range []struct{ peer, path string }{
		{"a", whale.PathRelayed},
		{"b", whale.PathNoPath},
		{"c", "direct"},
	} {
		if !strings.Contains(stdout, want.peer+"  ") && !strings.Contains(stdout, want.peer+" ") {
			t.Fatalf("peer %q is missing from the table:\n%s", want.peer, stdout)
		}
		line := ""
		for _, l := range strings.Split(stdout, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), want.peer+" ") {
				line = l
				break
			}
		}
		if line == "" {
			t.Fatalf("no row for peer %q:\n%s", want.peer, stdout)
		}
		if !strings.Contains(line, want.path) {
			t.Fatalf("peer %q rendered %q, want the cell %q that PathFor returned:\n%s",
				want.peer, strings.TrimSpace(line), want.path, stdout)
		}
	}
	// The row with no evidence at all must never have acquired a direct word.
	for _, l := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "a ") && strings.Contains(l, "direct") {
			t.Fatalf("a peer with no evidence rendered a direct path:\n%s", stdout)
		}
	}
	if !strings.Contains(stdout, whale.PathRelayed) {
		t.Fatalf("no relayed path was rendered:\n%s", stdout)
	}
	if !strings.Contains(stdout, whale.PathNoPath) {
		t.Fatalf("a peer that answered nothing did not render as %q:\n%s", whale.PathNoPath, stdout)
	}
	if !strings.Contains(stdout, "24.1 ms") {
		t.Fatalf("a measured round trip was not rendered:\n%s", stdout)
	}
}

// TestWhaleStatus_UnmeasuredPeersShowNoRTT: the RTT column is a measurement, so it stays
// empty until something measured it. A zero would read as an instant link.
func TestWhaleStatus_UnmeasuredPeersShowNoRTT(t *testing.T) {
	whaleTestIsolation(t)
	view := whaleStatusView{
		Self:     whaleSelf{Host: "h", Connection: "not connected"},
		PathNote: whale.PathNote(),
		Peers: []whaleStatusPeer{{whalePeer: whalePeer{Name: "a", Address: "2a04:2a01:1::2"},
			Path: whale.PathFor(whale.Observation{})}},
	}
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	if strings.Contains(stdout, " 0.0 ms") || strings.Contains(stdout, "0 ms") {
		t.Fatalf("an unmeasured peer rendered a round trip:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Nothing here is measured") {
		t.Fatalf("the unmeasured table did not carry the footnote that says so:\n%s", stderr)
	}
}

// TestWhaleStatus_NeverPrintsAKeyValue. The key state is shown; the key never is.
func TestWhaleStatus_NeverPrintsAKeyValue(t *testing.T) {
	whaleTestIsolation(t)
	const secret = "whisper_live_thisvaluemustnotappear"
	g.key = secret
	g.controlURL = "http://127.0.0.1:1/api/query"
	view := buildWhaleStatus(context.Background(), g.keyFile, true, false)
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	if strings.Contains(stdout+stderr, secret) {
		t.Fatal("the key value was printed")
	}
	if !strings.Contains(stdout, "set (") {
		t.Fatalf("the key state was not shown at all:\n%s", stdout)
	}
}

// TestTenantOfFQDN_OnlyClaimsWhatTheNameCarries.
func TestTenantOfFQDN_OnlyClaimsWhatTheNameCarries(t *testing.T) {
	cases := map[string]string{
		"db-01.t9f0a.agents.whisper.online":  "t9f0a",
		"db-01.t9f0a.agents.whisper.online.": "t9f0a",
		"db-01":                              "",
		"":                                   "",
	}
	for in, want := range cases {
		if got := tenantOfFQDN(in); got != want {
			t.Fatalf("tenantOfFQDN(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMatchPeer_AcceptsEverySpellingOfTheSamePeer.
func TestMatchPeer_AcceptsEverySpellingOfTheSamePeer(t *testing.T) {
	peers := []whalePeer{{
		Name:    "agent-abc",
		Label:   "db-01",
		Address: "2a04:2a01:1::2",
		FQDN:    "abc.t9f.agents.whisper.online",
	}}
	for _, in := range []string{
		"agent-abc", "AGENT-ABC", "db-01", "2a04:2a01:1::2",
		"abc.t9f.agents.whisper.online", "abc.t9f.agents.whisper.online.",
	} {
		if _, ok := matchPeer(peers, in); !ok {
			t.Fatalf("matchPeer did not match %q", in)
		}
	}
	if _, ok := matchPeer(peers, "somebody-else"); ok {
		t.Fatal("matchPeer matched a name that is not in the fleet")
	}
}
