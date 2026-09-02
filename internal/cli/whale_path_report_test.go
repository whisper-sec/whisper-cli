// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// whale_path_report_test.go covers the two halves of the report chain on the command layer: the
// candidate endpoints a peer row can carry, and the published record the surfaces read.

// ==========================================================================================
// The row parse. It has to accept what a NEWER control plane sends without a coordinated
// release, and keep working against an OLDER one that sends a single endpoint.
// ==========================================================================================

func TestCandidatesFromRow_ReadsTheSingleEndpointForm(t *testing.T) {
	got := candidatesFromRow(map[string]any{"endpoint": "192.168.1.5:51820"}, "direct-local")
	if len(got) != 1 {
		t.Fatalf("got %+v, want one candidate", got)
	}
	// A same-segment peer's endpoint is classed local, which is what puts it first in the train:
	// if it works it is the cheapest path there is.
	if got[0].Source != wgtun.SourceLocal {
		t.Fatalf("source = %q, want %q from the row's own class", got[0].Source, wgtun.SourceLocal)
	}
}

func TestCandidatesFromRow_ReadsAListOfStringsAndOfObjects(t *testing.T) {
	got := candidatesFromRow(map[string]any{
		"endpoint":  "192.168.1.5:51820",
		"endpoints": []any{"10.0.0.9:51820", map[string]any{"endpoint": "203.0.113.7:41234", "source": "observed"}},
	}, "direct-punch")
	if len(got) != 3 {
		t.Fatalf("got %d candidates, want all three: %+v", len(got), got)
	}
	if got[2].Endpoint != "203.0.113.7:41234" || got[2].Source != wgtun.SourceObserved {
		t.Fatalf("the object form lost its source: %+v", got[2])
	}
}

func TestCandidatesFromRow_ReadsTheObservedEndpointThatMakesAPunchPossible(t *testing.T) {
	// This one is the whole reason the punch needs no STUN server: the box already sees the
	// ip:port every peer's packets arrive from, because every peer holds a tunnel to it.
	got := candidatesFromRow(map[string]any{
		"endpoint":          "192.168.1.5:51820",
		"observed_endpoint": "203.0.113.7:41234",
	}, "direct-punch")
	if len(got) != 2 {
		t.Fatalf("got %+v, want the declared and the observed endpoint", got)
	}
	if got[1].Source != wgtun.SourceObserved {
		t.Fatalf("the observed endpoint was not classed as observed: %+v", got[1])
	}
}

func TestCandidatesFromRow_ARelayedRowOffersNothing(t *testing.T) {
	if got := candidatesFromRow(map[string]any{"address": "2a04:2a01:4::7"}, "relayed"); len(got) != 0 {
		t.Fatalf("a relayed row produced candidates to dial: %+v", got)
	}
}

// TestPeersFromRows_InstallsEveryCandidate is the end of that path: a control-plane row with
// several endpoints becomes ONE peer with several candidates to punch at, and the peer's
// primary endpoint is the best of them.
func TestPeersFromRows_InstallsEveryCandidate(t *testing.T) {
	rows := []map[string]any{
		{"item": map[string]any{"self": true, "state": "ok"}},
		{"item": map[string]any{
			"address":           "2a04:2a01:4::7",
			"name":              "db-01",
			"path":              "direct-punch",
			"public_key":        "YTItcGVlci1rZXktMzItYnl0ZXMtbG9uZy1wYWQhISE=",
			"endpoint":          "198.51.100.9:51820",
			"observed_endpoint": "203.0.113.7:41234",
		}},
	}
	peers := peersFromRows(rows)
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want one: %+v", len(peers), peers)
	}
	if len(peers[0].Candidates) != 2 {
		t.Fatalf("candidates = %+v, want both endpoints", peers[0].Candidates)
	}
	if peers[0].Endpoint != "198.51.100.9:51820" {
		t.Fatalf("the primary endpoint is %q, want the best-ranked candidate", peers[0].Endpoint)
	}
	if peers[0].Path != "direct-punch" {
		t.Fatalf("the class was dropped: %q", peers[0].Path)
	}
}

// ==========================================================================================
// The published record, and the wiring that reads it.
// ==========================================================================================

// pathStateHome points DefaultPathStateDir at a temp home and returns the directory records
// should be written to.
func pathStateHome(t *testing.T) string {
	t.Helper()
	home := testenv.HermeticHome(t)
	return filepath.Join(home, ".config", "whisper", "paths")
}

func writePathRecord(t *testing.T, dir string, rec wgtun.PathStateRecord) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.ReplaceAll(rec.Address, ":", "_") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func directRecord(self, peer, endpoint string) wgtun.PathStateRecord {
	return wgtun.PathStateRecord{
		Address: self, PID: os.Getpid(), Updated: time.Now(),
		Peers: []wgtun.PathPeerRecord{{
			Address: peer, Name: "db-01", Path: "direct-punch", Endpoint: endpoint, Promoted: true,
			Punch: wgtun.PathPunchRecord{
				Phase: string(wgtun.PunchEstablished), Attempts: 3, Candidates: 2,
				Winner: endpoint, WinnerSource: string(wgtun.SourceObserved), Since: time.Now(),
			},
		}},
	}
}

func TestReadPathEvidence_FindsThePeerAndAnswersHonestlyForAnUnknownOne(t *testing.T) {
	dir := pathStateHome(t)
	writePathRecord(t, dir, directRecord("2a04:2a01:4::9", "2a04:2a01:4::7", "203.0.113.7:41234"))

	ev := readPathEvidence("2a04:2a01:4::9")
	got := ev.For("2a04:2a01:4::7")
	if !got.Found || !got.Direct {
		t.Fatalf("the published direct path was not read back: %+v", got)
	}
	if got.Endpoint != "203.0.113.7:41234" {
		t.Fatalf("endpoint = %q", got.Endpoint)
	}
	// A peer nothing published about is not a failure and must not be reported as one.
	if unknown := ev.For("2a04:2a01:4::ff"); unknown.Found || unknown.Direct {
		t.Fatalf("an unpublished peer produced a claim: %+v", unknown)
	}
}

func TestReadPathEvidence_ARecordFromAnotherNodeIsNotReadAsOurs(t *testing.T) {
	dir := pathStateHome(t)
	writePathRecord(t, dir, directRecord("2a04:2a01:4::b", "2a04:2a01:4::7", "203.0.113.7:41234"))
	if got := readPathEvidence("2a04:2a01:4::9").For("2a04:2a01:4::7"); got.Found {
		t.Fatalf("this node read another node's path record as its own: %+v", got)
	}
	// With no self address we merge every tunnel on the host, which is the right answer for a
	// command that just wants to know whether ANY tunnel here has that path.
	if got := readPathEvidence("").For("2a04:2a01:4::7"); !got.Found {
		t.Fatal("a host-wide read missed a record that is right there")
	}
}

// TestWhaleStatus_PathColumnComesFromThePublishedRecord is the wiring test. It runs the REAL
// buildWhaleStatus against a control plane that says nothing about paths, with one record on
// disk that does, and it fails if the read is ever taken out of the status path - which is
// exactly how a feature ends up shipped and unreachable.
func TestWhaleStatus_PathColumnComesFromThePublishedRecord(t *testing.T) {
	whaleTestIsolation(t)
	dir := pathStateHome(t)
	const self = "2a04:2a01:4::9"
	const peer = "2a04:2a01:4::7"
	writePathRecord(t, dir, directRecord(self, peer, "203.0.113.7:41234"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` +
			`["agent",{"label":"me","agent":"ag_me","address":"` + self + `","state":"active"}],` +
			`["agent",{"label":"db-01","agent":"ag_db","address":"` + peer + `","state":"active"}]` +
			`]}}`))
	}))
	t.Cleanup(srv.Close)

	agentFile := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(agentFile, []byte(self), 0o600); err != nil {
		t.Fatal(err)
	}
	g.key = "whisper_live_test"
	g.controlURL = srv.URL + "/api/query"

	view := buildWhaleStatus(context.Background(), agentFile, true, false)

	var row *whaleStatusPeer
	for i := range view.Peers {
		if sameIP(view.Peers[i].Address, peer) {
			row = &view.Peers[i]
		}
	}
	if row == nil {
		t.Fatalf("the peer is missing from the status view: %+v", view.Peers)
	}
	if row.Path != "direct-punch" {
		t.Fatalf("PATH = %q, want the path the tunnel published. The status build is no longer "+
			"reading the record, so every direct path would render as relayed.", row.Path)
	}
	if !strings.Contains(row.Why, "direct via 203.0.113.7:41234") {
		t.Fatalf("WHY = %q, want the endpoint that carried it", row.Why)
	}
	// And it reaches the screen, not just the struct.
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	if !strings.Contains(stdout, "direct-punch") {
		t.Fatalf("the rendered table does not carry the path:\n%s", stdout)
	}
	if !strings.Contains(stderr, "direct via 203.0.113.7:41234") {
		t.Fatalf("the rendered notes do not carry the reason:\n%s", stderr)
	}
}

// TestWhaleStatus_AFailedPunchIsRenderedAsAFinding: the other half of the same wiring. A peer
// whose traversal failed must read as "relayed because the punch failed", not as a blank.
func TestWhaleStatus_AFailedPunchIsRenderedAsAFinding(t *testing.T) {
	whaleTestIsolation(t)
	dir := pathStateHome(t)
	const self = "2a04:2a01:4::9"
	const peer = "2a04:2a01:4::7"
	rec := directRecord(self, peer, "203.0.113.7:41234")
	rec.Peers[0].Promoted = false
	rec.Peers[0].Path = "relayed"
	rec.Peers[0].Punch.Phase = string(wgtun.PunchGaveUp)
	rec.Peers[0].Punch.Attempts = 12
	writePathRecord(t, dir, rec)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` +
			`["agent",{"label":"db-01","agent":"ag_db","address":"` + peer + `","state":"active"}]]}}`))
	}))
	t.Cleanup(srv.Close)

	agentFile := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(agentFile, []byte(self), 0o600); err != nil {
		t.Fatal(err)
	}
	g.key = "whisper_live_test"
	g.controlURL = srv.URL + "/api/query"

	view := buildWhaleStatus(context.Background(), agentFile, true, false)
	_, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	if !strings.Contains(stderr, "punch failed") {
		t.Fatalf("a failed traversal rendered as an absence rather than a finding:\n%s", stderr)
	}
	if !strings.Contains(stderr, "12 attempts") {
		t.Fatalf("the attempt count was not carried to the reader:\n%s", stderr)
	}
}
