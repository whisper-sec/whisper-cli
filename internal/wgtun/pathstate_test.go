// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pathstate_test.go covers the record the tunnel publishes so surfaces in other processes can
// report the path a packet is actually taking. The WRITE side is covered for real in
// whale_punch_test.go, against a live device; this is the read side and its failure modes,
// which all come down to one rule: a fault must never render as an empty peer list.

func writeRecord(t *testing.T, dir string, rec PathStateRecord) {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(pathRecordPath(dir, rec.Address), b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestReadPathStates_ReturnsALiveRecordAndSweepsADeadOne(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, PathStateRecord{
		Address: "2a04:2a01:4::9", PID: os.Getpid(), Updated: time.Now(),
		Peers: []PathPeerRecord{{Address: "2a04:2a01:4::7", Path: "direct-punch", Promoted: true}},
	})
	// A record from a tunnel that has since exited. Its claim about a live path describes
	// nothing, so it must not be believed - and it must not be left to be re-read forever.
	writeRecord(t, dir, PathStateRecord{
		Address: "2a04:2a01:4::a", PID: 0x7FFFFFF0, Updated: time.Now(),
		Peers: []PathPeerRecord{{Address: "2a04:2a01:4::7", Path: "direct-punch", Promoted: true}},
	})

	got := ReadPathStates(dir)
	if len(got) != 1 || got[0].Address != "2a04:2a01:4::9" {
		t.Fatalf("got %+v, want only the live record", got)
	}
	if _, err := os.Stat(pathRecordPath(dir, "2a04:2a01:4::a")); !os.IsNotExist(err) {
		t.Fatal("the record of a dead holder was not swept")
	}
}

func TestReadPathStates_AStaleRecordIsReturnedAndFlaggedNeverDropped(t *testing.T) {
	// The failure this guards: a live holder whose monitor has wedged. Dropping the record would
	// render a fault as "no direct paths", which reads as reassuring and is not.
	dir := t.TempDir()
	writeRecord(t, dir, PathStateRecord{
		Address: "2a04:2a01:4::9", PID: os.Getpid(),
		Updated: time.Now().Add(-10 * time.Minute),
		Peers:   []PathPeerRecord{{Address: "2a04:2a01:4::7", Path: "direct-punch", Promoted: true}},
	})
	got := ReadPathStates(dir)
	if len(got) != 1 {
		t.Fatalf("a stale record was dropped rather than flagged: %+v", got)
	}
	if !got[0].Stale() {
		t.Fatalf("a ten-minute-old record does not report itself as stale (age %s)", got[0].Age())
	}
}

func TestReadPathStates_SkipsRubbishWithoutLosingTheRest(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "half-written.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, PathStateRecord{Address: "2a04:2a01:4::9", PID: os.Getpid(), Updated: time.Now()})
	if got := ReadPathStates(dir); len(got) != 1 {
		t.Fatalf("one unreadable file cost the whole read: %+v", got)
	}
}

func TestReadPathStates_AMissingDirectoryIsNotAnError(t *testing.T) {
	if got := ReadPathStates(filepath.Join(t.TempDir(), "never-created")); got != nil {
		t.Fatalf("got %+v, want nothing at all - a host with no tunnel has published nothing", got)
	}
}

func TestPathStateRecord_PeerForIsLiberalAboutHowAnAddressIsWritten(t *testing.T) {
	rec := PathStateRecord{Peers: []PathPeerRecord{{Address: "2a04:2a01:4::7", Path: "relayed"}}}
	for _, form := range []string{"2a04:2a01:4::7", "2A04:2A01:4::7", "[2a04:2a01:4::7]", " 2a04:2a01:4::7 "} {
		if _, ok := rec.PeerFor(form); !ok {
			t.Fatalf("PeerFor(%q) found nothing", form)
		}
	}
	if _, ok := rec.PeerFor("2a04:2a01:4::99"); ok {
		t.Fatal("PeerFor invented a peer that is not in the record")
	}
}

func TestReadPathStateFor_PicksTheRightNode(t *testing.T) {
	dir := t.TempDir()
	writeRecord(t, dir, PathStateRecord{Address: "2a04:2a01:4::9", PID: os.Getpid(), Updated: time.Now()})
	writeRecord(t, dir, PathStateRecord{Address: "2a04:2a01:4::b", PID: os.Getpid(), Updated: time.Now()})
	got, ok := ReadPathStateFor(dir, "2a04:2a01:4::b")
	if !ok || got.Address != "2a04:2a01:4::b" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := ReadPathStateFor(dir, "2a04:2a01:4::ff"); ok {
		t.Fatal("a node nothing published for was reported as found")
	}
}

// TestPathRecordPath_FlattensColonsForWindows: a filename with colons in it is not creatable on
// Windows, and the CLI ships there. The address inside the record stays the real literal.
func TestPathRecordPath_FlattensColonsForWindows(t *testing.T) {
	got := pathRecordPath("/tmp/x", "2a04:2a01:4::9")
	if filepath.Base(got) != "2a04_2a01_4__9.json" {
		t.Fatalf("record path = %q", got)
	}
}
