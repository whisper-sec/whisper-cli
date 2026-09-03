// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// - two sessions, one agent.
//
// Measured on real hardware while proving a hand-started `whisper connect --tier wireguard`
// and the resident LaunchAgent both served the same /128. The registry was keyed on the address
// alone, so they shared one file, and when the hand-started one exited its cleanup removed the
// resident one's entry. The resident session kept working perfectly - the process up, 127.0.0.1:1080
// listening, a real request through it returning 200, launchd reporting it had never exited - while
// `whisper status` and `whisper panel status --json` both said "not connected - run: whisper
// connect". The remedy those surfaces print is what creates the second session, so the failure fed
// itself.
//
// Nothing modelled two owners for one address before this file, which is why the write was a bare
// overwrite and the clear was unconditional.

// heldSession is an owned session on a specific port, the way a held-open connect yields one.
func heldSession(addr string, port int) *egressSession {
	return &egressSession{
		endpoint: "socks5h://127.0.0.1:" + strconv.Itoa(port),
		addr:     addr,
		tier:     "wireguard",
		verified: true,
		local:    &fakeLocal{},
	}
}

func portsOf(recs []sessionRecord) []int {
	out := make([]int, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Port)
	}
	return out
}

func TestTwoSessionsForOneAgentAreTwoRows(t *testing.T) {
	stubSessionsDir(t)

	resident := heldSession("2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd", 1080)
	interactive := heldSession("2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd", 51234)
	writeSessionRecord(resident)
	writeSessionRecord(interactive)

	recs := readSessionRecords()
	if len(recs) != 2 {
		t.Fatalf("two live sessions for one /128 produced %d record(s) %v, want 2 - one file per"+
			" session is the whole fix; sharing one means whichever exits first erases the other",
			len(recs), portsOf(recs))
	}
}

func TestStoppingOneSessionLeavesTheOtherRegistered(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)

	addr := "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	resident := heldSession(addr, 1080)
	interactive := heldSession(addr, 51234)
	writeSessionRecord(resident)
	writeSessionRecord(interactive)

	// The terminal session ends. This is the exact sequence from the issue.
	clearSessionRecord(interactive)

	recs := readSessionRecords()
	if len(recs) != 1 {
		t.Fatalf("after one of two sessions exited, %d record(s) remain %v, want exactly 1",
			len(recs), portsOf(recs))
	}
	if recs[0].Port != 1080 {
		t.Fatalf("the surviving record is for port %d, want the resident session's 1080 -"+
			" the wrong row survived", recs[0].Port)
	}

	// ...and the surfaces a user reads have to agree, because "the file is there" was never the
	// complaint. `whisper status` and the panel both read liveStatusSessions().
	live := liveStatusSessions()
	if len(live) != 1 || live[0].Port != 1080 {
		t.Fatalf("liveStatusSessions() = %+v, want the still-serving resident session -"+
			" this is the reading that told a user with a working tunnel to run `whisper connect`",
			live)
	}
	if got := buildPanelConnection(&live[0]).State; got != panelConnected {
		t.Fatalf("panel connection state = %q, want %q", got, panelConnected)
	}
}

func TestClearNeverRemovesARecordThisProcessDidNotWrite(t *testing.T) {
	stubSessionsDir(t)

	addr := "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	// A record for the same address and port, held by SOME OTHER process.
	foreign := sessionRecord{
		Addr:     addr,
		Endpoint: "socks5h://127.0.0.1:1080",
		Tier:     "wireguard",
		Port:     1080,
		PID:      os.Getpid() + 1,
	}
	b, err := json.Marshal(foreign)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := sessionRecordPath(addr, 1080)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// A session of ours that never wrote anything (its write failed, or it predates recordPath)
	// tears down. It must not take the foreign row with it: per-session keying already stops the
	// collision, and this stops the NEXT key scheme reintroducing it.
	mine := heldSession(addr, 1080)
	clearSessionRecord(mine)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("teardown deleted a record written by another process (%v). A cleanup that can"+
			" unlink a row it did not write is the defect, whatever the key scheme is", err)
	}
}

func TestClearRemovesExactlyTheFileThisSessionWrote(t *testing.T) {
	dir := stubSessionsDir(t)

	addr := "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	mine := heldSession(addr, 51234)
	writeSessionRecord(mine)
	if mine.recordPath == "" {
		t.Fatal("writeSessionRecord did not remember the path it wrote, so teardown has nothing exact to remove")
	}
	clearSessionRecord(mine)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			t.Fatalf("the owner's own record survived teardown: %s", e.Name())
		}
	}
}

// A record written by a build that keyed on the address alone has no port in its filename.
// readSessionRecords still parses it, so the sweep has to be able to REMOVE it: a stale legacy
// record that cannot be swept reports "connected" forever.
func TestALegacyNamedRecordIsStillSweepable(t *testing.T) {
	dir := stubSessionsDir(t)
	stubProbe(t, false, nil) // nothing answers: every record here is stale

	addr := "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	legacy := sessionRecord{Addr: addr, Endpoint: "socks5h://127.0.0.1:1080", Tier: "wireguard", Port: 1080, PID: 4242}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	legacyPath := filepath.Join(dir, strings.ReplaceAll(addr, ":", "_")+".json")
	if err := os.WriteFile(legacyPath, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if recs := readSessionRecords(); len(recs) != 1 {
		t.Fatalf("a legacy-named record read back as %d row(s), want 1", len(recs))
	}
	if live := liveStatusSessions(); len(live) != 0 {
		t.Fatalf("a record whose proxy does not answer was reported live: %+v", live)
	}
	if _, err := os.Stat(legacyPath); err == nil {
		t.Fatal("the stale legacy-named record was not swept, so it will report a connection that" +
			" does not exist on every future status")
	}
}
