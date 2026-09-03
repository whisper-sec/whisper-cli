// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

// The tunnel half. The panel's "tunnel": {"known": false, "healthy": false} over a live
// Tier-1 tunnel comes from here, not from the session registry: panelTunnelFor reads
// ReadPathStateFor, and this record is keyed on the /128 alone. Two tunnels for one address share
// the file, and clearPaths used to remove it unconditionally, so whichever monitor exited first
// took the survivor's row with it.
//
// Ownership is checked on the pid rather than on the key, because the key scheme is not the
// invariant. A teardown that can unlink a record another process wrote is wrong however the file
// is named.

func writePathRecordFor(t *testing.T, dir, address string, pid int) string {
	t.Helper()
	rec := PathStateRecord{Address: address, PID: pid}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := pathRecordPath(dir, address)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func tunnelAt(dir, address string) *Tunnel {
	return &Tunnel{pathDir: dir, cfg: Config{Address: netip.MustParseAddr(address)}}
}

func TestClearPathsLeavesAnotherProcessRecordAlone(t *testing.T) {
	dir := t.TempDir()
	const addr = "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	// The surviving resident tunnel published this. Its pid is not ours.
	path := writePathRecordFor(t, dir, addr, os.Getpid()+1)

	// The other tunnel for the same /128 goes away.
	tunnelAt(dir, addr).clearPaths()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("clearPaths deleted a record written by another process (%v). That is the read"+
			" the panel renders as tunnel.known=false over a tunnel that is up", err)
	}
}

func TestClearPathsRemovesOurOwnRecord(t *testing.T) {
	dir := t.TempDir()
	const addr = "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	path := writePathRecordFor(t, dir, addr, os.Getpid())

	tunnelAt(dir, addr).clearPaths()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("our own record survived teardown, so a tunnel that is gone keeps claiming a live path")
	}
}

// A record with no pid predates pid tracking. Removing it is still right: nothing can prove it
// belongs to somebody else, and leaving it would strand a claim no sweep can retire.
func TestClearPathsRemovesAPidlessRecord(t *testing.T) {
	dir := t.TempDir()
	const addr = "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd"
	path := writePathRecordFor(t, dir, addr, 0)

	tunnelAt(dir, addr).clearPaths()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("a pid-less record survived teardown; nothing else will ever retire it")
	}
}
