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
	const addr = "2a04:2a01:0:beef:dead:beef:dead:1"
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
	const addr = "2a04:2a01:0:beef:dead:beef:dead:1"
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
	const addr = "2a04:2a01:0:beef:dead:beef:dead:1"
	path := writePathRecordFor(t, dir, addr, 0)

	tunnelAt(dir, addr).clearPaths()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("a pid-less record survived teardown; nothing else will ever retire it")
	}
}

// A renewal in the same process writes the same file, keyed by the address. The tunnel it replaced must
// not take the new one's record with it on the way out: the pid is the same, the instance is not.
func TestClearPathsLeavesAnotherTunnelInThisProcessAlone(t *testing.T) {
	dir := t.TempDir()
	const addr = "2a04:2a01:0:beef:dead:beef:dead:1"
	rec := PathStateRecord{Address: addr, PID: os.Getpid(), Instance: "new-tunnel"}
	b, _ := json.Marshal(rec)
	path := pathRecordPath(dir, addr)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	old := tunnelAt(dir, addr)
	old.instance = "old-tunnel"
	old.clearPaths()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the replaced tunnel removed its successor's record (%v)", err)
	}
	same := tunnelAt(dir, addr)
	same.instance = "new-tunnel"
	same.clearPaths()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a tunnel's own record survived its teardown")
	}
}

// Two tunnels never share an instance or a starting routed period, so a reader comparing two reads
// cannot take one tunnel's period for another's.
func TestInstanceAndEpochBaseAreUniquePerTunnel(t *testing.T) {
	seenI, seenE := map[string]bool{}, map[uint64]bool{}
	for i := 0; i < 64; i++ {
		id, e := newInstanceID(), newRouteEpochBase()
		if id == "" || seenI[id] || e == 0 || e>>62 != 0 || seenE[e] {
			t.Fatalf("draw %d: instance %q epoch %d repeats, is empty, or can wrap", i, id, e)
		}
		seenI[id], seenE[e] = true, true
	}
}

// A publish whose write fails is not remembered as written, and one made before a route is taken away
// removes the record instead, so a record that cannot be updated cannot go on claiming the route.
func TestAFailedPublishIsRetriedAndAFailedUnroutePublishDropsTheRecord(t *testing.T) {
	dir := t.TempDir()
	const addr = "2a04:2a01:0:beef:dead:beef:dead:2"
	tun := tunnelAt(dir, addr)
	tun.instance = "this-tunnel"
	if !tun.publishPaths() {
		t.Fatal("the first publish failed")
	}
	path := pathRecordPath(dir, addr)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("nothing was published: %v", err)
	}
	saved := writeRecordFile
	t.Cleanup(func() { writeRecordFile = saved })
	writeRecordFile = func(string, []byte) error { return os.ErrPermission }
	tun.mu.Lock()
	tun.pathFP = "something else" // a change to publish
	tun.mu.Unlock()
	if tun.publishPaths() {
		t.Fatal("a publish whose write failed reported success")
	}
	tun.mu.Lock()
	fp := tun.pathFP
	tun.mu.Unlock()
	if fp != "something else" {
		t.Fatal("a failed write was remembered as written, so it would not be tried again until the heartbeat")
	}
	tun.publishBeforeUnroute()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a record that could not be updated before a route was taken away is still on disk")
	}
}
