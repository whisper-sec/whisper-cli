package wgtun

import (
	"os"
	"testing"
	"time"
)

// A published record must carry the holder's OWN reading of tunnel health, because record
// freshness answers a different question than every reader assumed.
//
// The incident, 2026-09-03. A panel reported `"tunnel": {"known": true, "healthy": true}` for a
// session whose own log had reached "re-handshake attempt 183" and which was carrying no traffic
// at all: a SOCKS probe through it timed out on every target, including ones a fresh session
// answered in milliseconds. Nothing lied. Health was being derived from `!rec.Stale()`, and a
// monitor that is failing to re-handshake is still a monitor that is RUNNING, so it republishes
// on every tick and the record never goes stale. Freshness is the liveness of the publisher. It
// is not the health of the tunnel, and the two diverge exactly when it matters most.

func boolp(b bool) *bool { return &b }

func TestARecordWithNoOpinionIsDistinguishableFromOneThatSaysUnhealthy(t *testing.T) {
	// The pointer is load-bearing. An older holder publishes no opinion, and reading that as a
	// confident "unhealthy" would invent a fault nobody reported. Absent and false must differ.
	var absent PathStateRecord
	if healthy, published := absent.TunnelHealth(); published || healthy {
		t.Fatalf("(%v,%v), want an absent opinion to report published=false", healthy, published)
	}
	unhealthy := PathStateRecord{TunnelHealthy: boolp(false)}
	if healthy, published := unhealthy.TunnelHealth(); !published || healthy {
		t.Fatalf("(%v,%v), want a published false to be reported AS published", healthy, published)
	}
	healthyRec := PathStateRecord{TunnelHealthy: boolp(true)}
	if healthy, published := healthyRec.TunnelHealth(); !published || !healthy {
		t.Fatalf("(%v,%v), want a published true", healthy, published)
	}
}

func TestHealthAndReconnectsSurviveTheRoundTripToDisk(t *testing.T) {
	// The whole mechanism is a write in one process and a read in another, so a field that does
	// not survive the JSON round trip is the same as a field that does not exist.
	dir := t.TempDir()
	writeRecord(t, dir, PathStateRecord{
		Address:       "2a04:2a01:4::7",
		PID:           os.Getpid(),
		Updated:       time.Now(),
		TunnelHealthy: boolp(false),
		Reconnects:    183,
	})
	got, ok := ReadPathStateFor(dir, "2a04:2a01:4::7")
	if !ok {
		t.Fatal("the record did not read back")
	}
	healthy, published := got.TunnelHealth()
	if !published {
		t.Fatal("tunnel_healthy did not survive the round trip, so the panel would fall back to freshness")
	}
	if healthy {
		t.Fatal("a record published as unhealthy read back as healthy")
	}
	if got.Reconnects != 183 {
		t.Fatalf("reconnects = %d, want 183: the count is what tells a flapping tunnel from a steady one", got.Reconnects)
	}
}

func TestAFreshRecordCanStillReportAnUnhealthyTunnel(t *testing.T) {
	// THE regression. This is exactly the incident: the record is fresh, because the monitor is
	// alive and republishing, AND the tunnel is dead. Before the field existed, freshness alone
	// decided, so this combination was unrepresentable and rendered as healthy.
	dir := t.TempDir()
	writeRecord(t, dir, PathStateRecord{
		Address:       "2a04:2a01:4::8",
		PID:           os.Getpid(),
		Updated:       time.Now(), // fresh
		TunnelHealthy: boolp(false),
		Reconnects:    183,
	})
	got, _ := ReadPathStateFor(dir, "2a04:2a01:4::8")
	if got.Stale() {
		t.Fatal("fixture is not fresh, so it cannot prove the point")
	}
	if healthy, published := got.TunnelHealth(); !published || healthy {
		t.Fatalf("(%v,%v), want a FRESH record to still be able to say the tunnel is down", healthy, published)
	}
}
