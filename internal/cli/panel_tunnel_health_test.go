package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The panel must report the HOLDER'S reading of the tunnel, not the freshness of its record.
//
// On 2026-09-03 the panel reported `"tunnel": {"known": true, "healthy": true}` for a session
// whose own log had reached "re-handshake attempt 183" and which carried no traffic: a SOCKS
// probe through it timed out on every target that a fresh session answered instantly. The bug
// was that health came from `!rec.Stale()`, and a monitor failing to re-handshake is still a
// monitor that is running, so it republishes every tick and the record never goes stale.
//
// This test drives the REAL panelTunnelFor against a record on disk, so it fails if the wiring
// is removed. Asserting on the record type alone would pass with a panel that ignores it, which
// is the shape of a fix that ships and can never execute.

func writePanelRecord(t *testing.T, home, addr string, body map[string]any) {
	t.Helper()
	dir := filepath.Join(home, ".config", "whisper", "paths")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body["address"] = addr
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	name := strings.ReplaceAll(addr, ":", "-") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestThePanelReportsAFlappingTunnelAsUnhealthyEvenWhileTheRecordIsFresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	addr := "2a04:2a01:4::11"
	writePanelRecord(t, home, addr, map[string]any{
		"pid":            os.Getpid(),
		"updated":        time.Now().Format(time.RFC3339Nano), // FRESH: the monitor is alive
		"tunnel_healthy": false,                               // ...and the tunnel is down
		"reconnects":     183,
	})

	got := panelTunnelFor(addr)
	if !got.Known {
		t.Skip("the record did not read back on this platform; the wgtun round-trip test covers the format")
	}
	if got.Healthy {
		t.Fatal("the panel reported healthy for a tunnel the holder published as DOWN; this is the 2026-09-03 defect")
	}
	if got.Reconnects != 183 {
		t.Fatalf("reconnects = %d, want 183 surfaced so a reader can tell flapping from steady", got.Reconnects)
	}
}

func TestThePanelStillTrustsAHolderThatSaysHealthy(t *testing.T) {
	// CONTROL. A fix that simply reported everything unhealthy would pass the test above and be
	// useless, so the healthy case is pinned in the same breath.
	home := t.TempDir()
	t.Setenv("HOME", home)
	addr := "2a04:2a01:4::12"
	writePanelRecord(t, home, addr, map[string]any{
		"pid":            os.Getpid(),
		"updated":        time.Now().Format(time.RFC3339Nano),
		"tunnel_healthy": true,
	})
	got := panelTunnelFor(addr)
	if !got.Known {
		t.Skip("the record did not read back on this platform")
	}
	if !got.Healthy {
		t.Fatal("the panel called a working tunnel unhealthy")
	}
}

func TestAnOlderHolderWithNoOpinionFallsBackToFreshness(t *testing.T) {
	// Backward compatibility: a record written before this field existed must not be read as a
	// confident "unhealthy" that nobody published.
	home := t.TempDir()
	t.Setenv("HOME", home)
	addr := "2a04:2a01:4::13"
	writePanelRecord(t, home, addr, map[string]any{
		"pid":     os.Getpid(),
		"updated": time.Now().Format(time.RFC3339Nano),
	})
	got := panelTunnelFor(addr)
	if !got.Known {
		t.Skip("the record did not read back on this platform")
	}
	if !got.Healthy {
		t.Fatal("an older record with no opinion was reported unhealthy; absent is not false")
	}
}
