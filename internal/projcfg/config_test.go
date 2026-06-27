// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSaveLoad_RoundTripAndShape: Save writes a canonical, stamped .whisper/config and Load
// reads it back verbatim. The on-disk shape carries exactly agent/tier/port/schemaVersion (+
// optional fqdn) and nothing secret.
func TestSaveLoad_RoundTripAndShape(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)

	in := Config{Agent: "2a04:2a01:9::dead", Tier: "wireguard", Port: 28080, FQDN: "scout.agents.example."}
	if err := Save(p, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Mode 0600 on the config file (not world-readable). (Skip the bit-check on Windows where
	// unix perms don't apply.)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p.ConfigFile)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	got, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil for a written config")
	}
	if got.Agent != in.Agent || got.Tier != "wireguard" || got.Port != in.Port || got.FQDN != in.FQDN {
		t.Fatalf("round-trip mismatch: %+v vs %+v", *got, in)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion)
	}

	// The raw JSON must carry the expected keys and NO secret-looking field.
	raw, _ := os.ReadFile(p.ConfigFile)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	for _, k := range []string{"schemaVersion", "agent", "tier", "port"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("config missing key %q; got %v", k, m)
		}
	}
	for _, bad := range []string{"bearer", "et_", "private_key", "api_key", "key"} {
		if _, ok := m[bad]; ok {
			t.Fatalf("config must not carry secret field %q", bad)
		}
	}
}

// TestLoad_MissingIsNotError: a project with no .whisper/config returns (nil, nil) — "no
// config" is a normal state the caller decides on, not an error.
func TestLoad_MissingIsNotError(t *testing.T) {
	p := PathsFor(t.TempDir())
	got, err := Load(p)
	if err != nil {
		t.Fatalf("missing config must not error, got %v", err)
	}
	if got != nil {
		t.Fatalf("missing config must return nil, got %+v", *got)
	}
}

// TestLoad_CorruptIsClearError: a present-but-malformed config is a clear error (never an
// opaque decode panic) — Postel: fail with a helpful message.
func TestLoad_CorruptIsClearError(t *testing.T) {
	p := PathsFor(t.TempDir())
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ConfigFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("a corrupt config must be a clear error, got nil")
	}
}

// TestSave_TierNormalised: a blank or "wg" tier is normalised to the canonical token on write.
func TestSave_TierNormalised(t *testing.T) {
	cases := map[string]string{"": "socks5", "wg": "wireguard", "WireGuard": "wireguard", "socks5": "socks5"}
	for in, want := range cases {
		p := PathsFor(t.TempDir())
		if err := Save(p, Config{Agent: "2a04:2a01::1", Tier: in, Port: 20001}); err != nil {
			t.Fatalf("Save(tier=%q): %v", in, err)
		}
		got, _ := Load(p)
		if got.Tier != want {
			t.Fatalf("tier %q normalised to %q, want %q", in, got.Tier, want)
		}
	}
}

// TestPathsFor_AbsoluteAndLayout: PathsFor resolves to an absolute root and the standard
// per-project layout.
func TestPathsFor_AbsoluteAndLayout(t *testing.T) {
	dir := t.TempDir()
	p := PathsFor(dir)
	if !filepath.IsAbs(p.Root) {
		t.Fatalf("root must be absolute, got %q", p.Root)
	}
	if p.ConfigFile != filepath.Join(p.Root, ".whisper", "config") {
		t.Fatalf("ConfigFile = %q", p.ConfigFile)
	}
	if p.ClaudeLocal != filepath.Join(p.Root, ".claude", "settings.local.json") {
		t.Fatalf("ClaudeLocal = %q", p.ClaudeLocal)
	}
}
