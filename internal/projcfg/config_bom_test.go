// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
package projcfg

import (
	"os"
	"path/filepath"
	"testing"
)

// A config written by Windows PowerShell 5.1 carries a UTF-8 BOM, because
// `Set-Content -Encoding utf8` writes one on every file it touches. encoding/json
// refuses the leading U+FEFF, and the message it produced sent the reader off to
// re-run init on a file that was perfectly good:
//
//	whisper: C:\ProgramData\Whisper\sensor.json is corrupt
//	(re-run `whisper init claude --force`): invalid character 'ï' looking for
//	beginning of value
//
// That happened on a Windows lab host while bringing it onto Tier-1. A
// BOM is a difference of ENCODING, not of content, and refusing it is the console
// being stricter about what it accepts, which is the wrong direction.
func TestLoad_AcceptsUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	p := Paths{WhisperDir: filepath.Join(dir, Dir), ConfigFile: filepath.Join(dir, Dir, "config")}
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"schemaVersion":1,"agent":"2a04:2a01::1","tier":"wireguard","port":1080}`
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(body)...)
	if err := os.WriteFile(p.ConfigFile, withBOM, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(p)
	if err != nil {
		t.Fatalf("a BOM-prefixed config must load, got: %v", err)
	}
	if c == nil {
		t.Fatal("config was nil")
	}
	if c.Agent != "2a04:2a01::1" {
		t.Errorf("agent = %q, want 2a04:2a01::1", c.Agent)
	}
	if c.Tier != "wireguard" {
		t.Errorf("tier = %q, want wireguard", c.Tier)
	}
	if c.Port != 1080 {
		t.Errorf("port = %d, want 1080", c.Port)
	}
}

// The BOM tolerance must not become "accept anything". A file that is genuinely
// not JSON still fails, and the failure still names the file, because the whole
// point of the change is to tell an encoding difference apart from real damage.
func TestLoad_StillRejectsRealGarbage(t *testing.T) {
	dir := t.TempDir()
	p := Paths{WhisperDir: filepath.Join(dir, Dir), ConfigFile: filepath.Join(dir, Dir, "config")}
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"not json":            []byte("this is not json at all"),
		"BOM then not json":   append([]byte{0xEF, 0xBB, 0xBF}, []byte("still not json")...),
		"truncated mid-value": []byte(`{"agent":"2a04:`),
	} {
		if err := os.WriteFile(p.ConfigFile, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

// A BOM on an otherwise canonical file round-trips: Load accepts it, Save writes
// the canonical form back without one, and the second Load agrees with the first.
func TestLoad_BOMRoundTripsToCanonical(t *testing.T) {
	dir := t.TempDir()
	p := Paths{WhisperDir: filepath.Join(dir, Dir), ConfigFile: filepath.Join(dir, Dir, "config")}
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"schemaVersion":1,"agent":"2a04:2a01::2","tier":"socks5","port":1081}`
	if err := os.WriteFile(p.ConfigFile, append([]byte{0xEF, 0xBB, 0xBF}, []byte(body)...), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Load(p)
	if err != nil {
		t.Fatalf("load with BOM: %v", err)
	}
	if err := Save(p, *first); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(p.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		t.Error("Save re-emitted a BOM; the canonical form must not carry one")
	}
	second, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if second.Agent != first.Agent || second.Tier != first.Tier || second.Port != first.Port {
		t.Errorf("round trip changed the config: %+v -> %+v", first, second)
	}
}
