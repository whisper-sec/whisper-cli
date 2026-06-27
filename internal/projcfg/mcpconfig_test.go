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

func entry() map[string]any { return map[string]any{"command": "whisper", "args": []string{"mcp"}} }

// TestMergeJSONServer_CreatesAndPreserves: creates a fresh config, and a merge into an existing
// config keeps the user's other servers + top-level keys (never clobbers).
func TestMergeJSONServer_CreatesAndPreserves(t *testing.T) {
	dir := t.TempDir()

	// fresh
	fresh := filepath.Join(dir, ".mcp.json")
	res, err := MergeJSONServer(fresh, "mcpServers", "whisper", entry())
	if err != nil || !res.Created {
		t.Fatalf("fresh create: res=%+v err=%v", res, err)
	}

	// existing with another server + an unrelated top-level key
	exist := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(exist, []byte(`{"mcpServers":{"other":{"command":"x"}},"k":7}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = MergeJSONServer(exist, "mcpServers", "whisper", entry())
	if err != nil || res.Created {
		t.Fatalf("merge: res=%+v err=%v", res, err)
	}
	var m map[string]any
	b, _ := os.ReadFile(exist)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result not valid JSON: %v", err)
	}
	srv := m["mcpServers"].(map[string]any)
	if _, ok := srv["other"]; !ok {
		t.Fatalf("clobbered the user's other server: %s", b)
	}
	if _, ok := srv["whisper"]; !ok {
		t.Fatalf("did not add whisper: %s", b)
	}
	if m["k"] != float64(7) {
		t.Fatalf("clobbered an unrelated top-level key: %s", b)
	}
}

// TestMergeJSONServer_RefreshesAndRefusesSymlinkAndBadJSON.
func TestMergeJSONServer_RefreshesAndRefusesSymlinkAndBadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".mcp.json")
	if _, err := MergeJSONServer(p, "mcpServers", "whisper", entry()); err != nil {
		t.Fatal(err)
	}
	res, err := MergeJSONServer(p, "mcpServers", "whisper", entry())
	if err != nil || !res.Replaced {
		t.Fatalf("second merge should report Replaced: %+v %v", res, err)
	}

	// invalid JSON is a clear error (we never destroy it)
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0o644)
	if _, err := MergeJSONServer(bad, "mcpServers", "whisper", entry()); err == nil {
		t.Fatalf("invalid JSON must error, not be overwritten")
	}

	// symlink target is refused
	if runtime.GOOS != "windows" {
		secret := filepath.Join(dir, "secret.json")
		_ = os.WriteFile(secret, []byte(`{"keep":1}`), 0o600)
		link := filepath.Join(dir, "link.json")
		_ = os.Symlink("secret.json", link)
		if _, err := MergeJSONServer(link, "mcpServers", "whisper", entry()); err == nil {
			t.Fatalf("must refuse to write through a symlink")
		}
		if b, _ := os.ReadFile(secret); string(b) != `{"keep":1}` {
			t.Fatalf("symlink target was clobbered: %s", b)
		}
	}
}
