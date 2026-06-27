// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMCPInstall_WritesProjectConfigs: `whisper mcp install` creates .mcp.json + .cursor/mcp.json
// with a `whisper` stdio server, preserving any pre-existing servers.
func TestMCPInstall_WritesProjectConfigs(t *testing.T) {
	dir := t.TempDir()
	// pre-existing .mcp.json with another server, to prove no-clobber.
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"),
		[]byte(`{"mcpServers":{"keepme":{"command":"x"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	savedG := g
	g = globalFlags{quiet: true} // quiet → just paths on stdout, no matrix noise
	defer func() { g = savedG }()

	if err := runMCPInstall(dir); err != nil {
		t.Fatalf("runMCPInstall: %v", err)
	}

	for _, rel := range []string{".mcp.json", ".cursor/mcp.json"} {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s not valid JSON: %v", rel, err)
		}
		srv, _ := m["mcpServers"].(map[string]any)
		ws, _ := srv["whisper"].(map[string]any)
		if ws == nil || ws["command"] != "whisper" {
			t.Fatalf("%s missing whisper stdio entry: %s", rel, b)
		}
	}

	// the pre-existing server survived in .mcp.json
	b, _ := os.ReadFile(filepath.Join(dir, ".mcp.json"))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["mcpServers"].(map[string]any)["keepme"]; !ok {
		t.Fatalf("clobbered the user's existing server: %s", b)
	}
}

// TestMCPClientMatrix_HasVerifiedKeys: the printed matrix names each client's CORRECT top-level
// key (so we never tell a user the wrong shape).
func TestMCPClientMatrix_HasVerifiedKeys(t *testing.T) {
	mx := mcpClientMatrix()
	for _, want := range []string{
		"~/.cursor/mcp.json", "mcpServers",
		"~/.codeium/windsurf/mcp_config.json",
		"claude_desktop_config.json",
		".vscode/mcp.json", "\"servers\"",
		"context_servers",
		"config.yaml",
	} {
		if !contains(mx, want) {
			t.Fatalf("matrix missing %q:\n%s", want, mx)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
