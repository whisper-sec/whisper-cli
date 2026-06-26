// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// clearKeyEnv removes the key env vars so a test starts from a known-empty ladder.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	os.Unsetenv("WHISPER_API_KEY")
	os.Unsetenv("WHISPER_KEY")
}

func TestKeyLadderPrecedence(t *testing.T) {
	clearKeyEnv(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHISPER_API_KEY", "from-env")
	t.Setenv("WHISPER_KEY", "from-env-alt")

	// 1. --bearer beats everything (and selects Bearer auth).
	c, _ := ResolveCredential(KeyLadderOptions{
		FlagBearer: "et_token", FlagKey: "from-flag",
		KeyFile: keyFile, AllowEnv: true, AllowFile: true,
	})
	if c.Value != "et_token" || !c.Bearer || c.Source != SourceBearer {
		t.Fatalf("bearer should win: %+v", c)
	}

	// 2. --key beats env + file.
	c, _ = ResolveCredential(KeyLadderOptions{
		FlagKey: "from-flag", KeyFile: keyFile, AllowEnv: true, AllowFile: true,
	})
	if c.Value != "from-flag" || c.Bearer || c.Source != SourceFlag {
		t.Fatalf("flag should win over env+file: %+v", c)
	}

	// 3. WHISPER_API_KEY beats WHISPER_KEY + file.
	c, _ = ResolveCredential(KeyLadderOptions{KeyFile: keyFile, AllowEnv: true, AllowFile: true})
	if c.Value != "from-env" || c.Source != SourceEnvKey {
		t.Fatalf("WHISPER_API_KEY should win over alt+file: %+v", c)
	}

	// 4. WHISPER_KEY (alt) beats file when WHISPER_API_KEY is unset.
	t.Setenv("WHISPER_API_KEY", "")
	os.Unsetenv("WHISPER_API_KEY")
	c, _ = ResolveCredential(KeyLadderOptions{KeyFile: keyFile, AllowEnv: true, AllowFile: true})
	if c.Value != "from-env-alt" || c.Source != SourceEnvAlt {
		t.Fatalf("WHISPER_KEY should win over file: %+v", c)
	}

	// 5. file when env is disabled.
	c, _ = ResolveCredential(KeyLadderOptions{KeyFile: keyFile, AllowEnv: false, AllowFile: true})
	if c.Value != "from-file" || c.Source != SourceFile {
		t.Fatalf("file should be used: %+v", c)
	}

	// 6. prompt is the last resort.
	c, _ = ResolveCredential(KeyLadderOptions{
		KeyFile: filepath.Join(dir, "absent"), AllowEnv: false, AllowFile: true,
		Prompt: func() (string, error) { return "from-prompt", nil },
	})
	if c.Value != "from-prompt" || c.Source != SourcePrompt {
		t.Fatalf("prompt should be last resort: %+v", c)
	}

	// 7. nothing -> SourceNone, no error.
	c, err := ResolveCredential(KeyLadderOptions{
		KeyFile: filepath.Join(dir, "absent"), AllowEnv: false, AllowFile: true,
	})
	if err != nil {
		t.Fatalf("empty ladder should not error: %v", err)
	}
	if !c.IsZero() || c.Source != SourceNone {
		t.Fatalf("empty ladder should be SourceNone: %+v", c)
	}
}

func TestKeyLadderTrimsWhitespace(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv("WHISPER_API_KEY", "  spaced-key\n")
	c, _ := ResolveCredential(KeyLadderOptions{AllowEnv: true})
	if c.Value != "spaced-key" {
		t.Fatalf("env key not trimmed: %q", c.Value)
	}
}

func TestReadAgentFile(t *testing.T) {
	dir := t.TempDir()
	// absent file → "" (not an error: no pinned agent ⇒ most-recent default).
	if got := ReadAgentFile(filepath.Join(dir, "absent")); got != "" {
		t.Fatalf("absent agent file should be empty, got %q", got)
	}
	// present + trimmed.
	path := filepath.Join(dir, "agent")
	if err := os.WriteFile(path, []byte("  a1234beef  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadAgentFile(path); got != "a1234beef" {
		t.Fatalf("agent not read/trimmed: %q", got)
	}
	// blank/whitespace-only file → "" (treated as no pin).
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadAgentFile(path); got != "" {
		t.Fatalf("whitespace-only agent file should be empty, got %q", got)
	}
}

func TestSaveAgentMode600AndRemoveOnEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "agent")
	// write trims + 0600.
	if err := SaveAgent(path, "  agent-1a2b3c  "); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "agent-1a2b3c" {
		t.Fatalf("saved agent not trimmed: %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent file mode = %v, want 0600", fi.Mode().Perm())
	}
	// empty id removes the pin (so the most-recent default takes over) — and is idempotent.
	if err := SaveAgent(path, "   "); err != nil {
		t.Fatalf("SaveAgent(empty) should clear the pin, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty SaveAgent should remove the file, stat err = %v", err)
	}
	if err := SaveAgent(path, ""); err != nil {
		t.Fatalf("SaveAgent(empty) on an already-absent file should be a no-op, got %v", err)
	}
}

func TestSaveKeyMode600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "key")
	if err := SaveKey(path, "  the-key  "); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "the-key" {
		t.Fatalf("saved key not trimmed: %q", b)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", fi.Mode().Perm())
	}
}
