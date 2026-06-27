// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// stubEnsureDaemon replaces ensureDaemon with an in-memory no-op (no real fork / network), so
// an init test runs end-to-end without a live daemon. Returns a restore func.
func stubEnsureDaemon(t *testing.T) func() {
	t.Helper()
	saved := ensureDaemon
	ensureDaemon = func(_ projcfg.Paths, cfg projcfg.Config) (int, bool, error) {
		return cfg.Port, false, nil // "started cleanly"
	}
	return func() { ensureDaemon = saved }
}

// TestInitClaude_ExistingAgent_WritesEverything: `init claude --agent <128>` on an existing
// agent writes .whisper/config, the project agent file, and the merged settings, gitignores
// them, and starts the daemon — all without minting an agent.
func TestInitClaude_ExistingAgent_WritesEverything(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil { // make it a git repo
		t.Fatal(err)
	}

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	err := runInitClaude(initClaudeOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir})
	if err != nil {
		t.Fatalf("runInitClaude: %v", err)
	}

	p := projcfg.PathsFor(dir)

	// .whisper/config carries the agent + a deterministic port + tier.
	cfg, lerr := projcfg.Load(p)
	if lerr != nil || cfg == nil {
		t.Fatalf("config not written: %v", lerr)
	}
	if cfg.Agent != "2a04:2a01:9::abcd" || cfg.Tier != "socks5" {
		t.Fatalf("config wrong: %+v", *cfg)
	}
	if cfg.Port != projcfg.BasePort(p.Root) && (cfg.Port < 20000 || cfg.Port >= 40000) {
		t.Fatalf("port %d not in the deterministic band", cfg.Port)
	}

	// The PROJECT agent file holds the /128.
	if got := readFileTrim(t, filepath.Join(p.WhisperDir, "agent")); got != "2a04:2a01:9::abcd" {
		t.Fatalf("project agent file = %q", got)
	}

	// settings.local.json carries the managed env pointing at the config's port.
	m := readJSONMap(t, p.ClaudeLocal)
	env := m["env"].(map[string]any)
	wantProxy := "http://127.0.0.1:" + itoaTest(cfg.Port)
	if env["HTTPS_PROXY"] != wantProxy {
		t.Fatalf("settings HTTPS_PROXY = %v, want %s", env["HTTPS_PROXY"], wantProxy)
	}

	// .gitignore got the entries (it's a git repo).
	gi := readFileTrim(t, p.GitignoreFile)
	if !strings.Contains(gi, ".whisper/") || !strings.Contains(gi, ".claude/settings.local.json") {
		t.Fatalf(".gitignore not updated:\n%s", gi)
	}

	// It must NOT have minted an agent (we passed --agent).
	if containsOp(opsSeen(seen), "identity") {
		t.Fatalf("init --agent must not create an agent, ops=%v", opsSeen(seen))
	}
}

// TestInitClaude_NameCreatesAgent: `init claude --name scout` mints a NAMED agent (op:identity
// with label:'scout') and binds the project to its /128.
func TestInitClaude_NameCreatesAgent(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen) // fresh account
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	if err := runInitClaude(initClaudeOptions{tier: "socks5", name: "scout", dir: dir}); err != nil {
		t.Fatalf("runInitClaude --name: %v", err)
	}
	body, ok := bodyForOp(seen, "identity")
	if !ok {
		t.Fatalf("expected a named create (op:identity), ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "label:'scout'") {
		t.Fatalf("--name must map to the agent LABEL; create body = %q", body)
	}
	cfg, _ := projcfg.Load(projcfg.PathsFor(dir))
	if cfg == nil || cfg.Agent != "2a04:2a01:9::abcd" { // the stub server returns this /128 for identity
		t.Fatalf("config did not bind the created agent: %+v", cfg)
	}
}

// TestInitClaude_IdempotentReusesPort: a second init on the SAME dir reuses the SAME port and
// does NOT duplicate the settings env/hook (the merge is idempotent).
func TestInitClaude_IdempotentReusesPort(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	if err := runInitClaude(initClaudeOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("first init: %v", err)
	}
	cfg1, _ := projcfg.Load(projcfg.PathsFor(dir))

	if err := runInitClaude(initClaudeOptions{tier: "wireguard", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("re-init: %v", err)
	}
	cfg2, _ := projcfg.Load(projcfg.PathsFor(dir))

	if cfg1.Port != cfg2.Port {
		t.Fatalf("re-init changed the deterministic port: %d → %d", cfg1.Port, cfg2.Port)
	}
	// The tier updated (re-init reflects the new flag).
	if cfg2.Tier != "wireguard" {
		t.Fatalf("re-init did not update the tier: %q", cfg2.Tier)
	}
	// Exactly one SessionStart group (no duplicate hook).
	m := readJSONMap(t, projcfg.PathsFor(dir).ClaudeLocal)
	hooks := m["hooks"].(map[string]any)
	groups := hooks["SessionStart"].([]any)
	if len(groups) != 1 {
		t.Fatalf("re-init duplicated the SessionStart hook: %d groups", len(groups))
	}
}

// TestInitClaude_BadTierIsUsageError: a typo'd --tier is a clear usage error, not a silent
// default.
func TestInitClaude_BadTierIsUsageError(t *testing.T) {
	dir := t.TempDir()
	err := runInitClaude(initClaudeOptions{tier: "wormhole", dir: dir})
	if err == nil || !isUsageError(err) {
		t.Fatalf("a bad --tier must be a usage error, got %v", err)
	}
}

// --- small local helpers ---------------------------------------------------------------

func readFileTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	return m
}

func itoaTest(n int) string {
	// tiny local int→string (avoid importing strconv just for tests that already import a lot)
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
