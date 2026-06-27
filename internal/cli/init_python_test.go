// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// TestInitPython_ExistingAgent_WritesProxyEnv: `init python --agent <128>` writes .whisper/config,
// the project agent file, and the wholly-owned .whisper/proxy.env — and does NOT write a
// .claude/settings.local.json (that is Claude-only).
func TestInitPython_ExistingAgent_WritesProxyEnv(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	if err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("runInitPython: %v", err)
	}
	p := projcfg.PathsFor(dir)

	cfg, lerr := projcfg.Load(p)
	if lerr != nil || cfg == nil || cfg.Agent != "2a04:2a01:9::abcd" {
		t.Fatalf("config not written correctly: %+v (%v)", cfg, lerr)
	}

	// proxy.env carries the CONNECT-form proxy pointing at the config's port.
	body := readFileTrim(t, p.ProxyEnvFile)
	wantHTTP := "HTTP_PROXY=http://127.0.0.1:" + itoaTest(cfg.Port)
	wantSocks := "ALL_PROXY=socks5h://127.0.0.1:" + itoaTest(cfg.Port)
	if !strings.Contains(body, wantHTTP) || !strings.Contains(body, wantSocks) {
		t.Fatalf("proxy.env wrong:\n%s", body)
	}

	// It must NOT have written Claude Code settings.
	if _, err := os.Stat(p.ClaudeLocal); !os.IsNotExist(err) {
		t.Fatalf("init python must not write .claude/settings.local.json")
	}

	// .gitignore got ONLY .whisper/ (not the Claude settings line).
	gi := readFileTrim(t, p.GitignoreFile)
	if !strings.Contains(gi, ".whisper/") || strings.Contains(gi, ".claude/settings.local.json") {
		t.Fatalf(".gitignore wrong for python:\n%s", gi)
	}
}

// TestInitPython_NeverClobbersUserDotEnv: a pre-existing user ./.env holding secrets is
// byte-identical after `init python` (we own .whisper/proxy.env, never ./.env).
func TestInitPython_NeverClobbersUserDotEnv(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	userEnv := filepath.Join(dir, ".env")
	const secret = "OPENAI_API_KEY=sk-secret\nDATABASE_URL=postgres://u:p@h/db\n"
	if err := os.WriteFile(userEnv, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	// Run twice (incl. --force) — the most dangerous path — and assert ./.env is untouched both times.
	if err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("init python: %v", err)
	}
	if err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir, force: true}); err != nil {
		t.Fatalf("init python --force: %v", err)
	}
	if got := readFileTrim(t, userEnv); got != strings.TrimSpace(secret) {
		t.Fatalf("user ./.env was modified:\n%s", got)
	}
}

// TestInitPython_NoAgentFileFlag: the python command deliberately omits --agent-file (the flag
// that, reused from init claude, could redirect a write/remove onto a user file). --agent and
// --name remain.
func TestInitPython_NoAgentFileFlag(t *testing.T) {
	cmd := newInitEnvToolCmd(pythonProfile())
	if f := cmd.Flags().Lookup("agent-file"); f != nil {
		t.Fatalf("init python must NOT expose --agent-file (clobber risk)")
	}
	for _, want := range []string{"agent", "name", "tier", "dir", "force"} {
		if cmd.Flags().Lookup(want) == nil {
			t.Fatalf("init python missing expected flag --%s", want)
		}
	}
}

// TestEnvToolProfiles_RegisterCleanly: every env-tool profile builds a valid subcommand with the
// expected flags and NO --agent-file (the clobber-risk flag), and the expected tools are present.
func TestEnvToolProfiles_RegisterCleanly(t *testing.T) {
	want := map[string]bool{"python": false, "gemini": false, "aider": false, "ai-sdk": false}
	for _, prof := range envToolProfiles() {
		if _, ok := want[prof.name]; !ok {
			continue
		}
		want[prof.name] = true
		cmd := newInitEnvToolCmd(prof)
		if cmd.Use != prof.name {
			t.Fatalf("profile %q built command Use=%q", prof.name, cmd.Use)
		}
		if cmd.Flags().Lookup("agent-file") != nil {
			t.Fatalf("init %s must NOT expose --agent-file", prof.name)
		}
		if cmd.Flags().Lookup("agent") == nil || cmd.Flags().Lookup("tier") == nil {
			t.Fatalf("init %s missing core flags", prof.name)
		}
		if prof.runExample == "" || prof.covers == "" {
			t.Fatalf("profile %q missing runExample/covers", prof.name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("expected env-tool profile %q to be registered", name)
		}
	}
}

// TestRecipeProfiles_HaveRecipes: the Node/browser targets carry a printed code recipe (they do
// NOT auto-read proxy env) and register with their aliases.
func TestRecipeProfiles_HaveRecipes(t *testing.T) {
	want := map[string]bool{"browser-use": false, "discord": false, "telegram": false}
	for _, prof := range envToolProfiles() {
		if _, ok := want[prof.name]; !ok {
			continue
		}
		want[prof.name] = true
		if len(prof.recipe) == 0 {
			t.Fatalf("%s must carry a code recipe (frameworks don't auto-read proxy env)", prof.name)
		}
		if cmd := newInitEnvToolCmd(prof); cmd.Flags().Lookup("agent-file") != nil {
			t.Fatalf("init %s must NOT expose --agent-file", prof.name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("expected recipe profile %q registered", name)
		}
	}
}

// TestInitNotebook_WritesProxyEnvAndCell: `init notebook` wires proxy.env + config and the cell
// renderer interpolates the actual port.
func TestInitNotebook_WritesProxyEnvAndCell(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	if err := runInitNotebook(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("runInitNotebook: %v", err)
	}
	p := projcfg.PathsFor(dir)
	cfg, _ := projcfg.Load(p)
	if cfg == nil {
		t.Fatal("no config written")
	}
	cell := strings.Join(notebookCell(cfg.Port), "\n")
	if !strings.Contains(cell, itoaTest(cfg.Port)) || !strings.Contains(cell, "os.environ.update") {
		t.Fatalf("notebook cell missing port/os.environ:\n%s", cell)
	}
	if strings.Contains(cell, "whisper_live_") && !strings.Contains(cell, "whisper_live_xxx") {
		t.Fatalf("notebook cell must only use the redacted key placeholder")
	}
}

// TestInitGemini_WritesProxyEnv: a non-python env-tool (gemini) writes the same wholly-owned
// proxy.env + config and does NOT touch .claude/.
func TestInitGemini_WritesProxyEnv(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	var gemini envToolProfile
	for _, p := range envToolProfiles() {
		if p.name == "gemini" {
			gemini = p
		}
	}
	if err := runInitEnvTool(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}, gemini); err != nil {
		t.Fatalf("runInitEnvTool gemini: %v", err)
	}
	p := projcfg.PathsFor(dir)
	body := readFileTrim(t, p.ProxyEnvFile)
	if !strings.Contains(body, "HTTPS_PROXY=http://127.0.0.1:") || !strings.Contains(body, "NODE_USE_ENV_PROXY=1") {
		t.Fatalf("gemini proxy.env wrong:\n%s", body)
	}
	if _, err := os.Stat(p.ClaudeLocal); !os.IsNotExist(err) {
		t.Fatalf("init gemini must not write .claude/settings.local.json")
	}
}

// TestInitPython_IdempotentReusesPort: a second init on the same dir reuses the deterministic
// port and rewrites a byte-identical proxy.env.
func TestInitPython_IdempotentReusesPort(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()

	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	if err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("first: %v", err)
	}
	p := projcfg.PathsFor(dir)
	cfg1, _ := projcfg.Load(p)
	env1 := readFileTrim(t, p.ProxyEnvFile)

	if err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("re-init: %v", err)
	}
	cfg2, _ := projcfg.Load(p)
	env2 := readFileTrim(t, p.ProxyEnvFile)

	if cfg1.Port != cfg2.Port {
		t.Fatalf("re-init changed the port: %d → %d", cfg1.Port, cfg2.Port)
	}
	if env1 != env2 {
		t.Fatalf("re-init produced a different proxy.env")
	}
}

// TestInitPython_RefusesPlantedNamespaceSymlink: a cloned/malicious repo that ships a leaf
// symlink inside .whisper/ pointing at a user file (e.g. `.whisper/config -> ../.env`) must NOT
// let `init python` read-exfiltrate or write-clobber it — AssertSafeNamespace refuses up front and
// the user's ./.env stays byte-identical. Covers the default (no --force) path.
func TestInitPython_RefusesPlantedNamespaceSymlink(t *testing.T) {
	for _, leaf := range []string{"config", "agent"} {
		t.Run(leaf, func(t *testing.T) {
			srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
			defer srv.Close()
			defer stubEnsureDaemon(t)()

			dir := t.TempDir()
			userEnv := filepath.Join(dir, ".env")
			const secret = "OPENAI_API_KEY=sk-do-not-touch\n"
			if err := os.WriteFile(userEnv, []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, ".whisper"), 0o700); err != nil {
				t.Fatal(err)
			}
			// Plant the hostile leaf symlink pointing back at the user's ./.env.
			if err := os.Symlink("../.env", filepath.Join(dir, ".whisper", leaf)); err != nil {
				t.Skipf("symlinks unsupported: %v", err)
			}

			savedG := g
			g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
			defer func() { g = savedG }()

			err := runInitPython(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir})
			if err == nil {
				t.Fatalf("init python must refuse a planted .whisper/%s symlink", leaf)
			}
			if got := readFileTrim(t, userEnv); got != strings.TrimSpace(secret) {
				t.Fatalf("user ./.env was touched via .whisper/%s symlink: %q", leaf, got)
			}
		})
	}
}

// TestRun_ExplicitFlagOverridesProjectConfig: an explicit --agent (and --tier) still WINS over a
// project .whisper/config (the project-aware default must not override an explicit choice).
func TestRun_ExplicitFlagOverridesProjectConfig(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()

	dir := t.TempDir()
	p := projcfg.PathsFor(dir)
	if err := projcfg.Save(p, projcfg.Config{Agent: "2a04:2a01:9::beef", Tier: "socks5", Port: 28000}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	_ = runWithEgress("2a04:2a01:9::cafe", "", "", "true", nil)
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("no op:connect recorded, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "2a04:2a01:9::cafe") || strings.Contains(body, "2a04:2a01:9::beef") {
		t.Fatalf("explicit --agent must override project config; connect body = %q", body)
	}
}

// TestRun_PrefersProjectConfigAgent: after `init python` (which writes .whisper/config), a bare
// `whisper run` from inside the project must egress as the PROJECT agent — not the global default.
func TestRun_PrefersProjectConfigAgent(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()

	dir := t.TempDir()
	// Hand-write a project config pinning a specific agent /128.
	p := projcfg.PathsFor(dir)
	if err := projcfg.Save(p, projcfg.Config{Agent: "2a04:2a01:9::beef", Tier: "socks5", Port: 28000}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // discoverProjectConfig walks up from the cwd

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	// No explicit --agent: must adopt the project config's agent.
	if err := runWithEgress("", "", "", "true", nil); err != nil {
		// `true` may not exist on all platforms; the connect body is what we assert.
		_ = err
	}
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("no op:connect recorded, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "2a04:2a01:9::beef") {
		t.Fatalf("run did not adopt the project agent; connect body = %q", body)
	}
}
