// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// readSettings loads .claude/settings.local.json as a generic map (the shape the merge
// preserves) for assertions.
func readSettings(t *testing.T, p Paths) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p.ClaudeLocal)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("settings is not valid JSON: %v\n%s", err, b)
	}
	return m
}

// TestMerge_CreatesEnvAndHookFromScratch: on a fresh project the merge writes the managed env
// (HTTP(S)_PROXY = http://, ALL_PROXY = socks5h://, NO_PROXY) and a SessionStart ensure-hook.
func TestMerge_CreatesEnvAndHookFromScratch(t *testing.T) {
	p := PathsFor(t.TempDir())
	res, err := MergeClaudeSettings(p, 28080, ".whisper/config")
	if err != nil {
		t.Fatalf("MergeClaudeSettings: %v", err)
	}
	if !res.Created {
		t.Fatal("expected Created=true for a fresh project")
	}

	m := readSettings(t, p)
	env, _ := m["env"].(map[string]any)
	if env == nil {
		t.Fatal("missing env block")
	}
	want := map[string]string{
		"HTTP_PROXY":  "http://127.0.0.1:28080",
		"HTTPS_PROXY": "http://127.0.0.1:28080",
		"ALL_PROXY":   "socks5h://127.0.0.1:28080",
		"NO_PROXY":    "localhost,127.0.0.1,::1",
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("env[%q] = %v, want %q", k, env[k], v)
		}
	}

	// The SessionStart hook runs `whisper connect --ensure` and points at the config.
	if cmd := firstSessionStartCommand(t, m); !strings.Contains(cmd, whisperHookMarker) || !strings.Contains(cmd, ".whisper/config") {
		t.Fatalf("SessionStart hook command = %q, want it to run the ensure with --config", cmd)
	}
}

// TestMerge_PreservesExistingKeys: every non-Whisper key the user set survives the merge —
// other env vars, permissions, model, and OTHER SessionStart hooks.
func TestMerge_PreservesExistingKeys(t *testing.T) {
	p := PathsFor(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pre := map[string]any{
		"model": "example-model",
		"permissions": map[string]any{
			"allow": []any{"Bash(ls:*)"},
		},
		"env": map[string]any{
			"FOO":           "bar",
			"EXAMPLE_MODEL": "x",
		},
		"hooks": map[string]any{
			"SessionStart": []any{
				map[string]any{
					"hooks": []any{
						map[string]any{"type": "command", "command": "echo user-hook"},
					},
				},
			},
		},
	}
	b, _ := json.MarshalIndent(pre, "", "  ")
	if err := os.WriteFile(p.ClaudeLocal, b, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := MergeClaudeSettings(p, 30000, ".whisper/config"); err != nil {
		t.Fatalf("merge: %v", err)
	}

	m := readSettings(t, p)
	// Top-level non-Whisper keys preserved.
	if m["model"] != "example-model" {
		t.Fatalf("model clobbered: %v", m["model"])
	}
	if _, ok := m["permissions"]; !ok {
		t.Fatal("permissions block was dropped")
	}
	// Other env vars preserved + ours added.
	env := m["env"].(map[string]any)
	if env["FOO"] != "bar" || env["EXAMPLE_MODEL"] != "x" {
		t.Fatalf("existing env vars dropped: %v", env)
	}
	if env["HTTP_PROXY"] != "http://127.0.0.1:30000" {
		t.Fatalf("managed env not set: %v", env)
	}
	// The user's OTHER SessionStart hook survives AND ours is added (2 groups now).
	groups := sessionStartGroups(t, m)
	if len(groups) != 2 {
		t.Fatalf("expected the user's hook + ours = 2 SessionStart groups, got %d: %v", len(groups), groups)
	}
	if !hasCommandSubstring(groups, "echo user-hook") {
		t.Fatal("the user's existing SessionStart hook was dropped")
	}
	if !hasCommandSubstring(groups, whisperHookMarker) {
		t.Fatal("the whisper ensure hook was not added")
	}
}

// TestMerge_ReinitUpdatesNotDuplicates: running the merge twice (e.g. a re-init on a new port)
// updates the managed env + hook IN PLACE — it never duplicates the env keys or the hook.
func TestMerge_ReinitUpdatesNotDuplicates(t *testing.T) {
	p := PathsFor(t.TempDir())
	if _, err := MergeClaudeSettings(p, 28080, ".whisper/config"); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	if _, err := MergeClaudeSettings(p, 29090, ".whisper/config"); err != nil {
		t.Fatalf("second merge: %v", err)
	}

	m := readSettings(t, p)
	// Env updated to the new port (not duplicated — a map can't duplicate a key, but assert the
	// VALUE is the latest).
	env := m["env"].(map[string]any)
	if env["HTTP_PROXY"] != "http://127.0.0.1:29090" {
		t.Fatalf("env not updated on re-merge: %v", env["HTTP_PROXY"])
	}
	// Exactly ONE SessionStart group, with exactly ONE whisper hook (no duplication).
	groups := sessionStartGroups(t, m)
	if len(groups) != 1 {
		t.Fatalf("re-merge duplicated SessionStart groups: %d", len(groups))
	}
	count := 0
	for _, g := range groups {
		for _, h := range g["hooks"].([]any) {
			if cmd, _ := h.(map[string]any)["command"].(string); strings.Contains(cmd, whisperHookMarker) {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("the whisper hook was duplicated on re-merge: %d copies", count)
	}
}

// TestMerge_ConflictingProxyWarns: a pre-existing managed proxy var with a DIFFERENT value is
// reported as a conflict (the caller warns) — and still overridden (a stale/hostile value
// must never win).
func TestMerge_ConflictingProxyWarns(t *testing.T) {
	p := PathsFor(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pre := map[string]any{"env": map[string]any{"HTTPS_PROXY": "http://attacker:9"}}
	b, _ := json.Marshal(pre)
	if err := os.WriteFile(p.ClaudeLocal, b, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := MergeClaudeSettings(p, 28080, ".whisper/config")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(res.ConflictingProxy) == 0 {
		t.Fatal("a pre-existing conflicting proxy var must be reported")
	}
	found := false
	for _, c := range res.ConflictingProxy {
		if c == "HTTPS_PROXY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HTTPS_PROXY in the conflict list, got %v", res.ConflictingProxy)
	}
	// And it was still overridden (conservative-emit: the managed value wins).
	m := readSettings(t, p)
	if m["env"].(map[string]any)["HTTPS_PROXY"] != "http://127.0.0.1:28080" {
		t.Fatal("the conflicting proxy var was not overridden with ours")
	}
}

// TestMerge_NoConflictWhenValueMatches: re-running with the SAME port is NOT a conflict (the
// value already equals ours), so no spurious warning.
func TestMerge_NoConflictWhenValueMatches(t *testing.T) {
	p := PathsFor(t.TempDir())
	if _, err := MergeClaudeSettings(p, 28080, ".whisper/config"); err != nil {
		t.Fatal(err)
	}
	res, err := MergeClaudeSettings(p, 28080, ".whisper/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ConflictingProxy) != 0 {
		t.Fatalf("a value equal to ours must not be a conflict, got %v", res.ConflictingProxy)
	}
}

// TestMerge_CorruptSettingsIsError: a corrupt settings.local.json is refused (overwriting it
// would destroy the user's other settings) with a clear error.
func TestMerge_CorruptSettingsIsError(t *testing.T) {
	p := PathsFor(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ClaudeLocal, []byte("{ broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MergeClaudeSettings(p, 28080, ".whisper/config"); err == nil {
		t.Fatal("a corrupt settings file must be a clear error, not silently overwritten")
	}
}

// --- helpers ---------------------------------------------------------------------------

func sessionStartGroups(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	hooks, _ := m["hooks"].(map[string]any)
	if hooks == nil {
		return nil
	}
	raw, _ := hooks["SessionStart"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, g := range raw {
		if grp, ok := g.(map[string]any); ok {
			out = append(out, grp)
		}
	}
	return out
}

func firstSessionStartCommand(t *testing.T, m map[string]any) string {
	t.Helper()
	for _, g := range sessionStartGroups(t, m) {
		for _, h := range g["hooks"].([]any) {
			if cmd, _ := h.(map[string]any)["command"].(string); cmd != "" {
				return cmd
			}
		}
	}
	return ""
}

func hasCommandSubstring(groups []map[string]any, sub string) bool {
	for _, g := range groups {
		inner, _ := g["hooks"].([]any)
		for _, h := range inner {
			if cmd, _ := h.(map[string]any)["command"].(string); strings.Contains(cmd, sub) {
				return true
			}
		}
	}
	return false
}
