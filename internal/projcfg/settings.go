// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// settings.go performs the SURGICAL merge of Whisper-managed keys into Claude Code's
// per-user LOCAL settings file (`.claude/settings.local.json` — gitignored, this-machine
// only; NEVER the shared `.claude/settings.json`). The whole point is to be conservative
// in what we WRITE: we read the existing JSON into a generic map, set/update ONLY the
// keys we own, and write everything else back BYTE-for-VALUE unchanged — a user's
// permissions, model, other hooks, other env vars all survive untouched.
//
// What we own:
//   - env.HTTP_PROXY / env.HTTPS_PROXY  = http://127.0.0.1:<port>  (Claude Code speaks
//     HTTP-CONNECT, not SOCKS — the local proxy serves both, we point CC at the CONNECT form)
//   - env.ALL_PROXY                     = socks5h://127.0.0.1:<port>  (for any SOCKS-aware
//     subprocess CC spawns — git/curl/Bash tools)
//   - env.NO_PROXY                      = localhost,127.0.0.1,::1
//   - hooks.SessionStart                = a best-effort `whisper connect --ensure` re-ensure
//     (the daemon is started by init and stays up; this is the safety-net re-ensure that
//     CANNOT block startup but runs before the first API call).

// whisperHookMarker tags the SessionStart hook command we manage so a re-init updates it
// in place (and never duplicates it) and a teardown can find it. It is a literal substring
// of the command string.
const whisperHookMarker = "whisper connect --ensure"

// SettingsResult reports what MergeClaudeSettings did, so the caller can print an honest
// summary and WARN about a conflict instead of silently overriding it.
type SettingsResult struct {
	Created          bool     // the settings file did not exist and we created it
	ConflictingProxy []string // pre-existing env proxy vars whose value differed from ours (warned, then overridden)
}

// Conflicts returns the names of pre-existing proxy env vars we overrode (a conflict the
// caller WARNs about). Exposed as a method so callers in other packages can read it without
// depending on the field layout.
func (r SettingsResult) Conflicts() []string { return r.ConflictingProxy }

// MergeClaudeSettings reads `.claude/settings.local.json` (creating `.claude/` if needed),
// sets ONLY the Whisper-managed env keys + the SessionStart ensure-hook for the given port,
// preserves every other key, and writes it back pretty-printed (mode 0600). Re-running it is
// idempotent: the managed keys are updated in place, never duplicated.
//
// configRel is the project-relative path to the `.whisper/config` the ensure-hook reads
// (so the hook is location-independent — it cds to the project and points --config at it).
func MergeClaudeSettings(p Paths, port int, configRel string) (SettingsResult, error) {
	var res SettingsResult

	if err := os.MkdirAll(p.ClaudeDir, 0o700); err != nil {
		return res, fmt.Errorf("could not create %s: %w", p.ClaudeDir, err)
	}

	root := map[string]any{}
	if b, err := os.ReadFile(p.ClaudeLocal); err == nil {
		if len(strings.TrimSpace(string(b))) > 0 {
			if uerr := json.Unmarshal(b, &root); uerr != nil {
				// A corrupt settings file is the ONE place we refuse to plough on: silently
				// overwriting it would destroy the user's other settings. Fail with a clear,
				// actionable message (Postel: never an opaque 500).
				return res, fmt.Errorf("%s is not valid JSON — fix or remove it, then re-run: %w", p.ClaudeLocal, uerr)
			}
		}
	} else if os.IsNotExist(err) {
		res.Created = true
	} else {
		return res, fmt.Errorf("could not read %s: %w", p.ClaudeLocal, err)
	}

	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	socks := fmt.Sprintf("socks5h://127.0.0.1:%d", port)

	res.ConflictingProxy = mergeEnv(root, map[string]string{
		"HTTP_PROXY":  endpoint,
		"HTTPS_PROXY": endpoint,
		"ALL_PROXY":   socks,
		"NO_PROXY":    "localhost,127.0.0.1,::1",
	})

	mergeSessionStartHook(root, ensureHookCommand(configRel))

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return res, err
	}
	out = append(out, '\n')
	if err := os.WriteFile(p.ClaudeLocal, out, 0o600); err != nil {
		return res, fmt.Errorf("could not write %s: %w", p.ClaudeLocal, err)
	}
	return res, nil
}

// ensureHookCommand is the shell command the SessionStart hook runs: re-ensure the daemon
// from the project dir, pointed at the project's `.whisper/config`. It is silent and
// best-effort (a hook cannot block startup) — `connect --ensure` is idempotent, so a live
// daemon is a fast no-op and a dead one is restarted before the first API call. We pass
// --config so the hook works regardless of the cwd Claude Code launches it in.
func ensureHookCommand(configRel string) string {
	// Forward-slash the relative path so the command string is identical across OSes (the
	// CLI's --config accepts forward slashes everywhere; Windows is happy with them too).
	cfg := filepath.ToSlash(configRel)
	return fmt.Sprintf("whisper connect --ensure --config %q --quiet", cfg)
}

// mergeEnv sets the managed proxy vars on root["env"], preserving any OTHER env vars the
// user set. It returns the names of pre-existing managed vars whose value DIFFERED from
// ours — those are a real conflict the caller WARNS about (we still override, because a
// stale/hostile proxy var must never win — same rule as run.go's proxyInjectedEnv).
func mergeEnv(root map[string]any, managed map[string]string) []string {
	env, _ := root["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	var conflicts []string
	for k, v := range managed {
		if old, ok := env[k]; ok {
			if s, isStr := old.(string); isStr && s != "" && s != v {
				conflicts = append(conflicts, k)
			}
		}
		env[k] = v
	}
	root["env"] = env
	return conflicts
}

// mergeSessionStartHook installs/updates the Whisper ensure-hook under hooks.SessionStart,
// preserving every other hook the user has. Claude Code's hooks schema is:
//
//	"hooks": { "SessionStart": [ { "hooks": [ {"type":"command","command":"…"} ] } ] }
//
// We find OUR hook by the whisperHookMarker substring and update its command in place; if
// none exists we append a new matcher group carrying just our hook. A re-init thus updates
// (e.g. a changed port flows into the --config path? no — the command is port-independent,
// but we still rewrite it to the canonical form) and never duplicates.
func mergeSessionStartHook(root map[string]any, command string) {
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	groups, _ := hooks["SessionStart"].([]any)

	// Try to update OUR hook in place anywhere in the existing groups.
	updated := false
	for _, g := range groups {
		grp, ok := g.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := grp["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, whisperHookMarker) {
				hm["command"] = command
				hm["type"] = "command"
				updated = true
			}
		}
	}

	if !updated {
		groups = append(groups, map[string]any{
			"hooks": []any{
				map[string]any{"type": "command", "command": command},
			},
		})
	}

	hooks["SessionStart"] = groups
	root["hooks"] = hooks
}
