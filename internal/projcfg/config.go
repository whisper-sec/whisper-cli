// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package projcfg owns the PER-PROJECT Whisper state that `whisper init claude` writes and
// `whisper connect --ensure` reads: the `.whisper/` directory at a project root holding the
// machine-readable `config` (agent /128, tier, the deterministic local proxy port) and the
// detached daemon's `connect.pid`. It also merges the Whisper-managed keys into Claude Code's
// per-user `.claude/settings.local.json` without ever clobbering a user's other settings.
//
// Everything here is pure, multiplatform Go (filepath.Join, map[string]any JSON merge,
// FNV-derived deterministic port + free-probe) so the same project always resolves to the
// same port across runs and across linux/macOS/windows. Files are written mode 0600
// (directories 0700) — the config never holds a secret (only the /128 + tier + port), but we
// keep the same tight perms the key/agent files use for consistency.
package projcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SchemaVersion is the `.whisper/config` schema version. Bumped only on an incompatible
// shape change; a reader tolerates an OLDER/UNKNOWN version (Postel: liberal-accept) and
// fills sensible defaults rather than erroring.
const SchemaVersion = 1

// Dir is the per-project Whisper directory name (relative to the project root).
const Dir = ".whisper"

const (
	configName   = "config"
	pidName      = "connect.pid"
	proxyEnvName = "proxy.env"
)

// Config is the machine-readable `.whisper/config` shape. It carries ONLY non-secret
// identity + connectivity facts: the agent's /128, the egress tier, and the deterministic
// local proxy port. The bearer/WG private key are NEVER persisted here (they live only in
// the daemon process memory, per the bearer-hygiene contract).
type Config struct {
	SchemaVersion int    `json:"schemaVersion"`
	Agent         string `json:"agent"`          // the agent's /128 (or a selector the daemon re-resolves)
	Tier          string `json:"tier"`           // "socks5" (default) | "wireguard"
	Port          int    `json:"port"`           // the deterministic local loopback proxy port
	FQDN          string `json:"fqdn,omitempty"` // the agent's canonical name (display only)
}

// Paths bundles the resolved absolute paths for one project root, so callers never re-derive
// them (and so tests can point a whole run at a temp dir). Root is the project directory the
// user ran `whisper init` in.
type Paths struct {
	Root          string // the project root (where the user ran init)
	WhisperDir    string // <root>/.whisper
	ConfigFile    string // <root>/.whisper/config
	PIDFile       string // <root>/.whisper/connect.pid
	ProxyEnvFile  string // <root>/.whisper/proxy.env (dotenv proxy block — `whisper init python`)
	ClaudeDir     string // <root>/.claude
	ClaudeLocal   string // <root>/.claude/settings.local.json
	GitignoreFile string // <root>/.gitignore
}

// PathsFor resolves every per-project path under root. root is cleaned to an absolute path
// when possible (so the deterministic port — derived from the abs path — is stable regardless
// of how the user spelled the directory). A non-absolute or unresolvable root is used as-is
// (best-effort; init still works, the port is just derived from what we were given).
func PathsFor(root string) Paths {
	abs, err := filepath.Abs(root)
	if err == nil {
		root = abs
	}
	root = filepath.Clean(root)
	whisper := filepath.Join(root, Dir)
	claude := filepath.Join(root, ".claude")
	return Paths{
		Root:          root,
		WhisperDir:    whisper,
		ConfigFile:    filepath.Join(whisper, configName),
		PIDFile:       filepath.Join(whisper, pidName),
		ProxyEnvFile:  filepath.Join(whisper, proxyEnvName),
		ClaudeDir:     claude,
		ClaudeLocal:   filepath.Join(claude, "settings.local.json"),
		GitignoreFile: filepath.Join(root, ".gitignore"),
	}
}

// AssertSafeNamespace verifies the per-project `.whisper/` namespace is real and self-contained
// BEFORE any init target reads or writes inside it. It is the single guard every
// `whisper init <tool>` calls first, so the never-clobber-a-user-file invariant holds on the
// DEFAULT path — not merely inside one writer.
//
// Two escapes it closes: (1) a symlinked `.whisper` directory (`.whisper -> /outside`) would let
// every "namespaced" read/write land outside; (2) a planted leaf symlink (`.whisper/config` or
// `.whisper/agent -> ../.env`, which git can ship in a cloned repo) would let a plain read
// EXFILTRATE a user's secrets (ReadAgentFile/Load follow the link) or a plain write CLOBBER them
// (SaveAgent/Save use O_TRUNC, which follows a leaf symlink). We refuse with a clear, actionable
// error rather than an opaque failure (Postel: never a surprise, never an opaque 500).
func AssertSafeNamespace(p Paths) error {
	// (1) The directory: if it exists, it must be a real directory, not a symlink — and must
	// still resolve to a path inside the project root (defense against a symlinked component).
	if fi, err := os.Lstat(p.WhisperDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink — refusing to use it (remove it and re-run)", p.WhisperDir)
		}
		if real, rerr := filepath.EvalSymlinks(p.WhisperDir); rerr == nil {
			if root, perr := filepath.EvalSymlinks(p.Root); perr == nil {
				if rel, relErr := filepath.Rel(root, real); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fmt.Errorf("%s resolves outside the project — refusing to use it", p.WhisperDir)
				}
			}
		}
	}
	// (2) The leaf files we read or write: none may be a symlink.
	for _, f := range []string{p.ConfigFile, p.PIDFile, p.ProxyEnvFile, filepath.Join(p.WhisperDir, "agent")} {
		if err := refuseSymlink(f); err != nil {
			return err
		}
	}
	return nil
}

// Load reads + decodes `.whisper/config` at p.ConfigFile. A missing file returns (nil, nil) —
// "no project config" is not an error; the caller decides whether that is fatal. A present but
// malformed file IS an error (a clear, actionable one — never an opaque decode panic).
func Load(p Paths) (*Config, error) {
	b, err := os.ReadFile(p.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("could not read %s: %w", p.ConfigFile, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s is corrupt (re-run `whisper init claude --force`): %w", p.ConfigFile, err)
	}
	// Liberal-accept: normalise the tier; default a blank one to socks5.
	c.Tier = normalizeTier(c.Tier)
	return &c, nil
}

// Save writes `.whisper/config` (mode 0600, dir 0700), creating `.whisper/` as needed. It
// stamps the current SchemaVersion and normalises the tier so a written file is always
// canonical. Idempotent: re-saving overwrites cleanly (init re-run updates, never duplicates).
func Save(p Paths, c Config) error {
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		return fmt.Errorf("could not create %s: %w", p.WhisperDir, err)
	}
	c.SchemaVersion = SchemaVersion
	c.Tier = normalizeTier(c.Tier)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// Never follow a symlinked target (a planted .whisper/config -> ../.env would otherwise be
	// truncated), and write atomically (temp+rename) so a crash can't leave a half file.
	if err := refuseSymlink(p.ConfigFile); err != nil {
		return err
	}
	if err := writeFileAtomic(p.ConfigFile, b, 0o600); err != nil {
		return err
	}
	return nil
}

// normalizeTier maps a user-supplied tier string to the canonical token. Liberal-accept
// (Postel): trimmed + lower-cased, with "wg" as a friendly alias for wireguard; anything
// blank or unrecognised collapses to the safe default, "socks5".
func normalizeTier(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "wireguard", "wg":
		return "wireguard"
	default:
		return "socks5"
	}
}

// ValidTier reports whether tier (after normalisation) is a tier we support — used by the
// init command to reject a typo'd --tier with a clear error rather than silently defaulting.
func ValidTier(tier string) bool {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "", "socks5", "wireguard", "wg":
		return true
	default:
		return false
	}
}

// NormalizeTier is the exported form of normalizeTier (the init command needs it to echo the
// canonical tier it persisted).
func NormalizeTier(tier string) string { return normalizeTier(tier) }
