// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// DefaultKeyFile is the on-disk key location, mirroring the shell CLI + installer:
// $HOME/.config/whisper/key (mode 600).
func DefaultKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "key")
	}
	return filepath.Join(home, ".config", "whisper", "key")
}

// DefaultAgentFile is the on-disk location of the CHOSEN agent id, mirroring
// DefaultKeyFile: $HOME/.config/whisper/agent (mode 600). install.sh writes the agent
// the user picked/created here so `connect` binds egress to THAT identity with zero extra
// config; absent ⇒ the server's reuse-most-recent default applies (still zero-config).
func DefaultAgentFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "agent")
	}
	return filepath.Join(home, ".config", "whisper", "agent")
}

// ReadAgentFile returns the persisted CHOSEN agent id (trimmed), or "" when the file is
// absent/empty/unreadable. Liberal + fail-soft: a missing agent file is NOT an error - it
// simply means "no pinned agent", and the caller falls back to the most-recent default.
// When path is empty, DefaultAgentFile() is used.
func ReadAgentFile(path string) string {
	if path == "" {
		path = DefaultAgentFile()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SaveAgent writes the chosen agent id to an owner-only file in an owner-only directory,
// creating parents as needed - mirrors SaveKey. An empty id removes the pin (so a later
// reuse-most-recent default applies) rather than persisting a blank.
//
// The agent id is not a secret the way the key is, but it names the /128 this host answers
// as, and a file that tells every account on the box which identity to impersonate is a
// reconnaissance gift. It rides the same writer for the same reason.
func SaveAgent(path, agent string) error {
	if path == "" {
		path = DefaultAgentFile()
	}
	agent = strings.TrimSpace(agent)
	if agent == "" {
		// No pin to persist: remove any stale file so the most-recent default takes over.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	dir := filepath.Dir(path)
	if err := secfile.MkdirAll(dir); err != nil {
		return err
	}
	return secfile.WriteFile(path, []byte(agent))
}

// KeySource describes where a resolved credential came from - surfaced in `config`/
// diagnostics so an operator can see WHICH key the CLI will use (zero-config clarity).
type KeySource string

const (
	SourceFlag   KeySource = "flag"        // --key
	SourceBearer KeySource = "bearer-flag" // --bearer (an et_ monitor token)
	SourceEnvKey KeySource = "WHISPER_API_KEY"
	SourceEnvAlt KeySource = "WHISPER_KEY"
	SourceFile   KeySource = "key-file"
	SourcePrompt KeySource = "prompt"
	SourceNone   KeySource = "none"
)

// Credential is a resolved principal: either an X-API-Key (owner key) or an et_ Bearer
// (a read-only monitor token from op:token). Exactly one auth header is sent.
type Credential struct {
	Value  string
	Bearer bool // true => send "Authorization: Bearer <Value>"; false => "X-API-Key: <Value>"
	Source KeySource
}

// IsZero reports an unresolved credential.
func (c Credential) IsZero() bool { return c.Value == "" }

// KeyLadderOptions carries the explicit, highest-precedence inputs (the flags) plus a
// switch to disable the interactive prompt (for non-TTY / scriptable runs).
type KeyLadderOptions struct {
	FlagKey    string // --key (an owner key, sent as X-API-Key)
	FlagBearer string // --bearer (an et_ monitor token, sent as Authorization: Bearer)
	KeyFile    string // override the on-disk key path; empty => DefaultKeyFile()
	AllowEnv   bool   // consult WHISPER_API_KEY / WHISPER_KEY (default true)
	AllowFile  bool   // consult the key file (default true)
	// Prompt, when non-nil and a usable terminal exists, is called as the LAST resort.
	// It must return the entered key (or "" if none). Leave nil for non-interactive runs.
	Prompt func() (string, error)
}

// ResolveCredential walks the key ladder in strict precedence order and returns the
// first credential it finds:
//
// 1. --bearer flag (et_ monitor token -> Authorization: Bearer)
// 2. --key flag (owner key -> X-API-Key)
// 3. WHISPER_API_KEY env
// 4. WHISPER_KEY env (the alias the shell CLI also honoured)
// 5. ~/.config/whisper/key (mode-600 file)
// 6. interactive prompt (only when opts.Prompt != nil AND it yields a value)
//
// Conservative+liberal: try every place a key could legitimately live; prompt only
// when one is offered, never an opaque hang. Returns a SourceNone credential (not an
// error) when nothing is found - the caller renders the helpful "no key" guidance.
func ResolveCredential(opts KeyLadderOptions) (Credential, error) {
	// 1. --bearer (an explicit monitor token wins; it pins a read-only stream).
	if v := strings.TrimSpace(opts.FlagBearer); v != "" {
		return Credential{Value: v, Bearer: true, Source: SourceBearer}, nil
	}
	// 2. --key.
	if v := strings.TrimSpace(opts.FlagKey); v != "" {
		return Credential{Value: v, Source: SourceFlag}, nil
	}
	// 3 & 4. environment.
	if opts.AllowEnv {
		if v := strings.TrimSpace(os.Getenv("WHISPER_API_KEY")); v != "" {
			return Credential{Value: v, Source: SourceEnvKey}, nil
		}
		if v := strings.TrimSpace(os.Getenv("WHISPER_KEY")); v != "" {
			return Credential{Value: v, Source: SourceEnvAlt}, nil
		}
	}
	// 5. the key file.
	if opts.AllowFile {
		path := opts.KeyFile
		if path == "" {
			path = DefaultKeyFile()
		}
		if b, err := os.ReadFile(path); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return Credential{Value: v, Source: SourceFile}, nil
			}
		}
	}
	// 6. interactive prompt (last resort).
	if opts.Prompt != nil {
		v, err := opts.Prompt()
		if err != nil {
			return Credential{Source: SourceNone}, err
		}
		if v = strings.TrimSpace(v); v != "" {
			return Credential{Value: v, Source: SourcePrompt}, nil
		}
	}
	return Credential{Source: SourceNone}, nil
}

// SaveKey writes key to the key file as an owner-only file in an owner-only
// directory, creating parents as needed - used by `whisper login`.
//
// This is the one file on the machine that holds a live API key, so the write
// goes through secfile rather than through os.WriteFile at 0o600: the
// mode argument is the whole control on unix and controls nothing at all on
// Windows, where the file would otherwise inherit the containing directory's
// DACL and, under %ProgramData%, be readable by every interactive account.
func SaveKey(path, key string) error {
	if path == "" {
		path = DefaultKeyFile()
	}
	dir := filepath.Dir(path)
	if err := secfile.MkdirAll(dir); err != nil {
		return err
	}
	return secfile.WriteFile(path, []byte(strings.TrimSpace(key)))
}
