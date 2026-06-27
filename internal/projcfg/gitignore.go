// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// gitignoreEntries are the per-project paths `whisper init` keeps out of version control: the
// whole `.whisper/` directory (its `connect.pid` + config are machine-local) and Claude Code's
// per-user LOCAL settings (which carry this machine's proxy port + hook). The shared
// `.claude/settings.json` is deliberately NOT here — init never touches it.
var gitignoreEntries = []string{
	".whisper/",
	".claude/settings.local.json",
}

// EnsureGitignored appends any of the Whisper-managed entries that are not already present to
// the project's `.gitignore` — but ONLY when root is inside a git working tree (a `.git`
// exists at root). It is idempotent (a re-init adds nothing if the entries are there) and
// fail-soft: a non-git project, or an unwritable .gitignore, is NOT an error — gitignore
// hygiene is a courtesy, never a blocker (Postel: liberal, never fail the user's flow on it).
//
// It returns the list of entries it actually ADDED (empty if all were already ignored or root
// is not a git repo) so the caller can mention them in the summary.
func EnsureGitignored(p Paths) ([]string, error) {
	if !isGitRepo(p.Root) {
		return nil, nil
	}
	existing := readGitignoreLines(p.GitignoreFile)
	var toAdd []string
	for _, e := range gitignoreEntries {
		if !ignoreHas(existing, e) {
			toAdd = append(toAdd, e)
		}
	}
	if len(toAdd) == 0 {
		return nil, nil
	}

	// Append, preserving the existing file verbatim. Lead with a newline only if the file is
	// non-empty and doesn't already end in one (so we never glue our block onto a partial line).
	var buf bytes.Buffer
	old, _ := os.ReadFile(p.GitignoreFile) // missing ⇒ empty, fine
	buf.Write(old)
	if len(old) > 0 && old[len(old)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString("\n# Whisper (whisper init claude) — machine-local agent state\n")
	for _, e := range toAdd {
		buf.WriteString(e)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(p.GitignoreFile, buf.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("could not update %s: %w", p.GitignoreFile, err)
	}
	return toAdd, nil
}

// isGitRepo reports whether root looks like a git working tree — a `.git` directory OR a
// `.git` file (a worktree/submodule gitlink). We do NOT walk upward: init manages the project
// the user named, and only adds ignores when THAT directory is itself a repo root-ish place.
func isGitRepo(root string) bool {
	if fi, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		_ = fi
		return true
	}
	return false
}

// readGitignoreLines returns the trimmed, comment-stripped lines of .gitignore (or nil when
// absent) — the set we test membership against. We keep it forgiving: blank lines and
// comments are dropped, surrounding whitespace trimmed.
func readGitignoreLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ignoreHas reports whether want is already covered by an existing gitignore line. It is
// deliberately liberal: it matches the exact entry and the common equivalent spellings (a
// leading "/" anchor, a trailing-slash vs not) so we don't double-add `.whisper` when the
// user already wrote `/.whisper` or `.whisper`.
func ignoreHas(existing []string, want string) bool {
	want = strings.TrimSpace(want)
	wantTrim := strings.Trim(want, "/")
	for _, e := range existing {
		e = strings.TrimSpace(e)
		if e == want {
			return true
		}
		if strings.Trim(e, "/") == wantTrim {
			return true
		}
	}
	return false
}
