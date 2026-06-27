// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"os"
	"strings"
	"testing"
)

// mkGitRepo makes dir look like a git working tree (a .git directory).
func mkGitRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir+"/.git", 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestGitignore_AddsEntriesInGitRepo: in a git repo, the managed entries are appended and
// reported.
func TestGitignore_AddsEntriesInGitRepo(t *testing.T) {
	dir := t.TempDir()
	mkGitRepo(t, dir)
	p := PathsFor(dir)

	added, err := EnsureGitignored(p)
	if err != nil {
		t.Fatalf("EnsureGitignored: %v", err)
	}
	if len(added) != 2 {
		t.Fatalf("expected 2 entries added, got %v", added)
	}
	body, _ := os.ReadFile(p.GitignoreFile)
	for _, want := range []string{".whisper/", ".claude/settings.local.json"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf(".gitignore missing %q:\n%s", want, body)
		}
	}
}

// TestGitignore_NonGitRepoIsNoop: not a git repo ⇒ no .gitignore written, no error (gitignore
// hygiene is a courtesy, never a blocker).
func TestGitignore_NonGitRepoIsNoop(t *testing.T) {
	p := PathsFor(t.TempDir())
	added, err := EnsureGitignored(p)
	if err != nil {
		t.Fatalf("non-git EnsureGitignored must not error: %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("non-git repo must add nothing, got %v", added)
	}
	if _, err := os.Stat(p.GitignoreFile); !os.IsNotExist(err) {
		t.Fatal("non-git repo must not create a .gitignore")
	}
}

// TestGitignore_Idempotent: a second run adds nothing (entries already present), and an entry
// the user already wrote in an equivalent spelling is not double-added.
func TestGitignore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	mkGitRepo(t, dir)
	p := PathsFor(dir)

	// Pre-seed with an equivalent spelling of one entry (leading slash) to prove the liberal
	// membership match.
	if err := os.WriteFile(p.GitignoreFile, []byte("/.whisper\nnode_modules/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added, err := EnsureGitignored(p)
	if err != nil {
		t.Fatal(err)
	}
	// Only the settings file should be added (.whisper already covered by /.whisper).
	if len(added) != 1 || added[0] != ".claude/settings.local.json" {
		t.Fatalf("expected only the settings entry added, got %v", added)
	}
	// A second run adds nothing.
	added2, err := EnsureGitignored(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(added2) != 0 {
		t.Fatalf("re-run must add nothing, got %v", added2)
	}
	// The user's unrelated entry survives.
	body, _ := os.ReadFile(p.GitignoreFile)
	if !strings.Contains(string(body), "node_modules/") {
		t.Fatal("EnsureGitignored clobbered the user's existing .gitignore")
	}
}

// TestGitignoreEntries_PythonIgnoresOnlyWhisper: the `init python` call site passes only
// `.whisper/` — it must NOT add the Claude-specific `.claude/settings.local.json` line (that
// would be a needless, non-load-bearing emit for a Python project).
func TestGitignoreEntries_PythonIgnoresOnlyWhisper(t *testing.T) {
	dir := t.TempDir()
	mkGitRepo(t, dir)
	p := PathsFor(dir)

	added, err := EnsureGitignoredEntries(p, []string{".whisper/"})
	if err != nil {
		t.Fatalf("EnsureGitignoredEntries: %v", err)
	}
	if len(added) != 1 || added[0] != ".whisper/" {
		t.Fatalf("python init should add only .whisper/, got %v", added)
	}
	body := string(mustReadFile(t, p.GitignoreFile))
	if strings.Contains(body, ".claude/settings.local.json") {
		t.Fatalf("python init must NOT add the Claude settings line:\n%s", body)
	}
	// The banner is tool-neutral (no per-tool name).
	if strings.Contains(body, "init claude") {
		t.Fatalf("gitignore banner should be tool-neutral:\n%s", body)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
