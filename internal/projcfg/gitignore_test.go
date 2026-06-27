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
