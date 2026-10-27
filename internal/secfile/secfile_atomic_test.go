// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteFileAtomic replaces the file whole: the content is the new content, the path is a new
// file rather than the old one rewritten, the result is private, and no temp file is left.
func TestWriteFileAtomicReplacesWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record")
	if err := WriteFileAtomic(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	before := identity(t, path)
	if err := WriteFileAtomic(path, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	after := identity(t, path)
	if os.SameFile(before, after) {
		t.Fatal("the write rewrote the file in place rather than replacing it")
	}
	if b, _ := os.ReadFile(path); string(b) != "second\n" {
		t.Fatalf("content %q", b)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("not private: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".record.tmp-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	// The control: rewriting in place keeps the file, so the identity check can go red here.
	c1 := identity(t, path)
	if err := WriteFile(path, []byte("third\n")); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(c1, identity(t, path)) {
		t.Fatal("an in-place rewrite read as a new file: the identity check proves nothing on this platform")
	}
}

// identity stats path through an open handle. os.Stat on Windows reads the file index lazily,
// when os.SameFile first asks, so two stats of one path would compare equal across a replace.
func identity(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// A directory that does not exist fails the write and leaves nothing behind.
func TestWriteFileAtomicFailsCleanlyWithoutADirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "record")
	if err := WriteFileAtomic(path, []byte("x")); err == nil {
		t.Fatal("wrote into a directory that does not exist")
	}
}

// A replace that cannot happen (the target is a directory) fails, removes the temp file and
// leaves the target as it was.
func TestWriteFileAtomicFailedReplaceLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record")
	if err := os.MkdirAll(filepath.Join(path, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("x")); err == nil {
		t.Fatal("replaced a directory with a file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".record.tmp-*")); len(left) != 0 {
		t.Fatalf("temp files left after a failed replace: %v", left)
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatalf("the target changed: %v %v", fi, err)
	}
}
