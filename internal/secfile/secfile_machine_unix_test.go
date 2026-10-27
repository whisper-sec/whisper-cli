// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

// On unix the machine-scope writers carry the same mode bits as the
// per-account ones: root is the service, and owner-only already says "the
// service and the administrators".
func TestUnixWriteMachineFileLandsAtTheOwnerOnlyMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "whisper")
	if err := MkdirAllMachine(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bound")
	if err := WriteMachineFile(path, []byte("address=2a04:2a01::1\n")); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: DirMode, path: FileMode} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s is %04o, want %04o", p, got, want)
		}
	}
}

// A write that fails after the open is reported, not swallowed: /dev/full
// accepts the open and refuses every byte.
func TestUnixWriteMachineFileReportsAFailedWrite(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full on this platform")
	}
	if err := WriteMachineFile("/dev/full", []byte("k")); err == nil {
		t.Fatal("a write that landed no bytes must be an error")
	}
}

// A file the process may not open for writing fails at the open, before any
// hardening or write.
func TestUnixWriteMachineFileRefusesAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through mode bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := WriteMachineFile(filepath.Join(dir, "key"), []byte("k")); err == nil {
		t.Fatal("a write into a read-only directory must fail")
	}
}
