// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

import (
	"os"
	"path/filepath"
	"testing"
)

// secfile_machine_test.go covers the machine-scope writers: the files a host
// service reads from its own account's profile, written there by an
// administrator. On every platform they must land private, tighten a
// file they find, and fail loudly rather than write somewhere unprotected.

func TestWriteMachineFileProducesAPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteMachineFile(path, []byte("whisper_live_notarealkey")); err != nil {
		t.Fatalf("WriteMachineFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "whisper_live_notarealkey" {
		t.Fatalf("read back %q, %v", b, err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("the file WriteMachineFile just wrote is not private: %v", err)
	}
}

// Overwriting truncates: a shorter key must not leave the tail of a longer one.
func TestWriteMachineFileTruncatesWhatItFinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("a-much-longer-previous-value"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteMachineFile(path, []byte("short")); err != nil {
		t.Fatalf("WriteMachineFile over an existing file: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "short" {
		t.Fatalf("want the file replaced, got %q", b)
	}
	if err := Verify(path); err != nil {
		t.Errorf("an existing loose file must come out private: %v", err)
	}
}

func TestWriteMachineFileRefusesAMissingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "key")
	if err := WriteMachineFile(path, []byte("k")); err == nil {
		t.Fatal("a write into a directory that does not exist must fail, not succeed somewhere else")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a failed write must leave no file behind")
	}
}

func TestWriteMachineFileRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMachineFile(dir, []byte("k")); err == nil {
		t.Fatal("a directory is not a file to write a key into")
	}
}

func TestMkdirAllMachineHardensWhatItCreates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "whisper")
	if err := MkdirAllMachine(dir); err != nil {
		t.Fatalf("MkdirAllMachine: %v", err)
	}
	if err := VerifyDir(dir); err != nil {
		t.Errorf("a directory MkdirAllMachine created must be private: %v", err)
	}
}

// The "only when this call created it" rule holds here too: an existing
// directory keeps the permissions its owner chose.
func TestMkdirAllMachineLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := MkdirAllMachine(dir); err != nil {
		t.Fatalf("MkdirAllMachine on an existing directory: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("an existing directory was re-permissioned: %v -> %v", before.Mode(), after.Mode())
	}
}

func TestMkdirAllMachineRefusesAPathUnderAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAllMachine(filepath.Join(file, "whisper")); err == nil {
		t.Fatal("a directory cannot be created under a regular file")
	}
}

func TestHardenMachineRefusesTheWrongKind(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := HardenMachine(dir); err == nil {
		t.Error("HardenMachine must refuse a directory")
	}
	if err := HardenMachineDir(file); err == nil {
		t.Error("HardenMachineDir must refuse a file")
	}
	if err := HardenMachine(filepath.Join(dir, "missing")); err == nil {
		t.Error("HardenMachine must refuse a missing path")
	}
	if err := HardenMachineDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("HardenMachineDir must refuse a missing path")
	}
	if err := HardenMachine(file); err != nil {
		t.Errorf("HardenMachine on a regular file: %v", err)
	}
	if err := HardenMachineDir(dir); err != nil {
		t.Errorf("HardenMachineDir on a directory: %v", err)
	}
	if err := Verify(file); err != nil {
		t.Errorf("HardenMachine must leave the file private: %v", err)
	}
	if err := VerifyDir(dir); err != nil {
		t.Errorf("HardenMachineDir must leave the directory private: %v", err)
	}
}
