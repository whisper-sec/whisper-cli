// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package secfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// secfile_unix_test.go asserts the MECHANISM on the platforms that carry mode
// bits. The sentence is the same one secfile_windows_test.go asserts about a
// DACL; only the thing being read back differs.

// TestUnixWriteFileLandsAtTheOwnerOnlyMode: the number matters here in a way it
// never does on Windows, because on unix the number IS the control.
func TestUnixWriteFileLandsAtTheOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteFile(path, []byte("k")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != FileMode {
		t.Errorf("mode is %04o, want %04o", perm, FileMode)
	}
}

// TestUnixWriteFileIsUmaskIndependent is why Harden is a separate chmod rather
// than a trust in the create mode. umask can only take bits away, so a 0600
// create is safe under any umask, but a file that already existed carries
// whatever mode it was left with. This pins the case a permissive umask would
// otherwise let slide.
func TestUnixWriteFileIsUmaskIndependent(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteFile(path, []byte("k")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fi, _ := os.Stat(path)
	if perm := fi.Mode().Perm(); perm != FileMode {
		t.Errorf("with umask 0 the mode is %04o, want %04o", perm, FileMode)
	}
}

// TestUnixVerifyCatchesEveryLooseBit is the gate's teeth. Without a case that
// FAILS, "Verify returned nil" says nothing at all.
func TestUnixVerifyCatchesEveryLooseBit(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o777, 0o601} {
		path := filepath.Join(t.TempDir(), "loose")
		if err := os.WriteFile(path, []byte("k"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := Verify(path)
		if err == nil {
			t.Errorf("mode %04o reported as private", mode)
			continue
		}
		if !errors.Is(err, ErrExposed) {
			t.Errorf("mode %04o: error %v does not wrap ErrExposed", mode, err)
		}
	}
}

// TestUnixVerifyAcceptsEveryOwnerOnlyMode: the property is "no group or other
// bits", not "exactly 0600". A 0400 credential file an operator made read-only
// is still owner-only and must not be reported as a regression.
func TestUnixVerifyAcceptsEveryOwnerOnlyMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700, 0o200} {
		path := filepath.Join(t.TempDir(), "tight")
		if err := os.WriteFile(path, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := Verify(path); err != nil {
			t.Errorf("mode %04o reported as exposed: %v", mode, err)
		}
	}
}

// TestUnixVerifyDirCatchesALooseDirectory: the directory twin, and the
// assertion behind a machine-wide credential directory.
func TestUnixVerifyDirCatchesALooseDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "watch")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDir(dir); err == nil {
		t.Error("a 0755 directory reported as owner-only")
	}
	if err := HardenDir(dir); err != nil {
		t.Fatalf("HardenDir: %v", err)
	}
	if err := VerifyDir(dir); err != nil {
		t.Errorf("after HardenDir the directory is still loose: %v", err)
	}
}

// TestUnixVerifyExemptsANonRegularFile: an operator who points an output file at a
// fifo or /dev/stdout has made an explicit choice, and a device node's mode
// bits are not ours to judge or to chmod. Reporting one as "exposed" would fail
// the caller closed on a configuration that is perfectly deliberate.
func TestUnixVerifyExemptsANonRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o666); err != nil {
		t.Skipf("cannot create a fifo here: %v", err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("a 0666 fifo reported as exposed: %v", err)
	}
}

// TestUnixSecureTightensAFileItDidNotCreate is the append-to-an-existing-file
// case: a writer opens the file with its own flags and then asks for it to be
// made private. The unix half used to be a documented no-op, which meant a file
// this process could append to but did not own stayed at whatever mode its
// owner set.
func TestUnixSecureTightensAFileItDidNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "appended.ndjson")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err == nil {
		t.Fatal("precondition: the file was already private, so Secure has nothing to prove")
	}
	if err := Secure(path); err != nil {
		t.Fatalf("Secure: %v", err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("after Secure the file is still exposed: %v", err)
	}
}
