// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// secfile_test.go is the platform-NEUTRAL half of the suite: the decision table
// and the behaviour that must hold identically wherever this compiles. The
// mechanism-specific halves live beside it, one per platform, because "only the
// owner can read this" is one sentence with two implementations.

// --- the pure decision table -------------------------------------------------

// TestJudgeACEFailDirections pins the three rows the gate can never get wrong:
// a deny only tightens, a write-class or DACL-control grant still counts (a
// principal holding WRITE_DAC can grant itself the read at will), and an ace
// type this walk cannot parse is terminal rather than assumed harmless.
//
// It runs on every lane, which is the point of the table carrying no build tag:
// a change to the mask is caught by the ubuntu build rather than by the one
// Windows runner.
func TestJudgeACEFailDirections(t *testing.T) {
	const (
		writeDAC     = 0x00040000
		writeOwner   = 0x00080000
		genericAll   = 0x10000000
		fileReadData = 0x00000001
		genericRead  = 0x80000000
		fileReadEA   = 0x00000008
		synchronize  = 0x00100000 // not an exposure on its own
		readControl  = 0x00020000 // reading the DACL is not reading the data
	)
	for _, tc := range []struct {
		name    string
		aceType byte
		mask    uint32
		want    ACEJudgment
	}{
		{"deny of everything is harmless", aceTypeDenied, 0xFFFFFFFF, ACEHarmless},
		{"SYNCHRONIZE alone is harmless", aceTypeAllowed, synchronize, ACEHarmless},
		{"READ_CONTROL alone is harmless", aceTypeAllowed, readControl, ACEHarmless},
		{"zero mask is harmless", aceTypeAllowed, 0, ACEHarmless},
		{"WRITE_DAC needs a principal", aceTypeAllowed, writeDAC, ACENeedsPrincipal},
		{"WRITE_OWNER needs a principal", aceTypeAllowed, writeOwner, ACENeedsPrincipal},
		{"GENERIC_ALL needs a principal", aceTypeAllowed, genericAll, ACENeedsPrincipal},
		{"GENERIC_READ needs a principal", aceTypeAllowed, genericRead, ACENeedsPrincipal},
		{"FILE_READ_DATA needs a principal", aceTypeAllowed, fileReadData, ACENeedsPrincipal},
		{"FILE_READ_EA needs a principal", aceTypeAllowed, fileReadEA, ACENeedsPrincipal},
		{"callback allow (type 9) is unjudgeable", 9, fileReadData, ACEUnjudgeable},
		{"object allow (type 5) is unjudgeable", 5, genericAll, ACEUnjudgeable},
		{"callback deny (type 10) is unjudgeable", 10, 0, ACEUnjudgeable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := JudgeACE(tc.aceType, tc.mask); got != tc.want {
				t.Errorf("JudgeACE(%d, 0x%08x) = %v, want %v", tc.aceType, tc.mask, got, tc.want)
			}
		})
	}
}

// TestExposureMaskCoversBothDirections states in a test what the constant says
// in prose. A read grant is exposure because the file holds a credential; a
// write grant is exposure too, because a principal holding WRITE_DAC or
// WRITE_OWNER is one call away from granting itself the read.
func TestExposureMaskCoversBothDirections(t *testing.T) {
	for name, bit := range map[string]uint32{
		"GENERIC_READ":          0x80000000,
		"GENERIC_WRITE":         0x40000000,
		"GENERIC_EXECUTE":       0x20000000,
		"GENERIC_ALL":           0x10000000,
		"FILE_READ_DATA":        0x00000001,
		"FILE_WRITE_DATA":       0x00000002,
		"FILE_APPEND_DATA":      0x00000004,
		"FILE_READ_EA":          0x00000008,
		"FILE_WRITE_EA":         0x00000010,
		"FILE_WRITE_ATTRIBUTES": 0x00000100,
		"DELETE":                0x00010000,
		"WRITE_DAC":             0x00040000,
		"WRITE_OWNER":           0x00080000,
	} {
		if ExposureMask&bit == 0 {
			t.Errorf("ExposureMask does not cover %s (0x%08x)", name, bit)
		}
	}
	// And it does NOT claim the rights that grant nothing material, or every
	// ordinary DACL would read as exposed and the gate would be noise.
	for name, bit := range map[string]uint32{
		"SYNCHRONIZE":          0x00100000,
		"READ_CONTROL":         0x00020000,
		"FILE_READ_ATTRIBUTES": 0x00000080,
	} {
		if ExposureMask&bit != 0 {
			t.Errorf("ExposureMask claims %s (0x%08x), which grants no read and no alteration", name, bit)
		}
	}
}

// --- the writers -------------------------------------------------------------

// TestWriteFileProducesAPrivateFile is the headline on every platform: the
// bytes land, and the object that holds them passes the read-back.
func TestWriteFileProducesAPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteFile(path, []byte("whisper_live_notarealkey")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "whisper_live_notarealkey" {
		t.Fatalf("read back %q, %v", b, err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("the file WriteFile just wrote is not private: %v", err)
	}
}

// TestWriteFileTightensAFileItFinds: an earlier, looser version of this binary
// (or an operator's cp) may have left the credential file readable. Overwriting
// it must fix that rather than inherit it.
func TestWriteFileTightensAFileItFinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("WriteFile left a pre-existing loose file exposed: %v", err)
	}
}

// TestOpenFileHardensBeforeTheFirstWrite is the --keys-out shape: append to a
// file that may not exist, and hand the caller a handle that is already safe to
// write a minted API key into.
func TestOpenFileHardensBeforeTheFirstWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.txt")
	f, err := OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	// The guarantee holds while the handle is still open, which is the whole
	// point: the caller writes the secret through it next.
	if err := Verify(path); err != nil {
		f.Close()
		t.Fatalf("the open handle points at an exposed file: %v", err)
	}
	if _, err := f.WriteString("db-01\twhisper_live_minted\n"); err != nil {
		f.Close()
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := Verify(path); err != nil {
		t.Errorf("after the append the file is exposed: %v", err)
	}
}

// TestOpenFileRefusesAMissingParent: a create into a directory that is not
// there is an ordinary failure and must surface as one, not as a nil handle or
// a leaked descriptor.
func TestOpenFileRefusesAMissingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "keys.txt")
	f, err := OpenFile(path, os.O_CREATE|os.O_WRONLY)
	if err == nil {
		f.Close()
		t.Fatal("OpenFile into a missing directory returned a handle")
	}
}

// --- directories -------------------------------------------------------------

// TestMkdirAllHardensWhatItCreates covers the fresh-install path: a
// machine-wide credential directory under %ProgramData%, and the
// ~/.config/whisper the key lands in.
func TestMkdirAllHardensWhatItCreates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Whisper", "watch")
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := VerifyDir(dir); err != nil {
		t.Errorf("the directory MkdirAll just created is not private: %v", err)
	}
}

// TestMkdirAllLeavesAnExistingDirectoryAlone is the safety half, and it guards
// something worse than the bug being fixed. A caller's directory list comes
// from a config file, config is not trusted to name safe paths, and a MkdirAll that
// re-permissioned what it found would chmod /etc the moment somebody put it in
// a dirs list.
func TestMkdirAllLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll on an existing dir: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("MkdirAll re-permissioned a directory it did not create: %v -> %v", before.Mode(), after.Mode())
	}
}

// TestMkdirAllForMakesTheParent is the shape nearly every caller wants: name
// the file, get its directory made.
func TestMkdirAllForMakesTheParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whisper", "key")
	if err := MkdirAllFor(path); err != nil {
		t.Fatalf("MkdirAllFor: %v", err)
	}
	if err := VerifyDir(filepath.Dir(path)); err != nil {
		t.Errorf("the parent is not private: %v", err)
	}
	if err := WriteFile(path, []byte("k")); err != nil {
		t.Fatalf("WriteFile into the new parent: %v", err)
	}
}

// --- the read-back's own edges ------------------------------------------------

// TestVerifyRefusesAMissingPath: absent is not private. A nil here would let a
// caller conclude a file it never wrote is safe.
func TestVerifyRefusesAMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing")
	if err := Verify(path); err == nil {
		t.Error("Verify on a missing path returned nil")
	}
	if err := VerifyDir(path); err == nil {
		t.Error("VerifyDir on a missing path returned nil")
	}
}

// TestVerifyDistinguishesFilesFromDirectories: asking the file question about a
// directory is a programming error, and answering it anyway would let a caller
// assert the wrong thing about the wrong object.
func TestVerifyDistinguishesFilesFromDirectories(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := WriteFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dir); err == nil {
		t.Error("Verify accepted a directory")
	}
	if err := VerifyDir(file); err == nil {
		t.Error("VerifyDir accepted a file")
	}
}

// TestHardenRefusesTheWrongKind is a guard against damage, not against
// confusion. On unix Harden is a chmod that follows the path to whatever is at
// the end of it, so a Harden aimed at a directory would strip its execute bit
// and make it untraversable. Refusing is the only outcome that leaves the
// caller's mistake recoverable.
func TestHardenRefusesTheWrongKind(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := WriteFile(file, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := Harden(dir); err == nil {
		t.Error("Harden accepted a directory")
	}
	if err := HardenDir(file); err == nil {
		t.Error("HardenDir accepted a file")
	}
	// And the directory is still traversable, which is the property the refusal
	// exists to keep.
	if _, err := os.ReadFile(file); err != nil {
		t.Errorf("the directory became untraversable: %v", err)
	}
}

// TestHardenRefusesAMissingPath: nothing to harden is not "hardened".
func TestHardenRefusesAMissingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if err := Harden(path); err == nil {
		t.Error("Harden on a missing path returned nil")
	}
	if err := HardenDir(path); err == nil {
		t.Error("HardenDir on a missing path returned nil")
	}
}

// TestOpenFileExclusiveLeavesNoStubBehind: an O_EXCL create this call made and
// then could not protect must not survive, or the retry hits "refusing to
// overwrite" and the caller can never get its output. The success path is what
// runs here (hardening a file we just made does not fail on a healthy host);
// the assertion is that the file is present and private, which is the other
// half of the same contract.
func TestOpenFileExclusiveLeavesNoStubBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.out")
	f, err := OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("OpenFile O_EXCL: %v", err)
	}
	f.Close()
	if err := Verify(path); err != nil {
		t.Errorf("the exclusive create is not private: %v", err)
	}
	// A second exclusive create must still refuse: the flag has to reach the OS.
	if f2, err := OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		f2.Close()
		t.Error("a second O_EXCL create succeeded: the flag was dropped")
	}
}

// TestSecureOnAnEmptyPathIsNil: "" and "-" mean stdout to the telemetry sink,
// and it asks this before it knows better on some paths. An empty path is not a
// file and must not be an error.
func TestSecureOnAnEmptyPathIsNil(t *testing.T) {
	if err := Secure(""); err != nil {
		t.Errorf(`Secure("") = %v, want nil`, err)
	}
	if err := SecureDir(""); err != nil {
		t.Errorf(`SecureDir("") = %v, want nil`, err)
	}
}

// TestSecureOnAMissingPathReports: a path that does not exist cannot be
// secured, and a silent nil would read as "this file is private".
func TestSecureOnAMissingPathReports(t *testing.T) {
	if err := Secure(filepath.Join(t.TempDir(), "absent", "x")); err == nil {
		t.Error("Secure on a missing path returned nil")
	}
	if err := SecureDir(filepath.Join(t.TempDir(), "absent", "d")); err == nil {
		t.Error("SecureDir on a missing path returned nil")
	}
}

// TestSecureIsIdempotent: `whisper login` overwrites the key file, the
// installer reruns, a long-running writer reopens its output file. Securing an
// already-secured object stays green.
func TestSecureIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := WriteFile(path, []byte("k")); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		if err := Secure(path); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if err := Verify(path); err != nil {
			t.Fatalf("round %d: not private: %v", round, err)
		}
	}
}

// TestErrExposedIsMatchable: callers tell "this host cannot keep a credential
// private" apart from an ordinary filesystem failure with errors.Is, so the
// sentinel has to survive the wrapping.
func TestErrExposedIsMatchable(t *testing.T) {
	if !errors.Is(ErrExposed, ErrExposed) {
		t.Fatal("the sentinel does not match itself")
	}
	// A missing file is NOT an exposure: it is a different failure and must not
	// be reported as one, or a caller retrying on ErrExposed loops forever.
	err := Verify(filepath.Join(t.TempDir(), "nothing"))
	if err == nil {
		t.Fatal("Verify on a missing path returned nil")
	}
	if errors.Is(err, ErrExposed) {
		t.Errorf("a missing file reported as exposed: %v", err)
	}
}
