// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package secfile creates files and directories that only their owner can read.
//
// # Why this package exists
//
// Every credential this binary keeps on disk was written with os.WriteFile or
// os.OpenFile at 0o600, and on Linux and darwin that is the whole control: the
// kernel applies the mode at create time and os.Stat reads it back.
//
// On Windows the same line does nothing of the kind. Go's os package ignores
// the permission argument there except for the read-only bit, so a file created
// with 0o600 simply inherits the containing directory's DACL, and os.Stat
// reports 0666 however it was opened. Under a user profile the inherited ACL is
// tolerable (the user, SYSTEM, Administrators). Under %ProgramData%, where a
// machine-wide credential lives, the default ACL grants BUILTIN\Users read
// access: a machine-wide provisioned API key sat there readable by every
// interactive account on the box.
//
// So the property "only the owner can read this" needs a different mechanism on
// each platform, and the whole point of this package is that its CALLERS never
// have to know which. They ask for a private file; the platform half underneath
// picks mode bits or an explicit DACL.
//
// # What "private" means here
//
// The owner, LocalSystem and the local Administrators group, and nobody else.
// SYSTEM is on the list because a machine-wide service runs as it, and
// Administrators because an operator collecting a diagnostic bundle is not an
// attacker. On unix those same three collapse to "the owner, plus root, which
// can read anything anyway", which is exactly what 0o600 already says.
//
// On Windows the DACL is set PROTECTED, which is the load-bearing detail: a
// protected DACL DROPS the ACEs the object would have inherited from its parent
// rather than merging them, and the inherited BUILTIN\Users read is precisely
// the exposure. Setting a tight-looking DACL without the protect flag would
// leave the inherited grant in place and still read as a fix.
//
// # Prove it, do not assume it
//
// Harden sets the protection; Verify READS IT BACK and judges what is actually
// on the object. They are separate on purpose. A check that re-applies the fix
// before measuring cannot fail when the fix is missing, so Verify never writes,
// which is what lets the test suite call the same function production does
// without the assertion becoming circular.
//
// # What this does NOT close
//
// On Windows the object has to exist before SetNamedSecurityInfo can name it,
// so between the create and the DACL there is an instant in which the file
// carries its inherited ACL. WriteFile and OpenFile shrink that window to an
// EMPTY file: the secret is written afterwards, through a handle on an object
// that is already private. What remains is a local attacker who is already
// racing this exact path and who opens the empty file in that instant, keeping
// a handle whose granted access survives the DACL change.
//
// Closing it completely means creating the file with a SECURITY_ATTRIBUTES
// carrying the DACL, which is a per-platform open path rather than the
// os.OpenFile every caller here uses. That is worth doing and is not what this
// package set out to do; the thing to do meanwhile is to say what the window is
// rather than to imply there is none.
package secfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileMode and DirMode are the unix modes this package writes. They are also
// the permission argument handed to the os calls on Windows, where they decide
// only the read-only attribute and the DACL does the real work.
const (
	FileMode os.FileMode = 0o600
	DirMode  os.FileMode = 0o700
)

// WriteFile writes data to path as a private file, creating or truncating it.
//
// It is the drop-in replacement for os.WriteFile(path, data, 0o600) at every
// site that stores a credential, and it goes through OpenFile rather than
// os.WriteFile for one reason: the hardening has to happen BEFORE the secret
// bytes land. Writing first and tightening afterwards leaves a real, if brief,
// window in which a live API key sits on disk under the directory's inherited
// ACL, which is the exact exposure this package exists to end. Truncating an
// existing file before hardening is safe in the same way: the old content is
// already gone when the DACL lands.
func WriteFile(path string, data []byte) error {
	f, err := OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	// Under sudo this may have landed in the INVOKING user's home owned by root,
	// which leaves them unable to read their own file. Hand it back. Narrow and
	// best-effort - see ReownForSudo.
	ReownForSudo(path)
	return cerr
}

// OpenFile opens path with flag as a private file and returns the open handle.
//
// The permission argument is not a parameter because there is only one answer
// for a file that holds a credential. Callers needing O_EXCL or O_APPEND pass
// them in flag, and O_CREATE is implied by neither, so pass it when the file
// may not exist yet.
//
// The file is hardened before the caller can write a byte into it, which is the
// narrowest window this can be given without a Windows-specific create path: on
// Windows the object has to exist before SetNamedSecurityInfo can name it, so
// there is an instant between the create and the DACL landing. Nothing secret
// is in the file during that instant, because the write has not happened yet.
func OpenFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, FileMode)
	if err != nil {
		return nil, err
	}
	if err := Harden(path); err != nil {
		f.Close()
		// An O_EXCL create is one this call definitely made, and leaving the
		// empty file behind would poison the retry: the next attempt fails with
		// "refusing to overwrite" and the caller can never get its output. Any
		// other flag combination may have opened a file that was already there,
		// which is not ours to delete.
		if flag&os.O_EXCL != 0 && flag&os.O_CREATE != 0 {
			_ = os.Remove(path)
		}
		return nil, err
	}
	return f, nil
}

// WriteMachineFile is WriteFile for a file a machine-wide service reads: on
// Windows its DACL names LocalSystem and Administrators only, not the account
// that wrote it (see HardenMachine), and on unix it is WriteFile exactly.
//
// An administrator binding a host from an elevated PowerShell writes the
// LocalSystem sensor's key and marker into the SYSTEM profile, where the sensor
// reads them. The hardening still lands before the bytes do, as in
// WriteFile.
func WriteMachineFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, FileMode)
	if err != nil {
		return err
	}
	if err := HardenMachine(path); err != nil {
		f.Close()
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	ReownForSudo(path)
	return cerr
}

// MkdirAllMachine is MkdirAll for the directory of a file a machine-wide
// service reads, with the same "only when this call created it" rule.
func MkdirAllMachine(path string) error {
	_, statErr := os.Stat(path)
	if err := os.MkdirAll(path, DirMode); err != nil {
		return err
	}
	if statErr == nil {
		return nil
	}
	ReownForSudo(path)
	return HardenMachineDir(path)
}

// MkdirAll creates path and any missing parents, and makes the leaf private
// when, and only when, this call is what created it.
//
// The "only when we created it" rule is not timidity, it is the difference
// between a fix and an outage. A caller's watch dirs come from a config file,
// config is not trusted to name safe paths, and the existing code says as much:
// "MkdirAll on an existing / or /etc is a harmless no-op". It stops being
// harmless the moment the call also re-permissions what it found, and a
// whisper-cli that chmod 0700's /etc because someone put it in a dirs list is a
// far worse bug than the one this package fixes.
//
// Nothing is lost by it. The FILE is what holds the credential, and WriteFile
// and OpenFile harden the file itself unconditionally with a DACL that is
// PROTECTED, so a file is private whatever its directory grants. The directory
// is defense in depth: it keeps a newly created credential directory unlistable
// and, on Windows, gives what lands inside an owner-only starting point.
//
// Only the leaf is hardened, never a parent. A credential directory under
// %ProgramData% or under ~/.config has parents whose policy is not ours.
func MkdirAll(path string) error {
	_, statErr := os.Stat(path)
	if err := os.MkdirAll(path, DirMode); err != nil {
		return err
	}
	if statErr == nil {
		// It was already there. Whoever owns it chose its permissions, and
		// this call is not the place to overrule them.
		return nil
	}
	// A directory this process CREATED under sudo inside the invoking user's home
	// goes back to them too, or the next non-root write into it fails.
	ReownForSudo(path)
	return HardenDir(path)
}

// MkdirAllFor is MkdirAll for the directory that will hold path, which is the
// shape almost every caller wants: make the parent private, then write the file
// into it.
func MkdirAllFor(path string) error { return MkdirAll(filepath.Dir(path)) }

// Secure hardens an EXISTING file and then proves the hardening held.
//
// Use it for a file some other code opened: an append-only file another
// component already holds a handle on, a service log written through its own
// path. An empty path is not a
// file and reports nil, because several callers use "" to mean stdout.
//
// It fails closed. When the hardening itself errors the read-back still gets
// the last word, because the file may already carry a DACL or a mode that
// satisfies the guarantee: an operator-locked directory, or a re-open of a file
// an earlier run already secured. Only when BOTH refuse is this an error.
func Secure(path string) error {
	if path == "" {
		return nil
	}
	if err := Harden(path); err != nil {
		if verr := Verify(path); verr != nil {
			return fmt.Errorf("could not restrict %s (%w) and it is not already private: %w", path, err, verr)
		}
		return nil
	}
	return Verify(path)
}

// SecureDir is Secure for a directory.
func SecureDir(path string) error {
	if path == "" {
		return nil
	}
	if err := HardenDir(path); err != nil {
		if verr := VerifyDir(path); verr != nil {
			return fmt.Errorf("could not restrict %s (%w) and it is not already private: %w", path, err, verr)
		}
		return nil
	}
	return VerifyDir(path)
}

// WriteFileAtomic is WriteFile for a record a reader must never see half-written: the bytes go
// to a private temp file beside path, are flushed to disk, and then replace path in one rename.
// A crash leaves either the old file or the new one, never a truncated mix, and a reader that
// parses a prefix of an address can never read a sibling address out of it.
//
// The temp file is hardened before a byte is written, exactly as OpenFile does, so the DACL or
// mode travels with the rename. replaceFile is per platform: on unix the rename is followed by
// a sync of the directory so the new name survives power loss; on Windows the move is written
// through.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_ = tmp.Close()
	f, err := OpenFile(name, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(name)
		return errors.Join(werr, serr, cerr)
	}
	if err := replaceFile(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	ReownForSudo(path)
	return nil
}
