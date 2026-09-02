// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// whale_syspolicy_filestore_test.go is the acceptance criterion for the platforms
// whose managed policy lives in a FILE.
//
// It is unix-only because Windows has no file store to round-trip through, by
// design and not by omission: defaultSysPolicyPaths("windows") returns nil and
// says so in one line, because machine policy on Windows is a registry key
// (HKLM\SOFTWARE\Policies\Whisper), and the template we print for it is a .reg
// rather than a document any reader could load off disk. Installing that into a
// real registry is not a unit test's business; the Windows side of the same
// promise is TestWindowsTemplateNamesTheRealPolicyKey, which pins the key path,
// the DWORD encoding, the CRLF endings and the ASCII-only body that regedit
// needs.
//
// Forcing this one to run on Windows anyway would have meant reading a linux
// template on a Windows host, where the reader correctly rejects a KeyFile of
// /etc/whisper/key because filepath.IsAbs is false there. The reader is not
// wrong: a policy is read on the machine it governs. The cross-platform
// simulation is what does not exist.

// TestTemplateRoundTripsThroughTheReader is the acceptance criterion, executed:
// the template this command prints, installed as the store, is read back by the
// same reader with every setting reporting source=managed and not one complaint.
func TestTemplateRoundTripsThroughTheReader(t *testing.T) {
	body, err := sysPolicyTemplate("linux")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := sysPolicyPathsFor
	t.Cleanup(func() { sysPolicyPathsFor = prev })
	sysPolicyPathsFor = func(string) []string { return []string{path} }

	_, v := resolveSysPolicy(sysPolicyStoreFor("linux"))
	if v.Error != "" {
		t.Fatalf("the template we print is not readable by the reader we ship: %s", v.Error)
	}
	if len(v.Settings) == 0 {
		t.Fatal("the reader came back with no settings at all, so nothing below is a check")
	}
	for _, s := range v.Settings {
		if s.Source != "managed" {
			t.Errorf("%s did not come back from the installed template (source=%s)", s.Name, s.Source)
		}
	}
	if len(v.Notes) != 0 {
		t.Errorf("the file we print complains about itself when read back: %v", v.Notes)
	}
}
