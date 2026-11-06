// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// verifierCensus is every non-test Go file in whisper-cli that reads a peer certificate or
// verifies one, with whether it applies JudgeAllocation and why. A Whisper Agent CA leaf
// carries a /128 for 160 hours (S/MIME for 90 days), and the /128 can be reallocated inside
// that window, so a verifier added later must be judged here before it builds: either it holds
// the leaf to the current allocation, or the reason it need not is written down.
var verifierCensus = map[string]string{
	"internal/trustverify/dane.go": "NO, by position: the TLS handshaker only hands the served leaf to runDANE," +
		" which applies JudgeAllocation (CheckLeafAllocation) after the pin and SAN checks.",
	"internal/trustverify/fetch.go": "NO, exempt: GetPinned fetches the identity document over the same /128" +
		" and pin runDANE judged in the same run; the document is JWS-signed and checked against DNSSEC facts.",
	"internal/cli/sign.go": "YES: verifyDetachedWith applies JudgeAllocation (CheckLeafAllocation) to the" +
		" signer leaf after the SMIMEA pin matches, against the whisper-id1 at the mailbox's domain.",
}

// verifierPattern finds a read of a peer certificate or a certificate verification.
var verifierPattern = regexp.MustCompile(`\.PeerCertificates\b|\.Verify\(x509\.VerifyOptions|` +
	`x509\.VerifyOptions\{|\.VerifyWithChain\(|VerifyPeerCertificate\b|VerifyConnection\b`)

func TestEveryCertificateVerifierIsJudgedForTheAllocation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the whisper-cli root was not found at %s: %v", root, err)
	}
	found := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" ||
				name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if verifierPattern.Match(src) {
			rel, _ := filepath.Rel(root, path)
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unknown []string
	for f := range found {
		if _, ok := verifierCensus[f]; !ok {
			unknown = append(unknown, f)
		}
	}
	sort.Strings(unknown)
	for _, f := range unknown {
		t.Errorf("%s reads or verifies a peer certificate and is not in verifierCensus: decide whether it must"+
			" apply JudgeAllocation (a previous holder's Agent CA leaf must not pass for a reallocated /128),"+
			" then add it with the reason", f)
	}
	for f := range verifierCensus {
		if !found[f] {
			t.Errorf("verifierCensus lists %s, which no longer reads or verifies a certificate; remove it", f)
		}
	}
}
