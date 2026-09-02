// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

func TestReadSignature_FileStdinAndLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ballot.jws")
	if err := os.WriteFile(path, []byte("aaa.bbb.ccc\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readSignature(path)
	if err != nil || strings.TrimSpace(string(got)) != "aaa.bbb.ccc" {
		t.Fatalf("read from file = %q, %v", got, err)
	}
	if _, err := readSignature(filepath.Join(dir, "nope.jws")); err == nil {
		t.Fatal("a missing signature file must be a clear error, not a silent empty read")
	}
	empty := filepath.Join(dir, "empty.jws")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readSignature(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty signature must say so: %v", err)
	}
	big := filepath.Join(dir, "big.jws")
	if err := os.WriteFile(big, make([]byte, maxSignatureBytes+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readSignature(big); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("an oversized signature must be refused: %v", err)
	}
}

func TestReadSignature_FromStdin(t *testing.T) {
	orig := os.Stdin
	defer func() { os.Stdin = orig }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdin = r
	go func() {
		_, _ = w.WriteString("hdr.payload.sig")
		_ = w.Close()
	}()
	got, err := readSignature("-")
	if err != nil || string(got) != "hdr.payload.sig" {
		t.Fatalf("read from stdin = %q, %v", got, err)
	}
}

func TestWritePayload_FileAndStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.json")
	if _, stderr := captureStd(t, func() {
		if err := writePayload(path, []byte(`{"ballot":"aye"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}); !strings.Contains(stderr, path) {
		t.Errorf("the human line should name the file: %q", stderr)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != `{"ballot":"aye"}` {
		t.Fatalf("payload file = %q, %v", body, err)
	}
	stdout, _ := captureStd(t, func() {
		if err := writePayload("-", []byte(`{"ballot":"aye"}`)); err != nil {
			t.Errorf("write to stdout: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != `{"ballot":"aye"}` {
		t.Fatalf("payload to stdout = %q", stdout)
	}
}

// --json and --payload-out - both own stdout: say so clearly instead of interleaving them.
func TestRunSignatureVerify_RefusesTwoWritersOfStdout(t *testing.T) {
	orig := g.jsonOut
	g.jsonOut = true
	defer func() { g.jsonOut = orig }()
	err := runSignatureVerify("2a04:2a01::1", "/nonexistent.jws", "-", "")
	if err == nil {
		t.Fatal("--json with --payload-out - must be refused")
	}
	pe, ok := err.(*client.ProblemError)
	if !ok || pe.Status != 400 || !strings.Contains(pe.Detail, "pick one") {
		t.Fatalf("want a helpful 400, got %#v", err)
	}
}

func TestRenderSignatureVerdict_ShowsTheLedgerAndTheKey(t *testing.T) {
	rep := &trustverify.SignatureReport{
		Signer: "a1.te08.agents.example", Address: "2a04:2a01::1",
		KeyOwner: "_whisper-agentkey.a1.te08.agents.example",
		Kid:      strings.Repeat("ab", 32), PublishedKIDs: []string{strings.Repeat("ab", 32)},
		PayloadSHA256: strings.Repeat("cd", 32),
		Checks: []trustverify.Check{
			{Name: "agent_key", Status: trustverify.StatusPass, TrustLevel: trustverify.TrustDNSSECRoot,
				Detail: "one key"},
			{Name: "did_assertion", Status: trustverify.StatusSkip, Detail: "unavailable"},
		},
		Verdict: true,
	}
	stdout, _ := captureStd(t, func() { renderSignatureVerdict(rep) })
	for _, want := range []string{"signer", "a1.te08.agents.example", "_whisper-agentkey", "agent_key",
		"DNSSEC-root", "did_assertion", "skip"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the rendered verdict should contain %q:\n%s", want, stdout)
		}
	}
}

func TestSignatureNotProven_NamesTheFailingCheck(t *testing.T) {
	rep := &trustverify.SignatureReport{Checks: []trustverify.Check{
		{Name: "agent_key", Status: trustverify.StatusFail, Detail: "no per-agent key"},
	}}
	if got := signatureNotProven(rep, "x"); !strings.Contains(got, "agent_key") ||
		!strings.Contains(got, "no per-agent key") {
		t.Errorf("reason = %q", got)
	}
	if got := signatureNotProven(&trustverify.SignatureReport{}, "x"); !strings.Contains(got, "x") {
		t.Errorf("fallback reason = %q", got)
	}
}

func TestShortKid(t *testing.T) {
	if got := shortKid(strings.Repeat("a", 64)); got != strings.Repeat("a", 16)+"..." {
		t.Errorf("shortKid = %q", got)
	}
	if got := shortKid("abc"); got != "abc" {
		t.Errorf("a short kid must pass through, got %q", got)
	}
}

// The flag exists, is documented, and routes signature verification (a keyless surface: it
// must not sit behind --trustless or an API key).
func TestVerifyCmd_CarriesTheSignatureFlags(t *testing.T) {
	cmd := newVerifyCmd()
	for _, name := range []string{"signature", "payload-out", "resolver", "trustless"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("verify should carry a --%s flag", name)
		}
	}
	if !strings.Contains(cmd.Long, "_whisper-agentkey") {
		t.Error("the help should name the record a stranger resolves")
	}
	if !strings.Contains(cmd.Long, "no fall-back to any fleet key") {
		t.Error("the help should state that there is no fleet fall-back")
	}
}
