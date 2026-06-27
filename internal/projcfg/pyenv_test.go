// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteProxyEnv_Content: the proxy.env carries the canonical vars — HTTP-CONNECT primary,
// SOCKS additive, NO_PROXY incl. the IPv6 loopback ::1, and BOTH upper- and lower-case twins.
func TestWriteProxyEnv_Content(t *testing.T) {
	p := PathsFor(t.TempDir())
	res, err := WriteProxyEnv(p, 23456)
	if err != nil {
		t.Fatalf("WriteProxyEnv: %v", err)
	}
	if !res.Created {
		t.Fatalf("first write should report Created=true")
	}
	body := readFileT(t, p.ProxyEnvFile)
	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:23456",
		"HTTPS_PROXY=http://127.0.0.1:23456",
		"ALL_PROXY=socks5h://127.0.0.1:23456",
		"NO_PROXY=localhost,127.0.0.1,::1",
		"http_proxy=http://127.0.0.1:23456",
		"https_proxy=http://127.0.0.1:23456",
		"all_proxy=socks5h://127.0.0.1:23456",
		"no_proxy=localhost,127.0.0.1,::1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("proxy.env missing %q:\n%s", want, body)
		}
	}
	// No secret may ever appear (loopback only).
	for _, bad := range []string{"et_", "whisper_live_", "Bearer", "X-API-Key"} {
		if strings.Contains(body, bad) {
			t.Fatalf("proxy.env leaked %q:\n%s", bad, body)
		}
	}

	// Perms 0600 (advisory/no-op on Windows — Go synthesizes 0666 there regardless).
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p.ProxyEnvFile)
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("proxy.env perms = %o, want 0600", perm)
		}
	}

	// The self-ignoring .whisper/.gitignore is written as `*`.
	gi := readFileT(t, filepath.Join(p.WhisperDir, ".gitignore"))
	if !strings.Contains(gi, "*") {
		t.Fatalf(".whisper/.gitignore should self-ignore with `*`:\n%s", gi)
	}
}

// TestWriteProxyEnv_Idempotent: two runs at the same port produce byte-identical content, and
// the second reports Created=false (it rewrote, did not newly create).
func TestWriteProxyEnv_Idempotent(t *testing.T) {
	p := PathsFor(t.TempDir())
	if _, err := WriteProxyEnv(p, 31000); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := readFileT(t, p.ProxyEnvFile)
	res2, err := WriteProxyEnv(p, 31000)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if res2.Created {
		t.Fatalf("second write should report Created=false")
	}
	if second := readFileT(t, p.ProxyEnvFile); second != first {
		t.Fatalf("re-write not byte-identical:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	// No stray temp file left behind.
	entries, _ := os.ReadDir(p.WhisperDir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("atomic write left a temp file: %s", e.Name())
		}
	}
}

// TestWriteProxyEnv_RefusesSymlink: a symlinked proxy.env -> ../.env must NOT be written through
// (clobber-safety) — the user's ./.env stays byte-identical and we return a clear error.
func TestWriteProxyEnv_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	p := PathsFor(root)
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A user's secrets file at the project root.
	userEnv := filepath.Join(root, ".env")
	const secret = "OPENAI_API_KEY=sk-do-not-touch\n"
	if err := os.WriteFile(userEnv, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant a hostile symlink at our target pointing back at the user's .env.
	if err := os.Symlink("../.env", p.ProxyEnvFile); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteProxyEnv(p, 25000); err == nil {
		t.Fatalf("WriteProxyEnv must refuse to write through a symlink")
	}
	if got := readFileT(t, userEnv); got != secret {
		t.Fatalf("the user's ./.env was clobbered through a symlink: %q", got)
	}
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
