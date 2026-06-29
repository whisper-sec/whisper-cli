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

// TestWriteComposeSidecar_Content: the compose overlay carries the whisper sidecar on the config
// port, the official image, the env-var-sourced API key (never a literal), and — with a service —
// an app wired via shared netns + proxy.env. No secret may appear.
func TestWriteComposeSidecar_Content(t *testing.T) {
	p := PathsFor(t.TempDir())
	if err := os.MkdirAll(p.WhisperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Agent: "2a04:2a01:9::abcd", Tier: "socks5", Port: 38000}
	created, err := WriteComposeSidecar(p, cfg, "app")
	if err != nil || !created {
		t.Fatalf("WriteComposeSidecar: created=%v err=%v", created, err)
	}
	body := readFileT(t, composePath(p))
	for _, want := range []string{
		"image: " + ContainerImage,
		`"--agent", "2a04:2a01:9::abcd"`,
		`"--port", "38000"`,
		"WHISPER_API_KEY: ${WHISPER_API_KEY",
		"network_mode: \"service:whisper\"",
		"env_file: [.whisper/proxy.env]",
		"app:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("compose.yml missing %q:\n%s", want, body)
		}
	}
	// No real secret embedded (only the ${WHISPER_API_KEY} env reference).
	for _, bad := range []string{"whisper_live_", "et_", "Bearer "} {
		if strings.Contains(body, bad) {
			t.Fatalf("compose.yml leaked %q", bad)
		}
	}
	// Without --service, no app service is emitted.
	p2 := PathsFor(t.TempDir())
	_ = os.MkdirAll(p2.WhisperDir, 0o700)
	if _, err := WriteComposeSidecar(p2, cfg, ""); err != nil {
		t.Fatal(err)
	}
	if b := readFileT(t, composePath(p2)); strings.Contains(b, "depends_on:") {
		t.Fatalf("no --service should emit no app service (depends_on present):\n%s", b)
	}
}

// TestWriteK8sSidecar_Content: the k8s patch is a native sidecar (initContainer restartPolicy:
// Always) on the config port with the proxy env on the app container, keyed from a secret.
func TestWriteK8sSidecar_Content(t *testing.T) {
	p := PathsFor(t.TempDir())
	_ = os.MkdirAll(p.WhisperDir, 0o700)
	cfg := Config{Agent: "2a04:2a01:9::beef", Tier: "socks5", Port: 39000}
	if _, err := WriteK8sSidecar(p, cfg); err != nil {
		t.Fatalf("WriteK8sSidecar: %v", err)
	}
	body := readFileT(t, k8sPath(p))
	for _, want := range []string{
		"initContainers:",
		"restartPolicy: Always",
		"image: " + ContainerImage,
		`"--port", "39000"`,
		"secretKeyRef: { name: whisper, key: api-key }",
		"HTTP_PROXY,  value: \"http://127.0.0.1:39000\"",
		"ALL_PROXY,   value: \"socks5h://127.0.0.1:39000\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("whisper-sidecar.yaml missing %q:\n%s", want, body)
		}
	}
}

// TestContainerWriters_RefuseSymlink: neither writer follows a symlinked target (clobber-safety).
func TestContainerWriters_RefuseSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	p := PathsFor(root)
	_ = os.MkdirAll(p.WhisperDir, 0o700)
	secret := filepath.Join(root, "secret")
	_ = os.WriteFile(secret, []byte("KEEP"), 0o600)
	_ = os.Symlink("../secret", composePath(p))
	if _, err := WriteComposeSidecar(p, Config{Agent: "a", Port: 1}, ""); err == nil {
		t.Fatal("WriteComposeSidecar must refuse a symlinked target")
	}
	if got := readFileT(t, secret); got != "KEEP" {
		t.Fatalf("symlink target clobbered: %q", got)
	}
}
