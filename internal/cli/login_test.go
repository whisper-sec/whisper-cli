// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// loginTestServer returns a control-plane stub that accepts the verify op:list and a
// cleanup. It records whether it was hit so a test can assert verification ran.
func loginTestServer(t *testing.T, hit *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":[],"rows":[]}}`))
	}))
}

// withGlobals saves and restores the package-level g + deviceFlowFn around a test so the
// table-driven cases never leak state into each other.
func withGlobals(t *testing.T, keyFile, controlURL string, fn func() (string, error)) func() {
	t.Helper()
	savedG := g
	savedFlow := deviceFlowFn
	g = globalFlags{keyFile: keyFile, controlURL: controlURL, timeout: 5 * time.Second}
	deviceFlowFn = func(consoleURL string, timeout time.Duration) (string, error) { return fn() }
	return func() { g = savedG; deviceFlowFn = savedFlow }
}

func TestLogin_KeyArg_SavesAndVerifies(t *testing.T) {
	var verified bool
	srv := loginTestServer(t, &verified)
	defer srv.Close()
	keyFile := filepath.Join(t.TempDir(), "key")
	restore := withGlobals(t, keyFile, srv.URL, func() (string, error) { t.Fatal("device flow must NOT run for a key arg"); return "", nil })
	defer restore()

	cmd := newLoginCmd()
	cmd.SetArgs([]string{"whisper_live_argkey"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("login <key> errored: %v", err)
	}
	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if string(got) != "whisper_live_argkey" {
		t.Fatalf("saved key = %q, want whisper_live_argkey", string(got))
	}
	if !verified {
		t.Fatal("expected the control plane to be hit for verification")
	}
}

func TestLogin_Web_RunsDeviceFlowAndSaves(t *testing.T) {
	var verified bool
	srv := loginTestServer(t, &verified)
	defer srv.Close()
	keyFile := filepath.Join(t.TempDir(), "key")
	restore := withGlobals(t, keyFile, srv.URL, func() (string, error) { return "whisper_live_fromdevice", nil })
	defer restore()

	cmd := newLoginCmd()
	cmd.SetArgs([]string{"--web"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("login --web errored: %v", err)
	}
	got, _ := os.ReadFile(keyFile)
	if string(got) != "whisper_live_fromdevice" {
		t.Fatalf("saved key = %q, want the device-flow key", string(got))
	}
	if !verified {
		t.Fatal("expected verification after the device flow")
	}
}

func TestLogin_Web_DeviceFlowErrorIsSurfaced(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	restore := withGlobals(t, keyFile, "https://unused.example", func() (string, error) {
		return "", &deviceErr{"login code expired"}
	})
	defer restore()

	cmd := newLoginCmd()
	cmd.SetArgs([]string{"--web"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected the device-flow error to propagate")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("no key file should be written when the device flow fails")
	}
}

func TestLogin_WebAndManual_Conflict(t *testing.T) {
	restore := withGlobals(t, filepath.Join(t.TempDir(), "key"), "https://unused.example", func() (string, error) { return "", nil })
	defer restore()
	cmd := newLoginCmd()
	cmd.SetArgs([]string{"--web", "--manual"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a usage error for --web + --manual")
	}
}

// deviceErr is a tiny error type for the device-flow-failure test.
type deviceErr struct{ msg string }

func (e *deviceErr) Error() string { return e.msg }
