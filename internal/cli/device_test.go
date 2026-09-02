// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deviceRegisterServer is a mock control plane whose op:register returns the first step DEVICE shape
// (token/doh_url/dot_host/resolver_ip/address/label) rather than the agent shape. It records
// each request body so a test can assert device:true was actually sent.
func deviceRegisterServer(t *testing.T, token, doh, addr string, gotBody *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if gotBody != nil {
			*gotBody = string(raw)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{` +
			`"columns":["token","doh_url","dot_host","resolver_ip","address","label"],` +
			`"rows":[["` + token + `","` + doh + `","a1b2c3.dot.whisper.online","","` + addr + `","kitchen-ipad"]]}}`))
	}))
}

const (
	devTok  = "whisper_live_DEVICE_abc123"
	devDoh  = "https://doh.whisper.online/whisper_live_DEVICE_abc123/dns-query"
	devAddr = "2a04:2a01:9::d0e"
)

// TestDeviceAdd_HumanPrintsAllForms: the default `whisper device add` mints a device and prints
// every form a person/LLM needs - the DoH URL, the derived Apple one-tap profile URL, the
// Android Private-DNS host, and the /128 - with the token captured on stdout.
func TestDeviceAdd_HumanPrintsAllForms(t *testing.T) {
	var body string
	srv := deviceRegisterServer(t, devTok, devDoh, devAddr, &body)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() {
		cmd := newDeviceCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"add", "--label", "kitchen-ipad"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("device add errored: %v", err)
		}
	})

	// It must have sent op:register with the device discriminator (the first step device flag). The client
	// serialises to a Cypher CALL, so the arg appears as the literal `device:true`.
	if !strings.Contains(body, "op:'register'") || !strings.Contains(body, "device:true") {
		t.Fatalf("device add must send op:register with device:true; body=%q", body)
	}
	// The human summary (stderr) carries the DoH URL, the DERIVED Apple profile URL, and the /128.
	for _, want := range []string{devDoh, mobileconfigURL(devTok), devAddr, "a1b2c3.dot.whisper.online"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("device add human output missing %q; stderr=%q", want, stderr)
		}
	}
	// The token is the credential - shown ONCE on stdout so it is capturable.
	if strings.TrimSpace(stdout) != devTok {
		t.Fatalf("device add must print the token on stdout; stdout=%q", stdout)
	}
	// The Apple URL points at the profile generator on the canonical resolver host for THIS
	// token (the consumer product is served from resolver.whisper.online).
	if got := mobileconfigURL(devTok); got != "https://resolver.whisper.online/apple/"+devTok+".mobileconfig" {
		t.Fatalf("mobileconfigURL wrong: %q", got)
	}
}

// TestDeviceAdd_JSON: under --json the raw device envelope goes to stdout so an LLM/script can
// parse token + doh_url directly.
func TestDeviceAdd_JSON(t *testing.T) {
	srv := deviceRegisterServer(t, devTok, devDoh, devAddr, nil)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", jsonOut: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newDeviceCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"add"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("device add --json errored: %v", err)
		}
	})
	trimmed := strings.TrimSpace(stdout)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("device add --json stdout is not valid JSON: %v\nstdout=%q", err, stdout)
	}
	if !strings.Contains(stdout, devTok) || !strings.Contains(stdout, devDoh) {
		t.Fatalf("device add --json stdout must carry token + doh_url; stdout=%q", stdout)
	}
}

// TestDeviceAdd_Quiet: --quiet emits ONLY the load-bearing value (the DoH URL) on stdout.
func TestDeviceAdd_Quiet(t *testing.T) {
	srv := deviceRegisterServer(t, devTok, devDoh, devAddr, nil)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newDeviceCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"add"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("device add --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != devDoh {
		t.Fatalf("device add --quiet must print ONLY the DoH URL; stdout=%q", stdout)
	}
}
