// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestProxyInjectedEnv_SetsAllVarsAndOverrides: the proxy endpoint is injected as the
// full set (lower + UPPER) plus NODE_USE_ENV_PROXY=1, and any PRE-EXISTING proxy var is
// REPLACED (a stale/hostile value can never win). The bearer-free endpoint is the only
// value injected.
func TestProxyInjectedEnv_SetsAllVarsAndOverrides(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"ALL_PROXY=socks5h://stale:1",   // a pre-existing one that MUST be replaced
		"https_proxy=http://attacker:9", // and a hostile lower-case one
		"HOME=/home/x",
	}
	endpoint := "socks5h://127.0.0.1:54321"
	out := proxyInjectedEnv(base, endpoint)

	got := map[string]string{}
	for _, kv := range out {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}
	// ALL_PROXY stays socks5h (curl/git); HTTP(S)_PROXY become the http:// CONNECT form of
	// the SAME local endpoint so Node/undici (which can't use SOCKS) egress through it too.
	httpForm := "http://127.0.0.1:54321"
	want := map[string]string{
		"ALL_PROXY": endpoint, "all_proxy": endpoint,
		"HTTPS_PROXY": httpForm, "https_proxy": httpForm,
		"HTTP_PROXY": httpForm, "http_proxy": httpForm,
		"NODE_USE_ENV_PROXY": "1",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("env[%q] = %q, want %q", k, got[k], v)
		}
	}
	// The stale/hostile values must be GONE (replaced, not duplicated).
	if strings.Count(strings.Join(out, "\n"), "ALL_PROXY=") != 1 {
		t.Fatalf("ALL_PROXY must appear exactly once (replaced), env=%v", out)
	}
	if got["ALL_PROXY"] == "socks5h://stale:1" || got["https_proxy"] == "http://attacker:9" {
		t.Fatalf("a pre-existing proxy var was NOT overridden: %v", got)
	}
	// Unrelated vars are preserved.
	if got["PATH"] != "/usr/bin" || got["HOME"] != "/home/x" {
		t.Fatalf("unrelated env must be preserved, got %v", got)
	}
	// The bearer never appears (the endpoint is bearer-free; assert no et_ token leaked).
	if strings.Contains(strings.Join(out, "\n"), "et_") {
		t.Fatalf("the injected env must NEVER carry a bearer, env=%v", out)
	}
}

// TestRun_EnvInjectedAtSpawn: `whisper run <stub>` execs the child with ALL_PROXY set at
// SPAWN (not via a prompt). We exec a tiny `sh -c 'echo $ALL_PROXY'` stub and assert the
// child saw the local endpoint. The connect tail is stubbed (no live egress).
func TestRun_EnvInjectedAtSpawn(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)() // local proxy + verify → an in-memory verified session

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	// The child prints its inherited ALL_PROXY; we capture the real stdout fd.
	stdout, _ := captureStd(t, func() {
		_ = runWithEgress("2a04:2a01:9::abcd", "", "sh", []string{"-c", "printf '%s' \"$ALL_PROXY\""})
	})
	if !strings.HasPrefix(stdout, "socks5h://127.0.0.1:") {
		t.Fatalf("child did not inherit ALL_PROXY at spawn, child stdout=%q", stdout)
	}
	if strings.Contains(stdout, "et_") {
		t.Fatalf("the child env leaked a bearer: %q", stdout)
	}
}

// TestRun_MissingBinaryCleanError: a child that isn't on PATH is a clean usage error
// (never a stack trace), after the egress came up.
func TestRun_MissingBinaryCleanError(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEgressTail(t)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	err := runWithEgress("2a04:2a01:9::abcd", "", "definitely-not-a-real-binary-xyzzy", nil)
	if err == nil || !isUsageError(err) {
		t.Fatalf("a missing child binary must be a clean usage error, got %v", err)
	}
}
