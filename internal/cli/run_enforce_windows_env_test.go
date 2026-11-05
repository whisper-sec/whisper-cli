// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The Windows enforced run's platform-independent half: the agent's
// environment, the one port its filters permit, and how `whisper ip` inside asks the echo.

func TestWindowsEnforcedEnvSetsTheDoorAndDropsTheWayAround(t *testing.T) {
	base := []string{
		"PATH=C:\\Windows", "https_proxy=http://evil.example:3128", "ALL_PROXY=socks5h://evil:1",
		"NO_PROXY=*", "no_proxy=localhost", "WHISPER_ENFORCED_ADDR=2001:db8::bad", "WHISPER_RUN=1",
	}
	got := windowsEnforcedEnv(base, "socks5h://127.0.0.1:41234", "2a04:2a01::1", 777)
	m := map[string][]string{}
	for _, kv := range got {
		k, v, _ := strings.Cut(kv, "=")
		m[strings.ToUpper(k)] = append(m[strings.ToUpper(k)], v)
	}
	one := func(k, want string) {
		t.Helper()
		if len(m[k]) == 0 {
			t.Fatalf("%s missing", k)
		}
		for _, v := range m[k] {
			if v != want {
				t.Fatalf("%s=%q survives beside %q: %v", k, v, want, got)
			}
		}
	}
	one("ALL_PROXY", "socks5h://127.0.0.1:41234")
	one("HTTPS_PROXY", "http://127.0.0.1:41234")
	one("HTTP_PROXY", "http://127.0.0.1:41234")
	one("NODE_USE_ENV_PROXY", "1")
	one("WHISPER_ENFORCED_ADDR", "2a04:2a01::1")
	one("WHISPER_RUN", "777")
	one("PATH", "C:\\Windows")
	if _, ok := m["NO_PROXY"]; ok {
		t.Fatalf("NO_PROXY must go: a host listed there would be dialled directly and refused: %v", m["NO_PROXY"])
	}
}

func TestProxyPortOfAcceptsOnlyTheIPv4LoopbackDoor(t *testing.T) {
	for in, want := range map[string]uint16{
		"socks5h://127.0.0.1:41234": 41234,
		" socks5://127.0.0.1:1 ":    1,
		"http://127.0.0.1:65535":    65535,
	} {
		got, err := proxyPortOf(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "socks5h://", "127.0.0.1:1080", "socks5h://localhost:1080", "socks5h://[::1]:1080",
		"socks5h://10.0.0.1:1080", "socks5h://127.0.0.1", "socks5h://127.0.0.1:0", "socks5h://127.0.0.1:70000",
		"socks5h://127.0.0.1:x", "::not a url"} {
		if p, err := proxyPortOf(bad); err == nil {
			t.Fatalf("%q accepted as the door (port %d): a filter would permit a port no proxy stands behind", bad, p)
		}
	}
}

func TestEnforcedEchoGoesThroughTheProxyOnWindowsOnly(t *testing.T) {
	var direct, proxied int
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct++
		_, _ = w.Write([]byte(`{"ip":"2a04:2a01::d"}`))
	}))
	defer echo.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied++
		_, _ = w.Write([]byte(`{"ip":"2a04:2a01::p"}`))
	}))
	defer proxy.Close()
	c := client.New(client.Config{EchoURL: echo.URL})
	env := map[string]string{"ALL_PROXY": proxy.URL}
	ip, err := enforcedEcho(context.Background(), c, "windows", func(k string) string { return env[k] })
	if err != nil || ip != "2a04:2a01::p" || proxied != 1 || direct != 0 {
		t.Fatalf("windows: ip %q err %v (proxied %d, direct %d)", ip, err, proxied, direct)
	}
	env = map[string]string{"all_proxy": proxy.URL}
	if ip, err = enforcedEcho(context.Background(), c, "windows", func(k string) string { return env[k] }); err != nil || ip != "2a04:2a01::p" {
		t.Fatalf("windows, lower-case variable: %q %v", ip, err)
	}
	ip, err = enforcedEcho(context.Background(), c, "linux", func(k string) string { return env[k] })
	if err != nil || ip != "2a04:2a01::d" || direct != 1 {
		t.Fatalf("linux: the namespace's network is the tunnel, so the echo is asked directly: %q %v", ip, err)
	}
	// No proxy in the environment on Windows: a clear refusal, never a direct dial.
	if _, err := enforcedEcho(context.Background(), c, "windows", func(string) string { return "" }); err == nil || direct != 1 {
		t.Fatalf("windows without a proxy: err %v, direct %d", err, direct)
	}
}
