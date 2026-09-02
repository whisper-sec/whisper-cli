// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dialguard_test.go proves the guard is armed in THIS process, on the client the
// CLI actually builds, and that it still lets a normal test through.
//
// The proof has to be the real client. A unit test that reached production did so
// through client.New, so that is what is put in front of the guard here.

func TestAUnitTestCannotReachTheControlPlane(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "whisper_live_not_a_real_key"}})

	_, err := c.Agents(context.Background(), "list", map[string]any{})
	if err == nil {
		t.Fatal("a unit test just talked to the live control plane; that is exactly the accident this exists to make impossible")
	}
	if !errors.Is(err, ErrTestNetworkRefused) {
		t.Fatalf("the dial must be REFUSED, not merely fail: %v", err)
	}
	if !strings.Contains(err.Error(), AllowNetworkEnv) {
		t.Fatalf("the refusal must name the way out for a deliberately-live suite: %v", err)
	}
}

func TestTheGuardStillAllowsALoopbackTestServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["ok"],"rows":[{"ok":true}]}`))
	}))
	defer srv.Close()

	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "whisper_live_test"}})
	if _, err := c.Agents(context.Background(), "list", map[string]any{}); err != nil {
		t.Fatalf("a guard that blocks httptest blocks every honest test in the module: %v", err)
	}
}

func TestLoopbackIsRecognisedInEveryShapeATestWritesIt(t *testing.T) {
	allowed := []string{
		"127.0.0.1:8080", "127.0.0.1", "[::1]:443", "::1",
		"localhost:1234", "LOCALHOST", "api.localhost:80", "127.99.1.2:53", "",
	}
	for _, a := range allowed {
		if err := allowDial(a); err != nil {
			t.Fatalf("allowDial(%q) refused a loopback address: %v", a, err)
		}
	}
	refused := []string{
		"graph.whisper.online:443", "8.8.8.8:53", "[2a04:2a01::1]:443",
		"example.com", "10.0.0.1:80", "169.254.169.254:80",
	}
	for _, a := range refused {
		if err := allowDial(a); err == nil {
			t.Fatalf("allowDial(%q) let a test reach off-box", a)
		}
	}
}

func TestTheEscapeHatchIsExplicitAndPerRun(t *testing.T) {
	if err := allowDial("graph.whisper.online:443"); err == nil {
		t.Fatal("off-box must be refused by default")
	}
	t.Setenv(AllowNetworkEnv, "1")
	if err := allowDial("graph.whisper.online:443"); err != nil {
		t.Fatalf("a deliberately-live suite must be able to opt in: %v", err)
	}
}
