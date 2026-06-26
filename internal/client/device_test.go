// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- DeviceAuthorize --------------------------------------------------------------

func TestDeviceAuthorize(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantErr    bool
		wantCode   string // user_code on success
		wantDevice string // device_code on success
	}{
		{
			name:       "well-formed reply parses",
			status:     200,
			body:       `{"device_code":"dev-abc","user_code":"WXYZ-1234","verification_uri":"https://console.whisper.security/device","verification_uri_complete":"https://console.whisper.security/device?code=WXYZ-1234","interval":5,"expires_in":600}`,
			wantCode:   "WXYZ-1234",
			wantDevice: "dev-abc",
		},
		{
			name:    "non-200 -> clean ProblemError",
			status:  503,
			body:    `{"detail":"console down"}`,
			wantErr: true,
		},
		{
			name:    "malformed JSON -> clean error, no panic",
			status:  200,
			body:    `{not-json`,
			wantErr: true,
		},
		{
			name:    "missing device_code -> incomplete error",
			status:  200,
			body:    `{"user_code":"AB","verification_uri":"https://x/d"}`,
			wantErr: true,
		},
		{
			name:    "missing verification URL -> incomplete error",
			status:  200,
			body:    `{"device_code":"dev-1"}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/device/authorize" {
					t.Errorf("authorize hit wrong path %q", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("authorize method = %s, want POST", r.Method)
				}
				// The device endpoints are keyless: assert NO auth header is sent.
				if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
					t.Errorf("authorize must be keyless, got X-API-Key=%q Authorization=%q",
						r.Header.Get("X-API-Key"), r.Header.Get("Authorization"))
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			auth, err := DeviceAuthorize(context.Background(), srv.Client(), srv.URL)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got auth=%+v", auth)
				}
				// Errors must be clean (a *ProblemError or a wrapped transport error), never empty.
				if strings.TrimSpace(err.Error()) == "" {
					t.Fatalf("error message is empty")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if auth.UserCode != c.wantCode {
				t.Fatalf("user_code = %q, want %q", auth.UserCode, c.wantCode)
			}
			if auth.DeviceCode != c.wantDevice {
				t.Fatalf("device_code = %q, want %q", auth.DeviceCode, c.wantDevice)
			}
			if auth.PollInterval() != 5*time.Second {
				t.Fatalf("poll interval = %v, want 5s", auth.PollInterval())
			}
			if auth.Lifetime() != 600*time.Second {
				t.Fatalf("lifetime = %v, want 600s", auth.Lifetime())
			}
			if auth.OpenURL() == "" {
				t.Fatalf("OpenURL is empty")
			}
		})
	}
}

func TestDeviceAuthDefaults(t *testing.T) {
	// A reply with no interval/expires_in must fall back to RFC 8628 / conservative
	// defaults (liberal-accept: a sparse reply still works).
	d := DeviceAuth{DeviceCode: "x", VerificationURI: "https://x/d"}
	if d.PollInterval() != 5*time.Second {
		t.Fatalf("default interval = %v, want 5s", d.PollInterval())
	}
	if d.Lifetime() != 10*time.Minute {
		t.Fatalf("default lifetime = %v, want 10m", d.Lifetime())
	}
	if d.OpenURL() != "https://x/d" {
		t.Fatalf("OpenURL fell back wrong: %q", d.OpenURL())
	}
	// verification_uri_complete is preferred when present.
	d.VerificationURIComplete = "https://x/d?code=AB"
	if d.OpenURL() != "https://x/d?code=AB" {
		t.Fatalf("OpenURL did not prefer the complete URI: %q", d.OpenURL())
	}
}

// --- PollDeviceToken --------------------------------------------------------------

func TestPollDeviceToken_PendingThenApproved(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/device/token" {
			t.Errorf("poll hit wrong path %q", r.URL.Path)
		}
		// Keyless poll too.
		if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("poll must be keyless")
		}
		n := atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
		if n < 3 {
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"approved","api_key":"whisper_live_secret"}`))
	}))
	defer srv.Close()

	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 5*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "whisper_live_secret" {
		t.Fatalf("api_key = %q, want whisper_live_secret", key)
	}
	if atomic.LoadInt32(&hits) < 3 {
		t.Fatalf("expected >=3 polls (pending,pending,approved), got %d", hits)
	}
}

func TestPollDeviceToken_StopsOnExpired(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"expired"}`))
	}))
	defer srv.Close()

	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 5*time.Millisecond, 5*time.Second)
	if err == nil {
		t.Fatalf("expected an expired error, got key=%q", key)
	}
	if key != "" {
		t.Fatalf("key must be empty on expiry, got %q", key)
	}
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 410 {
		t.Fatalf("expected a 410 ProblemError on expiry, got %v", err)
	}
	// It must STOP on the first expired reply, not keep polling.
	if h := atomic.LoadInt32(&hits); h != 1 {
		t.Fatalf("expected exactly 1 poll before stopping on expired, got %d", h)
	}
}

func TestPollDeviceToken_ApprovedWithoutKey(t *testing.T) {
	// Defensive contract: approved but no api_key -> a clean error, never a "" key
	// silently treated as success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"approved"}`))
	}))
	defer srv.Close()

	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 5*time.Millisecond, 5*time.Second)
	if err == nil || key != "" {
		t.Fatalf("expected an error and empty key, got key=%q err=%v", key, err)
	}
}

func TestPollDeviceToken_DeadlineElapses(t *testing.T) {
	// Always pending: the poll must give up at the deadline with a clear timeout error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	start := time.Now()
	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 10*time.Millisecond, 60*time.Millisecond)
	if err == nil {
		t.Fatalf("expected a deadline error, got key=%q", key)
	}
	if key != "" {
		t.Fatalf("key must be empty on deadline, got %q", key)
	}
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 408 {
		t.Fatalf("expected a 408 timeout ProblemError, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("poll overran the deadline: took %v", elapsed)
	}
}

func TestPollDeviceToken_ContextCancel(t *testing.T) {
	// A cancelled parent context must abort the poll promptly (Ctrl-C), surfacing the
	// ctx error rather than a timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	key, err := PollDeviceToken(ctx, srv.Client(), srv.URL, "dev-abc", 10*time.Millisecond, 10*time.Second)
	if err == nil {
		t.Fatalf("expected a cancellation error, got key=%q", key)
	}
	if key != "" {
		t.Fatalf("key must be empty on cancel, got %q", key)
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected a context-canceled error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancel did not abort promptly: took %v", elapsed)
	}
}

func TestPollDeviceToken_MalformedReplyKeepsPollingThenSucceeds(t *testing.T) {
	// A momentary malformed reply during polling must NOT abort the flow (Postel: a blip
	// is tolerated); a subsequent approval still wins before the deadline.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
		if n == 1 {
			_, _ = w.Write([]byte(`{garbage`)) // malformed once
			return
		}
		_, _ = w.Write([]byte(`{"status":"approved","api_key":"k2"}`))
	}))
	defer srv.Close()

	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 5*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("a single malformed poll should not abort: %v", err)
	}
	if key != "k2" {
		t.Fatalf("key = %q, want k2", key)
	}
}

func TestPollDeviceToken_Non200KeepsPollingUntilDeadline(t *testing.T) {
	// A persistent non-200 during polling is treated as a transient blip and retried
	// until the deadline, then surfaces the last error (never a panic, never a key).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	defer srv.Close()

	key, err := PollDeviceToken(context.Background(), srv.Client(), srv.URL, "dev-abc", 10*time.Millisecond, 60*time.Millisecond)
	if err == nil || key != "" {
		t.Fatalf("expected an error and empty key, got key=%q err=%v", key, err)
	}
}

func TestPollDeviceToken_NoDeviceCode(t *testing.T) {
	key, err := PollDeviceToken(context.Background(), http.DefaultClient, "https://console.whisper.security", "  ", time.Second, time.Minute)
	if err == nil || key != "" {
		t.Fatalf("expected a clean error for an empty device_code, got key=%q err=%v", key, err)
	}
}

func TestConsoleBaseNormalises(t *testing.T) {
	cases := map[string]string{
		"":                                   DefaultConsoleURL,
		"  ":                                 DefaultConsoleURL,
		"https://c.example/":                 "https://c.example",
		"https://c.example":                  "https://c.example",
		"https://c.example///":               "https://c.example",
		" https://console.whisper.security ": "https://console.whisper.security",
	}
	for in, want := range cases {
		if got := consoleBase(in); got != want {
			t.Fatalf("consoleBase(%q) = %q, want %q", in, got, want)
		}
	}
}
