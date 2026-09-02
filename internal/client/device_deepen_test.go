// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ---- DeviceHTTPClient: the zero-config login transport -------------------------------

func TestDeepenClientDeviceHTTPClientIsEmbeddedCAWiredAndBounded(t *testing.T) {
	hc := DeviceHTTPClient()
	if hc.Timeout != DeviceClientTimeout {
		t.Fatalf("timeout = %v, want %v (a login call must never hang)", hc.Timeout, DeviceClientTimeout)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", hc.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("the device client must verify against the embedded-CA pool (zero config on a bare host)")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS floor = %x, want 1.2", tr.TLSClientConfig.MinVersion)
	}
}

func TestDeepenClientDeviceAuthorizeNilClientUsesTheDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"device_code":"dc_1","user_code":"AB-12","verification_uri":"https://console.example/activate"}`)
	}))
	t.Cleanup(srv.Close)
	// hc == nil: the real DeviceHTTPClient must be built and used (plain http here, so
	// the embedded-CA TLS config is simply not consulted).
	da, err := DeviceAuthorize(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatalf("DeviceAuthorize with the default client: %v", err)
	}
	if da.DeviceCode != "dc_1" {
		t.Fatalf("device_code = %q", da.DeviceCode)
	}
}

func TestDeepenClientPollDeviceTokenUnknownStatusKeepsPollingLiberally(t *testing.T) {
	// An unknown status is treated as pending (liberal-accept), so a NEW server-side
	// state can never abort an in-flight login. The next poll approves.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"status":"reviewing"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"approved","api_key":"whisper_live_new"}`)
	}))
	t.Cleanup(srv.Close)
	key, err := PollDeviceToken(context.Background(), nil, srv.URL, "dc_1", 10*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("an unknown status must not abort the login: %v", err)
	}
	if key != "whisper_live_new" {
		t.Fatalf("key = %q", key)
	}
	if calls.Load() < 2 {
		t.Fatalf("want at least 2 polls, got %d", calls.Load())
	}
}

func TestDeepenClientDevicePostJSONCancelledContextSurfacesTheCtxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the caller must see ctx.Err(), not a wrapped dial error
	_, err := DeviceAuthorize(ctx, srv.Client(), srv.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled ctx must surface unwrapped, got %v", err)
	}
}

func TestDeepenClientDeviceAuthorizeUnbuildableURLErrorsCleanly(t *testing.T) {
	// A console URL that cannot form a request (a space in the host) must be a clean
	// error, never a panic deep in the transport.
	if _, err := DeviceAuthorize(context.Background(), &http.Client{}, "http://bad host"); err == nil {
		t.Fatal("an unbuildable URL must error")
	}
}
