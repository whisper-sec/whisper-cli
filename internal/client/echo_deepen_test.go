// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- the keyless source-IP echo (direct + proxied) -----------------------------------

func TestDeepenClientDirectEgressIPReadsTheKeylessEcho(t *testing.T) {
	var sawKey, sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey, sawAuth = r.Header.Get("X-API-Key"), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"2a04:2a01:9::abcd"}`)
	}))
	t.Cleanup(srv.Close)

	// A credential IS configured - the echo is public and must never carry it.
	c := New(Config{EchoURL: srv.URL, Cred: Credential{Value: "whisper_live_secret"}})
	ip, err := c.DirectEgressIP(context.Background())
	if err != nil {
		t.Fatalf("DirectEgressIP: %v", err)
	}
	if ip != "2a04:2a01:9::abcd" {
		t.Fatalf("ip = %q", ip)
	}
	if sawKey != "" || sawAuth != "" {
		t.Fatalf("the echo must be keyless, got key=%q auth=%q", sawKey, sawAuth)
	}
}

func TestDeepenClientDirectEgressIPAcceptsABareTextEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.9\n")
	}))
	t.Cleanup(srv.Close)
	c := New(Config{EchoURL: srv.URL})
	ip, err := c.DirectEgressIP(context.Background())
	if err != nil || ip != "203.0.113.9" {
		t.Fatalf("a curl-style text/plain echo must parse (Postel), got ip=%q err=%v", ip, err)
	}
}

func TestDeepenClientDirectEgressIPNon2xxIsAProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	t.Cleanup(srv.Close)
	c := New(Config{EchoURL: srv.URL})
	_, err := c.DirectEgressIP(context.Background())
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 503 {
		t.Fatalf("a 5xx echo must be a clean problem, got %v", err)
	}
}

func TestDeepenClientDirectEgressIPUnreadableBodyIsAClearError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not an ip at all")
	}))
	t.Cleanup(srv.Close)
	c := New(Config{EchoURL: srv.URL})
	_, err := c.DirectEgressIP(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("a garbled echo body must be a clear error, got %v", err)
	}
}

func TestDeepenClientDirectEgressIPUnreachableEchoIsFriendlyAndNonLeaky(t *testing.T) {
	c := New(Config{EchoURL: deadBase})
	_, err := c.DirectEgressIP(context.Background())
	// The DIRECT fetch never rides the egress, so the message names the verification
	// service - it must not blame "the Whisper egress" for a plain network failure.
	if err == nil || !strings.Contains(err.Error(), "could not reach the egress verification service") {
		t.Fatalf("want the friendly unreachable message, got %v", err)
	}
	// The error must NOT leak the endpoint/proxy internals.
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error must not leak the endpoint, got %q", err.Error())
	}
}

func TestDeepenClientObservedEgressIPRoutesThroughTheSuppliedProxy(t *testing.T) {
	// The "proxy" answers every request itself and records the target host it was
	// asked for - proving the echo request genuinely rode the supplied endpoint
	// (an http:// target sent via a proxy arrives as an absolute-URI request).
	var sawHost string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"2a04:2a01:77::128"}`)
	}))
	t.Cleanup(proxy.Close)

	c := New(Config{EchoURL: "http://echo-target.invalid/egress-ip"})
	ip, err := c.ObservedEgressIP(context.Background(), proxy.URL)
	if err != nil {
		t.Fatalf("ObservedEgressIP via proxy: %v", err)
	}
	if ip != "2a04:2a01:77::128" {
		t.Fatalf("ip = %q", ip)
	}
	if sawHost != "echo-target.invalid" {
		t.Fatalf("the request must ride the proxy toward the echo host, proxy saw host %q", sawHost)
	}
}

func TestDeepenClientObservedEgressIPMalformedProxyEndpoint(t *testing.T) {
	c := New(Config{})
	_, err := c.ObservedEgressIP(context.Background(), "://not-a-url")
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 400 || !strings.Contains(pe.Detail, "malformed") {
		t.Fatalf("a malformed proxy endpoint must be a clean 400, got %v", err)
	}
}
