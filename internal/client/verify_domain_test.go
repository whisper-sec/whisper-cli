// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// verifyDomainServer is a mock /verify-domain/<apex> endpoint. It asserts the request the
// keyless verdict must be: a GET, on the escaped apex path, asking for JSON, with no key.
func verifyDomainServer(t *testing.T, wantPath string, status int, header map[string]string, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("verify-domain method = %s, want GET", r.Method)
		}
		if r.URL.EscapedPath() != wantPath {
			t.Errorf("verify-domain path = %q, want %q", r.URL.EscapedPath(), wantPath)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
		}
		if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("verify-domain must be keyless, got X-API-Key=%q Authorization=%q",
				r.Header.Get("X-API-Key"), r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("verify-domain sent no User-Agent")
		}
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestVerifyDomainVerified decodes a full verdict, keeps the raw body byte-faithful for --json,
// and keeps a check that was never reached (null) apart from one that failed (false).
func TestVerifyDomainVerified(t *testing.T) {
	body := `{"domain":"example.org","is_whisper_domain":true,"state":"verified","verdict":"delegated, signed and served",` +
		`"checks":{"delegated_to_whisper":true,"ds_matches_key":true,"validates_from_root":true,"child_key_validates":true,"served_by_every_node":true},` +
		`"nameservers":["ns1.whisper.online.","ns2.whisper.online."],"ds":["12345 13 2 abcd"],` +
		`"detail":"","checked_at":1792627200,"settled":true}`
	srv := verifyDomainServer(t, "/verify-domain/example.org", 200, nil, body)
	defer srv.Close()

	c := New(Config{VerifyURL: srv.URL + "/", HTTPClient: srv.Client()})
	v, raw, status, err := c.VerifyDomain(context.Background(), "  example.org \n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if string(raw) != body {
		t.Fatalf("raw body = %q, want the server's bytes", string(raw))
	}
	if !v.IsWhisperDomain || v.State != "verified" || v.Domain != "example.org" {
		t.Fatalf("verdict = %+v", v)
	}
	ch := v.Checks
	for name, p := range map[string]*bool{
		"delegated_to_whisper": ch.DelegatedToWhisper, "ds_matches_key": ch.DSMatchesKey,
		"validates_from_root": ch.ValidatesFromRoot, "child_key_validates": ch.ChildKeyValidates,
		"served_by_every_node": ch.ServedByEveryNode,
	} {
		if p == nil || !*p {
			t.Fatalf("check %s = %v, want true", name, p)
		}
	}
	if !ch.ChildKeyReported {
		t.Fatal("child_key_validates was sent; ChildKeyReported must say so")
	}
	if len(v.Nameservers) != 2 || len(v.DS) != 1 || v.CheckedAt != 1792627200 {
		t.Fatalf("nameservers/ds/checked_at = %v / %v / %d", v.Nameservers, v.DS, v.CheckedAt)
	}
	if v.Settled == nil || !*v.Settled {
		t.Fatalf("settled = %v, want true", v.Settled)
	}
}

// TestVerifyDomainUnreachedChecksStayNil: a chain that stopped at its first link reports the
// later links as not reached, and a server that predates "settled" leaves it nil, not false.
func TestVerifyDomainUnreachedChecksStayNil(t *testing.T) {
	body := `{"domain":"example.net","is_whisper_domain":false,"state":"not_delegated",` +
		`"checks":{"delegated_to_whisper":false,"ds_matches_key":null,"validates_from_root":null}}`
	srv := verifyDomainServer(t, "/verify-domain/example.net", 200, nil, body)
	defer srv.Close()

	v, _, status, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).
		VerifyDomain(context.Background(), "example.net")
	if err != nil || status != 200 {
		t.Fatalf("err=%v status=%d", err, status)
	}
	if v.IsWhisperDomain {
		t.Fatalf("is_whisper_domain = true for a domain that is not delegated")
	}
	if p := v.Checks.DelegatedToWhisper; p == nil || *p {
		t.Fatalf("delegated_to_whisper = %v, want a present false", p)
	}
	if v.Checks.DSMatchesKey != nil || v.Checks.ValidatesFromRoot != nil || v.Checks.ServedByEveryNode != nil ||
		v.Checks.ChildKeyValidates != nil || v.Checks.ChildKeyReported {
		t.Fatalf("an unreached check must stay nil, got %+v", v.Checks)
	}
	if v.Settled != nil {
		t.Fatalf("settled = %v from a server that never sent it, want nil", *v.Settled)
	}
}

// TestVerifyDomainEscapesTheApex: whatever the user typed reaches the server as ONE path
// segment, so a slash or a query character can never address another endpoint.
func TestVerifyDomainEscapesTheApex(t *testing.T) {
	srv := verifyDomainServer(t, "/verify-domain/a%2Fb%3Fc", 400, nil,
		`{"error":"bad_request","detail":"not a domain name"}`)
	defer srv.Close()

	v, _, status, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).
		VerifyDomain(context.Background(), "a/b?c")
	if err != nil {
		t.Fatalf("a 400 with a JSON body is an answer, not an error: %v", err)
	}
	if status != 400 || v.Error != "bad_request" || v.Detail != "not a domain name" {
		t.Fatalf("status=%d verdict=%+v", status, v)
	}
}

// TestVerifyDomainRateLimited: a shed request carries its Retry-After whether or not the
// body is JSON, so the caller can say when to try again.
func TestVerifyDomainRateLimited(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantError  string
	}{
		{"429 with a JSON refusal", `{"error":"rate_limited","detail":"slow down"}`, 429, "rate_limited"},
		{"429 from a proxy, no JSON", `Too Many Requests`, 429, ""},
		{"503 from a proxy, no JSON", `<html>busy</html>`, 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := verifyDomainServer(t, "/verify-domain/example.com", tc.status,
				map[string]string{"Retry-After": " 30 "}, tc.body)
			defer srv.Close()

			v, raw, status, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).
				VerifyDomain(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("a shed request is an answer, not an error: %v", err)
			}
			if status != tc.status || v.RetryAfter != "30" || v.Error != tc.wantError {
				t.Fatalf("status=%d retryAfter=%q error=%q", status, v.RetryAfter, v.Error)
			}
			if string(raw) != tc.body {
				t.Fatalf("raw = %q, want %q", raw, tc.body)
			}
		})
	}
}

// TestVerifyDomainNonJSONIsAClearError: any other status with a body that is not JSON names
// the status and the server instead of returning a zero verdict a script would read as "no".
func TestVerifyDomainNonJSONIsAClearError(t *testing.T) {
	srv := verifyDomainServer(t, "/verify-domain/example.com", 502, nil, `<html>bad gateway</html>`)
	defer srv.Close()

	v, raw, status, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).
		VerifyDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatalf("expected an error, got verdict %+v", v)
	}
	if v != nil {
		t.Fatalf("a failed decode returned a verdict: %+v", v)
	}
	if status != 502 || string(raw) != `<html>bad gateway</html>` {
		t.Fatalf("status=%d raw=%q", status, raw)
	}
	if !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("error %q does not name the status and the server", err)
	}
}

// TestVerifyDomainBlankApex is refused on the client as a 400 and never becomes a request.
func TestVerifyDomainBlankApex(t *testing.T) {
	c := New(Config{VerifyURL: "http://127.0.0.1:1"})
	_, _, status, err := c.VerifyDomain(context.Background(), " \t ")
	if err == nil {
		t.Fatal("expected an error for a blank apex")
	}
	if pe, ok := AsProblem(err); !ok || pe.Status != 400 {
		t.Fatalf("want a 400 ProblemError, got %v", err)
	}
	if status != 0 {
		t.Fatalf("status = %d, want 0: nothing was asked", status)
	}
}

// TestVerifyDomainUnreachable names the endpoint it could not reach.
func TestVerifyDomainUnreachable(t *testing.T) {
	addr, _ := testenv.RefusedPort(t) // nothing listens there, and nothing else can start to
	base := "http://" + addr

	_, _, _, err := New(Config{VerifyURL: base, HTTPClient: &http.Client{}}).
		VerifyDomain(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "verify-domain unreachable at "+base) {
		t.Fatalf("err = %v, want it to name %s", err, base)
	}
}

// TestVerifyDomainBadURL: a verify URL that cannot form a request is an error, not a panic.
func TestVerifyDomainBadURL(t *testing.T) {
	_, _, status, err := New(Config{VerifyURL: "http://bad host"}).VerifyDomain(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("err = %v, want the URL parse error", err)
	}
	if status != 0 {
		t.Fatalf("status = %d, want 0: no request was sent", status)
	}
}

// TestVerifyDomainTruncatedBody: a reply cut short mid-body is reported with its status, not
// decoded from the fragment that arrived.
func TestVerifyDomainTruncatedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"state":`)) // the server promised 200 bytes and stops at 9
	}))
	defer srv.Close()

	v, _, status, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).
		VerifyDomain(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "reading verify-domain reply") {
		t.Fatalf("err = %v, verdict = %+v; want a read error", err, v)
	}
	if status != 200 {
		t.Fatalf("status = %d, want the 200 the server sent before it stopped", status)
	}
}

// TestVerifyDomainChildKeyNullIsReportedFalseIsPresent keeps the three states of the fifth check
// apart: a null the server sent is "not checked", a false is a check that failed, and the
// two are both reported, unlike a key the server never sent.
func TestVerifyDomainChildKeyNullIsReportedFalseIsPresent(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want *bool
	}{{"null", nil}, {"false", new(bool)}} {
		body := `{"domain":"example.org","is_whisper_domain":false,"state":"pending",` +
			`"checks":{"delegated_to_whisper":true,"ds_matches_key":true,"validates_from_root":true,"child_key_validates":` + tc.raw + `}}`
		srv := verifyDomainServer(t, "/verify-domain/example.org", 200, nil, body)
		v, _, _, err := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()}).VerifyDomain(context.Background(), "example.org")
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if !v.Checks.ChildKeyReported {
			t.Fatalf("%s: a key the server sent must count as reported", tc.raw)
		}
		got := v.Checks.ChildKeyValidates
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Fatalf("%s: child_key_validates = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
