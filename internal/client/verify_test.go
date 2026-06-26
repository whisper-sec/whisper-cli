// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVerifyIdentity drives client.VerifyIdentity against a mock /verify-identity endpoint:
// it must GET (keyless), send ?ip=<addr>, decode the verdict, and return the verbatim body
// + the HTTP status so a script branches on the right answer.
func TestVerifyIdentity(t *testing.T) {
	cases := []struct {
		name        string
		addr        string
		status      int
		body        string
		wantErr     bool
		wantStatus  int
		wantAgent   bool
		wantDaneOK  bool
		wantFQDN    string
		wantMatches *bool
	}{
		{
			name:   "verified agent, served leaf matches the pin",
			addr:   "2a04:2a01::1",
			status: 200,
			body: `{"is_whisper_agent":true,"fqdn":"a1.t9.agents.whisper.online",` +
				`"operator":"t9","tenant":"t9","dane_ok":true,"jws_ok":true,` +
				`"evidence":{"dane_tlsa_sha256":"aa","dane":{"usage":3,"selector":1,"matching":1,` +
				`"served_leaf_matches":true}}}`,
			wantStatus:  200,
			wantAgent:   true,
			wantDaneOK:  true,
			wantFQDN:    "a1.t9.agents.whisper.online",
			wantMatches: boolPtr(true),
		},
		{
			name:        "agent but DANE drift, served leaf does NOT match",
			addr:        "2a04:2a01::2",
			status:      200,
			body:        `{"is_whisper_agent":true,"fqdn":"a2.t9.agents.whisper.online","dane_ok":false,"evidence":{"dane":{"served_leaf_matches":false}}}`,
			wantStatus:  200,
			wantAgent:   true,
			wantDaneOK:  false,
			wantFQDN:    "a2.t9.agents.whisper.online",
			wantMatches: boolPtr(false),
		},
		{
			name:       "not a whisper agent -> clean 404",
			addr:       "2001:db8::dead",
			status:     404,
			body:       `{"is_whisper_agent":false,"detail":"no Whisper agent identity anchors this address"}`,
			wantStatus: 404,
			wantAgent:  false,
			wantDaneOK: false,
		},
		{
			name:       "malformed address -> clean 400",
			addr:       "not-an-ip",
			status:     400,
			body:       `{"error":"bad_request","detail":"provide a valid IP literal"}`,
			wantStatus: 400,
			wantAgent:  false,
		},
		{
			name:       "non-JSON body is surfaced as a clear error, not a decode panic",
			addr:       "2a04:2a01::9",
			status:     502,
			body:       `<html>bad gateway</html>`,
			wantErr:    true,
			wantStatus: 502,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("verify method = %s, want GET", r.Method)
				}
				if r.URL.Path != "/verify-identity" {
					t.Errorf("verify hit wrong path %q, want /verify-identity", r.URL.Path)
				}
				if got := r.URL.Query().Get("ip"); got != c.addr {
					t.Errorf("verify ?ip = %q, want %q", got, c.addr)
				}
				// Keyless: assert NO auth header is ever sent on the public verify surface.
				if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
					t.Errorf("verify must be keyless, got X-API-Key=%q Authorization=%q",
						r.Header.Get("X-API-Key"), r.Header.Get("Authorization"))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			c2 := New(Config{VerifyURL: srv.URL, HTTPClient: srv.Client()})
			v, raw, status, err := c2.VerifyIdentity(context.Background(), c.addr)

			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got verdict=%+v", v)
				}
				if strings.TrimSpace(err.Error()) == "" {
					t.Fatalf("error message is empty")
				}
				if status != c.wantStatus {
					t.Fatalf("status = %d, want %d", status, c.wantStatus)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status != c.wantStatus {
				t.Fatalf("status = %d, want %d", status, c.wantStatus)
			}
			if v.IsWhisperAgent != c.wantAgent {
				t.Fatalf("is_whisper_agent = %v, want %v", v.IsWhisperAgent, c.wantAgent)
			}
			if v.DaneOK != c.wantDaneOK {
				t.Fatalf("dane_ok = %v, want %v", v.DaneOK, c.wantDaneOK)
			}
			if c.wantFQDN != "" && v.FQDN != c.wantFQDN {
				t.Fatalf("fqdn = %q, want %q", v.FQDN, c.wantFQDN)
			}
			// The raw body is byte-faithful (a script sees exactly what the server sent).
			if string(raw) != c.body {
				t.Fatalf("raw body = %q, want %q", string(raw), c.body)
			}
			// served_leaf_matches is decoded out of the verbatim evidence (the cross-check signal).
			if c.wantMatches != nil {
				got := decodeServedMatches(t, v.Evidence)
				if got == nil || *got != *c.wantMatches {
					t.Fatalf("served_leaf_matches = %v, want %v", got, *c.wantMatches)
				}
			}
		})
	}
}

// TestVerifyIdentityEmptyAddr asserts the liberal-but-strict input guard: a blank address is
// a clean client-side 400, never a request.
func TestVerifyIdentityEmptyAddr(t *testing.T) {
	c := New(Config{VerifyURL: "https://rdap.whisper.online"})
	_, _, _, err := c.VerifyIdentity(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected an error for a blank address")
	}
	if pe, ok := AsProblem(err); !ok || pe.Status != 400 {
		t.Fatalf("want a 400 ProblemError, got %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }

func decodeServedMatches(t *testing.T, ev json.RawMessage) *bool {
	t.Helper()
	var e struct {
		Dane *struct {
			ServedLeafMatches *bool `json:"served_leaf_matches"`
		} `json:"dane"`
	}
	if len(ev) == 0 || json.Unmarshal(ev, &e) != nil || e.Dane == nil {
		return nil
	}
	return e.Dane.ServedLeafMatches
}
