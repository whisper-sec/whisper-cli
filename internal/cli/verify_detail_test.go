// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// verify_detail_test.go covers the CLI half: a /verify-identity 400 carries a JSON error
// detail, and the CLI surfaces THAT detail — never an opaque "not a verified agent" misread.

// TestProblemDetail_Shapes: problemDetail is liberal in what it accepts — RFC-7807, message,
// legacy {"error":"…"}, nested {"error":{…}}, and junk (→ the fallback).
func TestProblemDetail_Shapes(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"rfc7807 detail", `{"status":400,"detail":"ip is not a valid IPv6 address"}`, "ip is not a valid IPv6 address"},
		{"rfc7807 title only", `{"status":400,"title":"bad address"}`, "bad address"},
		{"message field", `{"message":"malformed query"}`, "malformed query"},
		{"legacy error string", `{"error":"unparseable ip"}`, "unparseable ip"},
		{"nested error object", `{"error":{"detail":"prefix out of range"}}`, "prefix out of range"},
		{"junk body", `not json at all`, "fallback line"},
		{"empty object", `{}`, "fallback line"},
	}
	for _, c := range cases {
		if got := problemDetail([]byte(c.body), "fallback line"); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestVerify_400SurfacesServerDetail: end-to-end through the verify command — a 400 with an
// RFC-7807 body returns the server's detail as the error (exit non-zero), not the misleading
// "not a verified Whisper agent".
func TestVerify_400SurfacesServerDetail(t *testing.T) {
	srv := problemServer(t, 400, `{"status":400,"detail":"ip is not a valid IPv6 address: zz"}`)
	defer srv.Close()

	saved := g
	g = globalFlags{verifyURL: srv.URL, timeout: 5 * time.Second}
	defer func() { g = saved }()

	cmd := newVerifyCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"zz"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a 400 must be an error")
	}
	if !strings.Contains(err.Error(), "ip is not a valid IPv6 address: zz") {
		t.Fatalf("the 400 detail must be surfaced verbatim, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "not a verified Whisper agent") {
		t.Fatalf("a 400 must not be misread as a negative verdict, got %q", err.Error())
	}
}

// TestMCPVerify_400SurfacesServerDetail: the same surfacing through the MCP tool — a 400
// becomes a tool error carrying the server's detail (so the model can correct the target).
func TestMCPVerify_400SurfacesServerDetail(t *testing.T) {
	srv := problemServer(t, 400, `{"status":400,"detail":"ip is not a valid IPv6 address: zz"}`)
	defer srv.Close()
	pinKeyState(t, "", "")
	g.verifyURL = srv.URL

	r := drive(t, callLine(1, "whisper_verify", `{"target":"zz"}`))
	text, isError := toolText(t, r[0])
	if !isError {
		t.Fatalf("a 400 must be a tool error, got %q", text)
	}
	if !strings.Contains(text, "ip is not a valid IPv6 address: zz") {
		t.Fatalf("the tool error must carry the server detail, got %q", text)
	}
}
