// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "testing"

// TestParseEchoIP: the echo body is read liberally — a JSON {"ip":…} object OR a bare
// text/plain IP line (Postel: liberal in what we accept).
func TestParseEchoIP(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json object", `{"ip":"2a04:2a01:9::abcd"}`, "2a04:2a01:9::abcd"},
		{"json with extra fields", `{"ip":"2a04:2a01::1","seen":"now"}`, "2a04:2a01::1"},
		{"bare text v6", "2a04:2a01:9::dead\n", "2a04:2a01:9::dead"},
		{"bare text v4", "203.0.113.7", "203.0.113.7"},
		{"empty json ip", `{"ip":""}`, ""},
		{"garbage", "not an ip at all", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEchoIP([]byte(tc.body)); got != tc.want {
				t.Fatalf("parseEchoIP(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestObservedEgressIP_EmptyEndpoint: no proxy ⇒ a clean problem, never a panic.
func TestObservedEgressIP_EmptyEndpoint(t *testing.T) {
	c := New(Config{Cred: Credential{Value: "k"}})
	if _, err := c.ObservedEgressIP(nil, ""); err == nil {
		t.Fatal("an empty proxy endpoint must be a clean error")
	}
}
