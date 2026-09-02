// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"strings"
	"testing"
)

// servetarget_test.go pins the Postel boundary: every spelling a person reaches for means
// the same origin, and everything we cannot serve is refused BY NAME rather than guessed
// into a serve that starts and answers nothing.

func TestParseServeTargetAcceptsEverySpelling(t *testing.T) {
	cases := map[string]string{
		"3000":                      "http://127.0.0.1:3000/",
		":3000":                     "http://127.0.0.1:3000/",
		" 3000 ":                    "http://127.0.0.1:3000/",
		"localhost:3000":            "http://localhost:3000/",
		"127.0.0.1:8080":            "http://127.0.0.1:8080/",
		"[::1]:8080":                "http://[::1]:8080/",
		"http://127.0.0.1:3000":     "http://127.0.0.1:3000/",
		"http://localhost:3000/api": "http://localhost:3000/api",
		"https://127.0.0.1:8443":    "https://127.0.0.1:8443/",
		"http://example.internal":   "http://example.internal:80/",
		"https://example.internal":  "https://example.internal:443/",
	}
	for in, want := range cases {
		got, err := ParseServeTarget(in)
		if err != nil {
			t.Errorf("ParseServeTarget(%q) failed: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("ParseServeTarget(%q) = %q, want %q", in, got.String(), want)
		}
	}
}

func TestParseServeTargetKnowsWhatIsLocal(t *testing.T) {
	for _, in := range []string{"3000", "localhost:3000", "[::1]:3000", "http://127.0.0.1:9"} {
		got, err := ParseServeTarget(in)
		if err != nil || !got.Loopback {
			t.Errorf("%q should be loopback (err=%v)", in, err)
		}
	}
	got, err := ParseServeTarget("http://db.internal:5432")
	if err != nil || got.Loopback {
		t.Errorf("a remote origin was reported as loopback (err=%v)", err)
	}
}

func TestParseServeTargetRefusesWithAReason(t *testing.T) {
	cases := map[string]string{
		"":                    "give the local port",
		"0":                   "1 to 65535",
		"70000":               "1 to 65535",
		"./public":            "looks like a path",
		"/var/www":            "looks like a path",
		`text:"hello"`:        "not supported",
		"ftp://host:21":       "not a scheme we can proxy",
		"ws://127.0.0.1:3000": "http://127.0.0.1:3000",
		"2a04:2a01::5":        "[2a04:2a01::5]:3000",
		"not a target":        "is not a port, a host:port or a URL",
	}
	for in, want := range cases {
		_, err := ParseServeTarget(in)
		if err == nil {
			t.Errorf("ParseServeTarget(%q) was accepted", in)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ParseServeTarget(%q) said %q, which does not contain %q", in, err.Error(), want)
		}
	}
}

func TestMountPathNormalises(t *testing.T) {
	cases := map[string]string{"": "/", "/": "/", "api": "/api", "/api": "/api", "/api/": "/api", "/api///": "/api"}
	for in, want := range cases {
		got, err := MountPath(in)
		if err != nil || got != want {
			t.Errorf("MountPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/a b", "/../etc"} {
		if _, err := MountPath(bad); err == nil {
			t.Errorf("MountPath(%q) was accepted", bad)
		}
	}
}
