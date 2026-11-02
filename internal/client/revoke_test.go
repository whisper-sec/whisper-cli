// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"errors"
	"testing"
)

// TestRevokeMatchedNothing pins the two shapes of "nothing was revoked" every revoke client
// reads, and the near misses that must NOT read as it: a real revoke, a 404 without
// the code (a wrong URL or a proxy), and the code on a status that is not 404.
func TestRevokeMatchedNothing(t *testing.T) {
	decode := func(body string, status int) *Envelope {
		t.Helper()
		env, err := DecodeEnvelope([]byte(body), status)
		if err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return env
	}
	for _, tc := range []struct {
		name string
		env  *Envelope
		err  error
		want bool
	}{
		{"the plane's 404 NOT_FOUND envelope", decode(`{"ok":false,"status":404,"result":null,`+
			`"error":{"code":"NOT_FOUND","message":"nothing was revoked","retryable":false}}`, 404), nil, true},
		// The front door's shape: HTTP 200 and the 404 inside the 7-column envelope row.
		{"the front door's in-row 404 NOT_FOUND", decode(`{"columns":["op","ok","status","result","error",`+
			`"retry_after","elapsed_ms"],"rows":[["revoke",false,404,null,`+
			`{"code":"NOT_FOUND","message":"nothing was revoked","retryable":false},null,3]]}`, 200), nil, true},
		{"NOT_FOUND with no status", nil, &ProblemError{Title: "NOT_FOUND"}, true},
		{"an older plane's ok row", decode(`{"ok":true,"status":200,"result":{"columns":["agent","status"],`+
			`"rows":[["x","not_found"]]}}`, 200), nil, true},
		{"an older plane's ok row under item", decode(`{"ok":true,"status":200,"result":{"columns":["item"],`+
			`"rows":[[{"agent":"x","status":"NOT_FOUND"}]]}}`, 200), nil, true},
		{"a real revoke", decode(`{"ok":true,"status":200,"result":{"columns":["agent","status"],`+
			`"rows":[["x","revoked"]]}}`, 200), nil, false},
		{"ok with no rows", decode(`{"ok":true,"status":200,"result":{"columns":["agent"],"rows":[]}}`, 200), nil, false},
		{"a 404 without the code", nil, &ProblemError{Status: 404, Detail: "page not found"}, false},
		{"the code on a 403", nil, &ProblemError{Status: 403, Title: "NOT_FOUND"}, false},
		{"a transport error", nil, errors.New("NOT_FOUND"), false},
		{"nothing at all", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RevokeMatchedNothing(tc.env, tc.err); got != tc.want {
				t.Fatalf("RevokeMatchedNothing = %v, want %v", got, tc.want)
			}
		})
	}
}
