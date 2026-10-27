// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package testenv

import (
	"net/http"
	"time"
)

// ListingFailure is one way a listing of the account can fail to answer. Every reader of the
// account's agents is tested against all of them: none may be read as an account with no
// agents in it.
type ListingFailure struct {
	Name string
	// Serve answers the listing; nil means the server is not there at all.
	Serve func(w http.ResponseWriter, r *http.Request)
}

// WriteBody answers with status and body as JSON.
func WriteBody(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// ListingFailures is the corpus: no server, a timeout (the caller's client must time out
// well under three seconds), and ten replies that carry no listing.
func ListingFailures() []ListingFailure {
	return []ListingFailure{
		{Name: "unreachable"},
		{Name: "timeout", Serve: func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}},
		{Name: "503 empty body", Serve: WriteBody(http.StatusServiceUnavailable, "")},
		{Name: "503 empty object", Serve: WriteBody(http.StatusServiceUnavailable, `{}`)},
		{Name: "500 problem", Serve: WriteBody(http.StatusInternalServerError,
			`{"type":"about:blank","title":"Internal","status":500,"detail":"boom"}`)},
		{Name: "ok false", Serve: WriteBody(http.StatusOK,
			`{"ok":false,"status":403,"error":{"title":"Forbidden","detail":"no"}}`)},
		{Name: "status in body is not success", Serve: WriteBody(http.StatusOK,
			`{"ok":true,"status":502,"result":{"columns":["kind","item"],"rows":[]}}`)},
		{Name: "ok with no result", Serve: WriteBody(http.StatusOK, `{"ok":true,"status":200}`)},
		{Name: "result with no listing", Serve: WriteBody(http.StatusOK, `{"ok":true,"status":200,"result":{}}`)},
		{Name: "empty object", Serve: WriteBody(http.StatusOK, `{}`)},
		{Name: "not json", Serve: WriteBody(http.StatusOK, `<html>gateway</html>`)},
		{Name: "truncated json", Serve: WriteBody(http.StatusOK,
			`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[`)},
	}
}
