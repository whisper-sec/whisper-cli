// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Whisper Security / viaGraph B.V.
package wgtun

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The in-tunnel identity listener serves the gateway-signed docs at their well-known paths so a
// trustless DANE verifier's fourth leg (identity_doc) no longer times out; unknown paths 404, non-GET 405.
func TestDocsHandlerServesEachDocWithContentType(t *testing.T) {
	docs := []ServedDoc{
		{Path: "/.well-known/whisper-identity", ContentType: "application/jose", Body: []byte("JWSBYTES")},
		{Path: "/.well-known/jwks.json", ContentType: "application/jwk-set+json", Body: []byte(`{"keys":[]}`)},
	}
	h := docsHandler(docs)

	// identity-doc: 200 + exact body + content-type
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/whisper-identity", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "JWSBYTES" {
		t.Fatalf("identity-doc: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/jose" {
		t.Fatalf("identity-doc content-type = %q", ct)
	}

	// jwks: served too
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("jwks: code=%d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
	}

	// HEAD: 200, no body
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "/.well-known/whisper-identity", nil))
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("HEAD: code=%d bodylen=%d", rr.Code, rr.Body.Len())
	}

	// unknown path: 404
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown path: want 404, got %d", rr.Code)
	}

	// POST: 405 (+ Allow)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/.well-known/whisper-identity", nil))
	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") == "" {
		t.Fatalf("POST: want 405+Allow, got %d allow=%q", rr.Code, rr.Header().Get("Allow"))
	}
}

// With no docs (a fetch that missed everything), the handler 404s everything - the DANE handshake leg is
// unaffected (it needs no HTTP), so the tunnel still serves 3/4 rather than failing bring-up.
func TestDocsHandlerEmptyDocs404sEverything(t *testing.T) {
	h := docsHandler(nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/whisper-identity", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("empty docs: want 404, got %d", rr.Code)
	}
}

// A doc with no content-type falls back to application/octet-stream (never a blank type).
func TestDocsHandlerDefaultsContentType(t *testing.T) {
	h := docsHandler([]ServedDoc{{Path: "/x", Body: []byte("y")}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("default content-type = %q", ct)
	}
}
