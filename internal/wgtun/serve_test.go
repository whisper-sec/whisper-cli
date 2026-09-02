// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serve_test.go covers the seam: `whale serve` installs its front end BEHIND the
// in-tunnel identity listener rather than binding a second one, so the identity documents
// must keep working unchanged and everything else must reach the front end.

func identityDocs() []ServedDoc {
	return []ServedDoc{
		{Path: "/.well-known/whisper-identity", ContentType: "application/jose", Body: []byte("JWSBYTES")},
		{Path: "/.well-known/jwks.json", ContentType: "application/jwk-set+json", Body: []byte(`{"keys":[]}`)},
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

// TestIdentityDocsSurviveAServeFrontEnd is the regression this seam most has to avoid:
// the trustless verifier fourth leg must not become a proxy hit.
func TestIdentityDocsSurviveAServeFrontEnd(t *testing.T) {
	tun := &Tunnel{}
	tun.SetServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "front end")
	}))
	h := tun.identityHandler(identityDocs())

	rr := get(t, h, "/.well-known/whisper-identity")
	if rr.Code != http.StatusOK || rr.Body.String() != "JWSBYTES" {
		t.Fatalf("the identity doc was shadowed by the serve front end: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "application/jose" {
		t.Fatalf("content-type = %q", rr.Header().Get("Content-Type"))
	}
}

func TestEverythingElseReachesTheServeFrontEnd(t *testing.T) {
	tun := &Tunnel{}
	tun.SetServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "front end: "+r.URL.Path)
	}))
	h := tun.identityHandler(identityDocs())

	for _, path := range []string{"/", "/api/users", "/.well-known/other"} {
		rr := get(t, h, path)
		if rr.Code != http.StatusOK || rr.Body.String() != "front end: "+path {
			t.Errorf("%s: code=%d body=%q; the serve front end was not reached", path, rr.Code, rr.Body.String())
		}
	}
}

// TestWithNoServeHandlerTheListenerIsUnchanged: installing nothing must leave the
// documents-only behaviour byte for byte as it shipped.
func TestWithNoServeHandlerTheListenerIsUnchanged(t *testing.T) {
	tun := &Tunnel{}
	h := tun.identityHandler(identityDocs())
	if rr := get(t, h, "/"); rr.Code != http.StatusNotFound {
		t.Fatalf("an unknown path returned %d with no serve handler installed, want 404", rr.Code)
	}
	if rr := get(t, h, "/.well-known/jwks.json"); rr.Code != http.StatusOK {
		t.Fatalf("jwks returned %d", rr.Code)
	}
}

// TestTheHandlerIsReadPerRequest: bring-up starts the TLS listener before `whale serve`
// exists, so installing later - and removing on teardown - has to take effect live.
func TestTheHandlerIsReadPerRequest(t *testing.T) {
	tun := &Tunnel{}
	h := tun.identityHandler(identityDocs())

	if rr := get(t, h, "/late"); rr.Code != http.StatusNotFound {
		t.Fatalf("before install: %d", rr.Code)
	}
	tun.SetServeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	if rr := get(t, h, "/late"); rr.Code != http.StatusTeapot {
		t.Fatalf("after install: %d; the handler was captured at bind time instead of read per request", rr.Code)
	}
	tun.SetServeHandler(nil)
	if rr := get(t, h, "/late"); rr.Code != http.StatusNotFound {
		t.Fatalf("after teardown: %d; removing the front end left it serving", rr.Code)
	}
}

func TestServingTLSReportsTheRealListener(t *testing.T) {
	var tun *Tunnel
	if tun.ServingTLS() {
		t.Fatal("a nil tunnel claims to be serving")
	}
	tun = &Tunnel{}
	if tun.ServingTLS() {
		t.Fatal("a tunnel with no listener claims to be serving - a serve would install a handler nothing can reach")
	}
	tun.identityLn = fakeListener{}
	if !tun.ServingTLS() {
		t.Fatal("a tunnel with a bound listener reports it is not serving")
	}
	tun.SetServeHandler(nil) // nil-safe on a real tunnel
}

type fakeListener struct{ net.Listener }
