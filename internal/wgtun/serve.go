// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import "net/http"

// serve.go extends the in-tunnel identity listener into the listener
// `whisper whale serve` and `whisper whale funnel` publish on, WITHOUT adding a
// second listener.
//
// There can only be one. The identity leaf is served on the tunnel's own /128 at :443,
// that port is the one the published TLSA pins, and it is the one a peer and an
// `openssl s_client` dial. A serve front end that bound its own second listener would
// either collide with that one or have to move off the port the pin describes. So the
// serve front end is installed BEHIND the existing listener: the gateway-signed documents
// keep their exact well-known paths, and everything else - which used to be a 404 - goes
// to the handler installed here.
//
// Order does not matter. `serve` can install its handler before the tunnel's TLS listener
// starts or after, because the handler is read per request rather than captured at bind
// time. That matters in practice: bring-up starts the identity listener itself, deep
// inside the shared connect path, before the serve command has anything to install.

// SetServeHandler installs (or, with nil, removes) the handler the in-tunnel TLS listener
// uses for every path the gateway-signed identity documents do not claim. Safe to call at
// any time, from any goroutine, including while requests are in flight.
func (t *Tunnel) SetServeHandler(h http.Handler) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.serveH = h
	t.mu.Unlock()
}

// serveHandler reads the installed handler, or nil.
func (t *Tunnel) serveHandler() http.Handler {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.serveH
}

// ServingTLS reports whether the in-tunnel TLS listener is actually up. A serve front end
// asks before it claims to be serving anything: an installed handler behind a listener
// that never bound is precisely the shipped-but-unreachable defect, and it would be
// invisible from inside this process.
func (t *Tunnel) ServingTLS() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.identityLn != nil
}

// identityHandler is what ServeTLS actually serves: the documents at their exact paths,
// the installed serve handler for everything else, and - when nothing is installed - the
// same 404 the documents-only listener always gave.
func (t *Tunnel) identityHandler(docs []ServedDoc) http.Handler {
	mux := docsHandler(docs)
	claimed := make(map[string]bool, len(docs))
	for _, d := range docs {
		claimed[d.Path] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL != nil && claimed[r.URL.Path] {
			mux.ServeHTTP(w, r)
			return
		}
		if h := t.serveHandler(); h != nil {
			h.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
