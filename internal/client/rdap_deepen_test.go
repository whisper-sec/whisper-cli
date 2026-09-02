// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- RDAP: the public, keyless RFC 9083 fetch ----------------------------------------

func TestDeepenClientRDAPFetchesTheIPObjectKeyless(t *testing.T) {
	const body = `{"objectClassName":"ip network","handle":"2a04:2a01::1/128"}`
	srv, reqs := deepenclient_server(t, 200, body)
	// A credential IS configured - RDAP is public and must NEVER carry it.
	c := New(Config{RDAPURL: srv.URL, Cred: Credential{Value: "whisper_live_secret"}, HTTPClient: srv.Client()})

	raw, status, err := c.RDAP(context.Background(), RDAPIP, "2a04:2a01::1", "")
	if err != nil {
		t.Fatalf("RDAP: %v", err)
	}
	req := (*reqs)[0]
	if req.method != http.MethodGet || req.path != "/ip/2a04:2a01::1" {
		t.Fatalf("want GET /ip/<v6>, got %s %s", req.method, req.path)
	}
	if req.header.Get("X-API-Key") != "" || req.header.Get("Authorization") != "" {
		t.Fatalf("RDAP must be keyless, got key=%q auth=%q", req.header.Get("X-API-Key"), req.header.Get("Authorization"))
	}
	if req.header.Get("Accept") != "application/rdap+json" {
		t.Fatalf("Accept = %q, want application/rdap+json", req.header.Get("Accept"))
	}
	if status != 200 || string(raw) != body {
		t.Fatalf("verbatim passthrough broken: status=%d raw=%s", status, raw)
	}
}

func TestDeepenClientRDAPDomainKindAndQueryString(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{RDAPURL: srv.URL + "/", HTTPClient: srv.Client()}) // trailing slash trimmed
	_, _, err := c.RDAP(context.Background(), RDAPDomain, "a1.t9.agents.whisper.online", "history")
	if err != nil {
		t.Fatal(err)
	}
	req := (*reqs)[0]
	if req.path != "/domain/a1.t9.agents.whisper.online" {
		t.Fatalf("path = %q", req.path)
	}
	if req.query != "history" {
		t.Fatalf("the ?history query must be appended verbatim, got %q", req.query)
	}
}

func TestDeepenClientRDAPNotFoundBodyIsReturnedVerbatimNotAnError(t *testing.T) {
	// RDAP 404s carry a structured errorCode object the caller renders - the client
	// must pass it through with the status, never turn it into a transport error.
	const nf = `{"errorCode":404,"title":"not found"}`
	srv, _ := deepenclient_server(t, 404, nf)
	c := New(Config{RDAPURL: srv.URL, HTTPClient: srv.Client()})
	raw, status, err := c.RDAP(context.Background(), RDAPIP, "2001:db8::1", "")
	if err != nil {
		t.Fatalf("a 404 with a body is an ANSWER, not an error: %v", err)
	}
	if status != 404 || string(raw) != nf {
		t.Fatalf("status=%d raw=%s", status, raw)
	}
}

func TestDeepenClientRDAPEmptyTargetIsALocal400(t *testing.T) {
	srv, reqs := deepenclient_server(t, 200, `{}`)
	c := New(Config{RDAPURL: srv.URL, HTTPClient: srv.Client()})
	_, _, err := c.RDAP(context.Background(), RDAPIP, "   ", "")
	pe, ok := AsProblem(err)
	if !ok || pe.Status != 400 {
		t.Fatalf("a blank target must be a clean local 400, got %v", err)
	}
	if len(*reqs) != 0 {
		t.Fatal("no request may be made for a blank target")
	}
}

func TestDeepenClientRDAPUnreachableIsWrappedHelpfully(t *testing.T) {
	c := New(Config{RDAPURL: deadBase, HTTPClient: &http.Client{Timeout: 2 * time.Second}})
	_, _, err := c.RDAP(context.Background(), RDAPIP, "2a04:2a01::1", "")
	if err == nil || !strings.Contains(err.Error(), "RDAP unreachable") {
		t.Fatalf("a dial failure must say RDAP is unreachable, got %v", err)
	}
}
