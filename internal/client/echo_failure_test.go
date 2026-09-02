// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echo_failure_test.go: a failed egress verify must name its cause truthfully. The
// historical defect: EVERY through-proxy failure collapsed to "could not reach the Whisper
// egress to verify your address" - including the egress REJECTING the session's et_ token
// (a 407 upstream), which sent users debugging their network for an auth problem. The
// classifier distinguishes: dead local proxy vs a live local proxy whose upstream egress
// leg refused - and an HTTP 407 from the echo is named as the auth verdict it is.

// startRefusingSocks5 serves a local proxy that completes the SOCKS5 no-auth handshake and
// then REFUSES the CONNECT (REP 0x05) - exactly what the real local proxy does when the
// upstream Whisper egress rejects the session (e.g. a 407 on the tunnel CONNECT).
func startRefusingSocks5(t *testing.T) (endpoint string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				// Greeting: VER NMETHODS METHODS… → select no-auth.
				hdr := make([]byte, 2)
				if _, rerr := io.ReadFull(conn, hdr); rerr != nil || hdr[0] != 0x05 {
					return
				}
				if _, rerr := io.CopyN(io.Discard, conn, int64(hdr[1])); rerr != nil {
					return
				}
				if _, werr := conn.Write([]byte{0x05, 0x00}); werr != nil {
					return
				}
				// Request: read the fixed header + drain what the addr type implies, then
				// refuse. (Draining loosely is fine - we answer and close.)
				req := make([]byte, 4)
				if _, rerr := io.ReadFull(conn, req); rerr != nil {
					return
				}
				switch req[3] {
				case 0x01:
					_, _ = io.CopyN(io.Discard, conn, 4+2)
				case 0x03:
					l := make([]byte, 1)
					if _, rerr := io.ReadFull(conn, l); rerr != nil {
						return
					}
					_, _ = io.CopyN(io.Discard, conn, int64(l[0])+2)
				case 0x04:
					_, _ = io.CopyN(io.Discard, conn, 16+2)
				}
				// REP 0x05: connection refused - the upstream leg failed.
				_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "socks5h://127.0.0.1:" + port
}

// TestObservedEgressIP_UpstreamRefusalNamesTheSessionProblem: the local proxy is ALIVE but
// the egress leg refused - the error must name the session/token possibility and the
// remediation, never the misleading "could not reach" network framing, and never leak the
// loopback endpoint.
func TestObservedEgressIP_UpstreamRefusalNamesTheSessionProblem(t *testing.T) {
	endpoint := startRefusingSocks5(t)
	c := New(Config{})
	_, err := c.ObservedEgressIP(context.Background(), endpoint)
	if err == nil {
		t.Fatal("a refused upstream leg must be an error")
	}
	pe, ok := AsProblem(err)
	if !ok {
		t.Fatalf("want a clean ProblemError, got %T %v", err, err)
	}
	if !strings.Contains(pe.Detail, "session token may have been rejected") ||
		!strings.Contains(pe.Detail, "whisper connect") {
		t.Fatalf("the error must name the token possibility + the remediation, got %q", pe.Detail)
	}
	if strings.Contains(pe.Detail, "could not reach") {
		t.Fatalf("an auth-class refusal must NOT be framed as unreachability, got %q", pe.Detail)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error must not leak the endpoint, got %q", err.Error())
	}
}

// TestObservedEgressIP_DeadLocalProxyIsNamedDistinctly: nothing listens on the endpoint -
// the honest message is that the LOCAL proxy is gone (a crashed/stopped session), with the
// remediation, distinct from an upstream refusal.
func TestObservedEgressIP_DeadLocalProxyIsNamedDistinctly(t *testing.T) {
	// Bind-then-release a loopback port so it is almost certainly dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	c := New(Config{})
	_, err = c.ObservedEgressIP(context.Background(), "socks5h://127.0.0.1:"+strconv.Itoa(port))
	if err == nil {
		t.Fatal("a dead local proxy must be an error")
	}
	if !strings.Contains(err.Error(), "local Whisper proxy is not answering") {
		t.Fatalf("a dead local proxy must be named as such, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the error must not leak the endpoint, got %q", err.Error())
	}
}

// TestFetchEchoIP_407IsAnAuthVerdictNotUnavailability: an HTTP 407 reply on the echo fetch
// is the egress rejecting the session's token - it must surface as the distinct auth
// problem (status 407 + the remediation), never the generic "endpoint was unavailable".
func TestFetchEchoIP_407IsAnAuthVerdictNotUnavailability(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	t.Cleanup(proxy.Close)

	c := New(Config{EchoURL: "http://echo-target.invalid/egress-ip"})
	_, err := c.ObservedEgressIP(context.Background(), proxy.URL)
	pe, ok := AsProblem(err)
	if !ok || pe.Status != http.StatusProxyAuthRequired {
		t.Fatalf("a 407 must be a distinct auth problem, got %v", err)
	}
	if !strings.Contains(pe.Detail, "rejected this session's token") ||
		!strings.Contains(pe.Detail, "whisper connect") {
		t.Fatalf("the 407 must be named as the auth verdict + remediation, got %q", pe.Detail)
	}
	if strings.Contains(pe.Detail, "unavailable") {
		t.Fatalf("a 407 must not be framed as unavailability, got %q", pe.Detail)
	}
}
