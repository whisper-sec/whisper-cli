// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// echo_reach_test.go covers the second observation.
//
// The echo above it is a Whisper-owned host, so it can only ever prove that traffic reaches
// WHISPER. On a tenant whose policy is `default block` with a short allow list, that fetch
// succeeds while essentially nothing else can leave, and the panel drew a confident green over
// it. ReachOutside is the pair of observations that tells those two states apart, and what these
// tests pin is that it reports what it measured and nothing more: a refusal is not a timeout, a
// failure with no control is not evidence about the egress, and nothing it returns names the
// local proxy.

// reachAnswering is a server that answers anything immediately. As the TARGET it is a
// destination that is up; as the PROXY it is an egress that carried the request.
func reachAnswering(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// reachHanging is a server that accepts the connection and never answers, which is the black
// hole a timeout comes from. The handler is released at cleanup so Close does not sit on it.
func reachHanging(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv
}

// shortReachTimeout keeps the timeout case fast without making the refusal cases flaky.
func shortReachTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	saved := reachTimeout
	reachTimeout = d
	t.Cleanup(func() { reachTimeout = saved })
}

// deadLoopback is a port nothing listens on: an instant refusal on every platform we build for.
const deadLoopback = "http://127.0.0.1:1"

func TestReachOutside(t *testing.T) {
	cases := []struct {
		name string
		// setup returns the destination URL and the local proxy endpoint for this case.
		setup func(t *testing.T) (target, proxy string)
		want  func(t *testing.T, r OutsideReach)
	}{
		{
			name: "the egress carries it: both the proxied request and its control answered",
			setup: func(t *testing.T) (string, string) {
				return reachAnswering(t).URL, reachAnswering(t).URL
			},
			want: func(t *testing.T, r OutsideReach) {
				if !r.Tried || r.Proxied != nil || r.Direct != nil {
					t.Fatalf("both legs answered, so both must be nil: %+v", r)
				}
				if r.ProxiedTimedOut {
					t.Fatal("nothing timed out")
				}
			},
		},
		{
			name: "refused through the egress while the control answered: the evidence a block is made of",
			setup: func(t *testing.T) (string, string) {
				return reachAnswering(t).URL, deadLoopback
			},
			want: func(t *testing.T, r OutsideReach) {
				if !r.Tried || r.Proxied == nil {
					t.Fatalf("the proxied leg must have failed: %+v", r)
				}
				if r.Direct != nil {
					t.Fatalf("the control must have answered, or the pair proves nothing: %v", r.Direct)
				}
				if r.ProxiedTimedOut {
					t.Fatal("a refusal is not a timeout, and reporting it as one would lose the finding")
				}
			},
		},
		{
			name: "timed out through the egress: a black hole is not a refusal",
			setup: func(t *testing.T) (string, string) {
				// Generous enough that the CONTROL leg (a loopback round trip) can never be the
				// thing that runs out of time, including under the race detector, where a
				// tighter budget made this case flake.
				shortReachTimeout(t, time.Second)
				return reachAnswering(t).URL, reachHanging(t).URL
			},
			want: func(t *testing.T, r OutsideReach) {
				if !r.Tried || r.Proxied == nil {
					t.Fatalf("the proxied leg must have failed: %+v", r)
				}
				if !r.ProxiedTimedOut {
					t.Fatal("a request that ran out of time must be reported as a timeout, not as a refusal")
				}
				if r.Direct != nil {
					t.Fatalf("the control must have answered: %v", r.Direct)
				}
			},
		},
		{
			name: "both legs failed: that is the destination or this machine, and it says nothing about the egress",
			setup: func(t *testing.T) (string, string) {
				return deadLoopback, deadLoopback
			},
			want: func(t *testing.T, r OutsideReach) {
				if !r.Tried {
					t.Fatal("two real requests were made, so this WAS tried")
				}
				if r.Proxied == nil || r.Direct == nil {
					t.Fatalf("both legs failed, so neither may be nil: %+v", r)
				}
			},
		},
		{
			name: "no local proxy: nothing was measured, and nothing is claimed",
			setup: func(t *testing.T) (string, string) {
				return reachAnswering(t).URL, ""
			},
			want: func(t *testing.T, r OutsideReach) {
				if r.Tried {
					t.Fatalf("with no proxy to measure through, Tried must stay false: %+v", r)
				}
				if r.Proxied != nil || r.Direct != nil {
					t.Fatal("an unmeasured leg must not carry an error, which a caller could read as a failure")
				}
			},
		},
		{
			name: "malformed local proxy: still nothing measured, never a panic",
			setup: func(t *testing.T) (string, string) {
				return reachAnswering(t).URL, "://not-a-url"
			},
			want: func(t *testing.T, r OutsideReach) {
				if r.Tried {
					t.Fatalf("a malformed endpoint measures nothing: %+v", r)
				}
			},
		},
		{
			name: "unusable destination: nothing measured, and the host is empty rather than invented",
			setup: func(t *testing.T) (string, string) {
				return "not-a-url", reachAnswering(t).URL
			},
			want: func(t *testing.T, r OutsideReach) {
				if r.Tried || r.Host != "" {
					t.Fatalf("an unusable destination measures nothing: %+v", r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, proxy := tc.setup(t)
			t.Setenv(ReachURLEnv, target)
			r := ReachOutside(context.Background(), proxy)
			tc.want(t, r)
		})
	}
}

// TestReachOutsideNamesTheDestinationAndNeverTheProxy. The panel prints Host in a sentence a
// person reads, and it prints nothing else from here. A transport failure through a SOCKS proxy
// spells out the proxy's own host and port, and this document must never carry that.
func TestReachOutsideNamesTheDestinationAndNeverTheProxy(t *testing.T) {
	target := reachAnswering(t)
	proxy := reachAnswering(t)
	t.Setenv(ReachURLEnv, "http://reach-target.invalid/")

	r := ReachOutside(context.Background(), proxy.URL)
	if r.Host != "reach-target.invalid" {
		t.Fatalf("Host must be the destination that was tried, got %q", r.Host)
	}

	// Now the failing shape, which is the one that carries an error string at all: a local proxy
	// that is not answering, with the destination itself up.
	t.Setenv(ReachURLEnv, target.URL)
	r = ReachOutside(context.Background(), deadLoopback)
	if r.Proxied == nil {
		t.Fatal("expected the proxied leg to fail against a local proxy that is not answering")
	}
	if strings.Contains(r.Proxied.Error(), "127.0.0.1") {
		t.Fatalf("the proxied error leaks the local proxy endpoint: %q", r.Proxied.Error())
	}
	if !strings.Contains(r.Proxied.Error(), "Whisper egress") {
		t.Fatalf("the proxied error must say which leg failed, got %q", r.Proxied.Error())
	}
	if r.Direct != nil {
		t.Fatalf("the control must have answered: %v", r.Direct)
	}
}

// TestReachOutsideIsKeyless: the destination is a stranger, and a stranger is sent nothing. A
// probe that carried the tenant's key to example.com would be a leak we shipped on a timer.
func TestReachOutsideIsKeyless(t *testing.T) {
	var sawKey, sawAuth string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey, sawAuth = r.Header.Get("X-API-Key"), r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv(ReachURLEnv, "http://reach-target.invalid/")

	if r := ReachOutside(context.Background(), proxy.URL); r.Proxied != nil {
		t.Fatalf("the proxied leg should have been answered by the fake proxy: %v", r.Proxied)
	}
	if sawKey != "" || sawAuth != "" {
		t.Fatalf("the reachability probe must be keyless, got key=%q auth=%q", sawKey, sawAuth)
	}
}

// TestReachURLDefaultsAndOverride. The default has to be a host that is NOT ours - the whole
// defect was a probe inside the failure domain it was certifying - and it has to be overridable
// the way --echo-url is.
func TestReachURLDefaultsAndOverride(t *testing.T) {
	if strings.Contains(DefaultReachURL, "whisper") {
		t.Fatalf("the reachability destination must not be a Whisper host, got %q", DefaultReachURL)
	}
	if got := ReachURL(); got != DefaultReachURL {
		t.Fatalf("with no override the default applies, got %q", got)
	}
	if got := ReachURLHost(); got != "example.com" {
		t.Fatalf("ReachURLHost must name the default destination, got %q", got)
	}
	t.Setenv(ReachURLEnv, "  http://reach-target.invalid/  ")
	if got := ReachURL(); got != "http://reach-target.invalid/" {
		t.Fatalf("the override must apply, trimmed, got %q", got)
	}
	if got := ReachURLHost(); got != "reach-target.invalid" {
		t.Fatalf("ReachURLHost must follow the override, got %q", got)
	}
}

// TestReachOutside407IsNotReached. A 407 is the LOCAL proxy answering for itself: the egress
// rejected this session's token. The destination was never asked, so it must not count as
// reached - that would be a green tick minted by an auth failure.
func TestReachOutside407IsNotReached(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv(ReachURLEnv, "http://reach-target.invalid/")

	r := ReachOutside(context.Background(), proxy.URL)
	if r.Proxied == nil {
		t.Fatal("a 407 from the local proxy must not count as having reached the destination")
	}
	if !strings.Contains(r.Proxied.Error(), "whisper connect") {
		t.Fatalf("the 407 message must carry its remedy, got %q", r.Proxied.Error())
	}
}
