// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// When the panel could not fetch the echo through the local proxy it reported an unknown
// carrying whatever sentence the client had guessed at, which for a WireGuard session was
// always about the session token. The panel already holds the one fact that settles it - the
// tunnel-holding process publishes a path record - and now it uses it.

package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestPanelEgressStalledByTunnelNamesTheTunnel(t *testing.T) {
	apps, ok := panelEgressStalledByTunnel(panelTunnel{Known: true, Healthy: false},
		errors.New("the Whisper egress did not accept this session while verifying your address"))
	if !ok {
		t.Fatal("a failed echo beside a stale tunnel record was not recognised")
	}
	if apps.State != panelNotInForce {
		t.Fatalf("state = %q, want %q", apps.State, panelNotInForce)
	}
	if !strings.Contains(apps.Detail, "tunnel") || !strings.Contains(apps.Detail, "UDP") {
		t.Fatalf("the detail does not name the tunnel or what to check: %q", apps.Detail)
	}
	if strings.Contains(apps.Detail, "session token") {
		t.Fatalf("the detail still blames the session token: %q", apps.Detail)
	}
}

// TestPanelEgressStalledByTunnelStaysSilentWithoutBothFacts is the control: each fact alone
// must NOT produce the verdict, so a positive above is evidence of the two lining up and not
// of a branch that fires on anything.
func TestPanelEgressStalledByTunnelStaysSilentWithoutBothFacts(t *testing.T) {
	boom := errors.New("the echo failed")
	cases := []struct {
		name string
		tun  panelTunnel
		err  error
	}{
		{"echo succeeded, record stale (a wedged publisher, not a dead tunnel)",
			panelTunnel{Known: true, Healthy: false}, nil},
		{"echo failed, record fresh (the far end, not the tunnel)",
			panelTunnel{Known: true, Healthy: true}, boom},
		{"echo failed, nothing published (a socks5 session has no tunnel to blame)",
			panelTunnel{}, boom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := panelEgressStalledByTunnel(tc.tun, tc.err); ok {
				t.Fatal("the tunnel verdict fired without both facts")
			}
		})
	}
}
