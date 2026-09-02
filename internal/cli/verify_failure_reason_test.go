// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// When the egress verify step failed, the CLI printed one sentence for every possible cause -
// "the Whisper egress did not accept this session while verifying your address ... the session
// token may have been rejected; run `whisper connect` again". It printed that on a Mac whose
// network was dropping UDP to the egress node, so the WireGuard tunnel never handshaked. The
// remedy it named could not have fixed that, and a remedy that cannot work is worse than none:
// it sends the person away from what is broken.
//
// These tests hold the verify path to the truth the dialer already knew.

package cli

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/egress"
)

// verifyreason_deadTunnelDialer fails every dial the way netDialer.diagnosis does for a tunnel
// that has never completed a handshake: the one layer that is broken, named, with the check a
// person can actually make.
type verifyreason_deadTunnelDialer struct{}

const verifyreason_tunnelWhy = "could not reach the target over the Whisper tunnel. The tunnel has no " +
	"recent WireGuard handshake, so this is the tunnel itself and not the destination - " +
	"`whisper connect` again, or check that UDP to the Whisper endpoint is not blocked on your network"

func (verifyreason_deadTunnelDialer) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New(verifyreason_tunnelWhy)
}

// TestVerifyFailureNamesTheDeadTunnelNotTheSessionToken is the regression itself, end to end
// through the real front-end: a live local proxy on loopback (so the old "is the local proxy
// alive?" discriminator answers YES, exactly as it does for every WireGuard session, because
// the SOCKS listener is local and comes up whether or not the tunnel ever handshakes) whose
// dials all fail with the dead-tunnel sentence. The verify verdict must be the tunnel, not the
// token.
func TestVerifyFailureNamesTheDeadTunnelNotTheSessionToken(t *testing.T) {
	p, err := egress.StartWithDialer(verifyreason_deadTunnelDialer{}, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	defer p.Stop()

	sess := &egressSession{
		endpoint: p.Endpoint(),
		addr:     "2a04:2a01:fa55:9adb:7b3c:624c:c037:b3cd",
		tier:     "wireguard",
		local:    p,
	}
	c := client.New(client.Config{EchoURL: "https://echo.invalid/egress-ip", Timeout: 5 * time.Second})

	verr := verifyEgressLive(context.Background(), c, sess)
	if verr == nil {
		t.Fatal("verify succeeded through a dialer that fails every dial")
	}
	got := verr.Error()
	if !strings.Contains(got, "no recent WireGuard handshake") {
		t.Fatalf("the verify failure did not name the dead tunnel: %q", got)
	}
	if strings.Contains(got, "session token") || strings.Contains(got, "did not accept this session") {
		t.Fatalf("the verify failure still blames the session token: %q", got)
	}
}

// verifyreason_reporter is a localEndpoint that also remembers a dial failure, with both halves
// under the test's control so the staleness rule can be exercised without racing a clock.
type verifyreason_reporter struct {
	why string
	at  time.Time
}

func (verifyreason_reporter) Endpoint() string { return "socks5h://127.0.0.1:1" }
func (verifyreason_reporter) Addr() string     { return "127.0.0.1:1" }
func (verifyreason_reporter) Stop()            {}
func (r verifyreason_reporter) LastDialFailure() (string, time.Time) {
	return r.why, r.at
}

// TestVerifyFailureIgnoresAReasonThatPredatesThisCheck: the record holds the LAST failure,
// which may belong to some earlier request that has nothing to do with this verification.
// Reporting it would only be a different wrong answer, so a reason stamped before the check
// started is left alone and the original error stands.
func TestVerifyFailureIgnoresAReasonThatPredatesThisCheck(t *testing.T) {
	started := time.Now()
	original := errors.New("the original verify error")

	stale := &egressSession{tier: "wireguard", local: verifyreason_reporter{
		why: verifyreason_tunnelWhy,
		at:  started.Add(-time.Minute),
	}}
	if got := explainVerifyFailure(stale, started, original); got != original {
		t.Fatalf("a reason from before the check was reported as its cause: %v", got)
	}

	// The control: the SAME reason, stamped during the check, IS reported - so the test above
	// is proving the timestamp rule and not merely that nothing is ever reported.
	fresh := &egressSession{tier: "wireguard", local: verifyreason_reporter{
		why: verifyreason_tunnelWhy,
		at:  started.Add(time.Millisecond),
	}}
	got := explainVerifyFailure(fresh, started, original)
	if got == original || !strings.Contains(got.Error(), "no recent WireGuard handshake") {
		t.Fatalf("a fresh reason was not reported: %v", got)
	}
}

// TestVerifyFailureKeepsTheOriginalErrorWhenTheLocalEndpointRemembersNothing: a session whose
// local endpoint cannot report a reason (a stub, or a future tier) must be no worse off than
// before - the original error is returned untouched, never an empty or invented one.
func TestVerifyFailureKeepsTheOriginalErrorWhenTheLocalEndpointRemembersNothing(t *testing.T) {
	original := errors.New("the original verify error")
	if got := explainVerifyFailure(&egressSession{tier: "socks5"}, time.Now(), original); got != original {
		t.Fatalf("a session with no local endpoint changed the error: %v", got)
	}
	if got := explainVerifyFailure(nil, time.Now(), original); got != original {
		t.Fatalf("a nil session changed the error: %v", got)
	}
}
