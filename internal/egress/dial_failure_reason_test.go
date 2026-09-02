// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// The front-end used to throw away WHY an upstream dial failed, because neither wire protocol
// it speaks can carry a reason: SOCKS5 has a one-byte REP code and CONNECT answers a bodiless
// 502. The dialer underneath had already worked out which layer failed and written a sentence
// for a person; it died at the REP byte, and the CLI was left guessing. These tests hold the
// reason to the surface.

package egress

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// dialreason_dialer fails every dial with a fixed, already-user-facing sentence - the exact
// shape netDialer.diagnosis produces for a WireGuard tunnel that has never handshaked.
type dialreason_dialer struct{ why string }

func (d dialreason_dialer) Dial(context.Context, string) (net.Conn, error) {
	return nil, errors.New(d.why)
}

// dialreason_ok answers every dial with a live loopback pipe, so a test can prove the record
// STAYS empty on the success path (an absence that is actually an absence).
type dialreason_ok struct{}

func (dialreason_ok) Dial(context.Context, string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { _, _ = c.Write([]byte("hi")); _ = c.Close() }()
	return s, nil
}

const dialreason_why = "could not reach the target over the Whisper tunnel. The tunnel has no recent " +
	"WireGuard handshake, so this is the tunnel itself and not the destination"

// TestSocks5DialFailureReasonSurvivesTheREPByte: a SOCKS5 client gets the same opaque
// REP=0x05 it always did (the wire contract does not change), but the reason is now readable
// by the process that owns the proxy.
func TestSocks5DialFailureReasonSurvivesTheREPByte(t *testing.T) {
	p, err := StartWithDialer(dialreason_dialer{why: dialreason_why}, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	defer p.Stop()

	// The control: before anything fails there is nothing to report, so a later non-empty
	// answer cannot be something this proxy was born with.
	if why, at := p.LastDialFailure(); why != "" || !at.IsZero() {
		t.Fatalf("a fresh proxy already reports a dial failure: %q at %v", why, at)
	}

	started := time.Now()
	if _, derr := socks5Dial(p.Addr(), "example.test:443"); derr == nil {
		t.Fatal("the dial through a failing dialer should not succeed")
	}

	why, at := p.LastDialFailure()
	if !strings.Contains(why, "no recent WireGuard handshake") {
		t.Fatalf("the reason did not survive the REP byte: %q", why)
	}
	if at.Before(started) {
		t.Fatalf("the reason is stamped %v, before the dial started at %v", at, started)
	}
}

// TestHTTPConnectDialFailureReasonSurvivesTheBodilessBadGateway: the same for the CONNECT
// front-end, whose 502 carries no body a client could read.
func TestHTTPConnectDialFailureReasonSurvivesTheBodilessBadGateway(t *testing.T) {
	p, err := StartWithDialer(dialreason_dialer{why: dialreason_why}, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	defer p.Stop()

	c, derr := net.DialTimeout("tcp", p.Addr(), 5*time.Second)
	if derr != nil {
		t.Fatalf("dial local proxy: %v", derr)
	}
	defer c.Close()
	if _, werr := c.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}
	buf := make([]byte, 64)
	n, _ := c.Read(buf)
	if !strings.Contains(string(buf[:n]), "502") {
		t.Fatalf("expected a 502 on the wire, got %q", string(buf[:n]))
	}
	if why, _ := p.LastDialFailure(); !strings.Contains(why, "no recent WireGuard handshake") {
		t.Fatalf("the reason did not survive the bodiless 502: %q", why)
	}
}

// TestDialFailureRecordStaysEmptyWhenNothingFails is the control that gives the two tests
// above their meaning: a proxy whose dials all succeed reports NO reason, so a non-empty
// answer is evidence of a real failure and never of the record simply always being full.
func TestDialFailureRecordStaysEmptyWhenNothingFails(t *testing.T) {
	p, err := StartWithDialer(dialreason_ok{}, nil)
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	defer p.Stop()

	conn, derr := socks5Dial(p.Addr(), "example.test:443")
	if derr != nil {
		t.Fatalf("the dial through a working dialer failed: %v", derr)
	}
	conn.Close()

	if why, at := p.LastDialFailure(); why != "" || !at.IsZero() {
		t.Fatalf("a successful dial recorded a failure: %q at %v", why, at)
	}
}
