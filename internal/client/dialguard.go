// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// dialguard.go stops a unit test reaching the real internet.
//
// This is not a hypothetical. A test that asserted "with no key the CLI returns a
// clean 401" instead found a real key on the machine, talked to the LIVE control
// plane and listed 358 production agents into its own log, and the only reason
// anybody noticed was that the suite took 1438 seconds. Every second of that was
// network. The isolation helper it trusted set HOME and nothing else, which
// isolates nothing on Windows.
//
// internal/testenv closes the hole that particular accident went through. This
// closes the CLASS: under `go test`, a dial to anything but loopback is refused
// before a packet or a DNS query leaves the machine. A test that regains a real
// credential some other way now FAILS, loudly, naming what it tried to reach,
// instead of quietly doing it.
//
// testing.Testing() is the whole mechanism: the linker sets it only when building
// a test binary, so a shipped `whisper` carries the check as a constant false and
// dials exactly as it always did.

// AllowNetworkEnv opts one test run back into real network access, for the
// deliberately-live suites (a release e2e, a live resolver probe). It is
// explicit, per-run, and named in the refusal so nobody has to go looking.
const AllowNetworkEnv = "WHISPER_TEST_ALLOW_NETWORK"

// ErrTestNetworkRefused is the refusal, exported so a live suite can recognise it
// rather than string-matching the message.
var ErrTestNetworkRefused = errors.New("refused: a test tried to reach the network")

// guardedDial wraps a dialer so every connection this package opens passes the
// test-mode check first. Production keeps the dialer it had.
func guardedDial(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := allowDial(addr); err != nil {
			return nil, err
		}
		return d.DialContext(ctx, network, addr)
	}
}

// allowDial decides whether this process may open addr. Outside a test binary the
// answer is always yes and the cost is one comparison against a linker constant.
func allowDial(addr string) error {
	if !testing.Testing() || os.Getenv(AllowNetworkEnv) != "" {
		return nil
	}
	if isLoopbackAddr(addr) {
		return nil
	}
	return fmt.Errorf("%w: %s. A unit test must not depend on, or change, anything outside this machine. "+
		"Point it at an httptest server on loopback, or set %s=1 for a suite that is deliberately live",
		ErrTestNetworkRefused, addr, AllowNetworkEnv)
}

// isLoopbackAddr reports whether addr names this machine. Liberal in what it
// accepts, because httptest and hand-written fixtures spell it several ways: a
// host:port or a bare host, an IPv4 or IPv6 literal, "localhost" or a name under
// it, and the empty host a unix-socket dial carries.
func isLoopbackAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
