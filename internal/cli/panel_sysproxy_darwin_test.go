// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package cli

import (
	"errors"
	"strings"
	"testing"
)

// panel_sysproxy_darwin_test.go covers the file that actually touches somebody's Mac. Everything
// above it is driven through seams and therefore tested on any OS; this layer is the one that
// shells out to networksetup, and until now it had no test at all - which is how the ordering bug
// below survived into a build that was shipped to fix an outage.
//
// The tests run only on darwin, which is honest: they are about a macOS tool's behaviour, and
// pretending to prove that on Linux would be pretending.

// sysProxyCalls captures every shell-out, in order, so a sequence can be asserted rather than a
// set. Order is the whole property here.
type sysProxyCalls struct {
	got []string
	err map[string]error
}

// install answers the two read-only calls that resolve the primary service the way a real Mac
// does, so a test about WRITE ordering is not derailed by service lookup, and records every call
// in order.
func (c *sysProxyCalls) install(t *testing.T) *sysProxyCalls {
	t.Helper()
	saved := runSysProxyCmd
	runSysProxyCmd = func(name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		c.got = append(c.got, line)
		if c.err != nil {
			for k, e := range c.err {
				if strings.Contains(line, k) {
					return "", e
				}
			}
		}
		switch {
		case name == routePath:
			return "   route to: default\n  interface: en0\n", nil
		case strings.Contains(line, "-listnetworkserviceorder"):
			return "An asterisk (*) denotes that a network service is disabled.\n" +
				"(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n", nil
		}
		return "", nil
	}
	t.Cleanup(func() { runSysProxyCmd = saved })
	return c
}

// TestRestoreSystemProxy_SwitchesOffBEFOREItRewritesTheConfiguration.
//
// Measured on a real Mac: `networksetup -setsocksfirewallproxy <svc> "" 0` returns 0 and leaves
// the service reading `Enabled: Yes  Server:  Port: 0`. Writing the host and port SWITCHES THE
// PROXY ON. So a restore-to-off that writes the configuration first spends a window with the
// machine behind an enabled proxy pointing at no server, and a process that dies in that window
// leaves a Mac with no internet - inside the very code path that exists to rescue it.
func TestRestoreSystemProxy_SwitchesOffBEFOREItRewritesTheConfiguration(t *testing.T) {
	calls := (&sysProxyCalls{}).install(t)
	prev := sysProxyPrevious{Known: true, Enabled: false, Host: "", Port: 0, Service: "Wi-Fi"}

	if err := restoreSystemProxy(prev); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(calls.got) != 3 {
		t.Fatalf("expected off, write, off; got %d calls: %v", len(calls.got), calls.got)
	}
	if !strings.HasPrefix(calls.got[0], "-setsocksfirewallproxystate Wi-Fi off") {
		t.Fatalf("the FIRST thing a restore-to-off must do is switch the proxy off, so the machine "+
			"works from that instant whatever happens next; it did %q", calls.got[0])
	}
	if !strings.HasPrefix(calls.got[1], "-setsocksfirewallproxy Wi-Fi") {
		t.Fatalf("the configuration was never put back: %v", calls.got)
	}
	if !strings.HasPrefix(calls.got[2], "-setsocksfirewallproxystate Wi-Fi off") {
		t.Fatalf("writing the configuration switches the proxy ON, so the restore must switch it off "+
			"again; it did %q", calls.got[2])
	}
}

// TestRestoreSystemProxy_ClearsOurOwnResidueRatherThanLeavingIt.
//
// A Mac that never had a proxy has an empty server and port 0. The earlier restore skipped the
// write whenever the previous host was empty, and so left `127.0.0.1:<our session port>` sitting
// in the field, switched off. This Mac carries one of those on a second service from a session
// long gone. Flip that switch in System Settings months later and the machine comes up pointed at
// a dead port: a foot-gun we planted and then walked away from.
func TestRestoreSystemProxy_ClearsOurOwnResidueRatherThanLeavingIt(t *testing.T) {
	calls := (&sysProxyCalls{}).install(t)
	prev := sysProxyPrevious{Known: true, Enabled: false, Host: "", Port: 0, Service: "Wi-Fi"}

	if err := restoreSystemProxy(prev); err != nil {
		t.Fatalf("restore: %v", err)
	}
	var wrote string
	for _, c := range calls.got {
		if strings.HasPrefix(c, "-setsocksfirewallproxy Wi-Fi") {
			wrote = c
		}
	}
	if wrote != "-setsocksfirewallproxy Wi-Fi  0" {
		t.Fatalf("a previous state of 'nothing configured' must be written back as nothing - an empty "+
			"server and port 0 - so our own host and port do not stay in the field: got %q", wrote)
	}
}

// TestRestoreSystemProxy_PutsACorporateProxyBackOn is the case that makes "back" mean back. A Mac
// behind a company SOCKS proxy that switched Whisper on and then off must end up behind its
// company proxy again, not with no proxy and no idea why.
func TestRestoreSystemProxy_PutsACorporateProxyBackOn(t *testing.T) {
	calls := (&sysProxyCalls{}).install(t)
	prev := sysProxyPrevious{Known: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi"}

	if err := restoreSystemProxy(prev); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(calls.got) != 2 {
		t.Fatalf("a restore-to-on needs no off/on dance: %v", calls.got)
	}
	if calls.got[0] != "-setsocksfirewallproxy Wi-Fi proxy.corp.example 1080" {
		t.Fatalf("the corporate proxy was not written back: %q", calls.got[0])
	}
	if calls.got[1] != "-setsocksfirewallproxystate Wi-Fi on" {
		t.Fatalf("the corporate proxy was written but left switched off: %q", calls.got[1])
	}
}

// TestRestoreSystemProxy_AnUnknownPreviousStateOnlyEverSwitchesOff. Off is a working machine.
// Inventing a host and port to "restore" would be worse than the outage being undone.
func TestRestoreSystemProxy_AnUnknownPreviousStateOnlyEverSwitchesOff(t *testing.T) {
	calls := (&sysProxyCalls{}).install(t)

	if err := restoreSystemProxy(sysProxyPrevious{Service: "Wi-Fi"}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(calls.got) != 1 || calls.got[0] != "-setsocksfirewallproxystate Wi-Fi off" {
		t.Fatalf("an unknown previous state must switch off and write nothing: %v", calls.got)
	}
}

// TestWriteSystemProxy_SetsTheHostAndThenTheState pins the enable path's own order, which relies
// on the same macOS side effect from the other direction.
func TestWriteSystemProxy_SetsTheHostAndThenTheState(t *testing.T) {
	calls := (&sysProxyCalls{}).install(t)

	if err := writeSystemProxy(true, 55312); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The first calls resolve the service, so look at the two writes that matter.
	var seen []string
	for _, c := range calls.got {
		if strings.HasPrefix(c, "-setsocksfirewallproxy") {
			seen = append(seen, c)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("enable must make exactly two writes, got %d: %v", len(seen), calls.got)
	}
	if seen[0] != "-setsocksfirewallproxy Wi-Fi 127.0.0.1 55312" {
		t.Fatalf("enable did not point the primary service at the live session: %q", seen[0])
	}
	if seen[1] != "-setsocksfirewallproxystate Wi-Fi on" {
		t.Fatalf("enable wrote the host but never switched the proxy on: %q", seen[1])
	}
}

// TestSysProxyWriteError_EndsAPrivilegeRefusalWithTheWayThroughIt. "exit status 1" is not
// something a person can act on.
func TestSysProxyWriteError_EndsAPrivilegeRefusalWithTheWayThroughIt(t *testing.T) {
	err := sysProxyWriteError(errors.New("networksetup: you must have administrator privileges"), "on")
	if !strings.Contains(err.Error(), "sudo whisper panel system-proxy on") {
		t.Fatalf("the refusal does not name the command that gets through it: %v", err)
	}
}

// TestParseSocksFirewallProxy reads what networksetup actually prints, last line included, since
// "Authenticated Proxy Enabled: 0" is what a loose Enabled match trips over.
func TestParseSocksFirewallProxy(t *testing.T) {
	enabled, host, port := parseSocksFirewallProxy(
		"Enabled: Yes\nServer: 127.0.0.1\nPort: 54209\nAuthenticated Proxy Enabled: 0\n")
	if !enabled || host != "127.0.0.1" || port != 54209 {
		t.Fatalf("got enabled=%v host=%q port=%d", enabled, host, port)
	}
	enabled, host, port = parseSocksFirewallProxy(
		"Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n")
	if enabled || host != "" || port != 0 {
		t.Fatalf("an unconfigured service read as enabled=%v host=%q port=%d", enabled, host, port)
	}
}
