// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// Every op:connect that leaves this host is checked against the enforced runs held here.

func stubHolders(t *testing.T, held map[netip.Addr]int) {
	t.Helper()
	one, all := EnforcedHolder, EnforcedHolders
	EnforcedHolder = func(a netip.Addr) int { return held[a] }
	EnforcedHolders = func() []netip.Addr {
		var out []netip.Addr
		for a := range held {
			out = append(out, a)
		}
		return out
	}
	t.Cleanup(func() { EnforcedHolder, EnforcedHolders = one, all })
}

func TestRefuseIfEnforced(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:1::1")
	stubHolders(t, map[netip.Addr]int{a: 4242})
	var held *enforce.HeldError
	for _, args := range []map[string]any{
		{"agent": "2a04:2a01:1::1"},
		{"address": "2a04:2a01:1::1"},
		{"agent": " 2a04:2a01:1::1%wg0 "},
		{"agent": "[2a04:2a01:1::1]"},
		{"agent": 123, "address": "2a04:2a01:1::1"}, // a non-string agent falls through to address, as on the box
	} {
		err := RefuseIfEnforced(args)
		if !errors.As(err, &held) || held.PID != 4242 || held.Unnamed || held.Addr != a {
			t.Fatalf("%v: want the held agent refused, got %v", args, err)
		}
	}
	for _, args := range []map[string]any{
		{"agent": "2a04:2a01:1::2"},
		{"agent": "agent-a0000000000000001"},
		{"agent": "scout"},
	} {
		if err := RefuseIfEnforced(args); err != nil {
			t.Fatalf("%v: nothing held, want nil, got %v", args, err)
		}
	}
	// The box reads a blank string agent as "pick one", even with an address beside it, and ignores a
	// non-string agent with no address: all three are nameless connects.
	for _, args := range []map[string]any{
		{"tier": "socks5"},
		{"agent": ""},
		{"agent": "", "address": "2a04:2a01:1::1"},
		{"agent": 123},
	} {
		err := RefuseIfEnforced(args)
		if !errors.As(err, &held) || !held.Unnamed || held.Addr != a {
			t.Fatalf("%v is nameless to the box and a run is live: want refused, got %v", args, err)
		}
	}
	stubHolders(t, nil)
	if err := RefuseIfEnforced(map[string]any{"tier": "socks5"}); err != nil {
		t.Fatalf("no run live: a nameless connect passes, got %v", err)
	}
}

func TestAgentsChecksOnlyConnect(t *testing.T) {
	stubHolders(t, map[netip.Addr]int{netip.MustParseAddr("2a04:2a01:1::1"): 7})
	c := &Client{}
	_, err := c.Agents(context.Background(), "connect", map[string]any{"agent": "2a04:2a01:1::1"})
	var held *enforce.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("op:connect for a held agent is refused before any request, got %v", err)
	}
	if held.Error() == "" {
		t.Fatal("the refusal says why")
	}
}

func TestRawCypherConnectIsRefusedWhileARunIsLive(t *testing.T) {
	stubHolders(t, map[netip.Addr]int{netip.MustParseAddr("2a04:2a01:1::1"): 7})
	c := &Client{}
	_, err := c.GraphQuery(context.Background(), "CALL whisper.agents({op:'connect', args:{tier:'socks5'}})", nil)
	var held *enforce.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("a raw op:connect while a run is live must be refused, got %v", err)
	}
	if _, err := c.GraphQuery(context.Background(), "CALL whisper.agents($m)",
		map[string]any{"m": map[string]any{"op": "connect", "args": map[string]any{}}}); !errors.As(err, &held) {
		t.Fatalf("the parameterised form carries the op in its params and must be refused too, got %v", err)
	}
	for _, q := range []string{
		"MATCH (n) RETURN n LIMIT 1",
		"CALL whisper.agents({op:'disconnect', args:{agent:'2a04:2a01:1::1'}})",
		"CALL whisper.agents({op:'list', args:{kind:'connections'}})",
	} {
		if _, err := c.GraphQuery(context.Background(), q, nil); errors.As(err, &held) {
			t.Fatalf("%q is not an op:connect and is not this check's business", q)
		}
	}
}
