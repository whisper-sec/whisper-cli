// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// whale_v4_loopback_test.go is the named test: what `whale ip -4` says, and the
// property that makes it worth having - it never prints an empty line, never prints an
// address that is not this node's identity, and always names the local IPv4 endpoint that
// exists when one exists.

func TestWhaleV4NeverPrintsAnAddress(t *testing.T) {
	for _, sessions := range [][]statusSession{
		nil,
		{{Address: "2a04:2a01:1::a", Tier: "wireguard", Port: 1080, Endpoint: "socks5h://127.0.0.1:1080"}},
		{{Address: "2a04:2a01:1::a", Tier: "socks5", Port: 1081, Endpoint: "socks5h://127.0.0.1:1081"}},
	} {
		v := whaleV4Status(sessions, nil)
		if v.Address != "" {
			t.Fatalf("address = %q; there is no IPv4 identity and printing one would be a lie a script acts on", v.Address)
		}
		if v.Family != "ipv4" {
			t.Fatalf("family = %q, want ipv4", v.Family)
		}
		if strings.TrimSpace(v.Note) == "" {
			t.Fatal("empty note: an empty line is the exact failure this verb exists to avoid")
		}
	}
}

func TestWhaleV4DisconnectedSaysWhatToDo(t *testing.T) {
	v := whaleV4Status(nil, nil)
	if v.Connected {
		t.Fatal("connected with no sessions")
	}
	if v.Reachability != "none" {
		t.Fatalf("reachability = %q, want none", v.Reachability)
	}
	if v.Endpoint != "" {
		t.Fatalf("endpoint = %q with nothing connected", v.Endpoint)
	}
	if !strings.Contains(v.Note, "whisper connect") {
		t.Fatalf("note = %q, want the remedy named", v.Note)
	}
	// The disconnected sentence used to end "IPv4 destinations do work through the tunnel",
	// which is a claim about a translator this binary has never seen. Nothing here may
	// promise a working v4 path; it may only say how to measure one.
	for _, forbidden := range []string{"do work through the tunnel", "IPv4 destinations work"} {
		if strings.Contains(v.Note, forbidden) {
			t.Fatalf("note %q promises a working IPv4 path that nothing measured", v.Note)
		}
	}
	if !strings.Contains(v.Note, "--probe") {
		t.Fatalf("note = %q, want it to say how to measure the IPv4 path", v.Note)
	}
}

// The WireGuard tier is where the translation lives, so the answer must name NAT64 and
// the prefix actually in force - not a prefix from a document.
func TestWhaleV4WireGuardTierNamesTheLoopbackListenerAndNAT64(t *testing.T) {
	v := whaleV4Status([]statusSession{{
		Address: "2a04:2a01:1::a", Tier: "wireguard", Port: 1080, Endpoint: "socks5h://127.0.0.1:1080",
	}}, nil)
	if !v.Connected || v.Reachability != "nat64" {
		t.Fatalf("connected=%v reachability=%q, want a connected nat64 answer", v.Connected, v.Reachability)
	}
	if v.Endpoint != "127.0.0.1:1080" {
		t.Fatalf("endpoint = %q, want the IPv4 loopback listener", v.Endpoint)
	}
	if v.NAT64Prefix != "64:ff9b::/96" {
		t.Fatalf("nat64_prefix = %q, want the prefix in force", v.NAT64Prefix)
	}
	if v.Measured.State != v4NotMeasured {
		t.Fatalf("measured = %q with no probe run; an unmeasured answer must say so", v.Measured.State)
	}
	for _, want := range []string{"127.0.0.1:1080", "64:ff9b::/96", "curl -4", "2a04:2a01:1::a", "--probe"} {
		if !strings.Contains(v.Note, want) {
			t.Fatalf("note %q is missing %q", v.Note, want)
		}
	}
}

// The SOCKS tier reaches v4 too, but the box does it, not us. Say which, because the two
// have different failure modes and a user debugging one must not be sent to the other.
func TestWhaleV4SocksTierSaysTheBoxDialsIt(t *testing.T) {
	v := whaleV4Status([]statusSession{{
		Address: "2a04:2a01:1::b", Tier: "socks5", Port: 1081, Endpoint: "socks5h://127.0.0.1:1081",
	}}, nil)
	if v.Reachability != "box" {
		t.Fatalf("reachability = %q, want box", v.Reachability)
	}
	if v.NAT64Prefix != "" {
		t.Fatalf("nat64_prefix = %q: the local translation is not what carries v4 on this tier", v.NAT64Prefix)
	}
	if !strings.Contains(v.Note, "the box resolves and dials") {
		t.Fatalf("note = %q, want it to name where the v4 dial happens", v.Note)
	}
}

// A session with no tier recorded is the oldest shape in the registry. It must degrade to
// the box answer rather than to an empty tier and a blank note.
func TestWhaleV4UntieredSessionDegradesToTheBoxAnswer(t *testing.T) {
	v := whaleV4Status([]statusSession{{Address: "2a04:2a01:1::c", Port: 1082}}, nil)
	if v.Tier != "socks5" || v.Reachability != "box" || v.Endpoint != "127.0.0.1:1082" {
		t.Fatalf("view = %+v, want the socks5/box degradation", v)
	}
}

// An address the registry did not carry must render as a dash, never as an empty gap in a
// sentence that then reads as if the node had no identity at all.
func TestWhaleV4MissingAddressRendersAsADash(t *testing.T) {
	v := whaleV4Status([]statusSession{{Tier: "wireguard", Port: 1080}}, nil)
	if !strings.Contains(v.Note, "IPv6 /128 -") {
		t.Fatalf("note = %q, want the unknown address rendered as a dash", v.Note)
	}
}
