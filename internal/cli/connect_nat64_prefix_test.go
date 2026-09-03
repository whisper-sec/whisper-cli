// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// connect_nat64_prefix_test.go is 's anti-unreachable proof on the client side.
//
// The defect this repo ships most often is a field nothing populates, or one populated and never
// read. Both halves are covered here by driving a REAL op:connect answer, in the column shape the
// box emits, all the way through parseConnectEnvelope and FromWgQuick to the Config the tunnel is
// started from. Delete the field read in parseConnectEnvelope, or the assignment in FromWgQuick,
// and this reddens; nothing constructs a connectEnvelope by hand.

// wireguardResult is the answer op:connect{tier:'wireguard'} actually returns, in the server's own
// column order with nat64_prefix appended last, so a reordering on either side is visible here.
func wireguardResult(nat64 string) *client.Result {
	srvPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return &client.Result{
		Columns: []string{
			"tier", "wireguard_config", "server_public_key", "endpoint", "client_public_key",
			"client_private_key", "address", "allowed_ips", "fqdn", "ptr", "dns", "note",
			"nat64_prefix",
		},
		Rows: [][]any{{
			"wireguard",
			"[Interface]\nAddress = 2a04:2a01:9::abcd/128\nDNS = 2a04:2a01:0:53::1\n",
			srvPub, "box.example:51826", "", "", "2a04:2a01:9::abcd", "2a04:2a01:9::abcd/128",
			"bot.agents.whisper.online.", "bot.agents.whisper.online.", "2a04:2a01:0:53::1",
			"Tier-1 routed WireGuard", nat64,
		}},
	}
}

func configFromResult(t *testing.T, res *client.Result) wgtun.Config {
	t.Helper()
	ce, err := parseConnectEnvelope(res)
	if err != nil {
		t.Fatalf("parseConnectEnvelope: %v", err)
	}
	kp, err := wgtun.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	cfg, err := wgtun.FromWgQuick(
		ce.wgServerPubKey, ce.wgEndpoint, ce.address, ce.wgDNS, ce.wgNat64Prefix, ce.wgQuick,
		kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	return cfg
}

// TestConnectNat64Prefix_ReachesTheTunnelConfig: the column the box now names arrives, intact, on
// the Config the tunnel is started from. This is the wiring the issue asks for.
func TestConnectNat64Prefix_ReachesTheTunnelConfig(t *testing.T) {
	cfg := configFromResult(t, wireguardResult("2a04:2a00:64::/96"))
	if !cfg.NAT64Prefix.IsValid() {
		t.Fatal("op:connect named a NAT64 prefix and the tunnel config did not receive it")
	}
	if got := cfg.NAT64Prefix.String(); got != "2a04:2a00:64::/96" {
		t.Fatalf("cfg.NAT64Prefix = %q, want the prefix the box named", got)
	}
	// The control: everything else on the same answer still lands, so a failure above is about
	// the new column and not about a broken fixture.
	if cfg.Address.String() != "2a04:2a01:9::abcd" || cfg.DNS.String() != "2a04:2a01:0:53::1" {
		t.Fatalf("the rest of the envelope did not survive: %+v", cfg)
	}
}

// TestConnectNat64Prefix_AbsentColumnIsPreV1107BehaviourNotAFault: a server that never heard of
// this column must still bring a tunnel up, and the node then guesses exactly as it did before.
func TestConnectNat64Prefix_AbsentColumnIsPreV1107BehaviourNotAFault(t *testing.T) {
	res := wireguardResult("")
	res.Columns = res.Columns[:len(res.Columns)-1]
	res.Rows[0] = res.Rows[0][:len(res.Rows[0])-1]

	cfg := configFromResult(t, res)
	if cfg.NAT64Prefix.IsValid() {
		t.Fatalf("an absent column must leave the prefix undeclared, got %s", cfg.NAT64Prefix)
	}
	if cfg.Address.String() != "2a04:2a01:9::abcd" {
		t.Fatal("an absent nat64_prefix must not disturb the rest of the config")
	}
}

// TestConnectNat64Prefix_AnUnusablePrefixIsIgnoredRatherThanFatal: Postel. A box that names
// something we cannot use must not stop this node from connecting; it falls back to guessing.
func TestConnectNat64Prefix_AnUnusablePrefixIsIgnoredRatherThanFatal(t *testing.T) {
	for _, bad := range []string{"64:ff9b::/64", "192.0.2.0/24", "not a prefix", "   "} {
		cfg := configFromResult(t, wireguardResult(bad))
		if cfg.NAT64Prefix.IsValid() {
			t.Fatalf("%q must not be accepted as a NAT64 prefix, got %s", bad, cfg.NAT64Prefix)
		}
		if cfg.Address.String() != "2a04:2a01:9::abcd" {
			t.Fatalf("%q must not break the rest of the config", bad)
		}
	}
}

// TestWhaleV4_NamesTheTunnelsPrefixAndItsSource: `whisper whale ip -4` reads what the TUNNEL
// settled on out of the session record, not what this process would guess. Before that it
// always printed the guess, and there was no way to tell the two apart from the output.
func TestWhaleV4_NamesTheTunnelsPrefixAndItsSource(t *testing.T) {
	v := whaleV4Status([]statusSession{{
		Address:     "2a04:2a01:9::abcd",
		Tier:        "wireguard",
		Port:        41080,
		NAT64Prefix: "2a04:2a00:64::/96",
		NAT64Source: "the control plane",
	}}, nil)

	if v.NAT64Prefix != "2a04:2a00:64::/96" {
		t.Fatalf("NAT64Prefix = %q, want the tunnel's own answer", v.NAT64Prefix)
	}
	if v.NAT64PrefixSource != "the control plane" {
		t.Fatalf("NAT64PrefixSource = %q, want where the value came from", v.NAT64PrefixSource)
	}
	if !strings.Contains(v.Note, "2a04:2a00:64::/96") || !strings.Contains(v.Note, "Its source: the control plane.") {
		t.Fatalf("the note must name the prefix AND where it came from: %s", v.Note)
	}
}

// TestWhaleV4_FallsBackToTheGuessWhenTheRecordPredatesTheField: an old session record, or a
// record written by a build without the field, must still produce a usable line rather than an
// empty prefix. The absent SOURCE is left absent: "Its source: " with nothing after it would be
// worse than saying nothing.
func TestWhaleV4_FallsBackToTheGuessWhenTheRecordPredatesTheField(t *testing.T) {
	v := whaleV4Status([]statusSession{{
		Address: "2a04:2a01:9::abcd", Tier: "wireguard", Port: 41080,
	}}, nil)

	want, source := wgtun.NAT64Prefix()
	if v.NAT64Prefix != want.String() {
		t.Fatalf("NAT64Prefix = %q, want the local fallback %q", v.NAT64Prefix, want)
	}
	if v.NAT64PrefixSource != source {
		t.Fatalf("NAT64PrefixSource = %q, want %q", v.NAT64PrefixSource, source)
	}
	if !strings.Contains(v.Note, want.String()) {
		t.Fatalf("the note must still name a prefix: %s", v.Note)
	}
}
