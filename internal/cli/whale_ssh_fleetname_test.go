// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_ssh_fleetname_test.go covers `whisper whale ssh db-01`, the one spelling this
// command is named for. It looked the node's SSHFP up under its AGENT ID rather than its
// DNS name, got NXDOMAIN, and refused to connect to a node whose SSHFP was published and
// valid the whole time: the /128 spelling validated and the fleet-name spelling did not,
// which is the asymmetry every test below pins.
//
// The fixture is synthetic, deliberately. What these tests prove is which STRING the
// resolver hands the SSHFP validator, and no real address, handle or agent id is needed to
// prove it.
//
// Every test here drives the real resolveWhaleNode, because the defect was never in the
// SSHFP validator - it was in which string the resolver handed it.

// stubWhaleFleet points the fleet rung at a fixed peer table for one test.
func stubWhaleFleet(t *testing.T, peers []whalePeer) {
	t.Helper()
	prev := whaleFleet
	whaleFleet = func(context.Context, *client.Client) ([]whalePeer, error) { return peers, nil }
	t.Cleanup(func() { whaleFleet = prev })
}

// keyedTestClient is a client that reports a credential, so resolveWhaleNode's keyed
// fleet rung is actually entered. Without it the fleet lookup is skipped and every
// assertion below would pass against a code path that never ran.
func keyedTestClient(t *testing.T) *client.Client {
	t.Helper()
	c := client.New(client.Config{Cred: client.Credential{Value: "whisper_live_test-not-a-real-key"}})
	if c.Credential().IsZero() {
		t.Fatal("the test client reports no credential, so the fleet rung would be skipped")
	}
	return c
}

var sshTestPeer = whalePeer{
	Name:    "agent-0123456789abcdef0",
	Label:   "db-01",
	Address: "2a04:2a01:4::db01",
	FQDN:    "0123456789abcdef0.t0123456789abcdef0123456789abcdef.agents.whisper.online",
}

// TestFleetHitCarriesTheNodesDNSNameNotItsID is the defect itself. The CONTROL is Name:
// asserting it still holds the id proves the fix separated two strings rather than
// overwriting one, so `whale ping`'s display and `whale ssh`'s lookup can disagree
// on purpose.
func TestFleetHitCarriesTheNodesDNSNameNotItsID(t *testing.T) {
	whaleTestIsolation(t)
	stubWhaleFleet(t, []whalePeer{sshTestPeer})
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("a fleet hit fell through to public DNS")
		return nil, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	for _, spelling := range []string{"db-01", "agent-0123456789abcdef0", sshTestPeer.FQDN} {
		node, err := resolveWhaleNode(context.Background(), keyedTestClient(t), spelling)
		if err != nil {
			t.Fatalf("resolveWhaleNode(%q): %v", spelling, err)
		}
		if node.Via != "fleet" {
			t.Fatalf("resolveWhaleNode(%q).Via = %q, want fleet - the rest of this test asserts nothing otherwise",
				spelling, node.Via)
		}
		if node.FQDN != sshTestPeer.FQDN {
			t.Fatalf("resolveWhaleNode(%q).FQDN = %q, want the node's DNS name %q. An SSHFP is published "+
				"under a name; looking it up under an id is NXDOMAIN and reads as 'no host key published'",
				spelling, node.FQDN, sshTestPeer.FQDN)
		}
		// CONTROL: the short name is still the id, so this is two fields and not a rename.
		if node.Name != sshTestPeer.Name {
			t.Fatalf("resolveWhaleNode(%q).Name = %q, want the short id %q kept for display",
				spelling, node.Name, sshTestPeer.Name)
		}
	}
}

// TestSSHVerificationLooksTheSSHFPUpUnderTheFleetsDNSName is the anti-unreachable gate:
// it drives verifyWhaleSSHHost, the function `whale ssh` actually calls, and asserts the
// NAME it carried into the lookup. Asserting only on resolveWhaleNode would pass on a
// build where whale_ssh.go still read node.Name.
func TestSSHVerificationLooksTheSSHFPUpUnderTheFleetsDNSName(t *testing.T) {
	whaleTestIsolation(t)
	stubWhaleFleet(t, []whalePeer{sshTestPeer})

	node, err := resolveWhaleNode(context.Background(), keyedTestClient(t), "db-01")
	if err != nil {
		t.Fatalf("resolveWhaleNode: %v", err)
	}
	// A resolver that answers nothing: the validation must fail, but the REASON names
	// the FQDN it asked for, which is the fact under test.
	v := verifyWhaleSSHHost(context.Background(), node, "127.0.0.1:1")
	if v.FQDN != sshTestPeer.FQDN {
		t.Fatalf("whale ssh looked the host key up under %q, want %q", v.FQDN, sshTestPeer.FQDN)
	}
	if v.FQDNVia != "your fleet" {
		t.Fatalf("provenance = %q, want 'your fleet' - a claim about where a fact came from is a fact", v.FQDNVia)
	}
	if strings.Contains(v.FQDN, "agent-") {
		t.Fatalf("the SSHFP lookup name %q is an agent id, which resolves to nothing", v.FQDN)
	}
}

// TestAFleetPeerWithNoPublishedNameFallsThroughRatherThanRefusing: the old code
// dead-ended on any fleet hit. A legacy row with no fqdn must not cost a user the name
// they typed - which public DNS can answer perfectly well.
func TestAFleetPeerWithNoPublishedNameFallsThroughRatherThanRefusing(t *testing.T) {
	whaleTestIsolation(t)
	nameless := sshTestPeer
	nameless.FQDN = ""
	stubWhaleFleet(t, []whalePeer{nameless})
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("the fleet rung did not match, so this test would be asserting about the DNS rung instead")
		return nil, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	// matchPeer falls back to the leftmost label, so this fqdn still finds the peer we
	// hold under the short name `db-01` - a fleet hit that carries no fqdn of its own.
	const typed = "db-01.t9f.agents.whisper.online"
	node, err := resolveWhaleNode(context.Background(), keyedTestClient(t), typed)
	if err != nil {
		t.Fatalf("resolveWhaleNode: %v", err)
	}
	if node.Via != "fleet" || node.FQDN != "" {
		t.Fatalf("setup is wrong: node = %+v, want a fleet hit carrying no fqdn", node)
	}
	v := verifyWhaleSSHHost(context.Background(), node, "127.0.0.1:1")
	if v.FQDN != typed {
		t.Fatalf("a nameless fleet peer must fall through to the name you typed; got %q", v.FQDN)
	}
	if v.FQDNVia != "as you named it" {
		t.Fatalf("provenance = %q, want 'as you named it' - it did not come from the fleet", v.FQDNVia)
	}
}

// TestAPublicDNSNodeStillCarriesItsOwnName is the control on the other rung: the fix
// must not have made FQDN a fleet-only field, or `whale ssh` against a name outside your
// tenant would lose the only name it has.
func TestAPublicDNSNodeStillCarriesItsOwnName(t *testing.T) {
	whaleTestIsolation(t)
	stubWhaleFleet(t, nil) // no fleet hit, so the DNS rung runs
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2a04:2a01:1:4::c")}, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	node, err := resolveWhaleNode(context.Background(), keyedTestClient(t), "node.example.com")
	if err != nil {
		t.Fatalf("resolveWhaleNode: %v", err)
	}
	if node.Via != "dns" {
		t.Fatalf("Via = %q, want dns", node.Via)
	}
	if node.FQDN != "node.example.com" {
		t.Fatalf("a name from public DNS lost its own name: FQDN = %q", node.FQDN)
	}
}
