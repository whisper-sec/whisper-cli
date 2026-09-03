// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// nameservice_declared_test.go pins 's rung of the ladder: the prefix op:connect NAMED.
//
// The ladder is env pin, then RFC 7050 discovery, then the declaration, then the well-known
// guess. Every test here varies exactly one rung and holds the rest fixed, because the whole
// value of an ordered ladder is that a higher rung wins when both are present - a test with only
// one rung populated would pass with the order reversed.

const declaredNSP = "2a04:2a00:64::/96"

// TestTheDeclaredPrefixIsUsedWhenTheResolverCannotBeMeasured: the case the issue exists for. The
// resolver recurses but does not synthesise, so before that there was nothing to refine the
// guess with and the node wrapped into 64:ff9b::/96 - a translator it cannot reach.
func TestTheDeclaredPrefixIsUsedWhenTheResolverCannotBeMeasured(t *testing.T) {
	s := &dnsStack{
		answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()},
		rcodes:  map[string]uint8{key(wellKnownIPv4OnlyName, dnsTypeAAAA): 3}, // NXDOMAIN
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.MustParsePrefix(declaredNSP))

	if got := ns.prefix.String(); got != declaredNSP {
		t.Fatalf("prefix = %s, want the prefix the control plane named (%s)", got, declaredNSP)
	}
	if ns.prefixSource != "the control plane" {
		t.Fatalf("prefixSource = %q, want it to name the control plane", ns.prefixSource)
	}
	// The control that this is not just "the default happened to match": with no declaration the
	// SAME stack lands on the well-known guess.
	bare := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if bare.prefix.String() != WellKnownNAT64Prefix {
		t.Fatalf("without a declaration the same stack must guess %s, got %s",
			WellKnownNAT64Prefix, bare.prefix)
	}
	// And a declaration is not a degradation, so it is not something the user is warned about.
	if strings.Contains(ns.verdict, "not synthesising") {
		t.Fatalf("verdict = %q, want no complaint when the box already told us the prefix", ns.verdict)
	}
}

// TestAMeasurementOutranksTheDeclaration: the control the issue asks for by name - a node whose
// resolver DOES answer RFC 7050 follows the measurement, not the declaration. A box can be
// reconfigured between the connect and the next packet, and only the wire knows.
func TestAMeasurementOutranksTheDeclaration(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {
			synth(t, nsp, "192.0.0.170"),
			synth(t, nsp, "192.0.0.171"),
		},
	}}
	// Declare something DIFFERENT from what the resolver synthesises, so the two cannot be
	// confused for each other.
	declared := netip.MustParsePrefix("2001:db8:64::/96")
	ns := newNameService(context.Background(), s, resolverAddr(), declared)

	if got := ns.prefix.String(); got != nsp {
		t.Fatalf("prefix = %s, want the MEASURED %s rather than the declared %s", got, nsp, declared)
	}
	if !strings.Contains(ns.prefixSource, "RFC 7050") {
		t.Fatalf("prefixSource = %q, want it to name the discovery", ns.prefixSource)
	}
	if !strings.Contains(ns.verdict, "the control plane named") {
		t.Fatalf("verdict = %q, want the disagreement said out loud", ns.verdict)
	}
}

// TestAgreementBetweenTheBoxAndTheWireIsSilent: when the declaration and the measurement match,
// there is nothing wrong, so there is nothing to say. A verdict for a healthy tunnel trains
// people to ignore verdicts.
func TestAgreementBetweenTheBoxAndTheWireIsSilent(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {
			synth(t, nsp, "192.0.0.170"),
			synth(t, nsp, "192.0.0.171"),
		},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.MustParsePrefix(nsp))
	if ns.verdict != "" {
		t.Fatalf("verdict = %q, want silence when the box and the wire agree", ns.verdict)
	}
	if ns.prefix.String() != nsp {
		t.Fatalf("prefix = %s, want %s", ns.prefix, nsp)
	}
}

// TestAnOperatorPinStillOutranksTheDeclaration: WHISPER_NAT64_PREFIX is rung one and stays there.
// An operator who set it meant it, and a new column must not quietly take that away.
func TestAnOperatorPinStillOutranksTheDeclaration(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "2001:db8:1::/96")
	s := &dnsStack{
		answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()},
		rcodes:  map[string]uint8{key(wellKnownIPv4OnlyName, dnsTypeAAAA): 3},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.MustParsePrefix(declaredNSP))
	if got := ns.prefix.String(); got != "2001:db8:1::/96" {
		t.Fatalf("prefix = %s, want the operator's pin", got)
	}
	if ns.prefixSource != nat64PrefixEnv {
		t.Fatalf("prefixSource = %q, want it to name the env pin", ns.prefixSource)
	}
}

// TestTheDialerWrapsIntoTheDeclaredPrefix: the anti-unreachable leg inside this package. A
// nameService field nothing reads would satisfy every test above and still leave every IPv4 dial
// wrapping into the wrong prefix, so this asserts the value the DIALER uses.
func TestTheDialerWrapsIntoTheDeclaredPrefix(t *testing.T) {
	s := &dnsStack{
		answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()},
		rcodes:  map[string]uint8{key(wellKnownIPv4OnlyName, dnsTypeAAAA): 3},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.MustParsePrefix(declaredNSP))
	d := &netDialer{names: ns}

	if got := d.nat64().String(); got != declaredNSP {
		t.Fatalf("the dialer wraps into %s, want the declared %s", got, declaredNSP)
	}
	target, ok, err := TranslateTarget(d.nat64(), "192.0.2.10:443")
	if err != nil || !ok {
		t.Fatalf("TranslateTarget(192.0.2.10:443) = %q, %v, %v", target, ok, err)
	}
	if !strings.HasPrefix(target, "[2a04:2a00:64::c000:20a]") {
		t.Fatalf("wrapped target = %s, want it inside the declared prefix", target)
	}
}
