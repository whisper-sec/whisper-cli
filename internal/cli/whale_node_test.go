// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_node_test.go covers the argument boundary every whale verb shares: one parser,
// one resolution order, the same spellings accepted everywhere.

// TestResolveWhaleNode_AnAddressNeedsNoLookup: a literal is already the answer, and it
// must not cost a DNS query or a control-plane call.
func TestResolveWhaleNode_AnAddressNeedsNoLookup(t *testing.T) {
	whaleTestIsolation(t)
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("a literal address triggered a DNS lookup")
		return nil, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	for _, in := range []string{"2a04:2a01:1:4::b", "[2a04:2a01:1:4::b]", "2A04:2A01:1:4::B"} {
		node, err := resolveWhaleNode(context.Background(), nil, in)
		if err != nil {
			t.Fatalf("resolveWhaleNode(%q): %v", in, err)
		}
		if node.Addr.String() != "2a04:2a01:1:4::b" || node.Via != "literal" {
			t.Fatalf("resolveWhaleNode(%q) = %+v", in, node)
		}
	}
}

// TestResolveWhaleNode_AnFQDNResolvesThroughDNSWithOrWithoutTheDot.
func TestResolveWhaleNode_AnFQDNResolvesThroughDNSWithOrWithoutTheDot(t *testing.T) {
	whaleTestIsolation(t)
	var asked []string
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(_ context.Context, name string) ([]netip.Addr, error) {
		asked = append(asked, name)
		return []netip.Addr{netip.MustParseAddr("2a04:2a01:1:4::c")}, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	for _, in := range []string{"db-01.t9f.agents.whisper.online", "DB-01.T9F.Agents.Whisper.Online."} {
		node, err := resolveWhaleNode(context.Background(), nil, in)
		if err != nil {
			t.Fatalf("resolveWhaleNode(%q): %v", in, err)
		}
		if node.Addr.String() != "2a04:2a01:1:4::c" || node.Via != "dns" {
			t.Fatalf("resolveWhaleNode(%q) = %+v", in, node)
		}
	}
	for _, a := range asked {
		if a != "db-01.t9f.agents.whisper.online" {
			t.Fatalf("the lookup was asked for %q; every spelling must normalise to one name", a)
		}
	}
}

// TestResolveWhaleNode_ANameWithNoAAAAIsExplained: a name that resolves to nothing must
// say what was expected, since a Whalenet node is an IPv6 /128 by definition.
func TestResolveWhaleNode_ANameWithNoAAAAIsExplained(t *testing.T) {
	whaleTestIsolation(t)
	prev := lookupWhaleAAAA
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { lookupWhaleAAAA = prev })

	_, err := resolveWhaleNode(context.Background(), nil, "nothing.example.com")
	if err == nil {
		t.Fatal("a name with no AAAA resolved anyway")
	}
	if !strings.Contains(err.Error(), "AAAA") || !strings.Contains(err.Error(), "/128") {
		t.Fatalf("error = %q, which does not say what was expected", err.Error())
	}
}

// TestResolveWhaleNode_ASingleLabelKeylessAsksForAKeyRatherThanFailingVaguely: a bare
// name only means something inside a fleet, so the keyless answer is the way in, not a
// misleading "not accepted".
func TestResolveWhaleNode_ASingleLabelKeylessAsksForAKeyRatherThanFailingVaguely(t *testing.T) {
	whaleTestIsolation(t)
	_, err := resolveWhaleNode(context.Background(), nil, "db-01")
	if err == nil {
		t.Fatal("a bare label resolved with no fleet to resolve it in")
	}
	msg := friendly(err)
	if !strings.Contains(msg, "whisper login") {
		t.Fatalf("friendly(err) = %q, which does not offer the way in", msg)
	}
	if strings.Contains(msg, "was not accepted") {
		t.Fatal("a missing key was rendered as a rejected key, which is a different and wrong diagnosis")
	}
}

// TestResolveWhaleNode_RefusesIPv4AsAUsageErrorNamingTheReason.
func TestResolveWhaleNode_RefusesIPv4AsAUsageErrorNamingTheReason(t *testing.T) {
	whaleTestIsolation(t)
	_, err := resolveWhaleNode(context.Background(), nil, "10.0.0.1")
	if err == nil || !isUsageError(err) {
		t.Fatalf("resolveWhaleNode(v4) = %v, want a usage error", err)
	}
	if !strings.Contains(err.Error(), "IPv6-only") {
		t.Fatalf("error = %q, want the IPv6-only sentence", err.Error())
	}
}

// TestWhaleBoxHosts_DerivesFromTheOneListTheClientKeeps: a second hardcoded list of boxes
// is a list that drifts. This asserts the derivation, not the values.
func TestWhaleBoxHosts_DerivesFromTheOneListTheClientKeeps(t *testing.T) {
	hosts := whaleBoxHosts()
	if len(hosts) != len(client.DefaultReportFallbackBases) {
		t.Fatalf("whaleBoxHosts() has %d entries but the client keeps %d",
			len(hosts), len(client.DefaultReportFallbackBases))
	}
	want := map[string]bool{}
	for _, base := range client.DefaultReportFallbackBases {
		u, err := url.Parse(base)
		if err != nil {
			t.Fatalf("the client's own base %q does not parse", base)
		}
		want[u.Hostname()] = true
	}
	for _, h := range hosts {
		if !want[h] {
			t.Fatalf("whaleBoxHosts() returned %q, which is not one of the client's bases", h)
		}
		if strings.Contains(h, "/") || strings.Contains(h, ":") {
			t.Fatalf("whaleBoxHosts() returned %q, which is not a bare hostname", h)
		}
	}
	if len(hosts) < 2 {
		t.Fatal("fewer than two boxes: the fleet is active/active and netcheck must probe both")
	}
}

// TestFmtMs_NeverPrintsAZeroAsAMeasurement.
func TestFmtMs_NeverPrintsAZeroAsAMeasurement(t *testing.T) {
	if got := fmtMs(0); got != "-" {
		t.Fatalf("fmtMs(0) = %q, want a dash: nothing was measured", got)
	}
	if got := fmtMs(-1); got != "-" {
		t.Fatalf("fmtMs(-1) = %q", got)
	}
	if got := fmtMs(24.34); got != "24.3 ms" {
		t.Fatalf("fmtMs(24.34) = %q", got)
	}
}

// TestPingAttemptLine_NamesThePathAndNeverClaimsDirect. The direct-path work added the two classes a
// pair can honestly be direct on, so the rule is no longer "never say direct" - it is "say
// exactly what the control plane assigned, and say relayed for everything else, including
// every case where we could not ask".
func TestPingAttemptLine_NamesThePathAndNeverClaimsDirect(t *testing.T) {
	node := whaleNode{Addr: netip.MustParseAddr("2a04:2a01:1:4::b"), Name: "db-01"}
	for _, a := range []whale.Attempt{
		{Seq: 1, Outcome: whale.OutcomeOpen, RTTMs: 24.1},
		{Seq: 2, Outcome: whale.OutcomeRefused, RTTMs: 23.9},
		{Seq: 3, Outcome: whale.OutcomeNoReply, Detail: "timed out"},
		{Seq: 4, Outcome: whale.OutcomeNoRoute, Detail: "network is unreachable"},
	} {
		// No class: this is the pair the plane said nothing about, or could not be asked.
		line := pingAttemptLine(a, node, 443, "")
		if strings.Contains(strings.ToLower(line), "direct") {
			t.Fatalf("attempt line claims a direct path nothing established: %q", line)
		}
		if !strings.Contains(line, "db-01") {
			t.Fatalf("attempt line does not name the peer: %q", line)
		}
		if a.Outcome.Answered() && !strings.Contains(line, whale.PathRelayed) {
			t.Fatalf("an answered attempt did not name the path: %q", line)
		}
		// A class the plane did assign is named verbatim, and an invented one is not.
		if a.Outcome.Answered() {
			if got := pingAttemptLine(a, node, 443, whale.PathDirectLocal); !strings.Contains(got, whale.PathDirectLocal) {
				t.Fatalf("a direct-local pair did not name its path: %q", got)
			}
			if got := pingAttemptLine(a, node, 443, "punched"); !strings.Contains(got, whale.PathRelayed) {
				t.Fatalf("an unrecognised class was not rendered as relayed: %q", got)
			}
		}
	}
}
