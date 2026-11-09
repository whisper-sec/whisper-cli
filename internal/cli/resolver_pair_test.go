// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/resolverprofile"
)

// The readers take a resolver pair when the server sends one (resolver_ips,
// addresses) and fall back to the single address when it does not, so an
// older server keeps working exactly as before.

const (
	rpA = "2a04:2a01:0:53::42"
	rpB = "2a04:2a01:0:53::77"
)

func TestTier2ReadsResolverIPsWhenPresent(t *testing.T) {
	res := resultOf(t,
		[]string{"api_key", "agent", "address", "fqdn", "ptr", "doh_url", "resolver_ip", "resolver_ips"},
		[]any{"k", "a", "2a04:2a01:9::1", "f.", "p.", "", rpA, []any{rpA, rpB}})
	got := tier2FromResult(res)
	if got.ResolverIP != rpA || len(got.ResolverIPs) != 2 || got.ResolverIPs[1] != rpB {
		t.Fatalf("pair not read: %+v", got)
	}
}

func TestTier2WithoutResolverIPsKeepsTheSingleAddress(t *testing.T) {
	res := resultOf(t,
		[]string{"api_key", "agent", "address", "fqdn", "ptr", "doh_url", "resolver_ip"},
		[]any{"k", "a", "2a04:2a01:9::1", "f.", "p.", "", rpA})
	got := tier2FromResult(res)
	if got.ResolverIP != rpA || len(got.ResolverIPs) != 1 {
		t.Fatalf("older server shape: %+v", got)
	}
	if pairOrNil(got.ResolverIPs) != nil {
		t.Fatal("a single address must save and print as before")
	}
}

func TestTier2ResolverIPsJunkFailsSoft(t *testing.T) {
	res := resultOf(t,
		[]string{"resolver_ip", "resolver_ips"},
		[]any{rpA, []any{"not-an-ip", 7, rpA, "", rpB, rpB}})
	got := tier2FromResult(res)
	if len(got.ResolverIPs) != 2 || got.ResolverIPs[0] != rpA || got.ResolverIPs[1] != rpB {
		t.Fatalf("junk must be dropped, order kept: %v", got.ResolverIPs)
	}
	// The single-address column names the first address, whatever order the list came in.
	res = resultOf(t, []string{"resolver_ip", "resolver_ips"}, []any{rpA, []any{rpB, rpA}})
	if got := tier2FromResult(res).ResolverIPs; got[0] != rpA || got[1] != rpB {
		t.Fatalf("resolver_ip must stay first: %v", got)
	}
	// Only the list: its first entry becomes the address.
	res = resultOf(t, []string{"resolver_ips"}, []any{[]any{rpB, rpA}})
	if got := tier2FromResult(res); got.ResolverIP != rpB {
		t.Fatalf("list alone: %+v", got)
	}
	// Not a list at all: ignored.
	res = resultOf(t, []string{"resolver_ip", "resolver_ips"}, []any{rpA, "oops"})
	if got := tier2FromResult(res).ResolverIPs; len(got) != 1 {
		t.Fatalf("non-list column: %v", got)
	}
}

func TestResolverStateAddressList(t *testing.T) {
	if got := (resolverState{}).resolverIPs(); got != nil {
		t.Fatalf("empty state: %v", got)
	}
	if got := (resolverState{ResolverIP: rpA}).resolverIPs(); len(got) != 1 || got[0] != rpA {
		t.Fatalf("single: %v", got)
	}
	if got := (resolverState{ResolverIP: rpA, ResolverIPs: []string{rpA, rpB}}).resolverIPs(); len(got) != 2 {
		t.Fatalf("pair: %v", got)
	}
	// A saved list that no longer starts with the saved address is stale: the address wins.
	if got := (resolverState{ResolverIP: rpB, ResolverIPs: []string{rpA, rpB}}).resolverIPs(); len(got) != 1 || got[0] != rpB {
		t.Fatalf("stale list: %v", got)
	}
}

func TestResolverPlanJSONAddsTheListOnlyForAPair(t *testing.T) {
	single := resolverPlanJSON(resolverprofile.Rendered{ResolverIP: rpA}, false, "")
	if _, ok := single["resolver_ips"]; ok {
		t.Fatal("single-address plan JSON must not change")
	}
	pair := resolverPlanJSON(resolverprofile.Rendered{ResolverIP: rpA, ResolverIPs: []string{rpA, rpB}}, false, "")
	if got, ok := pair["resolver_ips"].([]string); !ok || len(got) != 2 {
		t.Fatalf("pair plan JSON: %v", pair["resolver_ips"])
	}
	rc := &resolverprofile.RouteCheck{Want: rpA, Accept: []string{rpA, rpB}}
	if m := routeJSON(rc); m["accept"] == nil {
		t.Fatalf("route JSON must list both: %v", m)
	}
	if m := routeJSON(&resolverprofile.RouteCheck{Want: rpA, Accept: []string{rpA}}); m["accept"] != nil {
		t.Fatalf("single-address route JSON must not change: %v", m)
	}
}
