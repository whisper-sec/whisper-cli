package wgtun

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// The ladder's second rung must stay on the AGENT plane.
//
// Why. Measured from inside a live agent tunnel on 2026-09-03, asking each candidate for
// ipv4only.arpa:
//
//	2a04:2a01:0:53::1        2a04:2a00:64::c000:aa   agent plane
//	2a04:2a01:0:53:8000::1   2a04:2a00:64::c000:aa   agent plane
//	2a04:2a00::53            64:ff9b::c000:aa        office plane
//
// Neither is misconfigured; each is right for its own plane. Falling back ACROSS planes makes
// the agent adopt a prefix whose translator its tunnel never traverses, so every IPv4-only
// destination becomes a silent black hole. Ordering is therefore load-bearing, not cosmetic,
// and a refactor that "tidied" this list would reintroduce the defect invisibly.

func TestTheFallbackListPrefersTheAgentPlaneAndKeepsTheOfficeAnycastLast(t *testing.T) {
	t.Setenv(WhisperPublicResolverEnv, "")
	got := fallbackResolvers()
	if len(got) < 2 {
		t.Fatalf("fallback list is %v, want the agent-plane resolvers ahead of the office anycast", got)
	}
	office := netip.MustParseAddr("2a04:2a00::53")
	if got[len(got)-1] != office {
		t.Fatalf("last candidate is %v, want the office anycast %v to be the LAST resort", got[len(got)-1], office)
	}
	for i, a := range got[:len(got)-1] {
		if a == office {
			t.Fatalf("the office anycast appears at position %d; it must be last", i)
		}
		// Every earlier candidate must live in agent space, which is what makes it same-plane.
		if !netip.MustParsePrefix("2a04:2a01::/32").Contains(a) {
			t.Fatalf("candidate %d is %v, which is not in agent space 2a04:2a01::/32", i, a)
		}
	}
}

func TestAnOperatorNamedResolverWinsAloneAndIsNotSecondGuessed(t *testing.T) {
	// Naming a resolver is an instruction, not a hint. Trying our defaults after it would
	// silently send a self-hosted deployment's lookups somewhere its operator did not choose.
	t.Setenv(WhisperPublicResolverEnv, "2001:db8::99")
	got := fallbackResolvers()
	if len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::99") {
		t.Fatalf("fallback list is %v, want exactly the operator's resolver and nothing else", got)
	}
}

func TestAGarbledOverrideFallsBackToTheDefaultsRatherThanFailing(t *testing.T) {
	// Postel: a typo in an env var must not take the tunnel's name resolution down.
	t.Setenv(WhisperPublicResolverEnv, "not-an-address")
	got := fallbackResolvers()
	if len(got) < 2 {
		t.Fatalf("a garbled override produced %v, want the normal candidate list", got)
	}
}

func TestTheFallbackWalkerTakesTheFirstResolverThatRecurses(t *testing.T) {
	// The first agent resolver answers, so it must be chosen and the walk must stop there.
	first := agentPlaneResolvers[0]
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): {netip.MustParseAddr("198.41.0.4")},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &nameService{}
	got, ok := n.probeFallbacks(ctx, s, netip.Addr{})
	if !ok || got != first {
		t.Fatalf("(%v,%v), want the first agent-plane resolver %v", got, ok, first)
	}
}

func TestASilentFirstResolverIsSkippedForTheSecondOnTheSamePlane(t *testing.T) {
	// THE regression this guards. If rung 2's first candidate is dead we must move to the other
	// AGENT resolver, not skip the plane entirely. A walker that gave up after one would land on
	// the office anycast and take the unroutable prefix with it.
	first, second := agentPlaneResolvers[0], agentPlaneResolvers[1]
	working := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): {netip.MustParseAddr("198.41.0.4")},
	}}
	s := &dnsStack{
		rcodes:      map[string]uint8{key(recursionProbeName, dnsTypeA): 2}, // first: SERVFAIL
		perResolver: map[string]*dnsStack{second.String(): working},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &nameService{}
	got, ok := n.probeFallbacks(ctx, s, netip.Addr{})
	if !ok {
		t.Fatal("no fallback chosen although the second agent-plane resolver answers")
	}
	if got == first {
		t.Fatalf("chose %v, which did not answer", got)
	}
	if got != second {
		t.Fatalf("chose %v, want the OTHER agent-plane resolver %v before leaving the plane", got, second)
	}
}

func TestWhenNoCandidateAnswersTheWalkerSaysSoRatherThanNamingOne(t *testing.T) {
	// CONTROL. Returning a plausible address on total failure would send every lookup to a
	// resolver known not to answer, and the caller could not tell that from success.
	s := &dnsStack{rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 2}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &nameService{}
	if got, ok := n.probeFallbacks(ctx, s, netip.Addr{}); ok {
		t.Fatalf("(%v,%v), want no resolver chosen when none answers", got, ok)
	}
}

func TestTheWalkerSkipsTheResolverThatAlreadyFailedAsRungOne(t *testing.T) {
	// The control plane can hand an agent the SHARED agent resolver rather than a per-tenant one,
	// in which case rung 1 and the first candidate here are the same address. Probing it twice
	// costs a timeout for nothing, and if the second probe somehow answered we would hand back a
	// resolver the ladder had already rejected. So it is skipped by identity, not by luck.
	first, second := agentPlaneResolvers[0], agentPlaneResolvers[1]
	working := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): {netip.MustParseAddr("198.41.0.4")},
	}}
	// Everything answers, including `first`. Only the skip can keep it from being chosen.
	s := &dnsStack{
		answers:     map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): {netip.MustParseAddr("198.41.0.4")}},
		perResolver: map[string]*dnsStack{second.String(): working},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &nameService{}
	got, ok := n.probeFallbacks(ctx, s, first)
	if !ok {
		t.Fatal("no fallback chosen although other candidates answer")
	}
	if got == first {
		t.Fatalf("chose %v, the resolver that already failed as rung 1", got)
	}
}
