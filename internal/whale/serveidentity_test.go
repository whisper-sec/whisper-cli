// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// serveidentity_test.go proves the three rules the resolver hot path lives by, with no
// network: the fast half always answers, one address costs one lookup, and a slow or dead
// dependency costs claims rather than the request.

var (
	onNet  = netip.MustParseAddr("2a04:2a01:1::5")
	offNet = netip.MustParseAddr("2001:db8::1")
)

func fullLookup(calls *int32) IdentityLookup {
	return IdentityLookup{
		PTR: func(context.Context, netip.Addr) (string, string) {
			atomic.AddInt32(calls, 1)
			return "db-01.acme.agents.whisper.online.", ""
		},
		Owner:  func(context.Context, netip.Addr) (string, string) { return "ACME B.V.", "" },
		Assess: func(context.Context, netip.Addr) (string, string, string) { return "CLEAN", "0.9", "" },
	}
}

func TestIdentityIsEstablishedOnce(t *testing.T) {
	var calls int32
	c := NewIdentityCache(fullLookup(&calls), IdentityCacheOptions{Budget: 2 * time.Second})

	for i := 0; i < 25; i++ {
		id := c.Resolve(context.Background(), onNet)
		if !id.Proven() {
			t.Fatalf("request %d got an unproven identity: %+v", i, id)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("the PTR walk ran %d times for one address; a proxy cannot pay that per request", got)
	}
}

// TestConcurrentCallersShareOneLookup: twenty requests arriving together must not become
// twenty DNSSEC walks.
func TestConcurrentCallersShareOneLookup(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	lookup := fullLookup(&calls)
	inner := lookup.PTR
	lookup.PTR = func(ctx context.Context, a netip.Addr) (string, string) {
		<-release
		return inner(ctx, a)
	}
	c := NewIdentityCache(lookup, IdentityCacheOptions{Budget: 2 * time.Second})

	var wg sync.WaitGroup
	proven := int32(0)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Resolve(context.Background(), onNet).Proven() {
				atomic.AddInt32(&proven, 1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("%d lookups ran for one address under concurrency", got)
	}
	if proven != 20 {
		t.Fatalf("%d of 20 concurrent callers got the proven identity", proven)
	}
}

// TestASlowLookupCostsClaimsNotTheRequest is the fail-open rule. A dependency that hangs
// must never hang a request.
func TestASlowLookupCostsClaimsNotTheRequest(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	lookup := IdentityLookup{
		PTR: func(context.Context, netip.Addr) (string, string) {
			select {
			case <-time.After(2 * time.Second):
			case <-done:
			}
			return "db-01.acme.agents.whisper.online.", ""
		},
		Assess: func(context.Context, netip.Addr) (string, string, string) { return "CLEAN", "", "" },
	}
	c := NewIdentityCache(lookup, IdentityCacheOptions{Budget: 60 * time.Millisecond})

	start := time.Now()
	id := c.Resolve(context.Background(), onNet)
	elapsed := time.Since(start)

	if elapsed > 900*time.Millisecond {
		t.Fatalf("the request waited %s on a hung lookup", elapsed)
	}
	if !id.Address.IsValid() || !id.OnWhisperNet {
		t.Fatal("the fast half was not served when the slow half timed out")
	}
	if id.FQDN != "" {
		t.Fatal("a name was claimed that the lookup had not returned yet")
	}
	if IdentityProof(id) == "" {
		t.Fatal("no proof line was produced for a timed-out lookup")
	}
}

// TestAFailedLookupIsRetriedSoon: an absence is cached briefly, not for the full TTL, so a
// control plane that blipped does not leave a caller anonymous for five minutes.
func TestAFailedLookupIsRetriedSoon(t *testing.T) {
	var calls int32
	lookup := IdentityLookup{
		PTR: func(context.Context, netip.Addr) (string, string) {
			atomic.AddInt32(&calls, 1)
			return "", "the control plane did not answer"
		},
	}
	now := time.Now()
	clock := &now
	c := NewIdentityCache(lookup, IdentityCacheOptions{
		TTL: time.Hour, NegativeTTL: 30 * time.Second, Budget: time.Second,
		Now: func() time.Time { return *clock },
	})

	if id := c.Resolve(context.Background(), onNet); id.Proven() {
		t.Fatal("a failed lookup produced a proven identity")
	}
	*clock = now.Add(45 * time.Second) // past the negative TTL, far short of the positive one
	c.Resolve(context.Background(), onNet)
	// The refresh is asynchronous behind the stale answer; give it a moment to land.
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt32(&calls) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("an unestablished identity was cached past its negative TTL (%d lookups)", got)
	}
}

// TestOffNetCallerIsNotAskedAboutByName: a public address gets no PTR and no owner lookup,
// because a header called Whisper-Agent-FQDN may never carry a stranger's reverse name.
func TestOffNetCallerIsNotAskedAboutByName(t *testing.T) {
	ptrCalls, ownerCalls, assessCalls := 0, 0, 0
	c := NewIdentityCache(IdentityLookup{
		PTR:   func(context.Context, netip.Addr) (string, string) { ptrCalls++; return "evil.example.", "" },
		Owner: func(context.Context, netip.Addr) (string, string) { ownerCalls++; return "Someone", "" },
		Assess: func(context.Context, netip.Addr) (string, string, string) {
			assessCalls++
			return "MALICIOUS", "0.99", ""
		},
	}, IdentityCacheOptions{Budget: time.Second})

	id := c.Resolve(context.Background(), offNet)
	if ptrCalls != 0 || ownerCalls != 0 {
		t.Fatalf("an off-net caller was looked up by name (ptr=%d owner=%d)", ptrCalls, ownerCalls)
	}
	if assessCalls != 1 || id.Band != "MALICIOUS" {
		t.Fatalf("the graph was not asked about an off-net caller: calls=%d band=%q", assessCalls, id.Band)
	}
	if id.FQDN != "" {
		t.Fatal("an off-net caller carried a name")
	}
}

func TestCacheStaysBounded(t *testing.T) {
	var calls int32
	c := NewIdentityCache(fullLookup(&calls), IdentityCacheOptions{MaxEntries: 8, Budget: time.Second})
	for i := 0; i < 200; i++ {
		addr := netip.AddrFrom16([16]byte{0x2a, 0x04, 0x2a, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		c.Resolve(context.Background(), addr)
	}
	if got := c.Size(); got > 16 {
		t.Fatalf("the cache grew to %d entries with a bound of 8", got)
	}
}

func TestNilCacheAndInvalidAddressStillAnswer(t *testing.T) {
	var c *IdentityCache
	if id := c.Resolve(context.Background(), onNet); !id.OnWhisperNet {
		t.Fatal("a nil cache did not return the fast half")
	}
	real := NewIdentityCache(IdentityLookup{}, IdentityCacheOptions{})
	if id := real.Resolve(context.Background(), netip.Addr{}); id.Address.IsValid() {
		t.Fatal("an invalid address produced a valid identity")
	}
}
