// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// serveidentity.go turns a caller's socket address into the PeerIdentity the headers carry
//. Three rules shape it, and they are the same three the resolver hot path obeys.
//
// 1. THE FAST HALF IS NEVER BLOCKED. The address and whether it is on the Whisper net are
// computed with no I/O at all, so the worst outcome of a dead control plane or a slow
// DNSSEC walk is a request served with fewer claims. It is never a request that hangs
// and never one that fails. Fail open, always answer.
// 2. ONE LOOKUP PER ADDRESS, NOT ONE PER REQUEST. A validated PTR walk plus a graph
// assessment on every request would put two network round trips in front of a proxy
// whose whole point is to be fast. Answers are cached with a TTL, absences with a
// shorter one, and concurrent callers for the same address share one lookup.
// 3. A STALE ANSWER IS SERVED IMMEDIATELY AND REFRESHED BEHIND THE REQUEST. Once we have
// established who an address is, no later request pays for it again.
//
// Nothing here dials anything: the three lookups are injected, which is what lets the
// timeout, the cache and the fail-open behaviour be proven in unit tests with no network.

// IdentityLookup is the injected outside world. Each function returns the value it
// established and, when it established nothing, the reason - the reason travels into
// Whisper-Identity-Proof, so an operator can see WHY a claim is missing.
type IdentityLookup struct {
	// PTR resolves and validates the reverse name for addr, forward-confirmed. It returns
	// a name ONLY when the whole chain verified.
	PTR func(ctx context.Context, addr netip.Addr) (fqdn string, note string)
	// Owner returns who holds addr, per our control plane.
	Owner func(ctx context.Context, addr netip.Addr) (owner string, note string)
	// Assess returns the graph's band and coverage for addr.
	Assess func(ctx context.Context, addr netip.Addr) (band, coverage, note string)
}

// IdentityCacheOptions tunes the cache. The zero value is the shipped default.
type IdentityCacheOptions struct {
	// TTL is how long a fully established identity is reused. 0 => 5m.
	TTL time.Duration
	// NegativeTTL is how long an identity we could not establish is reused before we try
	// again. 0 => 30s. Short, because a control plane that was down comes back.
	NegativeTTL time.Duration
	// Budget bounds how long a request waits for a FIRST lookup before being served with
	// the fast half alone. 0 => 900ms. The lookup keeps running; the next request gets it.
	Budget time.Duration
	// MaxEntries bounds the cache. 0 => 4096. Over the bound, the oldest entries go.
	MaxEntries int
	// Now is the clock. nil => time.Now.
	Now func() time.Time
}

const (
	defaultIdentityTTL         = 5 * time.Minute
	defaultIdentityNegativeTTL = 30 * time.Second
	defaultIdentityBudget      = 900 * time.Millisecond
	defaultIdentityMaxEntries  = 4096
)

// IdentityCache resolves caller identities with a TTL cache and a bounded wait.
type IdentityCache struct {
	lookup IdentityLookup
	opt    IdentityCacheOptions

	mu      sync.Mutex
	entries map[netip.Addr]*identityEntry
}

type identityEntry struct {
	id       PeerIdentity
	at       time.Time     // when the answer was established
	ttl      time.Duration // the TTL that answer earned (positive or negative)
	inflight chan struct{} // non-nil while a lookup is running; closed when it lands
}

// NewIdentityCache builds a cache over the given lookups. A nil member simply means that
// claim is never established, which is a supported configuration (`--identity-headers`
// narrowed, or a keyless run where the graph cannot be asked).
func NewIdentityCache(lookup IdentityLookup, opt IdentityCacheOptions) *IdentityCache {
	if opt.TTL <= 0 {
		opt.TTL = defaultIdentityTTL
	}
	if opt.NegativeTTL <= 0 {
		opt.NegativeTTL = defaultIdentityNegativeTTL
	}
	if opt.Budget <= 0 {
		opt.Budget = defaultIdentityBudget
	}
	if opt.MaxEntries <= 0 {
		opt.MaxEntries = defaultIdentityMaxEntries
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &IdentityCache{lookup: lookup, opt: opt, entries: map[netip.Addr]*identityEntry{}}
}

// Base is the no-I/O half of the answer: the two things the socket alone proves. It is
// what a request is served with when everything else is slow, down, or switched off.
func Base(addr netip.Addr) PeerIdentity {
	id := PeerIdentity{Address: addr}
	if addr.IsValid() {
		id.OnWhisperNet = WhisperRange.Contains(addr.Unmap())
	}
	if !id.OnWhisperNet {
		const off = "off Whisper net"
		id.FQDNNote, id.OwnerNote = off, off
	}
	return id
}

// Resolve returns the identity for addr, waiting at most the budget for a first lookup.
func (c *IdentityCache) Resolve(ctx context.Context, addr netip.Addr) PeerIdentity {
	if c == nil || !addr.IsValid() {
		return Base(addr)
	}
	now := c.opt.Now()

	c.mu.Lock()
	e, ok := c.entries[addr]
	switch {
	case ok && e.inflight == nil && now.Sub(e.at) < e.ttl:
		// Fresh. No wait, no I/O.
		id := e.id
		c.mu.Unlock()
		return id
	case ok && e.inflight == nil:
		// Stale. Serve it now and refresh behind the request: once an address is known,
		// no later request ever pays for it again.
		id := e.id
		e.inflight = make(chan struct{})
		done := e.inflight
		c.mu.Unlock()
		go c.run(addr, done)
		return id
	case ok && e.inflight != nil && !e.at.IsZero():
		// A refresh is running over a previous answer: serve the previous answer.
		id := e.id
		c.mu.Unlock()
		return id
	case ok:
		// A FIRST lookup is already running for this address: join it rather than start a
		// second one.
		done := e.inflight
		c.mu.Unlock()
		return c.wait(ctx, addr, done)
	}
	// Nothing known. Start the one lookup and wait for it, up to the budget.
	e = &identityEntry{inflight: make(chan struct{})}
	c.entries[addr] = e
	c.evictLocked()
	done := e.inflight
	c.mu.Unlock()
	go c.run(addr, done)
	return c.wait(ctx, addr, done)
}

// wait blocks for the in-flight lookup, the budget, or the request's own cancellation,
// whichever comes first. On a timeout the fast half is returned with the reason said out
// loud; the lookup is NOT cancelled, so the next request finds the answer waiting.
func (c *IdentityCache) wait(ctx context.Context, addr netip.Addr, done chan struct{}) PeerIdentity {
	timer := time.NewTimer(c.opt.Budget)
	defer timer.Stop()
	select {
	case <-done:
		c.mu.Lock()
		e, ok := c.entries[addr]
		var id PeerIdentity
		if ok {
			id = e.id
		}
		c.mu.Unlock()
		if ok {
			return id
		}
		return Base(addr)
	case <-timer.C:
	case <-ctx.Done():
	}
	id := Base(addr)
	const slow = "lookup did not finish inside the budget"
	if id.OnWhisperNet {
		id.FQDNNote, id.OwnerNote = slow, slow
	}
	id.AssessNote = slow
	return id
}

// run performs the three lookups for one address and stores the result. It never takes the
// caller's context: a request that walked away must not cancel the work the NEXT request
// is about to benefit from. Its own bound is the lookups' own timeouts.
func (c *IdentityCache) run(addr netip.Addr, done chan struct{}) {
	id := Base(addr)
	ctx := context.Background()

	// The name and the owner are asked only for addresses our own plane delivers. For
	// anything else the answer would be a public registry's view of a stranger, which is
	// not what a header called Whisper-Agent-FQDN may ever carry.
	if id.OnWhisperNet {
		if c.lookup.PTR != nil {
			id.FQDN, id.FQDNNote = c.lookup.PTR(ctx, addr)
		} else {
			id.FQDNNote = "reverse-name lookup is switched off"
		}
		if c.lookup.Owner != nil {
			id.Owner, id.OwnerNote = c.lookup.Owner(ctx, addr)
		} else {
			id.OwnerNote = "owner lookup is switched off"
		}
	}
	// The graph is asked about EVERY caller, on-net or not: a request from a known-bad
	// public address is exactly the case Whisper-Assess-Band exists for.
	if c.lookup.Assess != nil {
		id.Band, id.Coverage, id.AssessNote = c.lookup.Assess(ctx, addr)
	} else {
		id.AssessNote = "graph assessment is switched off"
	}

	ttl := c.opt.TTL
	if !id.Proven() && id.Band == "" {
		// Nothing was established. Retry sooner: a control plane that was down comes back,
		// and a caller should not be anonymous for five minutes because of one bad second.
		ttl = c.opt.NegativeTTL
	}

	c.mu.Lock()
	e, ok := c.entries[addr]
	if !ok {
		e = &identityEntry{}
		c.entries[addr] = e
		c.evictLocked()
	}
	e.id, e.at, e.ttl, e.inflight = id, c.opt.Now(), ttl, nil
	c.mu.Unlock()
	close(done)
}

// evictLocked keeps the cache bounded by dropping the oldest entries. An in-flight entry is
// never dropped: something is waiting on its channel.
func (c *IdentityCache) evictLocked() {
	if len(c.entries) <= c.opt.MaxEntries {
		return
	}
	type aged struct {
		addr netip.Addr
		at   time.Time
	}
	victims := make([]aged, 0, len(c.entries))
	for addr, e := range c.entries {
		if e.inflight != nil {
			continue
		}
		victims = append(victims, aged{addr, e.at})
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].at.Before(victims[j].at) })
	for _, v := range victims {
		if len(c.entries) <= c.opt.MaxEntries {
			return
		}
		delete(c.entries, v.addr)
	}
}

// Size reports how many addresses are cached. For `serve status` and for tests.
func (c *IdentityCache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
