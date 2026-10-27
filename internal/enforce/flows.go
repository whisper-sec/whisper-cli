// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"sync"
	"time"
)

// flows.go is the one piece of state the translator keeps, and the reason it needs any.
//
// A reply from inside the NAT64 prefix can belong to two different sockets in the namespace.
// A program that dialled a v4 literal went through the translator, so its reply has to be
// turned back into v4. A program that resolved a v4-only name got a DNS64 AAAA inside the same
// prefix and dialled it natively over v6, so its reply has to stay v6. The packets look the
// same on the wire. What tells them apart is which socket sent the first packet of the flow,
// so outbound packets claim their flow for a family and inbound packets look the claim up.
//
// The kernel picks ephemeral ports per family, so a v4 socket and a v6 socket can land on the
// same five-tuple once both are mapped into the prefix. The first claim wins; the second flow
// is refused at its first packet rather than having its replies delivered to the wrong
// socket. Entries expire on the idle timeouts the NAT RFCs set for exactly this job: two
// hours and four minutes for TCP (RFC 5382, requirement 5), five minutes for UDP (RFC 4787,
// requirement 5), one minute for ICMP echo. The table is bounded; when it is full of live
// flows a new translated flow is refused, never allowed to evict a live one.

const (
	famV4 = 4
	famV6 = 6

	maxFlows = 1 << 16
)

type flowKey struct {
	proto  uint8   // protoTCP, protoUDP, or protoICMP for an echo (keyed on its identifier)
	lport  uint16  // the namespace side's port, or the echo identifier
	remote [4]byte // the v4 address embedded in the prefix
	rport  uint16  // the far side's port; 0 for an echo
}

type flowEntry struct {
	fam  uint8
	seen time.Time // monotonic: a wall-clock jump neither keeps a flow alive nor kills it
}

type flowTable struct {
	mu  sync.Mutex
	m   map[flowKey]flowEntry
	now func() time.Time
	max int
}

func newFlowTable(now func() time.Time) *flowTable {
	if now == nil {
		now = time.Now
	}
	return &flowTable{m: make(map[flowKey]flowEntry), now: now, max: maxFlows}
}

func idleTimeout(proto uint8) time.Duration {
	switch proto {
	case protoTCP:
		return 2*time.Hour + 4*time.Minute
	case protoUDP:
		return 5 * time.Minute
	}
	return time.Minute
}

// claim records an outbound packet of family fam on k. It reports false when a live flow of
// the other family holds k, or when the table is full of live flows.
func (t *flowTable) claim(k flowKey, fam uint8) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if e, ok := t.m[k]; ok {
		if now.Sub(e.seen) <= idleTimeout(k.proto) && e.fam != fam {
			return false
		}
		t.m[k] = flowEntry{fam: fam, seen: now}
		return true
	}
	if len(t.m) >= t.max {
		t.sweepLocked(now)
		if len(t.m) >= t.max {
			return false
		}
	}
	t.m[k] = flowEntry{fam: fam, seen: now}
	return true
}

// lookup returns the family that claimed k, refreshing it, or ok=false when nothing live has.
func (t *flowTable) lookup(k flowKey) (uint8, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[k]
	if !ok {
		return 0, false
	}
	now := t.now()
	if now.Sub(e.seen) > idleTimeout(k.proto) {
		delete(t.m, k)
		return 0, false
	}
	e.seen = now
	t.m[k] = e
	return e.fam, true
}

func (t *flowTable) sweepLocked(now time.Time) {
	for k, e := range t.m {
		if now.Sub(e.seen) > idleTimeout(k.proto) {
			delete(t.m, k)
		}
	}
}

func (t *flowTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}
