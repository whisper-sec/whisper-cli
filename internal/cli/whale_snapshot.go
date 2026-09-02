// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_snapshot.go reads how stale each authoritative node's copy of the agent zone is,
// which is finding I-03's mitigation and the line `whisper whale ssh` shipped without.
//
// It asks EACH nameserver directly rather than asking a recursive resolver once. That is
// the whole point: a recursive answer tells you what some node said, and the question is
// whether the nodes AGREE. Two boxes serving different snapshots is the state that lets a
// principal you removed keep logging in to whichever one is behind, and it is invisible
// through a cache.
//
// Every leg is fail-open and bounded. This runs on `whale status`, a verb people run all
// day, so it gets its own short budget, it runs alongside the rest rather than in front of
// it, and any failure costs the line and nothing else. A status screen that hangs because
// a nameserver is slow would be a worse bug than the one this reports.

// snapshotBudget bounds the whole read: the NS lookup plus every per-node SOA query. It is
// deliberately short - this is a footnote on a screen, not the screen.
const snapshotBudget = 2500 * time.Millisecond

// readZoneSnapshot returns one SnapshotAge per authoritative nameserver of zone, or nil if
// the zone cannot be determined or nothing answered inside the budget.
func readZoneSnapshot(cx context.Context, zone string, now time.Time) []whale.SnapshotAge {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return nil
	}
	cx, cancel := context.WithTimeout(cx, snapshotBudget)
	defer cancel()

	// The NS set comes from an ordinary recursive lookup: which nodes are authoritative is
	// not the thing under suspicion, only what each of them is currently serving.
	servers := authoritativeNamesFor(cx, zone)
	if len(servers) == 0 {
		return nil
	}
	out := make([]whale.SnapshotAge, len(servers))
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func(i int, srv string) {
			defer wg.Done()
			out[i] = soaAgeFrom(cx, srv, zone, now)
		}(i, srv)
	}
	wg.Wait()

	kept := out[:0]
	for _, a := range out {
		if a.Server != "" {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// authoritativeNamesFor returns the zone's NS names, shortest first so the list a person
// reads is stable between runs rather than in whatever order the answer arrived.
func authoritativeNamesFor(cx context.Context, zone string) []string {
	res := trustverify.NewNetResolver("")
	msg, err := res.Query(cx, dns.Fqdn(zone), dns.TypeNS)
	if err != nil || msg == nil {
		return nil
	}
	names := make([]string, 0, 4)
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok && ns.Ns != "" {
			names = append(names, trimDot(ns.Ns))
		}
	}
	sortStringsStable(names)
	return names
}

// soaAgeFrom asks ONE nameserver for the zone's SOA and dates it. A server that does not
// answer comes back as a row with its own reason, never as a silently missing node: a
// nameserver that has stopped answering is a finding, and dropping it would hide it.
func soaAgeFrom(cx context.Context, server, zone string, now time.Time) whale.SnapshotAge {
	res := trustverify.NewNetResolver(server)
	msg, err := res.Query(cx, dns.Fqdn(zone), dns.TypeSOA)
	if err != nil || msg == nil {
		return whale.SnapshotAge{Server: server, Note: "did not answer for the zone's SOA"}
	}
	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return whale.AgeOf(server, soa.Serial, now)
		}
	}
	return whale.SnapshotAge{Server: server, Note: "answered without an SOA record"}
}

// sortStringsStable sorts in place, shortest-then-lexicographic, so ns1 sorts before ns2
// and both before a longer name.
func sortStringsStable(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && lessName(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func lessName(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}
