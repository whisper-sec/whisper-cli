// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_snapshot.go reads how stale each authoritative node's copy of the agent zone is,
// which is the staleness signal `whisper whale ssh` shipped without.
//
// It asks EACH nameserver directly rather than asking a recursive resolver once. That is
// the whole point: a recursive answer tells you what some node said, and the question is
// whether the nodes AGREE. Two boxes serving different snapshots is invisible through a
// cache, which is why each is asked directly.
//
// Every leg is fail-open and bounded. This runs on `whale status`, a verb people run all
// day, so it gets its own short budget, it runs alongside the rest rather than in front of
// it, and any failure costs the line and nothing else. A status screen that hangs because
// a nameserver is slow would be a worse bug than the one this reports.

// snapshotBudget bounds the whole read: the NS lookup plus every per-node SOA query. It is
// deliberately short - this is a footnote on a screen, not the screen.
const snapshotBudget = 2500 * time.Millisecond

// readFleetSnapshot finds the zone the fleet's names live in and dates each authoritative
// node's copy of it, all inside one snapshotBudget. It returns no zone, and no ages, when the
// fleet shares no single zone or DNS could not say which zone that is.
func readFleetSnapshot(cx context.Context, peers []whalePeer, now time.Time) (string, []whale.SnapshotAge) {
	cx, cancel := context.WithTimeout(cx, snapshotBudget)
	defer cancel()
	zone := fleetZone(cx, peers)
	if zone == "" {
		return "", nil
	}
	return zone, readZoneSnapshot(cx, zone, now)
}

// maxZoneProbes bounds how many distinct parent names fleetZone asks DNS about. Per-agent
// tenancy can give every agent a tenant label of its own, and a footnote must not cost a
// query per agent; the parents past the cap are held to the zone the asked ones agree on.
const maxZoneProbes = 8

// fleetZone is the DNS zone the fleet's names actually live in, which is where the SOA and
// the signing are. It is read from DNS, not from the shape of the names: a hosted name is
// <agent>.<tenant>.agents.whisper.online and its zone is agents.whisper.online, but a BYOD
// name is <agent>.<domain>, whose zone is the customer's domain itself, and taking the parent
// of a "tenant label" there dated the TLD (`app snapshot age` from the registry's
// nameservers, for a fleet under a .app domain). So each distinct parent of an agent name is
// asked for its SOA, and the owner of the SOA that comes back is the zone it sits in.
//
// Every parent asked must name the same zone, and every parent not asked must sit inside it;
// otherwise there is no zone this line describes for everybody, and it says nothing, as it
// does when DNS cannot answer.
func fleetZone(cx context.Context, peers []whalePeer) string {
	parents := map[string]bool{}
	for _, p := range peers {
		name, err := idna.Lookup.ToASCII(trimDot(strings.TrimSpace(p.FQDN)))
		if err != nil {
			continue // a name DNS cannot carry says nothing about a zone
		}
		if i := strings.IndexByte(name, '.'); i > 0 && i+1 < len(name) {
			parents[strings.ToLower(name[i+1:])] = true
		}
	}
	if len(parents) == 0 {
		return ""
	}
	sorted := make([]string, 0, len(parents))
	for p := range parents {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	asked := sorted
	if len(asked) > maxZoneProbes {
		asked = asked[:maxZoneProbes]
	}
	zones := make([]string, len(asked))
	var wg sync.WaitGroup
	for i, parent := range asked {
		wg.Add(1)
		go func(i int, parent string) {
			defer wg.Done()
			zones[i] = zoneOfName(cx, parent)
		}(i, parent)
	}
	wg.Wait()
	zone := zones[0]
	for _, z := range zones {
		if z == "" || z != zone {
			return ""
		}
	}
	// A name that does not exist is answered with the SOA of the closest zone that does, which for a
	// BYOD domain that has lapsed, is on hold or was never delegated is its TLD: the registry's zone,
	// which says nothing about this fleet. A public suffix is never a fleet's zone.
	if !strings.Contains(zone, ".") {
		return ""
	}
	if suffix, _ := publicsuffix.PublicSuffix(zone); suffix == zone {
		return ""
	}
	for _, parent := range sorted {
		if !dns.IsSubDomain(dns.Fqdn(zone), dns.Fqdn(parent)) {
			return ""
		}
	}
	return zone
}

// zoneOfName asks a recursive resolver for name's SOA and returns the zone it sits in, or ""
// when that cannot be said. It is a package var so a test drives fleetZone without the network.
var zoneOfName = func(cx context.Context, name string) string {
	msg, err := trustverify.NewNetResolver("").Query(cx, dns.Fqdn(name), dns.TypeSOA)
	if err != nil {
		return ""
	}
	return zoneFromSOAReply(msg, name)
}

// zoneFromSOAReply reads the zone a name sits in from the reply to an SOA query for it: the SOA
// in the answer when the name is the apex, or the one in the authority section of a NODATA or
// NXDOMAIN reply. A name that is an alias says nothing about its own zone (the resolver follows
// the CNAME to the target's), and an SOA whose owner is not the name or one of its parents is
// not the name's zone, so both answer nothing.
func zoneFromSOAReply(msg *dns.Msg, name string) string {
	if msg == nil || (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) {
		return ""
	}
	fq := dns.Fqdn(name)
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			return ""
		}
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				owner := strings.ToLower(soa.Hdr.Name)
				if !dns.IsSubDomain(owner, strings.ToLower(fq)) {
					return ""
				}
				return trimDot(owner)
			}
		}
	}
	return ""
}

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
	if (err != nil || msg == nil) && cx.Err() != nil {
		// Our own budget ran out, which says nothing about the server: no row rather than a false one.
		return whale.SnapshotAge{}
	}
	if err != nil || msg == nil {
		return whale.SnapshotAge{Server: server, Note: "did not answer for the zone's SOA"}
	}
	if !msg.Authoritative {
		// A server that also recurses can hand back a cached SOA; that is not its own copy of the zone.
		return whale.SnapshotAge{Server: server, Note: "answered for the zone's SOA without authority, so the answer is not its own copy"}
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
