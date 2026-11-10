// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

// When the server offers a resolver pair, every renderer configures both
// addresses in order: the first carries the lookups, the second is where the
// OS goes when the first stops answering. With one address every render is
// byte-identical to what it always was.

const (
	pairA = "2a04:2a01:0:53::42"
	pairB = "2a04:2a01:0:53::77"
)

func renderPair(os string, h Host, ips ...string) Rendered {
	return Profile{Mode: ModeDNS53, OS: os, ResolverIPs: ips}.Render(h)
}

func TestPairResolvedDropInListsBothInOrder(t *testing.T) {
	r := renderPair("linux", Host{ResolvedActive: true}, pairA, pairB)
	got := r.Apply[0].File.Content
	if !strings.Contains(got, "\nDNS=\nDNS="+pairA+" "+pairB+"\n") {
		t.Fatalf("drop-in must list both addresses, first one first:\n%s", got)
	}
	if r.ResolverIP != pairA || len(r.ResolverIPs) != 2 || r.ResolverIPs[1] != pairB {
		t.Fatalf("rendered addresses = %q / %v", r.ResolverIP, r.ResolverIPs)
	}
	if !strings.Contains(r.Summary, pairA+" (failover "+pairB+")") {
		t.Fatalf("summary must name the failover: %q", r.Summary)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "move to the second") {
		t.Fatalf("notes must say how the pair behaves: %v", r.Notes)
	}
}

func TestPairResolvConfHasBothNameserversAndTuning(t *testing.T) {
	r := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{pairA, pairB}, SearchDomains: []string{"t1.agents.whisper.online"}}.
		Render(Host{ResolvedActive: false})
	want := "nameserver " + pairA + "\nnameserver " + pairB + "\noptions timeout:1 attempts:2\nsearch t1.agents.whisper.online\n"
	if got := r.Apply[1].File.Content; got != want {
		t.Fatalf("resolv.conf mismatch:\n--- got\n%s\n--- want\n%s", got, want)
	}
	if strings.Contains(r.Apply[1].File.Content, "rotate") {
		t.Fatal("rotate would move the steady load onto the second address")
	}
}

func TestSingleAddressRendersExactlyAsBefore(t *testing.T) {
	r := renderPair("linux", Host{ResolvedActive: false}, pairA)
	if got, want := r.Apply[1].File.Content, "nameserver "+pairA+"\n"; got != want {
		t.Fatalf("single-address resolv.conf changed: %q", got)
	}
	if r.ResolverIPs != nil {
		t.Fatalf("a single address must not set the list: %v", r.ResolverIPs)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "resolver_ips") {
		t.Fatalf("single-address JSON must not grow a resolver_ips key: %s", b)
	}
	for _, n := range r.Notes {
		if n == failoverNote {
			t.Fatal("no failover note for a single address")
		}
	}
	w := renderPair("windows", Host{}, pairA)
	if !strings.HasSuffix(w.Apply[0].Shell, "-ServerAddresses '"+pairA+"'") {
		t.Fatalf("single-address Windows step changed: %q", w.Apply[0].Shell)
	}
	d := renderPair("darwin", Host{}, pairA)
	if !strings.Contains(d.Apply[1].Shell, `-setdnsservers "$s" `+pairA+` || exit 1; done`) {
		t.Fatalf("single-address macOS step changed: %q", d.Apply[1].Shell)
	}
}

func TestPairWindowsAndMacListBoth(t *testing.T) {
	w := renderPair("windows", Host{}, pairA, pairB)
	if !strings.HasSuffix(w.Apply[0].Shell, "-ServerAddresses '"+pairA+"','"+pairB+"'") {
		t.Fatalf("Windows must set both, in order: %q", w.Apply[0].Shell)
	}
	d := renderPair("darwin", Host{}, pairA, pairB)
	if !strings.Contains(d.Apply[1].Shell, `-setdnsservers "$s" `+pairA+" "+pairB+" || exit 1; done") {
		t.Fatalf("macOS must set both, in order: %q", d.Apply[1].Shell)
	}
}

func TestPairInputIsCleanedNotSorted(t *testing.T) {
	r := renderPair("linux", Host{ResolvedActive: false}, " "+pairB+" ", "", pairA, pairB)
	want := "nameserver " + pairB + "\nnameserver " + pairA + "\noptions timeout:1 attempts:2\n"
	if got := r.Apply[1].File.Content; got != want {
		t.Fatalf("order must be kept, blanks and repeats dropped:\n%s", got)
	}
}

func TestPairDoHFallbackCarriesBoth(t *testing.T) {
	r := Profile{Mode: ModeDoH, OS: "linux", DohTemplate: "https://doh.whisper.online/tok/dns-query", ResolverIPs: []string{pairA, pairB}}.
		Render(Host{ResolvedActive: true})
	if r.Mode != ModeDNS53 || !strings.Contains(r.Apply[0].File.Content, "DNS="+pairA+" "+pairB+"\n") {
		t.Fatalf("no-forwarder fallback must configure the pair: %+v", r)
	}
}

func TestRouteCheckAcceptsEitherAddressOfThePair(t *testing.T) {
	// resolved has moved to the second address: still ours.
	ev := ResolvedEvidence{
		DNS:    "Global: " + pairA + " " + pairB + "\n",
		Domain: "Global: ~.\n",
		Status: "Global\n  Current DNS Server: " + pairB + "\n",
	}
	if rc := CheckResolvedAny([]string{pairA, pairB}, true, ev); rc.State != RouteOurs {
		t.Fatalf("current server on the failover address must verify: %+v", rc)
	}
	// With only the first address wanted, the same evidence is shadowed.
	if rc := CheckResolved(pairA, true, ev); rc.State != RouteShadowed {
		t.Fatalf("single-address check must stay strict: %+v", rc)
	}
	// A stranger as current server is still caught, and the message names both.
	ev.Status = "Global\n  Current DNS Server: 2001:db8::1\n"
	rc := CheckResolvedAny([]string{pairA, pairB}, true, ev)
	if rc.State != RouteShadowed || !strings.Contains(rc.Problems[0], pairA+" or "+pairB) {
		t.Fatalf("a foreign current server must be shadowed: %+v", rc)
	}
	if rc.Want != pairA || len(rc.Accept) != 2 {
		t.Fatalf("Want/Accept = %q %v", rc.Want, rc.Accept)
	}
}

func TestResolvConfRouteCheckAcceptsThePair(t *testing.T) {
	if rc := CheckResolvConfAny([]string{pairA, pairB}, "nameserver "+pairB+"\n"); rc.State != RouteOurs {
		t.Fatalf("first nameserver from the pair must verify: %+v", rc)
	}
	if rc := CheckResolvConfAny([]string{pairA, pairB}, "nameserver 2001:db8::1\nnameserver "+pairA+"\n"); rc.State != RouteShadowed {
		t.Fatalf("a foreign first nameserver must be shadowed: %+v", rc)
	}
}
