// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// stubZoneOf replaces the DNS read fleetZone makes with a table, and records what was asked.
func stubZoneOf(t *testing.T, zones map[string]string) *[]string {
	t.Helper()
	var mu sync.Mutex
	asked := []string{}
	prev := zoneOfName
	zoneOfName = func(_ context.Context, name string) string {
		mu.Lock()
		asked = append(asked, name)
		mu.Unlock()
		return zones[name]
	}
	t.Cleanup(func() { zoneOfName = prev })
	return &asked
}

// TestFleetZone_TakesTheZoneDNSNamesForAHostedFleet. A hosted name is
// <agent>.<tenant>.agents.whisper.online, and the tenant label is not a zone cut: the SOA for
// each tenant subtree is the apex's. Each distinct parent is asked once, case and trailing dot
// aside, and the apex is what is dated.
func TestFleetZone_TakesTheZoneDNSNamesForAHostedFleet(t *testing.T) {
	asked := stubZoneOf(t, map[string]string{
		"ted67d6.agents.whisper.online": "agents.whisper.online",
		"t9ab.agents.whisper.online":    "agents.whisper.online",
	})
	peers := []whalePeer{
		{Name: "a", FQDN: "a141a459a.tED67D6.agents.whisper.online."},
		{Name: "b", FQDN: "b2b2b2b2b.tED67D6.agents.whisper.online"},
		{Name: "c", FQDN: "c3c3c3c3c.t9ab.agents.whisper.online"},
	}
	if got := fleetZone(t.Context(), peers); got != "agents.whisper.online" {
		t.Fatalf("fleetZone = %q, want the apex agents.whisper.online", got)
	}
	if len(*asked) != 2 {
		t.Fatalf("asked %v, want each distinct parent once", *asked)
	}
}

// TestFleetZone_ABYODFleetDatesItsOwnDomainNotTheTLD is what a live check of v0.268.1 caught.
// A BYOD agent is <agent>.<domain>, so the parent of its "tenant label" is the TLD, and `whale status`
// printed `app snapshot age` from the registry's nameservers with a serial that is not a time. The
// zone is the one DNS names: the customer's domain.
func TestFleetZone_ABYODFleetDatesItsOwnDomainNotTheTLD(t *testing.T) {
	stubZoneOf(t, map[string]string{"example.com": "example.com"})
	peers := []whalePeer{{Name: "agent-a9a1", FQDN: "a9a1.example.com"}}
	if got := fleetZone(t.Context(), peers); got != "example.com" {
		t.Fatalf("fleetZone = %q, want the customer's own zone example.com", got)
	}
	// A BYOD fleet one level further down sits in whichever zone DNS says, not one guessed from labels.
	stubZoneOf(t, map[string]string{"acme.example.com": "example.com"})
	peers = []whalePeer{{Name: "a", FQDN: "db-01.acme.example.com."}, {Name: "b", FQDN: "db-02.acme.example.com."}}
	if got := fleetZone(t.Context(), peers); got != "example.com" {
		t.Fatalf("fleetZone = %q, want example.com", got)
	}
}

// TestFleetZone_AMixedFleetYieldsNothing. THE reason this returns a zone rather than a
// guess: dating one zone when half the fleet lives in another would put a confident,
// irrelevant sentence on the screen. Saying nothing is the honest answer, and so it is when
// DNS cannot say which zone a name is in.
func TestFleetZone_AMixedFleetYieldsNothing(t *testing.T) {
	stubZoneOf(t, map[string]string{"t1.agents.whisper.online": "agents.whisper.online", "acme.example.com": "example.com"})
	peers := []whalePeer{
		{Name: "a", FQDN: "a.t1.agents.whisper.online."},
		{Name: "b", FQDN: "db-02.acme.example.com."},
	}
	if got := fleetZone(t.Context(), peers); got != "" {
		t.Fatalf("a mixed fleet must yield no zone, got %q", got)
	}
	if got := fleetZone(t.Context(), nil); got != "" {
		t.Fatalf("no peers must yield no zone, got %q", got)
	}
	// A peer with no name in DNS contributes nothing rather than breaking the read.
	if got := fleetZone(t.Context(), []whalePeer{{Name: "a"}, {Name: "b", FQDN: "x.t1.agents.whisper.online"}}); got != "agents.whisper.online" {
		t.Fatalf("a nameless peer must not veto the zone, got %q", got)
	}
	// DNS could not say: no zone, and no line.
	if got := fleetZone(t.Context(), []whalePeer{{Name: "c", FQDN: "x.unknown.example"}}); got != "" {
		t.Fatalf("an unanswered zone lookup must yield no zone, got %q", got)
	}
}

// TestFleetZone_ALapsedBYODDomainDatesNothing: a name that does not exist is answered with the SOA of
// the closest zone that does, and for a BYOD domain that lapsed, is on hold or was never delegated that
// is the TLD, the very line the zone discovery exists to stop. A public suffix is never a fleet's zone.
func TestFleetZone_ALapsedBYODDomainDatesNothing(t *testing.T) {
	stubZoneOf(t, map[string]string{"lapsed.app": "app", "never.example": "example", "x.co.uk": "co.uk"})
	for _, fqdn := range []string{"a9a1.lapsed.app", "a9a1.never.example", "a9a1.x.co.uk"} {
		if got := fleetZone(t.Context(), []whalePeer{{Name: "a", FQDN: fqdn}}); got != "" {
			t.Fatalf("%s dated %q, a public suffix", fqdn, got)
		}
	}
}

// TestFleetZone_AnInternationalisedNameIsAskedInItsASCIIForm: DNS carries A-labels, and a U-label
// sent raw gets NXDOMAIN, which would date the TLD.
func TestFleetZone_AnInternationalisedNameIsAskedInItsASCIIForm(t *testing.T) {
	asked := stubZoneOf(t, map[string]string{"xn--bcher-kva.example.com": "example.com"})
	if got := fleetZone(t.Context(), []whalePeer{{Name: "a", FQDN: "a9a1.bücher.example.com"}}); got != "example.com" {
		t.Fatalf("fleetZone = %q, want example.com", got)
	}
	if len(*asked) != 1 || (*asked)[0] != "xn--bcher-kva.example.com" {
		t.Fatalf("asked %v, want the A-label", *asked)
	}
}

// TestFleetZone_ALargeFleetAsksABoundedNumberOfParents: per-agent tenancy can give every agent a
// tenant label of its own, and a footnote must not cost a query per agent. Past the cap the
// parents not asked must still sit inside the zone the asked ones agree on.
func TestFleetZone_ALargeFleetAsksABoundedNumberOfParents(t *testing.T) {
	zones := map[string]string{}
	var peers []whalePeer
	for i := 0; i < 30; i++ {
		parent := fmt.Sprintf("t%02d.agents.whisper.online", i)
		zones[parent] = "agents.whisper.online"
		peers = append(peers, whalePeer{Name: fmt.Sprintf("n%d", i), FQDN: "a." + parent})
	}
	asked := stubZoneOf(t, zones)
	if got := fleetZone(t.Context(), peers); got != "agents.whisper.online" {
		t.Fatalf("fleetZone = %q, want agents.whisper.online", got)
	}
	if len(*asked) != maxZoneProbes {
		t.Fatalf("asked %d parents, want at most %d", len(*asked), maxZoneProbes)
	}
	// One agent outside the zone, past the cap, still vetoes the line.
	peers = append(peers, whalePeer{Name: "x", FQDN: "zz.zz.example.org"})
	stubZoneOf(t, zones)
	if got := fleetZone(t.Context(), peers); got != "" {
		t.Fatalf("a peer outside the zone the others share must veto the line, got %q", got)
	}
}

// TestZoneFromSOAReply_ReadsTheZoneCut pins how the reply to an SOA query names a zone: the SOA
// in the answer at an apex, the authority SOA of a NODATA or NXDOMAIN reply below one, and
// nothing for an alias, a failure, or an SOA that is not the name's own or a parent's.
func TestZoneFromSOAReply_ReadsTheZoneCut(t *testing.T) {
	soa := func(owner string) dns.RR {
		rr, err := dns.NewRR(owner + " 300 IN SOA ns1.whisper.online. hostmaster.whisper.online. 1794761491 7200 3600 1209600 300")
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	cname, _ := dns.NewRR("www.example.com. 300 IN CNAME a9a1.example.com.")
	cases := []struct {
		name   string
		q      string
		rcode  int
		answer []dns.RR
		ns     []dns.RR
		want   string
	}{
		{"apex", "example.com", dns.RcodeSuccess, []dns.RR{soa("example.com.")}, nil, "example.com"},
		{"nodata below the apex", "t332b.agents.whisper.online", dns.RcodeSuccess, nil, []dns.RR{soa("agents.whisper.online.")}, "agents.whisper.online"},
		{"nxdomain below the apex", "nosuch.agents.whisper.online.", dns.RcodeNameError, nil, []dns.RR{soa("agents.whisper.online.")}, "agents.whisper.online"},
		{"case is not a difference", "T332B.Agents.Whisper.Online", dns.RcodeSuccess, nil, []dns.RR{soa("agents.whisper.online.")}, "agents.whisper.online"},
		{"nxdomain for a lapsed domain names its tld", "lapsed.app", dns.RcodeNameError, nil, []dns.RR{soa("app.")}, "app"},
		{"an alias says nothing about its own zone", "www.example.com", dns.RcodeSuccess, []dns.RR{cname, soa("example.com.")}, nil, ""},
		{"servfail", "example.com", dns.RcodeServerFailure, nil, nil, ""},
		{"an soa that is not a parent", "example.com", dns.RcodeSuccess, nil, []dns.RR{soa("example.org.")}, ""},
		{"no soa at all", "example.com", dns.RcodeSuccess, nil, nil, ""},
	}
	for _, tc := range cases {
		m := new(dns.Msg)
		m.Rcode, m.Answer, m.Ns = tc.rcode, tc.answer, tc.ns
		if got := zoneFromSOAReply(m, tc.q); got != tc.want {
			t.Fatalf("%s: zoneFromSOAReply = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := zoneFromSOAReply(nil, "example.com"); got != "" {
		t.Fatalf("a nil reply named zone %q", got)
	}
}

// TestSoaAgeFrom_OnlyAnAuthoritativeAnswerIsANodesCopy: a server that also recurses can hand back a
// cached SOA, which is not its own copy of the zone; a read cut short by our own budget says nothing
// about the server and gives no row at all.
func TestSoaAgeFrom_OnlyAnAuthoritativeAnswerIsANodesCopy(t *testing.T) {
	now := time.Unix(time.Now().Unix(), 0)
	serial := uint32(now.Unix() - 120)
	authoritative := true
	var mu sync.Mutex
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no local UDP: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		mu.Lock()
		m.Authoritative = authoritative
		mu.Unlock()
		rr, _ := dns.NewRR(fmt.Sprintf("example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. %d 7200 3600 1209600 300", serial))
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().String()

	if a := soaAgeFrom(t.Context(), addr, "example.com", now); !a.Known || a.Age != 2*time.Minute {
		t.Fatalf("an authoritative answer reads %+v, want dated 2m", a)
	}
	mu.Lock()
	authoritative = false
	mu.Unlock()
	if a := soaAgeFrom(t.Context(), addr, "example.com", now); a.Known || !strings.Contains(a.Note, "without authority") {
		t.Fatalf("a non-authoritative answer reads %+v, want it refused as the node's copy", a)
	}
	done, cancel := context.WithCancel(t.Context())
	cancel()
	if a := soaAgeFrom(done, addr, "example.com", now); a.Server != "" {
		t.Fatalf("a read our own budget cut short reads %+v, want no row", a)
	}
}

// TestReadFleetSnapshot_NoZoneIsNoQueryAndNoLine: when the fleet shares no zone there is nothing
// to date, so no nameserver is asked and the view carries no line.
func TestReadFleetSnapshot_NoZoneIsNoQueryAndNoLine(t *testing.T) {
	stubZoneOf(t, map[string]string{})
	zone, ages := readFleetSnapshot(t.Context(), []whalePeer{{Name: "a", FQDN: "x.nowhere.example"}}, time.Now())
	if zone != "" || ages != nil {
		t.Fatalf("no zone must read nothing, got %q %+v", zone, ages)
	}
}

// TestWhaleStatus_AFleetOfOneSaysAnAgentKeySeesItselfAlone: an agent's own key lists that agent
// and nothing else, by design (the plane confines an agent key to its own rows). A live check read
// `whale status` with each node's own key and got a fleet of one; the screen says why, so the
// reader does not go looking for missing peers. A fleet of two does not get the note.
func TestWhaleStatus_AFleetOfOneSaysAnAgentKeySeesItselfAlone(t *testing.T) {
	whaleTestIsolation(t)
	const self = "2a04:2a01:9::a1"
	rows := `["agent",{"agent":"agent-a9a1","address":"` + self + `","state":"active"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` + rows + `]}}`))
	}))
	t.Cleanup(srv.Close)
	agentFile := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(agentFile, []byte(self), 0o600); err != nil {
		t.Fatal(err)
	}
	g.key = "whisper_live_test"
	g.controlURL = srv.URL + "/api/query"

	view := buildWhaleStatus(context.Background(), agentFile, true, false)
	_, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	if !strings.Contains(stderr, "only this node is listed") || !strings.Contains(stderr, "by design") {
		t.Fatalf("a fleet of one must say why it is one:\n%s", stderr)
	}

	rows += `,["agent",{"agent":"agent-a9b2","address":"2a04:2a01:9::b2","state":"active"}]`
	view = buildWhaleStatus(context.Background(), agentFile, true, false)
	for _, n := range view.Notes {
		if n == whaleFleetOfOneNote {
			t.Fatalf("a fleet of two carries the fleet-of-one note: %q", view.Notes)
		}
	}
}

// TestWhaleStatus_RendersTheSnapshotLine. THE anti-unreachable gate. A SnapshotAge that
// nothing renders is the defect this repo ships most often, so this drives the real
// renderer and asserts the sentence reached the screen. Remove the block from
// renderWhaleStatus and this fails.
func TestWhaleStatus_RendersTheSnapshotLine(t *testing.T) {
	whaleTestIsolation(t)
	now := time.Unix(1_788_239_069, 0)
	ages := []whale.SnapshotAge{
		whale.AgeOf("ns1.whisper.online", uint32(now.Unix()-120), now),
		whale.AgeOf("ns2.whisper.online", uint32(now.Unix()-120), now),
	}
	view := whaleStatusView{
		Self:         whaleSelf{Host: "h", Address: "2a04:2a01:1::1", Connection: "connected"},
		PathNote:     whale.PathNote(),
		Snapshot:     ages,
		SnapshotNote: whale.SnapshotNote("agents.whisper.online", ages),
	}
	// whaleNote writes to stderr, the same channel the path footnote uses.
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, true, false) })
	for _, want := range []string{"agents.whisper.online snapshot age", "ns1.whisper.online 2m", "ns2.whisper.online 2m"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("the snapshot line must carry %q:\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
		}
	}
}

// TestWhaleStatus_TheDivergenceWarningReachesTheScreen: the agreeing case is the one that
// prints all day, so a test that only covered it would pass on a renderer that dropped the
// warning. This is the state the line exists for and it must be impossible to miss.
func TestWhaleStatus_TheDivergenceWarningReachesTheScreen(t *testing.T) {
	whaleTestIsolation(t)
	now := time.Unix(1_788_239_069, 0)
	ages := []whale.SnapshotAge{
		whale.AgeOf("ns1.whisper.online", uint32(now.Unix()-60), now),
		whale.AgeOf("ns2.whisper.online", uint32(now.Unix()-400_000), now),
	}
	view := whaleStatusView{
		Self:         whaleSelf{Host: "h", Connection: "not connected"},
		PathNote:     whale.PathNote(),
		Snapshot:     ages,
		SnapshotNote: whale.SnapshotNote("agents.whisper.online", ages),
	}
	_, stderr := captureStd(t, func() { renderWhaleStatus(view, true, false, false) })
	if !strings.Contains(stderr, "THE NODES DISAGREE") {
		t.Fatalf("a divergent pair must be warned about on screen:\n%s", stderr)
	}
	if !strings.Contains(stderr, "unreliable until") {
		t.Fatalf("the consequence must reach the screen, not just the fact:\n%s", stderr)
	}
}

// TestWhaleStatus_NoSnapshotPrintsNoLine: the control. A run that could read nothing must
// not leave an empty or half-formed footnote behind, and it must not warn about a fleet it
// never measured.
func TestWhaleStatus_NoSnapshotPrintsNoLine(t *testing.T) {
	whaleTestIsolation(t)
	view := whaleStatusView{
		Self:     whaleSelf{Host: "h", Connection: "not connected"},
		PathNote: whale.PathNote(),
	}
	stdout, stderr := captureStd(t, func() { renderWhaleStatus(view, true, false, false) })
	if strings.Contains(stdout+stderr, "snapshot age") {
		t.Fatalf("nothing was read, so no snapshot line may be printed:\n%s\n%s", stdout, stderr)
	}
}

// TestReadZoneSnapshot_AnEmptyZoneIsNotAQuery: the guard in front of the network. `whale
// status` runs constantly, and a node with no name in DNS must cost zero DNS traffic
// rather than a lookup for the empty name.
func TestReadZoneSnapshot_AnEmptyZoneIsNotAQuery(t *testing.T) {
	if got := readZoneSnapshot(t.Context(), "", time.Now()); got != nil {
		t.Fatalf("an empty zone must read nothing, got %+v", got)
	}
	if got := readZoneSnapshot(t.Context(), "   ", time.Now()); got != nil {
		t.Fatalf("a blank zone must read nothing, got %+v", got)
	}
}
