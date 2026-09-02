// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeProber answers from a table so the whole report can be exercised with no network.
type fakeProber struct {
	v6, v4  map[string]string // host -> address
	lookErr map[string]error
	dnsErr  map[string]error
	tcpErr  map[string]error
	rtt     time.Duration
}

func (f *fakeProber) Lookup(_ context.Context, host string) ([]netip.Addr, []netip.Addr, error) {
	if err, ok := f.lookErr[host]; ok {
		return nil, nil, err
	}
	var v6, v4 []netip.Addr
	if s, ok := f.v6[host]; ok {
		v6 = append(v6, netip.MustParseAddr(s))
	}
	if s, ok := f.v4[host]; ok {
		v4 = append(v4, netip.MustParseAddr(s))
	}
	return v6, v4, nil
}

func (f *fakeProber) DNSUDP(_ context.Context, server netip.Addr) (time.Duration, error) {
	if err, ok := f.dnsErr[server.String()]; ok {
		return 0, err
	}
	return f.rtt, nil
}

func (f *fakeProber) TCP(_ context.Context, server netip.Addr, _ int) (time.Duration, error) {
	if err, ok := f.tcpErr[server.String()]; ok {
		return 0, err
	}
	return f.rtt, nil
}

func healthyProber() *fakeProber {
	return &fakeProber{
		v6:      map[string]string{"ns1.example": "2001:db8::1", "ns2.example": "2001:db8::2"},
		v4:      map[string]string{"ns1.example": "198.51.100.1", "ns2.example": "198.51.100.2"},
		lookErr: map[string]error{},
		dnsErr:  map[string]error{},
		tcpErr:  map[string]error{},
		rtt:     20 * time.Millisecond,
	}
}

// TestNetcheck_ReportsEveryBoxAndFamily: the report is per box AND per family, because a
// single "reachable" boolean is exactly what let a v4-only host conclude the fleet was
// down.
func TestNetcheck_ReportsEveryBoxAndFamily(t *testing.T) {
	rep := Netcheck(context.Background(), []string{"ns1.example", "ns2.example"}, healthyProber())
	if len(rep.Boxes) != 2 {
		t.Fatalf("got %d boxes, want 2", len(rep.Boxes))
	}
	if !rep.IPv6 || !rep.IPv4 || !rep.UDP || !rep.OK() {
		t.Fatalf("a fully healthy fleet reported %+v", rep)
	}
	for _, b := range rep.Boxes {
		if !b.IPv6.DNSUDP || !b.IPv6.TCP443 || !b.IPv4.DNSUDP || !b.IPv4.TCP443 {
			t.Fatalf("box %s did not report both legs on both families: %+v", b.Host, b)
		}
		if b.IPv6.Addr == "" || b.IPv4.Addr == "" {
			t.Fatalf("box %s reported a result with no address", b.Host)
		}
	}
	if rep.Anchor == "" || rep.AnchorMs <= 0 {
		t.Fatalf("no anchor box was chosen from a healthy fleet: %+v", rep)
	}
	if rep.MTU.Client == rep.MTU.Server {
		t.Fatalf("the two MTUs came back equal: %+v", rep.MTU)
	}
	if rep.PathNote == "" || strings.Contains(strings.ToLower(rep.PathNote), "direct path exists") {
		t.Fatalf("the path note must be present and must not imply a direct path: %q", rep.PathNote)
	}
}

// TestNetcheck_AV6OnlyOutageIsVisibleAsSuch is the case that keeps being misdiagnosed: v6
// is dead, v4 is fine. The report has to say exactly that, per box, with a reason.
func TestNetcheck_AV6OnlyOutageIsVisibleAsSuch(t *testing.T) {
	p := healthyProber()
	for _, a := range []string{"2001:db8::1", "2001:db8::2"} {
		p.dnsErr[a] = errors.New("dial udp: connect: network is unreachable")
		p.tcpErr[a] = errors.New("dial tcp: connect: network is unreachable")
	}
	rep := Netcheck(context.Background(), []string{"ns1.example", "ns2.example"}, p)
	if rep.IPv6 {
		t.Fatal("IPv6 reported as working while every v6 probe failed")
	}
	if !rep.IPv4 || !rep.OK() {
		t.Fatal("IPv4 was healthy but the report did not say so")
	}
	for _, b := range rep.Boxes {
		if b.IPv6.Note == "" {
			t.Fatalf("box %s reported a v6 failure with no reason; a false with no note is the "+
				"shape that reads as 'not applicable'", b.Host)
		}
		if !b.IPv6.Present {
			t.Fatalf("box %s published a v6 address but the report says it did not", b.Host)
		}
	}
}

// TestNetcheck_AResolutionFailureIsAWarningNotASilentZero: we could not ask is a
// different finding from we asked and it said no, and the report must never collapse the
// first into the second.
func TestNetcheck_AResolutionFailureIsAWarningNotASilentZero(t *testing.T) {
	p := healthyProber()
	p.lookErr["ns2.example"] = errors.New("no such host")
	rep := Netcheck(context.Background(), []string{"ns1.example", "ns2.example"}, p)
	if len(rep.Warnings) == 0 {
		t.Fatal("an unresolvable box produced no warning")
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "ns2.example") && strings.Contains(w, "resolve") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings %v do not name the box we could not resolve", rep.Warnings)
	}
	for _, b := range rep.Boxes {
		if b.Host == "ns2.example" && b.IPv6.Note == "" {
			t.Fatal("the unresolvable box reported no note on its family rows")
		}
	}
	if !rep.OK() {
		t.Fatal("one box was healthy, so the run is not a total failure")
	}
}

// TestNetcheck_ATotalOutageIsNotAnEmptyTable: nothing answered has to be a stated
// finding and a non-OK report, not a table of blanks.
func TestNetcheck_ATotalOutageIsNotAnEmptyTable(t *testing.T) {
	p := healthyProber()
	for _, a := range []string{"2001:db8::1", "2001:db8::2", "198.51.100.1", "198.51.100.2"} {
		p.dnsErr[a] = errors.New("i/o timeout")
		p.tcpErr[a] = errors.New("i/o timeout")
	}
	rep := Netcheck(context.Background(), []string{"ns1.example", "ns2.example"}, p)
	if rep.OK() {
		t.Fatal("OK() is true although nothing answered")
	}
	joined := strings.Join(rep.Warnings, " | ")
	if !strings.Contains(joined, "no box answered") {
		t.Fatalf("a total outage produced warnings %q, which do not say so", joined)
	}
}

// TestNetcheck_AnchorIsTheFastestBoxThatActuallyAnswered.
func TestNetcheck_AnchorIsTheFastestBoxThatActuallyAnswered(t *testing.T) {
	p := healthyProber()
	// Make ns1 dark entirely; ns2 must become the anchor.
	p.dnsErr["2001:db8::1"] = errors.New("i/o timeout")
	p.tcpErr["2001:db8::1"] = errors.New("i/o timeout")
	p.dnsErr["198.51.100.1"] = errors.New("i/o timeout")
	p.tcpErr["198.51.100.1"] = errors.New("i/o timeout")
	rep := Netcheck(context.Background(), []string{"ns1.example", "ns2.example"}, p)
	if rep.Anchor != "ns2.example" {
		t.Fatalf("anchor = %q, want the only box that answered", rep.Anchor)
	}
}

// TestPlain_ShortensATimeout keeps the note readable without losing other errors.
func TestPlain_ShortensATimeout(t *testing.T) {
	to := &net.DNSError{Err: "timeout", IsTimeout: true}
	if got := plain(to).Error(); got != "timed out" {
		t.Fatalf("plain(timeout) = %q", got)
	}
	other := errors.New("connection refused")
	if got := plain(other).Error(); got != "connection refused" {
		t.Fatalf("plain(other) = %q, want it passed through", got)
	}
}
