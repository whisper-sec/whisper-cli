// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// netcheck.go answers the question a v4-only host has been getting wrong for months:
// "is the network between me and Whisper actually working, and over which family?"
//
// It measures rather than infers, and it measures with a mechanism that already exists
// and already answers for everyone: a real DNS question to each box's authoritative
// :53, over UDP, plus a TCP connect to :443. A UDP send with no reply proves nothing,
// so we send something that is answered. Both are keyless.
//
// What it must never do is imply a direct peer-to-peer path exists. There is none; the
// report carries PathNote() to say so out loud.

// NetcheckQName is the question every box answers authoritatively, so the probe is a
// real round trip rather than a hopeful datagram. SOA of the fleet zone is cheap,
// cacheable-free, and identical on every node.
const NetcheckQName = "agents.whisper.online."

// probePort is the front door every box serves: DoH, the control plane, and the
// Tier-1.5 egress ingress all live behind :443.
const probePort = 443

// Prober is the seam every measurement goes through, so the whole report can be
// exercised with no network at all.
type Prober interface {
	// Lookup resolves a box hostname into its v6 and v4 addresses.
	Lookup(ctx context.Context, host string) (v6, v4 []netip.Addr, err error)
	// DNSUDP asks NetcheckQName of server over UDP and returns the round trip.
	DNSUDP(ctx context.Context, server netip.Addr) (time.Duration, error)
	// TCP opens a TCP connection to server:port and returns the time to established.
	TCP(ctx context.Context, server netip.Addr, port int) (time.Duration, error)
}

// FamilyProbe is one address family's result for one box. Note is always filled in when
// a leg failed: a false with no reason is the shape that turns a timeout into a silent
// "not available", which is exactly the report that sent people chasing a dead egress.
type FamilyProbe struct {
	Family  string  `json:"family"`
	Addr    string  `json:"addr,omitempty"`
	DNSUDP  bool    `json:"dns_udp"`
	DNSMs   float64 `json:"dns_udp_ms,omitempty"`
	TCP443  bool    `json:"tcp443"`
	TCPMs   float64 `json:"tcp443_ms,omitempty"`
	Note    string  `json:"note,omitempty"`
	Present bool    `json:"present"` // the box publishes an address in this family
}

// BoxReport is one box, both families.
type BoxReport struct {
	Host string      `json:"host"`
	IPv6 FamilyProbe `json:"ipv6"`
	IPv4 FamilyProbe `json:"ipv4"`
}

// BestMs returns the lowest successful round trip seen for this box, and whether one was
// seen at all.
func (b BoxReport) BestMs() (float64, string, bool) {
	best, fam, ok := 0.0, "", false
	for _, f := range []FamilyProbe{b.IPv6, b.IPv4} {
		for _, cand := range []struct {
			ms float64
			ok bool
		}{{f.DNSMs, f.DNSUDP}, {f.TCPMs, f.TCP443}} {
			if !cand.ok {
				continue
			}
			if !ok || cand.ms < best {
				best, fam, ok = cand.ms, f.Family, true
			}
		}
	}
	return best, fam, ok
}

// NetcheckReport is the whole answer. Every boolean in it is backed by a probe that ran,
// and every false is backed by a Note or a Warning saying why.
type NetcheckReport struct {
	IPv6     bool        `json:"ipv6"`
	IPv4     bool        `json:"ipv4"`
	UDP      bool        `json:"udp"`
	Anchor   string      `json:"anchor_box,omitempty"`
	AnchorMs float64     `json:"anchor_rtt_ms,omitempty"`
	Boxes    []BoxReport `json:"boxes"`
	MTU      MTU         `json:"mtu"`
	MTUNote  string      `json:"mtu_note"`
	PathNote string      `json:"path_note"`
	JoinNote string      `json:"join_note"`
	Warnings []string    `json:"warnings,omitempty"`
}

// OK reports whether at least one box answered at least one probe. It is the exit-code
// question: a report where nothing answered is a real failure, not an empty table.
func (r NetcheckReport) OK() bool {
	for _, b := range r.Boxes {
		if _, _, ok := b.BestMs(); ok {
			return true
		}
	}
	return false
}

// joinNote is the fact a v4-only host most needs and least often hears.
const joinNote = "A v4-only host can still join: the WireGuard endpoint is resolved over both " +
	"families, so the tunnel rides IPv4 while the identity inside it stays IPv6."

// Netcheck probes every box in parallel and returns one report. It never returns an
// error: an unreachable box, an unresolvable name and a host with no IPv6 at all are all
// findings, and a finding belongs in the report where a person can read it.
func Netcheck(ctx context.Context, hosts []string, p Prober) NetcheckReport {
	rep := NetcheckReport{
		MTU:      TunnelMTU(),
		MTUNote:  MTUNote(),
		PathNote: PathNote(),
		JoinNote: joinNote,
		Boxes:    make([]BoxReport, len(hosts)),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			box, warn := probeBox(ctx, host, p)
			mu.Lock()
			rep.Boxes[i] = box
			if warn != "" {
				rep.Warnings = append(rep.Warnings, warn)
			}
			mu.Unlock()
		}(i, host)
	}
	wg.Wait()
	sort.Strings(rep.Warnings)

	for _, b := range rep.Boxes {
		if b.IPv6.DNSUDP || b.IPv6.TCP443 {
			rep.IPv6 = true
		}
		if b.IPv4.DNSUDP || b.IPv4.TCP443 {
			rep.IPv4 = true
		}
		if b.IPv6.DNSUDP || b.IPv4.DNSUDP {
			rep.UDP = true
		}
		if ms, fam, ok := b.BestMs(); ok && (rep.Anchor == "" || ms < rep.AnchorMs) {
			rep.Anchor, rep.AnchorMs = b.Host, ms
			_ = fam
		}
	}
	if !rep.OK() {
		rep.Warnings = append(rep.Warnings,
			"no box answered any probe: this host has no working path to the Whisper fleet right now")
	}
	return rep
}

// probeBox resolves one box and runs both families. A resolution failure is reported as
// a warning AND as an empty pair of probes with a note, so the caller can never mistake
// "we could not ask" for "we asked and it said no".
func probeBox(ctx context.Context, host string, p Prober) (BoxReport, string) {
	box := BoxReport{
		Host: host,
		IPv6: FamilyProbe{Family: "ipv6"},
		IPv4: FamilyProbe{Family: "ipv4"},
	}
	v6, v4, err := p.Lookup(ctx, host)
	if err != nil {
		note := fmt.Sprintf("could not resolve %s: %v", host, err)
		box.IPv6.Note, box.IPv4.Note = note, note
		return box, note
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); box.IPv6 = probeFamily(ctx, "ipv6", v6, p) }()
	go func() { defer wg.Done(); box.IPv4 = probeFamily(ctx, "ipv4", v4, p) }()
	wg.Wait()
	return box, ""
}

// probeFamily runs the two legs against the first address of one family.
func probeFamily(ctx context.Context, family string, addrs []netip.Addr, p Prober) FamilyProbe {
	fp := FamilyProbe{Family: family}
	if len(addrs) == 0 {
		fp.Note = "the box publishes no " + family + " address"
		return fp
	}
	fp.Present = true
	addr := addrs[0]
	fp.Addr = addr.String()

	var wg sync.WaitGroup
	var dnsErr, tcpErr error
	var dnsRTT, tcpRTT time.Duration
	wg.Add(2)
	go func() { defer wg.Done(); dnsRTT, dnsErr = p.DNSUDP(ctx, addr) }()
	go func() { defer wg.Done(); tcpRTT, tcpErr = p.TCP(ctx, addr, probePort) }()
	wg.Wait()

	if dnsErr == nil {
		fp.DNSUDP, fp.DNSMs = true, ms(dnsRTT)
	}
	if tcpErr == nil {
		fp.TCP443, fp.TCPMs = true, ms(tcpRTT)
	}
	switch {
	case dnsErr != nil && tcpErr != nil:
		fp.Note = fmt.Sprintf("no %s path to %s: %v", family, fp.Addr, plain(dnsErr))
	case dnsErr != nil:
		fp.Note = fmt.Sprintf("UDP/53 did not answer over %s: %v", family, plain(dnsErr))
	case tcpErr != nil:
		fp.Note = fmt.Sprintf("TCP/443 did not connect over %s: %v", family, plain(tcpErr))
	}
	return fp
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// plain shortens a network error to the part a person can act on.
func plain(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timed out")
	}
	return err
}

// --- the real prober -------------------------------------------------------------

// NetProber is the production implementation: the system resolver for names, miekg/dns
// for the UDP round trip, and a plain dialer for TCP.
type NetProber struct {
	Timeout  time.Duration
	Resolver *net.Resolver
	Dialer   *net.Dialer
}

// NewNetProber builds a prober with a per-probe timeout. A zero timeout means 3s, which
// keeps `whale netcheck` under a couple of seconds wall-clock even when a box is dark.
func NewNetProber(timeout time.Duration) *NetProber {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &NetProber{Timeout: timeout, Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: timeout}}
}

// Lookup splits the host's addresses by family. A host that is itself an IP literal
// resolves to itself, so `--box <addr>` works with no DNS at all.
func (p *NetProber) Lookup(ctx context.Context, host string) (v6, v4 []netip.Addr, err error) {
	if a, perr := netip.ParseAddr(host); perr == nil {
		return splitFamilies([]netip.Addr{a})
	}
	cx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	res := p.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, lerr := res.LookupNetIP(cx, "ip", host)
	if lerr != nil {
		return nil, nil, lerr
	}
	return splitFamilies(addrs)
}

func splitFamilies(addrs []netip.Addr) (v6, v4 []netip.Addr, err error) {
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			v4 = append(v4, a.Unmap())
			continue
		}
		v6 = append(v6, a)
	}
	return v6, v4, nil
}

// DNSUDP asks the box a question it is authoritative for, over UDP, in the family the
// address selects. The answer proves the datagram went out AND came back.
func (p *NetProber) DNSUDP(ctx context.Context, server netip.Addr) (time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(NetcheckQName, dns.TypeSOA)
	m.SetEdns0(1232, false)
	c := &dns.Client{Net: udpNetwork(server), Timeout: p.Timeout}
	_, rtt, err := c.ExchangeContext(ctx, m, net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return 0, err
	}
	return rtt, nil
}

// TCP times a connect. Established is the measurement; the connection is closed at once.
func (p *NetProber) TCP(ctx context.Context, server netip.Addr, port int) (time.Duration, error) {
	cx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	d := p.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: p.Timeout}
	}
	start := time.Now()
	conn, err := d.DialContext(cx, tcpNetwork(server), net.JoinHostPort(server.String(), fmt.Sprint(port)))
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, nil
}

// udpNetwork / tcpNetwork pin the family so a probe labelled ipv6 can never be answered
// over IPv4 by a happy-eyeballs dialer, which would make the report a lie.
func udpNetwork(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "udp4"
	}
	return "udp6"
}

func tcpNetwork(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return "tcp4"
	}
	return "tcp6"
}
