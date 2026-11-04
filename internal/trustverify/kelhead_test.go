// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var kelOwner = "_whisper-kel." + agentFQDN

// setMsg stores a full canned answer (rcode, answer and authority sections).
func (m *mapResolver) setMsg(name string, qtype uint16, rcode int, answer, ns []dns.RR) {
	msg := new(dns.Msg)
	msg.Rcode = rcode
	msg.Answer = answer
	msg.Ns = ns
	m.answers[rkey(name, qtype)] = msg
}

// signed returns rrs followed by one RRSIG over them by the agent zone's ZSK.
func signed(t *testing.T, fx agentFixture, rrs ...dns.RR) []dns.RR {
	t.Helper()
	return append(append([]dns.RR{}, rrs...), signRRSet(t, fx.h.childZSK, agentZone, rrs, fx.h.now))
}

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: t, Class: dns.ClassINET, Ttl: 60}
}

func kelTXT(owner string, strs ...string) *dns.TXT {
	return &dns.TXT{Hdr: hdr(owner, dns.TypeTXT), Txt: strs}
}

func zoneSOA(minttl uint32) *dns.SOA {
	return &dns.SOA{Hdr: hdr(agentZone, dns.TypeSOA), Ns: "ns1." + agentZone, Mbox: "hostmaster." + agentZone,
		Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: minttl}
}

// zoneNames is the agent zone's names and the types each holds, for building denial chains.
func zoneNames() map[string][]uint16 {
	return map[string][]uint16{
		agentZone:                {dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeRRSIG},
		agentFQDN:                {dns.TypeAAAA, dns.TypeSSHFP, dns.TypeRRSIG},
		"te08." + agentZone:      nil, // an empty non-terminal
		"_443._tcp." + agentFQDN: {dns.TypeTLSA, dns.TypeRRSIG},
		"_tcp." + agentFQDN:      nil,
		"zz.agents.example.":     {dns.TypeA, dns.TypeRRSIG},
		"bb.agents.example.":     {dns.TypeA, dns.TypeRRSIG},
		"child.agents.example.":  {dns.TypeNS},
	}
}

// nsecChain is the zone's full NSEC chain in canonical order, each record signed.
func nsecChain(t *testing.T, fx agentFixture, names map[string][]uint16) []dns.RR {
	t.Helper()
	var order []string
	for n := range names {
		order = append(order, dns.CanonicalName(n))
	}
	sort.Slice(order, func(i, j int) bool { return canonicalCompare(order[i], order[j]) < 0 })
	var out []dns.RR
	for i, n := range order {
		next := order[(i+1)%len(order)]
		types := append(append([]uint16{}, names[n]...), dns.TypeNSEC)
		sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
		rec := &dns.NSEC{Hdr: hdr(n, dns.TypeNSEC), NextDomain: next, TypeBitMap: types}
		out = append(out, signed(t, fx, rec)...)
	}
	return out
}

// nsec3Chain is the zone's full NSEC3 chain (SHA-1, the given iterations, no salt).
func nsec3Chain(t *testing.T, fx agentFixture, names map[string][]uint16, flags uint8, iter uint16) []dns.RR {
	t.Helper()
	type h struct {
		hash  string
		types []uint16
	}
	var hs []h
	for n, types := range names {
		hs = append(hs, h{dns.HashName(n, dns.SHA1, iter, ""), types})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
	var out []dns.RR
	for i, x := range hs {
		next := hs[(i+1)%len(hs)].hash
		types := append([]uint16{}, x.types...)
		sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
		rec := &dns.NSEC3{Hdr: hdr(strings.ToLower(x.hash)+"."+agentZone, dns.TypeNSEC3), Hash: dns.SHA1,
			Flags: flags, Iterations: iter, SaltLength: 0, Salt: "", HashLength: 20, NextDomain: next,
			TypeBitMap: types}
		out = append(out, signed(t, fx, rec)...)
	}
	return out
}

func TestKelHeadPresentIsReadAsOctets(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	txt := kelTXT(kelOwner, "v=wkel1", `q=\"\\`, `b=\128`)
	fx.h.res.set(kelOwner, dns.TypeTXT, signed(t, fx, txt))
	got, err := fx.h.validator().ValidateKelHead(context.Background(), agentFQDN)
	if err != nil {
		t.Fatal(err)
	}
	if got.Absent || len(got.Records) != 1 || len(got.Records[0]) != 3 {
		t.Fatalf("%+v", got)
	}
	if string(got.Records[0][0]) != "v=wkel1" || string(got.Records[0][1]) != `q="\` || got.Records[0][2][2] != 0x80 {
		t.Fatalf("the octets were not unescaped: %q", got.Records[0])
	}
	if got.TTL != time.Hour {
		t.Fatalf("ttl %v", got.TTL)
	}
}

func TestKelHeadAbsenceIsProvenByNSEC3(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(map[string][]uint16)
		rcode int
	}{
		{"nxdomain", nil, dns.RcodeNameError},
		{"nodata", func(n map[string][]uint16) { n[kelOwner] = []uint16{dns.TypeA, dns.TypeRRSIG} }, dns.RcodeSuccess},
		{"wildcard nodata", func(n map[string][]uint16) { n["*."+agentFQDN] = []uint16{dns.TypeA} }, dns.RcodeSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildAgentFixture(t, "", "")
			names := zoneNames()
			if c.mut != nil {
				c.mut(names)
			}
			ns := append(nsec3Chain(t, fx, names, 0, 0), signedSOA(t, fx, 7200, 10800)...)
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, c.rcode, nil, ns)
			got, err := fx.h.validator().ValidateKelHead(context.Background(), agentFQDN)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Absent || len(got.Records) != 0 {
				t.Fatalf("%+v", got)
			}
			if got.TTL != 7200*time.Second {
				t.Fatalf("the negative TTL (SOA minimum 7200 under an SOA TTL of 10800) is longer than the denial's RRSIG TTL, so it bounds the absence: %v", got.TTL)
			}
		})
	}
}

// signedSOA is the agent zone's SOA with the given MINIMUM, its own TTL ttl, signed with that
// original TTL.
func signedSOA(t *testing.T, fx agentFixture, minttl, ttl uint32) []dns.RR {
	t.Helper()
	soa := zoneSOA(minttl)
	soa.Hdr.Ttl = ttl
	sig := signRRSetTTL(t, fx.h.childZSK, agentZone, []dns.RR{soa}, fx.h.now, ttl)
	return []dns.RR{soa, sig}
}

// The negative TTL of RFC 2308 section 5 is the LESSER of the SOA MINIMUM and the SOA's own TTL:
// a cache never holds an absence longer, so neither does the lag window built on it. The denial
// records' own RRSIG TTL (3600 here) is the floor.
func TestKelHeadAbsenceTTLIsTheRFC2308NegativeTTL(t *testing.T) {
	cases := []struct {
		name        string
		minttl, ttl uint32
		want        time.Duration
	}{
		{"the SOA's own TTL caps a longer MINIMUM", 7200, 5400, 5400 * time.Second},
		{"the MINIMUM caps a longer SOA TTL", 5400, 10800, 5400 * time.Second},
		{"a negative TTL below the denial's own TTL leaves the denial's", 600, 10800, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildAgentFixture(t, "", "")
			ns := append(nsec3Chain(t, fx, zoneNames(), 0, 0), signedSOA(t, fx, c.minttl, c.ttl)...)
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, ns)
			got, err := fx.h.validator().ValidateKelHead(context.Background(), agentFQDN)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Absent || got.TTL != c.want {
				t.Fatalf("absent %v ttl %v, want %v", got.Absent, got.TTL, c.want)
			}
		})
	}
}

func TestKelHeadAbsenceIsProvenByNSEC(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		mut   func(map[string][]uint16)
	}{
		{"nxdomain", kelOwner, nil},
		{"nodata", kelOwner, func(n map[string][]uint16) { n[kelOwner] = []uint16{dns.TypeA, dns.TypeRRSIG} }},
		{"wildcard nodata", kelOwner, func(n map[string][]uint16) { n["*."+agentFQDN] = []uint16{dns.TypeA} }},
		{"past the last name, wrapping to the apex", "_whisper-kel.zzzz." + agentZone, nil},
		{"empty non-terminal", "_whisper-kel.te08." + agentZone, func(n map[string][]uint16) {
			n["x._whisper-kel.te08."+agentZone] = []uint16{dns.TypeA}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildAgentFixture(t, "", "")
			names := zoneNames()
			if c.mut != nil {
				c.mut(names)
			}
			fx.h.res.setMsg(c.qname, dns.TypeTXT, dns.RcodeNameError, nil, nsecChain(t, fx, names))
			fqdn := strings.TrimPrefix(c.qname, "_whisper-kel.")
			got, err := fx.h.validator().ValidateKelHead(context.Background(), fqdn)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Absent || got.TTL != time.Hour {
				t.Fatalf("%+v", got)
			}
		})
	}
}

// Every way an absence or an answer can fail to be proven is an error, never an empty head.
func TestKelHeadRefusesWhatItCannotProve(t *testing.T) {
	type setup func(t *testing.T, fx agentFixture)
	nsec3 := func(flags uint8, iter uint16, mut func(map[string][]uint16)) setup {
		return func(t *testing.T, fx agentFixture) {
			names := zoneNames()
			if mut != nil {
				mut(names)
			}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, nsec3Chain(t, fx, names, flags, iter))
		}
	}
	cases := []struct {
		name string
		do   setup
		want string
	}{
		{"unsigned answer", func(t *testing.T, fx agentFixture) {
			fx.h.res.set(kelOwner, dns.TypeTXT, []dns.RR{kelTXT(kelOwner, "v=wkel1")})
		}, "UNSIGNED"},
		{"tampered answer", func(t *testing.T, fx agentFixture) {
			rrs := signed(t, fx, kelTXT(kelOwner, "v=wkel1"))
			rrs[0].(*dns.TXT).Txt = []string{"v=wkel1", "s=9"}
			fx.h.res.set(kelOwner, dns.TypeTXT, rrs)
		}, "verified"},
		{"expired signature", func(t *testing.T, fx agentFixture) {
			txt := kelTXT(kelOwner, "v=wkel1")
			sig := signRRSet(t, fx.h.childZSK, agentZone, []dns.RR{txt}, fx.h.now.Add(-30*24*time.Hour))
			fx.h.res.set(kelOwner, dns.TypeTXT, []dns.RR{txt, sig})
		}, "verified"},
		{"signed by an unrelated zone", func(t *testing.T, fx agentFixture) {
			evil := "evil.example."
			ksk, zsk := genKey(t, evil, 257), genKey(t, evil, 256)
			keys := []dns.RR{ksk.dnskey, zsk.dnskey}
			fx.h.res.set(evil, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), signRRSet(t, ksk, evil, keys, fx.h.now)))
			ds := ksk.dnskey.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: evil, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			fx.h.res.set(evil, dns.TypeDS, []dns.RR{ds, signRRSet(t, fx.h.rootZSK, ".", []dns.RR{ds}, fx.h.now)})
			txt := kelTXT(kelOwner, "v=wkel1")
			fx.h.res.set(kelOwner, dns.TypeTXT, []dns.RR{txt, signRRSet(t, zsk, evil, []dns.RR{txt}, fx.h.now)})
		}, "verified"},
		{"wildcard expansion", func(t *testing.T, fx agentFixture) {
			wild := kelTXT("*."+agentFQDN, "v=wkel1")
			sig := signRRSet(t, fx.h.childZSK, agentZone, []dns.RR{wild}, fx.h.now)
			sig.Hdr.Name = kelOwner
			exp := kelTXT(kelOwner, "v=wkel1")
			fx.h.res.set(kelOwner, dns.TypeTXT, []dns.RR{exp, sig})
		}, "wildcard"},
		{"alias", func(t *testing.T, fx agentFixture) {
			c := &dns.CNAME{Hdr: hdr(kelOwner, dns.TypeCNAME), Target: "x." + agentZone}
			fx.h.res.set(kelOwner, dns.TypeTXT, signed(t, fx, c))
		}, "alias"},
		{"servfail", func(t *testing.T, fx agentFixture) {
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeServerFailure, nil, nil)
		}, "SERVFAIL"},
		{"nxdomain with no denial", func(t *testing.T, fx agentFixture) {
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, signed(t, fx, zoneSOA(300)))
		}, "no signed NSEC"},
		{"unsigned denial", func(t *testing.T, fx agentFixture) {
			var ns []dns.RR
			for _, rr := range nsec3Chain(t, fx, zoneNames(), 0, 0) {
				if _, sig := rr.(*dns.RRSIG); !sig {
					ns = append(ns, rr)
				}
			}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, ns)
		}, "no signed NSEC"},
		{"NSEC3 opt-out", nsec3(1, 0, nil), "opt-out"},
		{"NSEC3 too many iterations", nsec3(0, 151, nil), "iterations"},
		{"NSEC3 NODATA lists TXT", nsec3(0, 0, func(n map[string][]uint16) {
			n[kelOwner] = []uint16{dns.TypeTXT, dns.TypeRRSIG}
		}), "present"},
		{"NSEC3 NODATA at a CNAME", nsec3(0, 0, func(n map[string][]uint16) {
			n[kelOwner] = []uint16{dns.TypeCNAME, dns.TypeRRSIG}
		}), "CNAME"},
		{"NSEC3 wildcard that answers", nsec3(0, 0, func(n map[string][]uint16) {
			n["*."+agentFQDN] = []uint16{dns.TypeTXT}
		}), "present"},
		{"NSEC3 under a delegation", func(t *testing.T, fx agentFixture) {
			names := zoneNames()
			names[agentFQDN] = []uint16{dns.TypeNS}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, nsec3Chain(t, fx, names, 0, 0))
		}, "delegation"},
		{"NSEC3 missing the wildcard proof", func(t *testing.T, fx agentFixture) {
			chain := nsec3Chain(t, fx, zoneNames(), 0, 0)
			wild := "*." + agentFQDN
			var ns []dns.RR
			for i := 0; i < len(chain); i += 2 {
				if n3 := chain[i].(*dns.NSEC3); n3.Cover(wild) && !n3.Cover(kelOwner) {
					continue
				}
				ns = append(ns, chain[i], chain[i+1])
			}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, ns)
		}, "wildcard"},
		{"NSEC that covers nothing", func(t *testing.T, fx agentFixture) {
			rec := &dns.NSEC{Hdr: hdr("aa."+agentZone, dns.TypeNSEC), NextDomain: "ab." + agentZone,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC}}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, signed(t, fx, rec))
		}, "no NSEC covers"},
		{"NSEC NODATA lists TXT", func(t *testing.T, fx agentFixture) {
			names := zoneNames()
			names[kelOwner] = []uint16{dns.TypeTXT}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeSuccess, nil, nsecChain(t, fx, names))
		}, "present"},
		{"NSEC without the wildcard proof", func(t *testing.T, fx agentFixture) {
			chain := nsecChain(t, fx, zoneNames())
			var ns []dns.RR
			for i := 0; i < len(chain); i += 2 {
				r := chain[i].(*dns.NSEC)
				if nsecCovers(dns.CanonicalName(r.Hdr.Name), dns.CanonicalName(r.NextDomain), agentZone, kelOwner) {
					ns = append(ns, chain[i], chain[i+1])
				}
			}
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, ns)
		}, "wildcard"},
		{"NSEC covering from a delegation", func(t *testing.T, fx agentFixture) {
			q := "_whisper-kel.x.child." + agentZone
			names := zoneNames()
			fx.h.res.setMsg(q, dns.TypeTXT, dns.RcodeNameError, nil, nsecChain(t, fx, names))
		}, "delegation"},
		{"mixed NSEC and NSEC3", func(t *testing.T, fx agentFixture) {
			ns := append(nsec3Chain(t, fx, zoneNames(), 0, 0), nsecChain(t, fx, zoneNames())...)
			fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, ns)
		}, "mixes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildAgentFixture(t, "", "")
			c.do(t, fx)
			fqdn := agentFQDN
			if c.name == "NSEC covering from a delegation" {
				fqdn = "x.child." + agentZone
			}
			got, err := fx.h.validator().ValidateKelHead(context.Background(), fqdn)
			if err == nil {
				t.Fatalf("proved %+v", got)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not say %q", err, c.want)
			}
		})
	}
	if _, err := NewValidator(newMapResolver(), nil, time.Now()).ValidateKelHead(context.Background(), " "); err == nil {
		t.Fatal("a blank name is refused")
	}
}

func TestProveNameForwardConfirms(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	got, err := fx.h.validator().ProveName(context.Background(), netip.MustParseAddr(testAddr))
	if err != nil || got != agentFQDN {
		t.Fatalf("%q %v", got, err)
	}
	other := buildAgentFixture(t, "", "other."+agentZone)
	if name, err := other.h.validator().ProveName(context.Background(), netip.MustParseAddr(testAddr)); err == nil ||
		!strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("a PTR naming a name with no AAAA must fail: %q %v", name, err)
	}
	if _, err := fx.h.validator().ProveName(context.Background(), netip.Addr{}); err == nil {
		t.Fatal("no address is refused")
	}
	if _, err := fx.h.validator().ProveName(context.Background(), netip.MustParseAddr("2001:db8::1")); err == nil ||
		!strings.Contains(err.Error(), "PTR") {
		t.Fatalf("an address with no PTR: %v", err)
	}
}

func TestCanonicalOrder(t *testing.T) {
	// RFC 4034 6.1's own example order.
	order := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.",
		"z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."}
	for i := 1; i < len(order); i++ {
		if canonicalCompare(order[i-1], order[i]) >= 0 {
			t.Fatalf("%s must sort before %s", order[i-1], order[i])
		}
	}
	if canonicalCompare("A.example.", "a.example.") != 0 {
		t.Fatal("case is folded")
	}
	if got := txtOctets(`a\`); string(got) != `a\` {
		t.Fatalf("a trailing backslash is kept: %q", got)
	}
	if got := txtOctets(`\999`); string(got) != "999" {
		t.Fatalf("an out-of-range escape is read literally: %q", got)
	}
}

// RFC 5155: the Opt-Out flag disqualifies the NSEC3 that covers the next closer name (section 8.3)
// and nothing else. The one covering the wildcard at the closest encloser counts with it (8.4).
func TestNSEC3OptOutCountsOnlyAgainstTheNextCloserName(t *testing.T) {
	names := zoneNames()
	next, wild := kelOwner, "*."+agentFQDN // the closest encloser is the agent name itself
	h := func(n string) string { return strings.ToLower(dns.HashName(n, dns.SHA1, 0, "")) }
	hn, hw := h(next), h(wild)
	between := func(x string) bool { // x strictly inside the span that runs from one hash to the other
		lo, hi := hn, hw
		if lo > hi {
			lo, hi = hi, lo
		}
		return x > lo && x < hi
	}
	// an existing name whose hash falls between the two, so one NSEC3 cannot cover both
	for i := 0; ; i++ {
		n := fmt.Sprintf("f%d.%s", i, agentZone)
		if between(h(n)) {
			names[n] = []uint16{dns.TypeA, dns.TypeRRSIG}
			break
		}
	}
	type hx struct {
		hash  string
		types []uint16
	}
	var hs []hx
	for n, types := range names {
		hs = append(hs, hx{h(n), types})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].hash < hs[j].hash })
	chain := func(optOut func(*dns.NSEC3, string) bool) []*dns.NSEC3 {
		var out []*dns.NSEC3
		for i, x := range hs {
			types := append([]uint16{}, x.types...)
			sort.Slice(types, func(a, b int) bool { return types[a] < types[b] })
			r := &dns.NSEC3{Hdr: hdr(x.hash+"."+agentZone, dns.TypeNSEC3), Hash: dns.SHA1, HashLength: 20,
				NextDomain: strings.ToUpper(hs[(i+1)%len(hs)].hash), TypeBitMap: types}
			if optOut(r, x.hash) {
				r.Flags = 1
			}
			out = append(out, r)
		}
		return out
	}
	covers := func(r *dns.NSEC3, name string) bool { return !r.Match(name) && r.Cover(name) }
	if err := proveNSEC3(chain(func(*dns.NSEC3, string) bool { return false }), agentZone, next, dns.TypeTXT); err != nil {
		t.Fatalf("the plain chain proves the absence: %v", err)
	}
	if err := proveNSEC3(chain(func(r *dns.NSEC3, _ string) bool { return covers(r, wild) }), agentZone, next,
		dns.TypeTXT); err != nil {
		t.Fatalf("opt-out on the wildcard's span still proves NXDOMAIN (RFC 5155 8.4): %v", err)
	}
	err := proveNSEC3(chain(func(r *dns.NSEC3, _ string) bool { return covers(r, next) }), agentZone, next, dns.TypeTXT)
	if err == nil || !strings.Contains(err.Error(), "opt-out covers the next closer name") {
		t.Fatalf("opt-out on the next closer name's span proves nothing (RFC 5155 9.2): %v", err)
	}

	// Signed and read end to end: a wildcard cover with Opt-Out proves the absence, and one whose
	// flags carry an unknown bit is ignored (RFC 5155 8.2), so with it the absence is unproven.
	signedWith := func(flags uint8) error {
		fx := buildAgentFixture(t, "", "")
		var rrs []dns.RR
		for _, r := range chain(func(r *dns.NSEC3, _ string) bool { return covers(r, wild) }) {
			if covers(r, wild) {
				r.Flags = flags
			}
			rrs = append(rrs, signed(t, fx, r)...)
		}
		fx.h.res.setMsg(kelOwner, dns.TypeTXT, dns.RcodeNameError, nil, rrs)
		_, err := fx.h.validator().ValidateKelHead(context.Background(), agentFQDN)
		return err
	}
	if err := signedWith(1); err != nil {
		t.Fatalf("a signed opt-out wildcard cover proves the absence: %v", err)
	}
	if err := signedWith(3); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("an NSEC3 with an unknown flag is ignored, so nothing covers the wildcard: %v", err)
	}
}
