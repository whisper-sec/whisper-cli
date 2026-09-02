// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the production netResolver against REAL loopback DNS
// servers (miekg/dns over genuine UDP+TCP sockets). The load-bearing behaviors: DO=1 + CD=1
// on every query (we are the validator, the transport is untrusted), UDP->TCP fallback on
// truncation (RFC 7766), and failover across resolvers on SERVFAIL/transport error.

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// deepentrustverify_startDNSServer serves handler on ONE loopback port over BOTH UDP and TCP
// (the resolver retries truncated UDP answers over TCP on the same address). Binding the
// same port on both transports can race another process, so it retries a few fresh ports.
func deepentrustverify_startDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("udp listen: %v", err)
		}
		addr := pc.LocalAddr().String()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close() // the TCP side of this port is taken; draw a fresh port
			continue
		}
		us := &dns.Server{PacketConn: pc, Handler: handler}
		ts := &dns.Server{Listener: ln, Handler: handler}
		go us.ActivateAndServe()
		go ts.ActivateAndServe()
		t.Cleanup(func() {
			us.Shutdown()
			ts.Shutdown()
		})
		return addr
	}
	t.Fatal("could not bind a matching udp+tcp loopback port pair")
	return ""
}

// deepentrustverify_txtAnswer builds a NOERROR reply carrying one TXT record.
func deepentrustverify_txtAnswer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"hello"},
	}}
	return m
}

// deepentrustverify_shortResolver clones the production resolver shape with test-friendly
// timeouts so the negative paths (dead servers) stay fast.
func deepentrustverify_shortResolver(servers ...string) *netResolver {
	return &netResolver{
		servers: servers,
		udp:     &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: 4096},
		tcp:     &dns.Client{Net: "tcp", Timeout: 2 * time.Second},
	}
}

func TestDeepenTV_NetResolver_QuerySendsDOAndCD(t *testing.T) {
	var mu sync.Mutex
	var sawCD, sawDO bool
	addr := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		mu.Lock()
		sawCD = req.CheckingDisabled
		if opt := req.IsEdns0(); opt != nil {
			sawDO = opt.Do()
		}
		mu.Unlock()
		w.WriteMsg(deepentrustverify_txtAnswer(req))
	}))
	in, err := NewNetResolver(addr).Query(context.Background(), "example.test", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("want the served answer, got: %+v", in)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawCD || !sawDO {
		t.Fatalf("every query must carry CD=1 and DO=1 (we validate, not the resolver): CD=%v DO=%v",
			sawCD, sawDO)
	}
}

func TestDeepenTV_NetResolver_TruncatedUDPFallsBackToTCP(t *testing.T) {
	var mu sync.Mutex
	sawTCP := false
	addr := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if w.RemoteAddr().Network() == "udp" {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Truncated = true
			w.WriteMsg(m)
			return
		}
		mu.Lock()
		sawTCP = true
		mu.Unlock()
		w.WriteMsg(deepentrustverify_txtAnswer(req))
	}))
	in, err := NewNetResolver(addr).Query(context.Background(), "example.test", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(in.Answer) != 1 || in.Truncated {
		t.Fatalf("want the full TCP answer after truncation, got: %+v", in)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawTCP {
		t.Fatal("a truncated UDP reply must be retried over TCP (RFC 7766)")
	}
}

func TestDeepenTV_NetResolver_FailsOverOnServfail(t *testing.T) {
	bad := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
	}))
	good := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		w.WriteMsg(deepentrustverify_txtAnswer(req))
	}))
	in, err := deepentrustverify_shortResolver(bad, good).Query(context.Background(),
		"example.test", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Query must fail over past a SERVFAIL resolver: %v", err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("want the second resolver's answer, got: %+v", in)
	}
}

func TestDeepenTV_NetResolver_FailsOverOnTransportError(t *testing.T) {
	dead := deepentrustverify_closedPort(t) // nothing listens on UDP either
	good := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		w.WriteMsg(deepentrustverify_txtAnswer(req))
	}))
	in, err := deepentrustverify_shortResolver(dead, good).Query(context.Background(),
		"example.test", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Query must fail over past a dead resolver: %v", err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("want the live resolver's answer, got: %+v", in)
	}
}

func TestDeepenTV_NetResolver_AllServersFailingReturnsTheLastError(t *testing.T) {
	bad := deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(m)
	}))
	_, err := deepentrustverify_shortResolver(bad).Query(context.Background(), "example.test", dns.TypeTXT)
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("want the last resolver error (REFUSED), got: %v", err)
	}
}

func TestDeepenTV_NetResolver_NoServersIsAClearError(t *testing.T) {
	_, err := deepentrustverify_shortResolver().Query(context.Background(), "example.test", dns.TypeTXT)
	if err == nil || !strings.Contains(err.Error(), "no resolver answered") {
		t.Fatalf("want the no-resolver error, got: %v", err)
	}
}

func TestDeepenTV_NewNetResolver_ServerSelection(t *testing.T) {
	if r := NewNetResolver("192.0.2.1").(*netResolver); len(r.servers) != 1 ||
		r.servers[0] != "192.0.2.1:53" {
		t.Fatalf("a bare host must gain :53, got: %v", r.servers)
	}
	if r := NewNetResolver("192.0.2.1:5353").(*netResolver); len(r.servers) != 1 ||
		r.servers[0] != "192.0.2.1:5353" {
		t.Fatalf("an explicit port must be kept, got: %v", r.servers)
	}
	r := NewNetResolver("  ").(*netResolver)
	if len(r.servers) < 3 {
		t.Fatalf("a blank server must fall back to the default failover list, got: %v", r.servers)
	}
	if r.udp == nil || r.tcp == nil {
		t.Fatal("both UDP and TCP clients must be initialised")
	}
}

func TestDeepenTV_DefaultResolvers_PublicTailAndNoLoopbackStubs(t *testing.T) {
	out := defaultResolvers()
	if len(out) < 3 {
		t.Fatalf("the well-known public tail must always be present, got: %v", out)
	}
	tail := out[len(out)-3:]
	if tail[0] != "1.1.1.1:53" || tail[1] != "9.9.9.9:53" || tail[2] != "8.8.8.8:53" {
		t.Fatalf("the failover tail must be the DNSSEC-capable publics in order, got: %v", tail)
	}
	for _, s := range out {
		host, port, err := net.SplitHostPort(s)
		if err != nil || port == "" {
			t.Fatalf("every entry must be host:port, got %q", s)
		}
		if ip, err := netip.ParseAddr(host); err != nil || ip.IsLoopback() {
			t.Fatalf("loopback stubs must be skipped (they SERVFAIL DNSKEY/DS): %q", s)
		}
	}
}

func TestDeepenTV_WithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1":         "192.0.2.1:53",
		"192.0.2.1:5353":    "192.0.2.1:5353",
		"2001:db8::1":       "[2001:db8::1]:53",
		"[2001:db8::1]:853": "[2001:db8::1]:853",
	}
	for in, want := range cases {
		if got := withDefaultPort(in); got != want {
			t.Fatalf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}
