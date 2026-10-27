// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// A DNS-speaking fake tunnel stack. Every test in this file drives the REAL query, framing
// and parse code over it, so a test failing here means the wire path is wrong and not that a
// mock drifted. Without it these paths could only be exercised against a live tunnel, which
// is another way of saying they would not be exercised.
type dnsStack struct {
	// answers maps "<qname>|<qtype>" to the addresses to return, and rcodes maps the same key
	// to a non-zero rcode. A key in neither is an empty NOERROR.
	answers map[string][]netip.Addr
	rcodes  map[string]uint8
	// dialed records every address the dialer asked for, DNS and payload alike.
	dialed []string
	// failDial is the set of payload targets that must fail, so a test can force the
	// v4-only-name retry the way a real v6-only netstack forces it.
	failDial map[string]bool
	// refuseConnect makes the DNS dial itself fail, which is a different fault from a
	// resolver that answers REFUSED and must produce a different sentence.
	refuseConnect bool
	// perResolver overrides the answers for one resolver address, so a test can make the
	// ladder's two rungs behave differently. Absent, every resolver sees the same table.
	perResolver map[string]*dnsStack
	// edes maps the same key to an RFC 8914 Extended DNS Error the reply should carry, so a
	// test can reproduce a resolver that refuses a name AND says why.
	edes map[string]ede
	// blackhole is the set of resolver addresses whose DNS dial never completes: it blocks until
	// the dial's context ends, which is what a silent far end does on the real stack. An instant
	// refusal (refuseConnect) is a different, much kinder fault.
	blackhole map[string]bool
	// garble makes every DNS reply arrive with a valid length and a body that is not a reply to
	// the query (a different ID), so a test can tell "replied" from "silent".
	garble bool
	mu     sync.Mutex
}

// ede is an Extended DNS Error a fixture reply attaches.
type ede struct {
	code uint16
	text string
}

func key(name string, qtype uint16) string { return dnsName(name) + "|" + typeName(qtype) }

func typeName(v uint16) string {
	if v == dnsTypeA {
		return "A"
	}
	return "AAAA"
}

func (s *dnsStack) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, address)
	refuse := s.refuseConnect
	s.mu.Unlock()
	if strings.HasSuffix(address, ":53") {
		if host, _, err := net.SplitHostPort(address); err == nil && s.blackhole[strings.Trim(host, "[]")] {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if refuse {
			return nil, errors.New("connection refused")
		}
		answerer := s
		if host, _, err := net.SplitHostPort(address); err == nil {
			if override, ok := s.perResolver[strings.Trim(host, "[]")]; ok {
				answerer = override
			}
		}
		client, server := net.Pipe()
		go answerer.serve(server)
		return client, nil
	}
	if s.failDial[address] {
		return nil, errors.New("no route")
	}
	c, _ := net.Pipe()
	return c, nil
}

func (s *dnsStack) LookupContextHost(_ context.Context, _ string) ([]string, error) {
	// The netstack resolver is deliberately useless here: it is what shipped-and-unreachable
	// looked like, and nothing in the production path may depend on it any more.
	return nil, errors.New("no such host")
}

// serve reads one length-prefixed query and writes one length-prefixed reply.
func (s *dnsStack) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var l [2]byte
	if _, err := readFull(conn, l[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := readFull(conn, q); err != nil {
		return
	}
	reply := s.reply(q)
	if s.garble {
		reply[0] ^= 0xFF // a different ID: a reply, but not to this query
	}
	out := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(out, uint16(len(reply)))
	copy(out[2:], reply)
	_, _ = conn.Write(out)
}

func (s *dnsStack) reply(q []byte) []byte {
	qname, qtype, end := readQuestion(q)
	k := qname + "|" + typeName(qtype)
	rcode := s.rcodes[k]
	addrs := s.answers[k]
	if rcode != 0 {
		addrs = nil
	}
	msg := make([]byte, end)
	copy(msg, q[:end])
	msg[2] = 0x81 // QR + RD
	msg[3] = 0x80 | rcode
	binary.BigEndian.PutUint16(msg[6:], uint16(len(addrs)))
	for _, a := range addrs {
		msg = append(msg, 0xC0, 0x0C) // a compression pointer at the question name
		msg = binary.BigEndian.AppendUint16(msg, qtype)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		if a.Is4() {
			b := a.As4()
			msg = binary.BigEndian.AppendUint16(msg, 4)
			msg = append(msg, b[:]...)
			continue
		}
		b := a.As16()
		msg = binary.BigEndian.AppendUint16(msg, 16)
		msg = append(msg, b[:]...)
	}
	// ARCOUNT is set explicitly rather than inherited. The header was copied from the QUERY,
	// which carries an OPT of its own, so without this every fixture reply would claim an
	// additional record it does not contain: a malformed message, and one that would let a
	// parser bug pass by reading a section that is not there.
	if e, ok := s.edes[k]; ok {
		msg = append(msg, 0) // root name
		msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
		msg = binary.BigEndian.AppendUint16(msg, ednsUDPPayload)
		msg = binary.BigEndian.AppendUint32(msg, 0)
		body := make([]byte, 2+len(e.text))
		binary.BigEndian.PutUint16(body, e.code)
		copy(body[2:], e.text)
		msg = binary.BigEndian.AppendUint16(msg, uint16(4+len(body))) // RDLEN
		msg = binary.BigEndian.AppendUint16(msg, ednsOptionExtendedError)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(body)))
		msg = append(msg, body...)
		binary.BigEndian.PutUint16(msg[10:], 1)
	} else {
		binary.BigEndian.PutUint16(msg[10:], 0)
	}
	return msg
}

func readQuestion(q []byte) (string, uint16, int) {
	off := 12
	var parts []string
	for off < len(q) && q[off] != 0 {
		n := int(q[off])
		parts = append(parts, string(q[off+1:off+1+n]))
		off += 1 + n
	}
	off++
	qtype := binary.BigEndian.Uint16(q[off:])
	return strings.Join(parts, ".") + ".", qtype, off + 4
}

func synth(t *testing.T, prefix, v4 string) netip.Addr {
	t.Helper()
	a, err := Synthesize(netip.MustParsePrefix(prefix), netip.MustParseAddr(v4))
	if err != nil {
		t.Fatalf("Synthesize(%s,%s): %v", prefix, v4, err)
	}
	return a
}

const nsp = "2a04:2a00:64::/96" // the fleet's dedicated agent NAT64 prefix

// controlA is what a resolver that recurses answers for the RECURSION PROBE name. The probe used to
// ask for the RFC 7050 name, which the Whisper resolver answers unconditionally, by design, so a
// resolver refusing every real name still passed it. It now asks a name nothing special-cases, and
// every fixture that means "this resolver is usable" answers that instead.
func controlA() []netip.Addr {
	return []netip.Addr{wellKnownIPv4OnlyAddrs[0], wellKnownIPv4OnlyAddrs[1]}
}

func resolverAddr() netip.Addr { return netip.MustParseAddr("2a04:2a01:0:53::1") }

// ---------------------------------------------------------------------------------------
// RFC 7050 discovery. THE regression this work exists for: the client used to assume the
// well-known prefix, and on the live fleet that prefix is translated by the WRONG translator,
// so a working connection silently egressed from the shared address instead of the dedicated
// agent one. Delete the discovery call in newNameService and this test fails.
// ---------------------------------------------------------------------------------------

func TestDiscoversTheNAT64PrefixTheResolverActuallySynthesisesInto(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {
			synth(t, nsp, "192.0.0.170"),
			synth(t, nsp, "192.0.0.171"),
		},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if got := ns.prefix.String(); got != nsp {
		t.Fatalf("prefix = %s, want the discovered %s (a guessed well-known prefix is the bug)", got, nsp)
	}
	if !ns.resolverOK {
		t.Fatalf("a resolver that answered must be usable")
	}
	if ns.verdict != "" {
		t.Fatalf("verdict = %q, want silence when everything holds", ns.verdict)
	}
	if !strings.Contains(ns.prefixSource, "RFC 7050") {
		t.Fatalf("prefixSource = %q, want it to name the discovery", ns.prefixSource)
	}
}

// A resolver could answer ipv4only.arpa with something that is not a synthesis. Reading a
// prefix off that would wrap every IPv4 destination into an address nothing translates, which
// is strictly worse than the guess it replaced, so the embedded-v4 check is load-bearing.
func TestAnAnswerThatDoesNotEmbedTheWellKnownIPv4IsNotAPrefix(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA):       controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {netip.MustParseAddr("2001:db8::1")},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if ns.prefix.String() != WellKnownNAT64Prefix {
		t.Fatalf("prefix = %s, want the unchanged default %s", ns.prefix, WellKnownNAT64Prefix)
	}
	if !strings.Contains(ns.verdict, "not synthesising") {
		t.Fatalf("verdict = %q, want it to say the resolver is not synthesising", ns.verdict)
	}
}

// ---------------------------------------------------------------------------------------
// The resolver probe: fail open, and say which of the three it was.
// ---------------------------------------------------------------------------------------

// A resolver that RECURSES but has no DNS64 is usable, and marking it otherwise would send
// every name to the host lookup for no reason and give up the socks5h property for nothing.
// This is the distinction the A control exists to make: measured on the live fleet, the
// per-tenant resolver answers NXDOMAIN for the RFC 7050 name, and reading that as a refusal
// was wrong. Ask for the AAAA only, and this test fails.
func TestAResolverThatRecursesWithoutDns64IsStillUsable(t *testing.T) {
	s := &dnsStack{
		answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()},
		rcodes:  map[string]uint8{key(wellKnownIPv4OnlyName, dnsTypeAAAA): 3}, // NXDOMAIN
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if !ns.resolverOK {
		t.Fatalf("a resolver that answers the control must stay usable; verdict = %q", ns.verdict)
	}
	if ns.prefix.String() != WellKnownNAT64Prefix {
		t.Fatalf("prefix = %s, want the unchanged default with no synthesis to read", ns.prefix)
	}
	if !strings.Contains(ns.verdict, "not synthesising") {
		t.Fatalf("verdict = %q, want it to name the missing DNS64 and nothing worse", ns.verdict)
	}
}

// Measured on the live fleet from inside a tunnel: the in-tunnel resolver answers for
// Whisper's own names and does not resolve anything else, so every socks5h name fails and all
// three possible faults look identical from the user's seat. The tunnel must still come up,
// must say which of the three it was, and must keep names inside the tunnel.
func TestARefusingResolverIsNamedAndTheTunnelStillComesUp(t *testing.T) {
	s := &dnsStack{rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 5}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if ns.confirmed {
		t.Fatalf("a resolver that refused the control must not be marked confirmed")
	}
	// It refused, so it is known not to serve names: they stay in the tunnel on the other
	// agent-plane resolver, never on this host.
	if ns.onHost || !ns.resolverOK || ns.resolver != agentPlaneResolvers[1] {
		t.Fatalf("onHost=%v resolver=%v ok=%v, want names kept in the tunnel on %v",
			ns.onHost, ns.resolver, ns.resolverOK, agentPlaneResolvers[1])
	}
	for _, want := range []string{"2a04:2a01:0:53::1", "treated as a resolver that does not serve names", "stay inside the tunnel"} {
		if !strings.Contains(ns.verdict, want) {
			t.Fatalf("verdict = %q, want it to contain %q", ns.verdict, want)
		}
	}
}

// Rung 2 of the ladder, and the reason it exists. The resolver the box named is broken and this
// host cannot resolve either (a lab guest with a stub resolver and no upstream is exactly that),
// so without a resolver reachable INSIDE the tunnel the session carries nothing by name. Delete
// the fallback rung from pickResolver and this test fails.
func TestABrokenNamedResolverFallsBackToOneInsideTheTunnel(t *testing.T) {
	// The named resolver here IS the first agent-plane candidate, which is the real case where
	// the control plane hands an agent the SHARED resolver rather than a per-tenant one. The
	// ladder must skip the address it has already rejected and move to the next one on the same
	// plane, so the expected fallback is the SECOND agent-plane resolver and not the first.
	fallback := agentPlaneResolvers[1]
	s := &dnsStack{
		perResolver: map[string]*dnsStack{
			fallback.String(): {answers: map[string][]netip.Addr{
				key(recursionProbeName, dnsTypeA):       controlA(),
				key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
			}},
		},
		rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 3}, // the named one: NXDOMAIN
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if !ns.resolverOK || ns.resolver != fallback {
		t.Fatalf("resolver = %v ok=%v, want the in-tunnel fallback %v", ns.resolver, ns.resolverOK, fallback)
	}
	if ns.prefix.String() != nsp {
		t.Fatalf("prefix = %s, want %s discovered from the resolver we actually settled on", ns.prefix, nsp)
	}
	for _, want := range []string{"2a04:2a01:0:53::1", fallback.String(), "still leave from your /128"} {
		if !strings.Contains(ns.verdict, want) {
			t.Fatalf("verdict = %q, want it to contain %q", ns.verdict, want)
		}
	}
}

// The ladder must not speak when there is nothing to report: the resolver the box named works,
// so the user hears nothing at all. A tunnel that narrates its own healthy bring-up is noise.
func TestAWorkingNamedResolverIsUsedSilently(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA):       controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if ns.resolver != resolverAddr() || ns.verdict != "" {
		t.Fatalf("resolver=%v verdict=%q, want the named resolver and silence", ns.resolver, ns.verdict)
	}
}

// A resolver that never REPLIED is not a broken resolver. The probe may simply have run before
// the tunnel carried its first packet, so the sentence must say "could not confirm" and must not
// state a Whisper-side fault as fact.
func TestASilentResolverIsCouldNotConfirmNotAFault(t *testing.T) {
	ns := newNameService(context.Background(), &dnsStack{refuseConnect: true}, resolverAddr(), netip.Prefix{})
	if ns.confirmed {
		t.Fatalf("an unreachable resolver must not be marked confirmed")
	}
	if !strings.Contains(ns.verdict, "could not confirm") {
		t.Fatalf("verdict = %q, want it to say the resolver could not be confirmed", ns.verdict)
	}
	if strings.Contains(ns.verdict, "fault on the Whisper side") {
		t.Fatalf("verdict = %q, states a fault from a probe that got no reply", ns.verdict)
	}
}

func TestNoResolverAtAllIsAnOrdinaryOutcome(t *testing.T) {
	ns := newNameService(context.Background(), &dnsStack{}, netip.Addr{}, netip.Prefix{})
	if ns.confirmed || ns.verdict == "" {
		t.Fatalf("confirmed=%v verdict=%q, want unconfirmed with a sentence", ns.confirmed, ns.verdict)
	}
}

// The retry. The first probe runs before the tunnel carries traffic and hears nothing;
// once the first handshake lands the same resolver answers. The tunnel must settle on it, in
// silence, exactly as if the first probe had been lucky.
func TestASilentProbeIsAskedAgainAfterTheFirstHandshake(t *testing.T) {
	s := &dnsStack{refuseConnect: true, answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA):       controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
	}}
	waited := 0
	afterHandshake := func(context.Context) bool {
		waited++
		s.mu.Lock()
		s.refuseConnect = false // the tunnel now carries traffic
		s.mu.Unlock()
		return true
	}
	ns := settleNameService(context.Background(), s, resolverAddr(), netip.Prefix{}, afterHandshake)
	if waited != 1 {
		t.Fatalf("waited for the handshake %d times, want exactly once", waited)
	}
	if !ns.confirmed || ns.resolver != resolverAddr() || ns.verdict != "" {
		t.Fatalf("confirmed=%v resolver=%v verdict=%q, want the named resolver, confirmed, in silence",
			ns.confirmed, ns.resolver, ns.verdict)
	}
	if ns.prefix.String() != nsp {
		t.Fatalf("prefix = %s, want %s discovered on the retry", ns.prefix, nsp)
	}
}

// CONTROL for the retry: a healthy bring-up never waits, and a resolver that REPLIED with a
// refusal is an answer, so it is not asked again either.
func TestOnlyASilentProbeWaitsForTheHandshake(t *testing.T) {
	for name, s := range map[string]*dnsStack{
		"healthy": {answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()}},
		"refused": {rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 5}},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			settleNameService(context.Background(), s, resolverAddr(), netip.Prefix{},
				func(context.Context) bool { called = true; return true })
			if called {
				t.Fatal("waited for a handshake although the first probe got a reply")
			}
		})
	}
}

// A silent probe whose tunnel never handshakes says so: that points at the tunnel, not DNS.
func TestASilentProbeWithNoHandshakePointsAtTheTunnel(t *testing.T) {
	ns := settleNameService(context.Background(), &dnsStack{refuseConnect: true}, resolverAddr(),
		netip.Prefix{}, func(context.Context) bool { return false })
	if !strings.Contains(ns.verdict, "first handshake") || !strings.Contains(ns.verdict, "could not confirm") {
		t.Fatalf("verdict = %q, want it to say the tunnel had not handshaked and the resolver is unconfirmed", ns.verdict)
	}
}

// An operator who pinned a prefix meant it. Obey, but say so when the network disagrees:
// the two ends disagreeing IS the bug class this file exists for.
func TestAPinnedPrefixWinsAndTheDisagreementIsReported(t *testing.T) {
	t.Setenv(nat64PrefixEnv, WellKnownNAT64Prefix)
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA):       controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if ns.prefix.String() != WellKnownNAT64Prefix {
		t.Fatalf("prefix = %s, want the pinned %s", ns.prefix, WellKnownNAT64Prefix)
	}
	if !strings.Contains(ns.verdict, nat64PrefixEnv) || !strings.Contains(ns.verdict, nsp) {
		t.Fatalf("verdict = %q, want it to name the override and the discovered prefix", ns.verdict)
	}
}

// ---------------------------------------------------------------------------------------
// dialV4OnlyName: the function that shipped and could never execute.
// ---------------------------------------------------------------------------------------

// The v4-only NAME path. Before this change the retry asked netstack's LookupContextHost,
// which on a v6-only stack fires the AAAA lane only, so it reached "no addresses" for every
// input it existed to serve. dnsStack.LookupContextHost always fails, so this test passes
// ONLY if the retry resolves the A record itself over the tunnel.
func TestAV4OnlyNameIsResolvedOverTheTunnelAndTranslated(t *testing.T) {
	s := &dnsStack{
		answers: map[string][]netip.Addr{
			key(recursionProbeName, dnsTypeA):       controlA(),
			key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
			key("v4only.example", dnsTypeA):         {netip.MustParseAddr("203.0.113.7")},
		},
		failDial: map[string]bool{"v4only.example:80": true},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	if _, err := d.Dial(context.Background(), "v4only.example:80"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	want := "[" + synth(t, nsp, "203.0.113.7").String() + "]:80"
	if last := s.dialed[len(s.dialed)-1]; last != want {
		t.Fatalf("last dial = %s, want the NAT64 form %s", last, want)
	}
}

// The bug a live lab guest found, and the reason the retry inspects the AAAA rather than just
// counting it. When DNS64 IS on the path, an A-only name comes back as a AAAA INSIDE the NAT64
// prefix. That is an IPv4 host written as IPv6, which is the answer we want; an earlier guard
// read "the name has a AAAA" as "the name has native v6, do not retry" and so refused the retry
// for exactly the names NAT64 exists to serve. Make the guard count AAAAs again and this fails.
func TestADns64SynthesisedAaaaIsDialledNotMistakenForNativeV6(t *testing.T) {
	synthesised := synth(t, nsp, "203.0.113.7")
	s := &dnsStack{
		answers: map[string][]netip.Addr{
			key(recursionProbeName, dnsTypeA):       controlA(),
			key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
			key("v4only.example", dnsTypeAAAA):      {synthesised},
		},
		failDial: map[string]bool{"v4only.example:80": true},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	if _, err := d.Dial(context.Background(), "v4only.example:80"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	want := "[" + synthesised.String() + "]:80"
	if last := s.dialed[len(s.dialed)-1]; last != want {
		t.Fatalf("last dial = %s, want the DNS64 answer %s", last, want)
	}
}

// The property worth keeping, restated for the current contract: a dual-stack name must NEVER be
// reached over NAT64. Doing so would egress from a shared IPv4 SNAT rather than the agent's own
// /128, and silently changing which identity a connection presents is the one thing an identity
// product must not do.
//
// What changed, and why the old assertion had to go. This used to also assert that the dial FAILED,
// on the reasoning that the name had "earned its error" from the first attempt. That reasoning
// depended on the first attempt being a real connect. It is not: the primary path now resolves the
// name on the settled resolver over TCP and dials the address, because handing the name to netstack
// asked AAAA-only over UDP against a single server and failed for every name on a live tunnel. So
// there is no earned error to preserve - the native address is dialled directly, and the fixture's
// failDial on the NAME is never consulted. The security property is unchanged and still asserted.
func TestANameWithNativeV6IsNotReroutedThroughNat64(t *testing.T) {
	s := &dnsStack{
		answers: map[string][]netip.Addr{
			key(recursionProbeName, dnsTypeA):       controlA(),
			key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
			key("dual.example", dnsTypeAAAA):        {netip.MustParseAddr("2001:db8::1")},
			key("dual.example", dnsTypeA):           {netip.MustParseAddr("203.0.113.7")},
		},
		failDial: map[string]bool{"dual.example:80": true},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	if _, err := d.Dial(context.Background(), "dual.example:80"); err != nil {
		t.Fatalf("the native v6 address is reachable, so the dial must succeed: %v", err)
	}
	if len(s.dialed) == 0 {
		t.Fatalf("nothing was dialled; the name must be resolved and its address dialled")
	}
	sawNative := false
	for _, dialed := range s.dialed {
		if strings.Contains(dialed, "2001:db8::1") {
			sawNative = true
		}
	}
	if !sawNative {
		t.Fatalf("dialed %v, want the NATIVE v6 address", s.dialed)
	}
	for _, dialed := range s.dialed {
		if strings.Contains(dialed, "cb00:7107") {
			t.Fatalf("dialed %v: a dual-stack name must not be rerouted over NAT64", s.dialed)
		}
	}
}

// The opt-in leg: the in-tunnel resolver refuses us and the user asked for WHISPER_RESOLVE_ON_HOST,
// so the name is resolved on this host and the connection still completes. It costs the socks5h
// property, which the verdict says out loud.
func TestAnUnusableResolverFallsBackToThisHostOnlyWhenAsked(t *testing.T) {
	t.Setenv(ResolveOnHostEnv, "1")
	s := &dnsStack{
		rcodes:   map[string]uint8{key(recursionProbeName, dnsTypeA): 5},
		failDial: map[string]bool{"v4only.example:80": true},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	if !ns.onHost || !strings.Contains(ns.verdict, ResolveOnHostEnv) {
		t.Fatalf("onHost=%v verdict=%q, want this host's resolver, said out loud", ns.onHost, ns.verdict)
	}
	ns.hostLookup = func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		if network != "ip4" {
			return nil, errors.New("no such host") // v4-only: no AAAA, so the retry is allowed
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	if _, err := d.Dial(context.Background(), "v4only.example:80"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// No resolver confirmed, so no discovery: the agent-plane prefix, not the office one.
	want := "[" + synth(t, agentPlaneNAT64.String(), "203.0.113.7").String() + "]:80"
	if last := s.dialed[len(s.dialed)-1]; last != want {
		t.Fatalf("last dial = %s, want %s", last, want)
	}
}

// Without the opt-in, names NEVER move to this host's resolver. A failed lookup inside the tunnel
// fails visibly; it does not quietly leave the /128.
func TestNamesNeverSilentlyMoveOffTheTunnel(t *testing.T) {
	t.Setenv(ResolveOnHostEnv, "")
	s := &dnsStack{
		rcodes:   map[string]uint8{key(recursionProbeName, dnsTypeA): 5},
		failDial: map[string]bool{"v4only.example:80": true},
	}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	asked := false
	ns.hostLookup = func(context.Context, string, string) ([]netip.Addr, error) {
		asked = true
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	_, _ = d.Dial(context.Background(), "v4only.example:80")
	if asked {
		t.Fatal("a name was resolved on this host although nobody asked for that")
	}
	if ns.onHost || !ns.resolverOK || !ns.resolver.IsValid() {
		t.Fatalf("onHost=%v resolver=%v, want names kept on an in-tunnel resolver", ns.onHost, ns.resolver)
	}
}

// A LITERAL must be wrapped into the DISCOVERED prefix too, not the compiled-in default:
// the literal path is the one that silently egressed from the wrong address.
func TestALiteralIsWrappedIntoTheDiscoveredPrefix(t *testing.T) {
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA):       controlA(),
		key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")},
	}}
	ns := newNameService(context.Background(), s, resolverAddr(), netip.Prefix{})
	d := &netDialer{stack: s, timeout: time.Second, names: ns}
	if _, err := d.Dial(context.Background(), "8.8.8.8:53"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	want := "[" + synth(t, nsp, "8.8.8.8").String() + "]:53"
	if last := s.dialed[len(s.dialed)-1]; last != want {
		t.Fatalf("last dial = %s, want %s", last, want)
	}
}

// ---------------------------------------------------------------------------------------
// The three-way diagnosis: routing, DNS, or the destination.
// ---------------------------------------------------------------------------------------

func TestAFailedDialNamesWhichLayerFailed(t *testing.T) {
	healthy := func() (time.Time, bool) { return time.Now(), true }
	stale := func() (time.Time, bool) { return time.Now().Add(-10 * time.Minute), true }
	never := func() (time.Time, bool) { return time.Time{}, true }

	okNames := &nameService{prefix: netip.MustParsePrefix(nsp), resolverOK: true, confirmed: true}
	badNames := &nameService{prefix: netip.MustParsePrefix(nsp)}

	for _, tc := range []struct {
		name      string
		handshake func() (time.Time, bool)
		names     *nameService
		want      string
	}{
		{"no handshake ever", never, okNames, "no recent WireGuard handshake"},
		{"handshake gone stale", stale, okNames, "no recent WireGuard handshake"},
		{"carrying, resolver unusable", healthy, badNames, "name resolution"},
		{"carrying, names resolve", healthy, okNames, "this is the destination"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &dnsStack{failDial: map[string]bool{"[2001:db8::1]:443": true}}
			d := &netDialer{stack: s, timeout: time.Second, names: tc.names, handshake: tc.handshake}
			_, err := d.Dial(context.Background(), "[2001:db8::1]:443")
			if err == nil {
				t.Fatalf("want a failure")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// The diagnosis must never echo the target: a hostname can itself be sensitive, and this
// sentence is printed to a shared terminal.
func TestTheDiagnosisNeverEchoesTheTarget(t *testing.T) {
	s := &dnsStack{failDial: map[string]bool{"secret-internal.example:443": true}}
	d := &netDialer{stack: s, timeout: time.Second,
		names:     &nameService{prefix: netip.MustParsePrefix(nsp), resolverOK: true, confirmed: true},
		handshake: func() (time.Time, bool) { return time.Now(), true }}
	_, err := d.Dial(context.Background(), "secret-internal.example:443")
	if err == nil {
		t.Fatalf("want a failure")
	}
	if strings.Contains(err.Error(), "secret-internal") {
		t.Fatalf("err = %q, must not name the target", err)
	}
}

// ---------------------------------------------------------------------------------------
// The wire parser. It reads bytes chosen by a resolver we do not control, so every malformed
// shape has to be a clean error: never a panic, never a loop, never a wrong address.
// ---------------------------------------------------------------------------------------

func TestParseAnswersRejectsMalformedMessages(t *testing.T) {
	hdr := func(qd, an uint16) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[4:], qd)
		binary.BigEndian.PutUint16(b[6:], an)
		return b
	}
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"shorter than a header", []byte{0, 1, 2}},
		{"question runs off the end", append(hdr(1, 0), 3, 'a', 'b')},
		{"record header truncated", append(append(hdr(1, 1), 0, 0, 28, 0, 1), 0xC0, 0x0C, 0, 28)},
		{"reserved label type", append(hdr(1, 0), 0x80, 0x00)},
		{"label longer than the message", append(hdr(1, 0), 63, 'a')},
		{"rdata past the end", append(append(hdr(1, 1), 0, 0, 28, 0, 1),
			0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 1, 2, 3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseAnswers(tc.msg, dnsTypeAAAA); err == nil {
				t.Fatalf("want a clean error, got none")
			}
		})
	}
}

// A compression pointer must terminate the name rather than be followed, so a pointer loop is
// unreachable by construction. This is the classic DNS parser crash and it must not exist here.
func TestASelfReferentialCompressionPointerTerminates(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, 0xC0, 0x0C, 0, 28, 0, 1) // a pointer at itself, then QTYPE/QCLASS
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = parseAnswers(msg, dnsTypeAAAA)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("parseAnswers did not terminate on a self-referential pointer")
	}
}

func TestParseAnswersReportsTheRcodeEvenWithNoAnswers(t *testing.T) {
	msg := make([]byte, 12)
	msg[3] = 0x85 // RA + REFUSED
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, 0, 0, 28, 0, 1) // root name, QTYPE, QCLASS
	rcode, addrs, err := parseAnswers(msg, dnsTypeAAAA)
	if err != nil || rcode != 5 || len(addrs) != 0 {
		t.Fatalf("(%d,%v,%v), want rcode 5 with no answers and no error", rcode, addrs, err)
	}
}

func TestBuildQueryRefusesNamesItCannotEmit(t *testing.T) {
	for _, name := range []string{
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a63456789012345678901234567890123456789012345678901234567890123.", 5) + "example",
		"a..b",
	} {
		if _, err := buildQuery(name, dnsTypeA); err == nil {
			t.Fatalf("buildQuery(%d bytes) accepted a name it cannot emit", len(name))
		}
	}
}

func TestBuildQueryRoundTripsThroughTheParser(t *testing.T) {
	q, err := buildQuery("Example.COM", dnsTypeAAAA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	name, qtype, _ := readQuestion(q)
	if name != "example.com." || qtype != dnsTypeAAAA {
		t.Fatalf("(%q,%d), want a lower-cased root-terminated name and AAAA", name, qtype)
	}
}

// A query with no OPT record cannot be answered with an Extended DNS Error, so a resolver that is
// broken and one that is deliberately refusing us arrive as the same bare rcode. Those two need
// opposite remedies, and telling them apart is the whole reason the OPT is on the wire. This asserts
// the additional section is really emitted and really well formed: a query that merely LOOKS right
// but sets ARCOUNT 0, or writes the OPT into the wrong section, buys us no diagnosis at all.
func TestBuildQueryCarriesAnOPTRecordSoTheResolverCanExplainItself(t *testing.T) {
	q, err := buildQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	if got := binary.BigEndian.Uint16(q[10:]); got != 1 {
		t.Fatalf("ARCOUNT = %d, want 1 - without it the OPT is invisible to the resolver", got)
	}

	// The OPT is the last 11 bytes: one zero byte for the root name, then TYPE, CLASS, TTL, RDLEN.
	const optLen = 1 + 2 + 2 + 4 + 2
	if len(q) < optLen {
		t.Fatalf("query is %d bytes, too short to hold an OPT at all", len(q))
	}
	opt := q[len(q)-optLen:]
	if opt[0] != 0 {
		t.Fatalf("OPT owner name = %#x, want the root label (0)", opt[0])
	}
	if got := binary.BigEndian.Uint16(opt[1:]); got != dnsTypeOPT {
		t.Fatalf("OPT TYPE = %d, want %d", got, dnsTypeOPT)
	}
	if got := binary.BigEndian.Uint16(opt[3:]); got != ednsUDPPayload {
		t.Fatalf("advertised payload = %d, want %d", got, ednsUDPPayload)
	}
	if got := binary.BigEndian.Uint32(opt[5:]); got != 0 {
		t.Fatalf("extended rcode/version/flags = %#x, want 0 (version 0, DO clear)", got)
	}
	if got := binary.BigEndian.Uint16(opt[9:]); got != 0 {
		t.Fatalf("RDLEN = %d, want 0 - we send no EDNS options", got)
	}

	// The question must still parse: an OPT appended over the top of the question would satisfy
	// every check above and still be a broken query.
	if name, qtype, _ := readQuestion(q); name != "example.com." || qtype != dnsTypeA {
		t.Fatalf("question reads (%q,%d) with the OPT present, want example.com./A", name, qtype)
	}
}

// ---------------------------------------------------------------------------------------
// Edge cases, part 1.
// ---------------------------------------------------------------------------------------

// A named resolver that BLACK-HOLES must not use up the budget the fallbacks need. On the real
// stack a silent dial blocks until its deadline; before each resolver had its own slice, the
// fallbacks were dialled on an expired context and reported as "did not answer" unasked.
func TestABlackHoledNamedResolverStillLetsTheFallbacksBeAsked(t *testing.T) {
	t.Setenv(ResolveOnHostEnv, "")
	named := netip.MustParseAddr("2a04:2a01:9:53:dead::1") // per-tenant, not on the fallback list
	fallback := agentPlaneResolvers[0]
	s := &dnsStack{
		blackhole: map[string]bool{named.String(): true},
		perResolver: map[string]*dnsStack{fallback.String(): {answers: map[string][]netip.Addr{
			key(recursionProbeName, dnsTypeA): controlA(),
		}}},
	}
	start := time.Now()
	ns := newNameService(context.Background(), s, named, netip.Prefix{})
	if !ns.confirmed || ns.resolver != fallback {
		t.Fatalf("confirmed=%v resolver=%v verdict=%q, want the agent-plane fallback confirmed",
			ns.confirmed, ns.resolver, ns.verdict)
	}
	if !strings.Contains(ns.verdict, "could not confirm") {
		t.Fatalf("verdict = %q, want the silent named resolver described as unconfirmed", ns.verdict)
	}
	if took := time.Since(start); took > nameServiceProbeTimeout+500*time.Millisecond {
		t.Fatalf("bring-up took %v, over the %v budget", took, nameServiceProbeTimeout)
	}
}

// Black-holed fallbacks are asked in parallel, so two of them cost one deadline, not two.
func TestBlackHoledFallbacksCostOneDeadlineNotOneEach(t *testing.T) {
	bh := map[string]bool{}
	for _, r := range fallbackResolvers() {
		bh[r.String()] = true
	}
	s := &dnsStack{blackhole: bh}
	n := &nameService{}
	start := time.Now()
	if _, ok, replied := n.probeFallbacks(context.Background(), s, netip.Addr{}); ok || replied {
		t.Fatalf("ok=%v replied=%v, want neither from silent resolvers", ok, replied)
	}
	if took := time.Since(start); took > perResolverProbe+500*time.Millisecond {
		t.Fatalf("took %v, want about one per-resolver deadline (%v)", took, perResolverProbe)
	}
}

// A reply that arrived but is not an answer to this query is a REPLY: it must not be called
// silence, must not confirm the resolver, and must not trigger the handshake retry.
func TestAGarbledReplyIsAReplyNotSilenceAndNeverConfirms(t *testing.T) {
	s := &dnsStack{garble: true, answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()}}
	res := (&nameService{}).probeRecursion(context.Background(), s, resolverAddr())
	if res.ok {
		t.Fatal("a reply carrying a different query ID confirmed the resolver")
	}
	if !res.replied {
		t.Fatal("a reply that arrived was classified as silence")
	}
	called := false
	settleNameService(context.Background(), s, resolverAddr(), netip.Prefix{},
		func(context.Context) bool { called = true; return true })
	if called {
		t.Fatal("a resolver that replied was retried as if it had been silent")
	}
}

// A bare REFUSED with no EDE does not say whose fault it is, so the verdict must not say either.
func TestABareRefusedIsNotStatedAsAWhisperFault(t *testing.T) {
	s := &dnsStack{rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 5}}
	_, verdict := (&nameService{}).pickResolver(context.Background(), s, resolverAddr())
	if strings.Contains(verdict, "fault on the Whisper side") {
		t.Fatalf("verdict = %q, blames Whisper for a refusal that gave no reason", verdict)
	}
	if !strings.Contains(verdict, "treated as a resolver that does not serve names") {
		t.Fatalf("verdict = %q, want the refusal described consistently with moving off it", verdict)
	}
}

// A refusal by POLICY (EDE Filtered) must not be routed around through a fallback that does not
// apply the policy. The fallback here answers everything; only the policy rule keeps it unused.
func TestAPolicyRefusalIsNotRoutedAroundThroughAFallback(t *testing.T) {
	t.Setenv(ResolveOnHostEnv, "")
	named := netip.MustParseAddr("2a04:2a01:9:53:dead::1")
	working := &dnsStack{answers: map[string][]netip.Addr{key(recursionProbeName, dnsTypeA): controlA()}}
	per := map[string]*dnsStack{}
	for _, r := range fallbackResolvers() {
		per[r.String()] = working
	}
	s := &dnsStack{
		rcodes:      map[string]uint8{key(recursionProbeName, dnsTypeA): 3},
		edes:        map[string]ede{key(recursionProbeName, dnsTypeA): {code: 17, text: "tenant dns policy"}},
		perResolver: per,
	}
	ns := newNameService(context.Background(), s, named, netip.Prefix{})
	if ns.resolver != named {
		t.Fatalf("resolver = %v, want the named resolver kept so its policy keeps applying", ns.resolver)
	}
	if !strings.Contains(ns.verdict, "your own DNS policy") {
		t.Fatalf("verdict = %q, want the resolver's own reason", ns.verdict)
	}
}

// CONTROL for the rule above: EDE 18 (Prohibited, "this resolver does not serve you") is about the
// resolver, not the names, so falling back is right.
func TestAProhibitedRefusalStillFallsBack(t *testing.T) {
	named := netip.MustParseAddr("2a04:2a01:9:53:dead::1")
	fallback := agentPlaneResolvers[0]
	s := &dnsStack{
		rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 5},
		edes:   map[string]ede{key(recursionProbeName, dnsTypeA): {code: 18}},
		perResolver: map[string]*dnsStack{fallback.String(): {answers: map[string][]netip.Addr{
			key(recursionProbeName, dnsTypeA): controlA(),
		}}},
	}
	ns := newNameService(context.Background(), s, named, netip.Prefix{})
	if !ns.confirmed || ns.resolver != fallback {
		t.Fatalf("resolver=%v confirmed=%v, want the fallback for a resolver that does not serve us", ns.resolver, ns.confirmed)
	}
}

// A named resolver that answered with a plain refusal is known not to serve names, so an
// unconfirmed tunnel stays on the first agent-plane fallback instead; one that was only silent
// is kept, because it may just not have been reachable yet.
func TestAnUnconfirmedTunnelStaysOnTheBestResolver(t *testing.T) {
	t.Setenv(ResolveOnHostEnv, "")
	named := netip.MustParseAddr("2a04:2a01:9:53:dead::1")
	refused := &dnsStack{rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 2}} // SERVFAIL everywhere
	if ns := newNameService(context.Background(), refused, named, netip.Prefix{}); ns.resolver != agentPlaneResolvers[0] {
		t.Fatalf("refused: resolver = %v, want %v", ns.resolver, agentPlaneResolvers[0])
	}
	silent := &dnsStack{refuseConnect: true}
	if ns := newNameService(context.Background(), silent, named, netip.Prefix{}); ns.resolver != named {
		t.Fatalf("silent: resolver = %v, want the named %v kept", ns.resolver, named)
	}
}

// With no resolver confirmed, RFC 7050 discovery never ran; without a declaration the prefix must
// be the agent-plane one, never the office-plane well-known prefix.
func TestAnUnconfirmedTunnelWrapsIntoTheAgentPlanePrefix(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "")
	ns := newNameService(context.Background(), &dnsStack{refuseConnect: true}, resolverAddr(), netip.Prefix{})
	if ns.prefix != agentPlaneNAT64 {
		t.Fatalf("prefix = %v, want the agent-plane %v", ns.prefix, agentPlaneNAT64)
	}
	declared := netip.MustParsePrefix(nsp)
	if ns := newNameService(context.Background(), &dnsStack{refuseConnect: true}, resolverAddr(), declared); ns.prefix != declared {
		t.Fatalf("prefix = %v, want the declared %v kept", ns.prefix, declared)
	}
}

// A lookup on the dial path is bounded on its own, so a black-holed resolver leaves the rest of
// the dial a live context.
func TestALookupOnABlackHoledResolverIsBounded(t *testing.T) {
	ns := &nameService{resolver: resolverAddr(), resolverOK: true}
	s := &dnsStack{blackhole: map[string]bool{resolverAddr().String(): true}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := ns.resolve(ctx, s, "example.com", dnsTypeAAAA); err == nil {
		t.Fatal("a black-holed lookup must fail")
	}
	if took := time.Since(start); took > perQueryTimeout+time.Second {
		t.Fatalf("lookup took %v, want it bounded near %v", took, perQueryTimeout)
	}
	if ctx.Err() != nil {
		t.Fatal("the dial's own context was used up by one lookup")
	}
}

// The background retry: a dial issued while the retry runs gets the settled answer, and a dial
// whose deadline ends first gets the first answer, never a half-built one.
func TestADialWaitsForTheSettledNamesWithinItsDeadline(t *testing.T) {
	first := &nameService{prefix: netip.MustParsePrefix(nsp), resolver: resolverAddr(), resolverOK: true}
	final := &nameService{prefix: netip.MustParsePrefix(nsp), resolver: agentPlaneResolvers[1], resolverOK: true, confirmed: true}
	h := newSettledNames(first)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if got := h.get(ctx); got != first {
		t.Fatal("a dial whose deadline ended before settling must get the first answer")
	}
	cancel()
	go func() { time.Sleep(20 * time.Millisecond); h.settle(final) }()
	if got := h.get(context.Background()); got != final {
		t.Fatal("a dial must get the settled answer once it is published")
	}
}

func TestWaitForHandshakeReturnsOnTheFirstHandshakeAndRespectsItsDeadline(t *testing.T) {
	calls := 0
	read := func() (time.Time, bool) {
		calls++
		if calls < 3 {
			return time.Time{}, true
		}
		return time.Now(), true
	}
	if !waitForHandshake(context.Background(), read, time.Millisecond) {
		t.Fatal("want true once a handshake is reported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if waitForHandshake(ctx, func() (time.Time, bool) { return time.Time{}, true }, time.Millisecond) {
		t.Fatal("want false when the deadline ends with no handshake")
	}
}

// ---------------------------------------------------------------------------------------
// Edge cases, part 2.
// ---------------------------------------------------------------------------------------

// An IPv6 literal needs no resolver and no prefix, so it never waits for the background retry.
func TestAnIPv6LiteralDialDoesNotWaitForTheNameRetry(t *testing.T) {
	first := &nameService{prefix: netip.MustParsePrefix(nsp), resolver: resolverAddr(), resolverOK: true}
	d := &netDialer{stack: &dnsStack{}, timeout: 5 * time.Second, names: first, pending: newSettledNames(first)}
	start := time.Now()
	if _, err := d.Dial(context.Background(), "[2001:db8::1]:443"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a v6 literal waited %v for a name check it does not need", took)
	}
}

// After a policy refusal the verdict must not suggest the host resolver (it would bypass the policy
// it just named), and the prefix is still MEASURED from the resolver, which answers ipv4only.arpa.
func TestAPolicyRefusalOffersNoBypassAndStillDiscoversThePrefix(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "")
	named := netip.MustParseAddr("2a04:2a01:9:53:dead::1")
	s := &dnsStack{
		rcodes:  map[string]uint8{key(recursionProbeName, dnsTypeA): 3},
		edes:    map[string]ede{key(recursionProbeName, dnsTypeA): {code: 17, text: "tenant dns policy"}},
		answers: map[string][]netip.Addr{key(wellKnownIPv4OnlyName, dnsTypeAAAA): {synth(t, nsp, "192.0.0.170")}},
	}
	ns := newNameService(context.Background(), s, named, netip.Prefix{})
	if strings.Contains(ns.verdict, ResolveOnHostEnv) {
		t.Fatalf("verdict = %q, offers a bypass of the policy it just named", ns.verdict)
	}
	if ns.prefix.String() != nsp {
		t.Fatalf("prefix = %v (%s), want %s measured from the resolver", ns.prefix, ns.prefixSource, nsp)
	}
}
