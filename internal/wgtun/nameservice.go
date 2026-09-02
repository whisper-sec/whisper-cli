// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// nameservice.go is the tunnel's answer to two questions it used to guess at, and to the
// third question a user is left holding when the answer is wrong.
//
// # 1. Which NAT64 prefix does the far end actually translate?
//
// nat64.go wraps an IPv4 destination into a NAT64 /96 so it can leave over a v6-only
// interface. Both ends have to name the SAME /96 or the packet lands somewhere else, and
// until this file existed the client simply assumed the RFC 6052 well-known prefix. On the
// live fleet that assumption is wrong in a way that is worse than a failure: the well-known
// prefix IS translated, by the office/staff translator, which SNATs to the shared edge IPv4
// address instead of the dedicated agent one. So a working connection quietly egressed from
// the wrong address and gave up the reputation isolation the dedicated prefix exists for.
// Measured, one tunnel, two prefixes, same second: 64:ff9b::/96 came out of 108.61.167.17
// and 2a04:2a00:64::/96 came out of 203.0.113.7.
//
// The fix is not a better constant. It is to ASK, with the mechanism designed for exactly
// this: RFC 7050. ipv4only.arpa has two well-known A records and nothing else, so a DNS64
// resolver's synthesised AAAA for it spells out the prefix it synthesises into. We query the
// resolver the box handed us, read the prefix off the answer, and the two ends agree by
// construction rather than by coincidence. An operator override still wins, because someone
// who set WHISPER_NAT64_PREFIX meant it.
//
// # 2. Is the resolver the box handed us one we may actually use?
//
// The Tier-1 wg config carries `DNS = <an in-tunnel resolver>`, and the netstack resolves
// every socks5h name through it. If it refuses us, every name fails, every failure looks
// identical, and the user cannot tell a DNS fault from a routing fault from a policy one -
// which is precisely the ambiguity behind "I enabled route t1 it killed my network".
// Measured from inside a live tunnel: that resolver answers NOERROR for Whisper's own names
// and REFUSED for github.com, api.ipify.org and ipv4only.arpa alike.
//
// So we probe it once at bring-up, and we FAIL OPEN: names are resolved on this host instead,
// and the tunnel still carries the traffic. That trades away half of the socks5h property
// (the lookup no longer leaves from the /128), which is a real cost and therefore one we say
// out loud rather than absorb silently. Conservative in what we emit: the user is told which
// of the three it was, in one sentence, with the resolver named.
//
// # 3. Everything here is bounded and best-effort.
//
// Bring-up runs the probe once under a short deadline. A probe that times out costs the
// prefix refinement and nothing else: the tunnel comes up, the previous defaults apply, and
// the verdict says which. A root always answers; so does this.

// The RFC 7050 section 3 discovery name and its two well-known A records. A DNS64 resolver
// MUST synthesise AAAA for this name, and because the v4 side is fixed and public, the low 32
// bits of whatever comes back identify the prefix unambiguously.
const wellKnownIPv4OnlyName = "ipv4only.arpa."

var wellKnownIPv4OnlyAddrs = [2]netip.Addr{
	netip.AddrFrom4([4]byte{192, 0, 0, 170}),
	netip.AddrFrom4([4]byte{192, 0, 0, 171}),
}

// WhisperPublicResolverEnv lets an operator name the resolver the ladder's second rung uses,
// for a self-hosted deployment whose anycast resolver is not the public one. Liberal in what
// we accept, and it changes nothing for the overwhelming majority who set nothing.
const WhisperPublicResolverEnv = "WHISPER_RESOLVER"

// whisperPublicResolver is the second rung of the ladder in pickResolver: Whisper's own public
// anycast resolver, dialled THROUGH the tunnel so the lookup still leaves from the agent's
// /128. It is deliberately a well-known public address and not infrastructure detail: it is the
// same resolver anyone can point a laptop at, it is reachable from inside every tunnel by
// construction, and having it here means a broken per-tenant resolver degrades to a slower
// correct answer instead of to no answer at all.
func whisperPublicResolver() netip.Addr {
	if raw := strings.TrimSpace(os.Getenv(WhisperPublicResolverEnv)); raw != "" {
		if a, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
			return a
		}
	}
	return netip.MustParseAddr("2a04:2a00::53")
}

// DNS record types and the rcodes we name in a verdict. Spelled out rather than imported so
// this file needs nothing beyond the standard library on the tunnel's bring-up path.
const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	dnsClassIN  uint16 = 1
)

var rcodeNames = map[uint8]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

func rcodeName(rc uint8) string {
	if n, ok := rcodeNames[rc]; ok {
		return n
	}
	return fmt.Sprintf("rcode %d", rc)
}

// nameService is what one tunnel settled on for names and for IPv4: the NAT64 prefix it wraps
// into, where that prefix came from, whether the in-tunnel resolver may be used, and the one
// sentence that says so. It is built once at bring-up and then read-only, so a dial never
// re-probes and every dial of one tunnel agrees with every other.
type nameService struct {
	prefix       netip.Prefix
	prefixSource string
	// resolver is the in-tunnel resolver, valid only when resolverOK. When it is not OK the
	// tunnel still carries traffic; names are resolved on this host instead.
	resolver   netip.Addr
	resolverOK bool
	// verdict is empty when everything the box promised holds. Otherwise it is one plain
	// sentence naming what did not, for the user, never for a log parser.
	verdict string
	// hostLookup is the fail-open leg: this host's own resolver, used only when the in-tunnel
	// one is unusable. A field rather than a direct call so a test can drive the fallback
	// without depending on the machine it runs on having a working resolver and a network.
	hostLookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// lookupOnThisHost is the default hostLookup: the ordinary system resolver.
func lookupOnThisHost(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, strings.TrimSuffix(host, "."))
}

// newNameService probes the tunnel once and settles both questions. It NEVER returns nil and
// never fails: an unreachable resolver, a refusing resolver and a resolver with no DNS64 are
// all ordinary outcomes with their own sentence, because a tunnel that came up must keep
// working while it tells you what is degraded about it.
func newNameService(ctx context.Context, stack tunnelStack, resolver netip.Addr) *nameService {
	envPrefix, envSource := NAT64Prefix()
	_, overridden := nat64PrefixOverride()
	ns := &nameService{prefix: envPrefix, prefixSource: envSource, hostLookup: lookupOnThisHost}

	chosen, why := ns.pickResolver(ctx, stack, resolver)
	ns.verdict = why
	if !chosen.IsValid() {
		return ns // no resolver in the tunnel will serve us; resolve() falls back to this host
	}
	ns.resolver, ns.resolverOK = chosen, true

	// The AAAA half of the RFC 7050 question: only a DNS64 resolver synthesises one, and the
	// synthesis spells out the prefix it synthesises into.
	_, answers, aerr := dnsQuery(ctx, stack, chosen, wellKnownIPv4OnlyName, dnsTypeAAAA)
	if aerr != nil {
		answers = nil
	}
	discovered, derr := prefixFromIPv4OnlyAnswers(answers)
	switch {
	case derr != nil && !overridden:
		// The resolver answers, but it is not synthesising. Names with only an A record cannot
		// come back as AAAA, so dialV4OnlyName is what covers them - and it can, because the
		// resolver is usable. Keep the default prefix and say which one we are wrapping into.
		ns.appendVerdict("the resolver " + chosen.String() + " is not synthesising IPv6 addresses" +
			" for IPv4-only names (no DNS64), so IPv4 destinations are resolved and wrapped by" +
			" this client into " + ns.prefix.String() + " instead.")
	case derr == nil && overridden:
		// An operator said which prefix to use. Obey it - but if the far end says something
		// different, that is worth one line, because the two disagreeing is the whole bug class.
		if discovered != ns.prefix {
			ns.appendVerdict("WHISPER_NAT64_PREFIX pins " + ns.prefix.String() + ", but the resolver" +
				" synthesises into " + discovered.String() + ". Using the pinned value as asked;" +
				" unset it to follow the network.")
		}
	case derr == nil:
		ns.prefix, ns.prefixSource = discovered, "RFC 7050 discovery via "+chosen.String()
	}
	return ns
}

// pickResolver walks the fail-open ladder and returns the resolver to use inside the tunnel,
// plus the sentence the user is owed when it is not the one the box named.
//
// The ladder, in order, and the reason for the order:
//
// 1. THE RESOLVER THE CONTROL PLANE NAMED. Conservative in what we do: the box said which
// resolver this agent should use, and if it works we use it and say nothing at all.
// 2. WHISPER'S PUBLIC ANYCAST RESOLVER, reached THROUGH the tunnel. Still Whisper, still
// sourced from the agent's /128, so the socks5h property that a name never leaks to the
// local network survives. This rung exists because rung 1 can be broken in a way the agent
// cannot fix while rung 3 is absent entirely: measured on a lab guest whose only resolver
// is a stub with no upstream, rung 1 answered NXDOMAIN for everything outside Whisper and
// rung 3 could not resolve a single name, so without this the tunnel came up and carried
// nothing addressed by name.
// 3. THIS HOST'S OWN RESOLVER (the caller falls back to it when we return an invalid addr).
// Last, because it gives up the property that the lookup leaves from the /128. That cost is
// real, so it is stated rather than absorbed.
//
// Each rung is probed with the SAME control question: an A query for the RFC 7050 name, whose A
// records exist and are fixed, so any resolver that recurses at all answers it and one that does
// not is one that will not resolve github.com either. Asking the control FIRST is what separates
// "this resolver will not serve me" from "this resolver has no DNS64" - an earlier draft read a
// missing AAAA as a refusal, which would have condemned a perfectly good resolver and sent every
// name to the host for no reason. Measured on the live fleet, the per-tenant resolver answers
// NXDOMAIN for that name, so the distinction is not hypothetical.
func (n *nameService) pickResolver(ctx context.Context, stack tunnelStack, named netip.Addr) (netip.Addr, string) {
	if !named.IsValid() {
		if fallback, ok := n.probeRecursion(ctx, stack, whisperPublicResolver()); ok {
			return fallback, "the control plane returned no in-tunnel resolver, so names are being" +
				" resolved through " + fallback.String() + " inside the tunnel instead. They still" +
				" leave from your /128."
		}
		return netip.Addr{}, "the control plane returned no in-tunnel resolver and no resolver" +
			" inside the tunnel answered, so names are being resolved on this host. They no longer" +
			" leave from your /128. The tunnel itself is carrying traffic - this is DNS, not routing."
	}
	if _, ok := n.probeRecursion(ctx, stack, named); ok {
		return named, "" // exactly what the box asked for, and it works: say nothing
	}
	// Rung 1 is broken. Say precisely how, because "the resolver we were handed does not resolve"
	// is a Whisper-side fault and the user must not be left thinking it is theirs.
	broken := "the in-tunnel resolver " + named.String() + " does not resolve names outside" +
		" Whisper (it does not answer for " + strings.TrimSuffix(wellKnownIPv4OnlyName, ".") +
		", which every recursive resolver answers). This is a fault on the Whisper side, not on" +
		" yours, and the tunnel is carrying traffic normally. "
	if fallback, ok := n.probeRecursion(ctx, stack, whisperPublicResolver()); ok {
		return fallback, broken + "Names are being resolved through " + fallback.String() +
			" inside the tunnel instead, so they still leave from your /128."
	}
	return netip.Addr{}, broken + "No resolver inside the tunnel answered, so names are being" +
		" resolved on this host instead and no longer leave from your /128."
}

// probeRecursion asks one resolver the control question and reports whether it recurses.
func (n *nameService) probeRecursion(ctx context.Context, stack tunnelStack, r netip.Addr) (netip.Addr, bool) {
	if !r.IsValid() {
		return netip.Addr{}, false
	}
	rcode, answers, err := dnsQuery(ctx, stack, r, wellKnownIPv4OnlyName, dnsTypeA)
	return r, err == nil && rcode == 0 && len(answers) > 0
}

// appendVerdict adds a second sentence without losing the first: a tunnel can be degraded in
// more than one way at once, and reporting only the last fault found is how the other gets lost.
func (n *nameService) appendVerdict(s string) {
	if n.verdict == "" {
		n.verdict = s
		return
	}
	n.verdict += " " + s
}

// prefixFromIPv4OnlyAnswers reads the NAT64 /96 off a set of synthesised ipv4only.arpa AAAAs
// (RFC 7050 section 3). An answer only counts when its low 32 bits are one of the two
// well-known IPv4 addresses: that is what makes the reading a proof rather than a guess, and
// it is why a resolver that returns some unrelated AAAA cannot mislead us into wrapping every
// IPv4 destination into a prefix nothing translates.
//
// Only /96 is read, matching ParseNAT64Prefix: RFC 6052 defines five other lengths whose
// embedding straddles the reserved byte, and a node that guessed the wrong one would produce
// addresses that are valid, routable and wrong.
func prefixFromIPv4OnlyAnswers(answers []netip.Addr) (netip.Prefix, error) {
	for _, a := range answers {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		b := a.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if embedded != wellKnownIPv4OnlyAddrs[0] && embedded != wellKnownIPv4OnlyAddrs[1] {
			continue
		}
		var p [16]byte
		copy(p[:12], b[:12])
		return netip.PrefixFrom(netip.AddrFrom16(p), 96), nil
	}
	return netip.Prefix{}, errors.New("no synthesised ipv4only.arpa answer")
}

// resolve returns the addresses of one family for host, from the in-tunnel resolver when we
// may use it and from this host's own resolver when we may not. The second is the fail-open
// half: it costs the socks5h property that the lookup leaves from the /128, which
// newNameService has already said out loud, and it is the difference between a connection
// that works and one that does not.
func (n *nameService) resolve(ctx context.Context, stack tunnelStack, host string, qtype uint16) ([]netip.Addr, error) {
	if n.resolverOK {
		rcode, answers, err := dnsQuery(ctx, stack, n.resolver, dnsName(host), qtype)
		switch {
		case err != nil:
			return nil, err
		case rcode != 0:
			return nil, errors.New("the in-tunnel resolver answered " + rcodeName(rcode))
		case len(answers) == 0:
			return nil, errNoSuchAddress
		}
		return answers, nil
	}
	lookup := n.hostLookup
	if lookup == nil {
		lookup = lookupOnThisHost
	}
	network := "ip4"
	want4 := true
	if qtype == dnsTypeAAAA {
		network, want4 = "ip6", false
	}
	addrs, err := lookup(ctx, network, host)
	if err != nil {
		return nil, errNoSuchAddress
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() == want4 {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errNoSuchAddress
	}
	return out, nil
}

// errNoSuchAddress is "the name has no address of that family", which is an ANSWER and not a
// fault. It is a sentinel so the dual-stack check below can tell it from a resolver that
// could not be asked at all.
var errNoSuchAddress = errors.New("the name has no address of that family")

// dnsQuery asks one resolver one question over the tunnel, on TCP.
//
// TCP rather than UDP on purpose: it is one dial through the same seam every other dial in
// this package uses (so a test drives it without a live gVisor stack), the two-byte length
// prefix makes the read exact, and there is no truncation case to get wrong. This runs at
// bring-up and on a dial that already failed, never on a healthy hot path, so the extra
// round trip costs nothing that matters.
//
// It returns the rcode even for a refusal, because "the resolver answered REFUSED" and "the
// resolver could not be reached" are different faults with different remedies, and collapsing
// them into one error is how a user ends up guessing.
func dnsQuery(ctx context.Context, stack tunnelStack, server netip.Addr, name string, qtype uint16) (uint8, []netip.Addr, error) {
	q, err := buildQuery(name, qtype)
	if err != nil {
		return 0, nil, err
	}
	conn, err := stack.DialContext(ctx, "tcp", net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return 0, nil, errors.New("the in-tunnel resolver could not be reached")
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		return 0, nil, errors.New("the in-tunnel resolver closed the connection")
	}
	var lenBuf [2]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return 0, nil, errors.New("the in-tunnel resolver returned no answer")
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 65535 {
		return 0, nil, errors.New("the in-tunnel resolver returned a malformed answer")
	}
	resp := make([]byte, n)
	if _, err := readFull(conn, resp); err != nil {
		return 0, nil, errors.New("the in-tunnel resolver returned a truncated answer")
	}
	return parseAnswers(resp, qtype)
}

// readFull is io.ReadFull without pulling io into a file that needs nothing else from it.
func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
		if n == 0 {
			return got, errors.New("short read")
		}
	}
	return got, nil
}

// dnsName normalises a host to a root-terminated, lower-case DNS name.
func dnsName(host string) string {
	h := strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	if !strings.HasSuffix(h, ".") {
		h += "."
	}
	return h
}

// buildQuery renders a standard recursive query. Names are validated on the way in - a label
// over 63 bytes or a name over 255 is refused here rather than emitted as a packet no server
// will accept. Conservative in what we do.
func buildQuery(name string, qtype uint16) ([]byte, error) {
	labels := strings.Split(strings.TrimSuffix(dnsName(name), "."), ".")
	body := make([]byte, 0, 32)
	for _, l := range labels {
		if l == "" {
			return nil, errors.New("dns: empty label")
		}
		if len(l) > 63 {
			return nil, errors.New("dns: label longer than 63 bytes")
		}
		body = append(body, byte(len(l)))
		body = append(body, l...)
	}
	body = append(body, 0)
	if len(body) > 255 {
		return nil, errors.New("dns: name longer than 255 bytes")
	}
	msg := make([]byte, 12, 12+len(body)+4)
	binary.BigEndian.PutUint16(msg[0:], uint16(rand.Intn(0xFFFF))) //nolint:gosec // a query id, not a secret
	binary.BigEndian.PutUint16(msg[2:], 0x0100)                    // RD
	binary.BigEndian.PutUint16(msg[4:], 1)                         // QDCOUNT
	msg = append(msg, body...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, nil
}

// parseAnswers walks a response and returns its rcode plus the addresses of the requested
// type. Every step is bounds-checked and compression pointers are followed under a hard jump
// budget, because this parser reads bytes a resolver we do not control chose: a malformed
// answer must be a clean error, never a loop and never a panic.
func parseAnswers(msg []byte, qtype uint16) (uint8, []netip.Addr, error) {
	if len(msg) < 12 {
		return 0, nil, errors.New("dns: short header")
	}
	rcode := uint8(msg[3] & 0x0F)
	qdcount := int(binary.BigEndian.Uint16(msg[4:]))
	ancount := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qdcount; i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return rcode, nil, err
		}
		off = next + 4 // QTYPE + QCLASS
		if off > len(msg) {
			return rcode, nil, errors.New("dns: truncated question")
		}
	}
	out := make([]netip.Addr, 0, ancount)
	for i := 0; i < ancount; i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return rcode, nil, err
		}
		off = next
		if off+10 > len(msg) {
			return rcode, nil, errors.New("dns: truncated record header")
		}
		rrType := binary.BigEndian.Uint16(msg[off:])
		rdLen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+rdLen > len(msg) {
			return rcode, nil, errors.New("dns: rdata past the end of the message")
		}
		if rrType == qtype {
			switch {
			case qtype == dnsTypeAAAA && rdLen == 16:
				var b [16]byte
				copy(b[:], msg[off:off+16])
				out = append(out, netip.AddrFrom16(b))
			case qtype == dnsTypeA && rdLen == 4:
				var b [4]byte
				copy(b[:], msg[off:off+4])
				out = append(out, netip.AddrFrom4(b))
			}
		}
		off += rdLen
	}
	return rcode, out, nil
}

// skipName advances past a (possibly compressed) name and returns the offset just after it.
// A pointer ends the name in the wire stream, so the first pointer is the last thing we need
// to read - we never follow it, which makes a pointer loop unreachable by construction rather
// than merely bounded.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("dns: name past the end of the message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, errors.New("dns: truncated compression pointer")
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, errors.New("dns: reserved label type")
		case l > 63:
			return 0, errors.New("dns: label longer than 63 bytes")
		default:
			off += 1 + l
		}
	}
}
