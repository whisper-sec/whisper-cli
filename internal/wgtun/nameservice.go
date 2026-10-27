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
	"sync"
	"sync/atomic"
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
// and 2a04:2a00:64::/96 came out of 95.179.179.56.
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
// So we probe it at bring-up, and the answer decides which resolver INSIDE the tunnel we use.
// Names never leave the tunnel on their own. This file used to fall back to this host's
// resolver when no in-tunnel resolver answered, and that took every lookup off the /128 on the
// strength of one unanswered probe, often a probe that only ran before the tunnel carried its
// first packet. A lookup that fails inside the tunnel is a visible, explained failure; a lookup
// that quietly moved to the local network is an identity leak nobody asked for. So the host
// resolver is used only when WHISPER_RESOLVE_ON_HOST=1 says so.
//
// # 3. One unanswered probe is not a finding.
//
// A probe that got NO reply at all says nothing about the resolver: it can run before the tunnel,
// or the box's own path back to the resolver's /128, can carry it. Which leg was silent in the
// field report is not measured, so the code does not assume one: bring-up waits briefly for the
// first handshake before probing, and a silent probe is asked again in the background once the
// handshake has landed (twice, spaced). If it is still silent the user hears "could not confirm",
// never "a fault on the Whisper side". A resolver that REPLIED with a refusal or an error is
// different: that is an answer, and it is reported as one.
//
// # 4. Everything here is bounded and best-effort.
//
// Each probe runs under a short deadline, and the wait for the first handshake has its own. A
// probe that times out costs the prefix refinement and nothing else: the tunnel comes up, the
// previous defaults apply, and the verdict says which.

// The RFC 7050 section 3 discovery name and its two well-known A records. A DNS64 resolver
// MUST synthesise AAAA for this name, and because the v4 side is fixed and public, the low 32
// bits of whatever comes back identify the prefix unambiguously.
const wellKnownIPv4OnlyName = "ipv4only.arpa."

// recursionProbeName is the control question pickResolver asks each rung, and it is deliberately
// NOT wellKnownIPv4OnlyName.
//
// The RFC 7050 name is the right question for NAT64 DISCOVERY and the wrong one for "does this
// resolver serve me". The Whisper resolver answers it unconditionally, by design: a tenant whose policy is
// `default: block` still gets an answer for it while everything else is sinkholed, so a resolver
// that refuses every real name still passes. Measured
// on a live tunnel: the per-tenant resolver returned NXDOMAIN for example.com while passing this
// probe, so resolverOK latched true, the rung-1 rejection note never printed, rung 2 was never
// reached, and the dialer went on to blame the destination. A control the system guarantees to
// answer is not a control.
//
// a.root-servers.net is the opposite: no special case anywhere in our stack, stable for decades,
// and a resolver that cannot answer it cannot serve this user. It is asked for A because the point
// is recursion, not address family.
const recursionProbeName = "a.root-servers.net."

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
	return fallbackResolvers()[0]
}

// agentPlaneResolvers are the shared DNS64 resolvers that belong to the AGENT plane, in the
// address space an agent's own tunnel routes.
//
// Why they exist as a distinct list. The office/staff anycast and the agent resolvers are two
// different planes with two different NAT64 translators, and each synthesises the prefix that
// its OWN path can translate. Measured from inside a live agent tunnel on 2026-09-03, asking
// each of them for ipv4only.arpa:
//
//	2a04:2a01:0:53::1        2a04:2a00:64::c000:aa   agent plane, routed via wg-ns
//	2a04:2a01:0:53:8000::1   2a04:2a00:64::c000:aa   agent plane, routed via wg-ns
//	2a04:2a00::53            64:ff9b::c000:aa        office plane, via the edge nat64
//
// Neither resolver is wrong; each is right for its own plane. What was wrong was falling back
// ACROSS planes, because the agent then adopts a prefix whose translator sits on a path its
// tunnel never traverses, and every IPv4-only destination becomes a silent black hole. A name
// that resolves to an address nothing can reach is worse than a name that does not resolve,
// because the failure arrives later and looks like the destination's fault.
var agentPlaneResolvers = []netip.Addr{
	netip.MustParseAddr("2a04:2a01:0:53::1"),
	netip.MustParseAddr("2a04:2a01:0:53:8000::1"),
}

// fallbackResolvers is the ordered candidate list for the ladder's second rung.
//
// An explicit WHISPER_RESOLVER wins outright and alone: an operator naming a resolver has said
// which one they want, and quietly trying others after it would be us overruling them.
//
// Otherwise the agent-plane resolvers come first and the office anycast last. It stays on the
// list because it does resolve names, and a slow correct answer beats no answer when both agent
// resolvers are unreachable; it is simply no longer the FIRST thing tried, which is what made a
// cross-plane prefix the normal outcome rather than the desperate one.
func fallbackResolvers() []netip.Addr {
	if raw := strings.TrimSpace(os.Getenv(WhisperPublicResolverEnv)); raw != "" {
		if a, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
			return []netip.Addr{a}
		}
	}
	out := make([]netip.Addr, 0, len(agentPlaneResolvers)+1)
	out = append(out, agentPlaneResolvers...)
	return append(out, netip.MustParseAddr("2a04:2a00::53"))
}

// DNS record types and the rcodes we name in a verdict. Spelled out rather than imported so
// this file needs nothing beyond the standard library on the tunnel's bring-up path.
const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	// dnsTypeOPT is the pseudo-record that carries EDNS. It is a query-side capability
	// advertisement, not a question: without it a resolver may not send us an Extended DNS Error.
	dnsTypeOPT uint16 = 41
	// ednsUDPPayload is the requestor's advertised payload size, carried in the OPT CLASS field.
	ednsUDPPayload uint16 = 1232
	dnsClassIN     uint16 = 1
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
	// resolver is the in-tunnel resolver every name is asked of, valid only when resolverOK.
	// resolverOK says one is in use; confirmed says it answered the control question. An
	// unconfirmed resolver is still used, because a name that fails inside the tunnel is better
	// than one that silently leaves it.
	resolver   netip.Addr
	resolverOK bool
	confirmed  bool
	// namedRefused: the named resolver replied with something other than an answer, and not a
	// policy refusal, so it is known not to serve names.
	namedRefused bool
	// policyRefused: the named resolver refused by policy (EDE 15 to 17), so names stay on it.
	policyRefused bool
	// silent: no resolver replied at all in the walk that settled this service, so the answer is
	// worth asking again once the tunnel carries traffic.
	silent bool
	// onHost sends names to this host's own resolver instead. It is set ONLY when no in-tunnel
	// resolver was confirmed AND the user asked for it with WHISPER_RESOLVE_ON_HOST=1, because
	// it gives up the property that a lookup leaves from the /128.
	onHost bool
	// verdict is empty when everything the box promised holds. Otherwise it is one plain
	// sentence naming what did not, for the user, never for a log parser.
	verdict string
	// hostLookup is this host's own resolver, used only when onHost is set. A field rather than a direct call so a test can drive the fallback
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
//
// declared is the prefix op:connect NAMED for this box, or the zero Prefix when it named
// none. It sits THIRD in the ladder, and the order is the whole point:
//
//  1. WHISPER_NAT64_PREFIX, an operator who said and meant it.
//  2. RFC 7050 discovery, a MEASUREMENT of the live path. It outranks the declaration because a
//     box can be reconfigured between the connect and the next packet, and because a declaration
//     that disagrees with the wire is the bug we want reported, not obeyed.
//  3. The declaration, which did not exist before it was added; the guess below
//     took its place.
//  4. The RFC 6052 well-known prefix, a guess, and now the last resort rather than the third.
func newNameService(
	ctx context.Context, stack tunnelStack, resolver netip.Addr, declared netip.Prefix,
) *nameService {
	return settleNameService(ctx, stack, resolver, declared, nil)
}

// settledNames holds a tunnel's name service while a silent first probe is asked again in the
// background. Start must return promptly, because the caller's connect budget also has to
// cover op:connect and the verify, so the retry cannot sit on the bring-up path. Instead the first
// answer is published at once, a dial waits for the settled one as long as its own deadline allows,
// and the swap is one atomic store, so a reader sees either answer whole and never a half-built one.
type settledNames struct {
	cur   atomic.Pointer[nameService]
	ready chan struct{}
}

func newSettledNames(first *nameService) *settledNames {
	h := &settledNames{ready: make(chan struct{})}
	h.cur.Store(first)
	return h
}

// settle publishes the final answer and releases every waiting dial. Called exactly once.
func (h *settledNames) settle(final *nameService) {
	if final != nil {
		h.cur.Store(final)
	}
	close(h.ready)
}

// get waits for the settled answer, or until ctx ends, and returns the best answer so far.
func (h *settledNames) get(ctx context.Context) *nameService {
	select {
	case <-h.ready:
	case <-ctx.Done():
	}
	return h.cur.Load()
}

// now is the best answer so far, without waiting.
func (h *settledNames) now() *nameService { return h.cur.Load() }

// ResolveOnHostEnv opts a tunnel into resolving names on this host when no resolver inside the
// tunnel could be confirmed. Off by default: it moves every lookup off the agent's /128, and
// that is a choice a person makes, never one the client makes for them.
const ResolveOnHostEnv = "WHISPER_RESOLVE_ON_HOST"

func resolveOnHostAsked() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(ResolveOnHostEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// firstHandshakeWait bounds how long a silent probe waits for the tunnel's first handshake before it
// is asked again. It must cover wireguard-go's first initiation being lost: the retransmit comes
// after REKEY_TIMEOUT (5 s) plus up to 333 ms of jitter, then one round trip. It is paid only when
// the first probe heard nothing at all, and only in the background (see Start), so a healthy
// bring-up never spends it and a dial waits for it only as long as its own deadline allows.
const firstHandshakeWait = 11 * time.Second

// preProbeHandshakeWait is how long bring-up waits for the first handshake BEFORE the first probe.
// A healthy tunnel handshakes in one round trip, so it pays only that; a probe sent before the
// tunnel can carry it is a probe that can only come back silent.
const preProbeHandshakeWait = 1500 * time.Millisecond

// secondRetryAfter spaces the last background retry, for a path that converges after the
// handshake (the box's route back to the resolver's /128).
const secondRetryAfter = 3 * time.Second

// settleNameService settles names in one call: a first walk of the ladder and, when nobody replied,
// one more walk after the first handshake. afterHandshake blocks until the tunnel's first
// handshake has landed (or its context ends) and reports whether it did; nil means there is no
// tunnel to wait on, so a silent probe is not asked again. Start runs the same two halves, with the
// retry in the background.
func settleNameService(
	ctx context.Context, stack tunnelStack, resolver netip.Addr, declared netip.Prefix,
	afterHandshake func(context.Context) bool,
) *nameService {
	first := firstNameService(ctx, stack, resolver, declared)
	if !first.silent || afterHandshake == nil {
		return first
	}
	return retrySilentNameService(ctx, first, stack, resolver, declared, afterHandshake)
}

// firstNameService is one walk of the ladder plus RFC 7050 discovery, under one bring-up budget.
func firstNameService(ctx context.Context, stack tunnelStack, resolver netip.Addr, declared netip.Prefix) *nameService {
	probeCtx, cancel := context.WithTimeout(ctx, nameServiceProbeTimeout)
	defer cancel()
	return walkNameService(probeCtx, stack, resolver, declared)
}

// retrySilentNameService waits for the first handshake and walks the ladder once more. When the
// handshake never lands, or the retry is silent too, the first answer stands with one more
// sentence, because the user is owed which of the two it was.
func retrySilentNameService(
	ctx context.Context, first *nameService, stack tunnelStack, resolver netip.Addr, declared netip.Prefix,
	afterHandshake func(context.Context) bool,
) *nameService {
	waitCtx, cancelWait := context.WithTimeout(ctx, firstHandshakeWait)
	landed := afterHandshake(waitCtx)
	cancelWait()
	if !landed {
		first.appendVerdict("The tunnel had not completed its first handshake within " +
			firstHandshakeWait.String() + ", so this is more likely the tunnel than DNS.")
		return first
	}
	again := firstNameService(ctx, stack, resolver, declared)
	if again.silent {
		pause := time.NewTimer(secondRetryAfter)
		select {
		case <-ctx.Done():
		case <-pause.C:
			again = firstNameService(ctx, stack, resolver, declared)
		}
		pause.Stop()
	}
	if again.silent {
		again.appendVerdict("It was asked again after the tunnel's first handshake, with the same result.")
	}
	return again
}

// walkNameService settles both questions under ctx: which resolver, and which NAT64 prefix.
func walkNameService(probeCtx context.Context, stack tunnelStack, resolver netip.Addr, declared netip.Prefix) *nameService {
	envPrefix, envSource := NAT64Prefix()
	_, overridden := nat64PrefixOverride()
	ns := &nameService{prefix: envPrefix, prefixSource: envSource, hostLookup: lookupOnThisHost}
	if !overridden && declared.IsValid() {
		ns.prefix, ns.prefixSource = declared, "the control plane"
	}
	chosen, why, outcome := ns.ladder(probeCtx, stack, resolver)
	ns.verdict = why
	ns.silent = outcome == probeSilent
	if outcome != probeConfirmed {
		ns.settleUnconfirmed(resolver, ns.namedRefused)
		ns.unconfirmedPrefix(probeCtx, stack, outcome == probeAnswered && !overridden && !declared.IsValid())
		return ns
	}
	ns.resolver, ns.resolverOK, ns.confirmed = chosen, true, true

	// The AAAA half of the RFC 7050 question: only a DNS64 resolver synthesises one, and the
	// synthesis spells out the prefix it synthesises into.
	_, answers, aerr := dnsQuery(probeCtx, stack, chosen, wellKnownIPv4OnlyName, dnsTypeAAAA)
	if aerr != nil {
		answers = nil
	}
	discovered, derr := prefixFromIPv4OnlyAnswers(answers)
	switch {
	case derr != nil && !overridden && declared.IsValid():
		// The resolver answers but is not synthesising, and the box already told us which prefix
		// it translates. That is not a degradation worth a sentence: we are using the value the
		// control plane named, which is exactly what discovery would have measured.
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
		// The measurement wins over the declaration - but when the two disagree, say so in one
		// line. A box that names one prefix and translates another is a real fault, and it is
		// invisible from either end alone.
		if declared.IsValid() && discovered != declared {
			ns.appendVerdict("the control plane named " + declared.String() + ", but the resolver" +
				" synthesises into " + discovered.String() + ". Following the resolver, which is" +
				" what actually translates; the two disagreeing is worth reporting.")
		}
		ns.prefix, ns.prefixSource = discovered, "RFC 7050 discovery via "+chosen.String()
	}
	return ns
}

// pickResolver walks the resolver ladder and returns the resolver to use inside the tunnel,
// plus the sentence the user is owed when it is not the one the box named. It is ladder without
// the outcome, for callers that only want the choice.
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
// 3. NOTHING CONFIRMED. The caller keeps names inside the tunnel anyway (settleUnconfirmed), and
// uses this host's resolver only when WHISPER_RESOLVE_ON_HOST asks for it, because that gives
// up the property that the lookup leaves from the /128.
//
// Each rung is probed with the SAME control question: an A query for the RFC 7050 name, whose A
// records exist and are fixed, so any resolver that recurses at all answers it and one that does
// not is one that will not resolve github.com either. Asking the control FIRST is what separates
// "this resolver will not serve me" from "this resolver has no DNS64" - an earlier draft read a
// missing AAAA as a refusal, which would have condemned a perfectly good resolver and sent every
// name to the host for no reason. Measured on the live fleet, the per-tenant resolver answers
// NXDOMAIN for that name, so the distinction is not hypothetical.
func (n *nameService) pickResolver(ctx context.Context, stack tunnelStack, named netip.Addr) (netip.Addr, string) {
	chosen, why, _ := n.ladder(ctx, stack, named)
	return chosen, why
}

// probeOutcome is what one walk of the ladder established.
type probeOutcome int

const (
	// probeConfirmed: some resolver inside the tunnel answered the control question.
	probeConfirmed probeOutcome = iota
	// probeAnswered: nothing confirmed, but at least one resolver REPLIED (a refusal, an error,
	// an empty answer). That is a finding about the resolver.
	probeAnswered
	// probeSilent: no resolver replied at all. That is a finding about nothing, and on a fresh
	// tunnel it usually means the probe ran before the tunnel carried traffic.
	probeSilent
)

// ladder is pickResolver plus the outcome, so the caller can tell a resolver that answered badly
// from one that was never heard from, and ask the second kind again.
func (n *nameService) ladder(ctx context.Context, stack tunnelStack, named netip.Addr) (netip.Addr, string, probeOutcome) {
	if !named.IsValid() {
		fallback, ok, replied := n.probeFallbacks(ctx, stack, netip.Addr{})
		if ok {
			return fallback, "the control plane returned no in-tunnel resolver, so names are being" +
				" resolved through " + fallback.String() + " inside the tunnel instead. They still" +
				" leave from your /128.", probeConfirmed
		}
		why := "the control plane returned no in-tunnel resolver, and no resolver inside the tunnel" +
			" answered a probe."
		if !replied {
			return netip.Addr{}, why, probeSilent
		}
		return netip.Addr{}, why, probeAnswered
	}
	first := n.probeRecursion(ctx, stack, named)
	namedReplied := first.replied
	n.namedRefused = first.replied && !first.ok && !first.policyRefusal()
	n.policyRefused = first.policyRefusal()
	if first.ok {
		return named, "", probeConfirmed // exactly what the box asked for, and it works: say nothing
	}
	if first.policyRefusal() {
		// The resolver refused by policy. That is an answer, and the policy is the caller's or
		// ours on purpose; going around it through a resolver that does not apply it would be the
		// client overruling the policy. Stay, and repeat the reason.
		return netip.Addr{}, "the in-tunnel resolver " + named.String() + " refused the control" +
			" query by policy: " + first.reason + ". Names stay on it, so that policy keeps" +
			" applying; names it allows still resolve.", probeAnswered
	}
	var broken string
	if !namedReplied {
		// One probe with no reply is not evidence of anything about the resolver, so the
		// sentence says what we know and no more.
		broken = "could not confirm that the in-tunnel resolver " + named.String() + " resolves" +
			" names outside Whisper: it did not reply to a probe for " +
			strings.TrimSuffix(recursionProbeName, ".") + ". "
	} else {
		// It replied, and the reply was not an answer. Say precisely how, because "the resolver
		// we were handed does not resolve" is a Whisper-side fault and the user must not be left
		// thinking it is theirs.
		broken = "the in-tunnel resolver " + named.String() + " does not resolve names outside" +
			" Whisper (it does not answer for " + strings.TrimSuffix(recursionProbeName, ".") +
			", which every recursive resolver answers). "
		switch {
		case first.reason != "":
			// The resolver told us why. Repeat it rather than attributing the fault ourselves:
			// the commonest cause is the caller's own policy, and blaming Whisper wastes their time.
			broken += "The resolver's own reason: " + first.reason + ". "
		case first.parsed && first.rcode == 5:
			// A bare REFUSED is a policy answer far more often than a fault, and RFC 8914 is
			// optional, so a resolver that gives no reason has not told us whose policy it is.
			broken += "It refused the query and gave no reason. A policy refusal from a Whisper" +
				" resolver says why, so this one is treated as a resolver that does not serve names. "
		case !first.parsed:
			broken += "Its reply could not be read as an answer. "
		default:
			broken += "This is a fault on the Whisper side, not on yours. "
		}
	}
	fallback, fok, fallbackReplied := n.probeFallbacks(ctx, stack, named)
	if fok {
		return fallback, broken + "Names are being resolved through " + fallback.String() +
			" inside the tunnel instead, so they still leave from your /128.", probeConfirmed
	}
	why := broken + "No other resolver inside the tunnel answered either."
	if !namedReplied && !fallbackReplied {
		return netip.Addr{}, why, probeSilent
	}
	return netip.Addr{}, why, probeAnswered
}

// settleUnconfirmed is where a tunnel lands when no in-tunnel resolver answered the control
// question. Names STAY in the tunnel, on the resolver the box named (or the first fallback when
// it named none), unless the user asked for this host's resolver. Either way the verdict says
// which, so the choice is never silent.
func (n *nameService) settleUnconfirmed(named netip.Addr, namedRefused bool) {
	if resolveOnHostAsked() {
		n.onHost = true
		n.appendVerdict(ResolveOnHostEnv + " is set, so names are being resolved on this host" +
			" instead. They no longer leave from your /128.")
		return
	}
	// Stay on the resolver the box named when it was silent (it may simply not have been
	// reachable yet) or refused by policy (the policy must keep applying). When it answered with a
	// plain refusal or error it is known not to serve names, so the first agent-plane fallback is
	// the better bet: if it too was only silent, it starts working when the path converges.
	stay := named
	if !stay.IsValid() || namedRefused {
		for _, r := range fallbackResolvers() {
			if r != named {
				stay = r
				break
			}
		}
	}
	n.resolver, n.resolverOK = stay, true
	s := "Names stay inside the tunnel on " + stay.String() + " and keep leaving from" +
		" your /128; a lookup that fails will say so rather than move to this host."
	if !n.policyRefused {
		// Not offered after a policy refusal: the host resolver would bypass the policy just named.
		s += " Set " + ResolveOnHostEnv + "=1 to resolve names on this host instead."
	}
	n.appendVerdict(s)
}

// perResolverProbe bounds ONE resolver's answer to the control question. A resolver inside the
// tunnel answers in about 0.1 s on the live fleet, so a second is generous; the bound exists so a
// resolver that black-holes cannot spend the whole bring-up budget and leave nothing for the
// fallbacks, which are the resolvers that exist for exactly that case.
const perResolverProbe = 1200 * time.Millisecond

// unconfirmedPrefix picks the NAT64 prefix for a tunnel whose resolver could not be confirmed, so
// RFC 7050 discovery never ran. An operator pin or the control plane's declaration already stands;
// with neither, the RFC 6052 well-known prefix would be the office-plane translator, which SNATs to
// the shared edge address, so the agent-plane prefix is used instead and the verdict says so.
//
// When the resolver names stay on REPLIED (it refused the control question but answers), discovery is
// still a measurement worth taking: the Whisper resolver answers ipv4only.arpa unconditionally, even for
// a tenant whose policy blocks everything else.
func (n *nameService) unconfirmedPrefix(ctx context.Context, stack tunnelStack, tryDiscovery bool) {
	if _, overridden := nat64PrefixOverride(); overridden || n.prefixSource == "the control plane" {
		return
	}
	if tryDiscovery && !n.onHost && n.resolver.IsValid() {
		// Its own short deadline, not what is left of the bring-up budget: the ladder may have spent
		// that, and a measurement skipped for time would silently become a guess.
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), perResolverProbe)
		_, answers, err := dnsQuery(qctx, stack, n.resolver, wellKnownIPv4OnlyName, dnsTypeAAAA)
		cancel()
		if err == nil {
			if discovered, derr := prefixFromIPv4OnlyAnswers(answers); derr == nil {
				n.prefix, n.prefixSource = discovered, "RFC 7050 discovery via "+n.resolver.String()
				return
			}
		}
	}
	n.prefix, n.prefixSource = agentPlaneNAT64, "the agent-plane default (no resolver confirmed to discover it)"
	n.appendVerdict("IPv4 destinations are wrapped into the agent-plane prefix " + agentPlaneNAT64.String() +
		" because no resolver could be asked which prefix it translates.")
}

// agentPlaneNAT64 is the prefix the agent-plane resolvers synthesise into (see agentPlaneResolvers).
var agentPlaneNAT64 = netip.MustParsePrefix("2a04:2a00:64::/96")

// probeResult is what one resolver said to the control question.
type probeResult struct {
	ok bool
	// reason is the resolver's own account of a refusal (an RFC 8914 Extended DNS Error), or "".
	reason string
	// replied: any byte of a response came back. A reply that is not an answer is a finding about
	// the resolver; no reply is a finding about nothing.
	replied bool
	// rcode is the response code, meaningful only when a whole message was parsed (parsed).
	rcode  uint8
	parsed bool
	// ede is the RFC 8914 info-code when the resolver attached one (hasEDE).
	ede    uint16
	hasEDE bool
}

// policyRefusal reports a refusal that is a POLICY decision about this caller (RFC 8914 Blocked,
// Censored, Filtered). Falling back to another resolver after one of those would route around the
// policy: the shared resolvers do not apply a tenant's own policy, so the agent's DNS would quietly
// stop obeying it. 18 (Prohibited, "this resolver does not serve you") is not one of them: it says
// nothing about the names, only about this resolver, so trying the next one is right.
func (r probeResult) policyRefusal() bool {
	return r.hasEDE && r.ede >= 15 && r.ede <= 17
}

// probeRecursion asks one resolver the control question, under its own perResolverProbe deadline.
//
// The reason field is the part that matters most. Before it, a failed probe was reported as "a
// fault on the Whisper side, not on yours", which is a guess dressed as a finding: the dominant
// real cause turned out to be the caller's OWN tenant policy set to default-block, and telling that
// user the fault was ours sent them looking in the one place it could not be. If the resolver
// attached an RFC 8914 Extended DNS Error we repeat what it said instead of inventing an
// attribution.
func (n *nameService) probeRecursion(ctx context.Context, stack tunnelStack, r netip.Addr) probeResult {
	if !r.IsValid() {
		return probeResult{}
	}
	pctx, cancel := context.WithTimeout(ctx, perResolverProbe)
	defer cancel()
	rcode, answers, raw, replied, err := dnsQueryRaw(pctx, stack, r, recursionProbeName, dnsTypeA)
	if err == nil && rcode == 0 && len(answers) > 0 {
		return probeResult{ok: true, replied: true, rcode: rcode, parsed: true}
	}
	res := probeResult{replied: replied, rcode: rcode, parsed: raw != nil && err == nil}
	if raw != nil {
		if code, text, ok := parseExtendedError(raw); ok {
			res.reason = describeExtendedError(code, text)
			res.ede, res.hasEDE = code, true
		}
	}
	return res
}

// probeFallbacks asks every second-rung candidate at once and returns the first, IN LADDER ORDER,
// that recurses, plus whether any candidate replied at all.
//
// Order is the whole point: same-plane first, so an agent that has to fall back still gets a
// NAT64 prefix its own tunnel can translate. See agentPlaneResolvers for the measurement. The
// candidates are asked in parallel so one that black-holes costs its own deadline and not the
// others' turns; the answer is still picked by order, never by which replied first.
func (n *nameService) probeFallbacks(ctx context.Context, stack tunnelStack, named netip.Addr) (netip.Addr, bool, bool) {
	var candidates []netip.Addr
	for _, r := range fallbackResolvers() {
		// Never re-probe the resolver that just failed as rung 1. The control plane can name a
		// SHARED agent resolver rather than a per-tenant one, in which case rung 1 and the first
		// candidate here are the same address: asking it twice costs a timeout and, if it somehow
		// answered the second time, would hand back a resolver the ladder has already rejected.
		if named.IsValid() && r == named {
			continue
		}
		candidates = append(candidates, r)
	}
	results := make([]probeResult, len(candidates))
	var wg sync.WaitGroup
	for i, r := range candidates {
		wg.Add(1)
		go func(i int, r netip.Addr) {
			defer wg.Done()
			results[i] = n.probeRecursion(ctx, stack, r)
		}(i, r)
	}
	wg.Wait()
	replied := false
	for i, res := range results {
		if res.ok {
			return candidates[i], true, true
		}
		replied = replied || res.replied
	}
	return netip.Addr{}, false, replied
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

// resolve returns the addresses of one family for host, from the in-tunnel resolver, or from
// this host's own resolver when the user asked for that with WHISPER_RESOLVE_ON_HOST. There is
// no third case: a name is never moved off the tunnel on the client's own initiative.
func (n *nameService) resolve(ctx context.Context, stack tunnelStack, host string, qtype uint16) ([]netip.Addr, error) {
	if !n.onHost {
		if !n.resolverOK || !n.resolver.IsValid() {
			return nil, errors.New("no resolver inside the tunnel is in use")
		}
		// Bounded per query: a resolver that black-holes must not spend the whole dial budget, or
		// the dial after the lookup runs on a dead context.
		qctx, cancel := context.WithTimeout(ctx, perQueryTimeout)
		rcode, answers, err := dnsQuery(qctx, stack, n.resolver, dnsName(host), qtype)
		cancel()
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

// perQueryTimeout bounds one in-tunnel lookup on the dial path.
const perQueryTimeout = 3 * time.Second

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
	rcode, answers, _, _, err := dnsQueryRaw(ctx, stack, server, name, qtype)
	return rcode, answers, err
}

// dnsQueryRaw is dnsQuery plus the response bytes, so a caller that wants to know WHY a name was
// refused can read the Extended DNS Error out of them, and plus whether the resolver REPLIED at all.
// Replied is true once any byte of a response came back: a short, malformed or unparseable reply is
// still evidence that the path through the tunnel works, which is a different finding from silence.
// raw is returned whenever a whole message was read, even when parsing it failed, so an EDE can
// still be read out of a reply whose answer section is damaged.
func dnsQueryRaw(ctx context.Context, stack tunnelStack, server netip.Addr, name string, qtype uint16) (rcode uint8, answers []netip.Addr, raw []byte, replied bool, err error) {
	q, err := buildQuery(name, qtype)
	if err != nil {
		return 0, nil, nil, false, err
	}
	conn, err := stack.DialContext(ctx, "tcp", net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return 0, nil, nil, false, errors.New("the in-tunnel resolver could not be reached")
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
		return 0, nil, nil, false, errors.New("the in-tunnel resolver closed the connection")
	}
	var lenBuf [2]byte
	if got, err := readFull(conn, lenBuf[:]); err != nil {
		return 0, nil, nil, got > 0, errors.New("the in-tunnel resolver returned no answer")
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 {
		return 0, nil, nil, true, errors.New("the in-tunnel resolver returned a malformed answer")
	}
	resp := make([]byte, n)
	if _, err := readFull(conn, resp); err != nil {
		return 0, nil, nil, true, errors.New("the in-tunnel resolver returned a truncated answer")
	}
	// RFC 1035 section 4.1.1: a response carries QR=1 and echoes the query's ID. Anything else is
	// not an answer to THIS question, and must never confirm a resolver.
	if resp[0] != q[0] || resp[1] != q[1] || resp[2]&0x80 == 0 {
		return 0, nil, nil, true, errors.New("the in-tunnel resolver returned a reply to a different query")
	}
	rcode, answers, perr := parseAnswers(resp, qtype)
	return rcode, answers, resp, true, perr
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

	// An OPT record, so the resolver is ALLOWED to tell us why (RFC 6891, RFC 8914).
	//
	// This query used to carry ARCOUNT 0. Without an OPT a resolver cannot attach an Extended
	// DNS Error, so "I am broken" and "I am refusing you" arrive as the same bare rcode and the
	// client cannot tell them apart. They need opposite remedies - one is ours to fix, the other
	// is a tenant policy - and that ambiguity is part of why a resolver answering NXDOMAIN for
	// every external name went unexplained for so long.
	//
	// Advertising 1232 is the conservative DNS flag-day figure: large enough to avoid needless
	// truncation, small enough to stay under the path MTU we can actually carry.
	msg = append(msg, 0)                                     // root name for OPT
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)     // TYPE = OPT
	msg = binary.BigEndian.AppendUint16(msg, ednsUDPPayload) // CLASS = requestor's payload size
	msg = binary.BigEndian.AppendUint32(msg, 0)              // extended rcode + version 0, no DO
	msg = binary.BigEndian.AppendUint16(msg, 0)              // RDLEN 0
	binary.BigEndian.PutUint16(msg[10:], 1)                  // ARCOUNT = 1
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

// ednsOptionExtendedError is EDNS option code 15, the RFC 8914 Extended DNS Error.
const ednsOptionExtendedError = 15

// parseExtendedError pulls an RFC 8914 Extended DNS Error out of a response's OPT record.
//
// Why this exists. A resolver that refuses a name by policy and a resolver that is simply broken
// hand back the same bare rcode, and the two need opposite remedies: one is a setting the operator
// can change, the other is ours to fix. The EDE is the only thing on the wire that tells them
// apart, and until this function existed we sent the OPT that invites one and then threw the answer
// away. A server that explains itself into a client that does not listen is not an explanation.
//
// The walk is deliberately bounds-checked at every step and never follows a compression pointer
// (skipName ends a name at the first pointer), so a hostile or truncated response cannot loop or
// read past the end. Anything it cannot parse is reported as absent, never as a guess: a wrong
// reason is worse here than no reason, because a user acts on it.
func parseExtendedError(msg []byte) (infoCode uint16, extraText string, ok bool) {
	if len(msg) < 12 {
		return 0, "", false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	ns := int(binary.BigEndian.Uint16(msg[8:]))
	ar := int(binary.BigEndian.Uint16(msg[10:]))
	if ar == 0 {
		return 0, "", false
	}

	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return 0, "", false
		}
		off = next + 4
		if off > len(msg) {
			return 0, "", false
		}
	}
	// The answer and authority sections are skipped wholesale: the OPT is only ever in ADDITIONAL.
	for i := 0; i < an+ns; i++ {
		next, err := skipRR(msg, off)
		if err != nil {
			return 0, "", false
		}
		off = next
	}

	for i := 0; i < ar; i++ {
		start, err := skipName(msg, off)
		if err != nil {
			return 0, "", false
		}
		if start+10 > len(msg) {
			return 0, "", false
		}
		rrType := binary.BigEndian.Uint16(msg[start:])
		rdLen := int(binary.BigEndian.Uint16(msg[start+8:]))
		rd := start + 10
		if rd+rdLen > len(msg) {
			return 0, "", false
		}
		if rrType == dnsTypeOPT {
			// OPT RDATA is a sequence of {code uint16, length uint16, value}. Walk it rather than
			// assuming the EDE is first: a resolver may legitimately send other options alongside.
			p := rd
			for p+4 <= rd+rdLen {
				code := binary.BigEndian.Uint16(msg[p:])
				olen := int(binary.BigEndian.Uint16(msg[p+2:]))
				p += 4
				if p+olen > rd+rdLen {
					return 0, "", false
				}
				if code == ednsOptionExtendedError && olen >= 2 {
					text := ""
					if olen > 2 {
						// EXTRA-TEXT is UTF-8 and is NOT null-terminated (RFC 8914 section 2);
						// trailing NULs appear in the wild anyway, so trim them rather than
						// rendering a control character into a user-facing line.
						text = strings.TrimRight(string(msg[p+2:p+olen]), "\x00")
					}
					return binary.BigEndian.Uint16(msg[p:]), text, true
				}
				p += olen
			}
		}
		off = rd + rdLen
	}
	return 0, "", false
}

// skipRR advances past one resource record and returns the offset just after it.
func skipRR(msg []byte, off int) (int, error) {
	next, err := skipName(msg, off)
	if err != nil {
		return 0, err
	}
	if next+10 > len(msg) {
		return 0, errors.New("dns: truncated record header")
	}
	rdLen := int(binary.BigEndian.Uint16(msg[next+8:]))
	end := next + 10 + rdLen
	if end > len(msg) {
		return 0, errors.New("dns: rdata past the end of the message")
	}
	return end, nil
}

// describeExtendedError turns an EDE into one line a person can act on. The two codes a Whisper
// resolver actually emits on a policy denial are named explicitly, because they have OPPOSITE
// remedies and that is the whole reason the server bothers to distinguish them: FILTERED is the
// tenant's own rule and the operator can change it, BLOCKED is the platform threat floor and they
// cannot. Anything else is reported with its number rather than guessed at.
func describeExtendedError(infoCode uint16, extraText string) string {
	var s string
	switch infoCode {
	case 15:
		s = "blocked by Whisper's threat policy (this one is not optional)"
	case 16:
		s = "blocked to meet an external requirement"
	case 17:
		s = "refused by your own DNS policy - check `whisper policy`, the default may be block"
	case 18:
		s = "this resolver does not serve you"
	default:
		s = fmt.Sprintf("the resolver reported extended error %d", infoCode)
	}
	if extraText != "" {
		s += " (" + extraText + ")"
	}
	return s
}
