// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// punch.go is the second half of the direct-path story: the client half of NAT traversal.
//
// # What the first step left on the table
//
// The first step installs a second WireGuard peer for the two cases the control plane can see with no
// traversal machinery at all: peers that share a private segment, and a peer whose public
// endpoint nothing rewrites. A node behind a NAT with neither relays, and relaying was measured
// at 23.8 to 24.3 ms hairpinned against 0.13 to 0.28 ms direct, about 130x. This file is the
// part that goes after the NAT case.
//
// # We are already the rendezvous, so this is not a STUN implementation
//
// A STUN server exists to tell a client the ip:port a NAT rewrote its packets to. Every Whalenet
// node already holds a WireGuard tunnel to a box, so the box already OBSERVES exactly that, for
// every peer, continuously, in `wg show <iface> dump`. There is no new protocol here and no third
// party: the observation the control plane already publishes IS the reflexive address, and this
// file is the half that acts on it.
//
// # The mechanism, and why it is this small
//
// A punch is nothing more than both sides sending a packet at the other's observed endpoint
// close enough together that each NAT has an outbound mapping by the time the other's packet
// arrives. WireGuard's own handshake initiation is a perfectly good punch packet, so we do not
// send a probe of our own: we point the peer at a candidate endpoint and let the device
// initiate. Two properties of WireGuard make the rest fall out:
//
// 1. ROAMING. A peer's endpoint is updated to wherever an AUTHENTICATED packet actually arrived
// from. So the pair only needs ONE direction to get through: if A is behind a symmetric NAT
// (its mapped port is unpredictable, so nothing can tell B where to aim) and B is reachable,
// A initiates, B authenticates, and B roams to A's real mapped source on its own. No port
// prediction is involved, which is why the birthday-paradox spray earns much less here than
// it does in a design that punches with its own probe packets. See the note on it below.
// 2. CRYPTOKEY ROUTING. A candidate carries no allowed-ips while it is being punched, so a
// punch that fails routes nothing anywhere: the box peer still holds ::/0 and every packet
// for that /128 keeps being relayed. A failed punch costs latency. It cannot cost
// reachability, and that is the invariant this whole file is arranged around.
//
// # What we do NOT do, said plainly
//
// No simultaneous multi-port spray against a symmetric NAT. wireguard-go's UAPI carries exactly
// ONE endpoint per peer, so a spray would mean replacing the device's conn.Bind and emitting
// packets the far side cannot authenticate - and a packet the far side discards cannot complete
// a handshake, it can only open a mapping on our own side that we already have. The case a
// spray would buy is symmetric NAT on BOTH ends, which is where even a full ICE implementation
// usually falls back to a relay, and we have a relay that already carries it correctly. If the
// control plane ever starts publishing predicted ports they arrive as ordinary candidates and
// are punched like any other, so the door is open at no cost.

const (
	// punchPeriod is how long one punch attempt is given before the next candidate is tried.
	//
	// Five seconds, matching WireGuard's own REKEY_TIMEOUT, which is the interval at which
	// wireguard-go retries a handshake initiation it has had no answer to. A faster rotation
	// would replace the endpoint underneath an initiation still in flight and throw away the
	// answer that was about to arrive; a slower one lets the NAT mapping the last attempt opened
	// go cold before the far side gets its own attempt out (RFC 4787 asks for at least two
	// minutes of UDP mapping lifetime, and the cheap consumer NATs that motivate this file are
	// routinely at thirty seconds).
	punchPeriod = 5 * time.Second

	// punchTrainAttempts is how many attempts one train makes before it gives up and lets the
	// pair rest.
	//
	// Twelve, which at punchPeriod is sixty seconds, which is exactly one PeerRefresh interval.
	// That is the number that matters: the far side learns about us on ITS next refresh, so a
	// train shorter than one refresh period can finish before the peer has even been told we
	// exist. A train longer than that is sending into a hole - if sixty seconds of attempts
	// across every candidate produced no handshake, the pair is one the relay should carry.
	//
	// The two sides do NOT need to fire at the same instant, and we deliberately do not try to
	// arrange that. What a punch actually needs is for the two trains to OVERLAP inside the NAT
	// mapping lifetime, which a sixty-second train on both ends gives with a wide margin and no
	// clock synchronisation, no shared epoch and no signalling channel. Simpler, and it degrades
	// to "keeps retrying" rather than to "misses each other" when a clock is wrong.
	punchTrainAttempts = 12

	// maxPunchCandidates caps how many endpoints we will punch at for one peer. The rotation is
	// sequential, so a list longer than a train has a tail that is never reached; a cap says so
	// out loud rather than quietly ignoring the last entries. Eight covers a multi-homed host's
	// private addresses plus its observed public endpoint with room to spare.
	maxPunchCandidates = 8
)

// CandidateSource says where an endpoint came from, which is the whole basis for the order we
// try them in and for the sentence a person reads afterwards.
type CandidateSource string

const (
	// SourceLocal is a private address the peer declared: RFC1918 or ULA. Tried first because if
	// it works it is the cheapest path that exists (no NAT, one segment, sub-millisecond).
	SourceLocal CandidateSource = "local"
	// SourcePublic is a public endpoint the peer declared for itself and nothing rewrites.
	SourcePublic CandidateSource = "public"
	// SourceObserved is the ip:port a box actually saw this peer's packets arrive from. This is
	// the reflexive address a STUN server would have returned, obtained from the tunnel the peer
	// already holds rather than from a protocol we would have to write and a server we would
	// have to run.
	SourceObserved CandidateSource = "observed"
	// SourceRoamed is where this peer's own authenticated packets last reached US from. It is
	// the strongest evidence there is - a packet came from there and it verified - so it is
	// tried first when a working path has to be rebuilt.
	SourceRoamed CandidateSource = "roamed"
)

// Candidate is one underlay endpoint we may aim a handshake at, and where it came from.
type Candidate struct {
	// Endpoint is a literal ip:port. Never a hostname: the UAPI does not resolve.
	Endpoint string
	// Source is the evidence class, which decides the order and the explanation.
	Source CandidateSource
}

// rank orders the sources: the strongest evidence and the cheapest path first. Two candidates
// with the same endpoint collapse to the better-ranked one, so an observed endpoint that equals
// a declared public one costs nothing extra.
func (s CandidateSource) rank() int {
	switch s {
	case SourceRoamed:
		return 0
	case SourceLocal:
		return 1
	case SourcePublic:
		return 2
	case SourceObserved:
		return 3
	default:
		return 4
	}
}

// Why is the fragment that ends up in the sentence a person reads under `whale status`. It is
// exported because the surface renders the sentence and the engine owns the vocabulary, and two
// copies of the same phrase in two packages is one copy too many.
func (s CandidateSource) Why() string {
	switch s {
	case SourceRoamed:
		return "the address its own packets last arrived from"
	case SourceLocal:
		return "a private address it shares a segment with us on"
	case SourcePublic:
		return "the public endpoint it declares"
	case SourceObserved:
		return "the endpoint a Whisper box saw it arrive from"
	default:
		return "an endpoint the control plane offered"
	}
}

// ParseCandidates validates and orders a peer's candidate endpoints.
//
// Every candidate goes through the SAME checkUnderlayEndpoint the single declared endpoint does.
// That is the load-bearing part: a candidate list is a list of places we will send UDP to, so a
// control plane that has been lied to (or replaced) must not be able to turn this node into a
// packet source aimed at loopback, at the internal network, at our own overlay, or at multicast.
//
// Liberal in what it accepts (Postel): duplicates collapse, blanks are dropped, an entry that
// fails validation is skipped rather than failing the whole peer, and the list is truncated to
// maxPunchCandidates. It returns an error only when NOTHING survived, because a peer with no
// endpoint at all is one there is nothing to install for.
func ParseCandidates(in []Candidate) ([]Candidate, error) {
	seen := map[string]int{} // endpoint -> index in out, so a duplicate can upgrade its source
	var out []Candidate
	for _, c := range in {
		ep := strings.TrimSpace(c.Endpoint)
		if ep == "" {
			continue
		}
		if err := checkUnderlayEndpoint(ep); err != nil {
			continue
		}
		src := c.Source
		if src == "" {
			src = SourcePublic
		}
		if at, dup := seen[ep]; dup {
			if src.rank() < out[at].Source.rank() {
				out[at].Source = src
			}
			continue
		}
		seen[ep] = len(out)
		out = append(out, Candidate{Endpoint: ep, Source: src})
	}
	if len(out) == 0 {
		return nil, errors.New("the peer has no endpoint we are willing to dial")
	}
	// A stable sort by source rank: the cheapest, best-evidenced path is punched first, and two
	// candidates of the same class keep the order the control plane sent them in.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Source.rank() < out[j].Source.rank()
	})
	if len(out) > maxPunchCandidates {
		out = out[:maxPunchCandidates]
	}
	return out, nil
}

// PunchPhase is what the punch machinery is doing for one peer right now. It is a closed set,
// and every value is something we can stand behind from evidence on this device.
type PunchPhase string

const (
	// PunchIdle: there is nothing to punch at. The control plane offered no endpoint for this
	// peer, which is what a relayed row looks like.
	PunchIdle PunchPhase = "idle"
	// PunchTrying: a train is running. The relay is carrying this peer meanwhile.
	PunchTrying PunchPhase = "punching"
	// PunchEstablished: a handshake landed and the /128 is routed to this peer.
	PunchEstablished PunchPhase = "established"
	// PunchGaveUp: a full train produced no handshake. The relay carries it, and another train
	// starts after the rearm window.
	PunchGaveUp PunchPhase = "gave-up"
)

// PunchInfo is the truthful, per-peer report: what was tried, how often, at what, and how it
// ended. It is what lets a surface say "relayed because the punch failed" as a finding rather
// than as the absence of a direct path.
type PunchInfo struct {
	Phase PunchPhase `json:"phase"`
	// Attempts is how many punch attempts the current (or last) train has made.
	Attempts int `json:"attempts,omitempty"`
	// Trains is how many trains have run for this peer since it was installed.
	Trains int `json:"trains,omitempty"`
	// Candidates is how many distinct endpoints there are to try.
	Candidates int `json:"candidates,omitempty"`
	// Trying is the endpoint the most recent attempt aimed at.
	Trying string `json:"trying,omitempty"`
	// Winner is the endpoint that carried the handshake, once one has.
	Winner string `json:"winner,omitempty"`
	// WinnerSource is that endpoint's evidence class, so the report can say WHY it worked.
	WinnerSource CandidateSource `json:"winner_source,omitempty"`
	// Since is when this phase began.
	Since time.Time `json:"since,omitempty"`
}

// Established reports whether a direct path is actually carrying this peer.
func (p PunchInfo) Established() bool { return p.Phase == PunchEstablished }

// punchTrain is one peer's live punch state. Guarded by the Tunnel's mu, like everything else
// in directPeer.
type punchTrain struct {
	cands     []Candidate
	next      int  // index of the candidate the NEXT attempt will use
	attempts  int  // attempts made in the current train
	trains    int  // trains started since this peer was installed
	gaveUp    bool // the current train is spent; the rearm window restarts it
	startedAt time.Time
	lastAt    time.Time
	lastEP    string
	winner    Candidate
	won       bool
}

// newPunchTrain starts a train over cands. A peer with no candidate is idle, not punching: there
// is nothing to aim at, and pretending otherwise would print an attempt count for packets that
// were never sent.
func newPunchTrain(cands []Candidate, now time.Time) *punchTrain {
	return &punchTrain{cands: cands, startedAt: now, trains: 1}
}

// due reports whether another attempt is owed, and returns the candidate to aim at.
//
// The first attempt of a train is due immediately: the peer was just installed (or just came
// back), and waiting a period before the first packet is a period the far side spends unable to
// reach us for no reason.
func (tr *punchTrain) due(now time.Time, period time.Duration) (Candidate, bool) {
	if tr == nil || len(tr.cands) == 0 || tr.gaveUp {
		return Candidate{}, false
	}
	if tr.attempts >= punchTrainAttempts {
		tr.gaveUp = true
		return Candidate{}, false
	}
	if period <= 0 {
		period = punchPeriod
	}
	// A tenth of the period of slack, because the caller is the health monitor and its tick is
	// the same order as this one. Without it two timers of equal length beat against each other
	// and every second round is skipped, which would silently halve the punch rate.
	if !tr.lastAt.IsZero() && now.Sub(tr.lastAt) < period-period/10 {
		return Candidate{}, false
	}
	c := tr.cands[tr.next%len(tr.cands)]
	tr.next++
	tr.attempts++
	tr.lastAt = now
	tr.lastEP = c.Endpoint
	return c, true
}

// restart begins a fresh train, preferring `first` if it is one of our candidates. After a path
// has been up and died, the endpoint that carried it is the one most likely to carry it again,
// so a rebuild starts there rather than at the top of the list.
func (tr *punchTrain) restart(now time.Time, first Candidate) {
	if tr == nil {
		return
	}
	tr.attempts = 0
	tr.gaveUp = false
	tr.startedAt = now
	tr.lastAt = time.Time{}
	tr.trains++
	tr.next = 0
	if first.Endpoint == "" {
		return
	}
	for i, c := range tr.cands {
		if c.Endpoint == first.Endpoint {
			tr.next = i
			return
		}
	}
}

// adopt replaces the candidate list without disturbing a train in progress. It exists for one
// case and it matters: the control plane refreshes the peer map every minute, and if a working
// direct path were torn down and re-armed because a list came back in a different ORDER, every
// direct pair in the fleet would flap on a timer. The counters and the winner are kept, and the
// rotation index is clamped so a shorter list cannot send it off the end.
func (tr *punchTrain) adopt(cands []Candidate) {
	if tr == nil || len(cands) == 0 {
		return
	}
	tr.cands = cands
	if tr.next >= len(cands) {
		tr.next = 0
	}
}

// spent reports whether the current train has given up, which is the state the rearm window
// exists to end.
func (tr *punchTrain) spent() bool { return tr == nil || tr.gaveUp || len(tr.cands) == 0 }

// info renders the report for one peer. promoted is the DEVICE's truth, not the train's opinion:
// the phase can only say "established" when the /128 is actually routed to this peer.
func (tr *punchTrain) info(promoted bool) PunchInfo {
	if tr == nil {
		return PunchInfo{Phase: PunchIdle}
	}
	in := PunchInfo{
		Attempts:   tr.attempts,
		Trains:     tr.trains,
		Candidates: len(tr.cands),
		Trying:     tr.lastEP,
		Since:      tr.startedAt,
	}
	if tr.won {
		in.Winner = tr.winner.Endpoint
		in.WinnerSource = tr.winner.Source
	}
	switch {
	case promoted:
		in.Phase = PunchEstablished
	case len(tr.cands) == 0:
		in.Phase = PunchIdle
	case tr.gaveUp:
		in.Phase = PunchGaveUp
	default:
		in.Phase = PunchTrying
	}
	return in
}

// punchAt aims one handshake at a candidate endpoint.
//
// It is deliberately the SMALLEST possible UAPI write, and what it leaves alone is the point:
//
// - update_only=true, so a peer the control plane removed underneath us is not recreated here.
// - NO replace_allowed_ips and NO allowed_ip, so a punch can never move the /128. Promotion and
// demotion are the only two things in this package that touch cryptokey routing, which is
// what keeps "a failed punch costs latency, never reachability" true by construction rather
// than by care.
// - the keepalive toggled 0 then back on, which is the whole trigger: wireguard-go sends an
// immediate keepalive when the interval goes from off to on, and a keepalive with no live
// session is a handshake initiation. It also resets the peer's handshake-attempt counter, so
// our train keeps the device initiating long past the ninety seconds after which it would
// otherwise go quiet by itself.
func (t *Tunnel) punchAt(p Peer, c Candidate) error {
	return t.dev.IpcSet(punchDoc(p, c))
}

// punchDoc is the UAPI document a punch writes, separated from the device so a test can assert
// what is in it - and, far more importantly, what is NOT.
func punchDoc(p Peer, c Candidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", p.PublicKeyHex)
	b.WriteString("update_only=true\n")
	fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	b.WriteString("persistent_keepalive_interval=0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", directKeepalive)
	return b.String()
}

// peerEndpoint reads back where the device currently believes a peer is. After a handshake this
// is the endpoint that actually carried it, INCLUDING the case where WireGuard roamed to a
// source we never configured - which is precisely the symmetric-NAT case, and the only way to
// learn the address that worked. Read once per promotion, not per tick.
func (t *Tunnel) peerEndpoint(keyHex string) string {
	dump, err := t.dev.IpcGet()
	if err != nil {
		return ""
	}
	return endpointFromDump(dump, keyHex)
}

// endpointFromDump pulls one peer's endpoint out of a UAPI dump. Separated from the device read
// so it can be tested against a recorded dump: a test that needs a live tunnel is a test nobody
// runs. The dump also carries private_key; we read only the per-peer endpoint line.
func endpointFromDump(dump, keyHex string) string {
	inPeer := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			inPeer = strings.TrimSpace(v) == keyHex
		case "endpoint":
			if inPeer {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
