// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"fmt"
	"net/netip"
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
	// This train is the UNTIMED one, for a peer the plane offered a direct path to (a shared
	// segment, an untranslated public endpoint, or the observed endpoint beside a local one). Its
	// two ends do not fire at the same instant, and on a real segment or towards an untranslated
	// endpoint they need not: whichever end's handshake arrives is answered. Once it is spent, a row
	// that carries the pair's window falls back to it (fallBack): the device is silenced and tried
	// again only inside the window, which is also what still meets a far end behind something that
	// drops what it did not ask for, because both ends send in the same seconds. A row without a
	// window keeps the device's own behaviour, a handshake initiation every five seconds for as long
	// as the peer is armed (wireguard-go resets its attempt counter on every keepalive). A RELAYED
	// pair is punched the timed way from the start (rendezvous.go, punchTrain.windowStep).
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
// packet source aimed at loopback, at a tailnet, at our own overlay, or at multicast.
//
// Liberal in what it accepts (Postel): duplicates collapse, blanks are dropped, an entry that
// fails validation is skipped rather than failing the whole peer, and the list is truncated to
// maxPunchCandidates. It returns an error only when NOTHING survived, because a peer with no
// endpoint at all is one there is nothing to install for.
func ParseCandidates(in []Candidate) ([]Candidate, error) {
	seen := map[string]int{} // endpoint -> index in out, so a duplicate can upgrade its source
	var out []Candidate
	for _, c := range in {
		if strings.TrimSpace(c.Endpoint) == "" {
			continue
		}
		ap, err := parseUnderlayEndpoint(c.Endpoint)
		if err != nil {
			continue
		}
		// The canonical form, not the row's text: two spellings of one endpoint collapse, and what
		// reaches the device's UAPI document is only ever what netip printed.
		ep := ap.String()
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
	// PunchTrying: a train is running, or a timed one is waiting for its first window. The relay
	// is carrying this peer meanwhile.
	PunchTrying PunchPhase = "punching"
	// PunchEstablished: a handshake landed and the /128 is routed to this peer.
	PunchEstablished PunchPhase = "established"
	// PunchGaveUp: a full train, or an attended window, produced no handshake. The relay carries
	// it, and another train starts after the rearm window (or at the next window attended).
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
	gaveUp    bool // the current train is spent; the rearm window (or the next window) restarts it
	startedAt time.Time
	lastAt    time.Time
	lastEP    string
	winner    Candidate
	won       bool

	// window is the plane's shared punch window, for a relayed pair; zero for an untimed train. A
	// timed train sends only inside a window it attends (windowStep). pending is a window a refresh
	// carried while one was being attended, taken when that one is over.
	window  Rendezvous
	pending Rendezvous
	// attending is true while a window is being attended, slot is that window (or the last one
	// attended, once attended is set), and missed is how many attended windows in a row ended with no
	// handshake, which is what the backoff reads.
	attending bool
	attended  bool
	slot      int64
	missed    int
	// quietAt is when the device is silenced after the window being attended, fixed on the monotonic
	// clock when the window is joined, so nothing a later read says can stretch a window already in
	// progress. rxAtJoin is the peer's received-byte count then, and extended whether the silence has
	// already been put off once because something arrived from the peer.
	quietAt  time.Time
	rxAtJoin uint64
	extended bool
	// opener is whether this end sends first in every window: the end with the lower overlay address
	// does, at the window's start, and the other end half a window later (see windowStep).
	opener bool

	// fallback is the pair's window on a DIRECT row (Peer.Window): the train runs untimed first, and once
	// that first train is spent it falls back to this window (fallBack), after which it is a timed train
	// like a relayed pair's. preludeAt is when the current untimed train started, zero for a train that
	// never ran one.
	fallback  Rendezvous
	preludeAt time.Time
}

// punchCarry is what one key's train hands the next when its row is re-armed, or installed again soon
// after a removal: how far the window backoff had got, and when the last untimed train started. Without it
// a row that kept changing (a peer moving its declared endpoints, its advice coming and going) would buy a
// fresh run of attempts every time it changed.
type punchCarry struct {
	missed    int
	preludeAt time.Time
	// window is the last pair's window the train had for a direct row, kept for a re-armed row whose read
	// carried none (a slow read, a plane mid-upgrade): the window is a pure function of the pair.
	window Rendezvous
}

// carry is this train's punchCarry.
func (tr *punchTrain) carry() punchCarry {
	if tr == nil {
		return punchCarry{}
	}
	return punchCarry{missed: tr.missed, preludeAt: tr.preludeAt, window: tr.fallback}
}

// newPunchTrain starts a train over cands. A peer with no candidate is idle, not punching: there
// is nothing to aim at, and pretending otherwise would print an attempt count for packets that
// were never sent.
func newPunchTrain(cands []Candidate, now time.Time) *punchTrain {
	return &punchTrain{cands: cands, startedAt: now, trains: 1}
}

// newPunchTrainFor starts the train a peer calls for: timed when the plane gave it a relayed pair's window
// (Peer.Rendezvous); otherwise untimed, falling back to the pair's window once spent when the row carries
// one (Peer.Window). A timed train has run no train yet; it counts one per window attended. self is this
// node's own overlay address, which decides which end of the pair opens each window.
//
// c is what an earlier train for the same key left (punchCarry): its backoff carries over, and a direct
// row whose last untimed train started less than rearm ago starts on the window straight away instead of
// running another.
func newPunchTrainFor(p Peer, self netip.Addr, now time.Time, c punchCarry, rearm time.Duration) *punchTrain {
	tr := newPunchTrain(p.candidateList(), now)
	tr.opener = self.Less(p.Address)
	if c.missed > 0 {
		tr.missed = min(c.missed, maxWindowBackoff)
	}
	window := p.Window
	if window.IsZero() {
		window = c.window
	}
	switch {
	case !p.Rendezvous.IsZero():
		tr.window = p.Rendezvous
		tr.trains = 0
	case !window.IsZero():
		tr.fallback = window
		if !c.preludeAt.IsZero() && now.Sub(c.preludeAt) < rearm {
			tr.window = window
			tr.trains = 0
			tr.preludeAt = c.preludeAt
		} else {
			tr.preludeAt = now
		}
	}
	return tr
}

// canFallBack reports whether this train runs untimed now and has a window to fall back to.
func (tr *punchTrain) canFallBack() bool {
	return tr != nil && tr.window.IsZero() && !tr.fallback.IsZero()
}

// fallBack ends the untimed train and puts it on the pair's window, from where its backoff stood. The
// caller silences the device (quietDoc) in the same breath, so nothing is sent until the first window the
// train attends.
func (tr *punchTrain) fallBack() {
	if !tr.canFallBack() {
		return
	}
	tr.window = tr.fallback
	tr.attending, tr.attended, tr.pending = false, false, Rendezvous{}
	tr.gaveUp = true
}

// adoptFallback takes the window a refresh carried for a direct row: as the next fallback while the train
// still runs untimed, and as the window itself once it has fallen back.
func (tr *punchTrain) adoptFallback(r Rendezvous) {
	if tr == nil || r.IsZero() {
		return
	}
	// A direct row's window may come from a slow read (ParseFallbackWindow), so a placement of the same
	// schedule replaces the one held only when its read was no less precise: one slow read must not cost a
	// pair the overlap a fast one gave it.
	if !tr.fallback.IsZero() && r.Period == tr.fallback.Period && r.ReadError > tr.fallback.ReadError {
		return
	}
	fellBack := !tr.fallback.IsZero() && !tr.window.IsZero()
	tr.fallback = r
	if fellBack {
		tr.adoptWindow(r)
	}
}

// timed reports whether this train punches inside the plane's windows.
func (tr *punchTrain) timed() bool { return tr != nil && !tr.window.IsZero() }

// punchAction is what one step of a timed train asks the tunnel to do.
type punchAction int

const (
	punchNothing punchAction = iota
	// punchSend aims one handshake at the returned candidate and leaves the device to retry it
	// (Tunnel.punchOnce).
	punchSend
	// punchQuiet silences the device for this peer until the next window it attends (quietDoc).
	punchQuiet
)

// retransmitCover is how long a timed train keeps the device's own retries running after it joins a
// window: wireguard-go's REKEY_TIMEOUT of five seconds, its jitter of up to a third of a second, and a
// margin. It is what resolves two initiations that cross on the wire. When both ends send inside one
// round trip of each other, each one's initiation reaches the other, each turns responder, and neither
// response matches an initiation any more; WireGuard's answer is the retry, and the retry's jitter is
// what makes the next two not cross again. Silencing the device before a retry, or retrying on the
// persistent keepalive, which has no jitter, would have the two ends cross the same way every window.
const retransmitCover = 6 * time.Second

// windowStep is one monitor tick of a TIMED train. lookahead is how far ahead this tick may schedule a
// send (the monitor's own interval, so no send is ever missed between two ticks), and rx is the peer's
// received-byte count as this tick read it. A send comes back with the instant it is due, which the
// tunnel fires on a timer (Tunnel.punchAtInstant), not on the tick.
//
// Nothing is sent outside a window this side attends, and each end sends at a fixed point in it: the
// OPENER (the end with the lower overlay address) at the window's start, the other end half a window
// later. That order is what makes the handshake land at the first attempt. The opener's packet reaches
// the far NAT before the far end has sent anything, so the far NAT drops it; but sending it opened the
// opener's own NAT towards the far end. Half a window later the far end's handshake arrives at an open
// door, the opener answers, and the far end, which is the only one still holding an initiation, takes
// the answer. Were both to send inside one round trip of each other, both handshakes would pass, both
// ends would turn responder, and neither answer would match an initiation any more (see
// retransmitCover). Half the plane's six-second window is three seconds, twice the skew it tolerates at
// each end, so the order survives any clock the plane is built for. Nor do they need to meet at an
// instant: both only have to send within the lifetime of the NAT mappings their sending opens, which is
// tens of seconds even on cheap NATs (RFC 4787 asks for two minutes).
//
// The train aims ONE handshake per window and leaves the retries to the device, which repeats an
// unanswered initiation every five seconds with a random jitter. It then waits until the window has
// closed and one more period has passed, because the far side's last packet may still be in flight,
// and at least retransmitCover after its send, and asks for the device to be silenced. Without that the
// device would go on retrying for ninety seconds, or for ever on a keepalive. The miss is counted, and
// the backoff in attends decides which window is next. So one window costs this side at most three
// initiations of 148 bytes: the one it aims and the device's retries before the silence.
//
// The silence is put off once, by one more period, when something arrived from the peer during the
// window. That is the far side's initiation having reached us: we answered, and our half of the session
// is waiting for the far side's first packet to confirm it. Silencing now would throw that session away
// (the quiet writes the peer back fresh) while the far side, which already holds its half, promotes and
// sends into nothing until it re-handshakes.
func (tr *punchTrain) windowStep(now time.Time, period, lookahead time.Duration, rx uint64) (punchAction, Candidate, time.Time) {
	if !tr.timed() || len(tr.cands) == 0 {
		return punchNothing, Candidate{}, time.Time{}
	}
	if period <= 0 {
		period = punchPeriod
	}
	if tr.attending {
		if rx > tr.rxAtJoin && !tr.extended && !now.Before(tr.quietAt) {
			tr.extended = true
			tr.quietAt = now.Add(period)
		}
		if now.Before(tr.quietAt) {
			return punchNothing, Candidate{}, time.Time{}
		}
		tr.attending, tr.gaveUp = false, true
		if tr.missed < maxWindowBackoff {
			tr.missed++
		}
		if !tr.pending.IsZero() {
			tr.takeWindow(tr.pending)
			tr.pending = Rendezvous{}
		}
		return punchQuiet, Candidate{}, time.Time{}
	}
	slot := tr.window.current(now)
	start, end := tr.window.bounds(slot)
	if end.Sub(start) > maxRendezvousWindow {
		end = start.Add(maxRendezvousWindow)
	}
	sendAt := start
	if !tr.opener {
		sendAt = start.Add(end.Sub(start) / 2)
	}
	if sendAt.Sub(now) > lookahead || !now.Before(end) {
		return punchNothing, Candidate{}, time.Time{}
	}
	if (tr.attended && slot <= tr.slot) || !attends(slot, tr.missed) {
		return punchNothing, Candidate{}, time.Time{}
	}
	if sendAt.Before(now) {
		sendAt = now // joined late (a node that read its peer map mid-window): send now, not never
	}
	quietAt := end.Add(period)
	if cover := sendAt.Add(retransmitCover); cover.After(quietAt) {
		quietAt = cover
	}
	tr.attending, tr.attended, tr.slot = true, true, slot
	tr.quietAt, tr.rxAtJoin, tr.extended = quietAt, rx, false
	tr.attempts, tr.gaveUp, tr.startedAt = 0, false, sendAt
	tr.trains++
	return punchSend, tr.aimWindow(sendAt), sendAt
}

// aimWindow takes the candidate a window aims at and records the attempt. It is the same in every window,
// so the two ends of a pair aim at each other in the same windows: the first endpoint a box observed, when
// there is one (the case a window exists for: two NATs, which only the observed endpoints cross), else the
// first candidate. A rotation would not do: each end's list is its own view of the other, the two lists
// need not be the same length, and two ends rotating through them can aim at the wrong pair of endpoints
// in every window for good. The other candidates had their turn in the untimed train before the window.
func (tr *punchTrain) aimWindow(now time.Time) Candidate {
	i := 0
	for j, c := range tr.cands {
		if c.Source == SourceObserved {
			i = j
			break
		}
	}
	tr.next = i
	return tr.aim(now)
}

// deferQuiet puts the silence off by one period, once, the way windowStep does when something has
// arrived from the peer. Tunnel.quietDirectPeer calls it when its own fresh read of the device shows a
// packet that landed after the tick decided to silence, and reports whether it did. A second deferral
// is refused, so a peer that keeps sending can never keep this side sending for longer than a window
// and two periods.
func (tr *punchTrain) deferQuiet(now time.Time, period time.Duration) bool {
	if tr == nil || !tr.timed() || tr.extended {
		return false
	}
	if period <= 0 {
		period = punchPeriod
	}
	if tr.missed > 0 {
		tr.missed-- // the window that is being extended was not missed after all, not yet
	}
	tr.attending, tr.gaveUp, tr.extended = true, false, true
	tr.quietAt = now.Add(period)
	return true
}

// freshEvidence starts the backoff over: the far side's mapping moved, so what was learned about the
// old one says nothing about the new one.
func (tr *punchTrain) freshEvidence() {
	if tr != nil {
		tr.missed = 0
	}
}

// adoptWindow takes the window a refresh carried. A window being attended is left exactly as it was
// joined (its end and its silence are fixed on the monotonic clock) and the new one is taken when that
// window is over, so no refresh can stretch, shift or end a window in progress.
func (tr *punchTrain) adoptWindow(r Rendezvous) {
	if tr == nil || r.IsZero() || tr.window.IsZero() {
		return
	}
	if tr.attending {
		tr.pending = r
		return
	}
	tr.takeWindow(r)
}

// takeWindow replaces the window. A refresh normally places the same schedule a few milliseconds
// differently, which changes nothing that matters. One that numbers its windows differently or moves
// them (a box whose clock disagrees with the other's by a whole number of periods, or a new period)
// makes the slot remembered as attended meaningless, so it is forgotten rather than compared across
// the two numberings.
func (tr *punchTrain) takeWindow(r Rendezvous) {
	old := tr.window
	tr.window = r
	if r.Period != old.Period {
		tr.attended = false
		return
	}
	label := old.current(r.At)
	start, _ := old.bounds(label)
	if d := start.Sub(r.At); label != r.Slot || d > maxRendezvousWindow || d < -maxRendezvousWindow {
		tr.attended = false
	}
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
	return tr.aim(now), true
}

// aim takes the next candidate in the rotation and records the attempt.
func (tr *punchTrain) aim(now time.Time) Candidate {
	c := tr.cands[tr.next%len(tr.cands)]
	tr.next++
	tr.attempts++
	tr.lastAt = now
	tr.lastEP = c.Endpoint
	return c
}

// restart begins a fresh train, preferring `first` if it is one of our candidates. After a path
// has been up and died, the endpoint that carried it is the one most likely to carry it again,
// so a rebuild starts there rather than at the top of the list.
func (tr *punchTrain) restart(now time.Time, first Candidate) {
	tr.restartFor(now, first, true)
}

// restartFor is restart, saying whether a direct row may run another untimed train now (fresh). A path that
// came up and died within one rekey, while an untimed train for the key ran within directRearmAfter, is not
// fresh evidence: such a direct row goes back to its window with the backoff it had, so a far end that
// completes one handshake and goes quiet cannot keep buying this node untimed trains (Tunnel.reconcile).
func (tr *punchTrain) restartFor(now time.Time, first Candidate, fresh bool) {
	if tr != nil && !fresh && !tr.fallback.IsZero() {
		tr.attempts, tr.gaveUp, tr.startedAt, tr.lastAt = 0, true, now, time.Time{}
		tr.window, tr.attending, tr.attended, tr.pending = tr.fallback, false, false, Rendezvous{}
		return
	}
	tr.restartFresh(now, first)
}

func (tr *punchTrain) restartFresh(now time.Time, first Candidate) {
	if tr == nil {
		return
	}
	tr.attempts = 0
	tr.gaveUp = false
	tr.startedAt = now
	tr.lastAt = time.Time{}
	tr.next = 0
	if !tr.fallback.IsZero() {
		// A direct row's path was up a moment ago and died: an untimed train again, at once, from the
		// endpoint that carried it, and the window again once that is spent. A handshake landed, so the
		// backoff starts over too.
		tr.window, tr.attending, tr.attended, tr.pending, tr.missed = Rendezvous{}, false, false, Rendezvous{}, 0
		tr.preludeAt = now
		tr.trains++
	} else if tr.timed() {
		// A timed train restarts by attending the next window it can, from the first rung of the
		// backoff: the path was up a moment ago, so this is the likeliest time it comes back. The
		// window counts as a train when it is attended, not here.
		tr.attending, tr.attended, tr.missed = false, false, 0
	} else {
		tr.trains++
	}
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

// punchOnce is the timed train's punch: one handshake aimed at the candidate, after which the device's
// keepalive is turned off again, so the retries are the device's jittered retransmissions and not a
// keepalive that fires on the same beat at both ends (see retransmitCover). Both writes are
// update_only, so a peer removed underneath cannot be recreated, and neither touches allowed-ips.
func (t *Tunnel) punchOnce(p Peer, c Candidate) error {
	if err := t.dev.IpcSet(punchDoc(p, c)); err != nil {
		return err
	}
	return t.dev.IpcSet(unkeepDoc(p))
}

// punchAtInstant fires a timed train's punch at the instant windowStep scheduled it for, on a timer
// rather than on the next monitor tick, which in production is up to five seconds late and would blur
// the order the two ends send in. The timer runs on its own goroutine, so it takes the peer-write lock
// that SetDirectPeers, the quiet and the promotion write under, checks the peer is still tracked,
// still unpromoted and still attending that window, and writes while holding it: a quiet, a removal
// or a promotion is either wholly before the punch or wholly after it. Both writes are update_only as
// well, so nothing a timer does can recreate a peer.
func (t *Tunnel) punchAtInstant(p Peer, c Candidate, at time.Time, slot int64) {
	fire := func() {
		select {
		case <-t.stop:
			return
		default:
		}
		t.peerWrite.Lock()
		defer t.peerWrite.Unlock()
		t.mu.Lock()
		d := t.direct[p.PublicKeyHex]
		ok := d != nil && !d.promoted && d.punch != nil && d.punch.attending && d.punch.slot == slot
		t.mu.Unlock()
		if ok {
			_ = t.punchOnce(p, c)
		}
	}
	if wait := time.Until(at); wait > 0 {
		time.AfterFunc(wait, fire)
		return
	}
	fire()
}

// unkeepDoc turns a peer's keepalive off and changes nothing else.
func unkeepDoc(p Peer) string {
	return "public_key=" + p.PublicKeyHex + "\nupdate_only=true\npersistent_keepalive_interval=0\n"
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

// quietDoc is the UAPI document that silences an unpromoted peer between windows: the peer is
// removed and written straight back with its endpoint, no allowed-ips and no keepalive.
//
// The remove is the point. Clearing the keepalive alone does not stop wireguard-go: an initiation
// already sent keeps being retransmitted every five seconds for ninety seconds, and while a
// keepalive is set the device starts a fresh round on every one of them, so it never stops at
// all. Writing the peer back fresh stops its timers at once. The peer stays on the device, so a
// handshake the far side starts is still answered, and nothing is routed to it. Same key, same
// endpoint, so nothing about which peer this is changes; only its timers do.
//
// It CREATES the peer, unlike punchDoc, so it is only ever written for a peer the tunnel tracks
// with the peer-write lock held (Tunnel.quietDirectPeer, SetDirectPeers' arm): a quiet raced
// against a removal must not bring the removed peer back.
func quietDoc(p Peer, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", p.PublicKeyHex)
	b.WriteString("remove=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", p.PublicKeyHex)
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("persistent_keepalive_interval=0\n")
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
