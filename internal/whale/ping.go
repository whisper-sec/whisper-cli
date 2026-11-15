// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ping.go measures a real round trip to a peer's /128 and says what the result proves.
//
// Why TCP and not ICMP: an ICMP echo needs a raw socket (root) or an unprivileged ping
// socket the operator has to enable first, and `whale ping` has to work for an ordinary
// user on a stock host on day one. A TCP connect needs nothing, and it carries MORE
// information than an echo does, because a refusal is as informative as an accept:
//
//	connect succeeds -> the packet reached the peer and something is listening
//	connect refused -> the packet reached the peer and came back; the path exists
//	timeout -> nothing came back. On Whalenet today the usual cause is a pair
//	                     split across two boxes, which has no path at all
//	no route -> this host has no IPv6 route; the fault is local, not the peer's
//
// Those four are different findings and the renderer must not collapse them into a bare
// "0 replies", which is the shape that turns a local misconfiguration into a bug report
// about the fleet.

// DefaultPingPort is :443, the port every box serves and the one an AnyIP-delivered
// /128 answers on. It is a flag, because a Tier-1 peer may listen anywhere.
const DefaultPingPort = 443

// TCPProbe is the one measurement ping needs. NetProber implements it.
type TCPProbe interface {
	TCP(ctx context.Context, server netip.Addr, port int) (time.Duration, error)
}

// Outcome classifies one attempt. The zero value is OutcomeNoReply.
type Outcome string

const (
	// OutcomeOpen: connected. The path exists and a service answered.
	OutcomeOpen Outcome = "open"
	// OutcomeRefused: the peer (or the box delivering its /128) sent us a refusal. The
	// path exists; nothing is listening on that port.
	OutcomeRefused Outcome = "refused"
	// OutcomeNoReply: nothing came back before the deadline.
	OutcomeNoReply Outcome = "no reply"
	// OutcomeNoRoute: this host could not even send. The fault is local.
	OutcomeNoRoute Outcome = "no route"
)

// Answered reports whether the network came back to us, which is what proves a path.
func (o Outcome) Answered() bool { return o == OutcomeOpen || o == OutcomeRefused }

// Attempt is one probe.
type Attempt struct {
	Seq     int     `json:"seq"`
	Outcome Outcome `json:"outcome"`
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Detail  string  `json:"detail,omitempty"`
	// Path is what carried this answered attempt (the PATH vocabulary). Empty when nothing came back.
	Path string `json:"path,omitempty"`
}

// PingSummary is the whole run.
type PingSummary struct {
	Target   string    `json:"target"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	Sent     int       `json:"sent"`
	Answered int       `json:"answered"`
	MinMs    float64   `json:"min_ms,omitempty"`
	AvgMs    float64   `json:"avg_ms,omitempty"`
	MaxMs    float64   `json:"max_ms,omitempty"`
	Path     string    `json:"path"`
	Attempts []Attempt `json:"attempts"`
	// From is the /128 the probes left from: the node whose tunnel on this host carried them. Empty
	// when they left from the host's own address, which no tunnel carries.
	From string `json:"from,omitempty"`
	// Why is the sentence beside the path: what is carrying this peer and why that rather
	// than something else, including "relayed because the punch failed" as a finding in its
	// own right rather than as the absence of a direct path.
	Why  string `json:"why,omitempty"`
	Note string `json:"note,omitempty"`
}

// OK reports whether any attempt proved a path.
func (s PingSummary) OK() bool { return s.Answered > 0 }

// PingOptions configures one run.
type PingOptions struct {
	Target   string // what the user typed, for the output
	Address  string // the resolved /128
	Port     int
	Count    int
	Interval time.Duration
	// Tunnel is the tunnel on this host the probes go through, or nil when they leave from the
	// host's own address. Only a probe that goes through a tunnel can take a direct path: on the
	// userspace tier the node's /128 and its direct peers exist only inside the process holding
	// the tunnel, so the host's own connect is routed to the box that announces the agent block,
	// the box delivers it, and the answer comes back the same way. nil is therefore always
	// relayed, whatever any tunnel on the host has published.
	//
	// There is deliberately no way to pass the control plane's class here. It is a candidacy: the
	// plane cannot see whether a direct handshake landed, and a path that was offered is not a
	// path the packets took.
	Tunnel *PingTunnel
	// HostSource is, for a run with no Tunnel, the address this host's routing would send the
	// probe from (the caller learns it without sending anything). It is what the sentence names:
	// a non-agent address is the host's own, outside every tunnel; an agent address is a tunnel
	// this CLI does not hold. Invalid when it could not be learned.
	HostSource netip.Addr
}

// OutcomeError is a probe failure that already knows its outcome, so the classifier does not have
// to read it out of an error's text. The tunnel probe uses it: through a SOCKS proxy only one reply
// code is a refusal from the far end, and a local failure to reach the proxy is not an answer.
type OutcomeError struct {
	Outcome Outcome
	Detail  string
}

func (e *OutcomeError) Error() string { return e.Detail }

// PingTunnel is the tunnel a probe goes through: the node's /128, and a reader for what that
// tunnel's device publishes about the peer (wgtun's path record).
type PingTunnel struct {
	From string
	// Read returns the published evidence for the peer. Ping reads it before the first probe and
	// again after every answered one, and calls an answer direct only when every read names the
	// same routed period (PunchEvidence.Epoch and Instance). While the device holds the peer's /128
	// on the direct peer, wireguard-go sends every probe to that peer (longest-prefix match) and
	// accepts an answer from the peer's address only from that peer (it drops a packet whose source
	// the delivering peer does not hold), so an answer that came back through a box in that period
	// would have been dropped, not counted. The tunnel publishes the end of a routed period before
	// any write of its own takes the /128 away, which makes the claim exact for every write the
	// tunnel makes; a removal it did not make is found, and published, on its monitor's next tick.
	Read func() PunchEvidence
}

// Ping runs Count attempts against one address, calling onAttempt (when non-nil) as each
// completes so the command can stream lines the way ping(8) does. It never returns an
// error: every failure mode is an Attempt with a name.
func Ping(ctx context.Context, addr netip.Addr, opts PingOptions, probe TCPProbe, onAttempt func(Attempt)) PingSummary {
	if opts.Count <= 0 {
		opts.Count = 3
	}
	if opts.Port <= 0 {
		opts.Port = DefaultPingPort
	}
	if opts.Interval <= 0 {
		opts.Interval = 300 * time.Millisecond
	}
	sum := PingSummary{
		Target:  firstNonEmpty(opts.Target, opts.Address),
		Address: opts.Address,
		Port:    opts.Port,
	}
	v := newVerdict(opts.Tunnel, opts.HostSource)
	if opts.Tunnel != nil {
		sum.From = opts.Tunnel.From
	}
	var total float64
	for i := 1; i <= opts.Count; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 1 {
			select {
			case <-ctx.Done():
			case <-time.After(opts.Interval):
			}
			if ctx.Err() != nil {
				break
			}
		}
		start := time.Now()
		rtt, err := probe.TCP(ctx, addr, opts.Port)
		elapsed := time.Since(start)
		att := Attempt{Seq: i}
		if err == nil {
			att.Outcome, att.RTTMs = OutcomeOpen, ms(rtt)
		} else {
			att.Outcome, att.Detail = classify(err)
			// A refusal came back over the network, so it has a real round trip. A probe that
			// timed the exchange itself says so; otherwise the call is timed here.
			if att.Outcome == OutcomeRefused {
				att.RTTMs = ms(elapsed)
				if rtt > 0 {
					att.RTTMs = ms(rtt)
				}
			}
		}
		if att.Outcome.Answered() {
			att.Path = PathRelayed
			switch {
			case opts.Tunnel == nil:
				att.Path = PathEdge
			case !v.before.Published:
				att.Path = PathUnknown
			}
			if direct, ok := v.answered(); ok {
				att.Path = direct
			}
		}
		sum.Sent++
		if att.Outcome.Answered() {
			sum.Answered++
			total += att.RTTMs
			if sum.MinMs == 0 || att.RTTMs < sum.MinMs {
				sum.MinMs = att.RTTMs
			}
			if att.RTTMs > sum.MaxMs {
				sum.MaxMs = att.RTTMs
			}
		}
		sum.Attempts = append(sum.Attempts, att)
		if onAttempt != nil {
			onAttempt(att)
		}
	}
	if sum.Answered > 0 {
		sum.AvgMs = total / float64(sum.Answered)
	}
	obs := v.observation().WithProbe(sum.Sent > 0, sum.Answered > 0)
	sum.Path = PathFor(obs)
	sum.Why = ReasonFor(obs)
	sum.Note = pingNote(sum)
	return sum
}

// verdict is the path claim of one run, built from the tunnel's own record as the run went.
type verdict struct {
	tunnel   *PingTunnel
	source   netip.Addr    // the host's own source, for a run with no tunnel
	before   PunchEvidence // the record before the first probe
	answers  int
	direct   int  // answers whose re-read still named the routed period of before
	moved    bool // an answer's re-read named another period, or none
	measured bool
}

func newVerdict(t *PingTunnel, source netip.Addr) *verdict {
	v := &verdict{tunnel: t, source: source}
	if t != nil && t.Read != nil {
		v.before = t.Read()
	}
	return v
}

// answered re-reads the record after an answer and returns the direct class it may carry, if any.
func (v *verdict) answered() (string, bool) {
	v.answers++
	if v.tunnel == nil || v.tunnel.Read == nil || !v.before.Direct || v.before.Epoch == 0 {
		return "", false
	}
	now := v.tunnel.Read()
	if !now.Direct || now.Epoch != v.before.Epoch || now.Instance != v.before.Instance {
		v.moved = true
		return "", false
	}
	v.direct++
	return PathFor(Observation{Direct: true, Class: v.before.Class}), true
}

// observation is the run's claim: direct only when the probes went through a tunnel and every
// answer was placed on the routed period the record named before the first one.
func (v *verdict) observation() Observation {
	if v.tunnel == nil {
		return Observation{Vantage: VantageHost, HostSource: v.source}
	}
	o := Observation{Vantage: VantageTunnel, Via: v.tunnel.From, Class: v.before.Class, Punch: v.before}
	switch {
	case v.answers > 0 && v.direct == v.answers:
		o.Direct = true
	case v.answers == 0:
		// Nothing came back; WithProbe retracts any claim, and the reason says nothing answered.
		o.Direct = v.before.Direct
	default:
		o.Changed = v.moved
	}
	return o
}

// pingNote states what the run proved, and for a silent run names both causes rather
// than leaving a zero to be read as "the peer is down".
func pingNote(s PingSummary) string {
	switch {
	case s.Sent == 0:
		return "no attempt ran"
	case s.Answered > 0 && s.Path == PathEdge:
		return "an answer came from Whisper's edge for that address. It shows neither that the node " +
			"is up nor the path between two nodes: the box that took the probe answers for the address " +
			"itself when the node is not connected to it."
	case s.Answered > 0 && s.Path == PathUnknown:
		return "the path exists; whether a box was in the middle is not known here."
	case s.Answered > 0 && s.Path != PathRelayed && s.Path != PathNoPath:
		return "the path exists and it is direct: these packets did not go through a box, " +
			"so this round trip is the network between the two nodes and the tunnel's work at each end."
	case s.Answered > 0:
		return "the path exists and it is relayed by a Whisper box, so this round trip " +
			"includes the hairpin out to the box and back."
	case s.hasOutcome(OutcomeNoRoute):
		return "this host could not send the packet at all: " + s.noRouteWhy() + ". That is a " +
			"local network fault, not a fault at the peer."
	default:
		return "nothing came back. Either the peer terminates on a different box, which has " +
			"no path today, or nothing is listening and the refusal is being dropped."
	}
}

// noRouteWhy is the first no-route attempt's own reason, or the usual one when it gave none.
func (s PingSummary) noRouteWhy() string {
	for _, a := range s.Attempts {
		if a.Outcome == OutcomeNoRoute && strings.TrimSpace(a.Detail) != "" {
			return a.Detail
		}
	}
	return "it has no route to the peer's address family"
}

func (s PingSummary) hasOutcome(o Outcome) bool {
	for _, a := range s.Attempts {
		if a.Outcome == o {
			return true
		}
	}
	return false
}

// classify turns a dial error into one of the four outcomes.
//
// It reads the message text rather than comparing errno constants because the constant
// set is not the same on every platform this binary ships to (linux, darwin, windows),
// and a build-tagged classifier would put the four outcomes in three places. The text Go
// produces for these conditions is stable across its supported platforms, and an
// unrecognised error degrades to "no reply" with the original message attached, so
// nothing is ever silently swallowed.
func classify(err error) (Outcome, string) {
	if err == nil {
		return OutcomeOpen, ""
	}
	var oe *OutcomeError
	if errors.As(err, &oe) {
		return oe.Outcome, oe.Detail
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return OutcomeNoReply, "timed out"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return OutcomeNoReply, "timed out"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "connection reset"):
		return OutcomeRefused, "refused"
	case strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "address family not supported"),
		strings.Contains(msg, "unreachable network"),
		strings.Contains(msg, "unreachable host"):
		return OutcomeNoRoute, shortErr(err)
	default:
		return OutcomeNoReply, shortErr(err)
	}
}

// shortErr trims Go's dial prefix so a line reads like ping(8) rather than like a stack.
func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		return msg[i+2:]
	}
	return msg
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
