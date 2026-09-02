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
	// DirectClass is the class the control plane assigned to this pair (PathDirectLocal /
	// PathDirectPublic / PathDirectPunched), or empty when it says the path is relayed.
	// It is a CANDIDACY, not an outcome: the control plane cannot know whether the
	// handshake landed, because a direct handshake never touches a box. It is used only
	// when this host published no record of its own.
	DirectClass string
	// Evidence is what the local tunnel published about this peer (wgtun's path record),
	// and it OUTRANKS DirectClass wherever it exists, because it is the device's own truth
	// rather than an offer. Its zero value means nothing published anything, which is not
	// a failure and is not reported as one.
	Evidence PunchEvidence
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
			// A refusal came back over the network, so it has a real round trip; the
			// probe cannot report one on an error, so time the call here.
			if att.Outcome == OutcomeRefused {
				att.RTTMs = ms(elapsed)
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
	// The device's own record outranks the control plane's offer. WithProbe then retracts a
	// direct claim that this run's own packets just contradicted.
	obs := Observation{Direct: opts.DirectClass != "", Class: opts.DirectClass}
	if opts.Evidence.Found {
		obs = Observation{Direct: opts.Evidence.Direct, Class: opts.Evidence.Class, Punch: opts.Evidence}
	}
	obs = obs.WithProbe(sum.Sent > 0, sum.Answered > 0)
	sum.Path = PathFor(obs)
	sum.Why = ReasonFor(obs)
	sum.Note = pingNote(sum)
	return sum
}

// pingNote states what the run proved, and for a silent run names both causes rather
// than leaving a zero to be read as "the peer is down".
func pingNote(s PingSummary) string {
	switch {
	case s.Sent == 0:
		return "no attempt ran"
	case s.Answered > 0 && s.Path != PathRelayed && s.Path != PathNoPath:
		return "the path exists and it is direct: these packets did not go through a box, " +
			"so this round trip is the raw network between the two nodes."
	case s.Answered > 0:
		return "the path exists and it is relayed by a Whisper box, so this round trip " +
			"includes the hairpin out to the box and back."
	case s.hasOutcome(OutcomeNoRoute):
		return "this host could not send the packet at all: it has no route to the peer's " +
			"address family. That is a local network fault, not a fault at the peer."
	default:
		return "nothing came back. Either the peer terminates on a different box, which has " +
			"no path today, or nothing is listening and the refusal is being dropped."
	}
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
