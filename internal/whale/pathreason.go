// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// pathreason.go is the WHY beside the PATH cell.
//
// A path column that only ever says `relayed` or `direct-local` makes every failure look
// identical, and they are not: a peer the control plane offered no endpoint for, a peer whose
// traversal is still in its first ten seconds, and a peer that tried a full minute across every
// endpoint anyone knows about and got nothing back are three different findings with three
// different next steps. Rendering all of them as the absence of a direct path is the shape that
// turns a diagnosable problem into a shrug.
//
// So `relayed because the punch failed` is a first-class outcome here, with its attempt count
// and the endpoints it tried, and it is built from what THIS host's tunnel actually did rather
// than from what the control plane said it might do. The control plane can only publish a
// candidacy: the handshake it would need to observe never touches a box. That is why the tunnel
// publishes its own record (wgtun's pathstate.go) and why this file reads it.

// PunchEvidence is what the local tunnel published about the traversal to one peer. The zero
// value means nothing published anything, which is honestly reported as "not known here" rather
// than as a failure.
type PunchEvidence struct {
	// Phase is wgtun's punch phase: "idle", "punching", "established", "gave-up", or "" when
	// no record was found.
	Phase string
	// Attempts is how many punch attempts the current or last train made.
	Attempts int
	// Candidates is how many distinct endpoints there were to try.
	Candidates int
	// Endpoint is the endpoint carrying the path, or the last one tried.
	Endpoint string
	// Source is the evidence class of that endpoint (local, public, observed, roamed).
	Source string
	// Age is how old the published record is, and Stale says it is too old to trust.
	Age   time.Duration
	Stale bool
	// Found is true when a record for this peer was read at all. It is what separates "this
	// host has nothing to say about that peer" from "this host says the path failed".
	Found bool
	// Direct is the device's own truth: this peer's address is routed to it right now, which
	// only happens after a handshake landed. It is NOT the control plane's candidacy.
	Direct bool
	// Class is the path class that record carried (direct-local / direct-public / direct-punch).
	Class string
}

// InFlight reports whether a traversal is running for this peer right now, which is the ONLY
// state in which waiting for a direct path can produce one. Every other state is settled: an
// established path is already there, a spent train has said what it found, and a peer with no
// endpoint to aim at has nothing in flight to wait for.
func (e PunchEvidence) InFlight() bool { return e.Found && e.Phase == string(wgtun.PunchTrying) }

// EvidenceFor turns one published peer record into the evidence the surface renders. rec comes
// from wgtun.PathStateRecord.PeerFor; age and stale come from the record that held it.
func EvidenceFor(rec wgtun.PathPeerRecord, age time.Duration, stale bool) PunchEvidence {
	return PunchEvidence{
		Phase:      rec.Punch.Phase,
		Attempts:   rec.Punch.Attempts,
		Candidates: rec.Punch.Candidates,
		Endpoint:   firstNonEmpty(rec.Punch.Winner, rec.Punch.Trying, rec.Endpoint),
		Source:     rec.Punch.WinnerSource,
		Age:        age,
		Stale:      stale,
		Found:      true,
		// A stale record is not evidence of a live path. It is evidence that something stopped
		// updating, which ReasonFor says out loud - but it may not carry a direct claim.
		Direct: rec.Promoted && !stale,
		Class:  rec.Path,
	}
}

// ObservationFor builds the whole Observation for one peer from the local record. It is the ONE
// place a published record becomes a path claim, so the rule that a direct path needs the /128
// to be actually routed - not merely offered - is enforced once.
func ObservationFor(rec wgtun.PathPeerRecord, age time.Duration, stale bool) Observation {
	e := EvidenceFor(rec, age, stale)
	return Observation{Direct: e.Direct, Class: e.Class, Punch: e}
}

// WithProbe folds a measurement into an observation that was built from the local record.
//
// The one rule it exists to enforce: a probe that ran and got NOTHING back retracts the direct
// claim. The device can be routing a /128 to a peer that has just stopped answering - that is
// exactly the window the demote closes, and for the seconds before it does, printing
// `direct-punch` beside a peer nothing can reach would be the surface lying on the device's
// behalf. An UNMEASURED observation is left alone: not probing is not evidence of anything.
func (o Observation) WithProbe(measured, reachable bool) Observation {
	o.Measured = measured
	o.Reachable = reachable
	if measured && !reachable {
		o.Direct = false
	}
	return o
}

// ReasonFor is the sentence beside the PATH cell: what is carrying this peer, and why that and
// not something else. It never invents a cause it was not told, and it never renders a missing
// record as a failure.
func ReasonFor(o Observation) string {
	e := o.Punch
	stale := ""
	if e.Stale && e.Found {
		stale = fmt.Sprintf("this reading is %s old, so it may no longer be true: ", roundAge(e.Age))
	}
	if o.Direct && DirectPathAvailable {
		via := ""
		if e.Endpoint != "" {
			via = " via " + e.Endpoint
		}
		how := ""
		if src := wgtun.CandidateSource(e.Source); src != "" {
			how = ", " + src.Why()
		}
		after := ""
		if e.Attempts > 0 {
			after = fmt.Sprintf(", after %s", plural(e.Attempts, "attempt"))
		}
		return stale + "direct" + via + how + after + "; the relay stays installed as the fallback"
	}
	if o.Measured && !o.Reachable {
		return stale + "nothing answered. On this network the usual cause is a pair split across " +
			"two boxes, which has no path between them at all"
	}
	switch e.Phase {
	case string(wgtun.PunchTrying):
		at := ""
		if e.Endpoint != "" {
			at = ", currently at " + e.Endpoint
		}
		return stale + fmt.Sprintf(
			"relayed while a direct path is being opened: %s so far across %s%s. "+
				"Traffic is unaffected meanwhile - it keeps going through the box",
			plural(e.Attempts, "attempt"), plural(e.Candidates, "endpoint"), at)
	case string(wgtun.PunchGaveUp):
		return stale + fmt.Sprintf(
			"relayed because the punch failed: %s across %s, and nothing came back. "+
				"This is what a peer behind a NAT that gives every destination a different "+
				"external port looks like from here. It will be tried again",
			plural(e.Attempts, "attempt"), plural(e.Candidates, "endpoint"))
	case string(wgtun.PunchIdle):
		return stale + "relayed: no endpoint was offered for this peer, so there was nothing to " +
			"aim a direct path at"
	case string(wgtun.PunchEstablished):
		// The record says established but the address is not routed here, so the honest answer is
		// the relay. Saying which of the two disagreed is what makes it debuggable.
		return stale + "relayed: a direct path was reported but this peer holds no address on " +
			"the tunnel, so the box is what is carrying it"
	}
	if !e.Found {
		return "relayed: no tunnel on this host has published a path for this peer, so the box " +
			"is what carries it"
	}
	return stale + "relayed: the box both peers terminate on is carrying this traffic"
}

// roundAge renders a duration the way a person would say it: seconds under a minute, then
// minutes, then hours, then days. Never more precision than the thing being timed has, and
// never a negative sign - a caller that hands it a backwards interval means the magnitude,
// and a leading minus in a duration reads as a clock error rather than as a length.
//
// The days branch exists for the snapshot age (snapshot.go), which legitimately reaches
// them: a zone nothing has written to in a week is exactly the case worth naming, and
// "168h" is a number a reader has to divide before it means anything.
func roundAge(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

// plural writes "1 attempt" / "3 attempts" so no sentence has to say "attempt(s)".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
