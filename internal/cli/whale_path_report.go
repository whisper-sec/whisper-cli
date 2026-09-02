// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_path_report.go joins the two halves of the truth about a path.
//
// The process holding the tunnel is the only one that knows whether a direct handshake landed:
// a direct handshake never touches a box, so the control plane can only ever publish a
// candidacy. `whale status` and `whale ping` run in a different process, so the tunnel writes
// what its device says into ~/.config/whisper/paths (see wgtun's pathstate.go) and this file
// reads it back.
//
// Every failure here is silent and lands on the relayed answer, which is the truthful default:
// no record, an unreadable record, a record from a tunnel that has since died, all mean "this
// host cannot say a direct path exists", and the box is what carries a peer with no direct path.

// pathEvidence is a lookup from a peer's overlay address to what this host's tunnels published
// about the path to it. The zero-value answer (Found false) means nothing published anything.
type pathEvidence struct {
	byAddr map[string]whale.PunchEvidence
}

// readPathEvidence loads the published records on this host.
//
// selfAddr, when known, picks the record written by THIS node's tunnel; without it the records
// are merged, preferring one that reports a live direct path. A host running one agent (the
// overwhelmingly common case) has exactly one record either way.
func readPathEvidence(selfAddr string) pathEvidence {
	ev := pathEvidence{byAddr: map[string]whale.PunchEvidence{}}
	self := strings.TrimSpace(strings.Trim(selfAddr, "[]"))
	for _, rec := range wgtun.ReadPathStates("") {
		if self != "" && !strings.EqualFold(rec.Address, self) {
			continue
		}
		age, stale := rec.Age(), rec.Stale()
		for _, p := range rec.Peers {
			key := strings.ToLower(p.Address)
			cand := whale.EvidenceFor(p, age, stale)
			// A second record for the same peer only wins if it carries better news: a live
			// direct path beats a relayed one, because one of this host's tunnels really does
			// have that path even if another does not.
			if cur, seen := ev.byAddr[key]; seen && cur.Direct && !cand.Direct {
				continue
			}
			ev.byAddr[key] = cand
		}
	}
	return ev
}

// For returns what this host knows about the path to one peer address.
func (e pathEvidence) For(address string) whale.PunchEvidence {
	if e.byAddr == nil {
		return whale.PunchEvidence{}
	}
	return e.byAddr[strings.ToLower(strings.TrimSpace(strings.Trim(address, "[]")))]
}

// Observation builds the path claim for one peer: the device's own record when there is one,
// falling back to the control plane's class when there is not. That fallback is what keeps a
// keyless or freshly started host printing the same thing it printed before any of this existed.
func (e pathEvidence) Observation(address, controlPlaneClass string) whale.Observation {
	ev := e.For(address)
	if !ev.Found {
		return whale.Observation{Direct: controlPlaneClass != "", Class: controlPlaneClass}
	}
	return whale.Observation{Direct: ev.Direct, Class: ev.Class, Punch: ev}
}

// whaleUntilDirectWait bounds `whale ping --until-direct`. One punch train is sixty seconds, so
// a wait shorter than that would give up while the answer was still being worked out, and a
// wait much longer would be waiting for a second train that the first already told us about.
const whaleUntilDirectWait = 75 * time.Second

// waitForDirectPath waits for an in-flight traversal to SETTLE - either a direct path appears
// or the train gives up - and returns the last evidence read.
//
// It polls the published record rather than doing anything itself, because the punching is
// already happening in the tunnel's own process and a second thing driving it would be a second
// thing to get wrong. It returns the moment the answer is known, so the common case costs a
// second or two rather than the whole budget, and it never blocks a caller that has no tunnel
// on this host: an evidence-free peer has nothing in flight and returns at once.
func waitForDirectPath(address string, within time.Duration) whale.PunchEvidence {
	cx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	ev := readPathEvidence("").For(address)
	for ev.InFlight() {
		select {
		case <-cx.Done():
			return ev
		case <-time.After(time.Second):
		}
		ev = readPathEvidence("").For(address)
	}
	return ev
}
