// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// snapshot.go answers one question: "how old is the answer this node just gave me".
//
// WHY IT EXISTS. A node can keep serving a copy of its configuration after it has lost
// contact with the primary, and from the outside it looks perfectly healthy either way.
// The choice made here is VISIBILITY rather than expiry: a fleet that stops answering is
// worse than one that answers a little late, so this reports the age of the copy and lets
// an operator decide what to do about it.
//
// WHY A CLIENT CAN COMPUTE IT AT ALL. Zone serials here are epoch-anchored, so a serial
// can be read as an approximate last-changed time. That makes staleness readable from a
// single SOA query per node, with no new server surface, no metrics endpoint and no
// credential. Deriving it from what a node already publishes beats fetching it from
// somewhere else, and it works from a laptop.
//
// Nothing in here queries anything. It takes serials that a caller read and turns them
// into an age and a sentence, so the rules can be tested exactly and the network part
// stays where the network already is.

// epochAnchorFloor is the earliest serial we will read as a timestamp (2020-09-13). Below
// it the number is a hand-written or imported serial (the classic YYYYMMDDnn form lands
// near 2.0e9 only by accident, and the small counters do not land near it at all), and
// reading one as seconds would print an age of decades with total confidence.
const epochAnchorFloor = 1_600_000_000

// serialLeadTolerance is how far AHEAD of the reader's clock a serial may sit and still be
// read as fresh. A busy zone can legitimately run a little into the future; beyond
// this the honest answer is that the two clocks (or the anchoring) disagree, not
// that the zone is fresh.
const serialLeadTolerance = time.Hour

// SnapshotAge is one node's answer about one zone.
type SnapshotAge struct {
	// Server is the nameserver that answered, as it was addressed.
	Server string `json:"server"`
	// Serial is the SOA serial it returned. Zero when the read failed.
	Serial uint32 `json:"serial,omitempty"`
	// Age is how long ago the zone last changed, per that serial. Only meaningful when
	// Known is true; it is never negative, because a negative age reads as freshness.
	Age time.Duration `json:"-"`
	// AgeSeconds is Age in whole seconds, for --json.
	AgeSeconds int64 `json:"age_seconds,omitempty"`
	// Known is true only when the serial could honestly be read as a timestamp.
	Known bool `json:"known"`
	// Note says why, whenever Known is false. Empty when Known is true.
	Note string `json:"note,omitempty"`
}

// AgeOf turns one serial into an age. It returns Known=false rather than a number it
// cannot stand behind, because the whole point of this line is that a person trusts it.
func AgeOf(server string, serial uint32, now time.Time) SnapshotAge {
	s := SnapshotAge{Server: server, Serial: serial}
	switch {
	case serial == 0:
		s.Note = "the zone answered with serial 0, so there is nothing to date it by"
		return s
	case int64(serial) < epochAnchorFloor:
		s.Note = fmt.Sprintf(
			"serial %d is not epoch-anchored, so it cannot be read as a time", serial)
		return s
	}
	delta := now.Sub(time.Unix(int64(serial), 0))
	if delta < -serialLeadTolerance {
		s.Note = fmt.Sprintf(
			"serial %d is %s ahead of this host's clock, so either the zone is not epoch-anchored"+
				" or this host's clock is behind", serial, roundAge(-delta))
		return s
	}
	if delta < 0 {
		delta = 0 // a busy zone runs a little ahead; that is fresh, not negative
	}
	s.Age, s.AgeSeconds, s.Known = delta, int64(delta.Seconds()), true
	return s
}

// SnapshotNote is the one line printed under `whale status`. It says how old each node's
// copy is, and it says the DIVERGENCE out loud when the nodes disagree, because two nodes
// answering from different snapshots is exactly the state this line exists to expose.
//
// An empty slice yields an empty string: a line that says nothing is worse than no line.
func SnapshotNote(zone string, ages []SnapshotAge) string {
	if len(ages) == 0 {
		return ""
	}
	sorted := make([]SnapshotAge, len(ages))
	copy(sorted, ages)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Server < sorted[j].Server })

	parts := make([]string, 0, len(sorted))
	serials := map[uint32]bool{}
	known := 0
	var oldest time.Duration
	for _, a := range sorted {
		if a.Known {
			known++
			serials[a.Serial] = true
			if a.Age > oldest {
				oldest = a.Age
			}
			parts = append(parts, a.Server+" "+roundAge(a.Age))
			continue
		}
		parts = append(parts, a.Server+" unknown ("+a.Note+")")
	}
	line := zone + " snapshot age: " + strings.Join(parts, ", ") + "."
	switch {
	case known == 0:
		return line + " Nothing here could be dated, so treat every answer about who may log in as" +
			" of unknown age."
	case len(serials) > 1:
		return line + " THE NODES DISAGREE: they are answering from different snapshots, so which one" +
			" replies decides what you are told. Treat the older node's answer as unreliable until they" +
			" converge."
	case oldest >= staleAfter:
		return line + " That is older than a healthy fleet runs. Treat this node's answer as unreliable" +
			" until it catches up."
	default:
		return line + " Every node is answering from the same recent snapshot."
	}
}

// staleAfter is when an age stops being ordinary and starts being worth a sentence. The
// ordinary write rate keeps a healthy fleet far below it; a zone
// that has not changed in a day is either idle or cut off, and the two look identical
// from here, which is precisely why the line says what it says rather than judging.
const staleAfter = 24 * time.Hour
