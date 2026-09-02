// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"sort"
	"time"
)

// watch.go holds the diff behind `whisper alerts watch`, and the one rule that keeps a
// terminal tail from becoming the thing an operator closes.
//
// The rule: emit on a STATE change, never on a severity change. Severity is derived and
// will move as the graph improves, so a feed that emits on it gets noisier every time our
// intelligence gets better, which is exactly backwards. The single exception is a
// PROMOTION - a lane crossing upward, which is the one raise the design permits to cross
// a lane boundary on its own - and even that is emitted once, on the crossing.
//
// A demotion is never emitted. A row that quietly falls out of act-now has not become
// interesting; it has become less interesting, and telling somebody about it at 03:00
// would be paying for a graph update with an interruption.

// Change tokens. Closed set, additive.
const (
	// ChangeOpened is a condition that was not standing on the previous read.
	ChangeOpened = "opened"
	// ChangeResolved is a condition the plane no longer reports open. Nothing closes
	// itself on the plane today, so in practice this follows a human or an auto-resolve.
	ChangeResolved = "resolved"
	// ChangePromoted is a lane crossing upward.
	ChangePromoted = "promoted"
	// ChangeHeld is somebody taking it: an acknowledgement or an assignment appearing.
	ChangeHeld = "held"
	// ChangeReleased is that mark going away again, which puts the row back in the queue.
	ChangeReleased = "released"
	// ChangeSevered is a control action landing on the endpoint after the finding began:
	// the moment a page becomes a receipt.
	ChangeSevered = "severed"
)

// Change is one emitted event.
type Change struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"`
	Ref  string    `json:"ref"`
	Lane string    `json:"lane"`
	// Was and Now carry the two sides of whatever actually moved: a lane on a promotion,
	// a holder on a hold or a release, an empty pair on an open or a resolve.
	Was string `json:"was,omitempty"`
	Now string `json:"now,omitempty"`
	// Line is the one-line human form. Prose: never key, diff or parse it.
	Line string `json:"line"`
	// Alert is the full row as of this change, so a consumer piping NDJSON never has to
	// make a second call to act.
	Alert Alert `json:"alert"`
}

// Snapshot is what a watch remembers between polls. It holds only the cells the diff is
// allowed to look at, which is the mechanical guarantee that a severity move cannot emit.
type Snapshot struct {
	rows map[string]watched
}

type watched struct {
	lane        string
	state       string
	holder      string
	disposition string
	alert       Alert
}

// Snap folds a book into the state a diff compares against.
func Snap(b *Book, opt Options) Snapshot {
	now := opt.now()
	s := Snapshot{rows: make(map[string]watched, len(b.Rows))}
	doc := b.Render(opt)
	byRef := make(map[string]Alert, len(doc.Alerts))
	for _, a := range doc.Alerts {
		byRef[a.Ref] = a
	}
	for _, r := range b.Rows {
		ref := r.Ref()
		s.rows[ref] = watched{
			lane:        r.Lane,
			state:       r.State,
			holder:      r.Holder(),
			disposition: Disposition(r, b.Trail, now),
			alert:       byRef[ref],
		}
	}
	return s
}

// Empty reports a snapshot that has never been filled, which is how a watch knows its
// first poll is a baseline rather than a burst of "opened" for everything standing.
func (s Snapshot) Empty() bool { return s.rows == nil }

// Diff emits the changes between two snapshots, oldest condition first for a stable tail.
// A nil or empty previous snapshot emits nothing: the first poll of a watch establishes
// the baseline, because printing the whole standing book as news would be the one thing a
// tail must not do.
func Diff(prev, next Snapshot, at time.Time) []Change {
	if prev.Empty() {
		return nil
	}
	var out []Change
	refs := make([]string, 0, len(next.rows))
	for ref := range next.rows {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	for _, ref := range refs {
		now := next.rows[ref]
		was, seen := prev.rows[ref]
		if !seen {
			out = append(out, Change{At: at, Kind: ChangeOpened, Ref: ref, Lane: now.lane,
				Line: ref + " opened in " + LaneProse(now.lane), Alert: now.alert})
			continue
		}
		if was.lane != now.lane && LaneRank(now.lane) < LaneRank(was.lane) {
			out = append(out, Change{At: at, Kind: ChangePromoted, Ref: ref, Lane: now.lane,
				Was: was.lane, Now: now.lane,
				Line:  ref + " moved up from " + LaneProse(was.lane) + " to " + LaneProse(now.lane),
				Alert: now.alert})
		}
		if was.holder == "" && now.holder != "" {
			out = append(out, Change{At: at, Kind: ChangeHeld, Ref: ref, Lane: now.lane,
				Now: now.holder, Line: now.holder + " took " + ref, Alert: now.alert})
		}
		if was.holder != "" && now.holder == "" {
			out = append(out, Change{At: at, Kind: ChangeReleased, Ref: ref, Lane: now.lane,
				Was: was.holder, Line: ref + " is back in the queue, " + was.holder + " let it go",
				Alert: now.alert})
		}
		if was.disposition != "severed" && now.disposition == "severed" {
			out = append(out, Change{At: at, Kind: ChangeSevered, Ref: ref, Lane: now.lane,
				Was: was.disposition, Now: now.disposition,
				Line:  "we severed the identity behind " + ref + ". the files on disk are unchanged",
				Alert: now.alert})
		}
	}

	gone := make([]string, 0)
	for ref := range prev.rows {
		if _, still := next.rows[ref]; !still {
			gone = append(gone, ref)
		}
	}
	sort.Strings(gone)
	for _, ref := range gone {
		was := prev.rows[ref]
		out = append(out, Change{At: at, Kind: ChangeResolved, Ref: ref, Lane: was.lane,
			Line: ref + " is no longer standing", Alert: was.alert})
	}
	return out
}
