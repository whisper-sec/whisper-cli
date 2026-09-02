// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"sort"
	"strings"
	"time"
)

// Book is one whole read of the alerting surface: the standing conditions, the
// endpoints they live on, the tenant's coverage envelope, the containment trail, the
// live suppressions - and, of equal weight, the READ STATUS of every one of those
// streams.
//
// The read status is not bookkeeping. A feed that failed to read and a feed with
// nothing in it render as the same blank space, and that is the easiest place in any
// security product to tell a comfortable lie. Every count this type derives is
// therefore nullable, and a stream that did not answer turns its counts into floors and
// says so in words.
type Book struct {
	Rows        []Row
	Endpoints   []Endpoint
	Coverage    Coverage
	Trail       []Action
	Suppression []Suppression

	// Streams is one entry per read attempted, in a stable order, whether it answered
	// or not. A stream absent from this slice was never attempted, which is a third
	// state again and renders differently from both of the others.
	Streams []Stream

	// ReadAt is when the read completed, and Endpoint is the control-plane host it went
	// to. Both are provenance: a count with no timestamp is a claim with no date on it.
	ReadAt   time.Time
	Endpoint string

	byAddr map[string]Endpoint
}

// Stream is the outcome of reading one plane surface.
type Stream struct {
	// Name is the stream as a person would name it in a sentence: "detections",
	// "coverage", "endpoints", "containment", "suppressions".
	Name string
	// Err is the read's failure, if it failed. A failed stream makes every count that
	// depends on it a floor.
	Err error
	// NotApplicable is a DEFINITE negative answer, which is a different thing from a
	// failure: an account with no partner organisation genuinely has no suppression
	// register, so nothing was hidden and no count is a floor. The string says why.
	NotApplicable string
	// Rows is how many rows came back. Meaningful only when the stream answered.
	Rows int
	// At is when this stream answered.
	At time.Time
}

// Answered reports a stream that returned a real answer, empty or not.
func (s Stream) Answered() bool { return s.Err == nil }

// Definite reports a stream whose answer can be relied on for arithmetic: it either
// answered, or it told us it does not apply.
func (s Stream) Definite() bool { return s.Err == nil || s.NotApplicable != "" }

// Index builds the address lookup. Call once after populating a Book; it is idempotent.
func (b *Book) Index() {
	b.byAddr = make(map[string]Endpoint, len(b.Endpoints))
	for _, e := range b.Endpoints {
		if a, ok := parseAddr(e.Address); ok {
			b.byAddr[a.String()] = e
		} else if e.Address != "" {
			b.byAddr[strings.ToLower(e.Address)] = e
		}
	}
}

// EndpointFor returns the endpoint a row lives on. A row whose endpoint was not read
// yields the zero Endpoint, whose Known() is false - and every rule in this package
// treats "not read" as live, never as offline.
func (b *Book) EndpointFor(r Row) Endpoint {
	if b.byAddr == nil {
		b.Index()
	}
	if a, ok := parseAddr(r.Address); ok {
		if e, hit := b.byAddr[a.String()]; hit {
			return e
		}
	}
	if e, hit := b.byAddr[strings.ToLower(r.Address)]; hit {
		return e
	}
	return Endpoint{}
}

// Incomplete lists the streams that did not answer. When it is non-empty, every count
// derived from this book is a FLOOR and the renderers say so.
func (b *Book) Incomplete() []Stream {
	var out []Stream
	for _, s := range b.Streams {
		if !s.Definite() {
			out = append(out, s)
		}
	}
	return out
}

// Complete reports whether the read spanned everything it claims. The absence of rows
// means the absence of conditions ONLY when this is true.
func (b *Book) Complete() bool { return len(b.Incomplete()) == 0 }

// LiveSuppressions are the rules actually holding quiet right now: not revoked, and not
// expired at the given instant. An expired rule is history, not a mute.
func (b *Book) LiveSuppressions(now time.Time) []Suppression {
	ms := now.UnixMilli()
	var out []Suppression
	for _, s := range b.Suppression {
		if s.Revoked {
			continue
		}
		if s.ExpiresAt > 0 && s.ExpiresAt <= ms {
			continue
		}
		out = append(out, s)
	}
	return out
}

// --- is it still true ---------------------------------------------------------------

// The three interrupt tokens. They are a SEPARATE axis from the lane, and keeping them
// separate is the whole design: a product that ships one number discovers it needs the
// other, and then the only lever an operator has is to lower the priority so it stops
// waking them. The cause survives, the channel dies, and the product never learns.
const (
	// InterruptPage means a decision this person alone can make, in the next few hours,
	// changes the outcome.
	InterruptPage = "page"
	// InterruptDigest means it is a fact to read when they next look.
	InterruptDigest = "digest"
	// InterruptSilent means it is counted and readable and asks for nobody.
	InterruptSilent = "silent"
)

// Verdict is an interrupt token together with the reason it came out that way. The
// reason is printed, because an interrupt decision a person cannot audit is one they
// will eventually route around.
type Verdict struct {
	Token  string
	Reason string
}

// NeverQuiet is the closed list of techniques on which no rule, suppression, quiet hour
// or lane demotion may buy silence. For these the cost of one miss is unbounded and the
// cost of one extra interruption is a phone call.
//
// T1486 ransomware, T1490 recovery and backup destruction, T1003 credential dumping,
// T1562 impairing defences, T1070 clearing the trail. The last two are the ones that
// matter most here: they are BOTH things we detect AND the inputs that quiet everything
// else on the host, so an attacker who succeeds at them must not thereby get quiet.
//
// Sub-techniques are covered: membership is tested on the T-number prefix, so T1003.001
// is on the list because T1003 is.
var NeverQuiet = []string{"T1486", "T1490", "T1003", "T1562", "T1070"}

// NeverQuietTechnique reports membership of the closed list above, sub-techniques
// included. Case-insensitive, because a person types what they remember.
func NeverQuietTechnique(technique string) bool {
	t := strings.ToUpper(strings.TrimSpace(technique))
	if t == "" {
		return false
	}
	base := t
	if i := strings.IndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	for _, n := range NeverQuiet {
		if base == n {
			return true
		}
	}
	return false
}

// Judge derives the interrupt for one row: not from its severity, which was decided by
// a detection author who has never seen this network, but from whether a human's
// decision still changes the outcome.
//
// Five questions, in the order they bind:
//
// 1. Is it still true? state open, and the plane's own act-now lane.
// 2. Did we already stop it? a landed containment on this endpoint after the finding
// began turns a page into a receipt. This is the gate no
// host-resident sensor can write, and it is the thesis.
// 3. Does a human have it? an acknowledgement or an assignee, both served cells, so
// an ack typed anywhere retires the interrupt everywhere.
// 4. Has that human moved? an acknowledgement nobody moved for staleAck is not quiet;
// it is an interruption that was absorbed and then dropped.
// 5. Is it still live? an endpoint the plane positively reports offline is not an
// emergency. Unknown never counts as offline: absence never lowers.
//
// Order matters at step two. Containment buys quiet because we ACTED; nothing about the
// evidence, the graph or the exposure ladder buys quiet in this function at all.
func Judge(r Row, e Endpoint, trail []Action, now time.Time, staleAck time.Duration) Verdict {
	if r.State != "" && r.State != StateOpen {
		return Verdict{InterruptSilent, "the plane no longer reports this open"}
	}
	switch r.Lane {
	case LaneActNow:
		// fall through to the gates
	case LaneReview:
		return Verdict{InterruptDigest, "the plane bands this for review, not for now"}
	case LaneUnscored:
		return Verdict{InterruptDigest, "never scored, so it is read rather than raised"}
	default:
		return Verdict{InterruptSilent, "banded below review; counted, not raised"}
	}

	if a, ok := severedAfter(trail, r, now); ok {
		return Verdict{InterruptDigest, "we severed this endpoint at " + a.stamp(now) + ", so this is a receipt"}
	}
	if r.Held() {
		age := ackAge(r, now)
		if staleAck > 0 && age > staleAck {
			return Verdict{InterruptPage, r.Holder() + " acknowledged this " + Age(age) + " ago and nothing moved"}
		}
		return Verdict{InterruptDigest, r.Holder() + " has it"}
	}
	if e.Known() && e.Offline() {
		if NeverQuietTechnique(r.Technique) {
			return Verdict{InterruptPage, "the endpoint is offline and we could not reach it either"}
		}
		return Verdict{InterruptDigest, "the endpoint is offline, so nothing can get worse there now"}
	}
	return Verdict{InterruptPage, "still true, still reachable, not contained, nobody has it"}
}

// stamp is when this action happened, dated whenever it did not happen today. The lines
// that print it report over the containment horizon, which is a week by default, so a
// bare clock time here would routinely name a moment several days back as if it were
// this morning.
func (a Action) stamp(now time.Time) string {
	if a.TsMs <= 0 {
		return "an unstamped moment"
	}
	return Stamp(a.TsMs, now)
}

// severedAfter finds a control action that LANDED on this row's endpoint at or after
// the finding began. Only a landed action counts: a refused or failed one is the
// opposite fact and the design's loudest signal.
func severedAfter(trail []Action, r Row, now time.Time) (Action, bool) {
	var best Action
	found := false
	for _, a := range trail {
		if !a.Landed() || !SameAddress(a.Address, r.Address) {
			continue
		}
		if r.FirstSeen > 0 && a.TsMs < r.FirstSeen {
			continue
		}
		if a.TsMs > now.UnixMilli() {
			continue
		}
		if !found || a.TsMs > best.TsMs {
			best, found = a, true
		}
	}
	return best, found
}

func ackAge(r Row, now time.Time) time.Duration {
	if r.AckAt == nil || *r.AckAt <= 0 {
		return 0
	}
	d := now.Sub(time.UnixMilli(*r.AckAt))
	if d < 0 {
		return 0
	}
	return d
}

// RowAge is how long a row has been true, from the plane's own age cell where it has
// one and from its first-seen stamp otherwise. Zero means the plane never stamped it,
// which is unknown rather than new.
func RowAge(r Row, now time.Time) time.Duration {
	if r.AgeMs != nil && *r.AgeMs > 0 {
		return time.Duration(*r.AgeMs) * time.Millisecond
	}
	if r.FirstSeen > 0 {
		if d := now.Sub(time.UnixMilli(r.FirstSeen)); d > 0 {
			return d
		}
	}
	return 0
}

// --- folding a wave ----------------------------------------------------------------

// Campaign is one technique running across several endpoints inside one window: three
// hits of the same technique on three hosts in one window is one wave, not three
// unrelated items. Nine rows would be nine decisions; one row with a roster under it is
// one decision, and the endpoints that still need a human are visible without scrolling.
//
// This is the same fold the EDR console already performs on its worklist. It is done
// here so the CLI shows the same shape, not to introduce a second grouping rule.
type Campaign struct {
	Technique string
	Lane      string
	Rows      []Row
	StartedMs int64
}

// Wave reports a campaign that actually collapsed something. A single row is not a
// wave, and rendering it as one would be a shape that overstates what happened.
func (c Campaign) Wave() bool { return len(c.Rows) > 1 }

// Severed and Unsevered split the roster by WHAT WE DID rather than by what we found,
// which is the only split that maps to work.
func (c Campaign) Severed(b *Book, now time.Time) (severed, unsevered []Row) {
	for _, r := range c.Rows {
		if _, ok := severedAfter(b.Trail, r, now); ok {
			severed = append(severed, r)
		} else {
			unsevered = append(unsevered, r)
		}
	}
	return severed, unsevered
}

// FoldWindow is how close together two hits of one technique must be to read as one
// wave. An hour is deliberate: shorter and a slow encryption run splits into several
// items, longer and two unrelated incidents a week apart merge into one.
const FoldWindow = time.Hour

// Fold groups rows into campaigns by technique, keeping only groups whose members began
// inside one window of each other. Rows that fold into nothing come back as
// single-member campaigns, in the input order, so a caller can render one list.
func Fold(rows []Row, window time.Duration) []Campaign {
	if window <= 0 {
		window = FoldWindow
	}
	order := []string{}
	groups := map[string][]Row{}
	for _, r := range rows {
		k := r.Technique
		if k == "" {
			k = r.ID // a plumbing condition folds on its own id, never with a technique
		}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	var out []Campaign
	for _, k := range order {
		members := groups[k]
		sort.SliceStable(members, func(i, j int) bool { return members[i].FirstSeen < members[j].FirstSeen })
		for len(members) > 0 {
			start := members[0].FirstSeen
			cut := len(members)
			if start > 0 {
				limit := start + window.Milliseconds()
				for i, m := range members {
					if m.FirstSeen > 0 && m.FirstSeen > limit {
						cut = i
						break
					}
				}
			}
			chunk := members[:cut]
			members = members[cut:]
			out = append(out, Campaign{
				Technique: k,
				Lane:      worstLane(chunk),
				Rows:      chunk,
				StartedMs: start,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return LaneRank(out[i].Lane) < LaneRank(out[j].Lane)
	})
	return out
}

func worstLane(rows []Row) string {
	worst := LaneQuiet
	for _, r := range rows {
		if LaneRank(r.Lane) < LaneRank(worst) {
			worst = r.Lane
		}
	}
	return worst
}

// --- the headline ------------------------------------------------------------------

// Headline is the one sentence at the top: a statement about the world, never a count
// of rows. "Two things want a decision" is a fact somebody can act on; "3 alerts require
// attention" is a description of a table.
//
// It returns the empty string when nothing is asking for anyone, because the quiet case
// has its own block and does not need a headline that repeats it.
func (b *Book) Headline(now time.Time, staleAck time.Duration) string {
	var paging, holding []Row
	for _, r := range b.Rows {
		v := Judge(r, b.EndpointFor(r), b.Trail, now, staleAck)
		switch v.Token {
		case InterruptPage:
			paging = append(paging, r)
		case InterruptDigest:
			if r.Held() && (r.Lane == LaneActNow || r.Lane == LaneReview) {
				holding = append(holding, r)
			}
		}
	}
	if len(paging) == 0 {
		return ""
	}
	sentence := countThings(len(paging)) + " want a decision"
	if len(paging) == 1 {
		sentence = "one thing wants a decision"
	}
	if who := soleHolder(holding); who != "" {
		if len(holding) == 1 {
			return sentence + ", one is waiting on " + who
		}
		return sentence + ", " + countThings(len(holding)) + " are waiting on " + who
	}
	if len(holding) > 0 {
		return sentence + ", " + countThings(len(holding)) + " more are already with somebody"
	}
	return sentence
}

// soleHolder names the person holding every held row, or "" when they are held by more
// than one person. Naming one person is useful; naming four is a roster, and a roster
// belongs in the table rather than the headline.
func soleHolder(rows []Row) string {
	who := ""
	for _, r := range rows {
		h := r.Holder()
		if h == "" {
			return ""
		}
		if who == "" {
			who = h
		} else if !strings.EqualFold(who, h) {
			return ""
		}
	}
	return who
}

// countThings spells the small numbers, because a sentence a person reads at a glance
// should read like a sentence. Above ten the digit is clearer than the word.
func countThings(n int) string {
	words := []string{"nothing", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Age renders a duration the way an operator reads one: 19m, 4h, 22d. A zero duration
// renders as a dash rather than as "0s", because an unstamped row has an unknown age
// and printing zero would claim it just happened.
func Age(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Minute:
		return itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		return itoa(int(d/time.Hour)) + "h"
	default:
		return itoa(int(d/(24*time.Hour))) + "d"
	}
}
