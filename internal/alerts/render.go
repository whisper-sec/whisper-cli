// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// render.go is the reference implementation of the legible-silence contract: the block
// every surface prints when there is nothing to say. Three facts, never one word - the
// verdict, the denominator, and the horizon.
//
// The five sentences this file must never produce are the ones a breach review would
// quote back at us: "no threats detected", "all clear", "you are protected", "0 alerts",
// and a bare tick with no denominator. The suite asserts their absence over the rendered
// corpus rather than trusting this comment.

// Options carry the few facts a renderer needs that are not in the Book.
type Options struct {
	// Now anchors every age and every horizon. Injected rather than read, so a rendered
	// block is reproducible in a test.
	Now time.Time
	// StaleAck is how long an acknowledgement stands before an untouched row starts
	// asking again. An acknowledgement nobody moved is not quiet.
	StaleAck time.Duration
	// Horizon is the containment window the "contained" line reports over.
	Horizon time.Duration
	// Fold collapses same-technique rows across endpoints into one wave. Off renders
	// every row on its own line, which is what a script piping the list usually wants.
	Fold bool
}

// DefaultStaleAck is a working day. An acknowledgement is "seen, working it", and a
// working day later that has either become work or become forgotten.
const DefaultStaleAck = 24 * time.Hour

// DefaultHorizon is the containment window the quiet block reports over. A week is long
// enough that a quiet queue explained by last Tuesday's severing still says so.
const DefaultHorizon = 7 * 24 * time.Hour

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o Options) staleAck() time.Duration {
	if o.StaleAck <= 0 {
		return DefaultStaleAck
	}
	return o.StaleAck
}

func (o Options) horizon() time.Duration {
	if o.Horizon <= 0 {
		return DefaultHorizon
	}
	return o.Horizon
}

// Verdict is the first line of any render: a statement about the world. Four distinct
// sentences, so that a broken pipeline, a blind estate, a half-read estate and a
// genuinely calm one are four different pieces of TEXT and not one blank space.
func (b *Book) Verdict(opt Options) string {
	if h := b.Headline(opt.now(), opt.staleAck()); h != "" {
		return h
	}
	if !b.Complete() {
		return "nothing is asking for you in what we could read"
	}
	c := b.Coverage
	if c.Present && c.Endpoints > 0 {
		switch {
		case c.HeardFrom() == 0:
			return "nothing is asking for you, but almost nothing could"
		case c.HeardFrom()*2 < c.Endpoints:
			return "nothing is asking for you, and most of your estate could not tell you if it were"
		}
	}
	return "nothing is asking for you"
}

// Disposition is what is TRUE NOW, in one of exactly three reserved words. A rule author
// cannot type them: they derive from the containment trail and from the stamp the sensor
// wrote, which is why no copy in this product can claim containment we did not achieve.
//
//	severed a control action landed on this endpoint after the finding began
//	held the sensor observed and recorded it, and contained nothing
//	noticed we have the finding and nothing acted on it
func Disposition(r Row, trail []Action, now time.Time) string {
	if _, ok := severedAfter(trail, r, now); ok {
		return "severed"
	}
	if strings.EqualFold(whatHappened(r.Evidence), "held") {
		return "held"
	}
	return "noticed"
}

// whatHappened reads the sensor's own verdict out of the evidence blob.
//
// It is READ, not grepped. The blob carries a signal list and file paths beside the
// verdict, so two independent substring searches - one for the key, one for the value -
// answer "held" for evidence that actually says {"whatHappened":"contained",
// "signals":["mass_write","held"]}. That is the surface contradicting the sensor about
// what happened on somebody's machine, which is the one thing this word exists to get
// right.
//
// Evidence that is absent, is not an object, or carries no verdict yields the empty
// string, which reads as "noticed": the honest floor, never a guess.
func whatHappened(evidence string) string {
	evidence = strings.TrimSpace(evidence)
	if !strings.HasPrefix(evidence, "{") {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(evidence), &m) != nil {
		return ""
	}
	s, _ := m["whatHappened"].(string)
	return strings.TrimSpace(s)
}

// RenderBrief writes the ten-second answer: the verdict, the lanes that want something,
// and the quiet block that proves the quiet. The answer goes to out; the next command a
// person would run goes to hint, so `whisper alerts | wc -l` counts only the answer.
func RenderBrief(out, hint io.Writer, b *Book, opt Options) {
	fmt.Fprintln(out, b.Verdict(opt))

	lanes := []string{LaneActNow, LaneReview, LaneUnscored}
	var firstRef string
	for _, lane := range lanes {
		rows := b.inLane(lane)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, LaneProse(lane))
		if firstRef == "" {
			firstRef = rows[0].Ref()
		}
		writeLaneRows(out, b, rows, opt)
	}

	fmt.Fprintln(out)
	RenderQuiet(out, b, opt)

	if firstRef != "" {
		fmt.Fprintf(hint, "\n  whisper alerts show %s\n", firstRef)
	}
}

// inLane returns the rows the plane banded into one lane, worst-fused-first as the plane
// already ordered them. The quiet band is deliberately absent from the brief: it is
// counted in the block below and one command away from fully readable.
func (b *Book) inLane(lane string) []Row {
	var out []Row
	for _, r := range b.Rows {
		if r.Lane == lane {
			out = append(out, r)
		}
	}
	return out
}

func writeLaneRows(out io.Writer, b *Book, rows []Row, opt Options) {
	if opt.Fold {
		for _, c := range Fold(rows, FoldWindow) {
			if c.Wave() {
				writeWave(out, b, c, opt)
				continue
			}
			writeRow(out, b, c.Rows[0], opt)
		}
		return
	}
	for _, r := range rows {
		writeRow(out, b, r, opt)
	}
}

func writeRow(out io.Writer, b *Book, r Row, opt Options) {
	now := opt.now()
	cells := []string{
		"  " + r.Ref(),
		trim(r.Title, 46),
		Disposition(r, b.Trail, now),
		Age(RowAge(r, now)),
		r.Holder(),
	}
	fmt.Fprintln(out, strings.TrimRight(pad(cells, []int{24, 48, 10, 6, 0}), " "))
}

// writeWave renders one technique running across several endpoints as ONE decision with
// a roster under it, split by what we did rather than by what we found. Nine rows would
// be nine decisions; the three that need a human are visible here without scrolling.
func writeWave(out io.Writer, b *Book, c Campaign, opt Options) {
	now := opt.now()
	severed, unsevered := c.Severed(b, now)
	head := fmt.Sprintf("  %s on %d endpoints", c.Technique, len(c.Rows))
	started := "-"
	if s := Stamp(c.StartedMs, now); s != "" {
		started = s
	}
	fmt.Fprintln(out, strings.TrimRight(pad([]string{head, "one wave, not " + countThings(len(c.Rows)) + " items", "started " + started}, []int{40, 30, 0}), " "))
	if len(severed) > 0 {
		fmt.Fprintf(out, "    severed  %s\n", strings.Join(refs(severed), " "))
	}
	for _, r := range unsevered {
		why := whyNotSevered(b, r, now)
		fmt.Fprintln(out, strings.TrimRight(pad([]string{"    not", "  " + subjectOf(r), why}, []int{11, 22, 0}), " "))
	}
}

func whyNotSevered(b *Book, r Row, now time.Time) string {
	// A refused or failed control action on this endpoint is the truest answer, and it
	// is the class where our own product is the failure. Say it in the plane's words.
	var latest Action
	found := false
	for _, a := range b.Trail {
		if !a.DidNotTake() || !SameAddress(a.Address, r.Address) {
			continue
		}
		if !found || a.TsMs > latest.TsMs {
			latest, found = a, true
		}
	}
	if found {
		if latest.Detail != "" {
			return latest.Result + ": " + trim(latest.Detail, 56)
		}
		return latest.Result
	}
	e := b.EndpointFor(r)
	if e.Known() && e.Offline() {
		if e.ConnLastSeen > 0 {
			return "offline since " + Stamp(e.ConnLastSeen, now) + ", we could not reach it"
		}
		return "offline, we could not reach it"
	}
	if r.Held() {
		return r.Holder() + " has it"
	}
	return "nothing acted on it"
}

func refs(rows []Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, subjectOf(r))
	}
	return out
}

func subjectOf(r Row) string {
	if r.Agent != "" {
		return r.Agent
	}
	return r.Address
}

// RenderQuiet writes the block that proves the quiet: the verdict's denominators, the
// horizon, what is holding any mute, and the provenance of the read. It is printed under
// a busy estate too, because the counts a person needs to trust the queue are the same
// counts either way.
func RenderQuiet(out io.Writer, b *Book, opt Options) {
	now := opt.now()
	lines := [][2]string{
		{"open", b.openLine()},
		{"heard from", b.heardFromLine(now)},
	}
	if g := b.governedLine(); g != "" {
		lines = append(lines, [2]string{"governed", g})
	}
	lines = append(lines, [2]string{"contained", b.containedLine(opt)})
	if d := b.didNotTakeLine(opt); d != "" {
		lines = append(lines, [2]string{"did not take", d})
	}
	if m := b.mutedLine(now); m != "" {
		lines = append(lines, [2]string{"muted", m})
	}
	lines = append(lines, [2]string{"read", b.readLine(now)})

	w := 0
	for _, l := range lines {
		if len(l[0]) > w {
			w = len(l[0])
		}
	}
	for _, l := range lines {
		fmt.Fprintf(out, "  %-*s  %s\n", w, l[0], l[1])
	}

	if b.Coverage.Present && b.Coverage.Endpoints > 0 && b.Coverage.HeardFrom() == 0 {
		// The sentence the whole product turns on. A network-governed fleet must never
		// render as an instrumented one.
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  a network-governed endpoint still cannot tell you what ran on it")
		fmt.Fprintln(out, "    "+SensorRemedy)
	}
}

// openLine is the count of things that could ask for you. A count that could not be read
// says so, and a partial read renders as a floor rather than as a number.
func (b *Book) openLine() string {
	c := b.Coverage
	standing := b.stream("detections")
	if !c.Present {
		if standing != nil && standing.Answered() {
			return fmt.Sprintf("at least %d in the queue we read; the coverage read did not answer", len(b.Rows))
		}
		return "not read"
	}
	parts := []string{}
	if c.ActNow > 0 {
		parts = append(parts, fmt.Sprintf("%d act now", c.ActNow))
	}
	if c.Review > 0 {
		parts = append(parts, fmt.Sprintf("%d review", c.Review))
	}
	if c.Unscored > 0 {
		parts = append(parts, fmt.Sprintf("%d unscored", c.Unscored))
	}
	if c.Quiet > 0 {
		parts = append(parts, fmt.Sprintf("%d not asking", c.Quiet))
	}
	head := fmt.Sprintf("%d detections", c.Open)
	if len(parts) == 0 {
		return head
	}
	return head + ": " + strings.Join(parts, ", ")
}

// heardFromLine is the spanning invariant. A zero only means something next to its
// denominator: nothing open over four of thirty-six heard from is not quiet, it is deaf.
func (b *Book) heardFromLine(now time.Time) string {
	c := b.Coverage
	if !c.Present {
		return "not read"
	}
	s := fmt.Sprintf("%d of %d endpoints", c.HeardFrom(), c.Endpoints)
	if worst := b.worstSilence(now); worst > 0 {
		s += ", worst silence " + Age(worst)
	}
	if c.SensorStale > 0 {
		s += fmt.Sprintf(", %d went stale", c.SensorStale)
	}
	return s
}

// worstSilence is the longest gap since any shipping endpoint last reported. It needs the
// endpoints stream; without it the clause is omitted rather than guessed.
func (b *Book) worstSilence(now time.Time) time.Duration {
	if s := b.stream("endpoints"); s == nil || !s.Answered() {
		return 0
	}
	var worst time.Duration
	for _, e := range b.Endpoints {
		if e.Sensor != "shipping" && e.Sensor != "slow" {
			continue
		}
		if e.SensorLastReport <= 0 {
			continue
		}
		if d := now.Sub(time.UnixMilli(e.SensorLastReport)); d > worst {
			worst = d
		}
	}
	return worst
}

// governedLine appears only when part of the estate is governed at the network layer with
// no host sensor. At production scale that is the majority, and it is not a defect to
// hide: it is the reason our containment holds where a host-only sensor's does not.
func (b *Book) governedLine() string {
	c := b.Coverage
	if !c.Present || c.NetworkOnly() == 0 {
		return ""
	}
	tiers := []string{}
	counted := c.TierUnknown
	for _, t := range []struct {
		n    int64
		name string
	}{{c.TierWireguard, "wireguard"}, {c.TierSocks, "socks"}, {c.TierResolver, "resolver"}} {
		counted += t.n
		if t.n > 0 {
			tiers = append(tiers, fmt.Sprintf("%d %s", t.n, t.name))
		}
	}
	s := fmt.Sprintf("%d of %d at the network layer only, with no host sensor", c.NetworkOnly(), c.Endpoints)
	if len(tiers) == 0 {
		return s
	}
	// The tier cells count every endpoint the plane knows, the sensor-carrying ones
	// included, so they describe THIS subset only when the subset happens to be the whole
	// fleet. Hanging them off a smaller number in a bare parenthesis is how a true line
	// comes to read as a false one: "N host-blind ... (a wireguard, b socks, c resolver)"
	// invites a reader to split the host-blind count into three numbers that sum to the
	// whole fleet instead.
	//
	// Which case we are in is decided from the numbers themselves rather than from an
	// assumption about the plane, so the sentence stays true if the plane ever narrows
	// the split to the sensorless endpoints.
	if counted == c.NetworkOnly() {
		return s + " (" + strings.Join(tiers, ", ") + ")"
	}
	return s + fmt.Sprintf("; the %d we see reach us as %s", counted, strings.Join(tiers, ", "))
}

// containedLine closes the other way a queue lies. An empty queue because we severed nine
// identities at 03:14 is a different fact from an empty queue because nothing happened.
func (b *Book) containedLine(opt Options) string {
	s := b.stream("containment")
	if s == nil {
		return "not read"
	}
	if !s.Answered() {
		return "not read: " + firstLine(s.Err.Error())
	}
	now := opt.now()
	since := now.Add(-opt.horizon())
	var landed []Action
	for _, a := range b.Trail {
		if a.Landed() && a.TsMs >= since.UnixMilli() {
			landed = append(landed, a)
		}
	}
	if len(landed) == 0 {
		return "nothing severed in the last " + Age(opt.horizon())
	}
	sort.SliceStable(landed, func(i, j int) bool { return landed[i].TsMs > landed[j].TsMs })
	return fmt.Sprintf("%d control actions landed in the last %s, most recently %s",
		len(landed), Age(opt.horizon()), landed[0].stamp(now))
}

// didNotTakeLine surfaces the class where our own product is the failure: we reached for
// containment and it did not land. Nothing else on any surface raises these today.
func (b *Book) didNotTakeLine(opt Options) string {
	s := b.stream("containment")
	if s == nil || !s.Answered() {
		return ""
	}
	since := opt.now().Add(-opt.horizon()).UnixMilli()
	byResult := map[string]int{}
	total := 0
	for _, a := range b.Trail {
		if a.DidNotTake() && a.TsMs >= since {
			byResult[strings.ToLower(a.Result)]++
			total++
		}
	}
	if total == 0 {
		return ""
	}
	keys := make([]string, 0, len(byResult))
	for k := range byResult {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", byResult[k], k))
	}
	return fmt.Sprintf("%d control actions we reached for did not land: %s", total, strings.Join(parts, ", "))
}

// mutedLine is the anti-tuning-project line: it must be impossible to be quiet without
// seeing what is holding the quiet.
func (b *Book) mutedLine(now time.Time) string {
	s := b.stream("suppressions")
	if s == nil {
		return ""
	}
	if !s.Answered() {
		return "not read, so we cannot show you what is holding any quiet: " + firstLine(s.Err.Error())
	}
	live := b.LiveSuppressions(now)
	if len(live) == 0 {
		return ""
	}
	var soonest int64
	for _, sup := range live {
		if sup.ExpiresAt > 0 && (soonest == 0 || sup.ExpiresAt < soonest) {
			soonest = sup.ExpiresAt
		}
	}
	s2 := fmt.Sprintf("%d rules holding quiet", len(live))
	if soonest > 0 {
		s2 += ", oldest expires " + time.UnixMilli(soonest).UTC().Format("2 Jan")
	} else {
		s2 += ", none of them expiring"
	}
	return s2 + "   whisper alerts mute list"
}

// readLine is provenance and freshness, and it is where a partial read declares itself.
func (b *Book) readLine(now time.Time) string {
	stamp := b.ReadAt
	if stamp.IsZero() {
		stamp = now
	}
	s := stamp.UTC().Format("15:04:05Z")
	if b.Endpoint != "" {
		s += " from " + b.Endpoint
	}
	bad := b.Incomplete()
	if len(bad) == 0 {
		return s
	}
	names := make([]string, 0, len(bad))
	for _, st := range bad {
		names = append(names, st.Name)
	}
	noun := "one stream did not answer"
	if len(names) > 1 {
		noun = fmt.Sprintf("%d streams did not answer", len(names))
	}
	return s + "; " + noun + ": " + strings.Join(names, ", ") + ". the counts above are floors"
}

func (b *Book) stream(name string) *Stream {
	for i := range b.Streams {
		if b.Streams[i].Name == name {
			return &b.Streams[i]
		}
	}
	return nil
}

// --- show --------------------------------------------------------------------------

// RenderShow writes one condition in full, in the four fixed slots. The order is the
// mechanism: it tells the reader where they are in the message and what is coming next.
// The commands that do something go to hint, and none of them is a new containment verb.
func RenderShow(out, hint io.Writer, b *Book, r Row, opt Options) {
	now := opt.now()
	e := b.EndpointFor(r)
	v := Judge(r, e, b.Trail, now, opt.staleAck())

	fmt.Fprintf(out, "%s   %s   %s\n\n", r.Ref(), LaneProse(r.Lane), v.Token)

	slot(out, "WHAT HAPPENED", firstLine(orNone(r.Title, "the plane served no sentence for this condition")))
	slot(out, "WHY WE THINK SO", why(r, b, now))
	slot(out, "WHAT IS TRUE NOW", Disposition(r, b.Trail, now))
	slot(out, "WHAT TO DO", todo(r, v))

	fmt.Fprintln(out)
	facts := [][2]string{
		{"endpoint", endpointLine(r, e)},
		{"first seen", seenLine(r, now)},
		{"score", scoreLine(r, b.Coverage)},
		{"held by", orNone(r.Holder(), "nobody")},
		{"why " + v.Token, v.Reason},
	}
	w := 0
	for _, f := range facts {
		if len(f[0]) > w {
			w = len(f[0])
		}
	}
	for _, f := range facts {
		fmt.Fprintf(out, "  %-*s  %s\n", w, f[0], f[1])
	}

	fmt.Fprintf(hint, "\n  whisper alerts ack %s\n", r.Ref())
	fmt.Fprintf(hint, "  whisper logs --agent %s\n", subjectOf(r))
	if r.Lane == LaneActNow {
		fmt.Fprintf(hint, "  whisper kill %s        ends this identity's network. irreversible\n", subjectOf(r))
	}
}

func slot(out io.Writer, label, body string) {
	fmt.Fprintf(out, "%-17s%s\n", label, body)
}

func why(r Row, b *Book, now time.Time) string {
	parts := []string{}
	if r.Origin != "" {
		parts = append(parts, "origin "+r.Origin)
	}
	if r.Confidence > 0 {
		parts = append(parts, fmt.Sprintf("confidence %.2f", r.Confidence))
	}
	if e := b.EndpointFor(r); e.Known() && e.Sensor != "" {
		parts = append(parts, "sensor "+e.Sensor)
	}
	if len(parts) == 0 {
		parts = append(parts, "the plane served no corroboration cells on this row")
	}
	return strings.Join(parts, ", ") + ". re-derive it with: whisper alerts show " + r.Ref() + " --json"
}

func todo(r Row, v Verdict) string {
	if v.Token == InterruptDigest && strings.HasPrefix(v.Reason, "we severed") {
		return "nothing, this is a receipt. the files on disk are unchanged"
	}
	if r.Remediation != "" {
		return firstLine(r.Remediation)
	}
	if r.Lane == LaneActNow {
		return "decide whether to end this identity's network, then acknowledge so nobody duplicates you"
	}
	return "read it when you next look; acknowledge if you are taking it"
}

func endpointLine(r Row, e Endpoint) string {
	s := subjectOf(r)
	if r.Address != "" && r.Address != s {
		s += "  " + r.Address
	}
	if !e.Known() {
		return s + "  (this endpoint was not in the read, so its liveness is unknown)"
	}
	return s + "  " + orNone(e.Connectivity, "connectivity unknown") + ", sensor " + orNone(e.Sensor, "unknown")
}

func seenLine(r Row, now time.Time) string {
	if r.FirstSeen <= 0 {
		return "not stamped, so its age is unknown"
	}
	return time.UnixMilli(r.FirstSeen).UTC().Format("2006-01-02 15:04") + "  (" + Age(RowAge(r, now)) + ")"
}

// scoreLine prints the fused score against the SERVED threshold. When the coverage read
// did not answer, the threshold is unknown and the line says so - it never falls back to
// a local constant, which is exactly how two surfaces come to disagree.
func scoreLine(r Row, c Coverage) string {
	score := "never scored"
	if r.Fused != nil {
		score = fmt.Sprintf("%.1f fused", *r.Fused)
	}
	// BOTH thresholds or neither. Printing "review at 0.0" because only one arrived would
	// be a fabricated number wearing the word "served", which is worse than saying nothing.
	if !c.Present || c.ActNowAt == nil || c.ReviewAt == nil {
		return score + ", against a lane threshold this read did not carry"
	}
	return fmt.Sprintf("%s, act now at %.1f and review at %.1f, both served", score, *c.ActNowAt, *c.ReviewAt)
}

// --- small text helpers ------------------------------------------------------------

func pad(cells []string, widths []int) string {
	var b strings.Builder
	for i, c := range cells {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		if c == "" && w == 0 {
			continue
		}
		b.WriteString(c)
		if i < len(cells)-1 {
			if n := w - len([]rune(c)); n > 0 {
				b.WriteString(strings.Repeat(" ", n))
			} else {
				b.WriteString(" ")
			}
		}
	}
	return b.String()
}

func trim(s string, n int) string {
	s = firstLine(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func orNone(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// Stamp renders a moment the way a person actually reads one: a bare clock time when it
// happened today, and a dated one when it did not.
//
// Every other number on this surface carries its denominator, and a clock time with no
// date is a number with no denominator. A wave that began three weeks ago printed as
// "started 20:00" reads as tonight, and a reader who believes that is looking at the
// wrong incident. The lines that use this all report over multi-day horizons - the
// containment horizon defaults to a week - so "not today" is the common case, not the
// exotic one.
//
// UTC, like every other stamp here, so two operators in two timezones quote the same
// number back at each other.
func Stamp(ms int64, now time.Time) string {
	if ms <= 0 {
		return ""
	}
	t := time.UnixMilli(ms).UTC()
	if n := now.UTC(); t.Year() == n.Year() && t.YearDay() == n.YearDay() {
		return t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// SensorRemedy is the one line printed under the coverage gap above: what to do about a
// fleet the network governs and nothing watches. The endpoint half sets it to the command
// that installs the sensor. A build that has no endpoint half - the published MIT client,
// which carries no `whisper service` - keeps this default and names the download instead,
// because instructing a command the running binary does not have is worse than saying
// nothing at all.
var SensorRemedy = "install the endpoint build: https://endpoint.whisper.online"
