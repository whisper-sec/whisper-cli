// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// quietBook is an estate with nothing standing and every stream answering.
func quietBook() *Book {
	b := &Book{
		Coverage: Coverage{
			Present: true, Endpoints: 36, SensorShipping: 34, SensorSlow: 2,
			TierWireguard: 20, TierSocks: 10, TierResolver: 6,
			ActNowAt: ptr(45.0), ReviewAt: ptr(30.0),
		},
		Streams: []Stream{
			{Name: "detections", Rows: 0},
			{Name: "coverage", Rows: 1},
			{Name: "endpoints", Rows: 36},
			{Name: "containment", Rows: 0},
			{Name: "suppressions", NotApplicable: "this account carries no mute register"},
		},
		ReadAt:   testNow,
		Endpoint: "graph.whisper.online",
	}
	b.Index()
	return b
}

// brokenBook is the SAME estate, read through a pipeline that failed.
func brokenBook() *Book {
	boom := errors.New("control plane returned status 500")
	b := &Book{
		Streams: []Stream{
			{Name: "detections", Err: boom},
			{Name: "coverage", Err: boom},
			{Name: "endpoints", Err: boom},
			{Name: "containment", Err: boom},
			{Name: "suppressions", NotApplicable: "this account carries no mute register"},
		},
		ReadAt:   testNow,
		Endpoint: "graph.whisper.online",
	}
	b.Index()
	return b
}

func render(b *Book) string {
	var out, hint bytes.Buffer
	RenderBrief(&out, &hint, b, Options{Now: testNow})
	return out.String()
}

// P3, and the single most important assertion in this package. A read that failed and a
// read that came back empty must differ in TEXT, not only in colour: they are the same
// blank space on every product that gets this wrong.
func TestQuiet_AFailedReadAndAnEmptyReadAreDifferentSentences(t *testing.T) {
	empty := render(quietBook())
	broken := render(brokenBook())
	if empty == broken {
		t.Fatal("an estate with nothing happening and a pipeline that broke rendered identically")
	}
	if !strings.Contains(empty, "nothing is asking for you") {
		t.Fatalf("the quiet verdict is missing:\n%s", empty)
	}
	if !strings.Contains(broken, "in what we could read") {
		t.Fatalf("a broken read must say so in its verdict:\n%s", broken)
	}
	if !strings.Contains(broken, "the counts above are floors") {
		t.Fatalf("a partial read must render its counts as floors:\n%s", broken)
	}
	for _, stream := range []string{"detections", "coverage", "endpoints", "containment"} {
		if !strings.Contains(broken, stream) {
			t.Fatalf("the stream %q that did not answer is not named:\n%s", stream, broken)
		}
	}
}

// A zero only means something next to its denominator. Nothing open over four of
// thirty-six heard from is not quiet, it is deaf.
func TestQuiet_EveryZeroCarriesItsDenominator(t *testing.T) {
	out := render(quietBook())
	if !strings.Contains(out, "36 of 36 endpoints") {
		t.Fatalf("the spanning invariant is missing:\n%s", out)
	}
	bareZero := regexp.MustCompile(`(^|\s)0(\s|$)`)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, l := range lines {
		if !bareZero.MatchString(l) {
			continue
		}
		near := l
		if i+1 < len(lines) {
			near += "\n" + lines[i+1]
		}
		if !strings.Contains(near, " of ") {
			t.Fatalf("line %d prints a bare zero with no denominator on it or the line below:\n%s", i, near)
		}
	}
}

// The sentence the whole product turns on. A network-governed fleet must never render as
// an instrumented one.
func TestQuiet_ANetworkOnlyFleetSaysSo(t *testing.T) {
	b := quietBook()
	b.Coverage = Coverage{Present: true, Endpoints: 334, SensorAbsent: 334,
		TierSocks: 293, TierResolver: 41, ActNowAt: ptr(45.0), ReviewAt: ptr(30.0)}
	out := render(b)
	if !strings.Contains(out, "but almost nothing could") {
		t.Fatalf("a blind estate must say so in its verdict:\n%s", out)
	}
	if !strings.Contains(out, "at the network layer only, with no host sensor") {
		t.Fatalf("the governed line is missing:\n%s", out)
	}
	if !strings.Contains(out, "still cannot tell you what ran on it") {
		t.Fatalf("the coverage-honest sentence is missing:\n%s", out)
	}
}

// It must be impossible to be quiet without seeing what is holding the quiet. This is the
// anti-tuning-project line, and its appearance is mandatory whenever a rule is live.
func TestQuiet_ALiveMuteIsAlwaysNamed(t *testing.T) {
	b := quietBook()
	b.Streams[4] = Stream{Name: "suppressions", Rows: 2}
	b.Suppression = []Suppression{
		{Name: "backup window", CreatedBy: "dana", ExpiresAt: ms(testNow.Add(72 * time.Hour))},
		{Name: "ci noise", CreatedBy: "dana", ExpiresAt: ms(testNow.Add(240 * time.Hour))},
	}
	out := render(b)
	if !strings.Contains(out, "2 rules holding quiet") {
		t.Fatalf("a live mute is not named in the quiet block:\n%s", out)
	}
	if !strings.Contains(out, "whisper alerts mute list") {
		t.Fatalf("the quiet block must carry the command that shows the register:\n%s", out)
	}
	// An expired rule is history, not a mute.
	b.Suppression = []Suppression{{Name: "old", ExpiresAt: ms(testNow.Add(-time.Hour))}}
	if strings.Contains(render(b), "holding quiet") {
		t.Fatal("an expired rule must not be reported as holding quiet")
	}
}

// The five sentences a breach review would quote back at us, asserted over the whole
// rendered corpus rather than trusted to a comment.
func TestRendered_NeverSaysTheThingsWeCannotProve(t *testing.T) {
	banned := []string{
		"no threats detected",
		"all clear",
		"you are protected",
		"0 alerts",
		"nothing to see here",
	}
	corpus := []string{
		render(quietBook()),
		render(brokenBook()),
		render(busyBook()),
		render(stormBook()),
	}
	var one bytes.Buffer
	var hint bytes.Buffer
	bb := busyBook()
	RenderShow(&one, &hint, bb, bb.Rows[0], Options{Now: testNow})
	corpus = append(corpus, one.String(), hint.String())

	for _, text := range corpus {
		low := strings.ToLower(text)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("rendered prose contains %q:\n%s", b, text)
			}
		}
		// "handled" is a filter token, never prose: printing it would assert work that
		// nobody did. The lane's own prose form is "not asking".
		for _, line := range strings.Split(low, "\n") {
			if strings.Contains(line, "handled") {
				t.Errorf("the word handled reached rendered prose:\n%s", line)
			}
		}
	}
}

// P8's lint: no rendered sentence may claim containment unless a control action actually
// landed on that row.
func TestRendered_NeverClaimsContainmentWeDidNotAchieve(t *testing.T) {
	b := busyBook()
	b.Trail = []Action{refused("2a04:2a01:9::1", 5*time.Minute)}
	text := strings.ToLower(render(b))
	for _, verb := range []string{"severed", "contained", "neutralized", "neutralised", "blocked"} {
		if strings.Contains(text, verb) && !strings.Contains(text, "nothing severed") {
			t.Errorf("a refused containment rendered the verb %q:\n%s", verb, text)
		}
	}
}

func busyBook() *Book {
	r1 := rowAt(LaneActNow, "T1486", 19*time.Minute)
	r2 := rowAt(LaneReview, "T1021.004", 4*time.Hour)
	r2.Agent, r2.Address, r2.Assignee = "runner-02", "2a04:2a01:9::2", "operator-a"
	r2.Title = "svc-backup opened SMB to three hosts it had never reached"
	b := &Book{
		Rows: []Row{r1, r2},
		Endpoints: []Endpoint{
			{Agent: "finance-01", Address: "2a04:2a01:9::1", Connectivity: "online", Sensor: "shipping", known: true},
			{Agent: "runner-02", Address: "2a04:2a01:9::2", Connectivity: "online", Sensor: "shipping", known: true},
		},
		Coverage: Coverage{Present: true, Endpoints: 36, SensorShipping: 36, Open: 61,
			ActNow: 1, Review: 1, Quiet: 59, ActNowAt: ptr(45.0), ReviewAt: ptr(30.0)},
		Streams: []Stream{
			{Name: "detections", Rows: 2}, {Name: "coverage", Rows: 1},
			{Name: "endpoints", Rows: 2}, {Name: "containment", Rows: 0},
			{Name: "suppressions", NotApplicable: "no register"},
		},
		ReadAt: testNow, Endpoint: "graph.whisper.online",
	}
	b.Index()
	return b
}

func stormBook() *Book {
	var rows []Row
	var eps []Endpoint
	hosts := []string{"finance-01", "finance-02", "finance-03", "kiosk-1", "kiosk-2", "kiosk-3", "hr-app-01", "payroll-01", "vpn-gw"}
	var trail []Action
	for i, h := range hosts {
		addr := "2a04:2a01:9::" + string(rune('a'+i))
		r := rowAt(LaneActNow, "T1486", time.Duration(19+i)*time.Minute)
		r.Agent, r.Address = h, addr
		rows = append(rows, r)
		conn := "online"
		if h == "vpn-gw" {
			conn = "offline"
		}
		eps = append(eps, Endpoint{Agent: h, Address: addr, Connectivity: conn, Sensor: "shipping", known: true})
		switch h {
		case "hr-app-01":
			trail = append(trail, Action{TsMs: ms(testNow.Add(-10 * time.Minute)), Address: addr, Result: "refused:disarmed"})
		case "payroll-01":
			trail = append(trail, Action{TsMs: ms(testNow.Add(-10 * time.Minute)), Address: addr, Result: "refused:critical_target"})
		case "vpn-gw":
			// nothing: we could not reach it at all
		default:
			trail = append(trail, landed(addr, 10*time.Minute))
		}
	}
	b := &Book{
		Rows: rows, Endpoints: eps, Trail: trail,
		Coverage: Coverage{Present: true, Endpoints: 9, SensorShipping: 8, SensorStale: 1,
			Open: 9, ActNow: 9, ActNowAt: ptr(45.0), ReviewAt: ptr(30.0)},
		Streams: []Stream{
			{Name: "detections", Rows: 9}, {Name: "coverage", Rows: 1},
			{Name: "endpoints", Rows: 9}, {Name: "containment", Rows: len(trail)},
			{Name: "suppressions", NotApplicable: "no register"},
		},
		ReadAt: testNow, Endpoint: "graph.whisper.online",
	}
	b.Index()
	return b
}

// One wave, one decision, and the endpoints that still need a human visible without
// scrolling - including the one that appears for two different true reasons.
func TestStorm_FoldsToOneDecisionWithARoster(t *testing.T) {
	var out, hint bytes.Buffer
	RenderBrief(&out, &hint, stormBook(), Options{Now: testNow, Fold: true})
	text := out.String()
	if !strings.Contains(text, "T1486 on 9 endpoints") {
		t.Fatalf("nine hits of one technique did not fold into one wave:\n%s", text)
	}
	if !strings.Contains(text, "severed") {
		t.Fatalf("the roster does not say what we did:\n%s", text)
	}
	for _, needs := range []string{"hr-app-01", "payroll-01", "vpn-gw"} {
		if !strings.Contains(text, needs) {
			t.Fatalf("the endpoint %s that still needs a human is not in the roster:\n%s", needs, text)
		}
	}
	if !strings.Contains(text, "refused:disarmed") {
		t.Fatalf("the roster must say WHY an endpoint was not severed:\n%s", text)
	}
	if !strings.Contains(text, "we could not reach it") {
		t.Fatalf("an unreachable endpoint must say so rather than reading as severed:\n%s", text)
	}
}

// The answer goes to stdout and the next command to stderr, so `whisper alerts | wc -l`
// counts only the answer.
func TestRenderBrief_TheHintIsNotPartOfTheAnswer(t *testing.T) {
	var out, hint bytes.Buffer
	RenderBrief(&out, &hint, busyBook(), Options{Now: testNow})
	if strings.Contains(out.String(), "whisper alerts show") {
		t.Fatalf("the next-command hint leaked into the answer:\n%s", out.String())
	}
	if !strings.Contains(hint.String(), "whisper alerts show ") {
		t.Fatalf("the next command is missing from the commentary:\n%s", hint.String())
	}
}

// The headline is a statement about the world, not a count of rows.
func TestHeadline_IsASentenceAboutTheWorld(t *testing.T) {
	got := busyBook().Headline(testNow, DefaultStaleAck)
	if !strings.Contains(got, "wants a decision") && !strings.Contains(got, "want a decision") {
		t.Fatalf("headline = %q; it must say what the world is asking for", got)
	}
	if strings.Contains(got, "alerts require attention") {
		t.Fatalf("headline = %q; a count of rows is not a statement about the world", got)
	}
	if q := quietBook().Headline(testNow, DefaultStaleAck); q != "" {
		t.Fatalf("a quiet estate produced the headline %q; quiet has its own block", q)
	}
}

// The lane thresholds are SERVED. A read that did not carry them must say so rather than
// printing a local constant, because a silent fallback is how two surfaces come to
// disagree during a rollout.
func TestShow_NeverFallsBackToALocalThreshold(t *testing.T) {
	b := busyBook()
	b.Coverage = Coverage{}
	var out, hint bytes.Buffer
	RenderShow(&out, &hint, b, b.Rows[0], Options{Now: testNow})
	if !strings.Contains(out.String(), "a lane threshold this read did not carry") {
		t.Fatalf("an absent threshold must be said, never substituted:\n%s", out.String())
	}
	if strings.Contains(out.String(), "45.0") {
		t.Fatalf("a local threshold constant reached the output:\n%s", out.String())
	}
	// Half a pair is not a threshold. Printing "review at 0.0" because only one cell
	// arrived would be a fabricated number wearing the word "served".
	b1 := busyBook()
	b1.Coverage.ReviewAt = nil
	var outHalf, hintHalf bytes.Buffer
	RenderShow(&outHalf, &hintHalf, b1, b1.Rows[0], Options{Now: testNow})
	if strings.Contains(outHalf.String(), "review at 0.0") {
		t.Fatalf("a missing threshold was rendered as zero:\n%s", outHalf.String())
	}
	if !strings.Contains(outHalf.String(), "did not carry") {
		t.Fatalf("half a threshold pair must read as not carried:\n%s", outHalf.String())
	}

	b2 := busyBook()
	var out2, hint2 bytes.Buffer
	RenderShow(&out2, &hint2, b2, b2.Rows[0], Options{Now: testNow})
	if !strings.Contains(out2.String(), "act now at 45.0 and review at 30.0, both served") {
		t.Fatalf("the served thresholds must be named as served:\n%s", out2.String())
	}
}

// A null count means NOT READ. It is never rendered as a zero, and a machine consumer can
// tell the difference without parsing prose.
func TestDocument_UnreadCountsAreNullNeverZero(t *testing.T) {
	d := brokenBook().Render(Options{Now: testNow})
	if d.Counts.Open != nil || d.Counts.Endpoints != nil || d.Counts.HeardFrom != nil {
		t.Fatalf("an unread count materialised as a number: %+v", d.Counts)
	}
	if d.Complete {
		t.Fatal("a book with four failed streams is not complete")
	}
	q := quietBook().Render(Options{Now: testNow})
	if q.Counts.Open == nil || *q.Counts.Open != 0 {
		t.Fatalf("a read zero must be a zero, not a null: %+v", q.Counts)
	}
	if !q.Complete {
		t.Fatal("a book whose streams all answered is complete")
	}
}

// A never-scored row carries a null score, and the null means never scored - not zero.
func TestDocument_NeverScoredIsNull(t *testing.T) {
	b := busyBook()
	b.Rows[0].Fused = nil
	d := b.Render(Options{Now: testNow})
	if d.Alerts[0].Score != nil {
		t.Fatalf("a never-scored row serialised a score: %+v", d.Alerts[0])
	}
}

// Take a fleet of 240 endpoints, 209 of them with no host sensor, and a tier split of
// 3 wireguard + 106 socks + 131 resolver - which sums to 240, not to 209. Hung off 209 in
// a bare parenthesis, three true numbers make a false sentence. Reverting governedLine to
// the unconditional parenthesis fails on the first assertion here.
func TestGoverned_ATierSplitNeverDescribesANumberItDoesNotSumTo(t *testing.T) {
	b := quietBook()
	b.Coverage = Coverage{Present: true, Endpoints: 240, SensorShipping: 26, SensorStale: 5,
		SensorAbsent: 209, TierWireguard: 3, TierSocks: 106, TierResolver: 131,
		ActNowAt: ptr(45.0), ReviewAt: ptr(30.0)}
	out := render(b)
	if strings.Contains(out, "with no host sensor (") {
		t.Errorf("a fleet-wide tier split is hung off the sensorless subset as if it split it:\n%s", out)
	}
	if !strings.Contains(out, "209 of 240 at the network layer only, with no host sensor") {
		t.Errorf("the governed count lost its denominator:\n%s", out)
	}
	// The numbers are still there, under the denominator they actually add up to.
	if !strings.Contains(out, "the 240 we see reach us as 3 wireguard, 106 socks, 131 resolver") {
		t.Errorf("the tier split was dropped instead of being attributed:\n%s", out)
	}

	// The control: when the sensorless subset IS the fleet, the split does describe it and
	// the compact parenthesis is right. If this half ever fails, the fix above went too far.
	b.Coverage = Coverage{Present: true, Endpoints: 334, SensorAbsent: 334,
		TierSocks: 293, TierResolver: 41, ActNowAt: ptr(45.0), ReviewAt: ptr(30.0)}
	whole := render(b)
	if !strings.Contains(whole, "334 of 334 at the network layer only, with no host sensor (293 socks, 41 resolver)") {
		t.Errorf("a split that genuinely describes the subset stopped being printed as one:\n%s", whole)
	}
}

// Every stamp on this surface reports over a multi-day horizon, so a bare clock time is a
// number with no denominator: a wave that began three weeks ago printed as
// "started 20:00", which any reader takes for tonight. Reverting Stamp to a bare
// Format("15:04") fails the dated assertion below.
func TestStamp_AMomentThatIsNotTodayCarriesItsDate(t *testing.T) {
	old := testNow.Add(-23 * 24 * time.Hour).Truncate(time.Minute)
	oldStamp := old.UTC().Format("2006-01-02 15:04")

	b := stormBook()
	// One wave, begun 23 days ago, on endpoints last heard from 23 days ago, with the most
	// recent containment 3 days back - all of it inside the horizons these lines report on.
	for i := range b.Rows {
		b.Rows[i].FirstSeen = ms(old)
	}
	for i := range b.Endpoints {
		b.Endpoints[i].Connectivity = "offline"
		b.Endpoints[i].ConnLastSeen = ms(old)
	}
	b.Trail = []Action{landed("2a04:2a01:9::a", 3*24*time.Hour)}
	b.Index()

	var out, hint bytes.Buffer
	RenderBrief(&out, &hint, b, Options{Now: testNow, Fold: true, Horizon: 7 * 24 * time.Hour})
	text := out.String()

	if !strings.Contains(text, "started "+oldStamp) {
		t.Errorf("a wave begun 23 days ago printed without its date:\n%s", text)
	}
	if !strings.Contains(text, "offline since "+oldStamp) {
		t.Errorf("an endpoint last seen 23 days ago printed without its date:\n%s", text)
	}
	want := testNow.Add(-3 * 24 * time.Hour).UTC().Format("2006-01-02 15:04")
	if !strings.Contains(text, "most recently "+want) {
		t.Errorf("a containment action 3 days back printed without its date:\n%s", text)
	}
	if regexp.MustCompile(`(started|offline since|most recently) \d\d:\d\d\b`).MatchString(text) {
		t.Errorf("a bare clock time survived for a moment that is not today:\n%s", text)
	}

	// The control: a moment from today is still the short, readable form. A helper that
	// dated everything would pass every assertion above and be worse to read.
	fresh := stormBook()
	fresh.Trail = []Action{landed("2a04:2a01:9::a", 10*time.Minute)}
	fresh.Index()
	var out2, hint2 bytes.Buffer
	RenderBrief(&out2, &hint2, fresh, Options{Now: testNow, Fold: true, Horizon: 7 * 24 * time.Hour})
	today := testNow.Add(-10 * time.Minute).UTC().Format("15:04")
	if !strings.Contains(out2.String(), "most recently "+today) {
		t.Errorf("a moment from today should stay a bare clock time:\n%s", out2.String())
	}
}
