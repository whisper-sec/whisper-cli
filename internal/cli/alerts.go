// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/alerts"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// alerts.go is the `whisper alerts` surface: the ten-second answer, the queue behind it,
// and the lifecycle from the keyboard.
//
// It invents no plane. Everything it prints is already served, and everything it writes
// goes through a verb that already exists:
//
//	op:list{kind:'standing'} the open conditions, worst-first, with the plane's LANE
//	op:list{kind:'coverage'} the denominators, and the SERVED lane thresholds
//	op:list{kind:'agents'} connectivity and sensor liveness per endpoint
//	op:list{kind:'audit'} the containment trail: what landed, and what did not
//	op:partner{op:'alert.suppressions'} the live mutes, read-only, so quiet can be audited
//	op:task{action:...} acknowledge / assign / note / snooze / reopen / done
//
// The lifecycle deliberately rides op:task rather than a second acknowledgement plane.
// The ack and assignee marks it writes are the exact cells kind:'standing' serves, and
// which the console and the portal read, so an acknowledgement typed at a keyboard is
// visible on every other surface without any of them knowing the others exist.
//
// Two conventions this file inherits rather than invents: the answer goes to stdout and
// the commentary to stderr, so `whisper alerts | wc -l` counts only the answer; and a
// pipe with no explicit flag does the sensible thing, which for a watch is NDJSON.

// alertsExitGate is the exit code `whisper alerts check` returns when something wants a
// decision. It is DISTINCT from the generic runtime failure code on purpose: a gate that
// cannot tell "there are alerts" from "I could not check" is the same defect as a feed
// that renders a fault as a zero. Any non-zero still blocks a naive `check && deploy`.
const alertsExitGate = 3

// exitCodeError carries a specific process exit code out of a RunE. Execute maps it.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

// exitCodeOf returns the exit code an error asks for, and whether it asked at all.
func exitCodeOf(err error) (int, bool) {
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code, true
	}
	return 0, false
}

// alertFlags are the knobs shared by the read commands.
type alertFlags struct {
	lane      string
	silent    bool
	contained bool
	held      bool
	limit     int
	staleAck  time.Duration
	horizon   time.Duration
	fold      bool
	by        string
	note      string
	assignee  string
	interval  time.Duration
	heartbeat time.Duration
}

func newAlertsCmd() *cobra.Command {
	var f alertFlags
	cmd := &cobra.Command{
		Use:     "alerts",
		Aliases: []string{"alert", "attention"},
		Short:   "What is asking for you right now, and what is holding the quiet",
		Long: "The ten-second answer: is anything happening that needs a decision from you,\n" +
			"and may you close this terminal.\n\n" +
			"Interruption here is a function of AGENCY, not of severity: something asks for\n" +
			"you when a decision only you can make still changes the outcome. Where we already\n" +
			"acted at the network layer and the action held, you get a receipt instead.\n\n" +
			"Every quiet answer proves itself. A pipeline that broke and an estate with nothing\n" +
			"happening are different sentences here, never the same blank space: you always see\n" +
			"how many endpoints reported, what was severed, what rules are holding quiet, and\n" +
			"which streams did not answer.\n\n" +
			"Three axes, one model, and they are the same words the console and the partner\n" +
			"portal use:\n\n" +
			"  LANE       act now | review | not asking     the plane's own band, served\n" +
			"  STATE      open | acked | snoozed | resolved  what a person did to it\n" +
			"  INTERRUPT  page | digest | silent             whether it needs you right now\n\n" +
			"Keeping them apart is the point. An act-now condition we already severed is a\n" +
			"receipt, not a page. And an acknowledgement typed here is the same mark the other\n" +
			"surfaces read, so acknowledging here silences there.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertsBrief(cmd.Context(), &f)
		},
	}
	cmd.PersistentFlags().DurationVar(&f.staleAck, "stale-ack", alerts.DefaultStaleAck,
		"how long an acknowledgement stands before an untouched row asks again")
	cmd.PersistentFlags().DurationVar(&f.horizon, "horizon", alerts.DefaultHorizon,
		"how far back the containment lines look")
	cmd.Flags().BoolVar(&f.fold, "fold", true,
		"collapse same-technique hits across endpoints into one wave with a roster")

	cmd.AddCommand(
		newAlertsListCmd(&f),
		newAlertsShowCmd(&f),
		newAlertsWatchCmd(&f),
		newAlertsCheckCmd(&f),
		newAlertsMuteCmd(&f),
	)
	for _, lc := range alertLifecycleCmds(&f) {
		cmd.AddCommand(lc)
	}
	return cmd
}

// --- reading the book ---------------------------------------------------------------

// wanted names which streams a command needs. Reading a stream nobody will render is a
// call we did not have to make, and the coverage read in particular is the expensive one.
type wanted struct {
	standing     bool
	coverage     bool
	endpoints    bool
	trail        bool
	suppressions bool
}

var wantAll = wanted{standing: true, coverage: true, endpoints: true, trail: true, suppressions: true}

// readBook runs the reads it was asked for CONCURRENTLY and folds them into one Book,
// recording the outcome of every one of them - including the ones that failed.
//
// A failure never aborts the read. The whole point of the surface is that a partial
// answer is printed as a partial answer, with its counts marked as floors and the stream
// that did not answer named. A read that gave up on the first fault would be the very
// defect this design exists to remove.
func readBook(ctx context.Context, c *client.Client, w wanted, limit int) *alerts.Book {
	b := &alerts.Book{Endpoint: controlHost(), ReadAt: time.Now()}
	type result struct {
		stream alerts.Stream
		apply  func()
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := map[string]result{}

	run := func(name string, fn func() (int, func(), error)) {
		defer wg.Done()
		st := alerts.Stream{Name: name, At: time.Now()}
		rows, apply, err := fn()
		st.Rows, st.Err = rows, err
		var na *notApplicableError
		if errors.As(err, &na) {
			st.Err = nil
			st.NotApplicable = na.why
		}
		mu.Lock()
		results[name] = result{stream: st, apply: apply}
		mu.Unlock()
	}

	if w.standing {
		wg.Add(1)
		go run("detections", func() (int, func(), error) {
			recs, err := listItems(ctx, c, map[string]any{"kind": "standing"})
			if err != nil {
				return 0, nil, err
			}
			rows := make([]alerts.Row, 0, len(recs))
			for _, item := range recs {
				rows = append(rows, alerts.RowFrom(item))
			}
			return len(rows), func() { b.Rows = rows }, nil
		})
	}
	if w.coverage {
		wg.Add(1)
		go run("coverage", func() (int, func(), error) {
			recs, err := listItems(ctx, c, map[string]any{"kind": "coverage"})
			if err != nil {
				return 0, nil, err
			}
			if len(recs) == 0 {
				return 0, nil, nil
			}
			cov := alerts.CoverageFrom(recs[0])
			return 1, func() { b.Coverage = cov }, nil
		})
	}
	if w.endpoints {
		wg.Add(1)
		go run("endpoints", func() (int, func(), error) {
			recs, err := listItems(ctx, c, map[string]any{"kind": "agents"})
			if err != nil {
				return 0, nil, err
			}
			eps := make([]alerts.Endpoint, 0, len(recs))
			for _, item := range recs {
				eps = append(eps, alerts.EndpointFrom(item))
			}
			return len(eps), func() { b.Endpoints = eps }, nil
		})
	}
	if w.trail {
		wg.Add(1)
		go run("containment", func() (int, func(), error) {
			args := map[string]any{"kind": "audit"}
			if limit > 0 {
				args["limit"] = limit
			}
			recs, err := listItems(ctx, c, args)
			if err != nil {
				return 0, nil, err
			}
			trail := make([]alerts.Action, 0, len(recs))
			for _, item := range recs {
				trail = append(trail, alerts.ActionFrom(item))
			}
			return len(trail), func() { b.Trail = trail }, nil
		})
	}
	if w.suppressions {
		wg.Add(1)
		go run("suppressions", func() (int, func(), error) {
			sups, err := readSuppressions(ctx, c)
			if err != nil {
				return 0, nil, err
			}
			return len(sups), func() { b.Suppression = sups }, nil
		})
	}
	wg.Wait()

	// Fold in a fixed order so the read line names streams the same way every time.
	for _, name := range []string{"detections", "coverage", "endpoints", "containment", "suppressions"} {
		r, ok := results[name]
		if !ok {
			continue
		}
		b.Streams = append(b.Streams, r.stream)
		if r.apply != nil {
			r.apply()
		}
	}
	b.ReadAt = time.Now()
	b.Index()
	return b
}

// listItems runs one op:list read and returns the item maps, unwrapping the plane's
// uniform [kind, item] row shape. A row that is not in that shape is passed through as
// itself, because a plane that grows a flatter shape should not blank this surface.
func listItems(ctx context.Context, c *client.Client, args map[string]any) ([]map[string]any, error) {
	cx, cancel := context.WithTimeout(ctx, callTimeout())
	defer cancel()
	env, err := c.Agents(cx, "list", args)
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, perr
	}
	recs := env.Result.Records()
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		if m, ok := rec["item"].(map[string]any); ok {
			out = append(out, m)
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// notApplicableError marks a DEFINITE negative answer, which is not a read failure. An
// account with no partner organisation genuinely has no suppression register: nothing was
// hidden from us, so nothing downstream becomes a floor.
type notApplicableError struct{ why string }

func (e *notApplicableError) Error() string { return e.why }

// readSuppressions reads the live mute register. A key that carries no partner scope gets
// a permanent 403 from the plane, and that is an ANSWER: there is no register, so no rule
// can be holding quiet on this account.
//
// Only the SCOPE refusal is read that way, and the distinction is not pedantry: the plane
// returns 403 for two different facts. FORBIDDEN_SCOPE means the key carries no partner
// grant, which is a definite answer - there is no register, so nothing can be holding
// quiet. ANONYMOUS_WRITE means we were not authenticated at all, which is a READ FAILURE
// and must turn every count below into a floor. Collapsing the two would make an
// unauthenticated caller see a confident "nothing is muted" it never actually read, which
// is the precise shape of a check that passes for the wrong reason.
func readSuppressions(ctx context.Context, c *client.Client) ([]alerts.Suppression, error) {
	cx, cancel := context.WithTimeout(ctx, callTimeout())
	defer cancel()
	env, err := c.Agents(cx, "partner", map[string]any{"op": "alert.suppressions"})
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		if pe, ok := client.AsProblem(perr); ok && isNoPartnerOrg(pe) {
			return nil, &notApplicableError{why: "this account carries no mute register (" + firstLineOf(pe.Error()) + ")"}
		}
		return nil, perr
	}
	var out []alerts.Suppression
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		out = append(out, alerts.SuppressionFrom(item))
	}
	return out, nil
}

// isNoPartnerOrg recognises the plane's PERMANENT "this key carries no partner
// organization" refusal, on its type token first (stable) and on its own sentence second
// (liberal, so a reworded detail does not silently reclassify the answer as a fault).
// Every other 403, ANONYMOUS_WRITE included, stays a read failure.
func isNoPartnerOrg(pe *client.ProblemError) bool {
	if pe.Status != 403 {
		return false
	}
	if strings.EqualFold(pe.Type, "FORBIDDEN_SCOPE") {
		return true
	}
	return strings.Contains(strings.ToLower(pe.Error()), "partner")
}

func callTimeout() time.Duration {
	if g.timeout > 0 {
		return g.timeout
	}
	return 30 * time.Second
}

// controlHost names the control endpoint this read went to, for the provenance line. A
// count with no host and no timestamp on it is a claim with no date.
func controlHost() string {
	raw := g.controlURL
	if raw == "" {
		raw = client.DefaultControlURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

func renderOptions(f *alertFlags, fold bool) alerts.Options {
	return alerts.Options{
		Now:      time.Now(),
		StaleAck: f.staleAck,
		Horizon:  f.horizon,
		Fold:     fold,
	}
}

// --- the ten-second answer ------------------------------------------------------------

func runAlertsBrief(ctx context.Context, f *alertFlags) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	b := readBook(ctx, c, wantAll, f.limit)
	opt := renderOptions(f, f.fold)
	if g.jsonOut {
		emitJSONValue(b.Render(opt))
		return nil
	}
	alerts.RenderBrief(os.Stdout, os.Stderr, b, opt)
	return nil
}

// --- list -----------------------------------------------------------------------------

func newAlertsListCmd(f *alertFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [target]",
		Short: "The queue, worst first, with an optional target to narrow it",
		Long: "List the standing conditions in your tenant, worst-fused-first across the whole\n" +
			"book of endpoints, in the plane's own lanes.\n\n" +
			"A target narrows the list and is read the way you would type it: an agent name, a\n" +
			"/128 (with or without its prefix length), a hostname, an fqdn with or without a\n" +
			"trailing dot, a bare technique like T1486, or any of those with a technique after\n" +
			"a slash.\n\n" +
			"With --json this emits the plane's own envelope verbatim, columns and all, so a\n" +
			"script sees exactly what the server sent.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return runAlertsList(cmd.Context(), f, target)
		},
	}
	cmd.Flags().StringVar(&f.lane, "lane", "", "narrow to one lane: act-now | review | handled | unscored")
	cmd.Flags().BoolVar(&f.silent, "silent", false,
		"the rows nothing is asking you about, so you can see what is being carried quietly "+
			"(a never-quiet technique such as ransomware is shown even here)")
	cmd.Flags().BoolVar(&f.contained, "contained", false, "only rows where a control action already landed on the endpoint")
	cmd.Flags().BoolVar(&f.held, "held", false, "only rows somebody has already taken")
	cmd.Flags().IntVar(&f.limit, "limit", 0, "cap the containment trail read (default: the plane's own cap)")
	return cmd
}

func runAlertsList(ctx context.Context, f *alertFlags, target string) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	// --json on a single-op read is the plane's own op envelope: one op call in, one
	// envelope out, no field loss and no re-encoding by us. Unwrapped from the Cypher
	// table the live plane transports it in, so `| jq '.result.columns'` is the plane's
	// own column list rather than the carrier's.
	if g.jsonOut && target == "" && f.lane == "" && !f.silent && !f.contained && !f.held {
		cx, cancel := context.WithTimeout(ctx, callTimeout())
		defer cancel()
		env, aerr := c.Agents(cx, "list", map[string]any{"kind": "standing"})
		if aerr != nil {
			return aerr
		}
		emitOpEnvelope(env)
		return envelopeError(env)
	}

	b := readBook(ctx, c, wantAll, f.limit)
	opt := renderOptions(f, false)
	sel := alerts.ParseSelector(target)
	rows := filterRows(b, sel, f, opt)

	if g.jsonOut {
		doc := b.Render(opt)
		keep := map[string]bool{}
		for _, r := range rows {
			keep[r.Ref()] = true
		}
		kept := doc.Alerts[:0]
		for _, a := range doc.Alerts {
			if keep[a.Ref] {
				kept = append(kept, a)
			}
		}
		doc.Alerts = kept
		emitJSONValue(doc)
		return nil
	}

	if len(rows) == 0 {
		// An empty list must say WHICH empty it is. A narrowed read that matched nothing
		// and a book that could not be read are different facts.
		if !b.Complete() {
			fmt.Fprintln(os.Stdout, "nothing matched in what we could read")
			alerts.RenderQuiet(os.Stdout, b, opt)
			return nil
		}
		if !sel.Empty() {
			fmt.Fprintf(os.Stdout, "nothing standing matches %s\n", sel.String())
		} else {
			fmt.Fprintln(os.Stdout, "nothing is standing")
		}
		alerts.RenderQuiet(os.Stdout, b, opt)
		return nil
	}

	now := opt.Now
	var out [][]string
	for _, r := range rows {
		e := b.EndpointFor(r)
		v := alerts.Judge(r, e, b.Trail, now, f.staleAck)
		out = append(out, []string{
			r.Ref(),
			alerts.LaneProse(r.Lane),
			v.Token,
			alerts.Disposition(r, b.Trail, now),
			alerts.Age(alerts.RowAge(r, now)),
			orDash(r.Holder()),
			firstLineOf(r.Title),
		})
	}
	printTable([]string{"ALERT", "LANE", "INTERRUPT", "NOW", "AGE", "HELD BY", "WHAT HAPPENED"}, out)
	alerts.RenderQuiet(os.Stderr, b, opt)
	return nil
}

// filterRows applies the selector and the narrowing flags. --silent deliberately refuses
// to hide a never-quiet technique: a filter that could bury ransomware because somebody
// asked for the quiet rows would be the tuning project this product exists not to need.
func filterRows(b *alerts.Book, sel alerts.Selector, f *alertFlags, opt alerts.Options) []alerts.Row {
	now := opt.Now
	lane := normaliseLane(f.lane)
	var out []alerts.Row
	for _, r := range b.Rows {
		e := b.EndpointFor(r)
		if !sel.Matches(r, e) {
			continue
		}
		if f.lane != "" && r.Lane != lane {
			continue
		}
		v := alerts.Judge(r, e, b.Trail, now, f.staleAck)
		if f.silent && v.Token == alerts.InterruptPage && !alerts.NeverQuietTechnique(r.Technique) {
			continue
		}
		if f.contained && alerts.Disposition(r, b.Trail, now) != "severed" {
			continue
		}
		if f.held && !r.Held() {
			continue
		}
		out = append(out, r)
	}
	return out
}

// normaliseLane accepts the ways a person spells a lane. "act now", "act-now" and
// "actnow" are one intent, and refusing two of them would be resistance for its own sake.
func normaliseLane(s string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "-"))) {
	case "act-now", "actnow", "now", "page":
		return alerts.LaneActNow
	case "review", "next":
		return alerts.LaneReview
	case "handled", "quiet", "counted", "not-asking":
		return alerts.LaneQuiet
	case "unscored", "none":
		return alerts.LaneUnscored
	default:
		return s
	}
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// --- show -----------------------------------------------------------------------------

func newAlertsShowCmd(f *alertFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show <target>",
		Short: "One condition in full: what happened, why we think so, what is true now",
		Long: "Show one standing condition in the four fixed slots, plus the endpoint it lives\n" +
			"on, the score against the SERVED lane thresholds, and the reason it is or is not\n" +
			"interrupting you.\n\n" +
			"The target is read liberally: an agent name, a /128, a hostname or an fqdn, with\n" +
			"or without a technique after a slash. A target that matches several conditions\n" +
			"lists them rather than picking one for you.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAlertsShow(cmd.Context(), f, args[0])
		},
	}
}

func runAlertsShow(ctx context.Context, f *alertFlags, target string) error {
	sel := alerts.ParseSelector(target)
	if sel.Empty() {
		return usageErr("name what to show: an agent, a /128, or an agent and a technique like scout/T1486")
	}
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	b := readBook(ctx, c, wantAll, f.limit)
	opt := renderOptions(f, false)
	rows := filterRows(b, sel, &alertFlags{staleAck: f.staleAck}, opt)

	if len(rows) == 0 {
		if !b.Complete() {
			return &client.ProblemError{Status: 502, Title: "partial read",
				Detail: "nothing matched " + sel.String() + ", and " + streamNames(b.Incomplete()) +
					" did not answer, so this is not proof that it is not there"}
		}
		return &client.ProblemError{Status: 404, Title: "no such condition",
			Detail: "nothing standing matches " + sel.String() + " - run `whisper alerts list` to see what is"}
	}
	if len(rows) > 1 {
		if g.jsonOut {
			doc := b.Render(opt)
			emitJSONValue(doc)
			return nil
		}
		fmt.Fprintf(os.Stdout, "%s matches %d standing conditions:\n\n", sel.String(), len(rows))
		var out [][]string
		for _, r := range rows {
			out = append(out, []string{r.Ref(), alerts.LaneProse(r.Lane), firstLineOf(r.Title)})
		}
		printTable([]string{"ALERT", "LANE", "WHAT HAPPENED"}, out)
		fmt.Fprintln(os.Stderr, "\nname one of them to see it in full")
		return nil
	}

	if g.jsonOut {
		doc := b.Render(opt)
		for _, a := range doc.Alerts {
			if a.Ref == rows[0].Ref() {
				emitJSONValue(a)
				return nil
			}
		}
		emitJSONValue(doc)
		return nil
	}
	alerts.RenderShow(os.Stdout, os.Stderr, b, rows[0], opt)
	return nil
}

func streamNames(ss []alerts.Stream) string {
	names := make([]string, 0, len(ss))
	for _, s := range ss {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// --- check ----------------------------------------------------------------------------

func newAlertsCheckCmd(f *alertFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Gate a script on whether anything wants a decision - the exit code is the answer",
		Long: "The scriptable gate. Prints nothing when nothing is asking for you and exits 0;\n" +
			"names what is asking on stderr and exits 3 when something is.\n\n" +
			"Three, not one, on purpose: exit 1 means we could not tell (a stream did not\n" +
			"answer), and a deploy gate has to be able to distinguish a failure from a verdict.\n" +
			"Both are non-zero, so a plain `whisper alerts check && deploy` still fails closed.\n\n" +
			"  whisper alerts check && ./deploy.sh",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertsCheck(cmd.Context(), f)
		},
	}
}

func runAlertsCheck(ctx context.Context, f *alertFlags) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	b := readBook(ctx, c, wanted{standing: true, endpoints: true, trail: true}, f.limit)
	opt := renderOptions(f, false)

	// A gate must never pass on a read it could not make. An incomplete read is exit 1,
	// which is "we could not tell", and it says which stream went missing.
	if bad := b.Incomplete(); len(bad) > 0 {
		return &client.ProblemError{Status: 502, Title: "could not check",
			Detail: streamNames(bad) + " did not answer, so this gate cannot tell you whether anything is asking"}
	}

	var paging []alerts.Row
	for _, r := range b.Rows {
		if alerts.Judge(r, b.EndpointFor(r), b.Trail, opt.Now, f.staleAck).Token == alerts.InterruptPage {
			paging = append(paging, r)
		}
	}
	if g.jsonOut {
		doc := b.Render(opt)
		emitJSONValue(doc)
	}
	if len(paging) == 0 {
		return nil
	}
	if !g.jsonOut {
		for _, r := range paging {
			fmt.Fprintf(os.Stderr, "%s  %s  %s\n", r.Ref(), alerts.LaneProse(r.Lane), firstLineOf(r.Title))
		}
	}
	return &exitCodeError{code: alertsExitGate,
		msg: fmt.Sprintf("%d condition(s) want a decision - run `whisper alerts` to read them", len(paging))}
}

// --- mute -------------------------------------------------------------------------------

func newAlertsMuteCmd(f *alertFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mute",
		Short: "The register of rules holding quiet",
		Long: "Read the named, dated, owner-attributed rules that are holding some of your\n" +
			"estate quiet. It must be impossible to be quiet without being able to see what is\n" +
			"holding the quiet, which is what this register is for.\n\n" +
			"Only the read half is here: creating and revoking a rule is done where the rule's\n" +
			"scope and expiry can be reviewed alongside the customers it covers.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertsMuteList(cmd.Context(), f)
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the rules holding quiet",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAlertsMuteList(cmd.Context(), f)
		},
	})
	return cmd
}

func runAlertsMuteList(ctx context.Context, f *alertFlags) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	b := readBook(ctx, c, wanted{suppressions: true}, 0)
	var st alerts.Stream
	if len(b.Streams) > 0 {
		st = b.Streams[0]
	}
	if g.jsonOut {
		emitJSONValue(b.Render(renderOptions(f, false)))
		return nil
	}
	if st.NotApplicable != "" {
		fmt.Fprintln(os.Stdout, "nothing is holding quiet: "+st.NotApplicable)
		return nil
	}
	if st.Err != nil {
		return st.Err
	}
	live := b.LiveSuppressions(time.Now())
	if len(live) == 0 {
		fmt.Fprintln(os.Stdout, "no rule is holding any of your estate quiet")
		return nil
	}
	var rows [][]string
	for _, s := range live {
		expires := "never, and that needs a second look"
		if s.ExpiresAt > 0 {
			expires = time.UnixMilli(s.ExpiresAt).UTC().Format("2006-01-02 15:04")
		}
		rows = append(rows, []string{orDash(s.Name), orDash(s.Scope), orDash(s.CreatedBy), expires})
	}
	printTable([]string{"NAME", "SCOPE", "CREATED BY", "EXPIRES"}, rows)
	fmt.Fprintf(os.Stderr, "%d rule(s) holding quiet\n", len(live))
	return nil
}

// --- lifecycle --------------------------------------------------------------------------

// lifecycleVerb binds a keyboard verb to the plane action it performs. The vocabulary is
// the one every other surface uses, because the mark written here is the same served cell
// they read: an acknowledgement typed at a terminal is why the browser badge and the
// partner queue go quiet, with none of the three knowing the others exist.
type lifecycleVerb struct {
	name    string
	aliases []string
	action  string
	short   string
	long    string
	// warn is printed to stderr before the write when the verb promises less than its
	// name suggests. Saying so is cheaper than a surface that quietly means something else.
	warn func(target string) string
}

func alertLifecycleCmds(f *alertFlags) []*cobra.Command {
	verbs := []lifecycleVerb{
		{
			name:    "ack",
			aliases: []string{"acknowledge"},
			action:  "acknowledge",
			short:   "Say you have seen it, so nobody duplicates you",
			long: "Mark a condition as seen. It stays exactly as open as the plane left it:\n" +
				"acknowledging says a human has it, never that it is handled. An acknowledged\n" +
				"detection that dropped out of the queue would be a keystroke that hides a live\n" +
				"intrusion.\n\nThe mark is the same served cell the console and the partner queue\n" +
				"read, so one acknowledgement retires the interruption on every surface.",
		},
		{
			name:    "unack",
			aliases: []string{"unacknowledge"},
			action:  "unacknowledge",
			short:   "Put it back in the queue",
			long:    "Remove your acknowledgement, so the condition asks for somebody again.",
		},
		{
			name:   "assign",
			action: "assign",
			short:  "Put a name on it",
			long: "Record who is taking a condition. Pass --to with a name, or leave it off to\n" +
				"clear the assignment.",
		},
		{
			name:   "note",
			action: "note",
			short:  "Leave a line on it for whoever looks next",
			long:   "Attach a short note. Passing no --text clears the note rather than failing.",
		},
		{
			name:   "snooze",
			action: "snooze",
			short:  "Hide it until you reopen it",
			long: "Hide a condition from the standing queue.\n\n" +
				"Read the name carefully: the plane stores the moment you snoozed, not a\n" +
				"wake-up time, so this hides the row until somebody reopens it. It does not\n" +
				"come back on its own. Until the plane carries an expiry, calling it a timed\n" +
				"snooze would be a promise this command cannot keep.",
			warn: func(target string) string {
				return "this hides " + target + " until you run `whisper alerts reopen " + target +
					"` - there is no wake-up timer on the plane yet"
			},
		},
		{
			name:   "reopen",
			action: "reopen",
			short:  "Bring it back into the standing queue",
			long:   "Return a snoozed or resolved condition to the open queue.",
		},
		{
			name:    "resolve",
			aliases: []string{"done"},
			action:  "done",
			short:   "Close it",
			long: "Close a condition.\n\n" +
				"The producer decides what is still true: if the condition is still being\n" +
				"observed, the next report reopens it. Closing something the plane can still\n" +
				"see does not make it untrue.",
		},
	}
	out := make([]*cobra.Command, 0, len(verbs))
	for _, v := range verbs {
		out = append(out, newLifecycleCmd(f, v))
	}
	return out
}

func newLifecycleCmd(f *alertFlags, v lifecycleVerb) *cobra.Command {
	cmd := &cobra.Command{
		Use:     v.name + " <target>",
		Aliases: v.aliases,
		Short:   v.short,
		Long: v.long + "\n\nThe target is read the way you would type it: an agent name, a /128 with or\n" +
			"without its prefix length, a hostname, an fqdn with or without a trailing dot, or\n" +
			"any of those with the technique after a slash, as `whisper alerts` prints it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLifecycle(cmd.Context(), f, v, args[0])
		},
	}
	if v.action == "assign" {
		cmd.Flags().StringVar(&f.assignee, "to", "", "who is taking it (omit to clear the assignment)")
	}
	if v.action == "note" {
		cmd.Flags().StringVar(&f.note, "text", "", "the note (omit to clear it)")
	}
	cmd.Flags().StringVar(&f.by, "by", "", "record a different actor than the key's own principal")
	return cmd
}

// runLifecycle resolves the target against the standing book, then writes ONE transition
// through op:task - the plane's own verb for a detection, whose ack and assignee marks are
// the exact cells every other surface reads.
//
// It resolves first rather than posting a guess, so a typo is a clear sentence naming what
// was expected instead of an opaque not_found from the plane.
func runLifecycle(ctx context.Context, f *alertFlags, v lifecycleVerb, target string) error {
	sel := alerts.ParseSelector(target)
	if sel.Empty() {
		return usageErr("name what to %s: an agent and a technique, like scout/T1486", v.name)
	}
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	b := readBook(ctx, c, wanted{standing: true, endpoints: true}, 0)
	if st := b.Incomplete(); len(st) > 0 {
		return &client.ProblemError{Status: 502, Title: "partial read",
			Detail: streamNames(st) + " did not answer, so we could not resolve " + sel.String() +
				" - nothing was written"}
	}
	rows := filterRows(b, sel, &alertFlags{staleAck: f.staleAck}, renderOptions(f, false))
	if len(rows) == 0 {
		return &client.ProblemError{Status: 404, Title: "no such condition",
			Detail: "nothing standing matches " + sel.String() + " - run `whisper alerts list` to see what is"}
	}
	if len(rows) > 1 && sel.Condition == "" {
		refs := make([]string, 0, len(rows))
		for _, r := range rows {
			refs = append(refs, r.Ref())
		}
		sort.Strings(refs)
		return usageErr("%s matches %d conditions - name one of them: %s",
			sel.String(), len(rows), strings.Join(refs, " "))
	}

	row := rows[0]
	if v.warn != nil {
		if w := v.warn(row.Ref()); w != "" {
			fmt.Fprintln(os.Stderr, "whisper: "+w)
		}
	}
	args := map[string]any{
		"address": row.Address,
		"id":      row.ID,
		"action":  v.action,
	}
	if row.Address == "" {
		args["agent"] = row.Agent
		delete(args, "address")
	}
	if f.by != "" {
		args["by"] = f.by
	}
	if v.action == "assign" {
		args["assignee"] = f.assignee
	}
	if v.action == "note" {
		args["note"] = f.note
	}

	cx, cancel := context.WithTimeout(ctx, callTimeout())
	defer cancel()
	env, err := c.Agents(cx, "task", args)
	if err != nil {
		return err
	}
	handled, perr := renderEnvelope(env)
	if handled || perr != nil {
		return perr
	}
	fmt.Fprintf(os.Stdout, "%s %s\n", row.Ref(), lifecyclePast(v))
	fmt.Fprintf(os.Stderr, "  whisper alerts show %s\n", row.Ref())
	return nil
}

// lifecyclePast is the past-tense clause the confirmation ends in. Past tense on purpose:
// a sentence in the present tense becomes a lie while the reader sleeps.
func lifecyclePast(v lifecycleVerb) string {
	switch v.action {
	case "acknowledge":
		return "acknowledged. it is still open, and it is still yours"
	case "unacknowledge":
		return "is back in the queue"
	case "assign":
		return "assigned"
	case "note":
		return "noted"
	case "snooze":
		return "hidden until you reopen it"
	case "reopen":
		return "reopened"
	case "done":
		return "closed. if the producer still sees it, its next report reopens it"
	default:
		return "updated"
	}
}
