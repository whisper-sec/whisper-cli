// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_migrate_acl.go is the ACL half of `whisper whale migrate apply` and its undo.
//
// The identity half gives every node of their tailnet a /128. This half publishes the
// reachability between them: their rules, rewritten onto those /128s, as ONE WhaleACL
// document, published with compare-and-set. The order of operations is the design:
//
//  1. Build the document from the plan alone (whale.BuildMigrationACL), and refuse before
//     any write when it cannot be built faithfully, does not fit, would govern agents the
//     operator has not acknowledged, or names a node whose live tags differ from the plan.
//  2. Record a PENDING receipt carrying the document and the one it replaces, and save it.
//     A reply lost in flight must never cost the tenant its previous document.
//  3. Send it. Applied, refused, or still pending when the answer never came.
//
// A document governs the whole tenant, so rollback undoes it FIRST, and refuses to revoke a
// single identity while a document that names it is still in force.

// aclSubject is the receipt subject of the ACL step: there is one document per fleet.
const aclSubject = "whale.acl"

// aclLagAttempts and aclLagDelay bound the retry for the one refusal that is not about the
// document: a control plane that has not yet seen this run's registers. Vars,
// so a test does not sleep.
var (
	aclLagAttempts = 6
	aclLagDelay    = 5 * time.Second
)

// aclLagPhrases are the control plane's words for "that node is not in my roster", which
// is what it says for a few seconds about a node registered just before. Each is part of a
// refusal it really sends; the document only ever names planned nodes, so on
// a converged box none of them can be about the document itself.
var aclLagPhrases = []string{"not one of your nodes", "matched no node", "matched nothing", "names nothing"}

type aclOptions struct {
	skip, replace, acceptFleetWide bool
}

// aclOutcome is what the ACL step did, for the summary and for --json.
type aclOutcome struct {
	State     string   `json:"state"` // published | unchanged | reconciled | skipped | refused
	Hash      string   `json:"hash,omitempty"`
	Replaced  string   `json:"replaced,omitempty"`
	Grants    int      `json:"grants,omitempty"`
	SSHRules  int      `json:"ssh_rules,omitempty"`
	Tests     int      `json:"tests,omitempty"`
	Notes     []string `json:"notes,omitempty"`
	Dropped   []string `json:"dropped,omitempty"`
	Adopted   []string `json:"adopted,omitempty"`
	OutOfPlan int      `json:"agents_outside_plan,omitempty"`
	// OutsideTagged names the agents outside the plan that carry one of its tags.
	OutsideTagged []string `json:"agents_outside_plan_with_plan_tags,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// planAddresses maps each node to the /128 its live identity receipt records.
func planAddresses(p *whale.Plan) (map[string]string, []string) {
	addrs := map[string]string{}
	var adopted []string
	for _, n := range p.Nodes {
		rec, ok := p.ReceiptFor(stepIdentity, n.TailscaleID)
		if !ok || !rec.Applied() || rec.Address == "" {
			continue
		}
		addrs[n.TailscaleID] = rec.Address
		if rec.Result == whale.ResultExisting {
			adopted = append(adopted, n.Label)
		}
	}
	return addrs, adopted
}

func sameAddr(a, b string) bool {
	x, err1 := netip.ParseAddr(strings.TrimSpace(a))
	y, err2 := netip.ParseAddr(strings.TrimSpace(b))
	return err1 == nil && err2 == nil && x == y
}

// runMigrateACL is step 1 to 3 above. peers is the fleet as it was read before this run
// wrote anything.
func runMigrateACL(c *client.Client, p *whale.Plan, planPath string, peers []whalePeer, opt aclOptions) (aclOutcome, error) {
	out := aclOutcome{}
	addrs, adopted := planAddresses(p)
	out.Adopted = adopted
	b, err := whale.BuildMigrationACL(p, addrs)
	if errors.Is(err, whale.ErrNothingToPublish) {
		out.State, out.Dropped = "refused", b.Dropped
		return out, &client.ProblemError{Status: 422, Title: "no ACL", Detail: "none of this plan's rules carries into a " +
			"WhaleACL grant, so nothing was published (the reasons are listed above). Publishing nothing leaves your fleet " +
			"open inside its tenancy; publishing a bare default-deny would refuse every flow. Decide which with " +
			"`whisper whale acl set`, or re-run with --skip-acl to finish the identities alone"}
	}
	if err != nil {
		out.State = "refused"
		return out, &client.ProblemError{Status: 422, Title: "no ACL", Detail: err.Error()}
	}
	doc := string(b.Document)
	out.Grants, out.SSHRules, out.Tests, out.Notes, out.Dropped = b.Grants, b.SSHRules, b.Tests, b.Notes, b.Dropped

	if n := len(client.EscapeCypherString(doc)); n > whale.MaxACLBytes {
		out.State = "refused"
		return out, &client.ProblemError{Status: 413, Title: "ACL too large", Detail: fmt.Sprintf(
			"the WhaleACL for this plan is %d bytes once escaped for the wire, and the control plane takes at most %d. "+
				"Nothing was published. Group nodes under tags in their policy and re-plan, or publish a hand-written "+
				"document with `whisper whale acl set` and re-run with --skip-acl", n, whale.MaxACLBytes)}
	}

	liveTags, err := checkPlannedTags(c, p, addrs)
	if err != nil {
		out.State = "refused"
		return out, err
	}

	// The document governs the whole tenant: say so, and require consent, when it would
	// reach agents this plan does not know. A tag is a tenant-wide selector, so an outside
	// agent carrying one of the plan's tags is not merely governed: it takes that tag's
	// grants. Those are named, because "governed" undersells it.
	planTags := map[string]bool{}
	for _, n := range p.Nodes {
		for _, t := range whale.NodeTags(n) {
			planTags[t] = true
		}
	}
	var tagged []string
	for _, peer := range peers {
		mine := false
		for _, a := range addrs {
			mine = mine || sameAddr(a, peer.Address)
		}
		if mine {
			continue
		}
		out.OutOfPlan++
		var shared []string
		for _, t := range liveTags[canonicalAddr(peer.Address)] {
			if planTags[t] {
				shared = append(shared, t)
			}
		}
		if len(shared) > 0 {
			tagged = append(tagged, firstNonBlank(peer.Label, peer.Name, peer.Address)+" ("+strings.Join(shared, ",")+")")
		}
	}
	out.OutsideTagged = tagged
	if out.OutOfPlan > 0 && !opt.acceptFleetWide {
		out.State = "refused"
		egress := "their egress is kept by the `* -> autogroup:internet` grant this document adds"
		if len(b.Notes) == 0 {
			egress = "their EGRESS stops too, because your policy has its own internet rules and they name only migrated nodes"
		}
		taggedNote := ""
		if len(tagged) > 0 {
			taggedNote = fmt.Sprintf(" %d of them carry a tag this plan's rules name, and so TAKE that tag's grants "+
				"as source and destination: %s.", len(tagged), strings.Join(tagged, ", "))
		}
		return out, &client.ProblemError{Status: 409, Title: "fleet-wide", Detail: fmt.Sprintf(
			"a WhaleACL governs every agent in this account, and %d agent(s) here are not part of this plan. Once it is "+
				"published, their east-west traffic is refused unless a rule names them, and %s.%s Nothing was published. "+
				"Re-run with --accept-fleet-wide if that is what you want, or --skip-acl to finish the identities alone",
			out.OutOfPlan, egress, taggedNote)}
	}

	cx, cancel := ctx()
	live, _, err := readWhaleACL(cx, c)
	cancel()
	if err != nil {
		out.State = "refused"
		return out, &client.ProblemError{Status: 502, Title: "ACL not read", Detail: "the WhaleACL in force could not be " +
			"read (" + friendly(err) + "), and publishing over a document nobody has looked at is how an edit gets lost. " +
			"Nothing was published"}
	}

	rec, has := p.ReceiptFor(stepACL, aclSubject)
	switch {
	case has && rec.Result == whale.ResultApplied && rec.RolledBackAt == "":
		if live.Published && (live.Hash == rec.ACLHash || whale.SameACLDocument(live.Document, rec.ACLDocument)) {
			out.State, out.Hash, out.Replaced = "unchanged", live.Hash, rec.ACLReplaced
			if !whale.SameACLDocument(rec.ACLDocument, doc) {
				out.Detail = "this build would write a different document than the one this plan published; roll the " +
					"plan back and apply it again to change it"
			}
			return out, nil
		}
		out.State = "refused"
		return out, &client.ProblemError{Status: 409, Title: "ACL changed", Detail: fmt.Sprintf(
			"this plan published WhaleACL %s, and %s is in force now: it was edited or replaced since. Nothing was "+
				"written. Roll this plan back first, or edit the document with `whisper whale acl`",
			rec.ACLHash, orVal(live.Hash, "no document"))}

	case has && rec.Result == whale.ResultPending && rec.RolledBackAt == "":
		if live.Published && whale.SameACLDocument(live.Document, rec.ACLDocument) {
			// The earlier send landed and only its answer was lost. Adopt it, keeping the
			// pre-image that receipt recorded before the send.
			markACLReceipt(p, rec.Seq, func(r *whale.Receipt) {
				r.Result, r.ACLHash = whale.ResultApplied, live.Hash
				r.Detail = "reconciled: the earlier publish had landed and only its reply was lost"
			})
			out.State, out.Hash, out.Replaced = "reconciled", live.Hash, rec.ACLReplaced
			return out, whale.SavePlan(planPath, p)
		}
		if !preImageInForce(live, rec) {
			out.State = "refused"
			return out, &client.ProblemError{Status: 409, Title: "ACL changed", Detail: fmt.Sprintf(
				"an earlier apply sent a WhaleACL and never heard back, and what is in force now (%s) is neither that "+
					"document nor the one it was replacing (%s). Nothing was written; look at it with `whisper whale acl show`",
				orVal(live.Hash, "no document"), orVal(rec.ACLReplaced, "none"))}
		}
		// Neither landed: send again over the same pre-image, on the same receipt.
		return publishMigrationACL(c, p, planPath, rec.Seq, doc, rec.ACLReplaced, out)
	}

	// A fresh publish.
	prevHash, prevDoc := "", ""
	if live.Published {
		if !opt.replace {
			out.State = "refused"
			return out, &client.ProblemError{Status: 409, Title: "ACL in force", Detail: fmt.Sprintf(
				"a WhaleACL this plan did not write is already in force (%s, v%s). Nothing was published over it. Re-run "+
					"with --replace-acl to replace it (rollback puts it back), or --skip-acl to leave it as it is",
				live.Hash, live.Version)}
		}
		if live.SSH == "invalid_stored" {
			out.State = "refused"
			return out, &client.ProblemError{Status: 409, Title: "ACL cannot be restored", Detail: "the WhaleACL in force " +
				"(" + live.Hash + ") carries an ssh block stored before the ssh grammar existed, which no write accepts " +
				"today. Replacing it would make rollback impossible, so nothing was published. Fix its ssh block with " +
				"`whisper whale acl set` first"}
		}
		prevHash, prevDoc = live.Hash, live.Document
	}
	var undoACL any
	if prevDoc != "" {
		undoACL = prevDoc
	}
	pending := p.Record(whale.Receipt{
		Step: stepACL, Subject: aclSubject, Result: whale.ResultPending,
		ACLReplaced: prevHash, ACLDocument: doc,
		Detail: "sent; the reply has not been read yet",
		Undo: &whale.Undo{Op: "policy", Args: map[string]any{"whale": map[string]any{"acl": undoACL}},
			Note: "restore the WhaleACL this replaced, or withdraw it when there was none"},
	})
	if err := whale.SavePlan(planPath, p); err != nil {
		return out, err
	}
	return publishMigrationACL(c, p, planPath, pending.Seq, doc, prevHash, out)
}

// publishMigrationACL sends the document over base, retrying only the replication-lag
// refusal, and settles the pending receipt seq from the answer.
func publishMigrationACL(c *client.Client, p *whale.Plan, planPath string, seq int, doc, base string,
	out aclOutcome) (aclOutcome, error) {
	var err error
	var live whale.ACLSummary
	answered := false // the control plane replied with a verdict (ok:false), not a transport failure
	for attempt := 1; ; attempt++ {
		cx, cancel := ctx()
		var env *client.Envelope
		env, err = publishWhaleACL(cx, c, doc, base)
		cancel()
		answered = false
		if err == nil {
			err = envelopeError(env)
			answered = err != nil && env != nil && !env.Ok && env.Err != nil
		}
		if err == nil {
			live = whale.ACLSummaryFrom(policyPairs(env))
			break
		}
		if !isLagRefusal(err) || attempt >= aclLagAttempts {
			break
		}
		time.Sleep(aclLagDelay)
	}
	// The reply's read-back can already show a concurrent writer's document. Only a reply that holds OUR document, under a hash, confirms the write;
	// anything else is settled by one read, and failing that stays pending for the next run.
	if err == nil && (live.Hash == "" || !whale.SameACLDocument(live.Document, doc)) {
		cx, cancel := ctx()
		now, _, rerr := readWhaleACL(cx, c)
		cancel()
		if rerr == nil && now.Published && now.Hash != "" && whale.SameACLDocument(now.Document, doc) {
			live = now
		} else {
			err = fmt.Errorf("the control plane accepted the write but its reply did not show this document in force")
		}
	}
	var pe *client.ProblemError
	switch {
	case err == nil:
		markACLReceipt(p, seq, func(r *whale.Receipt) {
			r.Result, r.ACLHash, r.ACLDocument = whale.ResultApplied, live.Hash, doc
			r.Detail = "published"
		})
		out.State, out.Hash, out.Replaced = "published", live.Hash, base
	// A definite refusal is an answer that cannot follow a commit: a 4xx, or an ok:false
	// reply with a non-error status. A 5xx can arrive after the write has committed, so it
	// stays pending and the next run settles it by reading what is in force.
	case errors.As(err, &pe) && pe.Status < 500 && (answered || pe.Status >= 400):
		markACLReceipt(p, seq, func(r *whale.Receipt) {
			r.Result, r.Detail = whale.ResultRefused, friendly(err)
		})
		out.State, out.Detail = "refused", friendly(err)
		err = &client.ProblemError{Status: pe.Status, Title: "ACL refused", Detail: "the control plane refused the " +
			"WhaleACL, and nothing was published: " + friendly(err) + "\nRead the document it was given with " +
			"`whisper whale migrate apply --dry-run -f " + planPath + "`; re-running apply retries it"}
	default:
		// No answer: it may or may not have landed. The receipt stays pending, holding the
		// pre-image, and the next apply or rollback reads what is in force to decide.
		out.State, out.Detail = "pending", friendly(err)
		err = &client.ProblemError{Status: 502, Title: "ACL unconfirmed", Detail: "the WhaleACL was sent and no answer " +
			"came back (" + friendly(err) + "). Whether it landed is not known yet; re-run apply (or rollback) and it " +
			"reads what is in force and settles it"}
	}
	if serr := whale.SavePlan(planPath, p); serr != nil {
		return out, serr
	}
	return out, err
}

func isLagRefusal(err error) bool {
	var pe *client.ProblemError
	if !errors.As(err, &pe) || pe.Status != 400 {
		return false // only the control plane's own 400 is about its roster; a proxy page is not
	}
	msg := strings.ToLower(err.Error())
	for _, ph := range aclLagPhrases {
		if strings.Contains(msg, ph) {
			return true
		}
	}
	return false
}

func markACLReceipt(p *whale.Plan, seq int, f func(*whale.Receipt)) {
	for i := range p.Receipts {
		if p.Receipts[i].Seq == seq {
			f(&p.Receipts[i])
			p.Receipts[i].At = time.Now().UTC().Format(time.RFC3339)
		}
	}
}

// preImageInForce reports whether what is live is the state an ACL receipt replaced.
func preImageInForce(live whale.ACLSummary, r whale.Receipt) bool {
	if r.ACLReplaced == "" {
		return !live.Published
	}
	return live.Published && (live.Hash == r.ACLReplaced || whale.SameACLDocument(live.Document, undoDocument(r)))
}

// undoDocument is the document an ACL receipt's undo would restore, "" for a withdraw.
func undoDocument(r whale.Receipt) string {
	if r.Undo == nil {
		return ""
	}
	w, _ := r.Undo.Args["whale"].(map[string]any)
	s, _ := w["acl"].(string)
	return s
}

// checkPlannedTags refuses a node whose live tags are not exactly the plan's. A node
// adopted from before the migration carries whatever it was minted with; fewer tags would
// silently lose its grants, and more would hand it grants their tailnet never gave it.
//
// A tagged node registered seconds ago can be absent from the listing for a while (the
// control plane converges), so an ABSENT tagged node is re-read within the lag budget and,
// if it is still absent, reported as not yet visible rather than as wrong: telling someone
// to re-register a node that is fine would cost it its /128 and its name. It returns the
// live tags by canonical address, for the fleet-scope check.
func checkPlannedTags(c *client.Client, p *whale.Plan, addrs map[string]string) (map[string][]string, error) {
	var live map[string][]string
	var absent, drift []string
	for attempt := 1; ; attempt++ {
		var err error
		live, err = readWhaleTags(c)
		if err != nil {
			return nil, &client.ProblemError{Status: 502, Title: "tags not read", Detail: "your nodes' tags could not be " +
				"read (" + friendly(err) + "), so whether every node carries the tags its rules name cannot be checked. " +
				"Nothing was published"}
		}
		absent, drift = nil, nil
		for _, n := range p.Nodes {
			key := canonicalAddr(addrs[n.TailscaleID])
			if key == "" {
				continue
			}
			want := whale.NodeTags(n)
			have, listed := live[key]
			switch {
			case !listed && len(want) > 0:
				absent = append(absent, n.Label)
			case strings.Join(want, ",") != strings.Join(have, ","):
				drift = append(drift, fmt.Sprintf("%s: the plan says [%s], the node carries [%s]",
					n.Label, strings.Join(want, ","), strings.Join(have, ",")))
			}
		}
		if len(absent) == 0 || attempt >= aclLagAttempts {
			break
		}
		time.Sleep(aclLagDelay)
	}
	if len(drift) > 0 {
		return nil, &client.ProblemError{Status: 409, Title: "tags differ", Detail: "the rules name nodes by tag, and " +
			"these nodes do not carry exactly the tags the plan gives them, so the document would mean something other " +
			"than their policy. Nothing was published.\n  - " + strings.Join(drift, "\n  - ") + "\nA node that existed " +
			"before this migration keeps the tags it was minted with: re-register it, or remove it from the plan's tailnet"}
	}
	if len(absent) > 0 {
		return nil, &client.ProblemError{Status: 503, Title: "tags not visible yet", Detail: "these tagged nodes are " +
			"registered but their tags are not visible yet: " + strings.Join(absent, ", ") + ". Nothing was published, " +
			"and nothing is wrong with them; re-run apply in a minute and it continues from here"}
	}
	return live, nil
}

// readWhaleTags is op:list{kind:'whale'}, as tags by canonical address. A node registered
// with no whale settings has no row, which reads as no tags.
func readWhaleTags(c *client.Client) (map[string][]string, error) {
	cx, cancel := ctx()
	env, err := c.Agents(cx, "list", map[string]any{"kind": "whale"})
	cancel()
	if err == nil {
		err = envelopeError(env)
	}
	if err != nil {
		return nil, err
	}
	live := map[string][]string{}
	if env.Result != nil {
		for _, rec := range env.Result.Records() {
			item := rec
			if m, ok := rec["item"].(map[string]any); ok {
				item = m
			}
			row := whaleNodeRowFrom(item)
			key := canonicalAddr(row.Address)
			if key == "" {
				continue
			}
			var tags []string
			for _, t := range row.Tags {
				tags = append(tags, strings.ToLower(strings.TrimSpace(t)))
			}
			sort.Strings(tags)
			live[key] = tags
		}
	}
	return live, nil
}

// canonicalAddr is an address in one spelling, or "" when it is not one.
func canonicalAddr(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// renderACLOutcome prints the ACL half of the apply summary.
func renderACLOutcome(o aclOutcome, planPath string) {
	if o.State == "" || o.State == "skipped" {
		return
	}
	fmt.Fprintln(os.Stdout)
	rows := [][]string{{"state", o.State}}
	if o.Hash != "" {
		rows = append(rows, []string{"hash", o.Hash})
	}
	if o.State == "published" || o.State == "reconciled" {
		rows = append(rows, []string{"replaced", orVal(o.Replaced, "nothing (the first document)")})
	}
	if o.Grants > 0 {
		rows = append(rows, []string{"grants", fmt.Sprintf("%d", o.Grants)},
			[]string{"ssh rules", fmt.Sprintf("%d", o.SSHRules)},
			[]string{"tests run before it landed", fmt.Sprintf("%d", o.Tests)})
	}
	if o.OutOfPlan > 0 {
		rows = append(rows, []string{"agents outside this plan", fmt.Sprintf("%d (governed too)", o.OutOfPlan)})
	}
	if len(o.OutsideTagged) > 0 {
		rows = append(rows, []string{"outside agents carrying a plan tag", strings.Join(o.OutsideTagged, ", ")})
	}
	printTable([]string{"WHALE ACL", ""}, rows)
	for _, n := range o.Notes {
		whaleNote("%s", n)
	}
	if len(o.Adopted) > 0 {
		whaleNote("already registered before this migration, governed under the plan's name: %s", strings.Join(o.Adopted, ", "))
	}
	if len(o.Dropped) > 0 {
		whaleNote("%d thing(s) did not carry, each narrower than their policy rather than broader:", len(o.Dropped))
		for _, d := range o.Dropped {
			whaleNote("  - %s", d)
		}
	}
	if o.Detail != "" && o.State != "refused" {
		whaleNote("%s", o.Detail)
	}
	if o.State == "published" || o.State == "reconciled" || o.State == "unchanged" {
		whaleNote("ask it a question with `whisper whale acl test <src> <dst>`; `whisper whale migrate rollback -f %s` "+
			"undoes it first, then the identities", planPath)
	}
}

// --- rollback --------------------------------------------------------------------------

// rollbackACL undoes one ACL receipt. It lets the compare-and-set decide: the undo always
// names our hash as its base, so it can never overwrite somebody's later edit. It returns
// whether the receipt is now rolled back, and an error that names why not.
func rollbackACL(c *client.Client, p *whale.Plan, planPath string, r whale.Receipt) (bool, error) {
	cx, cancel := ctx()
	live, _, err := readWhaleACL(cx, c)
	cancel()
	if err != nil {
		return false, fmt.Errorf("the WhaleACL in force could not be read (%s)", friendly(err))
	}
	base := r.ACLHash
	if r.Result == whale.ResultPending {
		switch {
		case live.Published && whale.SameACLDocument(live.Document, r.ACLDocument):
			base = live.Hash // it landed; its reply was lost
		case preImageInForce(live, r):
			markACLReceipt(p, r.Seq, func(x *whale.Receipt) {
				x.RolledBackAt = time.Now().UTC().Format(time.RFC3339)
				x.Detail = "never landed: the document it would have replaced is still in force"
			})
			return true, nil
		default:
			return false, fmt.Errorf("an apply sent a WhaleACL and never heard back, and what is in force (%s) is "+
				"neither that document nor the one it replaced", orVal(live.Hash, "no document"))
		}
	}

	prev := undoDocument(r)
	if prev != "" && !live.Published {
		return false, fmt.Errorf("the WhaleACL was withdrawn since this plan published it, and restoring the one it "+
			"replaced (%s) over a deliberate withdraw is not this tool's call. Restore it by hand if you mean to", r.ACLReplaced)
	}
	cx, cancel = ctx()
	env, err := publishWhaleACL(cx, c, prev, base)
	cancel()
	if err == nil {
		err = envelopeError(env)
	}
	if err != nil {
		// A conflict can mean our undo already landed and its reply was lost: read and see.
		cx, cancel = ctx()
		now, _, rerr := readWhaleACL(cx, c)
		cancel()
		converged := rerr == nil && preImageInForce(now, r)
		if !converged {
			var pe *client.ProblemError
			if prev != "" && errors.As(err, &pe) && pe.Status == 400 {
				return false, restoreRefused(planPath, prev, base, err)
			}
			return false, fmt.Errorf("the undo was refused (%s)", friendly(err))
		}
	}
	markACLReceipt(p, r.Seq, func(x *whale.Receipt) {
		x.RolledBackAt = time.Now().UTC().Format(time.RFC3339)
		x.Detail = "rolled back: " + map[bool]string{true: "the document it replaced is back in force",
			false: "the WhaleACL was withdrawn"}[prev != ""]
	})
	return true, nil
}

// restoreRefused is the one rollback failure that needs a person: the control plane will not
// take the previous document back (it re-runs today's checks against today's roster). The
// document is saved where they can read it, and the explicit fallback is named.
func restoreRefused(planPath, prev, ours string, cause error) error {
	path := planPath + ".acl-restore.json"
	saved := "it was saved to " + path
	if err := secfile.WriteFile(path, []byte(prev+"\n")); err != nil {
		saved = "and it could not be saved (" + err.Error() + "); `whisper whale acl show --raw` will not have it either"
	}
	return fmt.Errorf("the control plane refused to restore the WhaleACL this plan replaced (%s); %s. Edit it and "+
		"publish it with `whisper whale acl set %s --base %s`, or withdraw ours with `whisper whale acl withdraw --base %s`",
		friendly(cause), saved, path, ours, ours)
}

// aclStatus is `status`'s line for the ACL step.
func aclStatus(p *whale.Plan, live whale.ACLSummary, readErr error) (state, detail string) {
	rec, has := p.ReceiptFor(stepACL, aclSubject)
	switch {
	case readErr != nil:
		return "unread", "the WhaleACL in force could not be read (" + friendly(readErr) + ")"
	case !has || rec.RolledBackAt != "":
		if live.Published {
			return "not applied", "a WhaleACL this plan did not write is in force (" + live.Hash + ")"
		}
		return "not applied", ""
	case rec.Result == whale.ResultRefused:
		return "refused", rec.Detail
	case rec.Result == whale.ResultPending:
		return "pending", "sent and never confirmed; the next apply or rollback settles it"
	case !live.Published:
		return "withdrawn", "this plan published " + rec.ACLHash + " and nothing is in force now"
	case live.Hash == rec.ACLHash || whale.SameACLDocument(live.Document, rec.ACLDocument):
		return "live", live.Hash
	default:
		return "drifted", "this plan published " + rec.ACLHash + " and " + live.Hash + " is in force now"
	}
}
