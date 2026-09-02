// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_migrate.go is `whisper whale migrate`: turning an existing Tailscale fleet into
// ours without anybody losing a rule on the way.
//
// The shape is the one every serious migration tool has, and for the same reason: a DRY
// RUN that produces a reviewable artifact, then an apply that consumes it.
//
//	plan read their tailnet, write a plan file. Read-only on BOTH sides.
//	apply write the plan into Whisper. Idempotent and resumable.
//	status drift: the plan against what is live
//	collect node-side, capture the serve/funnel state their API does not expose
//	rollback undo, in reverse receipt order
//
// Three properties are worth naming because they are what makes this trustworthy.
//
// It cannot change their tailnet. The reader has no write method (whale/tsapi.go), so
// "changes nothing on either side" is a property of the type rather than a promise in a
// help string.
//
// It cannot widen a rule quietly. Their rule is a triple (src, dst, port); what our
// compiled ACL cannot hold is reported as APPROX-WIDENING with the plane it widens on, and
// `apply` REFUSES until the operator passes --accept-widening, which is then recorded in
// the plan file so the consent is auditable afterwards.
//
// It cannot leak their credential. It is read from the environment, never from a flag (a
// flag lands in shell history and in ps output), it is never written to the plan, and the
// only trace of it anywhere is the first 12 hex of its SHA-256.

// migratePlanDefault is the file everything defaults to, so the common case needs no flag.
const migratePlanDefault = "whalenet.plan.json"

// migrateCollectDefault is where `collect` writes on a node.
const migrateCollectDefault = "whalenet.collect.json"

// The receipt step names. Closed vocabulary: rollback dispatches on these.
const (
	stepIdentity = "identity"
	stepACL      = "acl"
)

func newWhaleMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Move a Tailscale tailnet onto Whalenet, plan first",
		Long: "whisper whale migrate - convert an existing Tailscale fleet into a Whisper one.\n\n" +
			"  plan       read their tailnet and write a plan file. Changes NOTHING, on either side\n" +
			"  apply      write that plan into Whisper. Idempotent and resumable\n" +
			"  status     drift: what the plan says against what is live\n" +
			"  collect    run ON a node to capture the serve/funnel state their API cannot expose\n" +
			"  rollback   undo an apply, in reverse receipt order\n\n" +
			"Read the plan before you apply it. It enumerates every write in the order it will\n" +
			"happen, and it names what mapped exactly, what mapped approximately, what mapped to\n" +
			"something STRICTLY BROADER than their rule, and what cannot map at all. A rule that\n" +
			"would widen is refused until you pass --accept-widening, and that consent is written\n" +
			"into the plan file so it can be audited later.\n\n" +
			"The Tailscale credential is read from the environment, never from a flag:\n" +
			"  TS_API_KEY                                  a personal API access token, or\n" +
			"  TS_OAUTH_CLIENT_ID + TS_OAUTH_CLIENT_SECRET a read-only OAuth client (preferred)\n" +
			"It is never written to the plan, never logged and never echoed. The plan records\n" +
			"only the first 12 hex of its SHA-256, so apply can refuse a plan made with a\n" +
			"different credential.",
		Args: cobraNoArgs,
	}
	cmd.AddCommand(
		newWhaleMigratePlanCmd(),
		newWhaleMigrateApplyCmd(),
		newWhaleMigrateStatusCmd(),
		newWhaleMigrateCollectCmd(),
		newWhaleMigrateRollbackCmd(),
	)
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

// --- the credential ------------------------------------------------------------------

// tailscaleCredentialFromEnv reads the credential from the environment and from nowhere
// else. Postel at the boundary: it accepts both the OAuth pair and a personal token, under
// both the spellings people actually have in their shells, and when someone hands it a
// NODE auth key it says which key this is and which one it needs rather than letting the
// API return a 401 that explains nothing.
func tailscaleCredentialFromEnv() (whale.Credential, error) {
	id := firstNonBlank(os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TAILSCALE_OAUTH_CLIENT_ID"))
	secret := firstNonBlank(os.Getenv("TS_OAUTH_CLIENT_SECRET"), os.Getenv("TAILSCALE_OAUTH_CLIENT_SECRET"))
	if secret != "" {
		if id == "" {
			return whale.Credential{}, usageErr("TS_OAUTH_CLIENT_SECRET is set but TS_OAUTH_CLIENT_ID is not: " +
				"an OAuth client needs both halves")
		}
		return whale.NewOAuthCredential(id, secret), nil
	}
	key := firstNonBlank(os.Getenv("TS_API_KEY"), os.Getenv("TAILSCALE_API_KEY"), os.Getenv("TAILSCALE_APIKEY"))
	if key == "" {
		return whale.Credential{}, usageErr("no Tailscale credential in the environment.\n" +
			"  Read-only OAuth client (preferred):\n" +
			"    export TS_OAUTH_CLIENT_ID=... TS_OAUTH_CLIENT_SECRET=...\n" +
			"  or a personal API access token:\n" +
			"    export TS_API_KEY=...\n" +
			"Both are read from the environment on purpose: a secret passed as a flag lands in " +
			"your shell history and in every ps listing on the box.")
	}
	if whale.LooksLikeTailscaleAuthKey(key) {
		return whale.Credential{}, usageErr("that is a Tailscale NODE auth key, not an API credential. " +
			"A node auth key enrols a machine; reading a tailnet needs an API access token (tskey-api-...) or a " +
			"read-only OAuth client (TS_OAUTH_CLIENT_ID + TS_OAUTH_CLIENT_SECRET).")
	}
	return whale.NewAPIKeyCredential(key), nil
}

// --- plan ------------------------------------------------------------------------------

func newWhaleMigratePlanCmd() *cobra.Command {
	var tailnet, out, apiBase string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Read a tailnet and write a plan. Changes nothing, on either side",
		Long: "Read a Tailscale tailnet with a read-only credential and write a plan file.\n\n" +
			"This command performs GETs and nothing else. The API client behind it has no write\n" +
			"method at all, so \"changes nothing on either side\" is structural rather than a\n" +
			"promise: re-read both sides afterwards and they are byte-identical.\n\n" +
			"Four things are unreadable and the plan says so before it starts rather than\n" +
			"halfway through: auth-key secrets (their schema populates `key` only at creation),\n" +
			"node private keys, IdP/SCIM-synced group membership, and per-node serve/funnel\n" +
			"config (there is no /device/{id}/serve path in their schema at all).",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, err := tailscaleCredentialFromEnv()
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			reader := whale.NewHTTPReader(cred, apiBase, g.timeout)
			tn, err := whale.ReadTailnet(cx, reader, tailnet)
			if err != nil {
				return &client.ProblemError{Status: 502, Title: "tailnet not read", Detail: whale.Scrub(err.Error())}
			}
			p, err := whale.BuildPlan(tn, whale.BuildOptions{
				CredentialFingerprint: cred.Fingerprint(),
			})
			if err != nil {
				return &client.ProblemError{Status: 422, Title: "no plan", Detail: whale.Scrub(err.Error())}
			}
			if err := whale.SavePlan(out, p); err != nil {
				return err
			}
			if g.jsonOut {
				emitJSONValue(p)
				return nil
			}
			renderMigratePlan(p, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&tailnet, "tailnet", "-", "the tailnet to read (default \"-\": the one the credential belongs to)")
	cmd.Flags().StringVarP(&out, "out", "o", migratePlanDefault, "where to write the plan")
	cmd.Flags().StringVar(&apiBase, "api-base", "", "the Tailscale API root (default https://api.tailscale.com/api/v2)")
	return cmd
}

// renderMigratePlan prints the read/map/plan report, in the order a
// person reads it: what we read, what we could not read, what it maps to, and the one
// sentence that says nothing has changed.
func renderMigratePlan(p *whale.Plan, path string) {
	fmt.Fprintf(os.Stdout, "read  tailnet %s   %d nodes, %d users, %d auth keys, policy %d lines\n",
		p.Tailnet, p.Source.Nodes, p.Source.Users, p.Source.AuthKeys, p.Source.PolicyLines)

	counts := map[string]map[whale.FidelityClass]int{}
	order := []string{}
	for _, f := range p.Fidelity {
		if _, ok := counts[f.Kind]; !ok {
			counts[f.Kind] = map[whale.FidelityClass]int{}
			order = append(order, f.Kind)
		}
		counts[f.Kind][f.Class]++
	}
	sort.Strings(order)
	for _, kind := range order {
		var parts []string
		for _, cl := range []whale.FidelityClass{whale.ClassExact, whale.ClassApprox, whale.ClassWidening, whale.ClassUnmapped} {
			if n := counts[kind][cl]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, cl))
			}
		}
		fmt.Fprintf(os.Stdout, "map   %-16s %s\n", kind, strings.Join(parts, ", "))
	}
	fmt.Fprintf(os.Stdout, "plan  written %s  sha256 %s  NOTHING HAS BEEN CHANGED\n",
		path, shortHash(p.Hash))
	fmt.Fprintln(os.Stdout)

	whaleNote("unreadable, and it is unreadable for everyone including them:")
	for _, u := range p.Unreadable {
		whaleNote("  - %s", u)
	}
	if n := p.WideningRules(); n > 0 {
		whaleNote("%d rule(s) map to something STRICTLY BROADER than what they wrote. `apply` refuses "+
			"until you pass --accept-widening. Read them first:", n)
		whaleNote("  jq '.fidelity[] | select(.class==\"APPROX-WIDENING\")' %s", path)
	}
	whaleNote("what does not carry over at all:  jq '.fidelity[] | select(.class==\"UNMAPPED\")' %s", path)
	whaleNote("then:  whisper whale migrate apply -f %s", path)
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// --- apply -------------------------------------------------------------------------------

func newWhaleMigrateApplyCmd() *cobra.Command {
	var planPath, keysOut string
	var acceptWidening, dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Write the plan into Whisper. Idempotent and resumable",
		Long: "Apply a plan written by `whisper whale migrate plan`.\n\n" +
			"Idempotent: every step is checked against what is already live before it runs, so a\n" +
			"second apply mints no second identity. Resumable: each step's receipt is written back\n" +
			"into the plan file as it happens, so an interrupted run continues where it stopped and\n" +
			"`rollback` can undo exactly what was done, in reverse.\n\n" +
			"If any rule maps to something strictly broader than their rule, apply REFUSES until\n" +
			"you pass --accept-widening. That consent is recorded in the plan file.\n\n" +
			"Nodes are allocated and named UP FRONT, before any node joins, because a node's\n" +
			"canonical name is a pure function of its address and the address is drawn at random\n" +
			"inside your /64: a node that joins first and is named afterwards has already published\n" +
			"a random name.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := whale.LoadPlan(planPath)
			if err != nil {
				return err
			}
			if err := p.VerifyHash(); err != nil {
				return &client.ProblemError{Status: 409, Title: "plan edited", Detail: err.Error()}
			}
			if err := checkPlanCredential(p); err != nil {
				return err
			}
			if p.HasWidening() && !acceptWidening && !p.AcceptedWidening {
				return wideningRefusal(p, planPath)
			}
			if acceptWidening && !p.AcceptedWidening {
				p.AcceptedWidening = true
				p.AcceptedWideningAt = time.Now().UTC().Format(time.RFC3339)
			}
			if dryRun {
				renderApplyDryRun(p)
				return nil
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			return runMigrateApply(c, p, planPath, keysOut)
		},
	}
	cmd.Flags().StringVarP(&planPath, "file", "f", migratePlanDefault, "the plan to apply")
	cmd.Flags().BoolVar(&acceptWidening, "accept-widening", false,
		"accept the rules that map to something strictly broader than the source rule (recorded in the plan file)")
	cmd.Flags().StringVar(&keysOut, "keys-out", "",
		"write each new agent's API key to this file, readable only by you (default: the key is not retained anywhere)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the writes this apply would make, and make none")
	return cmd
}

// checkPlanCredential refuses a plan produced by a different Tailscale credential, when
// one is present to compare against. A credential that is absent is not a mismatch: apply
// talks to Whisper, not to them, and demanding their credential to write ours would be
// resistance with no safety behind it.
func checkPlanCredential(p *whale.Plan) error {
	cred, err := tailscaleCredentialFromEnv()
	if err != nil || cred.IsZero() {
		return nil
	}
	if p.CredentialFingerprint == "" || cred.Fingerprint() == p.CredentialFingerprint {
		return nil
	}
	return &client.ProblemError{Status: 409, Title: "wrong credential", Detail: fmt.Sprintf(
		"this plan was made with the Tailscale credential sha256:%s and your environment holds sha256:%s. "+
			"Applying a plan built from a different tailnet than the one you are looking at is how a fleet gets "+
			"half migrated. Re-run `whisper whale migrate plan`, or unset the Tailscale variables to apply this "+
			"plan as it stands", p.CredentialFingerprint, cred.Fingerprint())}
}

// wideningRefusal is the refusal itself: it names every rule that widens and on which
// plane, because "refused, pass a flag" without the list would just train people to pass
// the flag.
func wideningRefusal(p *whale.Plan, path string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%d rule(s) in this plan map to something STRICTLY BROADER than the rule they came from:\n",
		p.WideningRules())
	shown := 0
	for _, r := range p.Rules {
		if !r.Widening {
			continue
		}
		if shown == 5 {
			fmt.Fprintf(&b, "  ... and %d more; read them all with:\n    jq '.fidelity[] | select(.class==\"APPROX-WIDENING\")' %s\n",
				p.WideningRules()-shown, path)
			break
		}
		fmt.Fprintf(&b, "  [%s] %s -> %s : %s\n", r.Plane, strings.Join(r.Src, ","), r.Dst, r.Note)
		shown++
	}
	b.WriteString("Nothing has been written. If that widening is acceptable, re-run with --accept-widening " +
		"and the consent is recorded in the plan file.")
	return &client.ProblemError{Status: 409, Title: "would widen", Detail: b.String()}
}

func renderApplyDryRun(p *whale.Plan) {
	rows := [][]string{}
	for _, n := range p.Nodes {
		state := "op:register"
		if rec, ok := p.ReceiptFor(stepIdentity, n.TailscaleID); ok && rec.Applied() {
			state = "already done (" + rec.Result + ")"
		}
		rows = append(rows, []string{n.Label, n.Hostname, state})
	}
	printTable([]string{"LABEL", "THEIR NODE", "WOULD DO"}, rows)
	whaleNote("%d identity write(s). Nothing was written: this was --dry-run.", len(p.Nodes))
}

// runMigrateApply walks the plan in order, verifying each step against what is live before
// it writes, and saving the plan after every receipt so an interrupted run is resumable.
func runMigrateApply(c *client.Client, p *whale.Plan, planPath, keysOut string) error {
	applied, existing, refused := 0, 0, 0

	// The fleet is read ONCE, before anything is written, and a read that FAILS stops the
	// run. Idempotency here is "does this agent already exist", and answering that from a
	// failed read would answer "no" for every node and mint a duplicate identity for each
	// of them. An unread fleet and an empty fleet are different facts.
	cx, cancel := ctx()
	peers, perr := whaleFleet(cx, c)
	cancel()
	if perr != nil {
		return &client.ProblemError{Status: 502, Title: "fleet not read", Detail: fmt.Sprintf(
			"your identities could not be read (%s). Applying without knowing what already exists would mint a "+
				"duplicate /128 for every node in this plan, so nothing has been written", friendly(perr))}
	}

	for _, n := range p.Nodes {
		if rec, ok := p.ReceiptFor(stepIdentity, n.TailscaleID); ok && rec.Applied() {
			existing++
			continue
		}
		// Already registered under this name: record it and mint nothing. This is the
		// same question `whisper create --register --reuse` asks, answered from the
		// one fleet read above rather than from a fresh read per node.
		if peer, found := matchPeer(peers, n.Label); found {
			p.Record(whale.Receipt{
				Step: stepIdentity, Subject: n.TailscaleID, Result: whale.ResultExisting,
				Agent: peer.Name, Address: peer.Address, FQDN: peer.FQDN,
				Detail: "an agent was already registered under this name; no second identity was minted",
				// No Undo, deliberately: this migration did not create it, so rolling this
				// plan back must not revoke somebody's existing identity.
			})
			existing++
			if err := whale.SavePlan(planPath, p); err != nil {
				return err
			}
			continue
		}

		rcx, rcancel := ctx()
		env, err := c.Agents(rcx, "register", map[string]any{"label": n.Label})
		rcancel()
		if err != nil {
			p.Record(whale.Receipt{Step: stepIdentity, Subject: n.TailscaleID, Result: whale.ResultRefused,
				Detail: friendly(err)})
			refused++
			if serr := whale.SavePlan(planPath, p); serr != nil {
				return serr
			}
			// One refusal is not a reason to abandon 83 other nodes: keep going, and the
			// summary and `status` both carry the count.
			continue
		}
		if perr := envelopeError(env); perr != nil {
			p.Record(whale.Receipt{Step: stepIdentity, Subject: n.TailscaleID, Result: whale.ResultRefused,
				Detail: friendly(perr)})
			refused++
			if serr := whale.SavePlan(planPath, p); serr != nil {
				return serr
			}
			continue
		}
		rec := receiptFromEnvelope(env, stepIdentity, n.TailscaleID, whale.ResultApplied)
		p.Record(rec)
		applied++
		if err := writeMintedKey(keysOut, n.Label, env); err != nil {
			return err
		}
		if err := whale.SavePlan(planPath, p); err != nil {
			return err
		}
	}

	if g.jsonOut {
		emitJSONValue(map[string]any{
			"plan": planPath, "applied": applied, "existing": existing, "refused": refused,
			"receipts": p.Receipts,
		})
		return nil
	}
	rows := [][]string{
		{"minted", fmt.Sprintf("%d", applied)},
		{"already there", fmt.Sprintf("%d", existing)},
		{"refused", fmt.Sprintf("%d", refused)},
	}
	printTable([]string{"APPLY", ""}, rows)
	if keysOut != "" && applied > 0 {
		whaleNote("each new agent's API key was written to %s, readable only by you. It is shown once and stored nowhere else.", keysOut)
	} else if applied > 0 {
		whaleNote("the per-agent API keys were NOT retained. Pass --keys-out <file> on a fresh run if a node needs its own key.")
	}
	whaleNote("receipts are in %s. `whisper whale migrate status -f %s` shows drift; "+
		"`... rollback -f %s` undoes this in reverse.", planPath, planPath, planPath)
	if refused > 0 {
		return &client.ProblemError{Status: 207, Title: "partly applied", Detail: fmt.Sprintf(
			"%d of %d identity writes were refused by the control plane. They are recorded in %s with the reason; "+
				"re-running apply retries exactly those", refused, len(p.Nodes), planPath)}
	}
	return nil
}

// receiptFromEnvelope lifts the identity fields out of a control-plane envelope, and
// records an undo ONLY for a step this run actually performed. It never touches api_key: a
// secret does not go into the plan file.
func receiptFromEnvelope(env *client.Envelope, step, subject, result string) whale.Receipt {
	rec := whale.Receipt{Step: step, Subject: subject, Result: result}
	if env == nil || env.Result == nil {
		return rec
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return rec
	}
	item := recs[0]
	if m, ok := item["item"].(map[string]any); ok {
		item = m
	}
	rec.Agent = field(item, "agent", "id")
	rec.Address = field(item, "address", "addr128")
	rec.FQDN = trimDot(field(item, "fqdn"))
	if rec.Agent != "" && result == whale.ResultApplied {
		rec.Undo = &whale.Undo{Op: "revoke", Args: map[string]any{"agent": rec.Agent},
			Note: "withdraw this identity: its /128, its PTR and its egress tokens"}
	}
	return rec
}

// writeMintedKey appends one agent's freshly minted API key to the --keys-out file, and
// does nothing at all when the operator did not ask for one. Not asking is the default
// because a file of 84 live credentials is a liability, and the node-side join that would
// consume them is a separate piece of work.
func writeMintedKey(path, label string, env *client.Envelope) error {
	if strings.TrimSpace(path) == "" || env == nil || env.Result == nil {
		return nil
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return nil
	}
	key := field(recs[0], "api_key")
	if key == "" {
		return nil
	}
	// secfile, not a 0o600 mode argument: this is the ONLY place a minted API key
	// is retained, and on Windows the mode argument would have left the file with
	// whatever DACL its directory grants. secfile hardens the file before
	// the first key is appended to it.
	f, err := secfile.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("opening %s for the minted key: %w", path, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\t%s\n", label, key); err != nil {
		return fmt.Errorf("writing the minted key for %s: %w", label, err)
	}
	return nil
}

// --- status --------------------------------------------------------------------------

func newWhaleMigrateStatusCmd() *cobra.Command {
	var planPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Drift: what the plan says against what is live",
		Long: "Compare a plan against what is actually live in your account.\n\n" +
			"It re-verifies the plan's own hash first, so a plan edited under a half-finished\n" +
			"apply is caught rather than trusted, and then reads your identities back and reports\n" +
			"each planned node as live, missing or not yet applied.\n\n" +
			"A read that FAILS is reported as a failure, never as an empty fleet.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := whale.LoadPlan(planPath)
			if err != nil {
				return err
			}
			hashErr := p.VerifyHash()
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			peers, perr := whaleFleet(cx, c)
			if perr != nil {
				// The control: a fleet we could not read is NOT a fleet of zero nodes, and
				// reporting it as "84 missing" would send someone to re-apply a finished
				// migration.
				return &client.ProblemError{Status: 502, Title: "fleet not read", Detail: fmt.Sprintf(
					"your identities could not be read (%s), so this command cannot tell a missing node from an "+
						"unread one and will not guess", friendly(perr))}
			}
			view := migrateStatusView(p, peers, hashErr)
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			renderMigrateStatus(view, planPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&planPath, "file", "f", migratePlanDefault, "the plan to compare")
	return cmd
}

// migrateStatusRow is one planned node against reality.
type migrateStatusRow struct {
	Label   string `json:"label"`
	Their   string `json:"their_node"`
	State   string `json:"state"`
	Address string `json:"address,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type migrateStatusReport struct {
	Plan     string             `json:"plan_hash"`
	PlanNote string             `json:"plan_note,omitempty"`
	Rows     []migrateStatusRow `json:"nodes"`
	Counts   map[string]int     `json:"counts"`
	Widening int                `json:"widening_rules"`
	Accepted bool               `json:"widening_accepted"`
}

// migrateStatusView is pure, so the drift logic is testable with no client at all.
func migrateStatusView(p *whale.Plan, peers []whalePeer, hashErr error) migrateStatusReport {
	rep := migrateStatusReport{
		Plan: shortHash(p.Hash), Counts: map[string]int{},
		Widening: p.WideningRules(), Accepted: p.AcceptedWidening,
	}
	if hashErr != nil {
		rep.PlanNote = hashErr.Error()
	}
	for _, n := range p.Nodes {
		row := migrateStatusRow{Label: n.Label, Their: n.Hostname}
		rec, hasReceipt := p.ReceiptFor(stepIdentity, n.TailscaleID)
		peer, live := matchPeer(peers, n.Label)
		switch {
		case live:
			row.State = "live"
			row.Address = peer.Address
			if hasReceipt && rec.Address != "" && peer.Address != rec.Address {
				row.State = "drifted"
				row.Detail = "the live address " + peer.Address + " is not the one this plan recorded (" + rec.Address + ")"
			}
		case hasReceipt && rec.Applied():
			row.State = "missing"
			row.Address = rec.Address
			row.Detail = "this plan applied it, and it is not in your fleet now"
		case hasReceipt && rec.Result == whale.ResultRefused:
			row.State = "refused"
			row.Detail = rec.Detail
		default:
			row.State = "pending"
		}
		rep.Counts[row.State]++
		rep.Rows = append(rep.Rows, row)
	}
	return rep
}

func renderMigrateStatus(rep migrateStatusReport, path string) {
	rows := make([][]string, 0, len(rep.Rows))
	for _, r := range rep.Rows {
		rows = append(rows, []string{r.Label, r.Their, r.State, firstNonBlank(r.Address, "-")})
	}
	printTable([]string{"LABEL", "THEIR NODE", "STATE", "ADDRESS"}, rows)
	fmt.Fprintln(os.Stdout)
	var parts []string
	for _, k := range []string{"live", "pending", "missing", "drifted", "refused"} {
		if n := rep.Counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	whaleNote("plan %s: %s", rep.Plan, strings.Join(parts, ", "))
	if rep.PlanNote != "" {
		whaleNote("WARNING: %s", rep.PlanNote)
	}
	if rep.Widening > 0 {
		state := "NOT accepted"
		if rep.Accepted {
			state = "accepted, and recorded in the plan"
		}
		whaleNote("%d widening rule(s), %s", rep.Widening, state)
	}
	for _, r := range rep.Rows {
		if r.Detail != "" {
			whaleNote("%s: %s", r.Label, r.Detail)
		}
	}
	_ = path
}

// --- collect -------------------------------------------------------------------------

func newWhaleMigrateCollectCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Run ON a node: capture the serve/funnel state their API cannot expose",
		Long: "Capture the local Tailscale state that no API read can reach.\n\n" +
			"There is no /device/{id}/serve path in their API schema at all: serve and funnel\n" +
			"configuration is local tailscaled state. So this command runs ON the node, reads it\n" +
			"with the local `tailscale` binary, and writes it beside the plan.\n\n" +
			"It is read-only: `tailscale serve status` and `tailscale funnel status`, both with\n" +
			"--json, and nothing else.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res := whale.CollectLocal(collectRunner)
			if err := whale.SaveCollected(out, res); err != nil {
				return err
			}
			if g.jsonOut {
				emitJSONValue(res)
				return nil
			}
			rows := [][]string{
				{"host", res.Host},
				{"tailscale", firstNonBlank(res.TailscaleVersion, "not found")},
				{"serve", res.ServeState},
				{"funnel", res.FunnelState},
			}
			printTable([]string{"COLLECTED", ""}, rows)
			whaleNote("written to %s. Run this on every node that serves anything: it is the only way to "+
				"read that configuration at all.", out)
			for _, note := range res.Notes {
				whaleNote("%s", note)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", migrateCollectDefault, "where to write what was collected")
	return cmd
}

// collectRunner is a package var so the collect tests run with no tailscale binary and no
// assumptions about the host they run on.
var collectRunner whale.CommandRunner = whale.ExecRunner

// --- rollback ------------------------------------------------------------------------

func newWhaleMigrateRollbackCmd() *cobra.Command {
	var planPath string
	var yes bool
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Undo an apply, in reverse receipt order",
		Long: "Undo what `apply` did, walking the receipts backwards.\n\n" +
			"Only steps this plan actually applied are undone, and each one is marked as rolled\n" +
			"back in the plan file as it happens, so an interrupted rollback resumes correctly and\n" +
			"never undoes the same thing twice.\n\n" +
			"This revokes identities. It is not reversible by re-running apply: a re-applied node\n" +
			"gets a NEW random /128 and therefore a new canonical name.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := whale.LoadPlan(planPath)
			if err != nil {
				return err
			}
			var undoable []whale.Receipt
			for _, r := range p.Receipts {
				if r.Applied() && r.Undo != nil {
					undoable = append(undoable, r)
				}
			}
			if len(undoable) == 0 {
				whaleNote("nothing to roll back: this plan has no applied step with an undo recorded.")
				return nil
			}
			if !yes && isInteractive() {
				fmt.Fprintf(os.Stderr, "whisper: this revokes %d identity/identities recorded in %s. "+
					"A re-applied node gets a NEW address and a new name. Re-run with --yes to proceed.\n",
					len(undoable), planPath)
				return &client.ProblemError{Status: 400, Title: "not confirmed",
					Detail: "rollback needs --yes, because revoking an identity cannot be undone by re-applying"}
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			return runMigrateRollback(c, p, planPath, undoable)
		},
	}
	cmd.Flags().StringVarP(&planPath, "file", "f", migratePlanDefault, "the plan to roll back")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func runMigrateRollback(c *client.Client, p *whale.Plan, planPath string, undoable []whale.Receipt) error {
	// Reverse receipt order: the last thing done is the first thing undone.
	sort.Slice(undoable, func(i, j int) bool { return undoable[i].Seq > undoable[j].Seq })
	done, failed := 0, 0
	for _, r := range undoable {
		cx, cancel := ctx()
		env, err := c.Agents(cx, r.Undo.Op, r.Undo.Args)
		cancel()
		if err == nil {
			err = envelopeError(env)
		}
		for i := range p.Receipts {
			if p.Receipts[i].Seq != r.Seq {
				continue
			}
			if err != nil {
				p.Receipts[i].Detail = "rollback failed: " + friendly(err)
				failed++
			} else {
				p.Receipts[i].RolledBackAt = time.Now().UTC().Format(time.RFC3339)
				done++
			}
		}
		if serr := whale.SavePlan(planPath, p); serr != nil {
			return serr
		}
	}
	if g.jsonOut {
		emitJSONValue(map[string]any{"rolled_back": done, "failed": failed, "plan": planPath})
		return nil
	}
	printTable([]string{"ROLLBACK", ""}, [][]string{
		{"rolled back", fmt.Sprintf("%d", done)},
		{"failed", fmt.Sprintf("%d", failed)},
	})
	if failed > 0 {
		return &client.ProblemError{Status: 207, Title: "partly rolled back", Detail: fmt.Sprintf(
			"%d step(s) could not be undone; each carries the reason in %s and re-running retries exactly those",
			failed, planPath)}
	}
	return nil
}
