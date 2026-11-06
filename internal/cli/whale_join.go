// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_join.go is the client half of a Whalenet fleet's join lifecycle.
//
// The control plane already carries the whole lifecycle on four ops: a node's join key is
// minted by op:register (tags, single use, ephemeral, pre-approval all ride its `whale`
// sub-map), approval is op:firewall, the tenant's join rule is op:policy, and the fleet's
// join state reads back from op:list{kind:'whale'}. Minting stays on `whisper create
// --register`, the one mint verb, and these four verbs govern what it minted:
//
//	whisper whale nodes [--pending]          who has joined, and what each join key allows
//	whisper whale approve <node>             admit a pending node to its fleet's east-west
//	whisper whale deny <node>                hold a node out of east-west again
//	whisper whale approval [auto|manual]     the fleet's join rule
//
// Approval gates east-west and nothing else. A held node keeps its /128, its DNS, its
// resolver and its internet egress; what it does not get is reachability to and from its
// siblings. Every receipt printed here is the server's own row, never a client-side guess.

// whaleIntentVersion is the whale-intent contract this client speaks. Every write pins
// it, so a box on another version refuses in terms instead of half-applying a security
// intent during a rolling upgrade.
const whaleIntentVersion = 1

// whaleNodeRow is one node of `op:list{kind:'whale'}`, as the server derives it.
type whaleNodeRow struct {
	Agent      string
	Address    string
	Tags       []string
	Reusable   bool
	Ephemeral  bool
	Approved   bool
	EastWest   string
	ApprovedBy string
	Connects   string
	Created    int64
}

func whaleNodeRowFrom(item map[string]any) whaleNodeRow {
	r := whaleNodeRow{
		Agent:      field(item, "agent"),
		Address:    field(item, "address"),
		Reusable:   boolCell(item["reusable"], true),
		Ephemeral:  boolCell(item["ephemeral"], false),
		Approved:   boolCell(item["approved"], true),
		EastWest:   field(item, "east_west"),
		ApprovedBy: field(item, "approved_by", "approvedBy"),
		Connects:   orVal(cellString(item["connects"]), "0"),
		Created:    parseEpoch(field(item, "created_at", "createdAt")),
	}
	switch t := item["tags"].(type) {
	case []any:
		for _, v := range t {
			if s := strings.TrimSpace(cellString(v)); s != "" {
				r.Tags = append(r.Tags, s)
			}
		}
	case string:
		for _, s := range strings.Split(strings.Trim(t, "[]"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				r.Tags = append(r.Tags, s)
			}
		}
	}
	if r.EastWest == "" {
		r.EastWest = "admitted"
		if !r.Approved {
			r.EastWest = "pending_approval"
		}
	}
	return r
}

// boolCell reads a JSON boolean liberally (a string "true"/"false" from an older writer
// too), falling back to def when the cell is absent or unreadable. The defaults are the
// server's own: a missing reusable means reusable and a missing approved means admitted.
func boolCell(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true":
			return true
		case "false":
			return false
		}
	}
	return def
}

func (r whaleNodeRow) use() string {
	if r.Reusable {
		return "reusable"
	}
	return "single-use"
}

func (r whaleNodeRow) tagCell() string {
	if len(r.Tags) == 0 {
		return "-"
	}
	return strings.Join(r.Tags, ",")
}

// --- nodes --------------------------------------------------------------------------

func newWhaleNodesCmd() *cobra.Command {
	var pending bool
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "Who has joined your fleet, and what each join key allows",
		Long: "List the nodes of your fleet that joined with Whalenet join settings: their tags,\n" +
			"whether their key was single-use or reusable, whether they are ephemeral (released\n" +
			"automatically once they hold no connection for 15 minutes), and whether they are\n" +
			"admitted to east-west or pending approval.\n\n" +
			"A node minted with no join settings writes no join record and is not listed here;\n" +
			"`whisper list` shows every agent. --pending shows only the nodes waiting for\n" +
			"`whisper whale approve`.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "list", map[string]any{"kind": "whale"})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if perr != nil || handled {
				return perr
			}
			var rows []whaleNodeRow
			for _, rec := range env.Result.Records() {
				item := rec
				if m, ok := rec["item"].(map[string]any); ok {
					item = m
				}
				r := whaleNodeRowFrom(item)
				if r.Agent == "" && r.Address == "" {
					continue
				}
				if pending && r.Approved {
					continue
				}
				rows = append(rows, r)
			}
			sort.SliceStable(rows, func(i, j int) bool {
				if rows[i].Approved != rows[j].Approved {
					return !rows[i].Approved // pending first: they are what needs a person
				}
				if rows[i].Created != rows[j].Created {
					return rows[i].Created > rows[j].Created
				}
				return rows[i].Agent < rows[j].Agent
			})
			if g.quiet {
				for _, r := range rows {
					fmt.Fprintln(os.Stdout, r.Address)
				}
				return nil
			}
			if len(rows) == 0 {
				if pending {
					fmt.Fprintln(os.Stderr, "whisper: no node is pending approval")
				} else {
					fmt.Fprintln(os.Stderr, "whisper: no node in this fleet joined with join settings "+
						"(tags, single-use, ephemeral or an approval rule); `whisper list` shows every agent")
				}
				return nil
			}
			table := make([][]string, 0, len(rows))
			waiting := 0
			for _, r := range rows {
				if !r.Approved {
					waiting++
				}
				eph := "-"
				if r.Ephemeral {
					eph = "ephemeral"
				}
				table = append(table, []string{
					orDash(r.Agent), orDash(r.Address), r.tagCell(), r.use(), r.Connects, eph, r.EastWest,
				})
			}
			printTable([]string{"NODE", "ADDRESS", "TAGS", "KEY", "CONNECTS", "LIFETIME", "EAST-WEST"}, table)
			if waiting > 0 {
				fmt.Fprintln(os.Stdout)
				whaleNote("%d node(s) pending approval: they resolve and reach the internet, but not "+
					"their siblings. `whisper whale approve <node>` admits one.", waiting)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&pending, "pending", false, "show only the nodes waiting for approval")
	return cmd
}

// --- approve / deny -----------------------------------------------------------------

func newWhaleApproveCmd() *cobra.Command { return newWhaleApprovalVerb("approve") }
func newWhaleDenyCmd() *cobra.Command    { return newWhaleApprovalVerb("deny") }

func newWhaleApprovalVerb(verb string) *cobra.Command {
	var reason string
	short := "Admit a pending node to its fleet's east-west"
	long := "Admit a node to east-west, so its siblings may reach it and it may reach them\n" +
		"(within whatever your WhaleACL allows). It changes nothing else about the node."
	if verb == "deny" {
		short = "Hold a node out of its fleet's east-west"
		long = "Hold a node out of east-west: it keeps its /128, its name, its resolver and its\n" +
			"internet egress, and loses reachability to and from its siblings until approved.\n" +
			"To cut a node off entirely, revoke it: `whisper kill --revoke` does that."
	}
	cmd := &cobra.Command{
		Use:   verb + " <node>",
		Short: short,
		Long: long + "\n\n" +
			"Name the node by its agent id, its /128, or its exact name in your fleet. A name is\n" +
			"matched in YOUR fleet only, exactly, never through public DNS, and a name two nodes\n" +
			"answer to is refused rather than guessed. This takes your account's own key: a\n" +
			"node's key can never approve or deny, itself or anything else.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			target, err := resolveWhaleJoinNode(cx, c, args[0])
			if err != nil {
				return err
			}
			intent := map[string]any{"v": whaleIntentVersion, "op": verb}
			if r := strings.TrimSpace(reason); r != "" {
				intent["reason"] = r
			}
			fa := target.selector()
			fa["whale"] = intent
			env, err := c.Agents(cx, "firewall", fa)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if perr != nil || handled {
				return perr
			}
			recs := env.Result.Records()
			if len(recs) == 0 {
				return &client.ProblemError{Status: 502, Detail: "the control plane accepted the " + verb +
					" but returned no receipt; read it back with `whisper whale nodes`"}
			}
			r := whaleNodeRowFrom(recs[0])
			if !target.receiptMatches(r) {
				return &client.ProblemError{Status: 502, Title: "receipt mismatch", Detail: fmt.Sprintf(
					"asked to %s %s and the control plane's receipt names %s (%s); not reporting that as "+
						"done. Read the state back with `whisper whale nodes`",
					verb, orVal(target.Agent, target.Address), orDash(r.Agent), orDash(r.Address))}
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, r.Address)
				return nil
			}
			printTable([]string{"NODE", "ADDRESS", "TAGS", "KEY", "EAST-WEST"},
				[][]string{{orDash(r.Agent), orDash(r.Address), r.tagCell(), r.use(), r.EastWest}})
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "a note for the audit trail (at most 200 characters are kept)")
	return cmd
}

// whaleJoinTarget is the node an approval is about, settled before anything is sent: the
// selector to send, and what the server's receipt must name for the CLI to call it done.
type whaleJoinTarget struct {
	Agent   string // the agent id, when the node came from the fleet listing
	Address string // the /128
}

func (t whaleJoinTarget) selector() map[string]any {
	if t.Agent != "" {
		return map[string]any{"agent": t.Agent}
	}
	return map[string]any{"address": t.Address}
}

// resolveWhaleJoinNode settles the node an approval is about, STRICTLY. The read verbs of
// `whisper whale` resolve liberally (fleet first, then public DNS, then a first-label
// match), which is right for a ping and wrong for a security decision: a name that came
// out of public DNS, a listing that failed, or a name that two nodes answer to would each
// turn into a guessed selector, and the guess could admit the very node a deny was meant
// to hold. So: a literal /128 is taken as typed; anything else must match exactly ONE node
// of your fleet, by agent id, label, address or full DNS name, and the agent id is sent.
func resolveWhaleJoinNode(cx context.Context, c *client.Client, raw string) (whaleJoinTarget, error) {
	want := strings.TrimSpace(raw)
	if want == "" {
		return whaleJoinTarget{}, usageErr("name the node: its agent id, its /128, or its name in your fleet")
	}
	if a, err := netip.ParseAddr(strings.Trim(want, "[]")); err == nil {
		if !a.Is6() || a.Is4In6() {
			return whaleJoinTarget{}, usageErr("%s is not an IPv6 address; a Whalenet node is a /128", want)
		}
		return whaleJoinTarget{Address: a.String()}, nil
	}
	peers, err := whaleFleet(cx, c)
	if err != nil {
		return whaleJoinTarget{}, &client.ProblemError{Status: 503, Title: "fleet unreadable", Detail: fmt.Sprintf(
			"your fleet could not be read (%v), so %q cannot be matched to a node, and an approval is "+
				"never sent on a guess. Retry, or name the node by its /128", err, want)}
	}
	norm := func(s string) string { return strings.ToLower(trimDot(strings.TrimSpace(s))) }
	w := norm(want)
	var hits []whalePeer
	for _, p := range peers {
		if w == norm(p.Name) || w == norm(p.Label) || w == norm(p.FQDN) || w == norm(p.Address) ||
			(p.Name != "" && w == norm(strings.TrimPrefix(p.Name, "agent-"))) {
			hits = append(hits, p)
		}
	}
	switch len(hits) {
	case 0:
		return whaleJoinTarget{}, &client.ProblemError{Status: 404, Title: "no such node", Detail: fmt.Sprintf(
			"nothing in your fleet is exactly %q. Names are matched exactly and never through public "+
				"DNS for an approval; `whisper whale nodes` lists your nodes", want)}
	case 1:
	default:
		var names []string
		for _, h := range hits {
			names = append(names, h.Name+" ("+h.Address+")")
		}
		return whaleJoinTarget{}, &client.ProblemError{Status: 409, Title: "ambiguous node", Detail: fmt.Sprintf(
			"%q names %d nodes in your fleet: %s. Name the one you mean by its agent id or its /128",
			want, len(hits), strings.Join(names, ", "))}
	}
	h := hits[0]
	if a, perr := netip.ParseAddr(h.Address); perr == nil {
		h.Address = a.String()
	}
	if h.Name == "" {
		return whaleJoinTarget{Address: h.Address}, nil
	}
	return whaleJoinTarget{Agent: h.Name, Address: h.Address}, nil
}

// receiptMatches says whether the server's receipt is about the node this command settled
// on. A mismatch is never printed as success: something answered for a different node.
func (t whaleJoinTarget) receiptMatches(r whaleNodeRow) bool {
	if t.Agent != "" && r.Agent != "" && !strings.EqualFold(t.Agent, r.Agent) {
		return false
	}
	if t.Address != "" {
		got, err := netip.ParseAddr(r.Address)
		if err != nil || got.String() != t.Address {
			return false
		}
	}
	return true
}

// --- approval rule ------------------------------------------------------------------

func newWhaleApprovalRuleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval [auto|manual]",
		Short: "Show or set how a new node joins: admitted at once, or held for approval",
		Long: "With no argument, show the fleet's join rule. `auto` (the default) admits a node to\n" +
			"east-west the moment it joins; `manual` holds every new node pending until you run\n" +
			"`whisper whale approve`, unless its key was minted with --preapproved.\n\n" +
			"Either way a new node gets its /128, its DNS and its egress at once; the rule\n" +
			"decides only when its siblings can reach it. Setting it needs `dns:whale:write`,\n" +
			"which is granted to nobody automatically: who joins a fleet is a fleet-wide decision.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := ""
			if len(args) == 1 {
				mode = strings.ToLower(strings.TrimSpace(args[0]))
				if mode != "auto" && mode != "manual" {
					return usageErr("the join rule is `auto` or `manual`, not %q", args[0])
				}
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			pa := map[string]any{}
			if mode != "" {
				pa["whale"] = map[string]any{"v": whaleIntentVersion, "approval": mode}
			}
			env, err := c.Agents(cx, "policy", pa)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if perr != nil || handled {
				return perr
			}
			got := ""
			for _, kv := range policyPairs(env) {
				if kv[0] == "whale_approval" {
					got = kv[1]
				}
			}
			if got == "" {
				return &client.ProblemError{Status: 502, Detail: "the control plane's policy read-back " +
					"carries no whale_approval row, so the join rule in force is unknown; this box may " +
					"predate the join lifecycle"}
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, got)
				return nil
			}
			fmt.Fprintf(os.Stdout, "join rule  %s\n", got)
			if mode != "" && got != mode {
				return &client.ProblemError{Status: 502, Detail: fmt.Sprintf(
					"asked for %s and the control plane reads back %s; nothing was assumed", mode, got)}
			}
			if got == "manual" {
				whaleNote("New nodes wait for `whisper whale approve <node>` before their siblings can reach them.")
			}
			return nil
		},
	}
	return cmd
}

// --- mint flags (on `whisper create --register`) --------------------------------------

// whaleJoinFlags are the join settings a node's key is minted with. They live on
// `whisper create --register` because op:register is the one mint, and they are properties
// of the KEY: a node can restate its tags at connect, never change them.
type whaleJoinFlags struct {
	tags        []string
	singleUse   bool
	ephemeral   bool
	preapproved bool
	ttl         string
}

func (f *whaleJoinFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.tags, "tag", nil,
		"a Whalenet tag for the new node's key, e.g. tag:prod (repeatable, or comma-separated); fixed for the key's life")
	cmd.Flags().BoolVar(&f.singleUse, "single-use", false,
		"the new key establishes a node once; a second connect with it is refused")
	cmd.Flags().BoolVar(&f.ephemeral, "ephemeral", false,
		"release the new node automatically once it holds no connection for 15 minutes")
	cmd.Flags().BoolVar(&f.preapproved, "preapproved", false,
		"admit the new node to east-west at once, even when the join rule is manual")
	cmd.Flags().StringVar(&f.ttl, "ttl", "",
		"the new key expires after this long, e.g. 24h or 3600 (seconds); not with --tag")
}

// ttlSeconds parses --ttl liberally: a Go duration (90m, 24h) or a bare number of seconds.
// It returns 0 when --ttl was not given.
func (f *whaleJoinFlags) ttlSeconds() (int64, error) {
	v := strings.TrimSpace(f.ttl)
	if v == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0, usageErr("--ttl must be positive, got %s", v)
		}
		return n, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, usageErr("--ttl is a duration like 24h or 90m, or a number of seconds; got %q", v)
	}
	if d < time.Second {
		return 0, usageErr("--ttl must be at least one second, got %s", v)
	}
	return int64(d / time.Second), nil
}

// validate refuses, before any request, the combinations the server would refuse anyway,
// and says why in the CLI's own terms.
func (f *whaleJoinFlags) validate(reuse bool) error {
	if reuse && (f.any() || strings.TrimSpace(f.ttl) != "") {
		return usageErr("--reuse returns an agent that already exists, so it cannot carry --tag, " +
			"--single-use, --ephemeral, --preapproved or --ttl: those are set when a key is minted. " +
			"Drop --reuse to mint a new key with them")
	}
	if len(f.cleanTags()) > 0 && strings.TrimSpace(f.ttl) != "" {
		return usageErr("--tag and --ttl are different governance models: a tagged key's authority is " +
			"the tag's and outlives whoever minted it, so it cannot also expire. Pass one or the other")
	}
	_, err := f.ttlSeconds()
	return err
}

// cleanTags trims, drops blanks and de-duplicates (first spelling wins, order kept), so the
// same command run twice sends byte-identical args and an idempotent retry never reads as
// a different request.
func (f *whaleJoinFlags) cleanTags() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range f.tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	return out
}

// any reports whether a whale join setting was given (-ttl is not one: it is the
// credential expiry, sent as ttl_seconds beside the whale intent rather than inside it).
func (f *whaleJoinFlags) any() bool {
	return len(f.cleanTags()) > 0 || f.singleUse || f.ephemeral || f.preapproved
}

// intent is the `whale` sub-map for op:register, or nil when no join flag was given, so a
// register without them is byte-identical to one from before these flags existed.
func (f *whaleJoinFlags) intent() map[string]any {
	if !f.any() {
		return nil
	}
	m := map[string]any{"v": whaleIntentVersion}
	if tags := f.cleanTags(); len(tags) > 0 {
		m["tags"] = tags
	}
	if f.singleUse {
		m["reusable"] = false
	}
	if f.ephemeral {
		m["ephemeral"] = true
	}
	if f.preapproved {
		m["preapproved"] = true
	}
	return m
}

// summary is the one stderr line that says what the new key was minted with. It echoes
// settings the server accepted (a refused one is a 400 and never reaches here).
func (f *whaleJoinFlags) summary() string {
	var parts []string
	if t := f.cleanTags(); len(t) > 0 {
		parts = append(parts, "tags "+strings.Join(t, ","))
	}
	if f.singleUse {
		parts = append(parts, "single-use")
	}
	if f.ephemeral {
		parts = append(parts, "ephemeral (released after 15 min with no connection)")
	}
	if f.preapproved {
		parts = append(parts, "pre-approved")
	}
	if n, err := f.ttlSeconds(); err == nil && n > 0 {
		parts = append(parts, "expires in "+(time.Duration(n)*time.Second).String())
	}
	return strings.Join(parts, ", ")
}
