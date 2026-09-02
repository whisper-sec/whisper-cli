// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_acl.go is `whisper whale acl`: the operator's door to the WhaleACL.
//
// The document, its compiler, its test block, its CAS and its enforcement at the CONNECT
// choke all shipped without a single verb to reach them, so the only way to publish a
// fleet's reachability policy was a hand-escaped Cypher CALL carrying a HuJSON file as a
// string literal. The acceptance criteria are written in
// commands that did not exist. These are those commands.
//
// Two tiers, the same rule as the rest of `whale`. Reading what governs your fleet
// (`show`) and asking what it says about a pair (`test`) need only an ordinary key, and
// both work today. Publishing needs `dns:whale:write`, a dedicated operator grant that is
// deliberately never auto-enrolled, because one document rewrites the reachability of an
// entire fleet. When a key does not carry it the control plane says so in a sentence that
// names the grant and says retrying will not obtain it, and this verb prints that sentence
// rather than reinterpreting it.
//
// `test` mutates nothing. It is answered by the compiled artifact that AddressOwnerIndex
// reads at the CONNECT choke, so it is the enforced answer rather than a second
// interpretation that would eventually disagree with the first.

func newWhaleACLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "The document that decides who in your fleet may reach what",
		Long: "The WhaleACL: one document per fleet, compiled when you write it.\n\n" +
			"  show      the document in force, its hash, and what it compiled to\n" +
			"  test      what the document says about one source and one target\n" +
			"  set       publish a document (HuJSON in, compiled and tested before it lands)\n" +
			"  withdraw  remove it, leaving east-west governed by tenancy alone\n\n" +
			"Reading is an ordinary read. Publishing takes `dns:whale:write`, a dedicated\n" +
			"grant that is never handed out automatically: one document governs every node\n" +
			"you have, so an account administrator grants it on purpose or not at all.\n\n" +
			"The grammar is Tailscale's, so a policy file you already have mostly pastes in:\n" +
			"tagOwners, groups, hosts, grants, autoApprovers, ssh, tests and default, with\n" +
			"comments and trailing commas accepted. What Tailscale cannot express, and this\n" +
			"can, is a `where` clause on the graph:\n\n" +
			"  { \"src\": [\"tag:prod\"], \"dst\": [\"autogroup:internet\"], \"ip\": [\"tcp:443\"],\n" +
			"    \"where\": { \"dst.band\": {\"notin\": [\"HIGH\",\"CRITICAL\"], \"onUnknown\": \"allow\"} } }",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleACLShowCmd(), newWhaleACLTestCmd(), newWhaleACLSetCmd(), newWhaleACLWithdrawCmd())
	// An unrecognised verb here used to print help and exit 0, so a typo in a
	// script reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

// --- show -------------------------------------------------------------------------

func newWhaleACLShowCmd() *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "The document in force, and what it compiled to",
		Long: "Read back the WhaleACL this fleet is governed by: the document itself, the hash\n" +
			"the control plane knows it by, and the artifact it compiled to (how many of your\n" +
			"nodes it governs, how many clauses, and which of them only the CONNECT plane can\n" +
			"enforce).\n\n" +
			"--raw prints the canonical document and nothing else, so `whisper whale acl show\n" +
			"--raw > policy.hujson` gives you the file back to edit and re-publish.\n\n" +
			"Publishing nothing is a real answer and is reported as one: with no document,\n" +
			"east-west is governed by tenancy alone, which still stops another customer's\n" +
			"agent reaching yours.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			s, env, err := readWhaleACL(cx, c)
			if err != nil {
				return err
			}
			if raw {
				if !s.Published {
					return &client.ProblemError{Status: 1,
						Detail: "this fleet publishes no WhaleACL, so there is no document to print"}
				}
				fmt.Fprintln(os.Stdout, s.Document)
				return nil
			}
			if g.jsonOut {
				emitJSONValue(s)
				return envelopeError(env)
			}
			renderWhaleACL(s)
			return nil
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "print only the canonical document, ready to edit and re-publish")
	return cmd
}

// readWhaleACL is the one read every verb here starts from: op:policy, narrowed to the
// whale.acl.* cells. It returns the envelope too, so a caller emitting --json can still
// report the op's own ok/err rather than inventing one.
func readWhaleACL(cx context.Context, c *client.Client) (whale.ACLSummary, *client.Envelope, error) {
	env, err := c.Agents(cx, "policy", map[string]any{})
	if err != nil {
		return whale.ACLSummary{}, nil, err
	}
	if err := envelopeError(env); err != nil {
		return whale.ACLSummary{}, env, err
	}
	return whale.ACLSummaryFrom(policyPairs(env)), env, nil
}

// policyPairs flattens an op:policy result into ordered key/value pairs. op:policy emits
// {key, value} rows and the note rows are numbered, so ORDER is content here, not
// presentation: a map would shuffle the compiler's own explanation of its document.
func policyPairs(env *client.Envelope) [][2]string {
	if env == nil || env.Result == nil {
		return nil
	}
	recs := env.Result.Records()
	out := make([][2]string, 0, len(recs))
	for _, rec := range recs {
		k, ok := rec["key"].(string)
		if !ok {
			continue
		}
		v, _ := rec["value"].(string)
		out = append(out, [2]string{k, v})
	}
	return out
}

func renderWhaleACL(s whale.ACLSummary) {
	if !s.Published {
		printTable([]string{"WHALE ACL", ""}, [][]string{{"document", "none published"}})
		fmt.Fprintln(os.Stdout)
		whaleNote("With no document, east-west is governed by tenancy alone: another customer's " +
			"agent still cannot reach yours, and inside your own fleet nothing is narrowed.")
		whaleNote("Publish one with `whisper whale acl set <file>`, and ask what it would say first " +
			"with `whisper whale acl test <src> <dst>`.")
		return
	}
	rows := [][]string{
		{"hash", s.Hash},
		{"version", s.Version},
		{"compiled artifact", s.Artifact},
		{"default", s.Default},
		{"nodes governed", s.Nodes},
		{"clauses", s.Clauses},
	}
	if s.ConnectOnly != "" && s.ConnectOnly != "0" {
		rows = append(rows, []string{"connect-plane only", s.ConnectOnly})
	}
	if s.Refusals != "" {
		rows = append(rows, []string{"refusals so far", s.Refusals})
	}
	if s.LastRefusal != "" {
		rows = append(rows, []string{"last refusal", s.LastRefusal})
	}
	printTable([]string{"WHALE ACL", ""}, rows)
	fmt.Fprintln(os.Stdout)
	for _, n := range s.Notes {
		whaleNote("%s", n)
	}
	if s.Document != "" {
		fmt.Fprintln(os.Stdout, s.Document)
	}
}

// --- test -------------------------------------------------------------------------

func newWhaleACLTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <src> <dst>",
		Short: "What the document says about one source and one target",
		Long: "Ask the compiled document whether one principal may reach one target, without\n" +
			"putting a packet on the wire to find out and without changing anything at all.\n\n" +
			"Both arguments are in the document's own grammar:\n\n" +
			"  whisper whale acl test group:sre tag:prod:22\n" +
			"  whisper whale acl test autogroup:member autogroup:internet:443\n" +
			"  whisper whale acl test tag:web '[2a04:2a01::5]:443'\n\n" +
			"The answer comes from the artifact the CONNECT path itself reads, so it is what\n" +
			"is enforced rather than a second reading of the same file. Exit status is 1 when\n" +
			"the document refuses the flow, so it can gate a deploy.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, dst := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
			if src == "" || dst == "" {
				return usageErr("both a source and a target are needed, e.g. " +
					"`whisper whale acl test group:sre tag:prod:22`")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "list", map[string]any{
				"kind": "whale", "view": "acltest", "src": src, "dst": dst,
			})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if perr != nil {
				return perr
			}
			state, note, verdicts := whaleACLTestRows(env)
			if !handled {
				renderWhaleACLTest(src, dst, state, note, verdicts)
			}
			for _, v := range verdicts {
				if v.Denied() {
					return &client.ProblemError{Status: 1, Detail: fmt.Sprintf(
						"the document in force REFUSES %s -> %s (%s)", src, dst, v.Why)}
				}
			}
			return nil
		},
	}
}

// whaleACLTestRows splits a dry-run result into its header (what was asked, and whether
// it could be answered at all) and the per-node verdicts.
func whaleACLTestRows(env *client.Envelope) (state, note string, verdicts []whale.ACLTestVerdict) {
	if env == nil || env.Result == nil {
		return "", "", nil
	}
	for _, rec := range env.Result.Records() {
		item, ok := rec["item"].(map[string]any)
		if !ok {
			continue
		}
		if s, ok := item["state"].(string); ok {
			state = s
			note, _ = item["note"].(string)
			continue
		}
		verdicts = append(verdicts, whale.ACLTestVerdict{
			Src:     cellString(item["src"]),
			SrcName: cellString(item["src_name"]),
			Dst:     cellString(item["dst"]),
			Proto:   cellString(item["proto"]),
			Port:    cellString(item["port"]),
			Verdict: cellString(item["verdict"]),
			Why:     cellString(item["why"]),
		})
	}
	return state, note, verdicts
}

// cellString renders one control-plane cell as text. JSON numbers arrive as float64, and
// a port printed as "22" rather than "22.000000" is the whole reason this exists.
func cellString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func renderWhaleACLTest(src, dst, state, note string, verdicts []whale.ACLTestVerdict) {
	if len(verdicts) == 0 {
		printTable([]string{"WHALE ACL TEST", ""}, [][]string{
			{"asked", src + " -> " + dst},
			{"answer", orVal(state, "no answer")},
		})
		fmt.Fprintln(os.Stdout)
		if note != "" {
			whaleNote("%s", note)
		}
		return
	}
	rows := make([][]string, 0, len(verdicts))
	for _, v := range verdicts {
		rows = append(rows, []string{
			orVal(v.SrcName, v.Src), v.Dst, strings.TrimSpace(v.Proto + ":" + v.Port),
			strings.ToUpper(v.Verdict), v.Why,
		})
	}
	printTable([]string{"SOURCE", "TARGET", "PORT", "VERDICT", "DECIDED BY"}, rows)
	fmt.Fprintln(os.Stdout)
	if note != "" {
		whaleNote("%s", note)
	}
	whaleNote("Nothing was changed: this is the artifact the CONNECT path reads, asked a question.")
}

// --- set --------------------------------------------------------------------------

func newWhaleACLSetCmd() *cobra.Command {
	var base string
	var force bool
	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Publish a document (compiled and tested before it lands)",
		Long: "Publish the WhaleACL for this fleet. The file is HuJSON, so comments and trailing\n" +
			"commas are fine; pass - to read it from stdin.\n\n" +
			"Nothing is stored until the document parses, compiles against your current roster,\n" +
			"and every assertion in its own `tests` block passes. A failure names the offending\n" +
			"rule by JSON pointer and leaves the previous document exactly where it was.\n\n" +
			"Replacing a document names the one you edited, so a concurrent edit cannot be lost:\n" +
			"pass --base with the hash `show` gave you, or --force to accept last-writer-wins.\n\n" +
			"This needs `dns:whale:write`. It is not granted automatically to anyone, because\n" +
			"one document decides the reachability of every node in the fleet.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := readACLFile(args[0])
			if err != nil {
				return err
			}
			// The local half of the guard the control plane also carries. It matters here
			// because our own release discipline restarts one box at a time, so there is a
			// window on every release where the box answering you is the older build.
			if err := whale.CheckACLDocument(doc); err != nil {
				return &client.ProblemError{Status: 1, Detail: err.Error()}
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			base, err = resolveACLBase(cx, c, base, force, "replacement",
				"whisper whale acl set "+args[0])
			if err != nil {
				return err
			}
			return writeWhaleACL(cx, c, string(doc), base)
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "the hash of the document you edited (from `whisper whale acl show`)")
	cmd.Flags().BoolVar(&force, "force", false, "publish over whatever is in force without naming it: last writer wins")
	return cmd
}

// readACLFile reads the document from a path or from stdin. It refuses an empty file
// rather than sending it: an empty document means "refuse everything" on a plane whose
// whole job is reachability, and a truncated file is far likelier than that intent.
func readACLFile(path string) ([]byte, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, &client.ProblemError{Status: 1, Detail: "cannot read the ACL document: " + err.Error()}
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, &client.ProblemError{Status: 1, Detail: "that file is empty. To remove the document " +
			"in force, run `whisper whale acl withdraw`, which says what it does"}
	}
	return raw, nil
}

// resolveACLBase settles the compare-and-set argument before anything is written.
//
// The control plane refuses an unbased replacement with a 409 naming the hash, which is
// the correct answer and arrives one round trip too late to be useful. So the base is
// settled here, from a read this verb makes anyway, and the refusal names the exact
// command to run next rather than a rule to go and look up.
func resolveACLBase(cx context.Context, c *client.Client, base string, force bool, verb, example string) (string, error) {
	base = strings.TrimSpace(base)
	if base != "" && force {
		return "", usageErr("--base and --force say opposite things: --base names the document you " +
			"edited, --force says you do not care which one is there. Pass one")
	}
	s, _, err := readWhaleACL(cx, c)
	if err != nil {
		return "", err
	}
	if !s.Published {
		if base != "" {
			return "", &client.ProblemError{Status: 1, Detail: "this fleet publishes no WhaleACL, so " +
				"there is no document " + base + " to base a " + verb + " on. Drop --base"}
		}
		return "", nil
	}
	if force {
		return s.Hash, nil
	}
	if base == "" {
		return "", &client.ProblemError{Status: 1, Detail: fmt.Sprintf(
			"a WhaleACL is already in force (%s, v%s). Going ahead without naming it could silently "+
				"discard somebody else's edit.\n\nRe-read it, apply your change, and name it:\n"+
				"  whisper whale acl show --raw > policy.hujson\n"+
				"  %s --base %s\n\n"+
				"Or --force, which takes whatever is there right now: last writer wins.",
			s.Hash, s.Version, example, s.Hash)}
	}
	return base, nil
}

// writeWhaleACL sends the document (or null, to withdraw) and renders what came back.
// The read-back is the compiler's own account of what it just published, and printing it
// is the point: a document can compile to something far broader or far narrower than its
// author intended, and a note about that is worthless if you have to go looking for it.
func writeWhaleACL(cx context.Context, c *client.Client, doc, base string) error {
	intent := map[string]any{}
	if doc == "" {
		intent["acl"] = nil
	} else {
		intent["acl"] = doc
	}
	if base != "" {
		intent["base"] = base
	}
	env, err := c.Agents(cx, "policy", map[string]any{"whale": intent})
	if err != nil {
		return err
	}
	handled, perr := renderEnvelope(env)
	if perr != nil {
		return perr
	}
	s := whale.ACLSummaryFrom(policyPairs(env))
	if handled {
		return nil
	}
	renderWhaleACL(s)
	if s.Published && s.Default == "deny" && (s.Clauses == "" || s.Clauses == "0") {
		fmt.Fprintln(os.Stdout)
		whaleNote("READ THAT AGAIN: the default is deny and this document compiled to no clauses, so "+
			"every flow between every one of your %s nodes is now refused. `whisper whale acl withdraw` "+
			"puts it back.", orVal(s.Nodes, "0"))
	}
	return nil
}

// --- withdraw ---------------------------------------------------------------------

func newWhaleACLWithdrawCmd() *cobra.Command {
	var base string
	var force bool
	cmd := &cobra.Command{
		Use:   "withdraw",
		Short: "Remove the document, leaving east-west governed by tenancy alone",
		Long: "Withdraw the WhaleACL. Your fleet keeps the tenancy boundary it always had, so no\n" +
			"other customer's agent can reach yours; what goes away is any narrowing you had\n" +
			"published INSIDE your own fleet.\n\n" +
			"It names the document it is removing, for the same reason `set` does.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			resolved, err := resolveACLBase(cx, c, base, force, "withdrawal",
				"whisper whale acl withdraw")
			if err != nil {
				return err
			}
			if resolved == "" {
				whaleNote("Nothing to withdraw: this fleet publishes no WhaleACL.")
				return nil
			}
			return writeWhaleACL(cx, c, "", resolved)
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "the hash of the document you mean to remove (from `whisper whale acl show`)")
	cmd.Flags().BoolVar(&force, "force", false, "withdraw whatever is in force without naming it")
	return cmd
}
