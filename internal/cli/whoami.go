// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/buildid"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whoami.go covers the two commands an agent/LLM naturally guesses at: `whisper
// whoami` (who am I on the Whisper network - key, tenant, fleet, selected agent) and
// `whisper version` (the spelled-out sibling of --version). Postel: a guessed command
// gets a helpful answer, never "unknown command".

// newWhoamiCmd shows the caller's standing in one calm table: whether a key is in
// effect (and from where - the value is NEVER printed), the tenant handle the key maps
// to, how many agents it holds, and the selected agent. Keyless it still answers
// helpfully (key: not set + the login nudge) and exits 0 - an identity question is
// never an error. Aliases catch the spellings different tools reach for.
func newWhoamiCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:     "whoami",
		Aliases: []string{"who", "me", "self"},
		Short:   "Show who you are: key status, tenant, and your agents",
		Long: "One calm answer to \"who am I here?\": whether an API key is in effect (and from\n" +
			"where - the key value is NEVER printed), the tenant it maps to, how many agents\n" +
			"it holds, and the selected agent. Works without a key too (it tells you how to\n" +
			"get one). Also answers to `who`, `me`, and `self`.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, _ := client.ResolveCredential(client.KeyLadderOptions{
				FlagKey:    g.key,
				FlagBearer: g.bearer,
				KeyFile:    g.keyFile,
				AllowEnv:   true,
				AllowFile:  true,
			})
			view := whoamiView{
				KeyPresent: !cred.IsZero(),
				KeySource:  string(cred.Source),
				Selected:   client.ReadAgentFile(agentFile),
			}
			// With a key, ask the control plane who it maps to (tenant + fleet size).
			// Best-effort: an unreachable/unhappy control plane degrades the two cells,
			// it never turns an identity question into a failure (fail-open, like the
			// dashboard's tenant lookup).
			if view.KeyPresent {
				if c, err := resolveClient(false, false); err == nil {
					view.Tenant, view.AgentTenants, view.Agents, view.reachErr = whoamiFleet(c)
				} else {
					view.reachErr = err
				}
			}
			if view.reachErr != nil {
				view.Error = friendly(view.reachErr)
			}
			if g.jsonOut {
				emitJSONValue(view)
				// A machine surface that could not fill its fields must not exit 0: a
				// script checks the exit code before it reads "agents", and a read that timed
				// out used to reach it as a clean answer. The object above still carries what
				// DID answer, and names what did not in "error".
				if view.reachErr != nil {
					return &exitCodeError{code: 1, msg: "whoami is incomplete: " + view.Error}
				}
				return nil
			}
			keyCell := "not set - run: whisper login"
			if view.KeyPresent {
				keyCell = "set (" + view.KeySource + ")"
			}
			// Per-cell, not per-request: the two facts come from two reads, so one of them
			// failing must not blank the other. A failed fleet read used to discard a
			// tenant handle that had answered perfectly well.
			tenantCell := orDash(view.Tenant)
			agentsCell := "-"
			if view.Agents != nil {
				agentsCell = fmt.Sprintf("%d", *view.Agents)
			}
			rows := [][]string{
				{"key", keyCell},
				{"tenant", tenantCell},
				{"agents", agentsCell},
			}
			// Said only when there is something to say. An owner whose agents file their
			// activity under their own handles cannot aggregate a fleet by the one
			// handle above, and learning that from a surprising op:logs result is how a
			// long investigation began once. An agent key, where the two coincide,
			// sees no such row.
			if view.AgentTenants != nil && *view.AgentTenants > 0 {
				rows = append(rows, []string{"agent tenants", fmt.Sprintf(
					"%d - each agent logs under its own, not yours", *view.AgentTenants)})
			}
			rows = append(rows, []string{"selected", orVal(view.Selected, "none - run: whisper use {agent}")})
			printTable([]string{"FIELD", "VALUE"}, rows)
			if view.reachErr != nil {
				fmt.Fprintf(os.Stderr, "whisper: whoami is incomplete - %s\n", view.Error)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// whoamiView is the JSON shape `whisper whoami --json` emits (no key value, ever).
type whoamiView struct {
	KeyPresent bool   `json:"key_present"`
	KeySource  string `json:"key_source"`
	// Tenant is the handle the CALLER'S OWN key files activity under - the one op:logs
	// scopes by for this key. It is NOT any agent's; see callerTenant.
	Tenant string `json:"tenant,omitempty"`
	// AgentTenants is how many OTHER handles this key's agents log under, each agent logging
	// under its own rather than its owner's. It is a pointer so that null (the plane did
	// not say) and 0 (nothing logs elsewhere) stay different answers on a machine surface.
	AgentTenants *int `json:"agent_tenants"`
	// Agents is the fleet size, and ABSENT when the count could not be read. It used to
	// be a plain int, so a timed-out read reached --json as "agents": 0, which is a measurement
	// of an empty fleet rather than "could not count". A script reading it now finds either a
	// real total or no field, with "error" saying why.
	Agents   *int   `json:"agents,omitempty"`
	Selected string `json:"selected_agent"`
	// Error names whatever the control plane could not answer, so a reader of the JSON knows
	// which absent fields are unknown rather than empty. Absent when every read answered.
	Error    string `json:"error,omitempty"`
	reachErr error  // the same failure as an error, for the exit code and the stderr note
}

// whoamiFleet answers the two halves of "who am I" with two cheap reads, run
// concurrently so the wall time is the slower of them rather than their sum (measured
// against the live plane on a 385-agent account, both around half a second).
//
// They are two reads because they are two facts, and conflating them was the
// defect. The tenant is the handle the CALLER'S key files activity under; the fleet size
// is how many agents that key holds. A registered agent's events live under the AGENT'S
// handle, so the first can never be read off the second value.
//
// Bounded short so whoami stays snappy. A failure degrades only its own cell, and is
// returned so the caller can say which cell is unknown: on stderr for the table, in "error"
// and the exit code for --json. agents is nil when the count did not answer.
func whoamiFleet(c *client.Client) (
	tenant string, agentTenants *int, agents *int, err error) {
	cx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var (
		wg               sync.WaitGroup
		ownErr, fleetErr error
	)
	wg.Add(2)
	go func() { defer wg.Done(); tenant, agentTenants, ownErr = callerTenant(cx, c) }()
	var count int
	go func() { defer wg.Done(); count, fleetErr = fleetSize(cx, c) }()
	wg.Wait()
	// Each read degrades its OWN cell and nothing else. Substituting a handle we could not
	// confirm is the defect this fixes; discarding one that DID answer because the other read
	// was shed by a 429 is the same mistake pointed the other way.
	if ownErr != nil {
		tenant, agentTenants = "", nil
	}
	if fleetErr == nil {
		agents = &count
	}
	// Both halves are named when both failed: reporting only the last one would leave a
	// reader of "error" believing the other absent field was simply empty.
	switch {
	case ownErr != nil && fleetErr != nil:
		err = fmt.Errorf("tenant: %s; agents: %s", friendly(ownErr), friendly(fleetErr))
	case ownErr != nil:
		err = fmt.Errorf("tenant: %s", friendly(ownErr))
	case fleetErr != nil:
		err = fmt.Errorf("agents: %s", friendly(fleetErr))
	}
	return tenant, agentTenants, agents, err
}

// callerTenant asks the plane what the CALLER'S OWN key files activity under:
// op:list kind:'activityTenants' view:'self', which answers in one row and
// carries agent_tenants, the number of other handles this key's agents log under.
//
// This is deliberately the only way the CLI learns the value. It cannot be computed here
// (the CLI never sees a userId), and what used to stand in for it was the FIRST agent's
// handle, derived off that agent's fqdn. That is a different tenant by construction, and
// a convincing one: right shape, stable, and genuinely belonging to something the caller
// owns. A real investigation was spent on it before it was recognised. A
// reply that does not mark exactly one row self is an ERROR, not an empty answer: every
// caller then shows "-" rather than a substitute, and says why.
func callerTenant(cx context.Context, c *client.Client) (own string, agentTenants *int, err error) {
	env, aerr := c.Agents(cx, "list", map[string]any{"kind": "activityTenants", "view": "self"})
	if aerr != nil {
		return "", nil, aerr
	}
	if perr := envelopeError(env); perr != nil {
		return "", nil, perr
	}
	// self is the plane's own marker, not an ordering we assume: the row order is documented and
	// stable, but a handle printed under the label "tenant" must not rest on a convention one
	// refactor can change. So every row is read and EXACTLY one must be marked - breaking on the
	// first would quietly let a second self row decide the answer by arriving earlier, which is
	// the ordering dependence this comment claims not to have.
	marked := 0
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if field(item, "self") != "true" {
			continue
		}
		marked++
		own = field(item, "tenant")
		// Absent (an older plane that predates the field) stays nil rather than becoming 0:
		// "nothing logs elsewhere" and "I was not told" are different answers. A negative count
		// is not an answer at all, so it is nil too - the field is a cardinality.
		if n, cerr := strconv.Atoi(field(item, "agent_tenants")); cerr == nil && n >= 0 {
			agentTenants = &n
		} else {
			agentTenants = nil
		}
	}
	switch {
	case marked == 0:
		return "", nil, fmt.Errorf("the control plane did not name this key's own tenant")
	case marked > 1:
		return "", nil, fmt.Errorf("the control plane named %d tenants as this key's own, so none is shown", marked)
	case own == "":
		return "", nil, fmt.Errorf("the control plane named this key's own tenant without a handle")
	}
	return own, agentTenants, nil
}

// fleetSize is op:list kind:'agents' mode:'count': the true total as one synthetic
// row. The count used to come from walking the full listing, which is the same number and
// roughly 435 KB of it, against about 300 bytes for the count, measured on the live plane.
// A question about a number should not have to download the roster to answer it.
func fleetSize(cx context.Context, c *client.Client) (int, error) {
	env, aerr := c.Agents(cx, "list", map[string]any{"kind": "agents", "mode": "count"})
	if aerr != nil {
		return 0, aerr
	}
	if perr := envelopeError(env); perr != nil {
		return 0, perr
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if n, cerr := strconv.Atoi(field(item, "count")); cerr == nil {
			return n, nil
		}
	}
	// No parseable count: an ERROR, so the cell shows "-" and the reader is told. Returning 0 here
	// would print "agents 0" beside a tenant that answered fine, with no dash and no note, and the
	// count mode's own contract is that it must never hand back "a fabricated 0 presented as a
	// real total". Three reply shapes reach this line: a note row instead of a count,
	// ok:true with no result, and ok:true with no rows.
	return 0, fmt.Errorf("the control plane answered op:list mode:'count' without a count")
}

// newVersionCmd is the spelled-out `whisper version` (the flag form --version already
// exists; an agent that types the word gets the same answer, not "unknown command").
// --quiet prints the bare version (the load-bearing value); --json a tiny object.
//
// The build identity rides alongside because the version alone has been caught
// lying: a lab host reported a June version tag from a binary built at the end
// of August, since the version is stamped by hand and falls back to a literal
// in the source when nobody stamps it. The revision is put there by the
// toolchain and cannot be forgotten. It is additive on both surfaces - the
// bare `--quiet` value stays the version and nothing else, because that is what
// scripts read - and it is omitted entirely when unrecorded rather than printed
// as "unknown", so what is shown is always something a reader can look up.
// printSourceRef names the PUBLIC tree these bytes came from, when one is known
// to exist. The build id is the commit that compiled the binary, which is not in this repository,
// so it is truthful and unresolvable to a holder, and the version output used to
// lead only somewhere they could not go. This is the line that goes somewhere
// they can. Absent on a development build, and absent means silence: a guessed
// tag is the same lie the build id was introduced to stop.
func printSourceRef() {
	if src := buildid.Source(); src != "" {
		fmt.Fprintf(os.Stdout, "source: %s\n", src)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the whisper CLI version",
		Long: "Print the whisper CLI version (same answer as --version), plus the build " +
			"revision it was compiled from when the toolchain recorded one.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if g.jsonOut {
				emitJSONValue(struct {
					Version   string `json:"version"`
					Build     string `json:"build,omitempty"`
					BuildTime string `json:"build_time,omitempty"`
					Source    string `json:"source,omitempty"`
				}{Version, buildid.ID(), buildid.Time(), buildid.Source()})
				return nil
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, Version)
				return nil
			}
			if b := buildid.ID(); b != "" {
				if t := buildid.Time(); t != "" {
					fmt.Fprintf(os.Stdout, "whisper version %s (build %s, %s)\n", Version, b, t)
				} else {
					fmt.Fprintf(os.Stdout, "whisper version %s (build %s)\n", Version, b)
				}
				printSourceRef()
				return nil
			}
			fmt.Fprintf(os.Stdout, "whisper version %s\n", Version)
			printSourceRef()
			return nil
		},
	}
}
