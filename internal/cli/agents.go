// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- list ------------------------------------------------------------------------

func newListCmd() *cobra.Command {
	var kind string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your agents (or records / identities)",
		Long:  "List the caller's agents, DNS records, or identities - confined to YOUR tenant.",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "list", map[string]any{"kind": kind})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled {
				return perr
			}
			if perr != nil {
				return perr
			}
			renderFleet(env.Result)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "agents", "what to list: agents | records | identities")
	return cmd
}

// renderFleet prints the agent fleet table, newest first. Each row's `item` is the
// per-agent map (the op:list shape: kind,item).
func renderFleet(res *client.Result) {
	recs := res.Records()
	type row struct {
		created int64
		cells   []string
	}
	var rows []row
	for _, rec := range recs {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		name := field(item, "agent", "id", "label")
		if name == "" {
			continue
		}
		created := field(item, "created", "allocated_at")
		rows = append(rows, row{
			created: parseEpoch(created),
			cells: []string{
				name,
				field(item, "address", "addr128"),
				orDash(field(item, "label")),
				orDash(agentDomain(field(item, "fqdn"))),
				orVal(field(item, "state"), "active"),
				humanTime(created),
				field(item, "contact"),
			},
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].created > rows[j].created })
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no agents yet - create one:  whisper create")
		return
	}
	cells := make([][]string, len(rows))
	for i, r := range rows {
		cells[i] = r.cells
	}
	printTable([]string{"AGENT", "ADDRESS", "LABEL", "DOMAIN", "STATE", "CREATED", "CONTACT"}, cells)
	fmt.Fprintf(os.Stderr, "%d agent(s)\n", len(rows))
}

// --- agent <agent|address> -------------------------------------------------------

func newAgentCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "agent [agent|address]",
		Short: "Per-agent info + live counters",
		Long:  "Show one agent's detail and counters (op:agent). Pass the agent id or its /128 address.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			args2 := map[string]any{}
			switch {
			case addr != "":
				args2["address"] = addr
			case len(args) == 1:
				// Accept either selector form (liberal): an agent id or a /128 address.
				if looksLikeV6(args[0]) {
					args2["address"] = args[0]
				} else {
					args2["agent"] = args[0]
				}
			default:
				return usageErr("agent needs an <agent|address> (or --address)")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "agent", args2)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderAgentDetail(env.Result)
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "address", "", "select by /128 address")
	return cmd
}

func renderAgentDetail(res *client.Result) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: not found in your account")
		return
	}
	rec := recs[0]
	order := []string{
		"agent", "address", "fqdn", "ptr", "label", "state", "allocated_at", "contact",
		"last_seen", "dns_queries", "dns_blocked", "dns_nxdomain", "packets",
		"bytes_up", "bytes_down", "connections_active", "connections_total",
	}
	rows := make([][]string, 0, len(order))
	for _, k := range order {
		if v, ok := rec[k]; ok {
			rows = append(rows, []string{k, asString(v)})
		}
	}
	printTable([]string{"FIELD", "VALUE"}, rows)
}

// --- create ----------------------------------------------------------------------

func newCreateCmd() *cobra.Command {
	var email, name, label string
	var register bool
	var ids identifierFlags
	var wallet, walletChain string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a named agent (your routable /128 identity), or --register a new agent+key",
		Long: "Create the caller's own /128 identity via op:identity. Every agent has a human\n" +
			"name - pass --name (an unnamed agent is a future support ticket; we refuse\n" +
			"to create one). On a terminal with no --name we ask for it; headless, --name is\n" +
			"required.\n\n" +
			"With --register, mint a brand-new agent with its own API key via op:register\n" +
			"(the key is shown ONCE - capture it).\n\n" +
			"Typed identity (one of): register the object under a domain-specific identifier it\n" +
			"already carries, so its /128 is attributed to that identifier (fleet device\n" +
			"attribution - the owner-private device_id `whisper list` surfaces). Passing one\n" +
			"implies --register (the object gets its own routable /128 + key):\n" +
			"  --vin (+ --ecu-serial)  a vehicle / ECU (automotive)\n" +
			"  --nf-instance-id        a 5G network function (telecom)\n" +
			"  --lfdi                  a DER / smart-grid device (energy, IEEE 2030.5)\n" +
			"  --udi                   a medical device (health, FHIR endpoint)\n" +
			"  --applicationuri        an OPC-UA / MUD industrial asset (OT)\n" +
			"  --c2pa-serial           a C2PA / CAWG content signer\n" +
			"  --agent-id              an A2A / AP2 / x402 commerce agent id\n" +
			"These are mutually exclusive; each is sent as the derivation's device_id. For a\n" +
			"DETERMINISTIC /128 derived from the device's OWN key (same key+id => same address),\n" +
			"use `whisper connect --tier wireguard --vin <VIN>` - the device holds the key.\n\n" +
			"With --wallet, additionally pin an x402 wallet (EOA) to the new /128 as a\n" +
			"resolvable TXT binding (via op:host) so a facilitator can tie the wallet to the\n" +
			"verifiable, revocable agent identity.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// --label is the legacy spelling of the name; --name wins.
			chosen := firstNonBlank(name, label)

			// Exactly-one typed identifier (or none) -> the derivation's device_id (fleet
			// attribution). A typed identifier IMPLIES the register path: op:register is where a
			// device_id is stored + surfaced (op:identity returns the caller's own /128 and does
			// not attribute a device), so a typed id on the default path would be a silent no-op.
			deviceID, derr := ids.resolve()
			if derr != nil {
				return derr
			}
			if deviceID != "" {
				register = true
			}

			if register {
				if strings.TrimSpace(chosen) == "" {
					return usageErr("--register needs a --name")
				}
				args := map[string]any{"label": strings.TrimSpace(chosen)}
				if email != "" {
					args["contact_email"] = email
				}
				if deviceID != "" {
					args["device_id"] = deviceID
				}
				c, err := resolveClient(true, false)
				if err != nil {
					return err
				}
				cx, cancel := ctx()
				defer cancel()
				env, err := c.Agents(cx, "register", args)
				if err != nil {
					return err
				}
				handled, perr := renderEnvelope(env)
				if handled || perr != nil {
					return perr
				}
				if err := maybePinWallet(c, env, wallet, walletChain); err != nil {
					return err
				}
				if g.quiet {
					// --quiet ⇒ ONLY the load-bearing value (the address) on stdout, no
					// chrome - mirror the identity path's quiet short-circuit . The
					// register-only API key is shown ONCE in the normal (non-quiet) path; a
					// caller that asked for quiet asked for exactly the address.
					if recs := env.Result.Records(); len(recs) > 0 {
						if addr := field(recs[0], "address", "addr128"); addr != "" {
							fmt.Fprintln(os.Stdout, addr)
						}
					}
					return nil
				}
				renderCreated(env.Result, true)
				return nil
			}

			// The default (op:identity) path goes through the ONE mandatory-name helper,
			// re-prompting on a TTY / failing clearly headless.
			gio := stdGuidedIO()
			finalName, err := requireName(guidedOptions{name: chosen, tty: isInteractive()}, gio)
			if err != nil {
				return err
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			env, err := createIdentityWithDevice(c, finalName, email, deviceID)
			if err != nil {
				return err
			}
			if err := maybePinWallet(c, env, wallet, walletChain); err != nil {
				return err
			}
			// - under --json, emit the VERBATIM op:identity envelope (agent/address/
			// fqdn/ptr/state) to STDOUT so a programmatic caller (the whisper-id SDKs'
			// register()) can JSON-parse it; the human one-liner stays on stderr. This
			// mirrors the --register path, which already routes through renderEnvelope.
			// --json wins over --quiet (same precedence as --register).
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			choice := identityChoice(env, finalName)
			if g.quiet {
				if choice.addr != "" {
					fmt.Fprintln(os.Stdout, choice.addr)
				}
				return nil
			}
			if choice.addr != "" {
				fmt.Fprintf(os.Stderr, "whisper: created %s - %s\n", choice.name, choice.addr)
			} else {
				fmt.Fprintf(os.Stderr, "whisper: created %s\n", choice.name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the agent's human name (required; maps to the server's friendly label)")
	cmd.Flags().StringVar(&label, "label", "", "legacy alias for --name (--name wins)")
	cmd.Flags().StringVar(&email, "email", "", "public contact email (opt-in; surfaced in RDAP)")
	cmd.Flags().BoolVar(&register, "register", false, "mint a NEW agent + its own API key (op:register)")
	ids.register(cmd)
	cmd.Flags().StringVar(&wallet, "wallet", "", "pin an x402 wallet (EOA) to the new /128 as a resolvable TXT binding (op:host)")
	cmd.Flags().StringVar(&walletChain, "wallet-chain", "", "the wallet's chain id for --wallet (e.g. eip155:8453)")
	_ = cmd.Flags().MarkHidden("label") // --name is the documented spelling
	return cmd
}

// identifierFlags holds the mutually-exclusive typed-identity flags (automotive/telecom/
// energy/health/OT/content/commerce verticals). Each is a domain-specific identifier the object
// ALREADY carries; resolve() collapses whichever one is set to the single derivation input
// (device_id), so the same VIN / NF-Instance-ID / LFDI / UDI / ApplicationUri / C2PA serial /
// agent id always derives the SAME routable /128 (a deterministic identity, not a fresh alloc).
type identifierFlags struct {
	vin          string
	ecuSerial    string
	nfInstanceID string
	lfdi         string
	udi          string
	appURI       string
	c2paSerial   string
	agentID      string
}

// register binds every typed-identity flag (and its documented aliases) onto cmd. Aliases exist
// because callers reach for the term their own domain uses (Postel: liberal in what we accept);
// they all feed the one derivation input.
func (f *identifierFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.vin, "vin", "", "derive the /128 from a vehicle VIN (automotive)")
	cmd.Flags().StringVar(&f.ecuSerial, "ecu-serial", "", "an ECU serial to combine with --vin (automotive)")
	cmd.Flags().StringVar(&f.nfInstanceID, "nf-instance-id", "", "derive the /128 from a 5G NF Instance ID (telecom)")
	cmd.Flags().StringVar(&f.lfdi, "lfdi", "", "derive the /128 from an IEEE 2030.5 LFDI (energy / DER)")
	cmd.Flags().StringVar(&f.udi, "udi", "", "derive the /128 from a medical-device UDI / FHIR endpoint (health)")
	cmd.Flags().StringVar(&f.appURI, "applicationuri", "", "derive the /128 from an OPC-UA ApplicationUri / MUD url (OT)")
	cmd.Flags().StringVar(&f.c2paSerial, "c2pa-serial", "", "derive the /128 from a C2PA / CAWG signer serial (content)")
	cmd.Flags().StringVar(&f.agentID, "agent-id", "", "derive the /128 from an A2A / AP2 / x402 agent id (commerce)")
	// Aliases (hidden - the canonical spellings above are documented; these accept the term a
	// given ecosystem naturally uses).
	cmd.Flags().StringVar(&f.nfInstanceID, "nf-id", "", "alias of --nf-instance-id")
	cmd.Flags().StringVar(&f.lfdi, "der-serial", "", "alias of --lfdi")
	cmd.Flags().StringVar(&f.udi, "endpoint-id", "", "alias of --udi")
	cmd.Flags().StringVar(&f.appURI, "mud", "", "alias of --applicationuri (a MUD url)")
	cmd.Flags().StringVar(&f.c2paSerial, "cawg", "", "alias of --c2pa-serial (a CAWG identity)")
	for _, a := range []string{"nf-id", "der-serial", "endpoint-id", "mud", "cawg"} {
		_ = cmd.Flags().MarkHidden(a)
	}
}

// resolve returns the single derivation input (device_id) from whichever typed-identity flag is
// set, or "" when none is. It REFUSES more than one (they are mutually exclusive - an object has
// ONE identity), with a clear error naming the conflict (Postel: never an opaque failure). VIN +
// ECU serial is the one legitimate pair: they combine into a single deterministic ECU identity.
func (f *identifierFlags) resolve() (string, error) {
	type pick struct {
		flag, val string
	}
	var set []pick
	if v := strings.TrimSpace(f.vin); v != "" {
		id := v
		if s := strings.TrimSpace(f.ecuSerial); s != "" {
			id = "vin:" + v + ";ecu:" + s // deterministic per-ECU identity
		}
		set = append(set, pick{"--vin", id})
	} else if strings.TrimSpace(f.ecuSerial) != "" {
		return "", usageErr("--ecu-serial needs --vin (the ECU is identified within its vehicle)")
	}
	if v := strings.TrimSpace(f.nfInstanceID); v != "" {
		set = append(set, pick{"--nf-instance-id", v})
	}
	if v := strings.TrimSpace(f.lfdi); v != "" {
		set = append(set, pick{"--lfdi", v})
	}
	if v := strings.TrimSpace(f.udi); v != "" {
		set = append(set, pick{"--udi", v})
	}
	if v := strings.TrimSpace(f.appURI); v != "" {
		set = append(set, pick{"--applicationuri", v})
	}
	if v := strings.TrimSpace(f.c2paSerial); v != "" {
		set = append(set, pick{"--c2pa-serial", v})
	}
	if v := strings.TrimSpace(f.agentID); v != "" {
		set = append(set, pick{"--agent-id", v})
	}
	switch len(set) {
	case 0:
		return "", nil
	case 1:
		return set[0].val, nil
	default:
		names := make([]string, len(set))
		for i, p := range set {
			names[i] = p.flag
		}
		return "", usageErr("only ONE typed identity may be given, got: %s", strings.Join(names, ", "))
	}
}

// createAgent is THE single place that creates a named identity . It is used by the
// guided flow, by `whisper create`, and (indirectly) by the TUI create modal validation.
// It REJECTS an empty/blank/whitespace name with a clear usage error - every agent has a
// human name, no exceptions. The name maps to the server's friendly label (what op:list
// and RDAP surface). Returns the created agent's (name, address) for a one-line report.
func createAgent(c *client.Client, name string) (agentChoice, error) {
	return createAgentWithContact(c, name, "")
}

// createAgentWithContact is createAgent plus an optional opt-in contact email (surfaced in
// RDAP). Splitting it keeps createAgent's signature exactly as specified while the
// `create` command can still pass --email.
func createAgentWithContact(c *client.Client, name, email string) (agentChoice, error) {
	env, err := createIdentity(c, name, email)
	if err != nil {
		return agentChoice{}, err
	}
	if perr := envelopeError(env); perr != nil {
		return agentChoice{}, perr
	}
	return identityChoice(env, strings.TrimSpace(name)), nil
}

// createIdentity fires the op:identity wire call and returns the RAW envelope, exactly as
// client.Agents does - only a transport error is returned here; a server-reported ok:false
// lives in the envelope. Splitting the call out from the (name,address) projection lets
// `create` emit the machine JSON envelope VERBATIM to STDOUT under --json while the
// human one-liner stays on stderr. A blank name never reaches the server.
func createIdentity(c *client.Client, name, email string) (*client.Envelope, error) {
	return createIdentityWithDevice(c, name, email, "")
}

// createIdentityWithDevice is createIdentity plus an optional deviceID: when non-empty it is
// passed as the derivation's device_id so the /128 is DETERMINISTICALLY derived from the object's
// own identifier (VIN / NF-Instance-ID / LFDI / UDI / ApplicationUri / C2PA serial / agent id)
// rather than freshly allocated - the same identifier always yields the same address.
func createIdentityWithDevice(c *client.Client, name, email, deviceID string) (*client.Envelope, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return nil, usageErr("--name is required to create an agent")
	}
	args := map[string]any{"label": n}
	if e := strings.TrimSpace(email); e != "" {
		args["contact_email"] = e
	}
	if d := strings.TrimSpace(deviceID); d != "" {
		args["device_id"] = d
	}
	cx, cancel := ctx()
	defer cancel()
	return c.Agents(cx, "identity", args)
}

// maybePinWallet, when --wallet is set, publishes a resolvable TXT binding tying an x402 wallet
// (an EOA) to the just-created agent's /128, via the SAME op:host record path `whisper` already
// uses. The binding lives at `_x402.<agent-label> TXT "x402-wallet=<wallet>[;chain=<chain>];
// agent=<addr>"`, a RELATIVE name that lands inside the caller's own served, DNSSEC-signed zone
// (the agent's identity fqdn may sit in a BYOD apex the caller cannot write host records into, so
// we anchor the binding under the caller's control subtree - the label is the agent fqdn's first
// label, which is reconstructable from the /128's PTR). It is ADDITIVE: the identity is already
// created; a wallet-pin failure is surfaced clearly and never rolls the identity back. A blank
// wallet is a no-op.
//
// Honest scope: this publishes the wallet<->/128 association as a signed-zone (DNSSEC) TXT record a
// facilitator can resolve keyless. A cryptographically SIGNED binding (the agent signing the
// statement with its identity key) is the stronger form documented in the commerce recipes; this
// command publishes the resolvable association record that a facilitator verifies against the
// DANE-pinned identity.
func maybePinWallet(c *client.Client, env *client.Envelope, wallet, chain string) error {
	w := strings.TrimSpace(wallet)
	if w == "" {
		return nil
	}
	if env == nil || env.Result == nil {
		return &client.ProblemError{Status: 500, Detail: "cannot pin a wallet: the identity result was empty"}
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return &client.ProblemError{Status: 500, Detail: "cannot pin a wallet: no identity was returned to bind it to"}
	}
	fqdn := trimDot(field(recs[0], "fqdn"))
	addr := field(recs[0], "address", "addr128")
	label := firstLabel(fqdn)
	if label == "" {
		return &client.ProblemError{Status: 500, Detail: "cannot pin a wallet: the identity has no name to anchor the binding"}
	}
	value := "x402-wallet=" + w
	if ch := strings.TrimSpace(chain); ch != "" {
		value += ";chain=" + ch
	}
	if addr != "" {
		value += ";agent=" + addr
	}
	// A RELATIVE op:host name (no trailing dot) is placed under the caller's own control subtree
	// (t<hash>.agents.whisper.online) - always writable, unlike a BYOD identity apex.
	owner := "_x402." + label
	args := map[string]any{"name": owner, "type": "TXT", "value": value, "ttl": 300}
	cx, cancel := ctx()
	defer cancel()
	henv, err := c.Agents(cx, "host", args)
	if err != nil {
		return err
	}
	if perr := envelopeError(henv); perr != nil {
		return perr
	}
	if !g.quiet && !g.jsonOut {
		bound := owner
		if hr := henv.Result.Records(); len(hr) > 0 {
			if f := trimDot(field(hr[0], "fqdn")); f != "" {
				bound = f
			}
		}
		fmt.Fprintf(os.Stderr, "whisper: pinned wallet %s -> %s  (TXT %s)\n", w, orDash(addr), bound)
	}
	return nil
}

// firstLabel returns the first DNS label of an fqdn (the per-agent leftmost label), trimming a
// trailing dot and surrounding space. Empty in => empty out.
func firstLabel(fqdn string) string {
	s := trimDot(strings.TrimSpace(fqdn))
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}

// identityChoice projects an op:identity envelope to the (name,address) summary used for the
// one-line human report, falling back to the requested name when the server echoed no label.
func identityChoice(env *client.Envelope, name string) agentChoice {
	recs := env.Result.Records()
	if len(recs) == 0 {
		return agentChoice{name: name}
	}
	addr := field(recs[0], "address", "addr128")
	disp := field(recs[0], "label")
	if disp == "" {
		disp = name
	}
	return agentChoice{name: disp, addr: addr}
}

// firstNonBlank returns the first argument that is non-blank after trimming, else "".
func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func renderCreated(res *client.Result, register bool) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no result from the control plane")
		return
	}
	rec := recs[0]
	fmt.Fprintln(os.Stderr, "whisper: identity ready")
	if v := field(rec, "agent"); v != "" {
		fmt.Fprintf(os.Stderr, "  agent    %s\n", v)
	}
	fmt.Fprintf(os.Stderr, "  address  %s\n", field(rec, "address"))
	if v := field(rec, "fqdn"); v != "" {
		fmt.Fprintf(os.Stderr, "  name     %s\n", trimDot(v))
	}
	if v := field(rec, "ptr"); v != "" {
		fmt.Fprintf(os.Stderr, "  ptr      %s\n", trimDot(v))
	}
	if v := field(rec, "state"); v != "" {
		fmt.Fprintf(os.Stderr, "  state    %s\n", v)
	}
	if register {
		if k := field(rec, "api_key"); k != "" {
			// The key is shown ONCE - print it to STDOUT (so it is capturable) with a loud note.
			fmt.Fprintln(os.Stderr, "  API KEY (shown once - store it now):")
			fmt.Fprintln(os.Stdout, k)
		}
	}
}

// --- kill <agent|address> --------------------------------------------------------

func newKillCmd() *cobra.Command {
	var yes, full bool
	cmd := &cobra.Command{
		Use:   "kill <agent|address>",
		Short: "Release an identity (IRREVERSIBLE) - or --revoke an agent's Whisper access",
		Long: "Release the caller's own /128 identity (op:identity release) - IRREVERSIBLE.\n" +
			"With --revoke (admin:dns), revoke an agent: withdraw its /128, PTR and egress\n" +
			"tokens and refuse its control-plane access (op:revoke). The API key is a Whisper\n" +
			"API key managed by Whisper auth and is NOT deleted. Confirms unless --yes; in a\n" +
			"non-interactive run --yes is required (we refuse to destroy without confirmation).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if !yes {
				if !isInteractive() {
					return fmt.Errorf("refusing to release %q without confirmation in a non-interactive run - pass --yes", target)
				}
				fmt.Fprintf(os.Stderr, "whisper: release %q? this is IRREVERSIBLE - type the target to confirm: ", target)
				if !confirm(target) {
					fmt.Fprintln(os.Stderr, "whisper: aborted - nothing released")
					return nil
				}
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()

			var op string
			var a map[string]any
			if full {
				op, a = "revoke", map[string]any{"agent": target}
			} else {
				op = "identity"
				a = map[string]any{"release": true}
				if looksLikeV6(target) {
					a["address"] = target
				} else {
					// op:identity release wants the address; resolve the id via list if needed.
					addr, rerr := resolveAddress(c, target)
					if rerr != nil {
						return rerr
					}
					a["address"] = addr
				}
			}
			env, err := c.Agents(cx, op, a)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderKilled(env.Result, target)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&full, "revoke", false, "revoke the agent: withdraw its /128, PTR & tokens and refuse its access (op:revoke; admin:dns)")
	return cmd
}

func renderKilled(res *client.Result, target string) {
	recs := res.Records()
	st := "submitted"
	if len(recs) > 0 {
		if v := field(recs[0], "status", "state"); v != "" {
			st = v
		}
	}
	fmt.Fprintf(os.Stderr, "whisper: %s - %s\n", target, st)
}

// resolveAddress maps an agent id to its /128 address via op:list (confined to the
// caller's tenant). Returns a clean not-found error for a foreign/unknown id.
func resolveAddress(c *client.Client, target string) (string, error) {
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if err != nil {
		return "", err
	}
	if perr := envelopeError(env); perr != nil {
		return "", perr
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if field(item, "agent", "id", "label") == target || field(item, "address", "addr128") == target {
			if addr := field(item, "address", "addr128"); addr != "" {
				return addr, nil
			}
		}
	}
	return "", &client.ProblemError{Status: 404, Detail: fmt.Sprintf("agent %q not found in your account", target)}
}

// --- small helpers ---------------------------------------------------------------

func looksLikeV6(s string) bool {
	// A /128 we care about has a colon; an agent id ("agent-…") never does.
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}

func parseEpoch(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func humanTime(s string) string {
	n := parseEpoch(s)
	if n == 0 {
		return s
	}
	// Heuristic: > 1e12 is epoch-ms, else epoch-s.
	if n > 1_000_000_000_000 {
		return time.UnixMilli(n).UTC().Format("2006-01-02 15:04")
	}
	return time.Unix(n, 0).UTC().Format("2006-01-02 15:04")
}

// agentDomain returns the zone an agent's FQDN sits under - its parent domain, i.e. the
// FQDN minus its first (per-agent) label. This is what distinguishes a hosted identity
// ("agents.whisper.online") from a BYOD-domain one ("example.com"). Liberal in what it
// reads (trailing dot or not, empty in → empty out); a bare apex with no dot returns the
// FQDN itself (it IS the zone).
func agentDomain(fqdn string) string {
	s := trimDot(strings.TrimSpace(fqdn))
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '.'); i >= 0 && i+1 < len(s) {
		return s[i+1:]
	}
	return s
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orVal(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// confirm reads one line and reports whether it equals want.
func confirm(want string) bool {
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	return line == want
}
