// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// agent_pick.go decides which agent a connect-shaped command (run, claude, connect, ip and the
// enforced run) binds when the person may or may not have named one.
//
// The rule it replaced: a command with no --agent, no project config and no saved agent file sent
// op:connect with NO selector, and the control plane chose. It chose differently per tier. A
// keyless connect (socks5) took the account's newest identity; a routed connect (wireguard), which
// carries this host's identity key, took the identity pinned to that key, else the one unclaimed
// identity, else the newest unclaimed one. So an owner key holding several agents ran a command
// from whichever agent that happened to be, and on the WireGuard tier replaced its peer, cutting
// off whatever else held that agent's tunnel. On top of it `run` accepted --create and --name
// (they are global flags) and never read them.
//
// The rule now, in precedence order:
//
//  1. --agent names an agent: use it.
//  2. --create makes a new agent called --name. --name alone uses the agent of that name; naming
//     none, it is the name rung 7 gives the agent it creates. The same two flags mean the same on
//     bare `whisper` (decideFlagSelection), which has no rungs 3 to 6 and so creates it.
//  3. The project's .whisper/config, when the command reads one (run, claude).
//  4. This host's saved agent (~/.config/whisper/agent, or --agent-file).
//  5. A `whisper connect` already running on this host, proved to egress as its /128 (run).
//  6. The one agent of the account whose published identity key is a key this host holds
//    : a host that kept its key but lost its saved agent file gets its own agent back,
//     and nothing else. Only a published pin counts, never a key file alone.
//  7. Otherwise a NEW agent for this host. An existing agent of the account is never picked for
//     a person who did not name it: on the WireGuard tier that would replace its peer.
//
// Rungs 5 to 7 say which agent was used or created, by name, and the success line of every
// connect names the agent it bound, so nothing is chosen silently.

// pickSource is where the agent a command binds came from.
type pickSource string

const (
	pickFlag    pickSource = "flag"    // --agent
	pickNamed   pickSource = "name"    // --name matched an agent the account has
	pickProject pickSource = "project" // the project's .whisper/config
	pickFile    pickSource = "file"    // this host's saved agent file
	pickSession pickSource = "session" // a proved `whisper connect` already running on this host
	pickCreated pickSource = "created" // made by this command
	pickOwn     pickSource = "own"     // the key's own sole identity (keysOwnSoleAgent)
	// pickProjectUnvouched: a project's .whisper/config this user's `whisper init` did not write
	// (project_trust.go). It selects its agent, but it is not the person's choice until they say
	// so, and projectGate keeps it off the WireGuard tier until then.
	pickProjectUnvouched pickSource = "project-unvouched"
	pickHeldKey          pickSource = "key" // pinned to an identity key this host holds (heldKeyAgent)
)

// explicit reports whether the person named this agent on the command line or in the project's
// config. Only an explicit selection may replace an existing agent's WireGuard peer, and the run
// says so first (peerReplacementNote). The key's own sole identity counts too: it is not someone
// else's agent, but another host using the same key may hold its tunnel.
func (s pickSource) explicit() bool {
	return s == pickFlag || s == pickNamed || s == pickProject || s == pickOwn
}

// agentPickOpts is what one command asked for, plus how that command behaves at each rung.
type agentPickOpts struct {
	agent     string // --agent
	agentFile string // --agent-file ("" = the default file)
	create    bool   // --create
	name      string // --name
	email     string // --email (connect), the created agent's contact
	// useProject: read the project's .whisper/config at rung 3 (run and claude do).
	useProject bool
	// defaultNames names an agent created at rung 7 when --name was not given: the first is the
	// name it gets, and an agent already carrying any of them is not adopted (it is refused). nil
	// keeps the mandatory-name rule: a terminal prompts, a script is told to pass --name.
	defaultNames func() []string
	// hostSession is rung 5; nil skips it. A session it returns is used as is, with no op:connect.
	hostSession func() (*egressSession, error)
	// noCreate: this command never creates on its own (ip, whale serve, the enforced run). Rung 7
	// becomes a refusal naming the fix; --create and --name still create when given.
	noCreate bool
	// nameless: the command takes no --name (ip, whale serve), so its refusal does not offer one.
	nameless bool
	// noSave: never write the saved agent file. The enforced run runs as root, and root's file is
	// not the one the invoking user's next command reads.
	noSave bool
	// command is how messages name the command ("whisper run").
	command string
	// trustFile is where this user's vouched-for projects are recorded ("" = the default file
	// beside the saved agent file). The enforced run, which runs as root, points it at the
	// invoking user's file.
	trustFile string
}

// agentPick is the decision. sel is what op:connect understands (a /128 or an id); it is empty
// only when session is set.
type agentPick struct {
	sel         string
	name        string
	source      pickSource
	projectTier string // rung 3: the project's pinned tier
	// projectRoot and projectAgent: rung 3's project directory and the agent its config names, kept
	// so projectGate can name the file and remember a yes.
	projectRoot  string
	projectAgent string
	session      *egressSession // rung 5
	// identityGone: the saved agent file named an agent the account no longer has, and the
	// account had none left. connect's refusal record reports it when the create cannot run.
	identityGone bool
}

// display is the agent's name when known, else its selector.
func (p agentPick) display() string {
	return firstNonBlank(p.name, p.sel)
}

// pickAgent runs the rungs above. Every refusal it returns is a clear usage error or the
// listing's own error, never a guess: a listing that did not answer cannot tell an existing
// agent from a free name, so nothing is created on it.
func pickAgent(c *client.Client, o agentPickOpts) (agentPick, error) {
	cmdName := firstNonBlank(o.command, "whisper")
	agent, name := strings.TrimSpace(o.agent), strings.TrimSpace(o.name)
	if o.create && agent != "" {
		return agentPick{}, usageErr("--create makes a new agent and --agent names an existing one: pass one of them, not both")
	}
	if agent != "" && name != "" {
		return agentPick{}, usageErr("--agent and --name both choose the agent: pass one of them, not both")
	}

	// 1. --agent.
	if agent != "" {
		cx, cancel := ctx()
		sel, err := resolveAgentArg(c, cx, agent, false, o.agentFile)
		cancel()
		if err != nil {
			return agentPick{}, err
		}
		return agentPick{sel: sel, name: agentNameFor(agent, sel), source: pickFlag}, nil
	}

	// 2. --create / --name.
	var listed []agentChoice // the listing rung 2 read, reused by rungs 6 and 7
	pendingName := ""        // --name naming no agent: the name rung 7 creates
	unmatched := func(p agentPick) agentPick {
		if pendingName != "" && !g.quiet {
			fmt.Fprintf(os.Stderr, "whisper: no agent is called %s, so using %s; pass --create --name %s to make it\n",
				pendingName, describeAgent(p.name, p.sel), pendingName)
		}
		return p
	}
	if o.create || name != "" {
		choices, err := listForPick(c)
		if err != nil {
			return agentPick{}, err
		}
		d, derr := decideFlagSelection(o.create, name, choices)
		if derr != nil {
			return agentPick{}, derr
		}
		if d.kind == selExisting {
			return agentPick{sel: firstNonBlank(d.choice.addr, d.choice.id, d.choice.name), name: d.choice.name,
				source: pickNamed}, nil
		}
		if o.create {
			// --create with no --name: the mandatory-name rule (a terminal prompts).
			nm, nerr := requireName(guidedOptions{name: d.name, tty: isInteractive() && stdoutIsTTY()}, stdGuidedIO())
			if nerr != nil {
				return agentPick{}, nerr
			}
			if d.name == "" {
				if _, aerr := decideFlagSelection(true, nm, choices); aerr != nil {
					return agentPick{}, aerr // the name typed at the prompt is taken
				}
			}
			return mintForPick(c, o, nm, choices, false, false)
		}
		// --name alone, naming no agent: it is the name an agent created at rung 7 gets. A saved
		// agent or a project still wins, as it always has (an installer that passes --name on every
		// run must not mint a second identity beside the host's saved one), and says so.
		listed, pendingName = choices, d.name
	}

	// 3. The project's .whisper/config. It applies only when no --agent-file was given either,
	// so a file override still means "this file", as it always has.
	if o.useProject && strings.TrimSpace(o.agentFile) == "" {
		root, cfg, derr := discoverProjectConfig()
		switch {
		case derr == nil:
			if v := strings.TrimSpace(cfg.Agent); v != "" {
				cx, cancel := ctx()
				sel, err := resolveAgentArg(c, cx, v, false, o.agentFile)
				cancel()
				if err != nil {
					return agentPick{}, err
				}
				p := agentPick{sel: sel, name: agentNameFor(v, sel), source: pickProject, projectTier: cfg.Tier,
					projectRoot: root, projectAgent: v}
				switch saved := client.ReadAgentFile(o.agentFile); {
				case saved != "" && (sameIP(saved, sel) || saved == sel):
					p.source = pickFile // the project names this host's own saved agent: not a takeover
				case !projectTrusted(o.trustFile, root, v):
					// Nothing outside the project says this user wrote it: a cloned repository can
					// ship one. Its tier pin came from the same file, so it is not honoured.
					p.source, p.projectTier = pickProjectUnvouched, ""
				}
				return unmatched(p), nil
			}
		case isProjectNotFound(derr):
			// no project here: carry on down the rungs
		default:
			// A project exists but its config cannot be read. Carry on (never block the run), and
			// say so, because the identity may not be the one the project meant.
			if !g.quiet {
				fmt.Fprintf(os.Stderr, "whisper: project .whisper/config unreadable (%v) - not using it\n", derr)
			}
		}
	}

	// 4. This host's saved agent.
	gone := false
	if saved := client.ReadAgentFile(o.agentFile); saved != "" {
		sel, savedName, err := resolveSavedAgent(c, saved, o.agentFile)
		if err != nil {
			return agentPick{}, err
		}
		if sel != "" {
			// The success line names it ("Connected as <name>"), so a saved agent is never silent.
			return unmatched(agentPick{sel: sel, name: savedName, source: pickFile}), nil
		}
		gone = true // proven gone, and the account has no agents left: rung 7 makes one
	}

	// 5. A connect already running on this host.
	if o.hostSession != nil {
		s, err := o.hostSession()
		if err != nil {
			return agentPick{}, err
		}
		if s != nil {
			p := unmatched(agentPick{sel: s.addr, name: s.name, source: pickSession, session: s})
			if !g.quiet && pendingName == "" {
				fmt.Fprintf(os.Stderr, "whisper: no agent was named, so using %s, which a running `whisper connect` on this host already holds\n",
					describeAgent(p.name, p.sel))
			}
			return p, nil
		}
	}

	choices := listed
	if choices == nil {
		var err error
		if choices, err = listForPick(c); err != nil {
			return agentPick{identityGone: gone}, err
		}
	}

	// 6. The agent pinned to an identity key this host holds.
	if p, ok, err := heldKeyAgent(c, o, choices); err != nil {
		return agentPick{identityGone: gone}, err
	} else if ok {
		return unmatched(p), nil
	}

	// 7. A new agent for this host.
	if o.noCreate && pendingName == "" {
		return agentPick{identityGone: gone}, nothingNamedRefusal(cmdName, choices, !o.nameless)
	}
	nm := pendingName
	taken := []string{nm}
	if nm == "" && o.defaultNames != nil {
		if names := o.defaultNames(); len(names) > 0 {
			nm, taken = strings.TrimSpace(names[0]), names
		}
	}
	if nm == "" {
		if len(choices) != 0 && !(isInteractive() && stdoutIsTTY()) {
			// A script with agents in the account and nothing named: the fix is a choice only the
			// person can make, so name both of them rather than the bare "--name is required".
			return agentPick{identityGone: gone}, nothingNamedRefusal(cmdName, choices, !o.nameless)
		}
		var nerr error
		if nm, nerr = requireName(guidedOptions{tty: isInteractive() && stdoutIsTTY()}, stdGuidedIO()); nerr != nil {
			return agentPick{identityGone: gone}, nerr
		}
	}
	{
		for _, alias := range append([]string{nm}, taken...) {
			if ch, ok := choiceNamed(choices, alias); ok && strings.TrimSpace(alias) != "" {
				// An agent already carries this host's name. It is probably this host's, but nothing
				// here proves it, and adopting it unasked is the takeover this rule exists to stop.
				label := firstNonBlank(ch.name, alias)
				return agentPick{identityGone: gone}, usageErr("no agent was named and none is saved for this host, and your account already has an agent "+
					"called %s (%s). If it is this host's, use it with --agent %s and keep it with 'whisper use %s'; "+
					"to make a new one instead, pass --name {name}",
					label, orDash(ch.addr), label, label)
			}
		}
	}
	p, merr := mintForPick(c, o, nm, choices, true, gone)
	if merr != nil {
		if pendingName != "" {
			// --name named an agent that does not exist and this key may not make it. The
			// person named an agent, so a different one is never bound in its place, not even the
			// key's own: that is the same refusal --create --name gives, plus what it could use.
			return agentPick{identityGone: gone}, namedAgentCannotBeCreated(pendingName, choices, merr)
		}
		// An agent's own key may not register, and its listing is its own one identity: that is
		// not someone else's agent, it is the only one this key can be. Only when nothing was
		// named: a name no agent carries is created or refused here, never swapped for the key's
		// own. Rungs 3 to 6 still prefer this host's project, saved agent, key or
		// running session over creating one, and say so (unmatched).
		if own, ok := keysOwnSoleAgent(c, choices, merr); ok {
			if !g.quiet {
				fmt.Fprintf(os.Stderr, "whisper: this key cannot create agents, and its only agent is its own, so using %s\n",
					describeAgent(own.name, own.sel))
			}
			return own, nil
		}
		return agentPick{identityGone: gone}, merr
	}
	return p, nil
}

// keysOwnSoleAgent is the one case where an agent nobody named is still bound: the key may not
// register, the account lists exactly one agent, and the control plane says every agent of this
// key files under the key's OWN handle (agent_tenants 0). That is an agent key and its one /128,
// or an owner key and its own identity: never an agent registered for something else, which
// files under its own handle. Anything unproven (the read fails, the count is absent) is no.
func keysOwnSoleAgent(c *client.Client, choices []agentChoice, mintErr error) (agentPick, bool) {
	var refused *registerRefusedError
	if !errors.As(mintErr, &refused) || len(choices) != 1 {
		return agentPick{}, false
	}
	ch := choices[0]
	if ch.addr == "" {
		return agentPick{}, false
	}
	cx, cancel := ctx()
	defer cancel()
	_, others, err := callerTenant(cx, c)
	if err != nil || others == nil || *others != 0 {
		return agentPick{}, false
	}
	return agentPick{sel: ch.addr, name: ch.name, source: pickOwn}, true
}

// namedAgentCannotBeCreated is the answer when --name names no agent of the account and the
// mint that would make it failed. A register refusal becomes the same usage error --create --name
// gives (exit 2, nothing connected), led by the fact the person needs first: no agent has that
// name. It then names the agents this key can use, so the fix is one paste. Any other mint
// failure (a listing or transport fault) is returned as it was.
func namedAgentCannotBeCreated(name string, choices []agentChoice, mintErr error) error {
	var refused *registerRefusedError
	if !errors.As(mintErr, &refused) {
		return mintErr
	}
	msg := fmt.Sprintf("no agent is called %s, so --name %s would create it, and %s", name, name, refused.Error())
	if len(choices) > 0 {
		ordered := append([]agentChoice(nil), choices...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].created > ordered[j].created })
		shown := ordered
		if len(shown) > staleAgentListCap {
			shown = shown[:staleAgentListCap]
		}
		uses := make([]string, 0, len(shown))
		for _, ch := range shown {
			uses = append(uses, fmt.Sprintf("%s (--agent %s)", describeAgent(ch.name, ch.addr), firstNonBlank(ch.id, ch.addr, ch.name)))
		}
		lead := "The agent this key can use: "
		if len(ordered) > 1 {
			lead = "Agents this key can use, newest first: "
		}
		msg += ". " + lead + strings.Join(uses, ", ")
		if rest := len(ordered) - len(shown); rest > 0 {
			msg += fmt.Sprintf(", and %d more ('whisper list' shows them all)", rest)
		}
	}
	return &registerRefusedError{usage: &usageError{msg: msg}}
}

// registerRefusedError is op:register refused for this key. It reads as the usage error it wraps.
type registerRefusedError struct{ usage *usageError }

func (e *registerRefusedError) Error() string { return e.usage.Error() }
func (e *registerRefusedError) Unwrap() error { return e.usage }

// resolveSavedAgent is resolveAgentArg for the saved agent file, also returning the agent's name
// so the note can say it. A saved /128 is checked against the listing exactly as resolveAgentArg
// checks it (a listing that cannot be fetched keeps the selector, a /128 the account does not have
// is staleSavedAgent's), reading the name off the row it matched.
func resolveSavedAgent(c *client.Client, saved, agentFile string) (sel, name string, err error) {
	cx, cancel := ctx()
	defer cancel()
	if !looksLikeV6(saved) {
		sel, err = resolveAgentArg(c, cx, saved, true, agentFile)
		return sel, agentNameFor(saved, sel), err
	}
	choices, known := accountAgents(c, cx, saved)
	if !known {
		sel, err = staleSavedAgent(saved, agentFile, choices)
		return sel, "", err
	}
	if ch, ok := choiceNamed(choices, saved); ok && !sameIP(ch.name, saved) {
		name = ch.name
	}
	return saved, name, nil
}

// selKind is decideFlagSelection's answer.
type selKind int

const (
	selNone     selKind = iota // neither --create nor --name: the command's own default applies
	selExisting                // --name matched an agent the account has
	selCreate                  // make a new agent called name ("" = ask for one)
)

type selDecision struct {
	kind   selKind
	choice agentChoice
	name   string
}

// decideFlagSelection is what --create and --name mean, for bare `whisper` and for run, claude and
// connect alike, so the flags cannot drift between them:
//
//	--create --name X: make X; an agent called X already existing is a clear refusal
//	--create         : make one, asking for the name
//	--name X         : the agent called X; naming none, X is the name of the agent the command
//	                   creates when nothing else selects one
//	neither          : selNone
func decideFlagSelection(create bool, name string, choices []agentChoice) (selDecision, error) {
	name = strings.TrimSpace(name)
	if looksLikeV6(name) {
		// An address selects; it never names a new agent.
		if ch, ok, err := selectAgent(choices, name); err != nil && !create {
			return selDecision{}, err
		} else if ok && !create {
			return selDecision{kind: selExisting, choice: ch}, nil
		}
		return selDecision{}, usageErr("--name %s is an address, and an agent's name cannot be one: "+
			"select an agent by address with --agent %s, or name a new one with letters", name, name)
	}
	switch {
	case create && name == "":
		return selDecision{kind: selCreate}, nil
	case create:
		if _, taken := choiceNamed(choices, name); taken {
			return selDecision{}, nameTakenError(name)
		}
		return selDecision{kind: selCreate, name: name}, nil
	case name != "":
		// Two agents answering to the name is refused, never settled by the listing's order.
		if ch, ok, err := selectAgent(choices, name); err != nil {
			return selDecision{}, err
		} else if ok {
			return selDecision{kind: selExisting, choice: ch}, nil
		}
		return selDecision{kind: selCreate, name: name}, nil
	}
	return selDecision{kind: selNone}, nil
}

// choiceNamed reports whether any agent answers to name (its label, its id or its address), and
// returns the one selectAgent picks. It is for "is this name taken" and display: two agents
// answering to it still means taken, and then the returned choice is the first of them. Anything
// that BINDS the agent it found uses selectAgent, which refuses that tie.
func choiceNamed(choices []agentChoice, name string) (agentChoice, bool) {
	if ch, ok, err := selectAgent(choices, name); err == nil && ok {
		return ch, true
	}
	for _, ch := range choices {
		if choiceMatchesSelector(ch, name) {
			return ch, true
		}
	}
	return agentChoice{}, false
}

func nameTakenError(name string) error {
	return usageErr("--create makes a new agent, and your account already has one called %s: "+
		"use it with --name %s (without --create) or --agent %s, or pick another name", name, name, name)
}

// listForPick is the one listing a decision reads. A listing that did not answer refuses: it
// cannot tell an existing agent from a free name.
func listForPick(c *client.Client) ([]agentChoice, error) {
	cx, cancel := ctx()
	defer cancel()
	return listAgents(c, cx)
}

// mintForPick creates the agent called name and, when this host had no saved agent, saves it so
// the next command on this host binds the same one.
func mintForPick(c *client.Client, o agentPickOpts, name string, choices []agentChoice, hostDefault, savedGone bool) (agentPick, error) {
	created, err := mintAgent(c, name, o.email, len(choices) != 0)
	if err != nil {
		return agentPick{}, err
	}
	sel := firstNonBlank(created.addr, created.id, created.name)
	p := agentPick{sel: sel, name: firstNonBlank(created.name, name), source: pickCreated}
	if created.born {
		// its first routed connect publishes this host's key, and only for an agent this call minted:
		// an op:identity that handed back an identity the key already held is not a birth
		markNewborn(created.addr)
	}
	saved := false
	// Saved when this host had no agent, or its saved one was proven gone: a stale file left in
	// place would be refused by the very next command.
	if !o.noSave && (savedGone || client.ReadAgentFile(o.agentFile) == "") {
		if serr := client.SaveAgent(o.agentFile, sel); serr != nil {
			debugf("could not save the agent selector (%v); the next command will not know this host's agent", serr)
		} else {
			saved = true
		}
	}
	if !g.quiet {
		why := "created agent " + describeAgent(p.name, created.addr)
		switch {
		case hostDefault && savedGone:
			why = "this host's saved agent is gone, so " + why + " for it"
		case hostDefault:
			why = "no agent was named and none is saved for this host, so " + why + " for it"
		}
		if n := len(choices); n > 0 {
			why += fmt.Sprintf("; your account's %d other %s left alone", n, plural(n, "agent was", "agents were"))
		}
		if saved {
			why += "; later commands on this host use it"
		} else if hostDefault || o.create || strings.TrimSpace(o.name) != "" {
			why += fmt.Sprintf("; this host's saved agent is unchanged ('whisper use %s' makes this one the default)", p.name)
		}
		fmt.Fprintf(os.Stderr, "whisper: %s\n", why)
	}
	return p, nil
}

// mintAgent makes a genuinely new agent. op:identity answers "this key's own /128": on an account
// that already holds one it hands that one back, so on such an account a create through it would
// bind an existing agent under a new name, the takeover again. There op:register mints instead,
// and a key that may not register is refused, never quietly given an existing agent.
func mintAgent(c *client.Client, name, email string, accountHasAgents bool) (agentChoice, error) {
	if !accountHasAgents {
		return createAgentWithContact(c, name, email)
	}
	args := map[string]any{"label": name}
	if e := strings.TrimSpace(email); e != "" {
		args["contact_email"] = e
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := mintVia(cx, c, args)
	if err == nil {
		err = envelopeError(env)
	}
	if err != nil {
		if pe, ok := client.AsProblem(err); ok && isScopeRefusal(pe) {
			return agentChoice{}, &registerRefusedError{usage: &usageError{msg: fmt.Sprintf("this key cannot create an agent (registering one needs "+
				"the account's admin:dns scope), so nothing was connected. Name one of your agents with --agent {agent} "+
				"and keep it for this host with 'whisper use {agent}'. The control plane said: %s", pe.Error())}}
		}
		return agentChoice{}, err
	}
	// The envelope also carries the new agent's own API key, shown once. It is not kept: the
	// owner's key, which made it, connects it.
	recs := env.Result.Records()
	if len(recs) == 0 {
		return agentChoice{}, &client.ProblemError{Status: 502, Detail: fmt.Sprintf("op:register returned no agent for %q, so nothing was connected", name)}
	}
	ch := agentChoice{
		name: firstNonBlank(field(recs[0], "label"), name),
		addr: field(recs[0], "address", "addr128"),
		id:   field(recs[0], "agent", "id"),
		born: true, // op:register always mints a new agent
	}
	if ch.addr == "" && ch.id == "" {
		return agentChoice{}, &client.ProblemError{Status: 502, Detail: fmt.Sprintf("op:register returned no address for %q, so nothing was connected", name)}
	}
	return ch, nil
}

// mintVia is op:register, a seam for tests.
var mintVia = func(cx context.Context, c *client.Client, args map[string]any) (*client.Envelope, error) {
	return c.Agents(cx, "register", args)
}

// nothingNamedRefusal is the answer when a command may not create (ip), or cannot name what it
// would create, and nothing selects an agent. It names the account's newest agents.
func nothingNamedRefusal(cmdName string, choices []agentChoice, takesName bool) error {
	if len(choices) == 0 {
		if !takesName {
			return usageErr("no agent is saved for this host and your account has none yet: make one with 'whisper create --name {name}'")
		}
		return usageErr("no agent is saved for this host and your account has none yet: make one with 'whisper create --name {name}', "+
			"or run '%s --name {name}'", cmdName)
	}
	ordered := append([]agentChoice(nil), choices...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].created > ordered[j].created })
	shown := ordered
	if len(shown) > staleAgentListCap {
		shown = shown[:staleAgentListCap]
	}
	names := make([]string, 0, len(shown))
	for _, ch := range shown {
		names = append(names, firstNonBlank(ch.name, ch.addr, ch.id))
	}
	listing := strings.Join(names, ", ")
	if rest := len(ordered) - len(shown); rest > 0 {
		listing += fmt.Sprintf(", and %d more ('whisper list' shows them all)", rest)
	}
	make := "--name {name}"
	if !takesName {
		make = "'whisper create --name {name}'"
	}
	return usageErr("no agent was named and none is saved for this host, so %s did not pick one of your account's agents for you. "+
		"Name one with --agent {agent} (keep it for this host with 'whisper use {agent}'), or make a new one with %s. "+
		"Your agents, newest first: %s", cmdName, make, listing)
}

// peerReplacementNote is said before a routed (WireGuard) connect binds an EXISTING agent the
// person selected: the box keeps one peer per /128, so this run's key takes over the agent's
// tunnel wherever else it is held. "" when there is nothing to say: a created agent has no other
// peer, a session reused on this host is not replaced, the saved agent is this host's own, and
// the socks5 tier replaces no peer.
func peerReplacementNote(p agentPick, tier string) string {
	if p.session != nil || !p.source.explicit() || !(isAutoTier(tier) || isWireGuardTier(tier)) {
		return ""
	}
	return fmt.Sprintf("whisper: binding a WireGuard peer for %s replaces the one any other host holds for it; "+
		"that host's tunnel stops until it reconnects", describeAgent(p.name, p.sel))
}

// describeAgent renders "name (addr)", or whichever half is known.
func describeAgent(name, addr string) string {
	name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
	switch {
	case name != "" && addr != "" && !sameIP(name, addr) && name != addr:
		return name + " (" + addr + ")"
	case name != "":
		return name
	default:
		return orDash(addr)
	}
}

// agentNameFor keeps the name a person typed when it is a name, not an address.
func agentNameFor(typed, sel string) string {
	if looksLikeV6(typed) || typed == sel {
		return ""
	}
	return typed
}
