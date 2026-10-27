// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// enroll.go - ONE verb that binds THIS host to a routable Whisper /128.
//
// The bind used to be implemented in shell, once per installer, and zero times in Go: each
// walked the same ladder (register --reuse, fall back to identity) and each hand-wrote the
// marker that client.ReadBoundFile parses. Several producers, one consumer, no shared code,
// so a fix to one silently missed the others - and a host installed by any other route (a
// hand-run `whisper create`, a config-management module, an image bake) got no marker at
// all and reported nothing.
//
// So the ladder lives here now, once, and the installers call it.

// enrollResult is what a bind attempt settled on, for reporting and for the marker.
type enrollResult struct {
	mode    string // "register" (minted or reused a named agent) or "identity" (this key's own /128)
	addr    string
	name    string // the FCrDNS name, when the envelope carried one
	agent   string
	reused  bool
	already bool // an existing marker already bound this host; nothing was called
	// replacedAgent is the saved agent selector a forced re-bind replaced, because it was the
	// previous binding or the account no longer had it. Empty when the file was left alone.
	replacedAgent string
	// replacedGone: the saved agent was replaced because the account no longer has it, not
	// because it was the previous binding.
	replacedGone bool
	// fromMarker: a forced re-bind kept the identity the marker recorded, because the account
	// still has it, rather than looking one up by name.
	fromMarker bool
	// target is where the bind was recorded. target.service is a bind written into the host
	// service's own profile from an administrator's shell.
	target identityTarget
	// keyCarried: the key this run bound with was written to the service's profile, which had
	// none, so the sensor can report with it.
	keyCarried bool
	// keyFrom names the sudo invoker whose key was carried, when it was theirs.
	keyFrom string
}

func newEnrollCmd() *cobra.Command {
	var name string
	var force, preview bool
	var confirm string
	cmd := &cobra.Command{
		Use:     "enroll",
		Aliases: []string{"bind"},
		Short:   "Bind this host to its routable Whisper /128 (idempotent)",
		Long: "Give THIS machine a Whisper identity and record it, so everything that needs to\n" +
			"know which /128 the host answers as - the sensor's uplink, `whisper connect`,\n" +
			"the uninstaller's revoke - can simply read it.\n\n" +
			"Idempotent by design. A host that is already bound prints what it is bound to and\n" +
			"exits 0; re-running after an upgrade, a re-image, or a lost marker re-finds the\n" +
			"same agent rather than minting a duplicate /128 (which would strand the old\n" +
			"identity and move the telemetry with it).\n\n" +
			"The ladder, in order: reuse the agent already registered under this host's name;\n" +
			"else mint a new agent + key under it; else fall back to this key's own /128 via\n" +
			"op:identity. A key that cannot register (no scope) still ends up bound. The host's\n" +
			"name drops a trailing .local, .localdomain or .lan; an agent registered under the\n" +
			"full name is still reused. If the account's agents cannot be read, enroll changes\n" +
			"nothing and says so, rather than register a second identity on a guess.\n\n" +
			"--force re-binds even when a marker exists. With no --name it keeps this device's\n" +
			"own identity (the one the marker records) whenever the account still has it, under\n" +
			"whatever label, and looks further only when the account no longer has it, which is\n" +
			"how a device whose identity was removed gets a new one. It also replaces the\n" +
			"saved agent (~/.config/whisper/agent) when that names the old identity or one the\n" +
			"account no longer has, so `whisper connect` binds this identity; an agent you\n" +
			"picked that is still in the account is left alone.\n\n" +
			"Writes ~/.config/whisper/bound (mode/address/name/agent/bound_at - no secrets).\n\n" +
			"With the sensor or connection unit installed on Linux or macOS, the bind is\n" +
			"recorded where that unit reads it: the HOME its registration names. When that is\n" +
			"not this shell's home, enroll binds there only if this account owns it, and\n" +
			"otherwise refuses and names the sudo line that does. Under sudo, a root context\n" +
			"with no API key is given the invoking user's.\n\n" +
			"On Windows with the sensor service installed, the bind is recorded where that\n" +
			"service reads it: the LocalSystem profile. Run from an elevated PowerShell, enroll\n" +
			"writes the marker there, readable by LocalSystem and Administrators only, and gives\n" +
			"the service the API key it bound with when it has none. From any other shell it\n" +
			"refuses and says so, rather than bind into a profile the sensor never reads.\n\n" +
			"To see first what --force would do, run it in two steps. --preview reads the account\n" +
			"and prints the plan (bind this device's own identity again, use an agent already\n" +
			"registered under this host's name, or register a new one) and changes nothing.\n" +
			"--confirm with the token it printed does exactly that plan, and does nothing if\n" +
			"anything it would act on has changed since. Unlike a bare --force, a confirm never\n" +
			"falls back to this key's own address. Pass - to read the token from stdin.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			confirmSet := cmd.Flags().Changed("confirm")
			if err := enrollFixFlagsError(preview, confirm, confirmSet); err != nil {
				return err
			}
			if preview || confirmSet {
				return runEnrollFixCmd(cmd, strings.TrimSpace(name), preview, confirm)
			}
			res, err := runEnroll(strings.TrimSpace(name), force)
			if err != nil {
				return err
			}
			if g.quiet {
				// --quiet: ONLY the load-bearing value.
				if res.addr != "" {
					fmt.Fprintln(os.Stdout, res.addr)
				}
				return nil
			}
			switch {
			case res.already:
				fmt.Fprintf(os.Stderr, "whisper: already bound - %s (%s); re-bind with --force\n",
					res.addr, firstNonBlank(res.name, res.agent, "no reverse name yet"))
			case res.fromMarker:
				fmt.Fprintf(os.Stderr, "whisper: bound %s - %s (kept this device's own identity, which the account still has)\n",
					res.addr, firstNonBlank(res.name, res.agent))
			case res.reused:
				fmt.Fprintf(os.Stderr, "whisper: bound %s - %s (reused the agent already registered under this name)\n",
					res.addr, firstNonBlank(res.name, res.agent))
			default:
				fmt.Fprintf(os.Stderr, "whisper: bound %s - %s\n",
					res.addr, firstNonBlank(res.name, res.agent, "no reverse name yet"))
			}
			writeServiceBindNote(os.Stderr, res)
			if r, ok := readConnectRefusal(); ok && r.Kind == refusalIdentityGone {
				// The refusal was about the identity this verb just replaced; it is no
				// longer true, and the next connect writes a new record if anything else is.
				clearConnectRefusal()
			}
			if res.replacedAgent != "" {
				why := "was this device's old identity"
				if res.replacedGone {
					why = "is no longer in the account"
				}
				fmt.Fprintf(os.Stderr, "whisper: whisper connect now binds %s (the saved agent %s %s)\n",
					res.agent, res.replacedAgent, why)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the agent name to bind under (default: this host's hostname)")
	cmd.Flags().BoolVar(&force, "force", false, "re-bind even when a marker already records an identity")
	cmd.Flags().BoolVar(&preview, "preview", false, "with --force: print what it would do and change nothing")
	cmd.Flags().StringVar(&confirm, "confirm", "", "with --force: do the plan --preview printed, given its token (- reads stdin)")
	return cmd
}

// runEnrollFixCmd is the body of --preview and --confirm.
func runEnrollFixCmd(cmd *cobra.Command, name string, preview bool, confirm string) error {
	if preview {
		v, err := runEnrollPreview(name)
		if err != nil {
			return err
		}
		return emitEnrollView(v, false)
	}
	tok, err := readTokenArg(confirm, cmd.InOrStdin())
	if err != nil {
		return err
	}
	v, _, err := runEnrollConfirm(name, tok)
	if err != nil {
		return err
	}
	return emitEnrollView(v, true)
}

// emitEnrollView prints the view in the requested form and returns an error when the plan did
// not go ahead, so the exit status says so.
func emitEnrollView(v previewView, confirming bool) error {
	if g.jsonOut {
		emitJSONValue(v)
		if v.MaybeChanged {
			return &errEnrollStopped{msg: "this may have changed this device's identity; look again with: " +
				previewLine(v.ExplicitName)}
		}
		if v.Outcome == fixRefuse || v.Outcome == fixChanged {
			return &errEnrollStopped{msg: firstNonBlank(v.Reason, "what this would do changed since you looked")}
		}
		return nil
	}
	return printEnrollView(v, confirming)
}

// runEnroll is the ladder itself, split out so tests can drive it without cobra.
func runEnroll(name string, force bool) (enrollResult, error) {
	// Where the host service reads this host's identity, decided before anything is read or
	// called. On Windows the sensor runs as LocalSystem and reads the SYSTEM profile; an
	// administrator's elevated shell writes there, and any other shell refuses rather than bind
	// into a profile the sensor never reads.
	target, terr := resolveIdentityTarget(serviceIdentityContextFn(), enrollRetryLine(name, force))
	if terr != nil {
		return enrollResult{}, terr
	}
	markerPath := target.marker

	// The identity being replaced, read before anything changes, so a forced re-bind can tell
	// the saved agent it pinned last time from one a person picked.
	prev, hadPrev := client.ReadBoundFile(markerPath)

	// Already bound? Say so and stop. This is the common case on every re-run, and it must
	// not call the control plane at all: an installer re-run on a flaky network still has to
	// succeed, and a host that is bound IS bound whether or not we can reach the server.
	if !force && hadPrev {
		return enrollResult{
			mode: "existing", addr: prev.Addr.String(), name: prev.Name,
			agent: prev.Agent, already: true, target: target,
		}, nil
	}

	// The names the ladder looks for, the first of which a mint registers under. An explicit
	// --name is a person's choice and is the only one; the default is this host's name, trimmed,
	// and the untrimmed form too for reuse, so a host enrolled before a suffix was trimmed
	// rebinds its agent instead of minting a second.
	names := []string{name}
	explicit := name != ""
	if !explicit {
		names = enrollHostNames()
	}
	if len(names) == 0 || names[0] == "" {
		return enrollResult{}, usageErr("could not determine this host's name; pass --name")
	}
	name = names[0]

	c, err := resolveClient(true, false)
	keyFrom := ""
	if err != nil {
		// `sudo whisper enroll` is the line a plain user's refusal names. Under a
		// sudo that resets HOME this process is root in the unit's own home, which has no
		// key until something gives it one; the invoking user's key is the one they meant.
		// It is used and carried, as an elevated Windows shell carries the administrator's.
		from, keyPath, ok := sudoInvokerKeyForFn(target)
		if !ok {
			return enrollResult{}, err
		}
		if c, err = resolveClientFrom(true, false, keyPath); err != nil {
			return enrollResult{}, err
		}
		keyFrom = from
		target.service, target.key, target.agent = true, client.DefaultKeyFile(), client.DefaultAgentFile()
	}
	// In the service's profile the key is half the identity. A key there that is not the one
	// this run binds with would leave a marker made under one account and a key from another,
	// a sensor that reports nowhere, so that refuses before anything is called.
	carryKey := false
	if target.service {
		have, ok := readKeyFile(target.key)
		switch {
		case !ok:
			// A monitor token is read-only and is not an API key; it is never handed on.
			carryKey = !c.Credential().Bearer
		case have != c.Credential().Value || c.Credential().Bearer:
			return enrollResult{}, &usageError{msg: fmt.Sprintf("the %s service already holds a different "+
				"API key (%s), so binding with this one would leave it reporting under another account; "+
				"nothing was written. To hand the service this key, remove that file and run '%s' again",
				target.ctx.Service, target.key, enrollRetryLine(name, force))}
		}
	}

	// One listing, read once, before any rung acts, and every rung reads that one. A listing
	// that did not answer (no reply, a timeout, an error status, a body that does not parse, a
	// reply with no listing in it) says nothing about whether this device already has an agent.
	// Read as an empty account, the name check finds nothing and the ladder registers a second
	// identity, orphaning the first. So it refuses and changes nothing, on every path. Reading
	// once also means the identity check cannot see an answer and the name check, a second
	// later, see a failure.
	lcx, lcancel := ctx()
	listing, lerr := accountListing(c, lcx)
	lcancel()
	if lerr != nil {
		return enrollResult{}, enrollListingRefusal(lerr, name, explicit, force, prev, hadPrev, markerPath)
	}
	live := liveAgentsIn(listing)

	// The device's OWN identity first. A forced re-bind with no --name is what every
	// identity-gone refusal tells a person to run, and the identity that is gone is often only
	// the saved agent file, while the marker's agent is still in the account under a label that
	// is not this host's name (say first-run labelled it studio-mac while os.Hostname() says
	// Mac.localdomain). Looking it up by host name then mints a second identity and orphans the
	// first. So the marker's agent is rebound when the listing still has it, and the host-name
	// rung runs only when it is provably gone.
	var res enrollResult
	rebound := false
	if !explicit && force && hadPrev {
		if env, found := markedAgentIn(live, prev); found {
			res = enrollFromEnvelope(env, "register", firstNonBlank(prev.Name, name))
			res.agent = firstNonBlank(res.agent, prev.Agent)
			res.reused, res.fromMarker, rebound = true, true, true
		}
	}

	if !rebound {
		res, err = enrollViaRegister(c, live, names)
		if err != nil {
			// The register rung is best-effort BY DESIGN (a key without the register scope is a
			// perfectly normal key). Fall through to op:identity, which every key can do, rather
			// than failing a bind the caller can still complete.
			res, err = enrollViaIdentity(c, name)
			if err != nil {
				return enrollResult{}, err
			}
		}
	}

	addr, perr := netip.ParseAddr(res.addr)
	if perr != nil || !addr.Is6() {
		return enrollResult{}, fmt.Errorf("the control plane returned no usable /128 for %q "+
			"(got %q); nothing was written", name, res.addr)
	}
	res.target = target
	if target.service {
		// The key first: a marker with no key beside it is the half identity this exists to end.
		if carryKey {
			if kerr := client.SaveServiceKey(target.key, c.Credential().Value); kerr != nil {
				return enrollResult{}, fmt.Errorf("bound %s but could not give the %s service its API key at %s: %w",
					res.addr, target.ctx.Service, target.key, kerr)
			}
			res.keyCarried = true
			res.keyFrom = keyFrom
		}
		if werr := client.WriteServiceBoundFile(markerPath, res.mode, addr, res.name, res.agent); werr != nil {
			return enrollResult{}, fmt.Errorf("bound %s but could not record it at %s: %w "+
				"(the sensor reads this file to know which /128 to ship as)", res.addr, markerPath, werr)
		}
		// The service's saved agent follows the same rule as a person's below, applied to the
		// service's own file: written when there is none, replaced only on --force when it named
		// the previous binding. The administrator's own saved agent is not this host's.
		if res.agent != "" {
			pinned := client.ReadAgentFile(target.agent)
			if pinned == "" || (force && savedAgentIsPrevBinding(pinned, prev, hadPrev)) {
				_ = client.SaveServiceAgent(target.agent, res.agent)
			}
		}
		return res, nil
	}
	if werr := client.WriteBoundFile(markerPath, res.mode, addr, res.name, res.agent); werr != nil {
		return enrollResult{}, fmt.Errorf("bound %s but could not record it at %s: %w "+
			"(the sensor reads this file to know which /128 to ship as)", res.addr, markerPath, werr)
	}
	// Pin the binary's chosen agent to THIS identity so a later `whisper connect` needs no
	// argument - but never clobber an agent a human already picked.
	//
	// A forced re-bind is how a device whose identity was removed gets a new one, and there
	// the saved agent is the dead identity itself: leaving it in place means connect goes on
	// refusing to start, naming an agent that no longer exists, after the person ran the very
	// command it told them to. So under --force the saved agent is replaced when it is the one
	// this verb pinned last time, or when the account provably no longer has it. One a person
	// picked that is still in the account is theirs, and it stays.
	if res.agent != "" {
		pinned := client.ReadAgentFile("")
		replace := pinned == ""
		gone := false
		if !replace && force {
			replace = savedAgentIsPrevBinding(pinned, prev, hadPrev)
			if !replace {
				// Decided from the listing already read: a second read that failed would keep
				// a saved agent the first one proved gone.
				gone = savedAgentGoneIn(listing, pinned)
				replace = gone
			}
		}
		if replace && !strings.EqualFold(pinned, res.agent) {
			if serr := client.SaveAgent("", res.agent); serr == nil {
				res.replacedAgent, res.replacedGone = pinned, gone
			}
		}
	}
	return res, nil
}

// readKeyFile reads a saved key, trimmed. ok is false when there is none.
func readKeyFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(b))
	return v, v != ""
}

// writeServiceBindNote says where a bind run from an administrator's shell (or under sudo)
// was recorded, so nobody goes looking for it in their own profile.
func writeServiceBindNote(w io.Writer, res enrollResult) {
	if !res.target.service {
		return
	}
	fmt.Fprintf(w, "whisper: recorded for the %s service, which runs as %s, at %s\n",
		res.target.ctx.Service, res.target.ctx.Account, res.target.marker)
	if res.keyCarried && res.keyFrom != "" {
		fmt.Fprintf(w, "whisper: gave the %s service %s's API key, which this bind used (%s)\n",
			res.target.ctx.Service, res.keyFrom, res.target.key)
	} else if res.keyCarried {
		fmt.Fprintf(w, "whisper: gave the %s service the API key this bind used (%s)\n",
			res.target.ctx.Service, res.target.key)
	} else if _, ok := readKeyFile(res.target.key); !ok {
		fmt.Fprintf(w, "whisper: the %s service has no API key at %s yet; run 'whisper enroll --force'"+
			" from this shell to give it yours and keep this identity\n", res.target.ctx.Service, res.target.key)
	}
}

// savedAgentIsPrevBinding reports whether the saved selector names the identity the marker
// recorded before this re-bind, by its agent handle or its /128.
func savedAgentIsPrevBinding(pinned string, prev client.BoundIdentity, hadPrev bool) bool {
	if !hadPrev || strings.TrimSpace(pinned) == "" {
		return false
	}
	if prev.Agent != "" && strings.EqualFold(strings.TrimSpace(pinned), prev.Agent) {
		return true
	}
	return prev.Addr.IsValid() && sameIP(pinned, prev.Addr.String())
}

// enrollListingRefusal is what enroll says when it could not read the account: what it was
// checking, that nothing changed, and the commands to run. A person's --name goes back into
// the retry line as they gave it; a name they have yet to choose is a placeholder.
func enrollListingRefusal(lerr error, name string, explicit, force bool,
	prev client.BoundIdentity, hadPrev bool, markerPath string) error {
	retry := "whisper enroll"
	if force {
		retry += " --force"
	}
	if explicit {
		return fmt.Errorf("could not read this account's agents to check whether an agent named %q "+
			"is already registered: %v. Nothing was changed. Run '%s --name %s' again once the "+
			"control plane answers", name, lerr, retry, pasteWord(name))
	}
	choose := retry + " --name " + pastePlaceholder("name")
	if force && hadPrev {
		return fmt.Errorf("could not read this account's agents to check whether "+
			"this device's identity %s (%s) is still there: %v. Nothing was changed. Run "+
			"'%s' again once the control plane answers, or bind under a name "+
			"you choose with: %s",
			firstNonBlank(prev.Agent, prev.Name, "recorded in "+markerPath), prev.Addr, lerr, retry, choose)
	}
	return fmt.Errorf("could not read this account's agents to check whether an agent named %q "+
		"is already registered: %v. Nothing was changed. Run '%s' again once the control plane "+
		"answers, or bind under a name you choose with: %s", name, lerr, retry, choose)
}

// pasteGOOS is runtime.GOOS, a seam so tests can render a line for another shell.
var pasteGOOS = runtime.GOOS

// pastePlaceholder writes a value the person fills in, in a line meant to be pasted: {braces},
// which every POSIX shell passes through literally. On Windows it is in double quotes, because
// PowerShell reads an unquoted brace as a script block and drops the argument without an error,
// and cmd.exe strips the quotes.
func pastePlaceholder(p string) string { return pastePlaceholderFor(pasteGOOS, p) }

// pastePlaceholderFor is pastePlaceholder for a named shell, for a line whose
// platform is already decided (the Windows readiness note).
func pastePlaceholderFor(goos, p string) string {
	if goos == "windows" {
		return `"{` + p + `}"`
	}
	return "{" + p + "}"
}

// pasteWord writes a value the person already gave as one word in a line meant to be pasted:
// bare when it is plain, quoted for the shell otherwise (double quotes on Windows, which both
// PowerShell and cmd.exe read as one argument, with an embedded quote doubled).
func pasteWord(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '.' || r == '_' || r == ':') {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	if pasteGOOS == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// enrollViaRegister walks the register rung over a listing that answered: reuse the agent
// already registered under any of these names, in order, else mint a new one under the first.
func enrollViaRegister(c *client.Client, live []liveAgent, names []string) (enrollResult, error) {
	name := names[0]
	for _, n := range names {
		if renv, found := registeredAgentIn(live, n); found {
			r := enrollFromEnvelope(renv, "register", n)
			r.reused = true
			if r.addr == "" {
				return enrollResult{}, fmt.Errorf("the reused agent %q carries no address", n)
			}
			return r, nil
		}
	}
	cx, cancel := ctx()
	defer cancel()
	// An op:register envelope also carries the minted agent's own API key, shown once. We
	// parse the address/name/agent out and drop the rest: the marker never holds a secret.
	env, err := c.Agents(cx, "register", map[string]any{"label": name})
	if err != nil {
		return enrollResult{}, err
	}
	r := enrollFromEnvelope(env, "register", name)
	if r.addr == "" {
		return enrollResult{}, fmt.Errorf("op:register returned no address for %q", name)
	}
	return r, nil
}

// enrollViaIdentity is the rung every key can reach: this key's own /128.
func enrollViaIdentity(c *client.Client, name string) (enrollResult, error) {
	env, err := createIdentityWithDevice(c, name, "", "")
	if err != nil {
		return enrollResult{}, err
	}
	r := enrollFromEnvelope(env, "identity", name)
	if r.addr == "" {
		return enrollResult{}, fmt.Errorf("op:identity returned no address for %q", name)
	}
	return r, nil
}

// enrollFromEnvelope pulls the marker's fields out of whichever envelope answered. The
// FCrDNS name is the forward fqdn (which is also what `dig -x <addr>` answers); `ptr` is
// the ip6.arpa OWNER name, used only when fqdn is absent.
func enrollFromEnvelope(env *client.Envelope, mode, fallbackName string) enrollResult {
	recs := env.Result.Records()
	if len(recs) == 0 {
		return enrollResult{mode: mode, name: fallbackName}
	}
	r := enrollResult{
		mode:  mode,
		addr:  field(recs[0], "address", "addr128"),
		name:  strings.TrimSuffix(field(recs[0], "fqdn", "ptr"), "."),
		agent: field(recs[0], "agent", "label"),
	}
	if r.name == "" {
		r.name = fallbackName
	}
	return r
}

// enrollHostName is the default agent name: this host's hostname, trimmed of any trailing
// dot and of the suffix a local network appends: ".local" (macOS mDNS, "macbook.local"),
// ".localdomain" (macOS and many distributions, "Mac.localdomain") and ".lan" (home routers),
// case-insensitively. The agent name reads better without them, and they change with the
// network the host happens to be on.
func enrollHostName() string {
	h, err := osHostname()
	if err != nil {
		return ""
	}
	return trimHostName(h)
}

// osHostname is os.Hostname, a seam so tests can be a host of any name.
var osHostname = os.Hostname

// localSuffixes are trimmed from the default name, longest first.
var localSuffixes = []string{".localdomain", ".local", ".lan"}

func trimHostName(h string) string {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	for _, suf := range localSuffixes {
		if len(h) > len(suf) && strings.EqualFold(h[len(h)-len(suf):], suf) {
			return h[:len(h)-len(suf)]
		}
	}
	return h
}

// enrollHostNames is the default name, then the untrimmed hostname when it differs: the reuse
// rung looks for both, so an agent registered under "box.lan" before ".lan" was trimmed is
// rebound rather than orphaned. A mint only ever uses the first.
func enrollHostNames() []string {
	h, err := osHostname()
	if err != nil {
		return nil
	}
	raw := strings.TrimSuffix(strings.TrimSpace(h), ".")
	names := []string{trimHostName(h)}
	if raw != "" && !strings.EqualFold(raw, names[0]) {
		names = append(names, raw)
	}
	return names
}
