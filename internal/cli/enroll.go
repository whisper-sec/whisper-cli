// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"net/netip"
	"os"
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
}

func newEnrollCmd() *cobra.Command {
	var name string
	var force bool
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
			"full name is still reused.\n\n" +
			"--force re-binds even when a marker exists. With no --name it keeps this device's\n" +
			"own identity (the one the marker records) whenever the account still has it, under\n" +
			"whatever label, and looks further only when the account no longer has it, which is\n" +
			"how a device whose identity was removed gets a new one. If the account cannot be\n" +
			"read it changes nothing rather than mint a second identity. It also replaces the\n" +
			"saved agent (~/.config/whisper/agent) when that names the old identity or one the\n" +
			"account no longer has, so `whisper connect` binds this identity; an agent you\n" +
			"picked that is still in the account is left alone.\n\n" +
			"Writes ~/.config/whisper/bound (mode/address/name/agent/bound_at - no secrets).",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
	return cmd
}

// runEnroll is the ladder itself, split out so tests can drive it without cobra.
func runEnroll(name string, force bool) (enrollResult, error) {
	markerPath := client.DefaultBoundFile()

	// The identity being replaced, read before anything changes, so a forced re-bind can tell
	// the saved agent it pinned last time from one a person picked.
	prev, hadPrev := client.ReadBoundFile(markerPath)

	// Already bound? Say so and stop. This is the common case on every re-run, and it must
	// not call the control plane at all: an installer re-run on a flaky network still has to
	// succeed, and a host that is bound IS bound whether or not we can reach the server.
	if !force && hadPrev {
		return enrollResult{
			mode: "existing", addr: prev.Addr.String(), name: prev.Name,
			agent: prev.Agent, already: true,
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
	if err != nil {
		return enrollResult{}, err
	}

	// The device's OWN identity first. A forced re-bind with no --name is what every
	// identity-gone refusal tells a person to run, and the identity that is gone is often only
	// the saved agent file, while the marker's agent is still in the account under a label that
	// is not this host's name (say first-run labelled it studio-mac while os.Hostname() says
	// Mac.localdomain). Looking it up by host name then mints a second identity and orphans the
	// first. So the marker's agent is rebound when a listing that answered still has it, and the
	// host-name rung runs only when it is provably gone. A listing that did not answer proves
	// nothing, and minting on nothing is that same second identity, so it refuses.
	var res enrollResult
	rebound := false
	if !explicit && force && hadPrev {
		env, found, lerr := reuseMarkedAgent(c, prev)
		switch {
		case lerr != nil:
			return enrollResult{}, fmt.Errorf("could not read this account's agents to check whether "+
				"this device's identity %s (%s) is still there: %v. Nothing was changed. Run "+
				"'whisper enroll --force' again once the control plane answers, or bind under a name "+
				"you choose with: whisper enroll --force --name {name}",
				firstNonBlank(prev.Agent, prev.Name, "recorded in "+markerPath), prev.Addr, lerr)
		case found:
			res = enrollFromEnvelope(env, "register", firstNonBlank(prev.Name, name))
			res.agent = firstNonBlank(res.agent, prev.Agent)
			res.reused, res.fromMarker, rebound = true, true, true
		}
	}

	if !rebound {
		res, err = enrollViaRegister(c, names)
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
				gone = savedAgentGone(c, pinned)
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

// savedAgentGone reports whether the account PROVABLY no longer has the saved selector: a
// listing that answered without it. A listing that failed proves nothing and keeps the file.
func savedAgentGone(c *client.Client, pinned string) bool {
	cx, cancel := ctx()
	defer cancel()
	_, known := accountAgents(c, cx, pinned)
	return !known
}

// enrollViaRegister walks the register rung: reuse the agent already registered under any of
// these names, in order, else mint a new one under the first.
func enrollViaRegister(c *client.Client, names []string) (enrollResult, error) {
	name := names[0]
	for _, n := range names {
		if renv, found := reuseRegisteredAgent(c, n); found {
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
