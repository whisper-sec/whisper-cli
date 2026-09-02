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
			"op:identity. A key that cannot register (no scope) still ends up bound.\n\n" +
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
			case res.reused:
				fmt.Fprintf(os.Stderr, "whisper: bound %s - %s (reused the agent already registered under this name)\n",
					res.addr, firstNonBlank(res.name, res.agent))
			default:
				fmt.Fprintf(os.Stderr, "whisper: bound %s - %s\n",
					res.addr, firstNonBlank(res.name, res.agent, "no reverse name yet"))
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

	// Already bound? Say so and stop. This is the common case on every re-run, and it must
	// not call the control plane at all: an installer re-run on a flaky network still has to
	// succeed, and a host that is bound IS bound whether or not we can reach the server.
	if !force {
		if id, ok := client.ReadBoundFile(markerPath); ok {
			return enrollResult{
				mode: "existing", addr: id.Addr.String(), name: id.Name,
				agent: id.Agent, already: true,
			}, nil
		}
	}

	if name == "" {
		name = enrollHostName()
	}
	if name == "" {
		return enrollResult{}, usageErr("could not determine this host's name; pass --name")
	}

	c, err := resolveClient(true, false)
	if err != nil {
		return enrollResult{}, err
	}

	res, err := enrollViaRegister(c, name)
	if err != nil {
		// The register rung is best-effort BY DESIGN (a key without the register scope is a
		// perfectly normal key). Fall through to op:identity, which every key can do, rather
		// than failing a bind the caller can still complete.
		res, err = enrollViaIdentity(c, name)
		if err != nil {
			return enrollResult{}, err
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
	if res.agent != "" {
		if pinned := client.ReadAgentFile(""); pinned == "" {
			_ = client.SaveAgent("", res.agent)
		}
	}
	return res, nil
}

// enrollViaRegister walks the register rung: reuse the agent already registered under this
// name, else mint a new one.
func enrollViaRegister(c *client.Client, name string) (enrollResult, error) {
	if renv, found := reuseRegisteredAgent(c, name); found {
		r := enrollFromEnvelope(renv, "register", name)
		r.reused = true
		if r.addr == "" {
			return enrollResult{}, fmt.Errorf("the reused agent %q carries no address", name)
		}
		return r, nil
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
// dot and of a ".local" suffix (macOS hands out "macbook.local", and the agent name
// reads better without it).
func enrollHostName() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	h = strings.TrimSuffix(h, ".local")
	return h
}
