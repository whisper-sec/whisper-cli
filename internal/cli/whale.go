// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale.go is the front door of `whisper whale`, the Whalenet command shell.
//
// Shape and naming follow `tailscale` deliberately: same verbs, same flag names, same
// argument order, so an operator's muscle memory transfers on day one. Where ours
// differs it is because ours is better or because theirs would be a lie here, and the
// help text says which in one line rather than leaving the difference to be discovered.
//
// Most of it reads: status, ip, ping, netcheck, whois, dns, route, syspolicy, and
// `acl show` / `acl test`. What writes says so and names what it changes. There is still
// no `up`, because a half-working join is worse than no join.
//
// Every verb here is keyless-tolerant where the answer is public (whois, netcheck, ping
// against an address) and asks for a key only where the answer is your tenant's
// (status's peer table, an agent name lookup). That is the two-tier rule, and it is why
// `whale whois` works for anyone on the internet with no account at all.

// whaleProbeTimeout bounds one probe. It is short on purpose: `whale status` and
// `whale netcheck` are things a person runs constantly, and a dark box must cost a
// second, not thirty.
const whaleProbeTimeout = 3 * time.Second

func newWhaleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whale",
		Short: "Whalenet: your fleet's mesh, as one command shell",
		Long: "whisper whale - the Whalenet command shell.\n\n" +
			"The verbs, flags and argument order mirror `tailscale`, so what you already know\n" +
			"transfers. What differs is said out loud rather than left to be discovered:\n\n" +
			"  status     this node, your fleet, and the path between them\n" +
			"  ip         this node's address (Whalenet is IPv6-only today)\n" +
			"  ping       a real round trip to a peer, and what it proves\n" +
			"  netcheck   what works between this host and the fleet, measured\n" +
			"  whois      who holds an address, keylessly, validated from the IANA root\n" +
			"  dns        the resolver in effect, a query with the graph's view, your records\n" +
			"  route      subnet routes: what this node carries, and what advertising needs\n" +
			"  exit-node  the ways out, ranked on the graph rather than on latency alone\n" +
			"  ssh        SSH to a node, host key proven from the IANA DNSSEC root\n" +
			"  migrate    move a Tailscale tailnet here, plan first, nothing silently widened\n" +
			"  serve      put a local port in front of your fleet, pinned by the published TLSA\n" +
			"  funnel     the same port, answered for the whole internet, deliberately\n" +
			"  syspolicy  the settings your MDM manages here, and the profile that sets them\n" +
			"  acl        the document that decides who in your fleet may reach what\n\n" +
			"Joining a node is still separate work: a half-working join would be worse than\n" +
			"none. Everything else here reads before it writes, `migrate plan` changes nothing\n" +
			"at all on either side, and `acl test` answers from the artifact the wire reads.",
	}
	cmd.AddCommand(
		newWhaleStatusCmd(),
		newWhaleIPCmd(),
		newWhalePingCmd(),
		newWhaleNetcheckCmd(),
		newWhaleWhoisCmd(),
		newWhaleDNSCmd(),
		newWhaleSSHCmd(),
		newWhaleMigrateCmd(),
		newWhaleRouteCmd(),
		newWhaleExitNodeCmd(),
		newWhaleServeCmd(),
		newWhaleFunnelCmd(),
		newWhaleSysPolicyCmd(),
		newWhaleACLCmd(),
	)
	// A typo here used to print help and exit 0. The Args validator above could never run
	// (cobra skips validation for a command with no RunE), so the guard has to be a RunE.
	return asParent(cmd)
}

// --- boxes ------------------------------------------------------------------------

// whaleBoxHosts derives the box list from the one list the client already keeps, rather
// than writing a second one that can drift out of step with it. Both nodes are
// active/active and answer identically, which is exactly why netcheck probes both.
func whaleBoxHosts() []string {
	var hosts []string
	for _, base := range client.DefaultReportFallbackBases {
		u, err := url.Parse(base)
		if err != nil || u.Hostname() == "" {
			continue
		}
		hosts = append(hosts, u.Hostname())
	}
	sort.Strings(hosts)
	return hosts
}

// --- naming -----------------------------------------------------------------------

// whaleNode is one resolved node reference: what the user typed, what it resolved to,
// and how. Every whale verb that takes a node argument goes through this, so they all
// accept exactly the same spellings.
type whaleNode struct {
	Target whale.Target
	Addr   netip.Addr
	// Name is the SHORT name a person calls the node: its agent id, or the label the
	// fleet holds it under. It is a display name and nothing looks it up.
	Name string
	// FQDN is the node's DNS name, set only when we actually learnt one. this is
	// the field a verb resolves records under - `whale ssh` looks the SSHFP up here -
	// and it is separate from Name because they are different strings for a registered
	// agent (`agent-a<hex>` against `a<hex>.t<hash>.agents.whisper.online.`). Looking a
	// record up under an id returns NXDOMAIN and reads as "no SSHFP is published",
	// which is a confident wrong answer about a security fact.
	FQDN    string
	Via     string // how the address was found: "literal" | "fleet" | "dns"
	Foreign bool   // resolved outside your tenant (a public name or a bare address)
}

// resolveWhaleNode is Postel at the argument boundary: an agent id, a /128, a hostname
// or an fqdn (trailing dot or not) all name a node, and all arrive here as one address.
//
// Order matters and is deliberate. A literal address is already the answer. A name is
// looked up in YOUR fleet first, because that is the answer a person means by `db-01`,
// and only then in public DNS. c may be nil (keyless): the fleet rung is skipped and the
// error, if any, says that a key would have let us look in your fleet.
func resolveWhaleNode(ctx context.Context, c *client.Client, raw string) (whaleNode, error) {
	t, err := whale.ParseTarget(raw)
	if err != nil {
		return whaleNode{}, usageErr("%s", err.Error())
	}
	if t.IsAddress() {
		return whaleNode{Target: t, Addr: t.Addr, Via: "literal", Foreign: true}, nil
	}

	keyed := c != nil && !c.Credential().IsZero()
	if keyed {
		if peers, ferr := whaleFleet(ctx, c); ferr == nil {
			if p, ok := matchPeer(peers, t.Text); ok {
				if addr, perr := netip.ParseAddr(p.Address); perr == nil {
					// Carry the peer's DNS name too. op:list publishes `fqdn`
					// beside the id, and a legacy row without one simply leaves FQDN
					// empty so the caller falls through to the name the user typed or
					// to the validated PTR - never to the id, which resolves to
					// nothing.
					return whaleNode{
						Target: t, Addr: addr, Name: p.Name,
						FQDN: trimDot(strings.TrimSpace(p.FQDN)), Via: "fleet",
					}, nil
				}
			}
		}
	}

	// A single label is not a name public DNS can answer: it needs a search domain, and
	// Graph DNS search domains are not built yet. Say that rather than emitting a
	// lookup that cannot succeed.
	if t.Kind == whale.KindLabel {
		if keyed {
			// Deliberately worded without the word "agent": the CLI's own friendly()
			// rewrites any agent-shaped 404 into a generic "not in your account" line,
			// which would throw away the two ways out this message offers.
			return whaleNode{}, &client.ProblemError{Status: 404, Title: "no such node", Detail: fmt.Sprintf(
				"nothing in your fleet is called %q - run `whisper list` to see what you have, "+
					"or name the node by its /128 or its full DNS name", t.Text)}
		}
		// Title "no key" keeps friendly() from rewriting this into "your key was not
		// accepted", which would be a different and wrong diagnosis.
		return whaleNode{}, &client.ProblemError{Status: 401, Title: "no key", Detail: fmt.Sprintf(
			"%q is a single name, and a single name only means something inside a fleet - "+
				"run `whisper login` to look it up in yours, or name the node by its /128 or its full DNS name", t.Text)}
	}

	addrs, derr := lookupWhaleAAAA(ctx, t.Text)
	if derr != nil || len(addrs) == 0 {
		return whaleNode{}, &client.ProblemError{Status: 404, Detail: fmt.Sprintf(
			"%s has no AAAA record - a Whalenet node is an IPv6 /128, and that name does not resolve to one", t.Text)}
	}
	// It came out of public DNS, so the name we asked for IS its DNS name.
	return whaleNode{Target: t, Addr: addrs[0], Name: t.Text, FQDN: t.Text, Via: "dns", Foreign: true}, nil
}

// lookupWhaleAAAA is a package var so tests resolve names without a network.
var lookupWhaleAAAA = func(ctx context.Context, name string) ([]netip.Addr, error) {
	cx, cancel := context.WithTimeout(ctx, whaleProbeTimeout)
	defer cancel()
	p := whale.NewNetProber(whaleProbeTimeout)
	v6, _, err := p.Lookup(cx, name)
	return v6, err
}

// --- the fleet --------------------------------------------------------------------

// whalePeer is one member of your fleet as the peer table shows it.
type whalePeer struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	FQDN    string `json:"fqdn,omitempty"`
	Label   string `json:"label,omitempty"`
	State   string `json:"state,omitempty"`
	Created int64  `json:"created,omitempty"`
}

// whaleFleet reads the caller's agents through op:list, the same op `whisper list`
// uses. It adds no op and no server change: this whole command shell is provable on the
// live fleet on day one precisely because it asks only questions already answered.
// whaleFleet is a package var for the same reason lookupWhaleAAAA is: a test drives the
// real resolution order without a control plane on the other end.
var whaleFleet = func(ctx context.Context, c *client.Client) ([]whalePeer, error) {
	env, err := c.Agents(ctx, "list", map[string]any{"kind": "agents"})
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, perr
	}
	var peers []whalePeer
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		name := field(item, "agent", "id", "label")
		addr := field(item, "address", "addr128")
		if name == "" && addr == "" {
			continue
		}
		peers = append(peers, whalePeer{
			Name:    name,
			Address: addr,
			FQDN:    trimDot(field(item, "fqdn")),
			Label:   field(item, "label"),
			State:   orVal(field(item, "state"), "active"),
			Created: parseEpoch(field(item, "created", "allocated_at")),
		})
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Created != peers[j].Created {
			return peers[i].Created > peers[j].Created
		}
		return peers[i].Name < peers[j].Name
	})
	return peers, nil
}

// matchPeer finds a peer by agent id, label, address or fqdn - with or without the
// trailing dot, in any case. One matcher, so every verb accepts the same spellings.
func matchPeer(peers []whalePeer, want string) (whalePeer, bool) {
	w := strings.ToLower(trimDot(strings.TrimSpace(want)))
	for _, p := range peers {
		for _, cand := range []string{p.Name, p.Label, p.Address, p.FQDN} {
			if cand != "" && strings.ToLower(trimDot(cand)) == w {
				return p, true
			}
		}
	}
	// An fqdn given for a peer we hold under its short name still matches on the first label.
	if i := strings.IndexByte(w, '.'); i > 0 {
		return matchPeer(peers, w[:i])
	}
	return whalePeer{}, false
}

// --- shared rendering ---------------------------------------------------------------

// whaleNote prints one calm footnote line to stderr, so stdout stays a clean table for
// anything reading it with a pipe.
func whaleNote(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "  %s\n", fmt.Sprintf(format, a...))
}

// fmtMs renders a measured round trip the way ping(8) does: one decimal, and never a
// number at all when nothing was measured.
func fmtMs(v float64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", v)
}
