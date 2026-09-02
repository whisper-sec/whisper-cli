// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_route.go is `whisper whale route`: the subnet-router surface.
//
// A person arriving from Tailscale types `--advertise-routes` on their first day. Today
// that lands on "unknown command", which is the least useful thing we could say, so this
// verb exists to give the real answer instead: what this node routes right now, what your
// prefix would have to be, and precisely which two things are missing before it could be
// advertised. Both of those are structural, both are named, and one of them is read from
// the same constant `whale status` reads for its PATH column - so when the that
// builds a direct node-to-node path lands, this stops refusing without anyone editing it.
//
// It refuses honestly rather than pretending. A verb that accepted the advertisement and
// quietly did nothing would be worse than the unknown command it replaces.

func newWhaleRouteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Subnet routes: what this node carries, and what advertising one needs",
		Long: "Subnet routing on Whalenet.\n\n" +
			"  list        the prefixes this node routes into the tunnel right now\n" +
			"  advertise   check a prefix and say exactly what advertising it needs\n\n" +
			"A Whisper agent peer is bound to exactly one /128, and that is a security\n" +
			"property rather than a limitation to flag away: it is what stops one agent\n" +
			"sourcing another's identity. A subnet router is therefore a separate class of\n" +
			"peer, it is kernel-tier only, and it is direct-path only - two customers\n" +
			"routinely advertise the same 10.0.0.0/8, and one shared box cannot hold both.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleRouteListCmd(), newWhaleRouteAdvertiseCmd())
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

// whaleRouteView is what `route list` emits under --json.
type whaleRouteView struct {
	Connected  bool               `json:"connected"`
	Tier       string             `json:"tier,omitempty"`
	Address    string             `json:"address,omitempty"`
	Captured   []string           `json:"captured"`
	Advertised []string           `json:"advertised"`
	Support    whale.RouteSupport `json:"support"`
	Notes      []string           `json:"notes,omitempty"`
}

func newWhaleRouteListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "The prefixes this node routes into the tunnel",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := buildWhaleRouteView(liveStatusSessions())
			if g.jsonOut {
				emitJSONValue(v)
				return nil
			}
			renderWhaleRoutes(v)
			return nil
		},
	}
}

// buildWhaleRouteView reports the real state, not a configured one. What a connected node
// captures is not a guess: everything this host sends through the local endpoint leaves
// through Whisper, in both families. The two entries below are DESTINATION families, not the
// tunnel's AllowedIPs: the WireGuard peer carries ::/0 alone (it is the only family the /128
// interface can source, see wgtun.boxDefaultRoute), and an IPv4 destination rides inside that
// as a NAT64-wrapped address (RFC 6052), which is what the note says out loud.
func buildWhaleRouteView(sessions []statusSession) whaleRouteView {
	v := whaleRouteView{Captured: []string{}, Advertised: []string{}}
	if len(sessions) > 0 {
		s := sessions[0]
		v.Connected = true
		v.Tier = orVal(s.Tier, "socks5")
		v.Address = s.Address
		v.Captured = []string{"::/0", "0.0.0.0/0"}
		v.Notes = append(v.Notes, "Everything sent through the local endpoint leaves through Whisper: the "+
			"tunnel captures both default routes. IPv4 destinations ride NAT64 inside it (`whisper whale ip -4`).")
	} else {
		v.Notes = append(v.Notes, "Nothing is connected, so this node routes nothing into a tunnel. "+
			"Run `whisper connect` first.")
	}
	v.Support = whale.SupportForRoutes(v.Tier)
	if !v.Support.Supported {
		v.Notes = append(v.Notes, "No subnet route is advertised, and none can be in this build: "+
			"run `whisper whale route advertise <prefix>` to see exactly what is missing.")
	}
	return v
}

func renderWhaleRoutes(v whaleRouteView) {
	rows := [][]string{}
	for _, c := range v.Captured {
		rows = append(rows, []string{c, "tunnel default", "into the tunnel"})
	}
	for _, a := range v.Advertised {
		rows = append(rows, []string{a, "advertised", "to your fleet"})
	}
	if len(rows) == 0 {
		rows = append(rows, []string{"-", "-", "nothing routed"})
	}
	printTable([]string{"PREFIX", "SOURCE", "DIRECTION"}, rows)
	for _, n := range v.Notes {
		whaleNote("%s", n)
	}
}

func newWhaleRouteAdvertiseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "advertise <prefix>...",
		Short: "Check a prefix and say what advertising it needs",
		Long: "Validate one or more prefixes as a subnet-router advertisement and report what\n" +
			"is required to carry them. Accepts repeated arguments or a comma-separated list.\n\n" +
			"This will refuse, and it will say why in full. Refusing loudly is the point: a\n" +
			"verb that accepted the advertisement and silently carried nothing would cost you\n" +
			"an afternoon instead of a sentence.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			routes, err := whale.ParseRoutes(args)
			if err != nil {
				return usageErr("%s", err.Error())
			}
			tier := ""
			if live := liveStatusSessions(); len(live) > 0 {
				tier = orVal(live[0].Tier, "socks5")
			}
			support := whale.SupportForRoutes(tier)
			out := map[string]any{"routes": routes, "support": support, "accepted": support.Supported}
			if g.jsonOut {
				emitJSONValue(out)
			} else {
				renderWhaleAdvertise(routes)
			}
			if support.Supported {
				// Reserved for the build in which a direct path exists. It cannot be
				// reached today, and the refusal below is what actually runs.
				return &client.ProblemError{Status: 501, Detail: "a direct path exists in this build but the " +
					"route-peer registration it needs has not shipped yet - please report this message"}
			}
			return &client.ProblemError{Status: 1, Detail: whaleAdvertiseRefusal(routes, support)}
		},
	}
}

// renderWhaleAdvertise prints what was checked. The WHY belongs to the refusal that
// follows it, said once: repeating it here would be two copies of the same paragraph on
// one screen, and the reader would trust neither.
func renderWhaleAdvertise(routes []whale.Route) {
	rows := make([][]string, 0, len(routes))
	for _, r := range routes {
		note := ""
		if r.Masked {
			note = "canonicalised from " + r.Input
		}
		rows = append(rows, []string{r.String(), string(r.Scope), note})
	}
	printTable([]string{"PREFIX", "SCOPE", "NOTE"}, rows)
}

// whaleAdvertiseRefusal is the sentence the non-zero exit carries. It names what was
// checked, so the validation the user just got is not thrown away with the refusal.
func whaleAdvertiseRefusal(routes []whale.Route, support whale.RouteSupport) string {
	names := make([]string, 0, len(routes))
	private := false
	for _, r := range routes {
		names = append(names, r.String())
		if r.Scope == whale.ScopePrivate {
			private = true
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s valid as a subnet-router advertisement, and this node cannot advertise %s.\n",
		strings.Join(names, ", "), plural(len(routes), "is", "are"), plural(len(routes), "it", "them"))
	for _, sentence := range blockerSentences(support) {
		fmt.Fprintf(&b, "\n  %s\n", sentence)
	}
	if private {
		b.WriteString("\n  That prefix is private space, so it is direct-path only permanently rather than " +
			"for now: two customers can hold the same 10.0.0.0/8, and one shared routing " +
			"table cannot serve both.\n")
	}
	b.WriteString("\nToday: reach that LAN directly and keep it out of the proxy (NO_PROXY), or put a host " +
		"on it that runs its own Whisper agent, so the service has an identity of its own.")
	return b.String()
}

func blockerSentences(support whale.RouteSupport) []string {
	out := make([]string, 0, len(support.Blockers))
	for _, b := range support.Blockers {
		out = append(out, whale.ExplainRouteBlocker(b))
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
