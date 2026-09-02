// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_ip.go is `whisper whale ip`, the smallest verb and the one with the sharpest
// failure mode to get right.
//
// `tailscale ip -4` prints a 100.x address. Ours cannot: a Whalenet identity is an IPv6
// /128 and there is no mesh-local v4. The wrong answer is an empty line and exit 0, which
// is what a script reads as "no address configured" and what sends a person looking for a
// bug in their own code. So -4 exits non-zero with one sentence that says what is true and
// what to reach for instead - and since that sentence describes the IPv4 this node can
// actually REACH (the loopback listener is v4; v4 destinations ride NAT64 inside the
// tunnel) rather than stopping at "we do not have one". See whale_v4.go.
//
// It also differs from `whisper ip` on purpose, and the help says so: `whisper ip` brings
// the connection up and proves the egress really is your /128. This one prints the
// address and touches nothing, because `tailscale ip` is instant and people script it.

func newWhaleIPCmd() *cobra.Command {
	var (
		want4     bool
		want6     bool
		probe     bool
		assert    string
		agentFile string
	)
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "Print this node's address",
		Long: "Print this node's Whalenet address. Instant and side-effect free: it brings\n" +
			"nothing up and verifies nothing, which is what makes it safe to script.\n" +
			"(`whisper ip` is the other one: it brings the connection up and proves the\n" +
			"egress really is your /128.)\n\n" +
			"-6 is the address. -4 exits non-zero with a sentence, because there is no IPv4\n" +
			"identity to print - but that sentence names the local endpoint IPv4 runs\n" +
			"through and the mechanism that carries it (NAT64, RFC 6052). It will never\n" +
			"print an empty line and call that success.\n\n" +
			"-4 --probe MEASURES it rather than describing it: two dials through the live\n" +
			"listener at the same host and port, an IPv6 control and that host's IPv4\n" +
			"wrapped into the NAT64 prefix. A failing control reports `unknown`, never\n" +
			"`IPv4 is broken`, because a tunnel that is down fails the same way.\n\n" +
			"--assert <ip> exits 0 only if this node's address is exactly that one, so a\n" +
			"script can gate on identity in one line.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if want4 && want6 {
				return usageErr("pick one of -4 or -6")
			}
			if want4 {
				// There is still no v4 ADDRESS to print, and inventing one would be
				// the bug. What changed is that we now name the mechanism that would carry
				// IPv4 and the endpoint it runs through - and, with --probe, MEASURE
				// whether it actually carries one, control and all. Unmeasured stays
				// unmeasured in the output rather than becoming a claim. --json gets the
				// same answer as data. Exit stays non-zero: a script asking for an address
				// must never be handed something that is not one.
				sessions := liveStatusSessions()
				var measured *v4Probe
				if probe {
					pcx, pcancel := ctx()
					defer pcancel()
					port := 0
					if len(sessions) > 0 {
						port = sessions[0].Port
					}
					m := probeV4Through(pcx, port, whaleBoxHosts())
					measured = &m
				}
				v := whaleV4Status(sessions, measured)
				if g.jsonOut {
					emitJSONValue(v)
				}
				return &client.ProblemError{Status: 1, Detail: v.Note}
			}
			cx, cancel := ctx()
			defer cancel()
			addr := whaleSelfAddress(cx, agentFile)
			if addr == "" {
				return &client.ProblemError{Status: 404, Detail: "this host has no Whalenet address yet: " +
					"nothing is connected, no agent is pinned, and your fleet did not name one. " +
					"Run `whisper connect` to bring one up, or `whisper use <agent>` to pin one"}
			}
			if assert != "" {
				if !sameIP(addr, assert) {
					return &client.ProblemError{Status: 1, Detail: fmt.Sprintf(
						"this node is %s, not %s", addr, assert)}
				}
				if g.quiet {
					fmt.Fprintln(os.Stdout, addr)
					return nil
				}
			}
			if g.jsonOut {
				emitJSONValue(map[string]any{"address": addr, "family": "ipv6"})
				return nil
			}
			fmt.Fprintln(os.Stdout, addr)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&want4, "4", "4", false, "IPv4 (there is no v4 identity: this exits non-zero and names how IPv4 is carried; add --probe to measure it)")
	cmd.Flags().BoolVarP(&want6, "6", "6", false, "IPv6 address (the default, and the only one there is)")
	cmd.Flags().BoolVar(&probe, "probe", false,
		"with -4, MEASURE whether an IPv4 destination completes through the tunnel (two dials, "+
			"an IPv6 control and the same host's IPv4 wrapped into the NAT64 prefix) instead of "+
			"describing the mechanism")
	cmd.Flags().StringVar(&assert, "assert", "", "exit 0 only if this node's address is exactly <ip>")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// whaleSelfAddress is the one answer to "which /128 am I", used by `ip` and by `status`.
// Order is by confidence: a live verified session, then the pinned agent, then a fleet
// of exactly one. Anything less certain returns "" so the caller can say so plainly
// rather than guess.
func whaleSelfAddress(cx context.Context, agentFile string) string {
	if live := liveStatusSessions(); len(live) > 0 && live[0].Address != "" {
		return live[0].Address
	}
	if sel := client.ReadAgentFile(agentFile); looksLikeV6(sel) {
		return sel
	}
	c, err := resolveClient(false, false)
	if err != nil || c == nil || c.Credential().IsZero() {
		return ""
	}
	peers, ferr := whaleFleet(cx, c)
	if ferr != nil {
		return ""
	}
	if sel := client.ReadAgentFile(agentFile); sel != "" {
		if p, ok := matchPeer(peers, sel); ok {
			return p.Address
		}
	}
	if len(peers) == 1 {
		return peers[0].Address
	}
	return ""
}
