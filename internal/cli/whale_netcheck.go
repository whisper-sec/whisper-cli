// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_netcheck.go is `whisper whale netcheck`: what actually works between this host
// and the fleet, measured rather than assumed.
//
// This is the direct fix for a class of false report we have had repeatedly: a v4-only
// host concludes "egress is down" because the thing it reached for was IPv6-only. So the
// report is per family and per box, every cell is backed by a probe that ran, and every
// false carries the reason it is false.
//
// Two things it must say out loud. The two MTUs are different numbers (1280 on this
// host's tunnel interface, a different one on the server) and are reported separately,
// because an earlier revision of the plan asserted they were equal. And there is no
// direct peer-to-peer path: netcheck reports reachability to the boxes, and nothing in
// it should be read as evidence that two agents can reach each other without one.
//
// Tailscale's netcheck reports DERP regions and a "nearest region". We have no DERP, so
// the equivalent is the anchor box: the node that answered fastest from here.

func newWhaleNetcheckCmd() *cobra.Command {
	var (
		format string
		boxes  []string
	)
	cmd := &cobra.Command{
		Use:   "netcheck",
		Short: "Measure what works between this host and the fleet",
		Long: "Probe every Whisper box over both address families and report what answered.\n\n" +
			"Each box gets a real DNS question over UDP/53 (a datagram nobody answers proves\n" +
			"nothing, so we send one that is answered) and a TCP connect to :443. Both are\n" +
			"keyless. The anchor box is whichever answered fastest from here; there are no\n" +
			"DERP regions to report because there is no DERP.\n\n" +
			"The two tunnel MTUs are reported separately and labelled: client is this host's\n" +
			"tunnel interface, server is the interface on the other end. They are not the\n" +
			"same number and the smaller one governs.\n\n" +
			"Nothing here says anything about the path between two agents: this command measures\n" +
			"this host against the boxes. For a peer-to-peer path, ask `whisper whale status` or\n" +
			"`whisper whale ping <peer>`, which report what this node's own tunnel established.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hosts := boxes
			if len(hosts) == 0 {
				hosts = whaleBoxHosts()
			}
			if len(hosts) == 0 {
				return &client.ProblemError{Status: 500, Detail: "no boxes to probe"}
			}
			cx, cancel := ctx()
			defer cancel()
			rep := whale.Netcheck(cx, hosts, whale.NewNetProber(whaleProbeTimeout))

			// Postel on the flag too: --json is our convention, --format json is
			// tailscale's spelling of the same request. Both work.
			if g.jsonOut || strings.EqualFold(strings.TrimSpace(format), "json") {
				emitJSONValue(rep)
			} else {
				renderNetcheck(rep)
			}
			if rep.OK() {
				return nil
			}
			return &client.ProblemError{Status: 1, Detail: "no box answered any probe: this host has no " +
				"working path to the Whisper fleet right now"}
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "output format: json (tailscale parity for --json)")
	cmd.Flags().StringArrayVar(&boxes, "box", nil, "probe this host instead of the fleet default (repeatable; a name or an address)")
	return cmd
}

// renderNetcheck prints the calm human report: one summary block, one row per box and
// family, then the two notes that keep it from being over-read.
func renderNetcheck(rep whale.NetcheckReport) {
	summary := [][]string{
		{"ipv6", yesNo(rep.IPv6)},
		{"ipv4", yesNo(rep.IPv4)},
		{"udp", yesNo(rep.UDP)},
	}
	if rep.Anchor != "" {
		summary = append(summary, []string{"anchor box", fmt.Sprintf("%s  %s", rep.Anchor, fmtMs(rep.AnchorMs))})
	} else {
		summary = append(summary, []string{"anchor box", "none answered"})
	}
	summary = append(summary,
		[]string{"mtu client", fmt.Sprintf("%d", rep.MTU.Client)},
		[]string{"mtu server", fmt.Sprintf("%d", rep.MTU.Server)},
	)
	printTable([]string{"NETCHECK", ""}, summary)

	fmt.Fprintln(os.Stdout)
	rows := make([][]string, 0, len(rep.Boxes)*2)
	for _, b := range rep.Boxes {
		for _, f := range []whale.FamilyProbe{b.IPv6, b.IPv4} {
			rows = append(rows, []string{
				b.Host,
				f.Family,
				orDash(f.Addr),
				probeCell(f.DNSUDP, f.DNSMs),
				probeCell(f.TCP443, f.TCPMs),
				orDash(f.Note),
			})
		}
	}
	printTable([]string{"BOX", "FAMILY", "ADDRESS", "UDP/53", "TCP/443", "NOTE"}, rows)

	fmt.Fprintln(os.Stdout)
	whaleNote("mtu: %s", rep.MTUNote)
	whaleNote("%s", rep.JoinNote)
	whaleNote("%s", rep.PathNote)
	for _, w := range rep.Warnings {
		whaleNote("%s", w)
	}
}

// probeCell renders one leg: a measured time when it answered, and a plain "no" when it
// did not. Never a blank, which reads as "not applicable" when it means "it failed".
func probeCell(ok bool, ms float64) string {
	if !ok {
		return "no"
	}
	return fmtMs(ms)
}
