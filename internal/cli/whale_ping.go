// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_ping.go is `whisper whale ping <peer>`: a real round trip, and a plain statement
// of what it proves.
//
// The measurement itself lives in internal/whale/ping.go, including why it is a TCP
// connect and not an ICMP echo, and why a refusal is a useful answer rather than a
// failure. This file is the surface: Postel at the argument (an agent id, a /128, a
// hostname or an fqdn all name the same node), ping(8)'s output shape, and one honest
// summary line.
//
// --until-direct waits only when waiting can change the answer. The first step gave us
// the two topologies that need no punching - peers on one segment, and a peer with an
// untranslated public endpoint - and those are already up or already impossible by the
// time you ask. The punch came later, and it takes real time, so there is now exactly
// one state in which waiting is honest: a traversal in flight for this peer in this
// host's own tunnel. Every other state is settled, and the flag says which one it is
// rather than spinning on a path that is not coming.

func newWhalePingCmd() *cobra.Command {
	var (
		count       int
		port        int
		timeout     time.Duration
		untilDirect bool
	)
	cmd := &cobra.Command{
		Use:   "ping <peer>",
		Short: "Measure the round trip to a peer, and say what it proves",
		Long: "Measure a real round trip to a peer and report what came back.\n\n" +
			"Name the peer any way you have it: an agent id, a /128, a short name from your\n" +
			"fleet, or an fqdn with or without the trailing dot.\n\n" +
			"The probe is a TCP connect, not an ICMP echo, because an echo needs a raw socket\n" +
			"and a connect carries more: a refusal proves the packet reached the peer and came\n" +
			"back, which an echo drop cannot distinguish from a black hole. So the outcomes\n" +
			"are `open`, `refused` (a path exists, nothing is listening), `no reply` (nothing\n" +
			"came back) and `no route` (this host could not even send).\n\n" +
			"PATH names what carried the packets. `relayed` is a Whisper box in the middle: tens\n" +
			"of milliseconds, not tenths. `direct-local` means you and the peer share a segment\n" +
			"and nothing was in the middle; `direct-public` means the peer was dialable as-is;\n" +
			"`direct-punch` means a path was opened through a NAT by both ends handshaking at\n" +
			"the endpoints a box observed them arriving from. A punch that fails costs latency\n" +
			"and nothing else - the relay carries the peer throughout - and this command says so\n" +
			"in those words. --until-direct waits only while a traversal is actually in flight,\n" +
			"and otherwise returns at once and says which of the reasons it was.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cx, cancel := ctx()
			defer cancel()
			// Keyless is fine for a literal address; a name needs the fleet, and
			// resolveWhaleNode says so if the key is missing.
			c, _ := resolveClient(false, false)
			node, err := resolveWhaleNode(cx, c, args[0])
			if err != nil {
				return err
			}
			probe := whale.NewNetProber(timeout)
			human := !g.jsonOut && !g.quiet
			// ask the control plane which first-step class, if any, applies to
			// this pair. Empty on any failure, and empty renders as `relayed` - a path we
			// could not ask about is not one we may claim.
			class := whalePeerClass(cx, c, node.Addr.String())
			// What THIS host's tunnel published about the path. It outranks the class above:
			// the control plane offers a candidacy, the device reports an outcome, and only the
			// second one knows whether the handshake landed.
			evidence := readPathEvidence("").For(node.Addr.String())
			liveClass := class
			if evidence.Found {
				liveClass = evidence.Class
				if !evidence.Direct {
					liveClass = ""
				}
			}
			sum := whale.Ping(cx, node.Addr, whale.PingOptions{
				Target:      firstNonBlank(node.Name, node.Target.Text),
				Address:     node.Addr.String(),
				Port:        port,
				Count:       count,
				DirectClass: class,
				Evidence:    evidence,
			}, probe, func(a whale.Attempt) {
				if human {
					fmt.Fprintln(os.Stdout, pingAttemptLine(a, node, port, liveClass))
				}
			})

			if g.jsonOut {
				emitJSONValue(sum)
			} else if human {
				fmt.Fprintln(os.Stdout)
				fmt.Fprintf(os.Stdout, "%d sent, %d answered, path %s", sum.Sent, sum.Answered, sum.Path)
				if sum.Answered > 0 {
					fmt.Fprintf(os.Stdout, ", rtt min/avg/max %.1f/%.1f/%.1f ms", sum.MinMs, sum.AvgMs, sum.MaxMs)
				}
				fmt.Fprintln(os.Stdout)
				if sum.Why != "" {
					whaleNote("%s", sum.Why)
				}
				whaleNote("%s", sum.Note)
				if untilDirect {
					renderUntilDirect(node, port, count, probe, sum, evidence)
				}
			} else if g.quiet && sum.Answered > 0 {
				fmt.Fprintf(os.Stdout, "%.1f\n", sum.MinMs)
			}

			if sum.OK() {
				return nil
			}
			return &client.ProblemError{Status: 1, Detail: fmt.Sprintf(
				"no path to %s: %s", node.Addr, sum.Note)}
		},
	}
	cmd.Flags().IntVarP(&count, "count", "c", 3, "how many probes to send")
	cmd.Flags().IntVar(&port, "port", whale.DefaultPingPort, "TCP port to probe (443 is the port every box serves)")
	cmd.Flags().DurationVar(&timeout, "timeout", whaleProbeTimeout, "per-probe timeout")
	cmd.Flags().BoolVar(&untilDirect, "until-direct", false, "tailscale parity: returns at once and says why a direct path cannot happen here")
	return cmd
}

// renderUntilDirect is the honest form of Tailscale's --until-direct.
//
// It waits ONLY when waiting can change the answer: a traversal that is actually in flight for
// this peer, in this host's own tunnel. A pair that is already direct says so and returns; a
// pair whose train has been spent, or that was never offered an endpoint, says WHICH of those it
// was rather than spinning on a path that is not coming. That distinction is the whole point of
// the flag - a wait that can never end is the cruellest thing a diagnostic can do.
func renderUntilDirect(node whaleNode, port, count int, probe whale.TCPProbe, sum whale.PingSummary, ev whale.PunchEvidence) {
	if sum.Path != whale.PathRelayed && sum.Path != whale.PathNoPath {
		whaleNote("--until-direct: already direct, so there was nothing to wait for.")
		return
	}
	if !ev.InFlight() {
		whaleNote("--until-direct: not waiting, because nothing is in flight for this peer. %s", sum.Why)
		return
	}
	whaleNote("--until-direct: a direct path is being opened for this peer - waiting up to %s.",
		whaleUntilDirectWait)
	settled := waitForDirectPath(node.Addr.String(), whaleUntilDirectWait)
	if !settled.Direct {
		obs := whale.Observation{Direct: settled.Direct, Class: settled.Class, Punch: settled}
		whaleNote("--until-direct: %s", whale.ReasonFor(obs))
		return
	}
	// It came up. Measure it again so the number beside the claim is the direct one, not the
	// relayed one from before the upgrade.
	cx2, cancel2 := ctx()
	defer cancel2()
	again := whale.Ping(cx2, node.Addr, whale.PingOptions{
		Target:   firstNonBlank(node.Name, node.Target.Text),
		Address:  node.Addr.String(),
		Port:     port,
		Count:    count,
		Evidence: settled,
	}, probe, nil)
	fmt.Fprintf(os.Stdout, "%d sent, %d answered, path %s", again.Sent, again.Answered, again.Path)
	if again.Answered > 0 {
		fmt.Fprintf(os.Stdout, ", rtt min/avg/max %.1f/%.1f/%.1f ms", again.MinMs, again.AvgMs, again.MaxMs)
	}
	fmt.Fprintln(os.Stdout)
	whaleNote("--until-direct: %s", again.Why)
}

// pingAttemptLine renders one attempt in ping(8)'s shape, naming the path taken rather
// than leaving the reader to assume one.
func pingAttemptLine(a whale.Attempt, node whaleNode, port int, class string) string {
	who := node.Addr.String()
	if node.Name != "" {
		who = fmt.Sprintf("%s (%s)", node.Name, node.Addr)
	}
	// an answered probe took whatever path the plane says this pair has. An
	// unrecognised or empty class is relayed, which is both the default and the truth for
	// every pair the first step does not cover.
	path := whale.PathForClass(class)
	switch a.Outcome {
	case whale.OutcomeOpen:
		return fmt.Sprintf("reply from %s tcp/%d in %.1f ms  path=%s", who, port, a.RTTMs, path)
	case whale.OutcomeRefused:
		return fmt.Sprintf("reply from %s tcp/%d in %.1f ms  path=%s  (refused: the path exists, nothing is listening on %d)",
			who, port, a.RTTMs, path, port)
	case whale.OutcomeNoRoute:
		return fmt.Sprintf("could not send to %s: %s", who, orVal(a.Detail, "no route from this host"))
	default:
		return fmt.Sprintf("no reply from %s tcp/%d: %s", who, port, orVal(a.Detail, "timed out"))
	}
}
