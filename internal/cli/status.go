// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// status.go gives the chosen identity visibility: `whisper use <agent>` pins the
// agent the rest of the CLI binds to, and `whisper status` shows - in plain language - the
// key state, the selected agent, and the connection state. The selected identity stops
// being an invisible file only the installer ever wrote.

// --- use <agent> -----------------------------------------------------------------

func newUseCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:   "use <agent|address>",
		Short: "Choose the agent the rest of whisper binds to (saved to ~/.config/whisper/agent)",
		Long: "Pin the agent (by name or /128) that `whisper`, `connect`, and `status` use by\n" +
			"default - written to ~/.config/whisper/agent (mode 600).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sel string
			if len(args) == 1 {
				sel = strings.TrimSpace(args[0])
			}
			if sel == "" {
				return usageErr("use needs an <agent|address> (the name or /128 of one of your agents)")
			}
			// A /128 is already the canonical form - save it directly. A friendly NAME/id
			// must be resolved to its /128 (Postel: accept a name, store the address) so
			// `connect`/`ip`/`status` bind correctly; without this, `whisper use <name>`
			// saved the name and a later `whisper connect` failed with "no egress". We only
			// reach the control plane for a name, and only when a key is present (so `use`
			// before login still works as a best-effort raw save).
			if !looksLikeV6(sel) {
				if c, cerr := resolveClient(true, false); cerr == nil && c != nil && !c.Credential().IsZero() {
					addr, rerr := resolveAddress(c, sel)
					if rerr != nil {
						return rerr // clear "agent not found", not a confusing later error
					}
					sel = addr
				}
			}
			if err := client.SaveAgent(agentFile, sel); err != nil {
				return fmt.Errorf("could not save the chosen agent: %w", err)
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, sel)
				return nil
			}
			fmt.Fprintf(os.Stderr, "whisper: using %s\n", sel)
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// --- status ----------------------------------------------------------------------

func newStatusCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show your key state, the selected agent, and the connection state",
		Long: "A calm one-glance summary: whether a key is in effect (and from where), which\n" +
			"agent is selected, and the connection state. The key value is NEVER printed.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, _ := client.ResolveCredential(client.KeyLadderOptions{
				FlagKey:    g.key,
				FlagBearer: g.bearer,
				KeyFile:    g.keyFile,
				AllowEnv:   true,
				AllowFile:  true,
			})
			selected := client.ReadAgentFile(agentFile)

			// The REAL connection state: every held-open egress (an interactive
			// `whisper connect`, the guided hold, the `--ensure` daemon) registers itself
			// in the local session registry after its verify passes; a record whose proxy
			// no longer answers is a crashed holder. Probe each record so status reports
			// what is genuinely serving right now - never a hardcoded guess.
			live := liveStatusSessions()
			conn := "not connected"
			if len(live) > 0 {
				conn = "connected"
			}

			var sensorRow string
			st := statusView{
				KeyPresent: !cred.IsZero(),
				KeySource:  string(cred.Source),
				Selected:   selected,
				Connection: conn,
				Sessions:   live,
			}
			// An optional host-status row, filled in only by a build that
			// installs a reporter. A build with none stays silent rather than
			// reporting on something it could not have installed, or naming a
			// remedy it does not carry.
			if hostSensorStatus != nil {
				st.Sensor, sensorRow = hostSensorStatus()
			}

			if g.jsonOut {
				emitJSONValue(st)
				return nil
			}
			keyCell := "not set - run: whisper login"
			if st.KeyPresent {
				keyCell = "set (" + st.KeySource + ")"
			}
			rows := [][]string{
				{"key", keyCell},
				{"agent", orVal(selected, "none - run: whisper use <agent>")},
			}
			if len(live) == 0 {
				rows = append(rows, []string{"connection", "not connected - run: whisper connect"})
			}
			for _, s := range live {
				rows = append(rows, []string{"connection",
					fmt.Sprintf("connected - %s via %s (%s)", s.Address, s.Endpoint, orVal(s.Tier, "socks5"))})
			}
			if hostSensorStatus != nil {
				rows = append(rows, []string{"sensor", sensorRow})
			}
			printTable([]string{"SETTING", "VALUE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// statusView is the JSON shape `whisper status --json` emits (no key value, ever).
type statusView struct {
	KeyPresent bool            `json:"key_present"`
	KeySource  string          `json:"key_source"`
	Selected   string          `json:"selected_agent"`
	Connection string          `json:"connection"`
	Sessions   []statusSession `json:"sessions,omitempty"`
	// Sensor is an optional host-status value. Where a build reports one it is never
	// omitted, because a reader forced to infer a state from a missing field is
	// exactly the absence-read-as-zero mistake this field exists to prevent. A build
	// that installs no reporter has nothing to report, so the field is then absent
	// rather than zero. hostSensorStatus is the seam.
	Sensor any `json:"sensor,omitempty"`
}

// hostSensorStatus is an optional host-status reporter for `whisper status`: the value
// marshalled under "sensor", and the cell the human table prints beside it. Nil unless
// a build installs one. Declared beside its only two call sites, so the seam is visible
// from the code that needs it.
var hostSensorStatus func() (value any, cell string)

// statusSession is one live, locally-held egress session as status reports it - the
// bearer/key-free local endpoint, the verified /128, and the tier. No secret, ever
// (the registry records none to begin with).
type statusSession struct {
	Endpoint string `json:"endpoint"`
	Address  string `json:"address"`
	Tier     string `json:"tier"`
	Port     int    `json:"port"`
	// NAT64Prefix / NAT64Source are the tunnel's own answer, empty when the record does
	// not carry one. `whale ip -4` prefers them over anything it could compute for itself.
	NAT64Prefix string `json:"nat64_prefix,omitempty"`
	NAT64Source string `json:"nat64_source,omitempty"`
}

// liveStatusSessions reads the session registry and keeps only the records whose
// local proxy still answers a real SOCKS5 handshake (probeWhisperProxy). A record whose
// probe fails is a crashed/stopped holder: it is swept lazily (the same hygiene
// findLiveSession applies) so a stale record never haunts the next status. Fail-open:
// no registry at all is simply "not connected", never an error.
func liveStatusSessions() []statusSession {
	var out []statusSession
	for _, rec := range readSessionRecords() {
		if !probeWhisperProxy(rec.Port) {
			removeSessionRecordAt(rec.path)
			continue
		}
		out = append(out, statusSession{
			Endpoint:    rec.Endpoint,
			Address:     rec.Addr,
			Tier:        rec.Tier,
			Port:        rec.Port,
			NAT64Prefix: rec.NAT64Prefix,
			NAT64Source: rec.NAT64Source,
		})
	}
	return out
}
