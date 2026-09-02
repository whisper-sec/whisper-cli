// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel.go is the surface the resident panel talks to, and the switch that closes the
// gap it kept having to report.
//
// `whisper panel status` is one JSON document: key, identity, connection, egress, sensor, fleet.
// It exists because a menu-bar app that shelled out to six commands would have six chances to
// disagree with itself about the same host in the same second, and because the answers it needs
// are already computed here - the session registry, the fleet listing, the sensor seam, the
// keyless verify and echo. panel_view.go assembles them; nothing there is a new source of truth.
//
// `whisper panel system-proxy` is the other half, and the more important one. `whisper connect`
// hands back a socks5h://127.0.0.1:PORT string. A shell that exports ALL_PROXY picks it up and
// curl, git and every agent SDK leave from the Whisper /128. Safari does not read ALL_PROXY.
// Neither does Chrome, Mail, Slack or anything else with a window, so all of them kept leaving
// from the machine's own address while the product said "connected". That is not a display bug;
// for the browser, egress was never in force at all. This verb points macOS's own SOCKS setting
// at the live session, which is the setting those apps DO read, and `status` reports on it
// afterwards - including the case that made this worth doing, where the setting is switched on
// and aimed at a port nothing has served since the last connection ended.

// newPanelCmd is the `panel` group. asParent is what makes `whisper panel typo` exit non-zero
// instead of printing help and reporting success.
func newPanelCmd() *cobra.Command {
	cmd := asParent(&cobra.Command{
		Use:   "panel",
		Short: "Open the resident panel, read what it reads, and drive the system-proxy switch",
		Long: "The machine-readable read of this host, for the resident panel.\n\n" +
			"  whisper panel show                bring the menu bar panel up in front of you,\n" +
			"                                    starting it first if it is not running (macOS)\n" +
			"  whisper panel status              one JSON document: key, identity, connection,\n" +
			"                                    egress, sensor and fleet, in one consistent read\n" +
			"  whisper panel system-proxy on     point this Mac's own SOCKS setting at the live\n" +
			"                                    Whisper session, so Safari and other GUI apps\n" +
			"                                    leave from your /128 too (needs admin rights)\n" +
			"  whisper panel system-proxy off    put the system network settings back\n" +
			"  whisper panel system-proxy reap   put them back if they point at a dead session\n" +
			"  whisper panel system-proxy        show what the system settings say right now\n\n" +
			"Anything the panel could not READ comes back as `unknown` with a line in `errors`,\n" +
			"never as a confident negative: a probe that timed out is not a stopped sensor and\n" +
			"not a dead connection.",
	})
	cmd.AddCommand(newPanelShowCmd(), newPanelStatusCmd(), newPanelSystemProxyCmd())
	return cmd
}

// newPanelStatusCmd emits the document. It is JSON always, with or without --json: this is the
// machine surface, and `whisper status` is the human one. A second human renderer of the same
// facts would be a second thing to keep true.
func newPanelStatusCmd() *cobra.Command {
	var (
		agentFile string
		probe     bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "One JSON document with everything the panel renders",
		Long: "Everything the resident panel shows, read once and emitted as one JSON document\n" +
			"(schema 1). Always JSON: this is the machine surface, and `whisper status` is the\n" +
			"one for people.\n\n" +
			"It never fails. A leg that could not be read lands on `unknown` with its reason in\n" +
			"the top-level `errors` array, because a panel that renders a failed probe as\n" +
			"`stopped` teaches you to stop believing it when it says `running`.\n\n" +
			"No round-trip time is reported unless something measured one: `rtt_ms` is absent\n" +
			"rather than zero. Pass --probe to measure every peer now.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cx, cancel := ctx()
			defer cancel()
			emitJSONValue(buildPanelView(cx, agentFile, probe))
			return nil
		},
	}
	cmd.Flags().BoolVar(&probe, "probe", false,
		"measure the round trip to every peer now (fills rtt_ms; costs a packet per peer)")
	cmd.Flags().StringVar(&agentFile, "agent-file", "",
		"override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// newPanelSystemProxyCmd is the honest fix: on, off, reap, or tell me what it says.
//
// Liberal in what it accepts (Postel): no argument means `status`, the read-only one, because
// that is the answer a bare verb should give and because guessing `on` would change the
// machine's networking for somebody who only asked a question.
func newPanelSystemProxyCmd() *cobra.Command {
	opt := sysProxyEnableOptions{verifyTimeout: defaultSysProxyVerifyTimeout}
	cmd := &cobra.Command{
		Use:     "system-proxy [on|off|status|reap]",
		Aliases: []string{"sysproxy"},
		Short:   "Send Safari and other GUI apps through your Whisper egress too (macOS)",
		Long: "GUI apps do not read ALL_PROXY. Safari, Chrome, Mail and everything else with a\n" +
			"window ignore the connection string `whisper connect` prints, so they keep leaving\n" +
			"from this machine's own address while your terminal leaves from your /128.\n\n" +
			"This points macOS's own SOCKS setting - the one those apps DO read - at the live\n" +
			"Whisper session, and puts it back when you are done.\n\n" +
			"  whisper panel system-proxy        what the system settings say right now\n" +
			"  whisper panel system-proxy on     point them at the live session (needs admin)\n" +
			"  whisper panel system-proxy off    put them back\n" +
			"  whisper panel system-proxy reap   put them back if they point at a dead session\n\n" +
			"`on` is the one that can hurt, so it proves three things before it changes anything:\n" +
			"the session's local port answers, traffic through it leaves from your Whisper\n" +
			"address, and a site that has no IPv6 address still loads through it. That last one\n" +
			"is the check this command exists for: an egress that carries IPv6 and not IPv4 is\n" +
			"a limitation in one shell and an outage when every app on the Mac is pointed at it.\n" +
			"It is measured against a direct control taken at the same moment, so a refusal\n" +
			"means the egress, never your own network. If it refuses, nothing was changed.\n\n" +
			"Once the setting is applied, `on` re-checks that traffic still works and puts your\n" +
			"previous settings back, exactly as they were, if it does not. That check runs in a\n" +
			"detached watchdog as well as in this process, so losing the terminal, the panel or\n" +
			"this command itself still leaves something running that will put your settings back.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := "status"
			if len(args) == 1 {
				action = strings.ToLower(strings.TrimSpace(args[0]))
			}
			switch action {
			case "status", "show", "":
				return runPanelSystemProxyStatus()
			case "on", "enable":
				return runPanelSystemProxySet(true, opt)
			case "off", "disable":
				return runPanelSystemProxySet(false, opt)
			case "reap", "sweep":
				return runPanelSystemProxyReap()
			case "dead-man", "deadman":
				return runPanelSystemProxyDeadMan()
			default:
				return usageErr("system-proxy takes on, off, status, reap or dead-man, got %q", action)
			}
		},
	}
	// No backquotes in these two strings: cobra reads a backquoted word as the flag's value
	// placeholder, so "(`on` only)" renders the flag as "--force on" in the help.
	cmd.Flags().BoolVar(&opt.force, "force", false,
		"with on: switch it on even when the pre-flight says the egress cannot carry IPv4 "+
			"(it prints what it is overriding)")
	cmd.Flags().DurationVar(&opt.verifyTimeout, "verify-timeout", defaultSysProxyVerifyTimeout,
		"with on: how long to wait for proof that traffic still works after the setting is "+
			"applied, before putting the previous settings back")
	return cmd
}

// runPanelSystemProxyDeadMan is the body of the DETACHED watchdog `system-proxy on` starts before
// it changes anything. It is not a verb anybody needs to type - `on` starts it, and standing it
// down is a single write it is already watching for - but it is a real verb rather than a hidden
// one, because a process that changes system settings on its own should be one an operator can
// run by hand and read the reasoning of. See panel_sysproxy_deadman.go.
func runPanelSystemProxyDeadMan() error {
	res := runSysProxyDeadManWatch()
	if g.jsonOut {
		emitJSONValue(res)
		return nil
	}
	printTable([]string{"DEAD MAN", "VALUE"}, [][]string{
		{"action", orDash(res.Action)},
		{"reverted", panelYesNo(res.Reverted)},
	})
	if res.Detail != "" {
		fmt.Fprintln(os.Stderr, res.Detail)
	}
	return nil
}

// runPanelSystemProxyReap is the watchdog verb, and the reason the resident panel can be trusted
// to leave a machine working. See panel_sysproxy_record.go for the ownership rule it obeys.
func runPanelSystemProxyReap() error {
	res, err := runSysProxyReap()
	if g.jsonOut {
		emitJSONValue(res)
		return err
	}
	printTable([]string{"REAP", "VALUE"}, [][]string{
		{"action", orDash(res.Action)},
		{"reverted", panelYesNo(res.Reverted)},
	})
	if res.Detail != "" {
		fmt.Fprintln(os.Stderr, res.Detail)
	}
	return err
}

// runPanelSystemProxyStatus reads the setting and renders the same sentence the panel document
// carries, so the CLI and the panel can never say different things about the same machine.
func runPanelSystemProxyStatus() error {
	return reportSystemProxyState()
}

// sysProxyEnableOptions are the two knobs on `system-proxy on`: the operator override, and how
// long the dead man waits for proof before putting everything back.
type sysProxyEnableOptions struct {
	force         bool
	verifyTimeout time.Duration
}

// systemProxyDrivable is systemProxySupported behind a var. The platform const stays the single
// declaration of what this build can do; the var exists so the ORDER and the LOGIC below - the
// pre-flight, the dead man, the ownership rule - can be exercised from a test on any OS, which is
// the only way any of it is ever tested before it reaches a Mac.
var systemProxyDrivable = systemProxySupported

// The two platform writers, behind vars for the same reason readSystemProxyState is (panel_view.go).
var (
	writeSystemProxyFn   = writeSystemProxy
	restoreSystemProxyFn = restoreSystemProxy
)

// runPanelSystemProxySet turns the system proxy on or off.
//
// Turning it ON is the dangerous direction, and the order of what happens here is the whole
// safety property:
//
// 1. refuse on a platform we cannot drive, FIRST, so nobody is sent off to connect and hits the
// same wall a step later;
// 2. find the live session, because a setting pointed at a dead port is the failure this whole
// surface exists to prevent;
// 3. read what this Mac has RIGHT NOW, before anything is touched, so "put it back" can mean the
// actual previous state rather than "off";
// 4. PRE-FLIGHT: prove the egress can carry what the machine needs, and refuse with a sentence
// if it cannot. Nothing has been changed at this point, which is what the refusal says;
// 5. write the record, then the setting;
// 6. DEAD MAN: prove traffic still works, and if it does not, put step 3's state back exactly
// and say so. A user must never be left with a dead machine because a toggle failed.
//
// Turning it OFF is the user's explicit instruction and needs none of that. It does forget the
// record, because from that moment Whisper no longer owns the setting and must not later
// "restore" something over a choice the person has since made themselves.
func runPanelSystemProxySet(on bool, opt sysProxyEnableOptions) error {
	// A platform this build cannot drive should say so at the FIRST step. Demanding a live
	// connection first would send somebody off to open one and only then tell them the switch
	// does not exist here, which is a dead end reached the slow way.
	if !systemProxyDrivable {
		return writeSystemProxyFn(on, 0)
	}
	if !on {
		// "Off" means BACK, not off. This is the verb a person actually types, and until now it
		// was the one path that ignored the record: a Mac already behind a corporate SOCKS proxy
		// that switched Whisper on and then off was left with no proxy at all and no idea why -
		// which is the exact outcome the record was written to prevent, and which the dead man
		// and the reaper both already avoided. Measured on a Mac, `off` also left our
		// own `127.0.0.1:<session port>` sitting in the field switched off; that residue is why
		// this Mac still carries one on a second service from a session long gone.
		//
		// Only when the live setting is still the one Whisper wrote. If somebody has changed it
		// since, or Whisper never set it, `off` means what it says and nothing more.
		cur, rerr := readSystemProxyState(sysProxyLivePorts(liveStatusSessions()))
		rec, hasRec := readSysProxyRecord()
		if rerr == nil && hasRec && sysProxyRecordMatches(rec, cur) {
			if err := restoreSystemProxyFn(rec.Previous); err != nil {
				return err
			}
		} else if err := writeSystemProxyFn(false, 0); err != nil {
			return err
		}
		// The record goes, because from here Whisper no longer owns this setting and must never
		// later "restore" something over a choice the person has since made themselves. The
		// pre-flight verdict STAYS: it is a measurement of the egress, which turning a local
		// setting off did not change, and re-measuring it would cost three requests to learn
		// what we already know.
		removeSysProxyRecord()
		return reportSystemProxyState()
	}

	live := liveStatusSessions()
	if len(live) == 0 {
		return &client.ProblemError{Status: 409,
			Detail: "there is no live Whisper connection on this host to point the system proxy at - " +
				"run `whisper connect` first, then `whisper panel system-proxy on`"}
	}
	sess := live[0]
	if sess.Port <= 0 {
		return &client.ProblemError{Status: 409,
			Detail: "the live Whisper session did not record a local port, so there is nothing to point " +
				"the system proxy at - run `whisper connect` again"}
	}

	// Read the machine's own state BEFORE anything changes. Without this there is no exact state
	// to restore, and a promise to put things back that can only put them "off" is not the promise.
	prev, rerr := readSystemProxyState(sysProxyLivePorts(live))
	if rerr != nil {
		return &client.ProblemError{Status: 500,
			Detail: "could not read this Mac's current network settings, so Whisper cannot promise to put " +
				"them back if this goes wrong. Nothing has been changed: " + friendly(rerr)}
	}

	cx, cancel := ctx()
	defer cancel()
	verdict := sysProxyPreflight(cx, sess)
	writeSysProxyVerdictCache(verdict)
	if !verdict.CanEnable {
		if !opt.force {
			return &client.ProblemError{Status: 409, Detail: verdict.Reason}
		}
		// --force says what it is overriding. An override that goes quiet is how somebody ends up
		// debugging a dead browser without ever learning we had told them.
		fmt.Fprintln(os.Stderr, "whisper: --force given, turning the system proxy on anyway and "+
			"overriding this: "+verdict.Reason)
	}
	if verdict.Note != "" && !g.quiet {
		fmt.Fprintln(os.Stderr, "whisper: "+verdict.Note)
	}

	// The record goes down BEFORE the setting, so a process killed between the two leaves a
	// record of a change that never happened (which the reaper declines to act on) rather than a
	// changed setting nothing remembers making. It carries a DEADLINE, because the revert below
	// must not depend on this process living long enough to run it.
	restore := sysProxyPreviousToRestore(prev)
	writeSysProxyRecord(sysProxyRecord{
		Service:    prev.Service,
		Host:       "127.0.0.1",
		Port:       sess.Port,
		Previous:   restore,
		ArmedUntil: sysProxyArmDeadline(opt.verifyTimeout, time.Now()),
	})

	// The detached watchdog starts BEFORE the setting is written, because the window it has to
	// cover includes the write itself. If it cannot be started we do not make the change at all:
	// the entire case for offering this switch is that a failed toggle cannot leave somebody with
	// a dead machine, and without an out-of-process revert that is not a promise we can keep.
	// --force does not reach this - it overrides a verdict about the egress, not the safety net.
	if err := spawnSysProxyDeadMan(); err != nil {
		removeSysProxyRecord()
		return &client.ProblemError{Status: 500,
			Detail: "could not start the watchdog that puts this Mac's network settings back if the " +
				"change goes wrong (" + friendly(err) + "). Without it, a failure here could leave every " +
				"app on this machine offline with nothing left running to undo it, so nothing has been " +
				"changed. Check the whisper install and try again."}
	}
	if err := writeSystemProxyFn(true, sess.Port); err != nil {
		// A half-applied write (host set, state refused) is a real macOS outcome, so roll back
		// rather than leave the machine somewhere between two settings.
		_ = restoreSystemProxyFn(restore)
		removeSysProxyRecord()
		return err
	}

	if err := sysProxyDeadMan(sess, opt.verifyTimeout); err != nil {
		restored := restoreSystemProxyFn(restore)
		removeSysProxyRecord()
		detail := "the system proxy was switched on and then could not fetch a single page through it " +
			"within " + orSysProxyBudget(opt.verifyTimeout).String() + " (" + friendly(err) + "), so this " +
			"Mac's previous network settings have been put back exactly as they were and nothing is " +
			"routed through Whisper. Check the connection with `whisper status` and try again."
		if restored != nil {
			// The worst case, and it must never be silent: we changed the setting, the machine is
			// not working, and we could not undo it. Say exactly what to run.
			detail = "the system proxy was switched on, could not fetch a page through it (" +
				friendly(err) + "), and putting your previous settings back ALSO failed (" +
				friendly(restored) + "). Turn it off by hand now: sudo whisper panel system-proxy off"
		}
		// Replace the passing pre-flight with what actually happened. Without this the panel
		// would draw the enable button again on its very next poll, on the strength of a verdict
		// the machine has just disproved, and offer the user the same trap once a minute.
		writeSysProxyVerdictCache(sysProxyVerdict{
			Reason:    detail,
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
			Port:      sess.Port,
			Address:   sess.Address,
		})
		return &client.ProblemError{Status: 504, Detail: detail}
	}
	// Confirmed. Stand the detached watchdog down, which is a single write it is already
	// watching for. The rest of the record stays: Whisper still owns this setting, and the
	// reaper still needs to know what to put back when the session eventually ends.
	disarmSysProxyDeadMan()
	return reportSystemProxyState()
}

// orSysProxyBudget renders the budget the dead man actually used, so the message quotes the real
// window rather than the default when --verify-timeout changed it.
func orSysProxyBudget(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultSysProxyVerifyTimeout
	}
	return d
}

// reportSystemProxyState prints what the machine says NOW, not what we asked it to do. A write
// that reported success and a setting that did not change is precisely the class of lie this file
// is here to stop telling.
func reportSystemProxyState() error {
	errs := &panelErrors{}
	cx, cancel := ctx()
	defer cancel()
	leg := panelSystemAppsLeg(cx, liveStatusSessions(), panelSelectedAddress(), errs)
	if g.jsonOut {
		emitJSONValue(leg)
		return nil
	}
	renderPanelSystemProxy(leg)
	for _, e := range errs.drain() {
		fmt.Fprintln(os.Stderr, "whisper: "+e)
	}
	return nil
}

// panelSelectedAddress is the /128 this host is bound to: the live session's, or the pinned one.
func panelSelectedAddress() string {
	if live := liveStatusSessions(); len(live) > 0 && live[0].Address != "" {
		return live[0].Address
	}
	return client.ReadAgentFile("")
}

// renderPanelSystemProxy prints the state as a small table plus the one sentence a person can
// act on. The sentence is built in panel_view.go, so it is the same words the panel renders.
func renderPanelSystemProxy(leg panelSystemApps) {
	sp := leg.SystemProxy
	rows := [][]string{{"system apps", leg.State}}
	if sp.Supported {
		rows = append(rows,
			[]string{"service", orDash(sp.Service)},
			[]string{"proxy", orDash(panelHostPort(sp.Host, sp.Port))},
			[]string{"switched on", panelYesNo(sp.Enabled)},
			[]string{"points at whisper", panelYesNo(sp.PointsAtWhisper)},
			[]string{"safe to switch on", panelYesNo(leg.CanEnable)},
		)
	}
	printTable([]string{"SETTING", "VALUE"}, rows)
	if leg.Detail != "" {
		fmt.Fprintln(os.Stderr, leg.Detail)
	}
	// The pre-flight's own answer, and its age. A verdict measured a minute ago is still worth
	// printing; passing it off as this second's reading would not be.
	if leg.CannotEnableReason != "" {
		fmt.Fprintln(os.Stderr, "whisper: "+leg.CannotEnableReason+panelCheckedAgo(leg.PreflightAgeSeconds))
	}
}

func panelYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
