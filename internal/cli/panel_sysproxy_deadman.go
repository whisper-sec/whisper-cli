// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// panel_sysproxy_deadman.go is the half of the revert that does not need this process to survive.
//
// WHAT WAS STILL WRONG. `system-proxy on` already refused to change anything it could not vouch
// for, and already put the previous setting back when traffic did not work afterwards. Both of
// those ran INSIDE the process that made the change. So the promise "a user is never left with a
// dead machine because a toggle failed" held only while that one process lived, and it is the
// easiest process in the world to lose: Ctrl-C in the twenty seconds it is verifying, the menu
// bar app being quit while it waits, a laptop lid closing, an OOM kill, a crash. Every one of
// those leaves the macOS SOCKS setting switched on and nothing at all left running that knows it
// was ever changed. That is the same dead machine, reached a different way.
//
// A rollback that depends on the thing it is rolling back is not a rollback.
//
// WHAT THIS DOES. Before the setting is written, the record on disk is stamped with a DEADLINE
// and a second, DETACHED process is started. That process is in its own session (Setsid on unix,
// DETACHED_PROCESS on Windows), holds none of the parent's pipes, and does exactly one thing:
// wait until the deadline, and if by then nobody has confirmed the change, put the previous
// setting back exactly and forget the record. Confirming is a single write: the parent clears the
// deadline the moment its own verification passes, and the watchdog sees that and exits.
//
// So the revert now survives losing the parent, losing the terminal, and losing the panel. It
// does not survive losing the watchdog too, which is why `system-proxy reap` also fires an
// expired arm: the resident panel polls it, and that is the third rung of the same ladder.
//
// WHY THE WATCHDOG FIRES EVEN WHEN THE MACHINE LOOKS FINE. It reverts on a deadline, not on a
// health check. Nobody confirmed the change, so we do not know it worked, and putting a machine
// back to a state it was demonstrably working in is the conservative direction. The cost of
// firing when it need not have is that somebody switches the proxy on again; the cost of not
// firing is a Mac with no internet and no way to know why.

// sysProxyDeadManGrace is added to the caller's verify budget when the deadline is stamped, so
// the in-process check has room to finish and disarm before the detached one starts acting. They
// are two views of the same window and the near one should normally win.
const sysProxyDeadManGrace = 10 * time.Second

// sysProxyDeadManPoll is how often the detached watchdog re-reads the record while it waits. It
// is short so a disarm ends the process promptly rather than leaving it sitting out the whole
// window, and a var so a test does not have to wait a second to watch it decide.
var sysProxyDeadManPoll = time.Second

// sysProxyDeadManLogPath is where the detached watchdog says what it did. It has to write
// somewhere: it has no terminal by construction, and a watchdog whose reasoning cannot be read
// after the fact is one nobody can trust. Truncated on each arm, so it is one window's worth.
func sysProxyDeadManLogPath() string {
	return filepath.Join(filepath.Dir(sysProxyRecordPath()), "sysproxy-deadman.log")
}

// sysProxyArmDeadline is the instant the watchdog acts unless the change is confirmed first.
func sysProxyArmDeadline(budget time.Duration, now time.Time) string {
	return now.Add(orSysProxyBudget(budget) + sysProxyDeadManGrace).UTC().Format(time.RFC3339)
}

// sysProxyArmExpired reports whether rec carries an arm whose moment has come.
//
// A deadline we cannot parse counts as expired. That is deliberate: an unreadable deadline means
// we cannot tell whether the change was ever confirmed, and between "revert a setting that might
// have been fine" and "leave a setting that might have taken the machine off the internet", the
// first is the answer that leaves somebody with a working Mac.
func sysProxyArmExpired(rec sysProxyRecord, now time.Time) bool {
	if rec.ArmedUntil == "" {
		return false
	}
	at, err := time.Parse(time.RFC3339, rec.ArmedUntil)
	if err != nil {
		return true
	}
	return !now.Before(at)
}

// disarmSysProxyDeadMan records that the change WAS confirmed, which is the one thing that stops
// the watchdog. The rest of the record stays: Whisper still owns this setting and the reaper
// still needs to know what to put back if the session later dies.
func disarmSysProxyDeadMan() {
	rec, ok := readSysProxyRecord()
	if !ok || rec.ArmedUntil == "" {
		return
	}
	rec.ArmedUntil = ""
	writeSysProxyRecord(rec)
}

// sysProxyDeadManArgv is the argv the detached watchdog is started with, declared once so the
// spawner and the test that proves the CLI accepts it cannot drift apart. A verb the spawner
// names and the command surface does not accept would ship a safety net that can never open.
var sysProxyDeadManArgv = []string{"panel", "system-proxy", "dead-man"}

// spawnSysProxyDeadMan starts the detached watchdog. A package var so the enable path's ORDERING
// can be asserted from a test without a second process ever being created.
var spawnSysProxyDeadMan = func() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, sysProxyDeadManArgv...)
	// No inherited pipes, ever. A caller that reads our stderr to EOF - which the macOS panel
	// does - would otherwise block for the whole arm window waiting on a grandchild it does not
	// know exists, and the panel would look hung for exactly as long as the safety net lasts.
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = nil, nil
	logPath := sysProxyDeadManLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0o700)
	if log, lerr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); lerr == nil {
		cmd.Stdout, cmd.Stderr = log, log
		defer log.Close()
	}
	applyDetach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Nothing waits for it, so release the handle rather than leave a zombie behind us.
	return cmd.Process.Release()
}

// sysProxyDeadManStep is one decision of the watchdog, taken from the record alone so the whole
// of its judgement can be tested without a clock, a process, or a Mac.
type sysProxyDeadManStep struct {
	// Fire says the deadline has passed with nothing confirmed: put the previous setting back.
	Fire bool
	// Stop says there is nothing left to watch. Why records which of the two reasons it was.
	Stop bool
	// Wait is how long to sleep before deciding again, when neither of the above applies.
	Wait time.Duration
	Why  string
}

// sysProxyDeadManDecide is the watchdog's judgement: fire, stop, or wait.
func sysProxyDeadManDecide(rec sysProxyRecord, ok bool, now time.Time, poll time.Duration) sysProxyDeadManStep {
	if !ok {
		return sysProxyDeadManStep{Stop: true,
			Why: "there is no record of a change to put back, so there is nothing to revert"}
	}
	if rec.ArmedUntil == "" {
		return sysProxyDeadManStep{Stop: true,
			Why: "the change was confirmed working, so the armed revert has been stood down"}
	}
	if sysProxyArmExpired(rec, now) {
		return sysProxyDeadManStep{Fire: true}
	}
	at, err := time.Parse(time.RFC3339, rec.ArmedUntil)
	if err != nil {
		return sysProxyDeadManStep{Fire: true}
	}
	wait := at.Sub(now)
	if wait > poll {
		wait = poll
	}
	if wait <= 0 {
		wait = time.Millisecond
	}
	return sysProxyDeadManStep{Wait: wait}
}

// sysProxyDeadManFire carries out the armed revert, under the same ownership rule as the reaper:
// only a setting that is still exactly the one Whisper wrote is Whisper's to undo.
func sysProxyDeadManFire() sysProxyReapResult {
	rec, ok := readSysProxyRecord()
	if !ok {
		return sysProxyReapResult{Action: "nothing-to-do",
			Detail: "there is no record of a change to put back"}
	}
	cur, err := readSystemProxyState(sysProxyLivePorts(liveStatusSessions()))
	if err != nil {
		return sysProxyReapResult{Action: "unknown",
			Detail: "could not read this Mac's network settings to carry out the armed revert: " + friendly(err)}
	}
	if !cur.Enabled || !sysProxyRecordMatches(rec, cur) {
		// Either the change was never made (killed between arming and writing) or somebody has
		// changed the setting since. Neither is ours to act on, and the record is stale either
		// way, so it goes rather than sitting there for a later reap to trip over.
		removeSysProxyRecord()
		return sysProxyReapResult{Action: "left-alone",
			Detail: fmt.Sprintf("the armed revert was for %s on %s, and this Mac's system proxy is not "+
				"that any more (%s). Nothing has been changed, and the stale record has been forgotten.",
				panelHostPort(rec.Host, rec.Port), orVal(rec.Service, "this Mac"),
				sysProxyStateWords(cur))}
	}
	if err := restoreSystemProxyFn(rec.Previous); err != nil {
		return sysProxyReapResult{Action: "failed",
			Detail: "the armed revert could not put this Mac's previous network settings back: " +
				friendly(err) + ". Turn the system proxy off by hand now: sudo whisper panel system-proxy off"}
	}
	removeSysProxyRecord()
	clearSysProxyVerdictCache()
	return sysProxyReapResult{Reverted: true, Action: "reverted",
		Detail: fmt.Sprintf("the system proxy was pointed at %s and nothing ever confirmed that traffic "+
			"still worked through it, so the revert Whisper armed before making the change has been "+
			"carried out: %s.", panelHostPort(rec.Host, rec.Port), describeSysProxyPrevious(rec.Previous))}
}

// sysProxyStateWords renders a live setting for a sentence a person reads.
func sysProxyStateWords(cur systemProxyState) string {
	if !cur.Enabled {
		return "it is switched off"
	}
	return "it is on " + panelHostPort(cur.Host, cur.Port)
}

// runSysProxyDeadManWatch is the detached process's whole body: wait out the arm, then fire.
func runSysProxyDeadManWatch() sysProxyReapResult {
	for {
		rec, ok := readSysProxyRecord()
		step := sysProxyDeadManDecide(rec, ok, time.Now(), sysProxyDeadManPoll)
		switch {
		case step.Stop:
			return sysProxyReapResult{Action: "stood-down", Detail: step.Why}
		case step.Fire:
			return sysProxyDeadManFire()
		default:
			time.Sleep(step.Wait)
		}
	}
}
