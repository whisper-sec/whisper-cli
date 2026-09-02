// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// panel_sysproxy_record.go is the memory behind the switch, and the watchdog that uses it.
//
// WHY A RECORD. `system-proxy off` used to mean "set the state to off", which is only the right
// answer when the machine had nothing set before. A Mac behind a corporate SOCKS proxy that
// switched Whisper on and then off would be left with no proxy at all, and the person would be
// off their company network with no idea why. So we write down what the machine had BEFORE we
// touched it, and putting it back means putting THAT back, not "off".
//
// WHY A WATCHDOG. The failure that started does not need a failed toggle to happen. A
// session ends - the daemon is killed, the laptop sleeps, the tunnel drops and the holder exits -
// and the macOS setting stays behind, still switched on, still aimed at a loopback port nothing
// is serving. Every application on the machine then fails to reach the internet while the network
// settings pane cheerfully reads "on". Nothing in the system fixes that, because nothing in the
// system knows the port used to mean something.
//
// `whisper panel system-proxy reap` is that missing piece, and the resident panel calls it on
// each refresh. It is unusual for an application to change a system setting without being asked,
// so the constraint is strict and it is the whole design: it reverts ONLY a setting Whisper
// itself wrote, identified by the service name, host and port in this record. A proxy Whisper did
// not set is left alone and said so, every time, even when it is broken. Undoing our own change
// once that change has become an outage is repair; touching somebody else's setting would be
// something else entirely.

// sysProxyRecord is what Whisper wrote, and what the machine had before it wrote it.
type sysProxyRecord struct {
	// What WE set. The reaper matches on all three: if the live setting is not this one, it was
	// changed by somebody else since, and it is not ours to revert.
	Service   string `json:"service"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	WrittenAt string `json:"written_at"`
	// ArmedUntil is the instant a DETACHED watchdog puts Previous back unless the change is
	// confirmed first, and empty once it has been. It is what makes the revert survive losing
	// the process that made the change; see panel_sysproxy_deadman.go.
	ArmedUntil string `json:"armed_until,omitempty"`
	// Previous is the state to restore, exactly as it was found. Enabled:false with a host and
	// port still set is a real macOS state (a configured proxy that is switched off) and is
	// restored as such.
	Previous sysProxyPrevious `json:"previous"`
}

// sysProxyPrevious is the setting as it stood before Whisper changed it.
type sysProxyPrevious struct {
	Known   bool   `json:"known"`
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// sysProxyRecordPath is where the record lives: with the rest of the CLI's local state, mode
// 0600, no secret in it (a service name, a loopback port, and whatever proxy the machine had).
func sysProxyRecordPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "sysproxy.json")
	}
	return filepath.Join(home, ".config", "whisper", "sysproxy.json")
}

// writeSysProxyRecord remembers the change we are about to make. It is written BEFORE the setting
// is changed on purpose: a process killed between the two leaves a record for a change that never
// happened, which the reaper simply declines to act on, whereas the other order would leave a
// changed setting nothing remembers making.
func writeSysProxyRecord(rec sysProxyRecord) {
	// Stamped once, on the write that made the change. A later rewrite - standing the armed
	// revert down, say - is not a new change and must not read as one.
	if rec.WrittenAt == "" {
		rec.WrittenAt = time.Now().UTC().Format(time.RFC3339)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return
	}
	path := sysProxyRecordPath()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

// readSysProxyRecord returns the record, or ok=false when there is none we can read. An
// unreadable record is treated as no record, which makes the reaper decline rather than guess.
func readSysProxyRecord() (sysProxyRecord, bool) {
	raw, err := os.ReadFile(sysProxyRecordPath())
	if err != nil {
		return sysProxyRecord{}, false
	}
	var rec sysProxyRecord
	if json.Unmarshal(raw, &rec) != nil || rec.Port <= 0 {
		return sysProxyRecord{}, false
	}
	return rec, true
}

// removeSysProxyRecord forgets the change, which is what "Whisper no longer owns this setting"
// means on disk. Called when the switch is turned off, when a revert has been carried out, and
// when a write failed and was rolled back.
func removeSysProxyRecord() {
	_ = os.Remove(sysProxyRecordPath())
}

// sysProxyPreviousToRestore is the state a revert must put back, which is NOT always the state
// read a moment ago.
//
// Switch the proxy on, then on again for a new session, and the naive answer records OUR OWN first
// setting as "what this Mac had before". A later revert would then dutifully restore a Whisper
// proxy pointed at a port that is long gone, which is precisely the broken state all of this
// exists to undo, reinstated by the repair itself. So when the setting found on the way in is one
// Whisper is already recorded as having written, the ORIGINAL previous state is carried forward
// and the intermediate one is discarded.
func sysProxyPreviousToRestore(cur systemProxyState) sysProxyPrevious {
	if rec, ok := readSysProxyRecord(); ok && sysProxyRecordMatches(rec, cur) && rec.Previous.Known {
		return rec.Previous
	}
	return sysProxyPrevious{
		Known: true, Enabled: cur.Enabled, Host: cur.Host, Port: cur.Port, Service: cur.Service,
	}
}

// sysProxyReapResult is what the reaper did and why, in the shape both the human table and the
// panel read. Reverted:false with a Detail is the normal, common answer.
type sysProxyReapResult struct {
	Reverted bool   `json:"reverted"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
}

// runSysProxyReap is the watchdog body: revert a Whisper-set system proxy that points at a port
// no live session is serving, and do nothing at all otherwise.
//
// Every branch says what it decided. A watchdog that is silent when it declines is a watchdog
// nobody can debug, and this one declines far more often than it acts.
func runSysProxyReap() (sysProxyReapResult, error) {
	if !systemProxyDrivable {
		return sysProxyReapResult{Action: "unsupported",
			Detail: "this build cannot read or write the system network settings on this platform, so " +
				"there is nothing here to reap"}, nil
	}
	live := liveStatusSessions()
	cur, err := readSystemProxyState(sysProxyLivePorts(live))
	if err != nil {
		return sysProxyReapResult{Action: "unknown",
			Detail: "could not read this Mac's network settings: " + friendly(err)}, err
	}

	// An arm that has run out is the OTHER reason to act, and the only one that applies to a
	// setting still pointing at a live session. `system-proxy on` writes a deadline, starts a
	// detached watchdog, and clears the deadline the moment it can prove traffic works. A
	// deadline still standing after its moment means nothing ever confirmed the change AND the
	// watchdog is gone too, so this poll is the last rung of that ladder. Without it, losing
	// both processes leaves a machine that nothing will ever put back.
	rec, ok := readSysProxyRecord()
	armExpired := ok && sysProxyArmExpired(rec, time.Now()) && sysProxyRecordMatches(rec, cur)

	switch {
	case !cur.Enabled:
		return sysProxyReapResult{Action: "nothing-to-do",
			Detail: "the system proxy is switched off, so nothing is pointing anywhere"}, nil
	case cur.PointsAtWhisper && !armExpired:
		return sysProxyReapResult{Action: "nothing-to-do",
			Detail: fmt.Sprintf("the system proxy points at the live Whisper session on port %d, which is "+
				"exactly where it should point", cur.Port)}, nil
	case !isLoopbackHost(cur.Host):
		return sysProxyReapResult{Action: "left-alone",
			Detail: fmt.Sprintf("the system proxy points at %s, which is not on this machine and is not "+
				"something Whisper set. Left alone.", panelHostPort(cur.Host, cur.Port))}, nil
	}

	// Enabled, loopback, and either no live session on that port or an arm that ran out: the
	// broken state, in one of its two shapes. Only ours to fix.
	if !ok {
		return sysProxyReapResult{Action: "left-alone",
			Detail: fmt.Sprintf("the system proxy is switched on and points at %s, which no live Whisper "+
				"session is serving, but Whisper has no record of setting it. Left alone: turn it off "+
				"yourself in Network Settings, or run: whisper panel system-proxy off",
				panelHostPort(cur.Host, cur.Port))}, nil
	}
	if !sysProxyRecordMatches(rec, cur) {
		return sysProxyReapResult{Action: "left-alone",
			Detail: fmt.Sprintf("the system proxy points at %s on %s, which is not what Whisper wrote "+
				"(%s on %s). Something else changed it since, so it is not Whisper's to revert.",
				panelHostPort(cur.Host, cur.Port), orVal(cur.Service, "this Mac"),
				panelHostPort(rec.Host, rec.Port), orVal(rec.Service, "this Mac"))}, nil
	}

	if err := restoreSystemProxyFn(rec.Previous); err != nil {
		return sysProxyReapResult{Action: "failed",
			Detail: "the system proxy points at a dead Whisper session and putting the previous setting " +
				"back failed: " + friendly(err)}, err
	}
	removeSysProxyRecord()
	clearSysProxyVerdictCache()
	found := "which no live Whisper session is serving, so every app on this Mac had stopped reaching " +
		"the internet"
	if armExpired {
		found = "and nothing ever confirmed that traffic still worked through it, so the revert Whisper " +
			"armed before making the change has been carried out"
	}
	return sysProxyReapResult{Reverted: true, Action: "reverted",
		Detail: fmt.Sprintf("the system proxy was switched on and pointed at %s, %s. Whisper set "+
			"that, so Whisper put it back: %s.", panelHostPort(cur.Host, cur.Port), found,
			describeSysProxyPrevious(rec.Previous))}, nil
}

// sysProxyRecordMatches is the ownership test, and it is deliberately all three fields. A record
// that names the same service but a different port describes a change we made and something else
// has since replaced; reverting on a partial match would let Whisper undo a setting it did not
// make just because it once made one nearby.
func sysProxyRecordMatches(rec sysProxyRecord, cur systemProxyState) bool {
	if rec.Port != cur.Port {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(rec.Host), strings.TrimSpace(cur.Host)) {
		return false
	}
	// The service is compared only when both sides name one: a reader that could not determine
	// the service name should not be able to veto the repair of a setting that matches on the
	// two fields that actually identify it.
	if rec.Service != "" && cur.Service != "" && !strings.EqualFold(rec.Service, cur.Service) {
		return false
	}
	return true
}

// describeSysProxyPrevious puts the restored state into words, so "it was reverted" is followed by
// what it was reverted TO. An unknown previous state restores as off, and says that too.
func describeSysProxyPrevious(prev sysProxyPrevious) string {
	switch {
	case !prev.Known:
		return "the system proxy is now switched off (Whisper could not read what this Mac had before)"
	case prev.Enabled && prev.Port > 0:
		return "the system proxy is back on " + panelHostPort(prev.Host, prev.Port) + ", where it was before"
	case prev.Port > 0:
		return "the system proxy is switched off again, with " + panelHostPort(prev.Host, prev.Port) +
			" left configured exactly as it was found"
	default:
		return "the system proxy is switched off again, as it was before"
	}
}
