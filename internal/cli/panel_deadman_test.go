// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// panel_deadman_test.go covers the half of the revert that has to survive losing this process.
//
// The switch already refused what it could not vouch for and already put the previous setting
// back when traffic did not work. Both ran inside the process that made the change, so the
// promise held only while that process lived - and Ctrl-C during the twenty seconds it verifies,
// quitting the menu bar app, or a lid closing all end it. Every one of those left the macOS SOCKS
// setting switched on with nothing running that knew it had been changed: the same dead machine,
// reached a different way.
//
// So each test below asks the same question in a different shape: if this process disappears
// right here, does something still put the Mac back?

// deadManSess sets up a live session and a fake Mac, and returns both.
func deadManSess(t *testing.T, prev systemProxyState) (*panelSysProxyMac, statusSession) {
	t.Helper()
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	mac := (&panelSysProxyMac{current: prev}).install(t)
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	return mac, sess
}

// stubDeadManSpawn replaces the detached spawn with a recorder, and reports what the record and
// the setting looked like AT THE MOMENT the watchdog would have been started. That ordering is
// the property: a watchdog started after the write cannot cover the write.
func stubDeadManSpawn(t *testing.T, err error) *deadManSpawn {
	t.Helper()
	spy := &deadManSpawn{err: err}
	saved := spawnSysProxyDeadMan
	spawnSysProxyDeadMan = func() error {
		spy.calls++
		spy.recordAtSpawn, spy.hadRecord = readSysProxyRecord()
		spy.writesAtSpawn = len(spawnWritesSoFar(spy))
		return spy.err
	}
	t.Cleanup(func() { spawnSysProxyDeadMan = saved })
	return spy
}

type deadManSpawn struct {
	err           error
	calls         int
	recordAtSpawn sysProxyRecord
	hadRecord     bool
	writesAtSpawn int
	mac           *panelSysProxyMac
}

// spawnWritesSoFar is how many writes the fake Mac had taken at the moment the watchdog was
// started, which is what turns "arms a revert" into "arms it before it can be needed".
func spawnWritesSoFar(s *deadManSpawn) []int {
	if s.mac == nil {
		return nil
	}
	return s.mac.writes()
}

// passingLegs lets the pre-flight and the in-process verification both succeed.
func passingLegs(addr string) *fakeSysProxyLegs {
	return &fakeSysProxyLegs{
		answers: true,
		egress:  func(int) (string, error) { return addr, nil },
		v4:      func() sysProxyV4Leg { return sysProxyV4Leg{Host: "api.ipify.org", Tried: true} },
	}
}

// --- arming ------------------------------------------------------------------------------------

// TestPanelSystemProxy_ArmsADetachedRevertBeforeItChangesAnything is the ordering the whole
// safety net rests on. The record has to be on disk with a deadline, and the detached watchdog
// has to be running, BEFORE the setting is written - because the window they exist to cover
// includes the write itself.
func TestPanelSystemProxy_ArmsADetachedRevertBeforeItChangesAnything(t *testing.T) {
	mac, sess := deadManSess(t, systemProxyState{Supported: true, Service: "Wi-Fi"})
	panelStubSysProxyLegs(t, passingLegs(sess.Address))
	spy := stubDeadManSpawn(t, nil)
	spy.mac = mac

	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: time.Second}); err != nil {
		t.Fatalf("system-proxy on: %v", err)
	}
	if spy.calls != 1 {
		t.Fatalf("the detached revert was started %d times, want exactly 1 - without it the promise "+
			"that a failed toggle cannot leave a dead machine holds only while this process lives",
			spy.calls)
	}
	if !spy.hadRecord {
		t.Fatal("the watchdog was started before the record it reads was written, so it would have " +
			"woken with nothing to put back")
	}
	if spy.recordAtSpawn.ArmedUntil == "" {
		t.Fatal("the record carried no deadline when the watchdog was started, so the watchdog would " +
			"stand down immediately and the machine would be left as it is")
	}
	if spy.writesAtSpawn != 0 {
		t.Fatalf("the setting was already written (%d writes) when the watchdog was started, so a kill "+
			"in between would leave a changed setting nothing was watching", spy.writesAtSpawn)
	}
	at, err := time.Parse(time.RFC3339, spy.recordAtSpawn.ArmedUntil)
	if err != nil {
		t.Fatalf("the deadline is not a timestamp the watchdog can read: %q", spy.recordAtSpawn.ArmedUntil)
	}
	if !at.After(time.Now()) {
		t.Fatalf("the deadline is already in the past, so the watchdog fires before the check it is "+
			"backing has had a chance to run: %s", spy.recordAtSpawn.ArmedUntil)
	}
}

// TestPanelSystemProxy_RefusesWhenTheDetachedRevertCannotBeStarted. The entire case for offering
// this switch at all is that a failure cannot leave somebody with a dead machine. If the safety
// net will not open, we do not jump.
func TestPanelSystemProxy_RefusesWhenTheDetachedRevertCannotBeStarted(t *testing.T) {
	mac, sess := deadManSess(t, systemProxyState{Supported: true, Service: "Wi-Fi"})
	panelStubSysProxyLegs(t, passingLegs(sess.Address))
	stubDeadManSpawn(t, errors.New("fork/exec: no such file or directory"))

	err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: time.Second})
	if err == nil {
		t.Fatal("the setting was changed with no out-of-process revert armed, which is the exact " +
			"promise this surface makes and cannot keep without one")
	}
	for _, want := range []string{"watchdog", "nothing has been changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must say what could not be started and that nothing changed; %q is "+
				"missing from:\n%s", want, err.Error())
		}
	}
	if len(mac.writes()) != 0 {
		t.Fatalf("the system proxy was written anyway: %v", mac.writes())
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("a change that never happened left a record behind for the reaper to trip over")
	}
}

// TestPanelSystemProxy_ConfirmingStandsTheDetachedRevertDown. The watchdog reverts on a deadline,
// not on a health check, so a working change MUST clear the deadline or the machine gets its
// proxy pulled out from under it twenty seconds later.
func TestPanelSystemProxy_ConfirmingStandsTheDetachedRevertDown(t *testing.T) {
	mac, sess := deadManSess(t, systemProxyState{Supported: true, Service: "Wi-Fi"})
	panelStubSysProxyLegs(t, passingLegs(sess.Address))
	stubDeadManSpawn(t, nil)

	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: time.Second}); err != nil {
		t.Fatalf("system-proxy on: %v", err)
	}
	rec, ok := readSysProxyRecord()
	if !ok {
		t.Fatal("a successful enable forgot the record, so the reaper can no longer put this Mac back " +
			"when the session ends")
	}
	if rec.ArmedUntil != "" {
		t.Fatalf("the armed revert was left standing after the change was confirmed working, so the "+
			"watchdog will undo a proxy that works: %q", rec.ArmedUntil)
	}
	if len(mac.restores()) != 0 {
		t.Fatalf("a successful enable restored something: %v", mac.restores())
	}
}

// TestPanelSystemProxy_AFailedDeadManLeavesNothingToFire. The in-process check failed and put
// everything back; the detached one must then find nothing to do rather than restore a second
// time over whatever the person has set since.
func TestPanelSystemProxy_AFailedDeadManLeavesNothingToFire(t *testing.T) {
	_, sess := deadManSess(t, systemProxyState{
		Supported: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi"})
	legs := &fakeSysProxyLegs{answers: true}
	legs.egress = func(call int) (string, error) {
		if call == 1 {
			return sess.Address, nil
		}
		return "", errors.New("the local Whisper proxy is not answering")
	}
	legs.v4 = func() sysProxyV4Leg { return sysProxyV4Leg{Host: "api.ipify.org", Tried: true} }
	panelStubSysProxyLegs(t, legs)
	stubDeadManSpawn(t, nil)
	sysProxyVerifyPoll = 10 * time.Millisecond
	t.Cleanup(func() { sysProxyVerifyPoll = 1500 * time.Millisecond })

	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: 80 * time.Millisecond}); err == nil {
		t.Fatal("the in-process dead man did not report the failure")
	}
	res := runSysProxyDeadManWatch()
	if res.Reverted {
		t.Fatalf("the detached watchdog restored a second time over a machine already put back: %+v", res)
	}
	if !strings.Contains(res.Detail, "no record") {
		t.Fatalf("the watchdog must say why it stood down: %q", res.Detail)
	}
}

// --- the watchdog's own judgement --------------------------------------------------------------

func TestSysProxyDeadMan_Decides(t *testing.T) {
	now := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	armed := func(at time.Time) sysProxyRecord {
		return sysProxyRecord{Port: 55312, Host: "127.0.0.1", ArmedUntil: at.UTC().Format(time.RFC3339)}
	}
	cases := map[string]struct {
		rec       sysProxyRecord
		ok        bool
		wantFire  bool
		wantStop  bool
		wantWait  bool
		wantInWhy string
	}{
		"no record at all": {
			ok: false, wantStop: true, wantInWhy: "nothing to revert"},
		"the change was confirmed": {
			rec: sysProxyRecord{Port: 55312}, ok: true, wantStop: true, wantInWhy: "stood down"},
		"the deadline has passed": {
			rec: armed(now.Add(-time.Second)), ok: true, wantFire: true},
		"the deadline is exactly now": {
			rec: armed(now), ok: true, wantFire: true},
		"the deadline is still ahead": {
			rec: armed(now.Add(30 * time.Second)), ok: true, wantWait: true},
		// A deadline we cannot read means we cannot tell whether the change was ever confirmed.
		// Reverting a setting that might have been fine leaves a working Mac; the other choice
		// might not.
		"an unreadable deadline": {
			rec: sysProxyRecord{Port: 55312, ArmedUntil: "soonish"}, ok: true, wantFire: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			step := sysProxyDeadManDecide(tc.rec, tc.ok, now, time.Second)
			if step.Fire != tc.wantFire {
				t.Fatalf("fire=%v want %v (%+v)", step.Fire, tc.wantFire, step)
			}
			if step.Stop != tc.wantStop {
				t.Fatalf("stop=%v want %v (%+v)", step.Stop, tc.wantStop, step)
			}
			if tc.wantWait && step.Wait <= 0 {
				t.Fatalf("the watchdog would spin instead of waiting: %+v", step)
			}
			if tc.wantInWhy != "" && !strings.Contains(step.Why, tc.wantInWhy) {
				t.Fatalf("the reason %q does not contain %q", step.Why, tc.wantInWhy)
			}
		})
	}
}

// TestSysProxyDeadMan_FiresWhenNobodyConfirmedTheChange is the whole point: the process that made
// the change is gone, and the Mac is still put back EXACTLY as it was found.
func TestSysProxyDeadMan_FiresWhenNobodyConfirmedTheChange(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSysProxyRecord(sysProxyRecord{
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		ArmedUntil: time.Now().Add(-time.Second).UTC().Format(time.RFC3339),
		Previous: sysProxyPrevious{
			Known: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi"},
	})

	res := runSysProxyDeadManWatch()
	if !res.Reverted {
		t.Fatalf("the armed revert did not fire, so a Mac whose toggle was interrupted stays pointed "+
			"at an unverified proxy forever: %+v", res)
	}
	got := mac.restores()
	if len(got) != 1 {
		t.Fatalf("nothing was restored: %v", got)
	}
	if !got[0].Enabled || got[0].Host != "proxy.corp.example" || got[0].Port != 1080 {
		t.Fatalf("the previous state was not put back exactly - a Mac behind a corporate proxy must "+
			"end up behind it again: %+v", got[0])
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("the record survived the revert, so a later reap would act on a setting we no longer own")
	}
	if !strings.Contains(res.Detail, "nothing ever confirmed") {
		t.Fatalf("the watchdog must say why it acted: %q", res.Detail)
	}
}

// TestSysProxyDeadMan_LeavesASettingItDidNotWriteAlone. The same ownership rule the reaper obeys,
// because a detached process that changes system settings on a partial match is worse than the
// bug it is fixing.
func TestSysProxyDeadMan_LeavesASettingItDidNotWriteAlone(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 44444, Service: "Wi-Fi",
	}}).install(t)
	writeSysProxyRecord(sysProxyRecord{
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		ArmedUntil: time.Now().Add(-time.Second).UTC().Format(time.RFC3339),
		Previous:   sysProxyPrevious{Known: true, Service: "Wi-Fi"},
	})

	res := runSysProxyDeadManWatch()
	if res.Reverted || len(mac.restores()) != 0 {
		t.Fatalf("the watchdog changed a setting that is no longer the one Whisper wrote: %+v", res)
	}
	if !strings.Contains(res.Detail, "not that any more") {
		t.Fatalf("the watchdog must say what it found instead: %q", res.Detail)
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("a stale armed record was left on disk, so the next reap would fire on it")
	}
}

// --- the third rung: reap, for when the watchdog is lost too -----------------------------------

// TestPanelSystemProxyReap_FiresAnExpiredArmEvenOnALiveSession.
//
// Kill the toggle AND its watchdog and the setting is left on, pointed at a session that is still
// alive, so every earlier branch of the reaper reads "exactly where it should point" and nothing
// ever puts the machine back. The resident panel polls reap; this is the last rung.
func TestPanelSystemProxyReap_FiresAnExpiredArmEvenOnALiveSession(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil) // the session IS alive, which is what makes this case invisible
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:55312", "wireguard"))
	writeSysProxyRecord(sysProxyRecord{
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		ArmedUntil: time.Now().Add(-time.Second).UTC().Format(time.RFC3339),
		Previous:   sysProxyPrevious{Known: true, Service: "Wi-Fi"},
	})

	res, err := runSysProxyReap()
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if !res.Reverted {
		t.Fatalf("an armed revert whose deadline passed was left standing because the session happens "+
			"to be alive, so nothing on this Mac will ever put the setting back: %+v", res)
	}
	if len(mac.restores()) != 1 {
		t.Fatalf("nothing was restored: %v", mac.restores())
	}
	if !strings.Contains(res.Detail, "nothing ever confirmed") {
		t.Fatalf("the reaper must say it was the armed revert, not a dead port: %q", res.Detail)
	}
}

// TestPanelSystemProxyReap_LeavesAConfirmedLiveSettingAlone is the control for the test above. A
// deliberate, confirmed enable must survive every poll of the reaper, forever.
func TestPanelSystemProxyReap_LeavesAConfirmedLiveSettingAlone(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:55312", "wireguard"))
	writeSysProxyRecord(sysProxyRecord{ // no ArmedUntil: the change was confirmed
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		Previous: sysProxyPrevious{Known: true, Service: "Wi-Fi"},
	})

	res, err := runSysProxyReap()
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if res.Reverted || len(mac.restores()) != 0 {
		t.Fatalf("the reaper undid a working system proxy the user deliberately switched on: %+v", res)
	}
	if !strings.Contains(res.Detail, "exactly where it should point") {
		t.Fatalf("unexpected reason: %q", res.Detail)
	}
}

// --- the wiring, end to end --------------------------------------------------------------------

// TestSysProxyDeadMan_TheArgvTheWatchdogIsStartedWithIsOneTheCLIAccepts.
//
// The house defect this repo keeps producing is a feature that ships, passes its tests, and can
// never execute. A watchdog spawned as `whisper panel system-proxy dead-man` is worth exactly
// nothing if the command surface does not accept that argv, and nothing in the spawn path would
// ever tell us: the detached process fails, its output goes to a log nobody reads, and the
// parent has already released it. So the REAL root command is handed the SAME argv the spawner
// uses, and it has to run.
func TestSysProxyDeadMan_TheArgvTheWatchdogIsStartedWithIsOneTheCLIAccepts(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	systemProxyDrivable = true

	var runErr error
	stdout, stderr := captureStd(t, func() {
		root := NewRootCommand()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetArgs(sysProxyDeadManArgv)
		runErr = root.Execute()
	})
	if runErr != nil {
		t.Fatalf("`whisper %s` - the argv the detached watchdog is started with - does not run: %v",
			strings.Join(sysProxyDeadManArgv, " "), runErr)
	}
	// With no record on disk there is nothing to revert, and saying so is the whole output. The
	// watchdog writes to the process streams, which is what its log file captures in the field.
	if !strings.Contains(stderr, "nothing to revert") || !strings.Contains(stdout, "stood-down") {
		t.Fatalf("the watchdog verb ran but did not report its reasoning:\nstdout=%q\nstderr=%q",
			stdout, stderr)
	}
	if !commandAcceptsVerb(t, "reap") {
		t.Fatal("`system-proxy reap` stopped being accepted, which is the third rung of the same ladder")
	}
}

// commandAcceptsVerb reports whether `panel system-proxy <verb>` is understood, by checking the
// verb is not rejected as unknown.
func commandAcceptsVerb(t *testing.T, verb string) bool {
	t.Helper()
	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	root.SetArgs([]string{"panel", "system-proxy", verb})
	err := root.Execute()
	return err == nil || !strings.Contains(err.Error(), "got \""+verb+"\"")
}

// TestSysProxyDeadMan_AnUnknownVerbIsStillRefused keeps the surface honest now that it has grown
// a fifth verb: a typo must not silently do nothing and exit 0.
func TestSysProxyDeadMan_AnUnknownVerbIsStillRefused(t *testing.T) {
	panelIsolation(t)
	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	root.SetArgs([]string{"panel", "system-proxy", "deadmanx"})
	err := root.Execute()
	if err == nil {
		t.Fatal("a mistyped verb exited 0")
	}
	if !strings.Contains(err.Error(), "dead-man") {
		t.Fatalf("the usage error should list the verbs that do exist: %v", err)
	}
}

// TestSysProxyDeadMan_TheSpawnHoldsNoneOfTheParentsPipes.
//
// The macOS panel runs the CLI and reads its stderr to EOF before waiting on it. A detached
// grandchild that inherited that pipe would hold it open for the whole arm window, and the panel
// would sit there looking hung for exactly as long as the safety net lasts. So the spawn is built
// and inspected here rather than trusted.
func TestSysProxyDeadMan_TheSpawnHoldsNoneOfTheParentsPipes(t *testing.T) {
	dir := panelIsolation(t)
	if err := spawnSysProxyDeadMan(); err != nil {
		t.Skipf("the test binary cannot re-exec itself here: %v", err)
	}
	// The log it was pointed at is the only stdio it has, and it lives beside the record.
	if !strings.HasPrefix(sysProxyDeadManLogPath(), dir) {
		t.Fatalf("the watchdog log is not in this test's isolated home: %q", sysProxyDeadManLogPath())
	}
	if _, err := os.Stat(sysProxyDeadManLogPath()); err != nil {
		t.Fatalf("the watchdog was started with no log to write to, so nothing it decides can ever be "+
			"read back: %v", err)
	}
}

// --- "off" means back, not off -----------------------------------------------------------------

// TestPanelSystemProxyOff_PutsThePreviousSettingBackNotJustOff.
//
// The record was written so a Mac already behind a corporate SOCKS proxy ends up behind it again.
// The dead man used it, the reaper used it, and the one verb a person actually types did not: it
// set the state to off and forgot the record, leaving somebody off their company network with no
// idea why. Measured on a real Mac, it also left our own 127.0.0.1:<session port> sitting in the
// field switched off, which is the residue this Mac still carries on a second service.
func TestPanelSystemProxyOff_PutsThePreviousSettingBackNotJustOff(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:55312", "wireguard"))
	writeSysProxyRecord(sysProxyRecord{
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		Previous: sysProxyPrevious{
			Known: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi"},
	})

	if err := runPanelSystemProxySet(false, sysProxyEnableOptions{}); err != nil {
		t.Fatalf("system-proxy off: %v", err)
	}
	got := mac.restores()
	if len(got) != 1 {
		t.Fatalf("`off` switched the proxy off instead of putting the previous setting back, so a Mac "+
			"behind a corporate proxy is now behind nothing: restores=%v writes=%v", got, mac.writes())
	}
	if !got[0].Enabled || got[0].Host != "proxy.corp.example" || got[0].Port != 1080 {
		t.Fatalf("the previous setting was not put back exactly: %+v", got[0])
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("`off` kept the record, so Whisper would later 'restore' over a choice the person has " +
			"since made themselves")
	}
}

// TestPanelSystemProxyOff_LeavesASettingWhisperDidNotWriteAlone is the control. `off` must not
// reach for a record that does not describe what is actually set: that would let it "restore"
// something on the strength of a change somebody else has since replaced.
func TestPanelSystemProxyOff_OnASettingWhisperNoLongerOwnsJustSwitchesOff(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, true, nil)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi",
	}}).install(t)
	writeSysProxyRecord(sysProxyRecord{ // a record for a DIFFERENT setting
		Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		Previous: sysProxyPrevious{Known: true, Enabled: true, Host: "old.example", Port: 3128},
	})

	if err := runPanelSystemProxySet(false, sysProxyEnableOptions{}); err != nil {
		t.Fatalf("system-proxy off: %v", err)
	}
	if len(mac.restores()) != 0 {
		t.Fatalf("`off` restored a setting Whisper does not own: %+v", mac.restores())
	}
	if mac.current.Enabled {
		t.Fatal("`off` did not switch the proxy off")
	}
}
