// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package resolverprofile

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The apply-cluster tests for the LINUX applier: command/write
// construction through the seams - NO real system mutation anywhere - the
// not-root contract, the pre-state guard semantics, and the verify-then-
// rollback discipline.

// t2linFake replaces every seam with recorders. Nothing touches the real
// system: exec, writes, removes, stat, dial and sleep are all faked.
type t2linFake struct {
	euid     int
	present  map[string]bool   // paths that "exist" for stat
	verOut   map[string]string // argv[0] -> version-probe stdout
	cmds     [][]string
	outs     [][]string // linuxRunOut calls (the version probes)
	writes   []string   // "path|content-prefix"
	removes  []string
	dialErr  error
	cmdErr   func(argv []string) error // nil = every command succeeds
	dialTrys int
}

func (f *t2linFake) install(t *testing.T) {
	t.Helper()
	savedEuid, savedRun, savedWrite := linuxGeteuid, linuxRunCmd, linuxWrite
	savedMkdir, savedRemove, savedStat := linuxMkdirAll, linuxRemove, linuxStat
	savedDial, savedSleep, savedLook := linuxDial, linuxSleep, linuxLookPath
	savedRunOut := linuxRunOut
	t.Cleanup(func() {
		linuxGeteuid, linuxRunCmd, linuxWrite = savedEuid, savedRun, savedWrite
		linuxMkdirAll, linuxRemove, linuxStat = savedMkdir, savedRemove, savedStat
		linuxDial, linuxSleep, linuxLookPath = savedDial, savedSleep, savedLook
		linuxRunOut = savedRunOut
	})
	linuxGeteuid = func() int { return f.euid }
	linuxRunOut = func(argv []string) (string, error) {
		f.outs = append(f.outs, argv)
		if out, ok := f.verOut[argv[0]]; ok {
			return out, nil
		}
		return "", nil
	}
	linuxRunCmd = func(argv []string) error {
		f.cmds = append(f.cmds, argv)
		if f.cmdErr != nil {
			return f.cmdErr(argv)
		}
		return nil
	}
	linuxWrite = func(path string, data []byte, _ fs.FileMode) error {
		content := string(data)
		if len(content) > 40 {
			content = content[:40]
		}
		f.writes = append(f.writes, path+"|"+content)
		return nil
	}
	linuxMkdirAll = func(string, fs.FileMode) error { return nil }
	linuxRemove = func(path string) error {
		f.removes = append(f.removes, path)
		return nil
	}
	linuxStat = func(path string) (os.FileInfo, error) {
		if f.present[path] {
			return nil, nil //nolint:nilnil // the applier only checks the error
		}
		return nil, os.ErrNotExist
	}
	linuxDial = func(_, _ string, _ time.Duration) (net.Conn, error) {
		f.dialTrys++
		if f.dialErr != nil {
			return nil, f.dialErr
		}
		c, s := net.Pipe()
		_ = s.Close()
		return c, nil
	}
	linuxSleep = func(time.Duration) {}
}

// cmdStrings flattens recorded argvs for contains-assertions.
func (f *t2linFake) cmdStrings() []string {
	out := make([]string, 0, len(f.cmds))
	for _, c := range f.cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func t2linDNS53Rendered() Rendered {
	return Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{t2LinIP}}.Render(t2HostNoFwd)
}

func TestT2LinuxApplyNotRootIsErrNeedsRootAndTouchesNothing(t *testing.T) {
	f := &t2linFake{euid: 1000}
	f.install(t)
	err := linuxApplier{}.Apply(t2linDNS53Rendered())
	if !errors.Is(err, ErrNeedsRoot) {
		t.Fatalf("not-root apply must return ErrNeedsRoot (the CLI then prints the sudo block), got: %v", err)
	}
	if len(f.writes) != 0 || len(f.removes) != 0 {
		t.Fatalf("not-root apply must not mutate anything: writes=%v removes=%v", f.writes, f.removes)
	}
}

func TestT2LinuxApplyDNS53OrderAndVerify(t *testing.T) {
	f := &t2linFake{euid: 0}
	f.install(t)
	if err := (linuxApplier{}.Apply(t2linDNS53Rendered())); err != nil {
		t.Fatalf("apply errored: %v", err)
	}
	// Write the drop-in, restart resolved, then VERIFY through the system
	// resolver (a neutral name - the ns boxes answer whisper.online
	// authoritatively even when refusing recursion).
	if len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], LinuxDropIn+"|") {
		t.Fatalf("apply must write the drop-in: %v", f.writes)
	}
	cmds := f.cmdStrings()
	if len(cmds) != 2 || cmds[0] != "systemctl restart systemd-resolved" || cmds[1] != "getent hosts example.com" {
		t.Fatalf("apply command order wrong: %v", cmds)
	}
}

func TestT2LinuxApplyVerifyFailureRollsBack(t *testing.T) {
	f := &t2linFake{euid: 0, present: map[string]bool{LinuxDropIn: true}}
	f.cmdErr = func(argv []string) error {
		if argv[0] == "getent" {
			return errors.New("no answer")
		}
		return nil
	}
	f.install(t)
	err := linuxApplier{}.Apply(t2linDNS53Rendered())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("verify failure must report the rollback plainly, got: %v", err)
	}
	// The revert plan ran: the drop-in (present per the fake) was removed and
	// resolved restarted again.
	found := false
	for _, r := range f.removes {
		if r == LinuxDropIn {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollback must remove the drop-in: removes=%v cmds=%v", f.removes, f.cmdStrings())
	}
}

func TestT2LinuxApplyDoHWaitsBeforeRepoint(t *testing.T) {
	f := &t2linFake{euid: 0}
	f.install(t)
	r := Profile{Mode: ModeDoH, OS: "linux", DohTemplate: t2LinDoH}.Render(t2HostResolvedCF)
	if err := (linuxApplier{}.Apply(r)); err != nil {
		t.Fatalf("apply errored: %v", err)
	}
	if f.dialTrys == 0 {
		t.Fatalf("the DoH apply must probe the forwarder before repointing")
	}
	// Unit written, then the drop-in - in that order.
	if len(f.writes) != 2 || !strings.HasPrefix(f.writes[0], LinuxForwarderUnit+"|") || !strings.HasPrefix(f.writes[1], LinuxDropIn+"|") {
		t.Fatalf("DoH write order wrong: %v", f.writes)
	}
	cmds := strings.Join(f.cmdStrings(), "\n")
	for _, want := range []string{"systemctl daemon-reload", "systemctl enable --now whisper-dns", "systemctl restart systemd-resolved"} {
		if !strings.Contains(cmds, want) {
			t.Fatalf("DoH apply must run %q:\n%s", want, cmds)
		}
	}
}

func TestT2LinuxApplyDoHWaitTimeoutStopsBeforeRepoint(t *testing.T) {
	f := &t2linFake{euid: 0, dialErr: errors.New("connection refused")}
	f.install(t)
	r := Profile{Mode: ModeDoH, OS: "linux", DohTemplate: t2LinDoH}.Render(t2HostResolvedCF)
	err := linuxApplier{}.Apply(r)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("a silent forwarder must stop the plan with a clear error, got: %v", err)
	}
	// The resolver repoint NEVER happened - DNS was left untouched.
	for _, w := range f.writes {
		if strings.HasPrefix(w, LinuxDropIn+"|") {
			t.Fatalf("the drop-in must not be written when the forwarder never answered: %v", f.writes)
		}
	}
	if f.dialTrys != 30 {
		t.Fatalf("the wait is bounded at 30 probes, got %d", f.dialTrys)
	}
}

func TestT2LinuxRevertNothingAppliedIsRootlessNoOp(t *testing.T) {
	// No whisper state on the machine: every revert step is guard-skipped, so
	// the revert succeeds WITHOUT root and runs nothing.
	f := &t2linFake{euid: 1000}
	f.install(t)
	if err := (linuxApplier{}.Revert(t2linDNS53Rendered())); err != nil {
		t.Fatalf("nothing-applied revert must be a clean no-op, got: %v", err)
	}
	if len(f.cmds) != 0 || len(f.removes) != 0 {
		t.Fatalf("nothing-applied revert must run nothing: cmds=%v removes=%v", f.cmds, f.removes)
	}
}

func TestT2LinuxRevertPreStateGuards(t *testing.T) {
	// Guards are evaluated against the PRE-state: the drop-in exists at plan
	// start, so BOTH its removal and the follow-up resolved restart run, even
	// though the removal precedes the restart.
	f := &t2linFake{euid: 0, present: map[string]bool{LinuxDropIn: true}}
	f.install(t)
	if err := (linuxApplier{}.Revert(t2linDNS53Rendered())); err != nil {
		t.Fatalf("revert errored: %v", err)
	}
	if len(f.removes) != 1 || f.removes[0] != LinuxDropIn {
		t.Fatalf("revert must remove the drop-in: %v", f.removes)
	}
	cmds := f.cmdStrings()
	if len(cmds) != 1 || cmds[0] != "systemctl restart systemd-resolved" {
		t.Fatalf("revert must restart resolved exactly once (pre-state guard): %v", cmds)
	}
}

func TestT2LinuxRevertFullStateRunsEverything(t *testing.T) {
	f := &t2linFake{euid: 0, present: map[string]bool{
		LinuxForwarderUnit:  true,
		LinuxDNSCryptConfig: true,
		LinuxDropIn:         true,
		LinuxResolvBackup:   true,
	}}
	f.install(t)
	if err := (linuxApplier{}.Revert(t2linDNS53Rendered())); err != nil {
		t.Fatalf("revert errored: %v", err)
	}
	cmds := strings.Join(f.cmdStrings(), "\n")
	for _, want := range []string{
		"systemctl disable --now whisper-dns",
		"systemctl daemon-reload",
		"systemctl restart systemd-resolved",
		"cp " + LinuxResolvBackup + " " + LinuxResolvConf,
	} {
		if !strings.Contains(cmds, want) {
			t.Fatalf("full revert must run %q:\n%s", want, cmds)
		}
	}
	removed := strings.Join(f.removes, "\n")
	for _, want := range []string{LinuxForwarderUnit, LinuxDNSCryptConfig, LinuxDropIn, LinuxResolvBackup} {
		if !strings.Contains(removed, want) {
			t.Fatalf("full revert must remove %q: %v", want, f.removes)
		}
	}
}

func TestT2LinuxDetectHostUnprivileged(t *testing.T) {
	f := &t2linFake{euid: 1000, verOut: map[string]string{"/usr/bin/dnscrypt-proxy": "2.0.45\n"}}
	f.install(t)
	savedLook := linuxLookPath
	linuxLookPath = func(name string) (string, error) {
		if name == "dnscrypt-proxy" {
			return "/usr/bin/dnscrypt-proxy", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { linuxLookPath = savedLook })
	h := linuxApplier{}.DetectHost()
	if h.Elevated {
		t.Fatalf("euid 1000 must not read as elevated")
	}
	if h.ForwarderKind != "dnscrypt-proxy" || h.ForwarderPath != "/usr/bin/dnscrypt-proxy" {
		t.Fatalf("forwarder detection wrong: %+v", h)
	}
	// The VERSION rides along, so the render emits config the installed
	// forwarder actually accepts (2.0.45 fatals on the 2.1 key).
	if h.ForwarderVersion != "2.0.45" {
		t.Fatalf("forwarder version must be detected, got %q", h.ForwarderVersion)
	}
	// The resolved probe went through the seam (is-active), not a real systemctl.
	if got := f.cmdStrings(); len(got) != 1 || !strings.Contains(got[0], "is-active") {
		t.Fatalf("DetectHost must probe resolved via the seam: %v", got)
	}
}

func TestT2LinuxDetectHostSkipsForwarderlessCloudflared(t *testing.T) {
	// cloudflared >= 2026.2.0 removed proxy-dns: it must NOT be selected (a
	// crash-looping unit is worse than none), and the why is carried for the
	// render's notes.
	f := &t2linFake{euid: 1000, verOut: map[string]string{"/usr/local/bin/cloudflared": "cloudflared version 2026.8.2 (built 2026-08-14-12:17 UTC)\n"}}
	f.install(t)
	savedLook := linuxLookPath
	linuxLookPath = func(name string) (string, error) {
		if name == "cloudflared" {
			return "/usr/local/bin/cloudflared", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { linuxLookPath = savedLook })
	h := linuxApplier{}.DetectHost()
	if h.ForwarderKind != "" || h.ForwarderPath != "" {
		t.Fatalf("a proxy-dns-less cloudflared must not be selected: %+v", h)
	}
	if !strings.Contains(h.ForwarderRejected, "proxy-dns was removed") {
		t.Fatalf("the rejection must be explained: %+v", h)
	}
}

func TestT2LinuxDetectHostAcceptsOldCloudflared(t *testing.T) {
	// A cloudflared that still ships proxy-dns (< 2026.2.0) remains usable.
	f := &t2linFake{euid: 1000, verOut: map[string]string{"/usr/local/bin/cloudflared": "cloudflared version 2025.11.1 (built 2025-11-20)\n"}}
	f.install(t)
	savedLook := linuxLookPath
	linuxLookPath = func(name string) (string, error) {
		if name == "cloudflared" {
			return "/usr/local/bin/cloudflared", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { linuxLookPath = savedLook })
	h := linuxApplier{}.DetectHost()
	if h.ForwarderKind != "cloudflared" || h.ForwarderRejected != "" {
		t.Fatalf("an old cloudflared must stay usable: %+v", h)
	}
}

func TestT2LinuxDetectHostPrefersDnscryptAndFallsBackToWellKnownPath(t *testing.T) {
	// dnscrypt-proxy is checked FIRST (it is what stock distros ship and it
	// still works), and a PATH that omits /usr/sbin (stock Debian user shells)
	// is covered by the well-known package home.
	f := &t2linFake{euid: 1000,
		present: map[string]bool{"/usr/sbin/dnscrypt-proxy": true},
		verOut:  map[string]string{"/usr/sbin/dnscrypt-proxy": "2.0.45\n"}}
	f.install(t)
	savedLook := linuxLookPath
	linuxLookPath = func(name string) (string, error) {
		if name == "cloudflared" {
			return "/usr/local/bin/cloudflared", nil // on PATH, but second in line
		}
		return "", errors.New("not found") // dnscrypt-proxy NOT on PATH
	}
	t.Cleanup(func() { linuxLookPath = savedLook })
	h := linuxApplier{}.DetectHost()
	if h.ForwarderKind != "dnscrypt-proxy" || h.ForwarderPath != "/usr/sbin/dnscrypt-proxy" || h.ForwarderVersion != "2.0.45" {
		t.Fatalf("well-known-path dnscrypt-proxy must win: %+v", h)
	}
}
