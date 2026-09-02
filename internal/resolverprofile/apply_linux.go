// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package resolverprofile

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The Linux applier: executes the rendered plan natively (systemd-resolved
// drop-in, resolv.conf fallback with backup, the whisper-dns forwarder unit,
// the bounded "answers before repoint" wait), then VERIFIES the system
// resolver still answers and rolls the plan back if it does not - a machine is
// never left with broken DNS. Least-privilege: DetectHost and every render run
// unprivileged; only Apply/Revert - the actual writes under /etc - require
// root, and without it they return ErrNeedsRoot so the CLI prints the exact
// sudo-able block instead of failing opaquely.

// Seams for the unit tests (no real system mutation in tests - the recorded
// fakes replace all of these, mirroring the sessionsDirFn pattern).
var (
	linuxGeteuid  = os.Geteuid
	linuxLookPath = exec.LookPath
	linuxRunCmd   = realRunCmd
	linuxRunOut   = realRunOut
	linuxWrite    = os.WriteFile
	linuxMkdirAll = os.MkdirAll
	linuxRemove   = os.Remove
	linuxStat     = os.Stat
	linuxDial     = net.DialTimeout
	linuxSleep    = time.Sleep
)

func init() { Register("linux", linuxApplier{}) }

type linuxApplier struct{}

// DetectHost gathers the facts the renderer needs; every probe is unprivileged.
func (linuxApplier) DetectHost() Host {
	h := Host{Elevated: linuxGeteuid() == 0}
	// `systemctl is-active` exits 0 only when the unit is active - the same probe
	// the server's Linux template uses to pick drop-in vs resolv.conf.
	h.ResolvedActive = linuxRunCmd([]string{"systemctl", "is-active", "--quiet", "systemd-resolved"}) == nil
	// dnscrypt-proxy first: it is what stock distros actually ship (apt/dnf)
	// and still carries a working DoH forwarder. cloudflared counts only while
	// it still HAS one - proxy-dns was removed in 2026.2.0 (probed by version,
	// never assumed; a forwarder that fatals on start is worse than none).
	for _, cand := range []struct {
		kind, verFlag string
		wellKnown     []string
	}{
		// Well-known package homes cover a PATH that omits them (stock Debian
		// keeps /usr/sbin off user PATH) - liberal in what we accept.
		{"dnscrypt-proxy", "-version", []string{"/usr/sbin/dnscrypt-proxy", "/usr/local/bin/dnscrypt-proxy"}},
		{"cloudflared", "--version", []string{"/usr/local/bin/cloudflared", "/usr/bin/cloudflared"}},
	} {
		path, err := linuxLookPath(cand.kind)
		if err != nil || path == "" {
			for _, wk := range cand.wellKnown {
				if _, serr := linuxStat(wk); serr == nil {
					path = wk
					break
				}
			}
		}
		if path == "" {
			continue
		}
		ver, _ := linuxRunOut([]string{path, cand.verFlag})
		if i := strings.IndexByte(ver, '\n'); i >= 0 {
			ver = ver[:i]
		}
		ver = strings.TrimSpace(ver)
		if cand.kind == "cloudflared" && cloudflaredProxyDNSRemoved(ver) {
			h.ForwarderRejected = "cloudflared is installed but no longer ships a DNS forwarder (proxy-dns was removed in cloudflared 2026.2.0) - it cannot serve this profile"
			continue
		}
		h.ForwarderKind, h.ForwarderPath, h.ForwarderVersion = cand.kind, path, ver
		break
	}
	return h
}

func (a linuxApplier) Apply(r Rendered) error {
	if len(r.Apply) == 0 {
		return nil
	}
	if err := a.run(r.Apply); err != nil {
		return err
	}
	// Never leave a machine with broken DNS: verify the system resolver still
	// answers; if not, run the (guarded, idempotent) revert plan and say
	// exactly what happened. The probe name is one Whisper is NOT
	// authoritative for on purpose: the ns boxes answer whisper.online
	// authoritatively even to a client whose recursion they would refuse, so
	// only a neutral name proves end-to-end RESOLUTION works.
	if !linuxVerifyResolution() {
		_ = a.run(r.Revert) // best-effort restore; guards make it safe
		hint := "this host may lack the route to the resolver"
		if r.Mode == ModeDNS53 {
			hint = "the dedicated resolver answers on IPv6 :53 - this host needs a global IPv6 route"
		}
		return fmt.Errorf("resolution could not be verified after the apply (%s); every change was rolled back and DNS is as it was", hint)
	}
	return nil
}

func (a linuxApplier) Revert(r Rendered) error { return a.run(r.Revert) }

// run executes steps in order, honouring the presence guards. Any step failure
// stops the plan with a clear error (the ordering guarantees DNS is never left
// half-configured: resolver repoints always come after their prerequisites).
func (linuxApplier) run(steps []Step) error {
	// Evaluate the guards FIRST (stat is unprivileged, and guards must see the
	// PRE-state of the whole plan): a plan whose every step is guard-skipped -
	// e.g. `--off` when nothing was ever applied - is a clean no-op and must
	// not demand root it will not use.
	runnable := steps[:0:0]
	for _, s := range steps {
		if guardsPass(s) {
			runnable = append(runnable, s)
		}
	}
	if len(runnable) == 0 {
		return nil
	}
	if linuxGeteuid() != 0 {
		return fmt.Errorf("%w (writing under /etc and restarting systemd units)", ErrNeedsRoot)
	}
	for _, s := range runnable {
		var err error
		switch {
		case s.File != nil:
			err = writeFileStep(*s.File)
		case s.Remove != "":
			if rmErr := linuxRemove(s.Remove); rmErr != nil && !os.IsNotExist(rmErr) {
				err = rmErr
			}
		case s.WaitFor != "":
			err = waitAnswers(s.WaitFor)
		case s.Shell != "":
			err = linuxRunCmd([]string{"bash", "-c", s.Shell})
		case len(s.Cmd) > 0:
			err = linuxRunCmd(s.Cmd)
		}
		if err != nil {
			return fmt.Errorf("step %q failed: %w", s.String(), err)
		}
	}
	return nil
}

func guardsPass(s Step) bool {
	if s.IfPresent != "" {
		if _, err := linuxStat(s.IfPresent); err != nil {
			return false
		}
	}
	if s.IfAbsent != "" {
		if _, err := linuxStat(s.IfAbsent); err == nil {
			return false
		}
	}
	return true
}

func writeFileStep(f FileSpec) error {
	if dir := filepath.Dir(f.Path); dir != "." && dir != "/" {
		if err := linuxMkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	return linuxWrite(f.Path, []byte(f.Content), mode)
}

// waitAnswers is the bounded "wait until the forwarder actually answers" gate
// (30 x 1s TCP connect probes - the server template's no-tool fallback probe).
// On timeout the plan STOPS before any resolver repoint, so DNS is left unchanged.
func waitAnswers(hostPort string) error {
	for i := 0; i < 30; i++ {
		conn, err := linuxDial("tcp", hostPort, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		linuxSleep(time.Second)
	}
	return fmt.Errorf("the local forwarder did not answer on %s within 30s; DNS was left unchanged (check: systemctl status whisper-dns)", hostPort)
}

// linuxVerifyResolution asks the SYSTEM resolver (getent goes through NSS, so
// it honours resolved and resolv.conf alike), bounded: 3 tries, 2s apart.
func linuxVerifyResolution() bool {
	for i := 0; i < 3; i++ {
		if i > 0 {
			linuxSleep(2 * time.Second)
		}
		if err := linuxRunCmd([]string{"getent", "hosts", "example.com"}); err == nil {
			return true
		}
	}
	return false
}

// realRunOut executes an argv directly (no shell) and returns its stdout -
// the version probes (`dnscrypt-proxy -version`, `cloudflared --version`).
func realRunOut(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	return string(out), err
}

// realRunCmd executes an argv directly (no shell), capturing stderr into the
// error so a failure is diagnosable, never opaque.
func realRunCmd(argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}
