// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package resolverprofile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Linux applier's VerifyRoute, through the seams. Nothing reads the
// real system: resolvectl, files and globs are all faked.

type rcLinFake struct {
	outs    map[string][]string // "resolvectl dns" -> successive outputs ("ERR" = fail)
	files   map[string]string
	calls   map[string]int
	sleeps  int
	globbed []string
}

func (f *rcLinFake) install(t *testing.T) {
	t.Helper()
	savedOut, savedRead, savedGlob, savedSleep := linuxRunOut, linuxReadFile, linuxGlob, linuxSleep
	t.Cleanup(func() { linuxRunOut, linuxReadFile, linuxGlob, linuxSleep = savedOut, savedRead, savedGlob, savedSleep })
	f.calls = map[string]int{}
	linuxRunOut = func(argv []string) (string, error) {
		k := strings.Join(argv, " ")
		seq := f.outs[k]
		i := f.calls[k]
		f.calls[k]++
		if len(seq) == 0 {
			return "", errors.New("exec: not found")
		}
		if i >= len(seq) {
			i = len(seq) - 1
		}
		if seq[i] == "ERR" {
			return "", errors.New("exit status 1")
		}
		return seq[i], nil
	}
	linuxReadFile = func(p string) ([]byte, error) {
		if c, ok := f.files[p]; ok {
			return []byte(c), nil
		}
		return nil, os.ErrNotExist
	}
	linuxGlob = func(pattern string) ([]string, error) {
		f.globbed = append(f.globbed, pattern)
		dir := filepath.Dir(pattern)
		var m []string
		for p := range f.files {
			if filepath.Dir(p) == dir && strings.HasSuffix(p, ".conf") {
				m = append(m, p)
			}
		}
		return m, nil
	}
	linuxSleep = func(time.Duration) { f.sleeps++ }
}

func rcRendered(ip string) Rendered {
	return Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{ip}}.Render(Host{ResolvedActive: true})
}

func rcFakeFor(ev ResolvedEvidence) *rcLinFake {
	f := &rcLinFake{
		outs: map[string][]string{
			"resolvectl dns":    {ev.DNS},
			"resolvectl domain": {ev.Domain},
			"resolvectl status": {ev.Status},
		},
		files: map[string]string{LinuxResolvConf: ev.ResolvConf},
	}
	for _, c := range ev.Confs {
		f.files[c.Path] = c.Content
	}
	return f
}

func TestRouteLinuxVerifyShadowedByAdminDropIn(t *testing.T) {
	f := rcFakeFor(rcEvShadowed)
	f.install(t)
	rc := linuxApplier{}.VerifyRoute(rcRendered(rcOurs))
	if rc.State != RouteShadowed || rc.Want != rcOurs || !strings.Contains(strings.Join(rc.Problems, "\n"), rcLab) {
		t.Fatalf("the admin drop-in must be found and named: %+v", rc)
	}
	for _, d := range resolvedConfDirs {
		found := false
		for _, g := range f.globbed {
			if g == filepath.Join(d, "*.conf") {
				found = true
			}
		}
		if !found {
			t.Fatalf("drop-in dir %s was not read (globbed %v)", d, f.globbed)
		}
	}
}

func TestRouteLinuxVerifyFixed(t *testing.T) {
	f := rcFakeFor(rcEvFixed)
	f.install(t)
	if rc := (linuxApplier{}.VerifyRoute(rcRendered(rcOurs))); rc.State != RouteOurs {
		t.Fatalf("fixed state must verify: %+v", rc)
	}
}

func TestRouteLinuxVerifyRetriesWhileResolvedStarts(t *testing.T) {
	f := rcFakeFor(rcEvFixed)
	f.outs["resolvectl dns"] = []string{"ERR", "Global:\n", rcEvFixed.DNS}
	f.install(t)
	rc := linuxApplier{}.VerifyRoute(rcRendered(rcOurs))
	if rc.State != RouteOurs || f.calls["resolvectl dns"] != 3 || f.sleeps != 2 {
		t.Fatalf("a just-restarted resolved gets bounded retries: state=%v calls=%d sleeps=%d", rc.State, f.calls["resolvectl dns"], f.sleeps)
	}
}

func TestRouteLinuxVerifyFailedReadIsUnknown(t *testing.T) {
	f := rcFakeFor(rcEvFixed)
	f.outs["resolvectl dns"] = []string{"ERR"}
	f.install(t)
	rc := linuxApplier{}.VerifyRoute(rcRendered(rcOurs))
	if rc.State != RouteUnknown || !strings.Contains(rc.Unread, "resolvectl dns") || f.calls["resolvectl dns"] != 3 {
		t.Fatalf("resolvectl failing must be RouteUnknown after 3 bounded tries, never a pass: %+v calls=%d", rc, f.calls["resolvectl dns"])
	}
	f2 := rcFakeFor(rcEvFixed)
	f2.outs["resolvectl status"] = []string{"ERR"}
	f2.install(t)
	if rc := (linuxApplier{}.VerifyRoute(rcRendered(rcOurs))); rc.State != RouteUnknown {
		t.Fatalf("a failed status read is unknown too: %+v", rc)
	}
}

func TestRouteLinuxVerifyEtcMasksSameNamedDropIn(t *testing.T) {
	// /usr/lib's copy of a name that /etc also has is never read by resolved;
	// it must not be blamed.
	ev := rcEvShadowed
	f := rcFakeFor(ev)
	f.files["/usr/lib/systemd/resolved.conf.d/10-corp-dns.conf"] = "[Resolve]\nDNS=" + rcOther + "\n"
	f.install(t)
	rc := linuxApplier{}.VerifyRoute(rcRendered(rcOurs))
	if strings.Contains(strings.Join(rc.Problems, "\n"), "/usr/lib/") {
		t.Fatalf("a masked drop-in must not be named: %v", rc.Problems)
	}
}

func TestRouteLinuxVerifyDoHWantsTheForwarder(t *testing.T) {
	ev := rcEvFixed
	ev.DNS = "Global: 127.0.0.1\n"
	ev.Status = "Global\n  Current DNS Server: 127.0.0.1\n"
	f := rcFakeFor(ev)
	f.install(t)
	r := Profile{Mode: ModeDoH, OS: "linux", DohTemplate: "https://doh.whisper.online/t/dns-query"}.Render(t2HostResolvedCF)
	if rc := (linuxApplier{}.VerifyRoute(r)); rc.State != RouteOurs || rc.Want != LinuxLoopback {
		t.Fatalf("DoH verifies the local forwarder: %+v", rc)
	}
}

func TestRouteLinuxVerifyResolvConfFallback(t *testing.T) {
	r := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{rcOurs}}.Render(Host{ResolvedActive: false})
	f := &rcLinFake{files: map[string]string{LinuxResolvConf: "nameserver 192.168.1.1\n"}}
	f.install(t)
	if rc := (linuxApplier{}.VerifyRoute(r)); rc.State != RouteShadowed {
		t.Fatalf("a rewritten resolv.conf must be caught: %+v", rc)
	}
	if len(f.calls) != 0 {
		t.Fatalf("no resolved: resolvectl must not be asked: %v", f.calls)
	}
	f.files[LinuxResolvConf] = "nameserver " + rcOurs + "\n"
	if rc := (linuxApplier{}.VerifyRoute(r)); rc.State != RouteOurs {
		t.Fatalf("resolv.conf with ours first: %+v", rc)
	}
	delete(f.files, LinuxResolvConf)
	if rc := (linuxApplier{}.VerifyRoute(r)); rc.State != RouteUnknown {
		t.Fatalf("unreadable resolv.conf is unknown: %+v", rc)
	}
}
