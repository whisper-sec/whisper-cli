// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"path"
	"sort"
	"strings"
)

// The route check answers one question after an apply: do this machine's
// lookups actually GO to the resolver we just configured? "Something resolves"
// is not that question. A host whose earlier resolved.conf.d drop-in kept its
// own server current resolved every name fine while not one packet reached
// Whisper and the tenant's policy never applied, and the CLI said
// "now resolves through Whisper" anyway.
//
// Everything here is pure: the applier gathers the evidence (resolvectl output,
// /etc/resolv.conf, the drop-in files) and this file decides. That keeps the
// decision table-testable on every OS and keeps the I/O in the Linux applier.

// RouteState is the verdict of a route check.
type RouteState int

const (
	// RouteUnknown means the evidence could not be read, so nothing is claimed
	// either way. A failed read is never rendered as a pass.
	RouteUnknown RouteState = iota
	// RouteOurs means every lookup this machine makes goes to our resolver.
	RouteOurs
	// RouteShadowed means the configuration is written but lookups go
	// elsewhere, at least in part. Problems says where and why.
	RouteShadowed
)

// RouteCheck is what the applier found after an apply.
type RouteCheck struct {
	State RouteState
	// Want is the resolver address lookups should reach (the dedicated /128,
	// or the local DoH forwarder on 127.0.0.1).
	Want string
	// Problems is one plain sentence per thing that takes lookups away from
	// Want, each ending with the fix. Empty unless State is RouteShadowed.
	Problems []string
	// Unread says what could not be read when State is RouteUnknown.
	Unread string
}

// RouteVerifier is implemented by appliers that can prove where lookups go
// after an apply. The CLI prints its success line only for RouteOurs.
type RouteVerifier interface {
	VerifyRoute(r Rendered) RouteCheck
}

// resolvedStubAddrs are the systemd-resolved stub listeners. A resolv.conf
// that points at one of them hands every glibc lookup to resolved.
var resolvedStubAddrs = map[string]bool{"127.0.0.53": true, "127.0.0.54": true}

// ConfFile is one resolved configuration file as read from disk.
type ConfFile struct {
	Path    string
	Content string
}

// ResolvedEvidence is the raw material for checking a systemd-resolved host.
type ResolvedEvidence struct {
	// Status is `resolvectl status` (only the Global "Current DNS Server" is read).
	Status string
	// DNS is `resolvectl dns`: "Global: a b" and "Link N (if): c" lines.
	DNS string
	// Domain is `resolvectl domain`, same shape as DNS.
	Domain string
	// ResolvConf is /etc/resolv.conf (after symlinks), "" when unreadable.
	ResolvConf string
	// Confs are resolved.conf and every resolved.conf.d drop-in, in any order;
	// they are only used to NAME what shadows us, never to decide.
	Confs []ConfFile
}

// resolvedScopes parses `resolvectl dns` / `resolvectl domain` output into
// scope -> values. The scope key is "Global" or the link's "Link N (if)" label.
func resolvedScopes(out string) (order []string, vals map[string][]string) {
	vals = map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// The scope ends at the first ": " (or a bare trailing ":" when the
		// scope lists nothing). Splitting at the first ":" would cut an IPv6
		// server in half: "Global: 2a04:2a01::53".
		scope, rest, ok := strings.Cut(line, ": ")
		if !ok {
			if !strings.HasSuffix(line, ":") {
				continue
			}
			scope, rest = strings.TrimSuffix(line, ":"), ""
		}
		if scope != "Global" && !strings.HasPrefix(scope, "Link ") {
			continue
		}
		if _, seen := vals[scope]; !seen {
			order = append(order, scope)
		}
		vals[scope] = append(vals[scope], strings.Fields(rest)...)
	}
	return order, vals
}

// stripServer drops resolvectl's decorations from a server token:
// "2a04::53%2#name" -> "2a04::53", "[2a04::53]:53" -> "2a04::53",
// "1.2.3.4:53" -> "1.2.3.4".
func stripServer(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			s = s[1:i]
		}
	} else if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// globalCurrentServer reads the Global section's "Current DNS Server:" from
// `resolvectl status`, "" when the section has none (resolved has not picked
// one yet).
func globalCurrentServer(status string) string {
	inGlobal := false
	for _, line := range strings.Split(status, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "Global":
			inGlobal = true
		case strings.HasPrefix(t, "Link "):
			inGlobal = false
		case inGlobal && strings.HasPrefix(t, "Current DNS Server:"):
			return stripServer(strings.TrimSpace(strings.TrimPrefix(t, "Current DNS Server:")))
		}
	}
	return ""
}

// resolvConfNameservers lists the nameserver lines of a resolv.conf in order.
func resolvConfNameservers(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, stripServer(f[1]))
		}
	}
	return out
}

// confDNSLines returns a resolved config file's DNS= values in file order; an
// empty assignment ("DNS=") is returned as "" - it clears every server set
// before it.
func confDNSLines(content string) []string {
	var out []string
	section := ""
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if strings.HasPrefix(t, "[") {
			section = t
			continue
		}
		if section != "[Resolve]" {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || strings.TrimSpace(k) != "DNS" {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			out = append(out, "")
			continue
		}
		for _, s := range strings.Fields(v) {
			out = append(out, stripServer(s))
		}
	}
	return out
}

// sortedConfs orders config files the way systemd-resolved reads them: the
// main resolved.conf first, then every drop-in by file NAME, whatever
// directory it lives in.
func sortedConfs(confs []ConfFile) []ConfFile {
	out := append([]ConfFile(nil), confs...)
	sort.SliceStable(out, func(i, j int) bool {
		mi, mj := !strings.Contains(out[i].Path, ".conf.d/"), !strings.Contains(out[j].Path, ".conf.d/")
		if mi != mj {
			return mi
		}
		return path.Base(out[i].Path) < path.Base(out[j].Path)
	})
	return out
}

// filesSetting names the config files (other than ours) that list server s,
// or that reset the list after ours when s is "".
func filesSetting(confs []ConfFile, s, ours string) []string {
	var names []string
	afterOurs := false
	for _, c := range sortedConfs(confs) {
		if c.Path == ours {
			afterOurs = true
			continue
		}
		for _, v := range confDNSLines(c.Content) {
			if (s == "" && v == "" && afterOurs) || (s != "" && v == s) {
				names = append(names, c.Path)
				break
			}
		}
	}
	return names
}

// CheckResolved decides whether a systemd-resolved host sends its lookups to
// want. matchAll is true when the profile routes every name ("~."); then a
// link that also carries "~." takes a share of the lookups, which was
// measured, not assumed: such a link received 41 of 72 upstream queries in
// parallel with ours.
func CheckResolved(want string, matchAll bool, ev ResolvedEvidence) RouteCheck {
	want = stripServer(want)
	rc := RouteCheck{Want: want}
	order, servers := resolvedScopes(ev.DNS)
	if _, ok := servers["Global"]; !ok {
		rc.Unread = "`resolvectl dns` listed no Global scope"
		return rc
	}
	global := make([]string, 0, len(servers["Global"]))
	for _, s := range servers["Global"] {
		global = append(global, stripServer(s))
	}
	has := false
	for _, s := range global {
		if s == want {
			has = true
		}
	}
	switch {
	case !has:
		p := "systemd-resolved is not using " + want + " at all"
		if len(global) > 0 {
			p += "; its global servers are " + strings.Join(global, ", ")
		}
		if by := filesSetting(ev.Confs, "", LinuxDropIn); len(by) > 0 {
			p += ". " + strings.Join(by, ", ") + " is read after " + path.Base(LinuxDropIn) + " and resets DNS=; remove that line or rename the file so it sorts before " + path.Base(LinuxDropIn)
		} else {
			p += ". A configuration read after " + LinuxDropIn + " replaced it; check /etc/systemd/resolved.conf.d and /run/systemd/resolved.conf.d"
		}
		rc.Problems = append(rc.Problems, p)
	default:
		if cur := globalCurrentServer(ev.Status); cur != "" && cur != want {
			p := "systemd-resolved's current server is " + cur + ", not " + want
			if by := filesSetting(ev.Confs, cur, LinuxDropIn); len(by) > 0 {
				p += " (set in " + strings.Join(by, ", ") + "); remove that DNS= line, then run: sudo systemctl restart systemd-resolved"
			} else {
				p += "; run: sudo systemctl restart systemd-resolved"
			}
			rc.Problems = append(rc.Problems, p)
		}
	}
	if matchAll {
		_, domains := resolvedScopes(ev.Domain)
		for _, scope := range order {
			if scope == "Global" {
				continue
			}
			routesAll := false
			for _, d := range domains[scope] {
				if d == "~." {
					routesAll = true
				}
			}
			if !routesAll || len(servers[scope]) == 0 {
				continue
			}
			ls := make([]string, 0, len(servers[scope]))
			for _, s := range servers[scope] {
				ls = append(ls, stripServer(s))
			}
			rc.Problems = append(rc.Problems, scope+" also routes every name (~.) to "+strings.Join(ls, ", ")+
				", so lookups go there as well as to Whisper; that link's own configuration (NetworkManager, systemd-networkd or a VPN client) adds the ~. - remove it there, or disconnect that link")
		}
	}
	if ev.ResolvConf != "" {
		if ns := resolvConfNameservers(ev.ResolvConf); len(ns) > 0 && !resolvedStubAddrs[ns[0]] && ns[0] != want {
			rc.Problems = append(rc.Problems, "/etc/resolv.conf sends lookups straight to "+ns[0]+", bypassing systemd-resolved; point it at the resolved stub (sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf) or stop the tool that rewrites it")
		}
	}
	if len(rc.Problems) > 0 {
		rc.State = RouteShadowed
	} else {
		rc.State = RouteOurs
	}
	return rc
}

// CheckResolvConf decides the no-resolved fallback: glibc asks the FIRST
// nameserver, so that must be ours. Something like NetworkManager or a DHCP
// hook can rewrite the file the moment we write it.
func CheckResolvConf(want, content string) RouteCheck {
	want = stripServer(want)
	rc := RouteCheck{Want: want}
	ns := resolvConfNameservers(content)
	if len(ns) == 0 {
		rc.Unread = LinuxResolvConf + " lists no nameserver"
		return rc
	}
	if ns[0] != want {
		rc.State = RouteShadowed
		rc.Problems = append(rc.Problems, LinuxResolvConf+" sends lookups to "+ns[0]+" first, not "+want+"; another tool (NetworkManager, dhclient, resolvconf) rewrote it - configure that tool to use "+want+", or stop it managing the file")
		return rc
	}
	rc.State = RouteOurs
	return rc
}
