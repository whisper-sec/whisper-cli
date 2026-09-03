// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package resolverprofile is the OS-agnostic Tier-2 resolver-profile MODEL plus the
// per-OS appliers behind it. A Profile says WHAT this machine's DNS should be
// (the DoH template, the dedicated :53 resolver /128s, the match domains); Render
// turns it into the exact, inspectable plan for one OS - the files to write and the
// commands to run, with their revert - as pure data. `whisper resolver --print` shows
// the plan verbatim; the registered applier for the running OS executes it.
//
// The server's live per-OS setup surfaces are the SPEC this package mirrors, so the
// CLI apply and the web-script apply converge on ONE mechanism:
// - Linux: the server's Linux setup template (systemd-resolved drop-in,
// resolv.conf fallback, cloudflared/dnscrypt-proxy DoH forwarder, bounded wait).
// - Windows: the server's Windows setup template (DoH server registration + NRPT).
// - macOS: the server's mobileconfig builder (com.apple.dnsSettings.managed).
package resolverprofile

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
)

// Mode selects which Tier-2 transport the profile configures.
type Mode string

const (
	// ModeDoH is the default: encrypted DNS-over-HTTPS (conservative out).
	ModeDoH Mode = "doh"
	// ModeDNS53 points the OS at the dedicated per-tenant /128 on plain :53
	// (no forwarder, no GUI approval - the simplest apply; plaintext on-path).
	ModeDNS53 Mode = "dns53"
)

// BareDoHURL is the bare Whisper DoH endpoint (no device token in the path).
// Tier-2 DoH is KEYED BY DESIGN: the resolver must identify the tenant to load
// and apply THEIR policy, so the endpoint answers only the per-tenant form
// (/<device-token>/dns-query) and refuses anonymous queries (403). The bare
// form exists as a template shape and a revert matcher - it is never an
// applyable profile, and the CLI never wires it into OS config.
const BareDoHURL = "https://doh.whisper.online/dns-query"

// Canonical Linux paths (shared by the renderer, the applier, and the tests -
// one source of truth so display and execution can never drift).
const (
	// LinuxDropIn is the systemd-resolved drop-in this tool owns (created by
	// apply, removed by revert). The name is ours alone - the web setup script
	// writes whisper-dns.conf, so the two never fight over one file.
	LinuxDropIn = "/etc/systemd/resolved.conf.d/whisper-resolver.conf"
	// LinuxForwarderUnit is the local DoH forwarder service (same unit name as
	// the server's Linux setup script - idempotent convergence, one mechanism).
	LinuxForwarderUnit  = "/etc/systemd/system/whisper-dns.service"
	LinuxDNSCryptConfig = "/etc/dnscrypt-proxy/whisper-dns.toml"
	LinuxResolvConf     = "/etc/resolv.conf"
	// LinuxResolvBackup matches the server script's backup path so either
	// surface can restore what the other saved.
	LinuxResolvBackup = "/etc/resolv.conf.whisper-backup"
	// LinuxLoopback is where the DoH forwarder listens (the server template's
	// 127.0.0.1:53 contract).
	LinuxLoopback = "127.0.0.1"
)

// windowsNrptComment tags every NRPT rule this tool creates so revert removes
// exactly ours and nothing else.
const windowsNrptComment = "whisper-resolver"

// darwinProfileIdentifier is the stable top-level PayloadIdentifier of the locally
// generated macOS profile, so revert can address it by name.
const darwinProfileIdentifier = "online.whisper.resolver"

// darwinMobileconfigFile is where the darwin plan stages the profile before `open`.
const darwinMobileconfigFile = "whisper-dns.mobileconfig"

// ErrNeedsRoot is returned by an applier when the plan mutates system state but the
// process is not privileged. The caller prints the exact block to run instead of
// failing opaquely (Postel: a clear, helpful path, never a dead end).
var ErrNeedsRoot = errors.New("root privileges required to change system DNS")

// Profile is the OS-agnostic description of the desired Tier-2 resolver state.
type Profile struct {
	Mode Mode
	// OS is the render target: a GOOS - linux | windows | darwin.
	OS string
	// DohTemplate is the DoH URL - the public keyless endpoint or the per-tenant
	// keyed one (the token in the path is a resolve-only device credential).
	DohTemplate string
	// ResolverIPs are the dedicated per-tenant :53 resolver /128s (usually one).
	ResolverIPs []string
	// MatchDomains says which names route through Whisper; ["."] (the default
	// when empty) means everything.
	MatchDomains []string
	// SearchDomains are real suffix SEARCH domains: the list the OS APPENDS to a
	// bare hostname, so `ping db-01` reaches db-01.<suffix>. It is a different
	// thing from MatchDomains, which only says which names ROUTE to Whisper -
	// systemd-resolved's "~example.com" is routing-only and never completes a
	// bare name, which is why the search-domain support had to add this rather than reuse the
	// field that looked like it. Empty means the OS keeps whatever
	// search list it already had; we only ever ADD ours.
	SearchDomains []string
	// AppleProfileURL, when set, is the CMS-SIGNED .mobileconfig URL for this
	// profile's token (keyed darwin renders download it instead of generating an
	// unsigned local plist).
	AppleProfileURL string
}

// Host carries the detected facts about the machine a plan will run on. For a
// cross-OS --print they are sensible defaults; the applier supplies real ones.
type Host struct {
	// ResolvedActive: systemd-resolved is running (Linux only).
	ResolvedActive bool
	// ForwarderPath/ForwarderKind: a USABLE local DoH forwarder (Linux DoH needs
	// one - systemd-resolved cannot speak DoH). Kind is "cloudflared",
	// "dnscrypt-proxy", or "".
	ForwarderPath string
	ForwarderKind string
	// ForwarderVersion is the detected version of that forwarder ("2.0.45",
	// "2.1.7"); the render adapts the emitted config to what the shipped
	// version actually accepts (stock Ubuntu 24.04 ships dnscrypt-proxy 2.0.45,
	// which FATALs on the 2.1 config key - proven live).
	ForwarderVersion string
	// ForwarderRejected explains a forwarder that was found but cannot serve
	// (e.g. cloudflared >= 2026.2.0, which removed proxy-dns); rendered as a
	// note so "install a forwarder" guidance never reads as blind.
	ForwarderRejected string
	// Elevated: root (euid 0) / an elevated shell.
	Elevated bool
}

// FileSpec is one file the plan writes, byte-exact.
type FileSpec struct {
	Path    string      `json:"path"`
	Content string      `json:"content"`
	Mode    fs.FileMode `json:"-"`
}

// Step is one ordered action of a plan. Exactly one of File / Cmd / Shell /
// Remove / WaitFor is set. Guards make every step idempotent and every revert
// safe to run twice.
type Step struct {
	// File writes File.Path with File.Content (creating parent dirs).
	File *FileSpec `json:"file,omitempty"`
	// Cmd is an argv executed directly (no shell) - the precise form.
	Cmd []string `json:"cmd,omitempty"`
	// Shell is a shell-language line (PowerShell on windows, sh on unix) for
	// actions that are inherently shell-shaped; displayed and applied verbatim.
	Shell string `json:"shell,omitempty"`
	// Remove deletes a file (missing is fine - idempotent).
	Remove string `json:"remove,omitempty"`
	// WaitFor blocks (bounded) until host:port answers a TCP connect - the
	// server template's "never leave DNS half-configured" gate.
	WaitFor string `json:"wait_for,omitempty"`
	// IfPresent runs the step only when this path exists.
	IfPresent string `json:"if_present,omitempty"`
	// IfAbsent runs the step only when this path does NOT exist.
	IfAbsent string `json:"if_absent,omitempty"`
}

// String renders the step as one legible line (what --print's summary shows).
func (s Step) String() string {
	guard := ""
	if s.IfPresent != "" {
		guard = "[if " + s.IfPresent + " exists] "
	}
	if s.IfAbsent != "" {
		guard += "[if " + s.IfAbsent + " absent] "
	}
	switch {
	case s.File != nil:
		return guard + "write " + s.File.Path
	case s.Remove != "":
		return guard + "remove " + s.Remove
	case s.WaitFor != "":
		return guard + "wait until " + s.WaitFor + " answers (bounded, 30s)"
	case s.Shell != "":
		return guard + s.Shell
	case len(s.Cmd) > 0:
		return guard + shellJoin(s.Cmd)
	}
	return guard + "(no-op)"
}

// Rendered is the concrete, inspectable plan for one OS: pure data, no I/O.
type Rendered struct {
	OS         string `json:"os"`
	Mode       Mode   `json:"mode"`
	DoHURL     string `json:"doh_url,omitempty"`
	ResolverIP string `json:"resolver_ip,omitempty"`
	// Summary is the one-line human description of what apply will do.
	Summary string `json:"summary"`
	Apply   []Step `json:"apply"`
	Revert  []Step `json:"revert"`
	// Notes carry the plain-spoken caveats (plaintext :53, the macOS approval
	// step, a missing forwarder's install line) - stated, never hidden.
	Notes []string `json:"notes,omitempty"`
}

// Render turns the profile into the exact plan for p.OS given the host facts.
// Pure - no I/O, fully table-testable; this IS what --print shows.
func (p Profile) Render(h Host) Rendered {
	switch p.OS {
	case "windows":
		return p.renderWindows()
	case "darwin":
		return p.renderDarwin()
	default:
		return p.renderLinux(h)
	}
}

// firstResolverIP returns the plan's :53 target, "" when none is known.
func (p Profile) firstResolverIP() string {
	for _, ip := range p.ResolverIPs {
		if s := strings.TrimSpace(ip); s != "" {
			return s
		}
	}
	return ""
}

// matchDomains returns the normalised routing set, defaulting to everything.
func (p Profile) matchDomains() []string {
	var out []string
	for _, d := range p.MatchDomains {
		if s := strings.TrimSpace(d); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"."}
	}
	return out
}

// searchDomains returns the normalised suffix search list: trimmed, without a
// leading "~" (that prefix is systemd-resolved ROUTING syntax and would be a
// nonsense search suffix) and without a trailing dot, empties dropped, order
// preserved, deduplicated. Conservative in what we emit, liberal in what the
// caller may hand us.
func (p Profile) searchDomains() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range p.SearchDomains {
		s := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(d), "~"), ".")
		if s == "" || s == "." || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// --- Linux ------------------------------------------------------------------------

// linuxDomainsLine renders the resolved drop-in Domains= line, which carries BOTH
// meanings systemd-resolved gives that one setting:
//
// - "~example.com" is ROUTING only: send queries for that namespace to this
// link's DNS. It never completes a bare hostname, which is the whole of
// the distinction: the code that looked like a search domain was not one.
// - "example.com" (no tilde) is a real SEARCH domain: it is appended to a
// single-label name AND routed. That is what makes `ping db-01` work.
//
// So the routing entries come first, then any search domains, in one line.
func (p Profile) linuxDomainsLine() string {
	parts := make([]string, 0, 2)
	for _, d := range p.matchDomains() {
		parts = append(parts, "~"+d)
	}
	parts = append(parts, p.searchDomains()...)
	return "Domains=" + strings.Join(parts, " ")
}

// linuxSearchLine renders the resolv.conf fallback's search line (the pre-resolved
// mechanism, RFC 3484-era but still what glibc reads), or "" when there is nothing
// to search - never an empty "search" directive.
func (p Profile) linuxSearchLine() string {
	sd := p.searchDomains()
	if len(sd) == 0 {
		return ""
	}
	return "search " + strings.Join(sd, " ") + "\n"
}

func (p Profile) renderLinux(h Host) Rendered {
	r := Rendered{OS: "linux", Mode: p.Mode, DoHURL: p.DohTemplate, ResolverIP: p.firstResolverIP()}

	if p.Mode == ModeDoH {
		if h.ForwarderKind == "" {
			// systemd-resolved cannot speak DoH, so Linux DoH needs a local
			// forwarder. Callers holding a dedicated :53 /128 fall back to it
			// with a clear note; otherwise the one install line (never a
			// silent failure).
			if ip := p.firstResolverIP(); ip != "" {
				fallback := p
				fallback.Mode = ModeDNS53
				r = fallback.renderLinux(h)
				r.Notes = append([]string{
					"no usable DoH forwarder found - using your dedicated :53 resolver " + ip + " instead (no forwarder needed; plaintext on-path)",
				}, r.Notes...)
				return r
			}
			r.Summary = "Linux DoH needs a local forwarder - none usable"
			if h.ForwarderRejected != "" {
				r.Notes = append(r.Notes, h.ForwarderRejected)
			}
			r.Notes = append(r.Notes,
				"install a DoH forwarder first: sudo apt install dnscrypt-proxy, then re-run `whisper resolver --doh`",
				"with a Whisper key, plain `whisper resolver` prefers your dedicated :53 resolver - no forwarder needed at all",
			)
			r.Revert = linuxRevertSteps(h)
			return r
		}
		// Forwarder present: unit on 127.0.0.1:53 -> bounded wait -> repoint the
		// system resolver. Step-for-step the server's LINUX_TEMPLATE.
		r.Summary = "run " + h.ForwarderKind + " as systemd service whisper-dns on " + LinuxLoopback + ":53 -> " + p.DohTemplate + ", then point the system resolver at it"
		if h.ForwarderKind == "dnscrypt-proxy" {
			r.Apply = append(r.Apply, Step{File: &FileSpec{
				Path:    LinuxDNSCryptConfig,
				Content: dnscryptConfig(p.DohTemplate, h.ForwarderVersion),
				Mode:    0o644,
			}})
		}
		r.Apply = append(r.Apply,
			Step{File: &FileSpec{
				Path:    LinuxForwarderUnit,
				Content: forwarderUnit(h.ForwarderKind, h.ForwarderPath, p.DohTemplate),
				Mode:    0o644,
			}},
			Step{Cmd: []string{"systemctl", "daemon-reload"}},
			Step{Cmd: []string{"systemctl", "enable", "--now", "whisper-dns"}},
			Step{Cmd: []string{"systemctl", "restart", "whisper-dns"}},
			// systemd marks the unit active the instant it forks - wait until it
			// ANSWERS before repointing, so DNS is never left half-configured.
			Step{WaitFor: LinuxLoopback + ":53"},
		)
		r.Apply = append(r.Apply, linuxPointResolverSteps(h, LinuxLoopback, p.linuxDomainsLine(), p.linuxSearchLine())...)
		r.Revert = linuxRevertSteps(h)
		return r
	}

	// ModeDNS53: the dedicated /128 is a real :53 listener - no forwarder, the
	// trivial apply.
	ip := p.firstResolverIP()
	if ip == "" {
		r.Summary = "no dedicated :53 resolver address known"
		r.Notes = append(r.Notes, "a dedicated :53 resolver needs a Whisper key (it is allocated per tenant, so your policy rides it) - run with a key")
		r.Revert = linuxRevertSteps(h)
		return r
	}
	if h.ResolvedActive {
		r.Summary = "point systemd-resolved at your dedicated Whisper resolver " + ip + " (drop-in " + LinuxDropIn + ")"
	} else {
		r.Summary = "point " + LinuxResolvConf + " at your dedicated Whisper resolver " + ip + " (backup kept)"
	}
	r.Apply = linuxPointResolverSteps(h, ip, p.linuxDomainsLine(), p.linuxSearchLine())
	r.Revert = linuxRevertSteps(h)
	r.Notes = append(r.Notes,
		"plain :53 is unencrypted on-path; the DoH profile (default mode) is the encrypted alternative",
		"the dedicated resolver answers on IPv6; this host needs a global IPv6 route")
	return r
}

// linuxPointResolverSteps points the system resolver at ip: the resolved drop-in
// when systemd-resolved is active, else the resolv.conf fallback with a backup
// (only taken when no backup exists - matching the server script).
func linuxPointResolverSteps(h Host, ip, domainsLine, searchLine string) []Step {
	if h.ResolvedActive {
		return []Step{
			{File: &FileSpec{
				Path:    LinuxDropIn,
				Content: "# Whisper resolver - generated by `whisper resolver`; revert with `whisper resolver --off`.\n[Resolve]\nDNS=" + ip + "\n" + domainsLine + "\n",
				Mode:    0o644,
			}},
			{Cmd: []string{"systemctl", "restart", "systemd-resolved"}},
		}
	}
	return []Step{
		{Cmd: []string{"cp", LinuxResolvConf, LinuxResolvBackup}, IfPresent: LinuxResolvConf, IfAbsent: LinuxResolvBackup},
		{File: &FileSpec{
			Path:    LinuxResolvConf,
			Content: "nameserver " + ip + "\n" + searchLine,
			Mode:    0o644,
		}},
	}
}

// linuxRevertSteps is ONE universal, guard-protected undo covering every apply
// shape this tool can produce (drop-in, forwarder unit, resolv.conf backup), so
// `--off` is idempotent and self-healing regardless of what a prior run applied.
// It is the server template's Undo recipe, guarded. Guards are evaluated against
// the PRE-state of the whole plan (both the applier and the rendered script
// capture them before the first step runs), so "restart resolved if the drop-in
// existed" works even though the drop-in is removed earlier in the plan - and a
// nothing-was-ever-applied revert is a clean, rootless no-op.
func linuxRevertSteps(h Host) []Step {
	steps := []Step{
		{Cmd: []string{"systemctl", "disable", "--now", "whisper-dns"}, IfPresent: LinuxForwarderUnit},
		{Remove: LinuxForwarderUnit, IfPresent: LinuxForwarderUnit},
		{Remove: LinuxDNSCryptConfig, IfPresent: LinuxDNSCryptConfig},
		{Cmd: []string{"systemctl", "daemon-reload"}, IfPresent: LinuxForwarderUnit},
		{Remove: LinuxDropIn, IfPresent: LinuxDropIn},
	}
	if h.ResolvedActive {
		steps = append(steps, Step{Cmd: []string{"systemctl", "restart", "systemd-resolved"}, IfPresent: LinuxDropIn})
	}
	steps = append(steps,
		Step{Cmd: []string{"cp", LinuxResolvBackup, LinuxResolvConf}, IfPresent: LinuxResolvBackup},
		Step{Remove: LinuxResolvBackup, IfPresent: LinuxResolvBackup},
	)
	return steps
}

// forwarderUnit renders the whisper-dns systemd unit for the detected forwarder
// (the server LINUX_TEMPLATE's unit, byte-shape preserved).
func forwarderUnit(kind, path, dohURL string) string {
	var exec string
	if kind == "dnscrypt-proxy" {
		exec = path + " -config " + LinuxDNSCryptConfig
	} else {
		exec = path + " proxy-dns --address " + LinuxLoopback + " --port 53 --upstream " + dohURL
	}
	return "[Unit]\n" +
		"Description=Whisper encrypted DNS (" + kind + " DoH forwarder)\n" +
		"After=network-online.target\n" +
		"\n" +
		"[Service]\n" +
		"ExecStart=" + exec + "\n" +
		"Restart=always\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
}

// dnscryptConfig renders the dedicated dnscrypt-proxy config with the DoH endpoint
// as its only (static, stamp-addressed) server - the server template's TOML, with
// its explicit IP bootstrap so the stamp's hostname resolves WITHOUT the resolver
// we are about to install (no loop). The bootstrap key is version-adapted: emit
// what the INSTALLED forwarder accepts, never a key it fatals on.
func dnscryptConfig(dohURL, version string) string {
	return "# Whisper encrypted DNS - generated by `whisper resolver`; points dnscrypt-proxy at the Whisper DoH endpoint.\n" +
		"listen_addresses = ['" + LinuxLoopback + ":53']\n" +
		"server_names = ['whisper']\n" +
		dnscryptBootstrapKey(version) + " = ['9.9.9.9:53', '1.1.1.1:53']\n" +
		"netprobe_address = '9.9.9.9:53'\n" +
		"[static.whisper]\n" +
		"stamp = '" + DoHStamp(dohURL) + "'\n"
}

// --- forwarder version policy (pure; DetectHost supplies the raw version) ---------

// parseVersion extracts the first dotted-number token as numeric fields:
// "2.0.45" -> [2 0 45], "cloudflared version 2026.8.2 (built ...)" ->
// [2026 8 2]. nil when the string carries none (liberal in what we accept).
func parseVersion(s string) []int {
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] < '0' || s[i] > '9') {
			i++
		}
		if i == len(s) {
			return nil
		}
		var fields []int
		n, dotted := 0, false
		for i < len(s) {
			switch c := s[i]; {
			case c >= '0' && c <= '9':
				n = n*10 + int(c-'0')
				i++
				continue
			case c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
				fields = append(fields, n)
				n, dotted = 0, true
				i++
				continue
			}
			break
		}
		if dotted {
			return append(fields, n)
		}
		// A lone number ("built 2026") is not a version; keep scanning.
	}
	return nil
}

// versionAtLeast reports v >= want, field by field (missing fields read as 0).
func versionAtLeast(v []int, want ...int) bool {
	for i, w := range want {
		got := 0
		if i < len(v) {
			got = v[i]
		}
		if got != w {
			return got > w
		}
	}
	return true
}

// dnscryptBootstrapKey is the config key this dnscrypt-proxy accepts for its
// plain-IP bootstrap: 2.1.0 renamed fallback_resolvers -> bootstrap_resolvers,
// and BOTH lineages FATAL on the other's key ("Unsupported key in configuration
// file" - proven live on stock Ubuntu 24.04's apt 2.0.45). An unknown
// version gets the modern key.
func dnscryptBootstrapKey(version string) string {
	if v := parseVersion(version); v != nil && !versionAtLeast(v, 2, 1) {
		return "fallback_resolvers"
	}
	return "bootstrap_resolvers"
}

// cloudflaredProxyDNSRemoved: cloudflared removed its DNS forwarder in
// 2026.2.0 (`proxy-dns` now prints "dns-proxy feature is no longer supported"
// and exits - proven live on 2026.8.2). An unparseable version also
// reads as removed: conservative out - never install a unit that crash-loops.
func cloudflaredProxyDNSRemoved(version string) bool {
	v := parseVersion(version)
	if v == nil {
		return true
	}
	return versionAtLeast(v, 2026, 2)
}

// DoHStamp encodes a DoH URL as an RFC-draft DNS stamp (sdns://...) - the form
// dnscrypt-proxy configures a static DoH server with. Byte-identical to the
// server's own DoH stamp: protocol 0x02, no informal property
// claims, empty addr (resolve the hostname at run time), empty hashes (trust the
// WebPKI), then LP(host) and LP(path).
func DoHStamp(dohURL string) string {
	host, path := splitDoHURL(dohURL)
	buf := make([]byte, 0, 12+len(host)+len(path))
	buf = append(buf, 0x02)               // protocol: DNS-over-HTTPS
	buf = append(buf, make([]byte, 8)...) // informal properties: none claimed
	buf = append(buf, 0x00)               // LP(addr): empty - resolve at run time
	buf = append(buf, 0x00)               // VLP(hashes): empty - trust the WebPKI
	buf = append(buf, byte(len(host)))
	buf = append(buf, host...)
	buf = append(buf, byte(len(path)))
	buf = append(buf, path...)
	return "sdns://" + base64.RawURLEncoding.EncodeToString(buf)
}

// splitDoHURL splits a DoH URL into host and path for the stamp encoding,
// tolerating a bare host (liberal in what we accept).
func splitDoHURL(dohURL string) (host, path string) {
	u, err := url.Parse(strings.TrimSpace(dohURL))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(dohURL), "/dns-query"
	}
	p := u.Path
	if p == "" {
		p = "/dns-query"
	}
	return u.Host, p
}

// --- Windows ----------------------------------------------------------------------

func (p Profile) renderWindows() Rendered {
	r := Rendered{OS: "windows", Mode: p.Mode, DoHURL: p.DohTemplate, ResolverIP: p.firstResolverIP()}
	if p.Mode == ModeDNS53 {
		ip := p.firstResolverIP()
		if ip == "" {
			r.Summary = "no dedicated :53 resolver address known"
			r.Notes = append(r.Notes, "a dedicated :53 resolver needs a Whisper key (it is allocated per tenant, so your policy rides it) - run with a key")
			return r
		}
		r.Summary = "point every non-loopback adapter at your dedicated Whisper resolver " + ip
		r.Apply = []Step{
			{Shell: "Get-DnsClient | Where-Object InterfaceAlias -notmatch 'Loopback' | Set-DnsClientServerAddress -ServerAddresses " + psQuote(ip)},
		}
		r.Apply = append(r.Apply, p.windowsSearchApply()...)
		r.Revert = []Step{
			{Shell: "Get-NetAdapter | Reset-DnsClientServerAddress"},
		}
		r.Revert = append(r.Revert, p.windowsSearchRevert()...)
		r.Notes = append(r.Notes,
			"plain :53 is unencrypted on-path; the DoH profile (default mode) is the encrypted alternative",
			"run in an ELEVATED PowerShell (DNS changes need elevation)",
			"the dedicated resolver answers on IPv6; this host needs a global IPv6 route",
			"revert resets adapter DNS back to DHCP/automatic",
		)
		return r
	}

	// DoH: Windows anchors a DoH template to a server IP, so the template is
	// registered per resolved IP FIRST (A and AAAA - encrypt both stacks), then a
	// targeted NRPT rule routes the namespace without globally reconfiguring
	// adapter DNS (the least-surprise default; WIN_TEMPLATE's adapter-global form
	// stays the web script's shape).
	dohHost, _ := splitDoHURL(p.DohTemplate)
	tpl := psQuote(p.DohTemplate)
	r.Summary = "register the Whisper DoH template for " + dohHost + " and route DNS through it via an NRPT rule (encrypted, no adapter rewrite)"
	r.Apply = []Step{
		{Shell: "$ips = @((Resolve-DnsName " + dohHost + " -Type A -ErrorAction SilentlyContinue).IPAddress) + @((Resolve-DnsName " + dohHost + " -Type AAAA -ErrorAction SilentlyContinue).IPAddress) | Where-Object { $_ }"},
		{Shell: "foreach ($srv in $ips) { Add-DnsClientDohServerAddress -ServerAddress $srv -DohTemplate " + tpl + " -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null }"},
	}
	for _, ns := range p.matchDomains() {
		r.Apply = append(r.Apply, Step{Shell: "Add-DnsClientNrptRule -Namespace " + psQuote(ns) + " -NameServers $ips -DohTemplate " + tpl + " -Comment " + psQuote(windowsNrptComment)})
	}
	r.Apply = append(r.Apply, p.windowsSearchApply()...)
	r.Revert = []Step{
		{Shell: "Get-DnsClientNrptRule | Where-Object Comment -eq " + psQuote(windowsNrptComment) + " | Remove-DnsClientNrptRule -Force"},
		{Shell: "Get-DnsClientDohServerAddress | Where-Object DohTemplate -eq " + tpl + " | Remove-DnsClientDohServerAddress"},
	}
	r.Revert = append(r.Revert, p.windowsSearchRevert()...)
	r.Notes = append(r.Notes, "run in an ELEVATED PowerShell (DNS changes need elevation)")
	return r
}

// windowsSearchApply ADDS our suffixes to the machine's global suffix search list
// without disturbing whatever was already there. Set-DnsClientGlobalSetting takes
// the WHOLE list, so a naive apply would silently delete a corporate suffix an
// admin put there; reading the current list and unioning ours into it is the only
// non-destructive shape, and it makes the apply idempotent for free.
func (p Profile) windowsSearchApply() []Step {
	sd := p.searchDomains()
	if len(sd) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(sd))
	for _, d := range sd {
		quoted = append(quoted, psQuote(d))
	}
	add := "@(" + strings.Join(quoted, ", ") + ")"
	return []Step{{Shell: "$cur = @((Get-DnsClientGlobalSetting).SuffixSearchList); " +
		"Set-DnsClientGlobalSetting -SuffixSearchList ($cur + " + add + " | Where-Object { $_ } | Select-Object -Unique)"}}
}

// windowsSearchRevert removes EXACTLY the suffixes we added and leaves every other
// entry alone - the same discipline as the NRPT comment tag: undo ours, nothing else.
func (p Profile) windowsSearchRevert() []Step {
	sd := p.searchDomains()
	if len(sd) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(sd))
	for _, d := range sd {
		quoted = append(quoted, psQuote(d))
	}
	ours := "@(" + strings.Join(quoted, ", ") + ")"
	return []Step{{Shell: "$cur = @((Get-DnsClientGlobalSetting).SuffixSearchList); " +
		"Set-DnsClientGlobalSetting -SuffixSearchList ($cur | Where-Object { " + ours + " -notcontains $_ })"}}
}

// psQuote single-quotes a value for PowerShell (its no-interpolation quoting),
// doubling embedded quotes - a no-op for our closed grammar, but defensive.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// --- macOS ------------------------------------------------------------------------

func (p Profile) renderDarwin() Rendered {
	r := Rendered{OS: "darwin", Mode: p.Mode, DoHURL: p.DohTemplate, ResolverIP: p.firstResolverIP()}
	if p.Mode == ModeDNS53 {
		ip := p.firstResolverIP()
		if ip == "" {
			r.Summary = "no dedicated :53 resolver address known"
			r.Notes = append(r.Notes, "a dedicated :53 resolver needs a Whisper key (it is allocated per tenant, so your policy rides it) - run with a key")
			return r
		}
		// networksetup is the ONE truly no-GUI macOS path (supported write, takes
		// effect immediately, per network service).
		r.Summary = "point every macOS network service at your dedicated Whisper resolver " + ip + " (networksetup - no GUI approval)"
		r.Apply = []Step{
			{Shell: `networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r s; do networksetup -setdnsservers "$s" ` + ip + `; done`},
		}
		r.Revert = []Step{
			{Shell: `networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r s; do networksetup -setdnsservers "$s" Empty; done`},
		}
		r.Notes = append(r.Notes,
			"plain :53 is unencrypted on-path; the DoH profile (default mode) is the encrypted alternative",
			"the dedicated resolver answers on IPv6; this host needs a global IPv6 route")
		return r
	}

	// DoH: a com.apple.dnsSettings.managed profile. Modern macOS REFUSES a silent
	// CLI `profiles install` (GUI/MDM only - a hard Apple constraint), so the plan
	// STAGES the profile and opens the one approval step; it never claims a silent
	// install.
	if p.AppleProfileURL != "" {
		r.Summary = "download your signed Whisper DNS profile and stage it for the one-tap approval in System Settings"
		r.Apply = []Step{
			{Cmd: []string{"curl", "-fsSL", "-o", darwinMobileconfigFile, p.AppleProfileURL}},
			{Cmd: []string{"open", darwinMobileconfigFile}},
		}
	} else {
		r.Summary = "generate the Whisper DNS profile locally and stage it for the one-tap approval in System Settings"
		r.Apply = []Step{
			{File: &FileSpec{
				Path:    darwinMobileconfigFile,
				Content: AppleMobileconfigWithSearch(p.DohTemplate, p.searchDomains()),
				Mode:    0o644,
			}},
			{Cmd: []string{"open", darwinMobileconfigFile}},
		}
		r.Notes = append(r.Notes, "the locally generated profile is unsigned - macOS will show it as unverified; the signed per-device profile comes with an API key (whisper device add)")
	}
	// The staged .mobileconfig stays on disk until the user approves it (System
	// Settings reads it at approval time); revert cleans it up. `profiles remove`
	// tolerates a not-installed profile (the trailing guard) so a double `--off`
	// stays a clean no-op.
	r.Revert = []Step{
		{Remove: darwinMobileconfigFile, IfPresent: darwinMobileconfigFile},
		{Shell: "profiles remove -identifier " + darwinProfileIdentifier + " 2>/dev/null || true"},
	}
	r.Notes = append(r.Notes,
		"macOS requires the final approval by hand: System Settings > General > VPN & Device Management (Apple offers no silent CLI install)",
		"remove it any time in the same place; with an API key, `whisper resolver --resolver` is the no-approval :53 alternative",
	)
	return r
}

// AppleMobileconfig builds the com.apple.dnsSettings.managed configuration profile
// for a DoH URL - the server's mobileconfig payload (DNSProtocol
// HTTPS + ServerURL, top-level PayloadScope System), with STABLE
// identifiers so `--off` can address the profile by name. Deterministic for a
// given URL (same UUIDs every render - idempotent, Apple upgrades in place).
func AppleMobileconfig(dohURL string) string {
	return AppleMobileconfigWithSearch(dohURL, nil)
}

// AppleMobileconfigWithSearch is the same profile carrying a real suffix SEARCH
// list: macOS completes a bare hostname from SearchDomains in the DNS
// payload, which is the per-OS half of "ping db-01 just works". An empty list
// renders the byte-identical profile AppleMobileconfig always produced, and the
// PayloadUUIDs stay keyed on the URL alone so a re-render is still idempotent and
// still upgrades the installed profile in place rather than adding a second one.
func AppleMobileconfigWithSearch(dohURL string, search []string) string {
	dnsUUID := deterministicUUID("whisper-resolver-dns:", dohURL)
	cfgUUID := deterministicUUID("whisper-resolver-cfg:", dohURL)
	serverURL := xmlEscape(dohURL)
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>` + serverURL + `</string>` + appleSearchDomains(search) + `
      </dict>
      <key>PayloadDescription</key>
      <string>Encrypted DNS (DoH) via Whisper</string>
      <key>PayloadDisplayName</key>
      <string>Whisper Encrypted DNS</string>
      <key>PayloadIdentifier</key>
      <string>` + darwinProfileIdentifier + `.dns</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>` + dnsUUID + `</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Whisper Resolver - Encrypted DNS</string>
  <key>PayloadDescription</key>
  <string>Points this device's DNS at Whisper over encrypted DoH.</string>
  <key>PayloadIdentifier</key>
  <string>` + darwinProfileIdentifier + `</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>` + cfgUUID + `</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadScope</key>
  <string>System</string>
</dict>
</plist>
`
}

// appleSearchDomains renders the optional SearchDomains array of the DNSSettings
// payload, or "" when there is nothing to search (never an empty array, which some
// macOS builds treat as "clear the search list").
func appleSearchDomains(search []string) string {
	if len(search) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n        <key>SearchDomains</key>\n        <array>")
	for _, d := range search {
		b.WriteString("\n          <string>" + xmlEscape(d) + "</string>")
	}
	b.WriteString("\n        </array>")
	return b.String()
}

// deterministicUUID is an RFC 4122 v3 (name-based, md5) UUID from salt+name,
// uppercased - the server's UUID.nameUUIDFromBytes contract: same input, same
// UUID, forever.
func deterministicUUID(salt, name string) string {
	sum := md5.Sum([]byte(salt + name))
	sum[6] = (sum[6] & 0x0f) | 0x30 // version 3
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]))
}

// xmlEscape escapes the five XML special characters (defensive; the URL grammar
// is closed).
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// shellJoin renders an argv as one copy-pasteable sh line, quoting only when needed.
func shellJoin(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, shQuote(a))
	}
	return strings.Join(parts, " ")
}

// shQuote single-quotes an argument for sh when it contains anything outside the
// safe set (POSIX quoting; an embedded single quote closes, escapes, reopens).
func shQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\"'`$&|;<>()*?[]\\#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
