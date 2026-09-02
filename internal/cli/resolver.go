// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/resolverprofile"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// resolver.go - `whisper resolver`: Tier-2 as ONE command.
//
// Tier 2 = keep your own address, use Whisper DNS. Until now the CLI could only
// PRINT the values (DoH URL, .mobileconfig, DoT host); this verb turns them into a
// real OS resolver profile: render it (--print), apply it (default), revert it
// (--off).
//
// Tier-2 resolution is KEYED BY DESIGN: the resolver must identify the tenant to
// load and apply THEIR policy, so the DoH endpoint refuses anonymous queries and
// the :53 /128 is a per-tenant allocation. Postel two-tier here means:
//
// - NO key: --print previews every profile (clearly-marked stand-ins, zero
// side effects); an APPLY fails soft with the one next step (get a free key),
// never by wiring a profile that can never answer.
// - key: a resolve-only DEVICE token is minted once (op:register {device:true},
// the `whisper device add` primitive). On LINUX the dedicated per-tenant /128
// :53 resolver (op:resolver) is PREFERRED - no forwarder, no extra install,
// one command on a stock distro - with the encrypted DoH forwarder profile as
// the explicit choice (--doh) or the fallback when :53 is unreachable. On
// Windows/macOS the tenant DoH URL is wired natively (the OS speaks DoH).
//
// The minted token is persisted in ~/.config/whisper/resolver.json (0600) so
// re-running never sprawls new devices, and `--off` both reverts the OS and
// revokes the token (a leaked config file then stops resolving).
//
// The per-OS apply engines live in internal/resolverprofile; the server's own
// setup surfaces the server serves are their spec.

// Test seams (mirroring the sessionsDirFn pattern).
var (
	resolverStatePathFn = defaultResolverStatePath
	resolverApplierFor  = resolverprofile.For
	resolverGOOS        = runtime.GOOS
	resolverProbe53     = defaultResolverProbe53
)

// resolverKeyURL is where a key comes from - the one URL login/root already print.
const resolverKeyURL = "https://console.whisper.online/settings"

// errResolverNeedsKey is the keyless-apply fail-soft: Tier-2 resolution is keyed
// BY DESIGN (the resolver identifies the tenant to apply THEIR policy; the DoH
// endpoint refuses anonymous queries), so a keyless apply would wire a profile
// that can never answer. A clear, helpful no - nothing touched, non-zero exit.
func errResolverNeedsKey() error {
	return fmt.Errorf("Tier-2 DNS applies your per-tenant policy, so it needs a Whisper key - "+
		"get one free at %s, then run `whisper resolver` (save the key with `whisper login <key>`; "+
		"preview the exact profile without a key: `whisper resolver --print`)", resolverKeyURL)
}

// defaultResolverProbe53 answers "is the dedicated :53 resolver reachable from
// HERE?" with one bounded TCP dial (the resolver serves TCP :53; a host without
// the IPv6 route fails instantly). Selection-only: the applier still runs its
// own bounded verify + rollback after any apply.
func defaultResolverProbe53(ip string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "53"), 3*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// resolverPrintPlaceholderIP marks a keyed dry run that has not allocated the
// tenant's /128 yet. It is the RFC 6666 discard prefix: valid to parse, routes
// nowhere, can never accidentally point real DNS at someone else's resolver.
const resolverPrintPlaceholderIP = "100::"

// resolverState is the on-disk record of what this tool minted and applied.
// The token is a resolve-only credential (it can look up names and nothing
// else), which is why the file is 0600 - and why --off revokes it.
type resolverState struct {
	Token      string `json:"token,omitempty"`
	Address    string `json:"address,omitempty"` // the device /128 - the durable revoke selector
	DoHURL     string `json:"doh_url,omitempty"`
	DotHost    string `json:"dot_host,omitempty"`
	ResolverIP string `json:"resolver_ip,omitempty"` // the tenant's dedicated :53 /128
	// Suffix is this tenant's DNS namespace (t<hash>.agents.whisper.online), the
	// parent of the device's own FQDN. The search-domain work installs it as a real OS SEARCH
	// domain so a bare `ping db-01` completes to db-01.<suffix> locally, without
	// needing the server-side single-label fallback at all.
	Suffix    string `json:"suffix,omitempty"`
	OS        string `json:"os,omitempty"`
	Mode      string `json:"mode,omitempty"`
	AppliedAt string `json:"applied_at,omitempty"`
}

func defaultResolverStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "resolver.json")
	}
	return filepath.Join(home, ".config", "whisper", "resolver.json")
}

// loadResolverState reads the persisted state; any problem yields the zero
// value (liberal in - a garbled file only costs the reuse optimisation).
func loadResolverState() resolverState {
	var st resolverState
	b, err := os.ReadFile(resolverStatePathFn())
	if err != nil {
		return resolverState{}
	}
	if json.Unmarshal(b, &st) != nil {
		return resolverState{}
	}
	return st
}

// saveResolverState persists the state owner-only (the token is a credential).
// Best-effort: a write failure costs only token reuse, never the apply.
//
// It goes through secfile rather than a 0o600 mode argument because on Windows
// that argument decides nothing but the read-only attribute, and this file holds
// the Tier-2 resolver token.
func saveResolverState(st resolverState) {
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	path := resolverStatePathFn()
	if err := secfile.MkdirAllFor(path); err != nil {
		return
	}
	_ = secfile.WriteFile(path, b)
}

func removeResolverState() { _ = os.Remove(resolverStatePathFn()) }

type resolverOpts struct {
	print        bool
	off          bool
	dns53        bool
	dohForced    bool // --doh passed explicitly: skip the Linux :53-first preference
	osName       string
	label        string
	retention    string
	retentionSet bool
}

func newResolverCmd() *cobra.Command {
	var (
		printFlag, dryRun   bool
		offFlag, revertFlag bool
		dohFlag             bool
		dns53Flag, dnsAlias bool
		osFlag              string
		label, retention    string
		tier2               bool
	)
	cmd := &cobra.Command{
		Use:   "resolver",
		Short: "Point THIS machine's DNS at Whisper (Tier 2) - one command, revertible",
		Long: "Tier-2 connectivity: keep your own address, resolve through Whisper with\n" +
			"YOUR tenant's DNS policy applied. One command applies the best resolver\n" +
			"profile for this OS, and `whisper resolver --off` puts everything back.\n\n" +
			"Tier-2 resolution is per-tenant (the answers follow your policy), so applying\n" +
			"needs a Whisper key - get one free at " + resolverKeyURL + ".\n" +
			"--print previews every profile without a key and changes nothing. A\n" +
			"resolve-only device token is minted once and reused; --off revokes it.\n\n" +
			"  whisper resolver             apply the best profile for this OS (needs a key)\n" +
			"  whisper resolver --print     show the exact profile + commands, change nothing\n" +
			"  whisper resolver --doh       force the encrypted DoH profile\n" +
			"  whisper resolver --resolver  force your tenant's dedicated :53 resolver only\n" +
			"  whisper resolver --off       revert; also revokes the minted device token\n\n" +
			"Per OS: Linux prefers your dedicated IPv6 resolver on plain :53 - no\n" +
			"forwarder, nothing to install, one command on a stock distro - and falls\n" +
			"back to a local DoH forwarder (version-matched config) when :53 is\n" +
			"unreachable; Windows registers the DoH template plus one tagged NRPT rule\n" +
			"(elevated PowerShell); macOS stages the DNS profile for the one System\n" +
			"Settings approval Apple requires (--resolver needs none).",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_ = tier2 // accepted for symmetry with `connect --tier`; this verb IS Tier 2
			if cmd.Flags().Changed("doh") && dohFlag && (dns53Flag || dnsAlias) {
				return usageErr("pick one of --doh or --resolver (they select the profile mode)")
			}
			o := resolverOpts{
				print:     printFlag || dryRun,
				off:       offFlag || revertFlag,
				dns53:     dns53Flag || dnsAlias,
				dohForced: cmd.Flags().Changed("doh") && dohFlag,
				osName:    osFlag,
				label:     label,
			}
			if cmd.Flags().Changed("retention") {
				o.retention, o.retentionSet = retention, true
			}
			return runResolver(o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&printFlag, "print", false, "emit the exact profile (files + commands) without applying anything")
	f.BoolVar(&dryRun, "dry-run", false, "alias for --print")
	f.BoolVar(&offFlag, "off", false, "revert what this tool applied and revoke the minted device token (idempotent)")
	f.BoolVar(&revertFlag, "revert", false, "alias for --off")
	f.BoolVar(&dohFlag, "doh", true, "encrypted DNS-over-HTTPS profile (default on Windows/macOS; pass explicitly to force the forwarder profile on Linux)")
	f.BoolVar(&dns53Flag, "resolver", false, "use ONLY your tenant's dedicated IPv6 :53 resolver (the Linux default tries it first)")
	f.BoolVar(&dnsAlias, "dns53", false, "alias for --resolver")
	f.StringVar(&osFlag, "os", "", "render another OS's profile with --print: linux | windows | macos (apply always targets this machine)")
	f.StringVar(&label, "label", "", "a friendly name for the minted device identity (keyed; e.g. \"work-laptop\")")
	f.StringVar(&retention, "retention", "", "days to keep this device's DNS/query logs, 0-3650 (keyed; same as `whisper device add`)")
	f.BoolVar(&tier2, "tier2", false, "accepted no-op selector (this verb is Tier 2)")
	_ = f.MarkHidden("dns53")
	_ = f.MarkHidden("tier2")
	return cmd
}

// normalizeResolverOS maps liberal OS spellings onto a GOOS ("" -> this machine).
func normalizeResolverOS(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "":
		return resolverGOOS, nil
	case "linux":
		return "linux", nil
	case "windows", "win", "win11", "windows11":
		return "windows", nil
	case "darwin", "macos", "mac", "osx", "mac-os":
		return "darwin", nil
	}
	return "", usageErr("unknown --os %q: use linux, windows, or macos", raw)
}

func runResolver(o resolverOpts) error {
	osName, err := normalizeResolverOS(o.osName)
	if err != nil {
		return err
	}
	if o.off {
		return runResolverOff(o, osName)
	}
	if !o.print && osName != resolverGOOS {
		return usageErr("--os renders another OS's profile with --print; apply always targets this machine (%s)", resolverGOOS)
	}

	mode := resolverprofile.ModeDoH
	if o.dns53 {
		mode = resolverprofile.ModeDNS53
	}

	c, err := resolveClient(false, false)
	if err != nil {
		return err
	}
	keyed := c != nil && !c.Credential().IsZero()

	// Tier-2 resolution is keyed by design (per-tenant policy on the wire): a
	// keyless APPLY would wire a profile the resolver refuses (403), so it
	// fails soft here with the one next step. --print keeps working keyless.
	if !keyed && !o.print {
		return errResolverNeedsKey()
	}

	// Real host facts when the target is this machine; sensible defaults for a
	// cross-OS --print.
	host := resolverprofile.Host{ResolvedActive: true}
	ap, haveApplier := resolverApplierFor(resolverGOOS)
	if haveApplier && osName == resolverGOOS {
		host = ap.DetectHost()
	}

	// Linux default: PREFER the dedicated per-tenant /128 on :53 - no
	// forwarder, nothing to install, ONE command on a stock distro. The
	// encrypted DoH forwarder profile is the explicit choice (--doh) or the
	// fallback when :53 is unreachable from this host.
	prefer53 := osName == "linux" && mode == resolverprofile.ModeDoH && !o.dohForced

	var notes []string
	st := loadResolverState()
	doh := firstNonBlank(st.DoHURL, resolverprofile.BareDoHURL)
	resolverIP := st.ResolverIP
	if o.print {
		// A dry run mints and allocates NOTHING (no side effects, keyed or
		// not); it shows the exact shape with clearly-marked stand-ins.
		mintPlanned := st.DoHURL == ""
		if mintPlanned {
			doh = "https://doh.whisper.online/YOUR-DEVICE-TOKEN/dns-query"
		}
		allocPlanned := resolverIP == "" && (mode == resolverprofile.ModeDNS53 || prefer53)
		if allocPlanned {
			resolverIP = resolverPrintPlaceholderIP
		}
		if prefer53 {
			mode = resolverprofile.ModeDNS53
			notes = append(notes, "Linux default: the dedicated :53 resolver (no forwarder needed); apply verifies it answers first and falls back to the encrypted DoH forwarder profile when it does not (force that with --doh)")
		}
		if !keyed {
			notes = append(notes, "applying needs a Whisper key (Tier-2 DNS applies YOUR per-tenant policy) - get one free at "+resolverKeyURL+", then run `whisper resolver`")
		}
		if mintPlanned {
			notes = append(notes, "dry run: apply will mint a resolve-only device token (op:register {device:true}) and use its real DoH URL in place of YOUR-DEVICE-TOKEN")
		}
		if allocPlanned {
			notes = append(notes, "dry run: apply will allocate your tenant's dedicated :53 resolver (op:resolver) and use its real /128 in place of "+resolverPrintPlaceholderIP+" (a discard-prefix stand-in that resolves nothing)")
		}
	} else {
		if st.Token == "" && st.DoHURL == "" {
			minted, err := mintResolverDevice(c, o)
			if err != nil {
				return err
			}
			st = minted
			doh = firstNonBlank(st.DoHURL, doh)
			resolverIP = st.ResolverIP
			saveResolverState(st)
		}
		if resolverIP == "" && (mode == resolverprofile.ModeDNS53 || prefer53) {
			ip, err := ensureTenantResolver(c)
			if err != nil {
				return err
			}
			st.ResolverIP, resolverIP = ip, ip
			saveResolverState(st)
		}
		if prefer53 {
			if perr := resolverProbe53(resolverIP); perr == nil {
				mode = resolverprofile.ModeDNS53
				notes = append(notes, "Linux default: your dedicated per-tenant resolver on :53 - no forwarder needed (force the encrypted DoH forwarder profile with --doh)")
			} else if host.ForwarderKind != "" {
				notes = append(notes, "your dedicated :53 resolver "+resolverIP+" did not answer from this host ("+perr.Error()+") - applying the encrypted DoH forwarder profile instead")
				// The DoH plan must not silently fall back to the /128 we just
				// proved unreachable.
				resolverIP = ""
			} else {
				return fmt.Errorf("your dedicated resolver %s did not answer from this host (%v; it listens on IPv6 :53, so check the global IPv6 route) "+
					"and no usable DoH forwarder is installed for the encrypted fallback - install one (sudo apt install dnscrypt-proxy) and re-run `whisper resolver`; nothing was changed", resolverIP, perr)
			}
		}
	}

	p := resolverprofile.Profile{
		Mode:        mode,
		OS:          osName,
		DohTemplate: doh,
	}
	if resolverIP != "" {
		p.ResolverIPs = []string{resolverIP}
	}
	// install the tenant's own namespace as a REAL OS search domain, so
	// a bare hostname completes on the host rather than relying on the server-side
	// fallback. Empty when we do not know the suffix (a state file written before search domains, or an
	// unkeyed run) - and then nothing is emitted at all, never a guessed suffix.
	if st.Suffix != "" {
		p.SearchDomains = []string{st.Suffix}
	}
	r := p.Render(host)
	r.Notes = append(notes, r.Notes...)

	if o.print {
		renderResolverPlan(r, false, r.ApplyScript())
		return nil
	}

	// Apply. A plan with no steps means the render could not proceed (e.g.
	// --doh with no usable forwarder installed): the notes carry the exact
	// next step, and the exit is non-zero so scripts notice.
	if len(r.Apply) == 0 {
		renderResolverPlan(r, false, "")
		return fmt.Errorf("nothing was applied - %s", firstNonBlank(r.Summary, "see the notes above"))
	}
	if !haveApplier {
		renderResolverPlan(r, false, r.ApplyScript())
		return fmt.Errorf("applying on %s is not wired yet - the exact steps were printed above", resolverGOOS)
	}
	if err := ap.Apply(r); err != nil {
		if errors.Is(err, resolverprofile.ErrNeedsRoot) {
			// Postel: the exact block, then the one-line fix - never a dead end.
			fmt.Fprintln(os.Stdout, r.ApplyScript())
			return fmt.Errorf("changing system DNS needs privileges - re-run with sudo (the block above is exactly what apply runs)")
		}
		return err
	}
	st.OS, st.Mode = osName, string(r.Mode)
	st.AppliedAt = time.Now().UTC().Format(time.RFC3339)
	saveResolverState(st)
	renderResolverApplied(r)
	return nil
}

// runResolverOff reverts the OS state (idempotent - guards make a
// nothing-ever-applied revert a clean no-op) and revokes the minted device
// token so a leaked config file's token stops resolving.
func runResolverOff(o resolverOpts, osName string) error {
	if !o.print && osName != resolverGOOS {
		return usageErr("--os renders another OS's revert with --print; --off always targets this machine (%s)", resolverGOOS)
	}
	st := loadResolverState()
	mode := resolverprofile.ModeDoH
	if st.Mode == string(resolverprofile.ModeDNS53) {
		mode = resolverprofile.ModeDNS53
	}
	p := resolverprofile.Profile{
		Mode:        mode,
		OS:          osName,
		DohTemplate: firstNonBlank(st.DoHURL, resolverprofile.BareDoHURL),
	}
	if st.ResolverIP != "" {
		p.ResolverIPs = []string{st.ResolverIP}
	}
	if st.Suffix != "" {
		p.SearchDomains = []string{st.Suffix} // the search-domain support, same list the apply installed
	}
	if st.Token != "" {
		p.AppleProfileURL = mobileconfigURL(st.Token)
	}
	host := resolverprofile.Host{ResolvedActive: true}
	ap, haveApplier := resolverApplierFor(resolverGOOS)
	if haveApplier && osName == resolverGOOS {
		host = ap.DetectHost()
	}
	r := p.Render(host)

	if o.print {
		renderResolverPlan(r, false, r.RevertScript())
		return nil
	}
	if !haveApplier {
		renderResolverPlan(r, false, r.RevertScript())
		return fmt.Errorf("reverting on %s is not wired yet - the exact steps were printed above", resolverGOOS)
	}
	if err := ap.Revert(r); err != nil {
		if errors.Is(err, resolverprofile.ErrNeedsRoot) {
			fmt.Fprintln(os.Stdout, r.RevertScript())
			return fmt.Errorf("changing system DNS needs privileges - re-run with sudo (the block above is exactly what the revert runs)")
		}
		return err
	}

	// Revoke the resolve-only device token (op:revoke by its /128 - the durable
	// selector). Requires the account key; without one the OS is still reverted
	// and the state is kept so a later keyed --off can finish the job.
	if st.Address != "" {
		c, cerr := resolveClient(false, false)
		if cerr != nil || c == nil || c.Credential().IsZero() {
			fmt.Fprintln(os.Stderr, "whisper: DNS reverted; the resolve-only device token was NOT revoked (no API key available) - re-run `whisper resolver --off` with your key to revoke it")
			return nil
		}
		cx, cancel := ctx()
		defer cancel()
		env, rerr := c.Agents(cx, "revoke", map[string]any{"agent": st.Address})
		if rerr == nil {
			rerr = envelopeError(env)
		}
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "whisper: DNS reverted, but revoking the device token failed - re-run `whisper resolver --off` to retry")
			return rerr
		}
	}
	removeResolverState()

	if g.jsonOut {
		emitJSONValue(resolverPlanJSON(r, false, ""))
		return nil
	}
	if g.quiet {
		return nil
	}
	// The render's notes describe the APPLY path (forwarder install lines, the
	// macOS approval); after a successful revert only the outcome matters.
	fmt.Fprintln(os.Stderr, "whisper: resolver profile reverted - this machine's DNS is back to what it was")
	return nil
}

// mintResolverDevice mints the resolve-only device identity this profile bakes
// into OS config (op:register {device:true} - the `whisper device add`
// primitive; revocable, and it can never touch the account).
func mintResolverDevice(c *client.Client, o resolverOpts) (resolverState, error) {
	args := map[string]any{"device": true}
	if s := strings.TrimSpace(o.label); s != "" {
		args["label"] = s
	} else {
		args["label"] = "resolver-" + resolverGOOS
	}
	if o.retentionSet {
		days, err := parseRetentionDays(o.retention)
		if err != nil {
			return resolverState{}, err
		}
		args["retention"] = days
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "register", args)
	if err != nil {
		return resolverState{}, err
	}
	if perr := envelopeError(env); perr != nil {
		return resolverState{}, perr
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return resolverState{}, fmt.Errorf("the control plane returned no device record")
	}
	rec := recs[0]
	t2 := tier2FromEnvelope(env) // validated doh_url + resolver_ip (fail-soft)
	return resolverState{
		Token:      field(rec, "token"),
		Address:    field(rec, "address"),
		DoHURL:     t2.DoHURL,
		DotHost:    field(rec, "dot_host"),
		ResolverIP: t2.ResolverIP,
		// search domains on top of that: the suffix worth SEARCHING is the fleet
		// namespace the MEMBER name lives in, not the agent's own island. op:register
		// re-parents the member name into the registrant's subtree while the canonical
		// a<hex> `fqdn` stays under the agent's, so deriving the search domain from
		// `fqdn` alone installs the one suffix under which `db-01` does not exist and
		// `ping db-01` fails on the host. `member` first, `fqdn` as the fallback for a
		// older control plane and for BYOD, where the two names share a parent anyway.
		Suffix: parentOfFqdn(field(rec, "member", "fqdn")),
	}, nil
}

// parentOfFqdn returns everything after the first label of an FQDN - for
// "resolver-linux.t9ab.agents.whisper.online." that is "t9ab.agents.whisper.online",
// this tenant's own namespace and therefore the suffix worth searching. Anything
// that is not a dotted name yields "" (no search domain, and the server-side
// single-label fallback still covers a bare name), never a guess.
func parentOfFqdn(fqdn string) string {
	s := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	i := strings.Index(s, ".")
	if i < 0 || i+1 >= len(s) {
		return ""
	}
	parent := s[i+1:]
	if !strings.Contains(parent, ".") {
		return "" // a bare TLD is never a tenant namespace
	}
	return strings.ToLower(parent)
}

// ensureTenantResolver allocates (or returns) the caller-tenant's dedicated
// :53 resolver /128 via op:resolver - a per-tenant slot, one per account.
func ensureTenantResolver(c *client.Client) (string, error) {
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "resolver", map[string]any{})
	if err != nil {
		return "", err
	}
	if perr := envelopeError(env); perr != nil {
		return "", perr
	}
	recs := env.Result.Records()
	if len(recs) == 0 {
		return "", fmt.Errorf("the control plane returned no resolver record")
	}
	addr := field(recs[0], "address")
	if addr == "" {
		return "", fmt.Errorf("the control plane returned no resolver address (state %q)", field(recs[0], "state"))
	}
	return addr, nil
}

// --- rendering --------------------------------------------------------------------

// resolverPlanJSON is the scriptable shape: {mode, os, doh_url, resolver_ip,
// summary, apply, revert, notes, applied} plus the runnable script when one is
// being shown.
func resolverPlanJSON(r resolverprofile.Rendered, applied bool, script string) map[string]any {
	steps := func(ss []resolverprofile.Step) []string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, s.String())
		}
		return out
	}
	m := map[string]any{
		"mode":        string(r.Mode),
		"os":          r.OS,
		"doh_url":     r.DoHURL,
		"resolver_ip": r.ResolverIP,
		"summary":     r.Summary,
		"apply":       steps(r.Apply),
		"revert":      steps(r.Revert),
		"notes":       r.Notes,
		"applied":     applied,
	}
	if script != "" {
		m["script"] = script
	}
	return m
}

// resolverQuietValue is the one load-bearing value: the /128 for a :53 profile,
// else the DoH URL.
func resolverQuietValue(r resolverprofile.Rendered) string {
	if r.Mode == resolverprofile.ModeDNS53 && r.ResolverIP != "" {
		return r.ResolverIP
	}
	return r.DoHURL
}

// renderResolverPlan shows a plan WITHOUT applying it: the human header on
// stderr, the runnable script on stdout (pipe-able into a privileged shell).
func renderResolverPlan(r resolverprofile.Rendered, applied bool, script string) {
	if g.jsonOut {
		emitJSONValue(resolverPlanJSON(r, applied, script))
		return
	}
	if g.quiet {
		if v := resolverQuietValue(r); v != "" {
			fmt.Fprintln(os.Stdout, v)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "whisper: Tier-2 resolver profile - %s (%s)\n", r.Mode, r.OS)
	if r.Summary != "" {
		fmt.Fprintf(os.Stderr, "  plan      %s\n", r.Summary)
	}
	if r.DoHURL != "" {
		fmt.Fprintf(os.Stderr, "  doh url   %s\n", r.DoHURL)
	}
	if r.ResolverIP != "" {
		fmt.Fprintf(os.Stderr, "  resolver  %s\n", r.ResolverIP)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(os.Stderr, "  note      %s\n", n)
	}
	if script != "" {
		fmt.Fprintln(os.Stdout, script)
	}
}

// renderResolverApplied reports a successful apply.
func renderResolverApplied(r resolverprofile.Rendered) {
	if g.jsonOut {
		emitJSONValue(resolverPlanJSON(r, true, ""))
		return
	}
	if g.quiet {
		if v := resolverQuietValue(r); v != "" {
			fmt.Fprintln(os.Stdout, v)
		}
		return
	}
	what := "encrypted DoH"
	if r.Mode == resolverprofile.ModeDNS53 {
		what = "your dedicated :53 resolver"
	}
	fmt.Fprintf(os.Stderr, "whisper: Tier-2 DNS applied - this machine now resolves through Whisper (%s)\n", what)
	if r.DoHURL != "" {
		fmt.Fprintf(os.Stderr, "  doh url   %s\n", r.DoHURL)
	}
	if r.ResolverIP != "" {
		fmt.Fprintf(os.Stderr, "  resolver  %s\n", r.ResolverIP)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(os.Stderr, "  note      %s\n", n)
	}
	fmt.Fprintln(os.Stderr, "  revert    whisper resolver --off")
}
