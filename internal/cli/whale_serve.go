// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_serve.go is `whisper whale serve` and, through the same engine, `whisper whale
// funnel`.
//
// WHAT IS DIFFERENT ABOUT OURS
//
// Tailscale's serve needs a relay, a coordination server and a certificate authority to
// put a local port in front of a peer. We need none of those, because the thing being
// exposed already has a globally routable address and already terminates TLS with a leaf
// whose SPKI is published as a TLSA record in a DNSSEC-signed zone. `serve` does not build
// that. It installs a handler behind the listener that is already there, so a
// peer verifies us from the IANA root with no CA and nothing pre-installed.
//
// And because every caller arrives from a routable /128 we delivered, the origin can be
// told WHO is calling - proven from the network and from DNSSEC, not asserted in a header
// the caller wrote. internal/whale/serveheaders.go is that contract, and it is the part of
// this a reviewer should read first.
//
// THE TWO VERBS
//
//	serve answer this node's own fleet. Everyone else gets a 403. The port is still
//	         reachable - the /128 is globally routable and we will not pretend otherwise -
//	         but it is not answered.
//	funnel answer everyone. Irreversible in the way a leak is irreversible, so it takes
//	         a typed `yes` (or --yes), it is written to disk the moment it starts, it shows
//	         in `whale status` from any shell, and one word turns it off.
//
// WHY THE PORT IS ALWAYS 443
//
// The published TLSA is `_443._tcp.<fqdn>`. That record is what makes the leaf verifiable
// with no CA, and it is the whole reason to prefer this over their product. A serve on
// another port would be a serve nobody can pin, so `--https` accepts the number people
// type out of habit and refuses any other value, with the reason.

// whaleServeFleetRefresh is how often a running serve re-reads its fleet, so a peer added
// or removed while it runs takes effect without a restart.
const whaleServeFleetRefresh = 60 * time.Second

// whaleServeStartBudget bounds how long `--bg` waits for the detached holder to come up
// before it says so rather than claiming a serve that is not there.
const whaleServeStartBudget = 45 * time.Second

// whaleServeIdentityPaths are the three well-known paths the in-tunnel identity listener
// keeps for itself. They are never proxied to the origin, and the help says so.
var whaleServeIdentityPaths = []string{
	"/.well-known/whisper-identity", "/.well-known/jwks.json", "/.well-known/did.json",
}

// serveOptions is one invocation of either verb.
type serveOptions struct {
	scope     whale.ServeScope
	target    string
	setPath   string
	httpsPort int
	agent     string
	allow     []string
	compat    bool
	headers   bool
	yes       bool
	bg        bool
	held      bool   // set on the detached child; suppresses a second spawn
	stateDir  string // test seam; empty means the real ~/.config/whisper
}

func newWhaleServeCmd() *cobra.Command { return newWhaleExposeCmd(whale.ScopeFleet) }

func newWhaleFunnelCmd() *cobra.Command { return newWhaleExposeCmd(whale.ScopeInternet) }

// newWhaleExposeCmd builds serve or funnel. One engine, one flag set, one difference: who
// is answered. Two commands that differed in more than that would drift.
func newWhaleExposeCmd(scope whale.ServeScope) *cobra.Command {
	opt := serveOptions{scope: scope, headers: true, httpsPort: identityTLSPort}
	verb := scope.Verb()

	short := "Expose a local port to your fleet, pinned by the published TLSA"
	long := "Put a local port in front of your fleet on this node's own /128, over the TLS\n" +
		"leaf the published TLSA already pins - so a peer verifies it from the IANA DNSSEC\n" +
		"root, with no CA and nothing pre-installed.\n\n" +
		"Only your fleet is ANSWERED. The /128 is globally routable, so a stranger can still\n" +
		"open the port; they get a 403 and nothing else. If you want the world answered, that\n" +
		"is `whisper whale funnel`, and it asks you to say so out loud.\n\n"
	if scope == whale.ScopeInternet {
		short = "Expose a local port to the whole internet, deliberately"
		long = "Put a local port in front of THE INTERNET on this node's own /128.\n\n" +
			"This is not a relay and there is no propagation wait: the address is already\n" +
			"globally routable and already inbound-reachable, so a funnel is a decision, not a\n" +
			"deployment. There is no port restriction and no certificate-authority rate limit to\n" +
			"lock you out - the leaf is ours and the pin is in DNS.\n\n" +
			"Because it is a decision, it is an explicit one: you type `yes` (or pass --yes), it\n" +
			"is recorded on disk the moment it starts, `whisper whale status` shows it from any\n" +
			"shell on this host, and `whisper whale funnel off` ends it in one word.\n\n" +
			"One honest limit: a caller that is itself a Whisper /128 in ANOTHER tenant is still\n" +
			"governed by the east-west plane, so it can be refused before it ever reaches you\n" +
			"while the rest of the internet is answered normally. We expect to relax that.\n\n"
	}
	long += "Every request the origin receives carries who called, established here rather than\n" +
		"claimed by the caller: Whisper-Client-Address always, and Whisper-Agent-Address,\n" +
		"-FQDN, -Owner plus Whisper-Assess-Band and -Coverage when we could prove them.\n" +
		"Whisper-Identity-Proof says how each one was established, and how the missing ones\n" +
		"failed. Every Whisper-* and Tailscale-* header the CALLER sent is deleted first, so\n" +
		"an origin can trust Whisper-Agent-FQDN by its presence alone. --compat-headers adds\n" +
		"the Tailscale-User-* spellings for a proven caller, so an app being migrated changes\n" +
		"nothing on day one.\n\n" +
		"The port is 443 because `_443._tcp.<fqdn> TLSA` is what makes the leaf verifiable.\n" +
		"The three /.well-known/ identity paths stay ours and are not proxied.\n\n" +
		"Targets, liberally: `3000`, `:3000`, `localhost:3000`, `[::1]:3000`,\n" +
		"`http://127.0.0.1:3000/api`."

	cmd := &cobra.Command{
		Use:   verb + " <port|host:port|url>",
		Short: short,
		Long:  long,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageErr("say what to %s, for example `whisper whale %s 3000` "+
					"(`%s status` shows what is running, `%s off` stops it)", verb, verb, verb, verb)
			}
			opt.target = args[0]
			return runWhaleServe(cmd, opt)
		},
	}
	cmd.Flags().StringVar(&opt.setPath, "set-path", "/", "mount the origin at this path instead of the root")
	cmd.Flags().IntVar(&opt.httpsPort, "https", identityTLSPort, "the HTTPS port to serve on (443 - the port the published TLSA pins)")
	cmd.Flags().StringVar(&opt.agent, "agent", "", "which of your agents to serve as (default: this host's usual one)")
	cmd.Flags().StringSliceVar(&opt.allow, "allow", nil, "extra source addresses or prefixes to answer, beyond your fleet (repeatable)")
	cmd.Flags().BoolVar(&opt.compat, "compat-headers", false, "also emit the Tailscale-User-* spellings for a proven caller")
	cmd.Flags().BoolVar(&opt.headers, "identity-headers", true, "stamp the Whisper-* identity headers on proxied requests")
	cmd.Flags().BoolVar(&opt.yes, "yes", false, "skip the confirmation (scripts)")
	cmd.Flags().BoolVar(&opt.bg, "bg", false, "hold it in the background and return")
	cmd.Flags().BoolVar(&opt.held, "__held", false, "internal: this process IS the background holder")
	_ = cmd.Flags().MarkHidden("__held")
	cmd.Flags().StringVar(&opt.stateDir, "state-dir", "", "override the state directory (testing)")
	_ = cmd.Flags().MarkHidden("state-dir")

	cmd.AddCommand(newWhaleServeOffCmd(verb), newWhaleServeStatusCmd(verb))
	return cmd
}

// newWhaleServeOffCmd is the one word that ends an exposure. It stops whatever is
// recorded, serve or funnel, because a person reaching for `off` wants the exposure gone
// and being told they used the other verb's spelling would help nobody.
func newWhaleServeOffCmd(verb string) *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "off",
		Short: "Stop serving, immediately",
		Long: "Stop whatever this host is serving - fleet or public - and remove the record.\n\n" +
			"Idempotent: if nothing is running it says so and succeeds. There is no way to be\n" +
			"left exposed by an `off` that thought it had nothing to do.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := serveStateDir(stateDir)
			st, wasRunning, err := whale.StopServeState(dir)
			if err != nil {
				return err
			}
			if !wasRunning {
				if st.Scope.Valid() {
					whaleNote("nothing was running: the record named pid %d, which is gone. Record cleared.", st.PID)
					return nil
				}
				whaleNote("nothing is being served from this host.")
				return nil
			}
			fmt.Fprintf(os.Stdout, "stopped: %s of %s (%s)\n", st.Scope.Verb(), st.Target, st.URL())
			if st.Scope.Public() {
				whaleNote("the public exposure is gone. The address stays routable, as it always was; nothing answers on it now.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "override the state directory (testing)")
	_ = cmd.Flags().MarkHidden("state-dir")
	_ = verb
	return cmd
}

// newWhaleServeStatusCmd prints what is being served, with the scope first, because the
// scope is the part that matters.
func newWhaleServeStatusCmd(verb string) *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "What this host is serving, and to whom",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, ok := whale.ReadServeState(serveStateDir(stateDir))
			if g.jsonOut {
				if !ok {
					emitJSONValue(map[string]any{"serving": false})
					return nil
				}
				emitJSONValue(map[string]any{"serving": true, "state": st})
				return nil
			}
			if !ok {
				fmt.Fprintln(os.Stdout, "nothing is being served from this host.")
				return nil
			}
			renderServeState(st)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "override the state directory (testing)")
	_ = cmd.Flags().MarkHidden("state-dir")
	_ = verb
	return cmd
}

// serveStateDir resolves where the record lives: the flag (tests), else ~/.config/whisper.
func serveStateDir(override string) string {
	if s := strings.TrimSpace(override); s != "" {
		return s
	}
	return whale.DefaultServeStateDir()
}

// renderServeState is the shared rendering, used by `serve status` and by `whale status`.
func renderServeState(st whale.ServeState) {
	audience := "your fleet only"
	if st.Scope.Public() {
		audience = "THE INTERNET (public)"
	}
	rows := [][]string{
		{"scope", string(st.Scope) + " - " + audience},
		{"url", st.URL()},
		{"origin", st.Target},
		{"address", orDash(st.Address)},
	}
	if st.FQDN != "" {
		rows = append(rows, []string{"name", st.FQDN})
	}
	headers := "off"
	if st.IdentityHeaders {
		headers = "on"
		if st.CompatHeaders {
			headers += " (+ Tailscale-User-* compat)"
		}
	}
	rows = append(rows,
		[]string{"identity headers", headers},
		[]string{"since", st.Since.Local().Format(time.RFC3339)},
		[]string{"pid", strconv.Itoa(st.PID)},
	)
	printTable([]string{"SERVING", ""}, rows)
	if st.Scope.Public() {
		whaleNote("this is public. `whisper whale %s off` ends it.", st.Scope.Verb())
	}
}

// runWhaleServe is the engine both verbs land in.
func runWhaleServe(cmd *cobra.Command, opt serveOptions) error {
	target, err := whale.ParseServeTarget(opt.target)
	if err != nil {
		return usageErr("%s", err.Error())
	}
	mount, err := whale.MountPath(opt.setPath)
	if err != nil {
		return usageErr("%s", err.Error())
	}
	if opt.httpsPort != identityTLSPort {
		return usageErr("port %d cannot be served: the pin that makes this verifiable with no CA is "+
			"`_443._tcp.<fqdn> TLSA`, so the only port that can be proven is %d",
			opt.httpsPort, identityTLSPort)
	}
	extra, err := parseAllowList(opt.allow)
	if err != nil {
		return usageErr("%s", err.Error())
	}
	dir := serveStateDir(opt.stateDir)

	if st, ok := whale.ReadServeState(dir); ok {
		return &client.ProblemError{Status: 409, Title: "already serving", Detail: fmt.Sprintf(
			"this host is already running a %s of %s (pid %d) - run `whisper whale %s off` first",
			st.Scope.Verb(), st.Target, st.PID, st.Scope.Verb())}
	}

	// Consent, before anything is built. A funnel is the one verb here whose mistake
	// cannot be taken back, so it is the one verb that asks.
	if opt.scope.Public() && !opt.yes && !opt.held {
		fmt.Fprintf(os.Stdout,
			"This publishes %s to the WHOLE INTERNET from this node's /128, on port %d.\n"+
				"Anyone who finds the address gets whatever that origin serves. It is not a preview\n"+
				"and there is no propagation delay: it is live the moment it starts.\n\n"+
				"Type yes to continue: ", target.String(), identityTLSPort)
		if !confirm("yes") {
			return &client.ProblemError{Status: 400, Title: "not confirmed", Detail: "nothing was exposed. " +
				"Run it again and type yes, pass --yes from a script, or use `whisper whale serve` to reach your fleet only"}
		}
	}

	if opt.bg && !opt.held {
		return spawnWhaleServe(opt, target.String(), mount)
	}

	c, err := resolveClient(true, !opt.held)
	if err != nil {
		return err
	}

	cx, cancel := ctx()
	defer cancel()

	// Never take a tunnel away from something already holding one. op:connect binds ONE
	// WireGuard peer per /128, so connecting for an address a local daemon is serving
	// would replace its peer and kill it (session_registry.go says why at length).
	sel := strings.TrimSpace(opt.agent)
	if sel != "" {
		if resolved, rerr := resolveAgentArg(c, cx, sel, false, ""); rerr == nil {
			sel = resolved
		} else {
			return rerr
		}
	}
	if live, ok := findLiveSession(cx, c, sel); ok {
		return &client.ProblemError{Status: 409, Title: "connection already held", Detail: fmt.Sprintf(
			"this host already holds a Whisper connection for %s, and `whale %s` has to own the tunnel it "+
				"serves on. Stop that connection first, or pass --agent to serve as a different agent",
			live.addr, opt.scope.Verb())}
	}

	sess, tun, err := whaleServeConnect(cx, c, sel)
	if err != nil {
		return err
	}
	defer sess.Stop()
	// Register the held session, exactly as the connect daemon does. op:connect binds ONE
	// WireGuard peer per /128, so a `whisper ip` run while this serve is up would otherwise
	// open its own connect, replace our peer, and take the serve down on its way out. The
	// record is how that one-shot finds us and reuses us instead.
	writeSessionRecord(sess)
	defer clearSessionRecord(sess)

	// The listener has to be REAL before we claim to be serving on it. An installed
	// handler behind a listener that never bound is the shipped-but-unreachable defect,
	// and from inside this process it would look perfectly healthy.
	if !whaleServeListenerUp(tun) {
		return &client.ProblemError{Status: 503, Title: "no listener", Detail: "the in-tunnel TLS listener did not " +
			"start on this node, so there is nothing to serve on. Run `whisper connect --tier wireguard` to see why it failed"}
	}

	gate, err := newFleetGate(cx, c, sess.addr, extra, opt.scope)
	if err != nil {
		return err
	}

	proxy, err := whale.NewServeProxy(whale.ProxyOptions{
		Target:          target.URL,
		MountPath:       mount,
		Scope:           opt.scope,
		Gate:            gate.gateFor(opt.scope),
		Identity:        newServeIdentityCache(c),
		IdentityHeaders: opt.headers,
		CompatHeaders:   opt.compat,
		Logf:            serveLogf(opt),
	})
	if err != nil {
		return &client.ProblemError{Status: 500, Detail: err.Error()}
	}

	fqdn := ""
	if peers, ferr := whaleFleet(cx, c); ferr == nil {
		for _, p := range peers {
			if p.Address == sess.addr {
				fqdn = firstNonBlank(p.FQDN, p.Name)
				break
			}
		}
	}

	st := whale.ServeState{
		Scope: opt.scope, Target: target.String(), Path: mount, Port: identityTLSPort,
		Address: sess.addr, FQDN: fqdn, PID: os.Getpid(), Since: time.Now(),
		IdentityHeaders: opt.headers, CompatHeaders: opt.compat,
	}
	if werr := whale.WriteServeState(dir, st); werr != nil {
		// The record is how `off` from another shell finds us. Without it, a funnel could
		// outlive the shell that knows about it, which is exactly the failure this whole
		// verb is careful about. Refuse rather than expose something we cannot switch off.
		return &client.ProblemError{Status: 500, Title: "could not record the serve", Detail: fmt.Sprintf(
			"%v - refusing to serve something `whale %s off` could not find", werr, opt.scope.Verb())}
	}
	defer func() { _ = whale.ClearServeState(dir) }()

	whaleServeInstall(tun, proxy)
	defer whaleServeInstall(tun, nil)

	go gate.refreshLoop(c, opt.scope)

	if !g.quiet && !opt.held {
		renderServeState(st)
		if !target.Loopback {
			whaleNote("the origin %s is not on this host, so it sees THIS node as the client. The identity "+
				"headers still describe the real caller.", target.URL.Host)
		}
		if opt.scope == whale.ScopeFleet {
			whaleNote("callers outside your fleet get a 403. Ctrl-C stops it.")
		} else {
			whaleNote("Ctrl-C stops it, and so does `whisper whale funnel off` from any shell.")
		}
	}

	holdWhaleServe()
	if !g.quiet && !opt.held {
		stats := proxy.Stats()
		fmt.Fprintf(os.Stderr, "\nstopped. %d request(s), %d refused, %d with claimed identity headers stripped.\n",
			stats.Requests, stats.Refused, stats.Spoofed)
	}
	return nil
}

// whaleServeListenerUp and whaleServeInstall are the two seams between this command and
// the tunnel it serves inside. They exist so a test can drive the REAL command - flags,
// consent, gate, proxy, headers, state record - and then send real requests through the
// handler the command installed, which is the only way to prove the production path
// actually reaches it. In the binary they are exactly the two tunnel methods.
var (
	whaleServeListenerUp = func(tun *wgtun.Tunnel) bool { return tun.ServingTLS() }
	whaleServeInstall    = func(tun *wgtun.Tunnel, h http.Handler) { tun.SetServeHandler(h) }
)

// holdWhaleServe parks until the operator (or `off`) asks us to stop. A package var so a
// test can run the whole engine without a signal.
var holdWhaleServe = func() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
}

// whaleServeConnect brings up the Tier-1 tunnel this serve runs inside, through the SAME
// shared connect path every other surface uses. Nothing here is a second connect: op:connect,
// the local WireGuard keypair, the identity leaf and the in-tunnel listener are all
// the existing ones. A package var so the command can be tested without a network.
var whaleServeConnect = func(cx context.Context, c *client.Client, sel string) (*egressSession, *wgtun.Tunnel, error) {
	args := map[string]any{"tier": "wireguard"}
	if sel != "" {
		args["agent"] = sel
	}
	wgKey, err := prepareWireGuard("wireguard", args)
	if err != nil {
		return nil, nil, err
	}
	idKey, err := prepareIdentityKey("wireguard", args, sel)
	if err != nil {
		return nil, nil, err
	}
	env, err := c.Agents(cx, "connect", args)
	if err != nil {
		return nil, nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, nil, perr
	}
	sess, err := connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result),
		&connectKeys{wg: wgKey, identity: idKey}, 0)
	if err != nil {
		return nil, nil, err
	}
	tun, ok := sess.local.(*wgtun.Tunnel)
	if !ok || tun == nil {
		sess.Stop()
		return nil, nil, &client.ProblemError{Status: 503, Title: "no routed tunnel", Detail: "this connection did " +
			"not land on the routed WireGuard tier, and only a routed node can be reached on its own /128. " +
			"`whisper whale netcheck` reports whether UDP to the box is getting out"}
	}
	return sess, tun, nil
}

// serveLogf is the one operational line a serve is allowed to print: refusals, stripped
// claims, a dead origin. Never a header value, never a target path.
func serveLogf(opt serveOptions) func(string, ...any) {
	if g.quiet || opt.held {
		return nil
	}
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

// --- who may be answered ------------------------------------------------------------

// fleetGate is the scope decision, kept in one place and refreshed while the serve runs.
// It holds the LAST GOOD fleet: a control plane that goes away must never widen who is
// answered, and must never narrow it to nobody either.
type fleetGate struct {
	mu      sync.RWMutex
	members map[netip.Addr]bool
	extra   []netip.Prefix
	self    netip.Addr
}

// newFleetGate reads the fleet once, up front. For a fleet-scoped serve that read MUST
// succeed: starting without knowing who the fleet is would mean either answering nobody
// or, far worse, answering everybody.
func newFleetGate(cx context.Context, c *client.Client, self string, extra []netip.Prefix, scope whale.ServeScope) (*fleetGate, error) {
	g := &fleetGate{members: map[netip.Addr]bool{}, extra: extra}
	if addr, err := netip.ParseAddr(self); err == nil {
		g.self = addr
		g.members[addr] = true
	}
	if scope.Public() {
		return g, nil // everyone is answered; the fleet is not consulted
	}
	if err := g.refresh(cx, c); err != nil {
		return nil, &client.ProblemError{Status: 503, Title: "fleet unknown", Detail: fmt.Sprintf(
			"could not read your fleet, so there is no way to know who to answer: %s. "+
				"Name the callers with --allow, or use `whisper whale funnel` if you meant to answer everyone",
			friendly(err))}
	}
	return g, nil
}

func (g *fleetGate) refresh(cx context.Context, c *client.Client) error {
	peers, err := whaleFleet(cx, c)
	if err != nil {
		return err
	}
	next := map[netip.Addr]bool{}
	for _, p := range peers {
		if addr, perr := netip.ParseAddr(p.Address); perr == nil {
			next[addr] = true
		}
	}
	if g.self.IsValid() {
		next[g.self] = true
	}
	if len(next) == 0 {
		return fmt.Errorf("your fleet is empty")
	}
	g.mu.Lock()
	g.members = next
	g.mu.Unlock()
	return nil
}

// refreshLoop keeps the fleet current for as long as the serve runs. A failed refresh
// KEEPS the last good set: the previous answer is both the safest and the most accurate
// thing we have, and a transient control-plane fault must not change who is answered.
func (g *fleetGate) refreshLoop(c *client.Client, scope whale.ServeScope) {
	if scope.Public() {
		return
	}
	for {
		time.Sleep(whaleServeFleetRefresh)
		cx, cancel := ctx()
		_ = g.refresh(cx, c)
		cancel()
	}
}

// gateFor returns the per-request decision. A public funnel has no gate at all, which is
// the only configuration where nil is the right answer.
func (g *fleetGate) gateFor(scope whale.ServeScope) whale.ServeGate {
	if scope.Public() {
		return nil
	}
	return g.permit
}

func (g *fleetGate) permit(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	g.mu.RLock()
	member := g.members[a]
	g.mu.RUnlock()
	if member {
		return true
	}
	for _, p := range g.extra {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseAllowList reads --allow. Addresses and prefixes only: a name would have to be
// resolved at request time through a resolver we do not control, which is a worse security
// property than the flag looks like it has, so it is refused with the reason.
func parseAllowList(raw []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("--allow %q is neither an address nor a prefix. Names are not accepted here: "+
			"resolving one at request time would make who gets answered depend on a resolver, which is not a "+
			"decision an access rule should delegate", s)
	}
	return out, nil
}

// --- establishing who the caller is ---------------------------------------------------

// newServeIdentityCache wires the three lookups behind the identity headers to the code
// that already answers those exact questions elsewhere in this CLI: the in-process DNSSEC
// walk `whale whois` uses, the RDAP object it reads the holder from, and the
// `whisper.assess` call `whale dns` shows. Nothing here is a new source of truth.
func newServeIdentityCache(c *client.Client) *whale.IdentityCache {
	return whale.NewIdentityCache(whale.IdentityLookup{
		PTR:    servePTRLookup,
		Owner:  serveOwnerLookup(c),
		Assess: serveAssessLookup(c),
	}, whale.IdentityCacheOptions{})
}

// servePTRLookup is the same in-process validation `whale whois` performs, and for the
// same reason: our resolver never sets AD, so anyone reading an AD bit here would be
// building on nothing. A name is returned ONLY when the reverse chain validated from the
// IANA root AND the forward name confirmed back to the same address.
var servePTRLookup = func(ctx context.Context, addr netip.Addr) (string, string) {
	cx, cancel := context.WithTimeout(ctx, whaleServeLookupTimeout)
	defer cancel()
	v := trustverify.NewValidator(trustverify.NewNetResolver(""), trustverify.IANARootAnchors(), time.Now())
	ptr, note := validatedPTR(cx, v, addr)
	if ptr == "" {
		return "", note
	}
	confirm := forwardConfirm(cx, v, ptr, addr)
	if strings.HasPrefix(confirm, "not confirmed") {
		return "", "PTR validated but " + confirm
	}
	return dns.Fqdn(ptr), ""
}

// whaleServeLookupTimeout bounds one identity lookup. It is longer than the per-request
// budget on purpose: the request does not wait for it, the CACHE does, and an answer that
// lands a second late still serves every later request from this caller.
const whaleServeLookupTimeout = 6 * time.Second

// serveOwnerLookup asks RDAP who holds the address. RDAP is public and keyless, and it is
// OUR object for a Whisper /128, so the answer is the one our own registry publishes.
func serveOwnerLookup(c *client.Client) func(context.Context, netip.Addr) (string, string) {
	return func(ctx context.Context, addr netip.Addr) (string, string) {
		if c == nil {
			return "", "no control-plane client"
		}
		cx, cancel := context.WithTimeout(ctx, whaleServeLookupTimeout)
		defer cancel()
		body, status, err := c.RDAP(cx, client.RDAPIP, addr.String(), "")
		if err != nil {
			return "", "RDAP did not answer"
		}
		if status >= 400 {
			return "", fmt.Sprintf("RDAP returned %d", status)
		}
		var obj map[string]any
		if json.Unmarshal(body, &obj) != nil {
			return "", "RDAP answered with something that is not an object"
		}
		if holder := rdapHolder(obj); holder != "" {
			return holder, ""
		}
		if name := jsonStr(obj["name"]); name != "" {
			return name, ""
		}
		return "", "the RDAP object names no holder"
	}
}

// serveAssessLookup is the graph's own verdict on the caller, the same `whisper.assess`
// call `whale dns` renders. It is the header the competition cannot emit at all.
func serveAssessLookup(c *client.Client) func(context.Context, netip.Addr) (string, string, string) {
	return func(ctx context.Context, addr netip.Addr) (string, string, string) {
		cx, cancel := context.WithTimeout(ctx, whaleServeLookupTimeout)
		defer cancel()
		return graphAssess(cx, c, addr.String())
	}
}

// graphAssess is the single place the graph is asked to assess an indicator for the whale
// shell. `whale dns` renders it for a name; `whale serve` puts it in a header for a caller.
// One call, one shape, so the two can never disagree about what a band means.
func graphAssess(cx context.Context, c *client.Client, target string) (band, coverage, note string) {
	if c == nil || c.Credential().IsZero() {
		return "", "", "add your key to see the graph's assessment"
	}
	rows, _, err := c.GraphQueryRows(cx,
		"CALL whisper.assess([$v]) YIELD host, label, band, coverage", map[string]any{"v": target})
	if err != nil {
		return "", "", "the graph did not answer: " + friendly(err)
	}
	if len(rows) == 0 {
		return "", "", "the graph holds no assessment"
	}
	r := rows[0]
	band = firstNonBlank(asString(r["band"]), asString(r["label"]))
	if band == "" {
		return "", "", "the graph holds no assessment"
	}
	return band, asString(r["coverage"]), ""
}

// --- background hold -------------------------------------------------------------------

// spawnWhaleServe re-execs this binary as the detached holder, exactly the way the connect
// daemon is spawned (same detach, same never-on-argv key handling), and waits until the
// child has RECORDED itself before reporting success - so `--bg` never returns claiming a
// serve that did not come up.
var spawnWhaleServe = func(opt serveOptions, target, mount string) error {
	self, err := os.Executable()
	if err != nil || strings.TrimSpace(self) == "" {
		return &client.ProblemError{Status: 500, Detail: "couldn't locate the whisper binary to hold the serve"}
	}
	args := []string{"whale", opt.scope.Verb(), target, "--__held", "--yes"}
	if mount != "/" {
		args = append(args, "--set-path", mount)
	}
	if opt.agent != "" {
		args = append(args, "--agent", opt.agent)
	}
	for _, a := range opt.allow {
		args = append(args, "--allow", a)
	}
	if opt.compat {
		args = append(args, "--compat-headers")
	}
	if !opt.headers {
		args = append(args, "--identity-headers=false")
	}
	if opt.stateDir != "" {
		args = append(args, "--state-dir", opt.stateDir)
	}
	if g.controlURL != "" {
		args = append(args, "--control-url", g.controlURL)
	}
	if g.keyFile != "" {
		args = append(args, "--key-file", g.keyFile)
	}

	c := exec.Command(self, args...)
	if devnull, derr := os.OpenFile(os.DevNull, os.O_RDWR, 0); derr == nil {
		c.Stdin, c.Stdout, c.Stderr = devnull, devnull, devnull
		defer devnull.Close()
	}
	c.Env = daemonEnv(os.Environ())
	applyDetach(c)
	if err := c.Start(); err != nil {
		return &client.ProblemError{Status: 500, Detail: "couldn't start the background holder - please try again"}
	}
	if c.Process != nil {
		defer func() { _ = c.Process.Release() }()
	}

	dir := serveStateDir(opt.stateDir)
	deadline := time.Now().Add(whaleServeStartBudget)
	for time.Now().Before(deadline) {
		if st, ok := whale.ReadServeState(dir); ok {
			if !g.quiet {
				renderServeState(st)
			}
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return &client.ProblemError{Status: 504, Title: "did not come up", Detail: fmt.Sprintf(
		"the background %s did not record itself within %s. Run it in the foreground to see why",
		opt.scope.Verb(), whaleServeStartBudget)}
}
