// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// connect_accept.go is `whisper connect --accept`: the operator's choice of which
// TCP ports this node answers on its own /128, and who may reach them.
//
// On the userspace tier the /128 lives only inside this process, so `ssh` to a healthy node
// met a closed port and `whisper whale ssh` could never reach one. --accept opens the ports
// named, OFF unless asked for, and splices each connection to a service on this host
// (wgtun/accept.go). The access decision is the one `whale serve` makes, from the same code:
// your fleet by default, refreshed while the connection runs, keeping the last good answer
// through a control-plane fault. `--accept-from` adds named addresses or prefixes. The
// internet is admitted only with --accept-public, which, like `whale funnel`, has to be said
// out loud: a typed yes or --yes, recorded in the session record so `whisper whale status`
// shows it from any shell.
//
// The rules are held for the whole process and re-opened on every tunnel the process brings
// up, so a session that renews after the box dropped its peer comes back accepting the same
// ports. That is why they live here as process state rather than on one tunnel.

// acceptReservedPort is the port the identity TLS listener owns on every routed /128. An
// accept rule cannot take it: the published TLSA pins it, and `whale serve` lives behind it.
const acceptReservedPort = identityTLSPort

// parseAcceptRules reads --accept values, liberally: `22`, `:22`, `2222=22`,
// `2222=127.0.0.1:22`, `2222=[::1]:22` and `2222=localhost:22`, repeated or comma-joined.
// The target is always on THIS host's loopback. Forwarding fleet connections on into a LAN
// would turn a node into a pivot onto networks the fleet was never given, which is a decision
// this flag is too small to carry.
func parseAcceptRules(raw []string) ([]wgtun.AcceptRule, error) {
	var out []wgtun.AcceptRule
	seen := map[int]bool{}
	for _, item := range raw {
		for _, spec := range strings.Split(item, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			rule, err := parseAcceptRule(spec)
			if err != nil {
				return nil, err
			}
			if seen[rule.Port] {
				return nil, fmt.Errorf("--accept names port %d twice; each port on the /128 goes to one place", rule.Port)
			}
			seen[rule.Port] = true
			out = append(out, rule)
		}
	}
	return out, nil
}

func parseAcceptRule(spec string) (wgtun.AcceptRule, error) {
	listen, target, mapped := strings.Cut(spec, "=")
	port, err := acceptPort(strings.TrimPrefix(strings.TrimSpace(listen), ":"))
	if err != nil {
		return wgtun.AcceptRule{}, fmt.Errorf("--accept %q: %v. Write a port (22) or a mapping (2222=127.0.0.1:22)", spec, err)
	}
	if port == acceptReservedPort {
		return wgtun.AcceptRule{}, fmt.Errorf("--accept %q: port %d on the /128 is the identity listener the published "+
			"TLSA pins, so it cannot be handed to another service. Put an HTTPS origin behind it with `whisper whale serve`", spec, port)
	}
	if !mapped {
		return wgtun.AcceptRule{Port: port, Target: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}, nil
	}
	target = strings.TrimSpace(target)
	host, tport := "127.0.0.1", target
	if strings.Contains(target, ":") {
		h, p, serr := net.SplitHostPort(target)
		if serr != nil {
			return wgtun.AcceptRule{}, fmt.Errorf("--accept %q: the target %q is not host:port", spec, target)
		}
		host, tport = h, p
	}
	tp, err := acceptPort(tport)
	if err != nil {
		return wgtun.AcceptRule{}, fmt.Errorf("--accept %q: the target port: %v", spec, err)
	}
	host = strings.TrimSpace(host)
	switch {
	case strings.EqualFold(host, "localhost"):
		host = "127.0.0.1"
	case host == "":
		host = "127.0.0.1"
	default:
		a, perr := netip.ParseAddr(host)
		if perr != nil || !a.Unmap().IsLoopback() {
			return wgtun.AcceptRule{}, fmt.Errorf("--accept %q: the target must be a service on this host (127.0.0.1, ::1 "+
				"or localhost), not %s. Passing fleet connections on to another machine would make this node a way into "+
				"its network", spec, host)
		}
		host = a.Unmap().String()
	}
	return wgtun.AcceptRule{Port: port, Target: net.JoinHostPort(host, strconv.Itoa(tp))}, nil
}

func acceptPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("no port given")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a TCP port (1-65535)", s)
	}
	return n, nil
}

// acceptRequest is what the operator asked for, from flags or from a service config, before
// anything has been checked against the network.
type acceptRequest struct {
	rules  []wgtun.AcceptRule
	extra  []netip.Prefix
	public bool
}

// buildAcceptRequest validates the three flags together. It is the one parser both the
// interactive connect and the service install use, so the two can never accept different
// spellings of the same request.
func buildAcceptRequest(ports, from []string, public bool) (*acceptRequest, error) {
	rules, err := parseAcceptRules(ports)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		if public || len(nonBlank(from)) > 0 {
			return nil, fmt.Errorf("--accept-from and --accept-public say who may reach the accepted ports, " +
				"so they need an --accept to apply to (for example --accept 22)")
		}
		return nil, nil
	}
	extra, err := parseAllowList(from)
	if err != nil {
		return nil, fmt.Errorf("%s", strings.Replace(err.Error(), "--allow", "--accept-from", 1))
	}
	for _, p := range extra {
		if p.Bits() < acceptFromShortest(p) {
			return nil, fmt.Errorf("--accept-from %s admits a large part of the internet. That is what --accept-public "+
				"is for, and it asks you to confirm it; name a prefix of /%d or longer here", p, acceptFromShortest(p))
		}
	}
	return &acceptRequest{rules: rules, extra: extra, public: public}, nil
}

// acceptFromShortest is the widest prefix --accept-from takes: a /32 of IPv6 is a whole
// provider, and a /16 of IPv4 is already a large slice of one. Anything wider is the internet in
// all but name, so it must go through the consent --accept-public asks for instead of around it.
func acceptFromShortest(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 16
	}
	return 32
}

func nonBlank(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// acceptRequestFromConfig reads the durable form a service install wrote. A public request
// with no recorded consent is downgraded to the fleet and says so: a hand edit that flips
// one boolean must not open a port to the internet.
func acceptRequestFromConfig(ac *projcfg.AcceptConfig, logf func(string, ...any)) (*acceptRequest, error) {
	if ac == nil || len(nonBlank(ac.Ports)) == 0 {
		return nil, nil
	}
	public := ac.Public
	if _, terr := time.Parse(time.RFC3339, strings.TrimSpace(ac.PublicConsentedAt)); public && terr != nil {
		public = false
		if logf != nil {
			logf("whisper: the config asks for public accept but records no consent to it, so only your fleet is " +
				"admitted. `whisper service install --accept-public --yes ...` records it")
		}
	}
	return buildAcceptRequest(ac.Ports, ac.From, public)
}

// scope is who the request admits, in the words `whale serve` and `whale funnel` use.
func (r *acceptRequest) scope() whale.ServeScope {
	if r != nil && r.public {
		return whale.ScopeInternet
	}
	return whale.ScopeFleet
}

// confirmAcceptPublic is the funnel's consent, for accept. It runs before anything is built.
func confirmAcceptPublic(r *acceptRequest, yes bool) error {
	if r == nil || !r.public || yes {
		return nil
	}
	ports := make([]string, 0, len(r.rules))
	for _, rule := range r.rules {
		ports = append(ports, strconv.Itoa(rule.Port))
	}
	fmt.Fprintf(os.Stdout,
		"This opens port(s) %s on this node's /128 to the WHOLE INTERNET, not only your fleet.\n"+
			"Anyone who finds the address can reach the service behind it. It is live the moment\n"+
			"the tunnel is up.\n\nType yes to continue: ", strings.Join(ports, ", "))
	if !confirm("yes") {
		return &client.ProblemError{Status: 400, Title: "not confirmed", Detail: "nothing was opened. " +
			"Type yes, pass --yes from a script, or drop --accept-public to admit your fleet only"}
	}
	return nil
}

// acceptPlan is a request made live: the rules, the access decision, and the fleet refresh
// that keeps it current. One per process.
type acceptPlan struct {
	req  *acceptRequest
	gate *fleetGate
	stop func()
	logf func(string, ...any)

	mu   sync.Mutex
	tuns []*wgtun.Tunnel
}

// newAcceptPlan reads the fleet once and keeps it current. It never fails: a holder whose
// connection is the thing being supervised must come up even when the control plane is
// away, so a fleet that cannot be read yet admits NOBODY (fail closed for access, open for
// the connection) and the refresh keeps trying.
func newAcceptPlan(cx context.Context, c *client.Client, req *acceptRequest, logf func(string, ...any)) *acceptPlan {
	p := &acceptPlan{req: req, logf: logf, stop: func() {}}
	p.gate = &fleetGate{members: map[netip.Addr]bool{}, extra: req.extra}
	// The fleet is read even when the internet is admitted: it no longer decides who gets in,
	// but it still decides who is counted as one agent rather than pooled with a /64.
	if err := acceptFleetRefresh(cx, p.gate, c); err != nil && logf != nil && !req.public {
		logf("whisper: could not read your fleet (%s), so the accepted ports admit no one yet; trying again every %s",
			friendly(err), roughDuration(whaleServeFleetRefresh))
	}
	p.gate.onRefresh = p.revalidate
	p.stop = p.gate.startRefresh(c, whale.ScopeFleet, callTimeout(), whaleServeFleetRefresh)
	return p
}

// acceptFleetRefresh is the fleet read, behind a seam so a test can hand it a fleet.
var acceptFleetRefresh = func(cx context.Context, g *fleetGate, c *client.Client) error { return g.refresh(cx, c) }

func (p *acceptPlan) permit(a netip.Addr) bool {
	if p == nil {
		return false
	}
	if p.req.public {
		return a.IsValid()
	}
	return p.gate.permit(a)
}

// member reports a caller that is a fleet member by its own /128, which the limits count alone.
func (p *acceptPlan) member(a netip.Addr) bool {
	if p == nil || p.gate == nil {
		return false
	}
	p.gate.mu.RLock()
	defer p.gate.mu.RUnlock()
	return p.gate.members[a.Unmap()]
}

func (p *acceptPlan) close() {
	if p != nil && p.stop != nil {
		p.stop()
	}
}

// acceptOpener is the tunnel method, behind a seam so the bring-up can be tested without a
// netstack.
var acceptOpener = func(tun *wgtun.Tunnel, rules []wgtun.AcceptRule, opts wgtun.AcceptOptions) error {
	return tun.Accept(rules, opts)
}

// open puts the plan's rules on a freshly brought-up tunnel and returns what to record. A
// port that cannot be opened is reported and costs the accept, never the connection: egress
// is still the thing most of this host depends on.
func (p *acceptPlan) open(tun *wgtun.Tunnel) ([]acceptRecord, string) {
	if p == nil || tun == nil {
		return nil, ""
	}
	p.track(tun)
	if err := acceptOpener(tun, p.req.rules, wgtun.AcceptOptions{Permit: p.permit, Individual: p.member, Logf: p.logf, OnCarry: recordAcceptCaller}); err != nil {
		if p.logf != nil {
			p.logf("whisper: no ports accepted: %v. The connection itself is unaffected", err)
		}
		return nil, ""
	}
	recs := make([]acceptRecord, 0, len(p.req.rules))
	for _, r := range p.req.rules {
		recs = append(recs, acceptRecord{Port: r.Port, Target: r.Target})
	}
	if p.logf != nil {
		p.logf("whisper: accepting %s on this node's /128, %s", acceptRulesText(recs), acceptAudience(p.req.scope(), p.req.extra))
	}
	return recs, string(p.req.scope())
}

// fromText is the extra prefixes, as the session record carries them.
func (p *acceptPlan) fromText() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.req.extra))
	for _, x := range p.req.extra {
		out = append(out, x.String())
	}
	return out
}

// track remembers a tunnel this plan opened ports on, so a changed fleet reaches the
// connections it already carries (revalidate). Tunnels that have stopped are dropped.
func (p *acceptPlan) track(tun *wgtun.Tunnel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := p.tuns[:0]
	for _, t := range p.tuns {
		if t != tun && len(t.Accepting()) > 0 {
			live = append(live, t)
		}
	}
	p.tuns = append(live, tun)
}

// revalidate closes every open accepted connection the fleet no longer admits. Run after each
// fleet refresh: an agent revoked mid-session loses the shell it has, not only the next one.
func (p *acceptPlan) revalidate() {
	p.mu.Lock()
	tuns := append([]*wgtun.Tunnel(nil), p.tuns...)
	p.mu.Unlock()
	for _, t := range tuns {
		t.RevalidateAccept()
	}
}

// The plan this process applies to every tunnel it brings up. Set by the holder (the
// interactive connect, the supervised daemon) for its lifetime; nil everywhere else, which is
// every one-shot and `whale serve`.
var (
	acceptPlanMu sync.Mutex
	acceptActive *acceptPlan
)

// installAcceptPlan makes p the process's plan and returns the function that removes it.
func installAcceptPlan(p *acceptPlan) (remove func()) {
	acceptPlanMu.Lock()
	acceptActive = p
	acceptPlanMu.Unlock()
	return func() {
		acceptPlanMu.Lock()
		if acceptActive == p {
			acceptActive = nil
		}
		acceptPlanMu.Unlock()
		p.close()
	}
}

func currentAcceptPlan() *acceptPlan {
	acceptPlanMu.Lock()
	defer acceptPlanMu.Unlock()
	return acceptActive
}

// acceptRecord is one accepted port as the session record carries it: no secret, the same
// discipline as the rest of that record.
type acceptRecord struct {
	Port   int    `json:"port"`
	Target string `json:"target"`
}

func acceptRulesText(recs []acceptRecord) string {
	parts := make([]string, 0, len(recs))
	for _, r := range recs {
		parts = append(parts, fmt.Sprintf("%d -> %s", r.Port, r.Target))
	}
	return strings.Join(parts, ", ")
}

// acceptAudience is who is admitted, said the way a person needs to read it.
func acceptAudience(scope whale.ServeScope, extra []netip.Prefix) string {
	if scope.Public() {
		return "THE INTERNET (public)"
	}
	s := "your fleet only"
	if len(extra) > 0 {
		names := make([]string, 0, len(extra))
		for _, p := range extra {
			names = append(names, p.String())
		}
		s += " and " + strings.Join(names, ", ")
	}
	return s
}

// acceptScopeText renders a recorded scope for status.
func acceptScopeText(scope string) string {
	if whale.ServeScope(scope).Public() {
		return "THE INTERNET (public)"
	}
	return "your fleet only"
}

// acceptStartupBudget bounds the fleet read a holder makes before its first bring-up.
const acceptStartupBudget = 15 * time.Second
