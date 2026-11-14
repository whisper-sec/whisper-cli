// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// run_enforce_linux.go is `whisper run --enforce`: the agent runs in a network namespace whose
// only way out is a WireGuard tunnel from its own /128, so a program that ignores the proxy
// variables still leaves from that /128, or is refused. The design and its reasons are ADR
// 0152; this file is the order things happen in, which is the order that never leaves a
// window:
//
//  1. who the agent runs as (never root), and with which key and agent;
//  2. the connect, through the same body every other connect runs;
//  3. the namespace and the tunnel, which come up refusing everything until the first handshake;
//  4. the egress verified from INSIDE the namespace, exactly as the agent's packets will leave;
//  5. only then the agent, under its own init.
//
// A failure at any step returns before the agent exists. There is no fallback to an
// unenforced run.

// enforceTarget is the account the agent runs as.
type enforceTarget struct {
	name       string
	uid, gid   uint32
	groups     []uint32
	home       string
	runtimeDir string
}

// resolveEnforceTarget picks the agent's account: --user, else the account that ran sudo.
// Root is refused in every spelling, because an agent with root's capabilities inside the
// namespace can add interfaces and routes and mount over what init set up.
func resolveEnforceTarget(flagUser string) (enforceTarget, error) {
	name := strings.TrimSpace(flagUser)
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		return enforceTarget{}, usageErr("the agent must not run as root, and this was not started with sudo: " +
			"name the account the agent runs as with --user <name>")
	}
	u, err := user.Lookup(name)
	if err != nil {
		if id, aerr := strconv.Atoi(name); aerr == nil {
			u, err = user.LookupId(strconv.Itoa(id))
		}
	}
	if err != nil {
		return enforceTarget{}, usageErr("no account named %q on this host", name)
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return enforceTarget{}, usageErr("the account %q has no numeric uid", name)
	}
	if uid == 0 {
		return enforceTarget{}, usageErr("the agent must not run as root (uid 0): an agent with root's " +
			"capabilities could leave its namespace. Name an ordinary account with --user")
	}
	t := enforceTarget{name: u.Username, uid: uint32(uid), gid: uint32(gid), home: u.HomeDir,
		runtimeDir: "/run/user/" + u.Uid}
	if ids, err := u.GroupIds(); err == nil {
		for _, s := range ids {
			if g, perr := strconv.ParseUint(s, 10, 32); perr == nil {
				t.groups = append(t.groups, uint32(g))
			}
		}
	}
	if len(t.groups) == 0 {
		t.groups = []uint32{t.gid}
	}
	return t, nil
}

// invokerFile names one of the sudo invoker's whisper files when root's own context has
// none: read, never written, and only when it is a regular file the invoker owns (never a
// link). Root's context is where everything enforce WRITES goes, so nothing in the invoker's
// home is ever created or changed by a process running as root.
func invokerFile(t enforceTarget, rootPath, leaf string) string {
	if _, err := os.Lstat(rootPath); err == nil {
		return ""
	}
	if !filepath.IsAbs(t.home) {
		return "" // no invoker (not run through sudo): root's own files are the only ones
	}
	p := filepath.Join(t.home, ".config", "whisper", leaf)
	if ownedRegularFile(p, int(t.uid)) {
		return p
	}
	return ""
}

func runEnforced(agent, agentFile, tier, flagUser, name string, childArgs []string) error {
	if os.Geteuid() != 0 {
		return usageErr("--enforce builds a network namespace for the agent, which needs root: " +
			"run it as `sudo whisper run --enforce -- <command>`")
	}
	if t := strings.ToLower(strings.TrimSpace(tier)); !isAutoTier(t) && !isWireGuardTier(t) {
		return usageErr("--enforce always uses the WireGuard tier (it is the one with a routed /128); drop --tier %s", tier)
	}
	seccompMode, err := enforce.NormalizeSeccomp(enforceSeccomp)
	if err != nil {
		return usageErr("%s", err.Error())
	}
	target, err := resolveEnforceTarget(flagUser)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return usageErr("couldn't find %q to run - is it installed and on your PATH?", name)
	}
	if abs, aerr := filepath.Abs(path); aerr == nil {
		path = abs
	}
	dir, _ := os.Getwd()

	up, err := bringUpEnforced(enforcedBringUp{
		target: target, agent: agent, agentFile: agentFile,
		command: "whisper run --enforce", notDone: "the agent was not started",
		start: enforce.StartTunnel,
	})
	if err != nil {
		return err
	}
	defer up.close()
	ce, hold, tun, logf, early := up.ce, up.hold, up.tun, up.logf, up.early
	logf("Enforced as %s - %s ✓ verified from inside the agent's namespace; %s", up.label, ce.address, up.v4note)

	spec := enforce.Spec{
		Path:      path,
		Args:      append([]string{name}, childArgs...),
		Env:       enforcedEnv(os.Environ(), target.name, target.home, target.runtimeDir, ce.address),
		Dir:       dir,
		UID:       target.uid,
		GID:       target.gid,
		Groups:    target.groups,
		Resolvers: addrStrings(up.resolvers),
		Seccomp:   seccompMode,
	}
	if seccompMode == enforce.SeccompOff {
		logf("whisper: --seccomp=off: the agent can open vsock sockets and io_uring rings")
	}
	// Once the agent has run, the /128 is let go only if the box still routes it through this
	// tunnel: a box that gave the peer to another key drops the probe.
	hold.confirm = func() bool {
		pcx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pcancel()
		ip, perr := echoInsideRetry(pcx, tun.NS, "ip6")
		return perr == nil && sameIP(ip, ce.address)
	}
	// The terminal delivers Ctrl-C to the agent directly; the CLI waits it out rather than
	// dying first and taking the agent's tunnel with it. A SIGTERM or SIGHUP sent to the CLI is
	// passed on to the agent's init, which passes it to the agent.
	//
	// The forwarder is registered before the early handler goes, so no signal in between meets
	// the default action and kills the CLI with the /128 still held. It stays registered to the
	// end: a SIGTERM during the teardown is absorbed rather than killing the CLI mid-disconnect,
	// and once the agent's init has been reaped nothing is sent to its pid, which another process
	// may hold by then. A Ctrl-C between the ignore below and the agent joining the terminal's
	// foreground group is lost, as before; the ignore has to precede the fork, which inherits it.
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	early.stop()
	if err := early.interrupted(); err != nil {
		return err
	}
	reaped := make(chan struct{})
	code, err := tun.NS.Spawn(spec, func(pid int) {
		go forwardSignals(fwd, reaped, pid)
	})
	close(reaped)
	st := &tun.Filter.Stats
	logf("whisper: enforced run ended: %d packets passed, %d translated, %d refused, %d dropped",
		st.Passed.Load(), st.Translated.Load(), st.Refused.Load(), st.Dropped.Load())
	if err != nil {
		return &client.ProblemError{Status: 500, Detail: strings.TrimPrefix(err.Error(), "enforce: ")}
	}
	// os.Exit runs no deferred call, so the /128 and the tunnel are let go here.
	hold.release(tun.Stop)
	os.Exit(code)
	return nil
}

// enforcedBringUp is what an enforced run and a containment pass to bringUpEnforced.
type enforcedBringUp struct {
	target           enforceTarget // whose key and agent files are read, when root's own has none
	agent, agentFile string
	command          string // how the command names itself in a refusal
	notDone          string // what a failure says was not done
	interruptNote    string // what an interruption says was not done; empty keeps the run's wording
	start            func(wgtun.Config, enforce.Policy, enforce.Options) (*enforce.Tunnel, error)
}

// enforcedUp is an enforced tunnel that is up and verified: the connect, the hold at the box, the
// per-/128 lock and the tunnel. `whisper run --enforce` puts a new agent behind it and `whisper
// contain` a running one; neither starts until this has verified the egress through the tunnel.
type enforcedUp struct {
	c      *client.Client
	ce     connectEnvelope
	hold   *enforcedHold
	tun    *enforce.Tunnel
	lock   *enforce.AgentLock
	early  *enforceSignals
	logf   func(string, ...any)
	label  string
	v4note string
	// resolvers are the in-tunnel resolvers the box named, the only DNS destinations.
	resolvers []netip.Addr
}

// close lets everything go in the order it was taken: the /128 at the box (which stops the
// tunnel itself, after deciding through it whether the peer is still this run's), the early
// signal handler, then the lock. Safe on a partly built value and more than once.
func (u *enforcedUp) close() {
	if u == nil {
		return
	}
	if u.hold != nil {
		stop := func() {}
		if u.tun != nil {
			stop = u.tun.Stop
		}
		u.hold.release(stop)
	} else if u.tun != nil {
		u.tun.Stop()
	}
	if u.early != nil {
		u.early.stop()
	}
	u.lock.Release()
}

// bringUpEnforced is steps 1 to 4 of an enforced run (see the top of this file): the key and the
// agent, the lock, the connect, the tunnel through o.start, and the egress verified through it.
// On any failure everything it took is let go again before it returns.
func bringUpEnforced(o enforcedBringUp) (_ *enforcedUp, err error) {
	target := o.target
	u := &enforcedUp{}
	ok := false
	defer func() {
		if !ok {
			u.close()
		}
	}()
	keyFile := g.keyFile
	if keyFile == "" && g.key == "" && g.bearer == "" && os.Getenv("WHISPER_API_KEY") == "" {
		keyFile = invokerFile(target, client.DefaultKeyFile(), "key")
	}
	c, err := resolveClientFrom(true, false, keyFile)
	if err != nil {
		return nil, err
	}
	identityBorrow = func(handle string) (*idkey.Keypair, bool) {
		p := filepath.Join(target.home, ".config", "whisper", "identity", filepath.Base(idkey.PathFor(handle)))
		if !ownedRegularFile(p, int(target.uid)) {
			return nil, false
		}
		kp, lerr := idkey.LoadFile(p)
		return kp, lerr == nil
	}
	agent, agentFile := o.agent, o.agentFile
	if agentFile == "" && strings.TrimSpace(agent) == "" {
		agentFile = invokerFile(target, client.DefaultAgentFile(), "agent")
	}
	// The one selection rule (agent_pick.go): --agent, --create/--name, the project (when no
	// agent file was found for the invoker), the invoker's saved agent. Never an existing agent the
	// person did not name: an enforced run replaces that agent's peer. It does not make one on its
	// own either, because it runs as root and root's saved agent file is not the one the invoker's
	// next command reads; the refusal names `whisper run` as the user, --agent and --name.
	pick, err := pickAgent(c, agentPickOpts{
		agent: agent, agentFile: agentFile, create: g.create, name: g.name,
		useProject: true, noCreate: true, noSave: true, command: o.command,
		trustFile: invokerFile(target, defaultProjectTrustFile(), projectTrustLeaf),
	})
	if err != nil {
		return nil, err
	}
	// An enforced run is always WireGuard, so a project config the invoking user never vouched
	// for is asked about on a terminal and refused in a script. Root remembers nothing.
	if _, gerr := projectGate(&pick, tierWireGuard, stdGuidedIO(), isInteractive(), false, "", o.command); gerr != nil {
		return nil, gerr
	}
	sel := pick.sel
	if note := peerReplacementNote(pick, tierWireGuard); note != "" && !g.quiet {
		fmt.Fprintln(os.Stderr, note)
	}
	// One enforced run per /128 on this host, and no `whisper connect` beside it. The lock is
	// taken BEFORE op:connect whenever the /128 is already known, because op:connect itself replaces
	// whatever peer the box holds for it; a selector that only resolves inside op:connect is locked
	// right after it, still before any tunnel or namespace exists.
	if a, perr := netip.ParseAddr(sel); perr == nil {
		if u.lock, err = enforce.LockExclusive(a); err != nil {
			return nil, usageErr("%s", err.Error())
		}
	}
	// The box holds one peer per /128. Connecting here would replace a live `whisper connect`'s
	// peer and kill its tunnel, so that is refused with the fix rather than done quietly.
	cxr, cancelr := ctx()
	_, live := findLiveSession(cxr, c, sel)
	cancelr()
	if live {
		return nil, usageErr("this agent is already connected by a running `whisper connect` on this host, and an " +
			"enforced agent needs a tunnel of its own. Name another agent with --agent (`whisper create <name>` " +
			"makes one), or stop that connect first")
	}

	logf := func(format string, args ...any) {
		if !g.quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	// From the connect on, a signal must not kill the CLI before it lets the /128 go: the peer it
	// asked the box for is exclusive, and would refuse the agent's next connect until the reaper.
	// Until the agent exists a signal ends the run through the same path as any other failure; the
	// connect itself is not cut short, so its outcome is always known.
	early := armEnforceSignals()
	early.notDone = o.interruptNote
	u.early, u.logf = early, logf

	base := enforcedConnectBase(sel)
	cx, cancel := ctx()
	// direct=false: the enforced device installs no direct peers, so this connect declares
	// nowhere to be dialed, and neither does any renewal of it.
	env, keys, err := connectTierEnvelope(cx, c, base, tierWireGuard, sel, false)
	cancel()
	if err != nil {
		return nil, err
	}
	// The run holds the /128 from here, and lets it go however it ends: close releases it
	// on a failure here, and the caller's deferred close() (or an explicit release before os.Exit)
	// afterwards. It stops the tunnel itself, after deciding through it whether the peer is still this run's.
	holdAddr := ""
	if a, perr := netip.ParseAddr(sel); perr == nil {
		holdAddr = a.String() // an answer that does not parse still leaves the named /128 to let go
	}
	hold := newEnforcedHold(c, base, keys, holdAddr, ctx, logf)
	hold.noteGrant(env.Result)
	u.hold = hold
	ce, err := parseConnectEnvelope(env.Result)
	if err != nil {
		return nil, err
	}
	hold.addr = ce.address
	if !hold.granted.Load() {
		logf("%s", notExclusiveNote(ce.address))
	}
	if err := early.interrupted(); err != nil {
		return nil, err
	}
	if !ce.isWireGuard() {
		return nil, &client.ProblemError{Status: 502, Detail: "the control plane did not return a WireGuard tunnel, so " + o.notDone}
	}
	if u.lock == nil {
		if a, perr := netip.ParseAddr(ce.address); perr == nil {
			if u.lock, err = enforce.LockExclusive(a); err != nil {
				return nil, usageErr("%s", err.Error())
			}
		}
	}
	var wgKey *wgtun.Keypair
	if keys != nil {
		wgKey = keys.wg
	}
	cfg, err := wireGuardConfig(ce, wgKey)
	if err != nil {
		return nil, err
	}
	resolvers := wgtun.DNSServers(ce.wgDNS, ce.wgQuick)
	if len(resolvers) == 0 {
		return nil, &client.ProblemError{Status: 502, Detail: "the control plane named no in-tunnel resolver, so there " +
			"would be no DNS; " + o.notDone}
	}
	prefix := cfg.NAT64Prefix
	if !prefix.IsValid() {
		prefix, _ = wgtun.NAT64Prefix()
	}
	// Renew registers THIS device's key for the same agent again, for a tunnel that was dead
	// long enough for the box to forget its peer. It is not a fresh connect: a fresh connect
	// mints a new WireGuard key, which the running device does not hold.
	// The periodic signed check-in a held session makes (checkIn) runs on the tunnel's own
	// goroutine, so it never overlaps the tunnel's renewal of a dead peer.
	tun, err := o.start(cfg, enforce.Policy{Resolvers: resolvers, NAT64: prefix},
		enforce.Options{Logf: logf, Renew: hold.renew, CheckInEvery: checkInEvery, Jitter: renewJitter})
	if err != nil {
		return nil, &client.ProblemError{Status: 502, Detail: strings.TrimPrefix(err.Error(), "enforce: ")}
	}
	u.tun = tun

	vcx, vcancel := context.WithTimeout(early.ctx, 45*time.Second)
	observed, verr := echoInsideRetry(vcx, tun.NS, "ip6")
	v4, v4err := echoInsideRetry(vcx, tun.NS, "ip4")
	vcancel()
	if err := early.interrupted(); err != nil {
		return nil, err
	}
	if verr != nil || !sameIP(observed, ce.address) {
		why := "the echo saw " + observed
		if verr != nil {
			why = verr.Error()
		}
		return nil, &client.ProblemError{Status: 502, Detail: "the tunnel came up but its egress did not verify as " +
			ce.address + " (" + why + "), so " + o.notDone}
	}
	u.label = firstNonBlank(displayName(env.Result), ce.address)
	u.v4note = "IPv4 leaves through Whisper's NAT64"
	if v4err == nil && v4 != "" {
		u.v4note += " as " + v4
	} else {
		u.v4note = "IPv4 through the tunnel did not answer, so IPv4 destinations will be refused (never leaked)"
	}
	u.c, u.ce, u.resolvers = c, ce, resolvers
	ok = true
	return u, nil

}

// enforceSignals holds INT, TERM, HUP and QUIT from the connect until the agent exists, so a signal
// in that time ends the run through its ordinary teardown instead of killing the CLI with the /128
// still held at the box. ctx is cancelled by the first one.
type enforceSignals struct {
	ch       chan os.Signal
	caught   atomic.Int32
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once
	// notDone is what an interruption says was not done; empty keeps the enforced run's wording.
	notDone string
}

func armEnforceSignals() *enforceSignals {
	s := &enforceSignals{ch: make(chan os.Signal, 1), done: make(chan struct{}), finished: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	signal.Notify(s.ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		defer close(s.finished)
		select {
		case sig := <-s.ch:
			s.note(sig)
		case <-s.done:
			select { // one that arrived as the handler went still counts
			case sig := <-s.ch:
				s.note(sig)
			default:
			}
		}
	}()
	return s
}

func (s *enforceSignals) note(sig os.Signal) {
	if ss, ok := sig.(syscall.Signal); ok {
		s.caught.Store(int32(ss))
	}
	s.cancel()
}

// stop lets the signals go and waits until what was caught is settled. Idempotent.
func (s *enforceSignals) stop() {
	s.stopOnce.Do(func() {
		signal.Stop(s.ch)
		close(s.done)
		<-s.finished
	})
}

// interrupted is the error a signal before the agent started ends the run with: exit status
// 128 plus the signal's number, as a shell reports a process the signal ended.
func (s *enforceSignals) interrupted() error {
	n := s.caught.Load()
	if n == 0 {
		return nil
	}
	sig := syscall.Signal(n)
	if s.notDone != "" {
		return &exitCodeError{code: 128 + int(n), msg: "interrupted (" + sig.String() + ") before it was done, so " + s.notDone}
	}
	return &exitCodeError{code: 128 + int(n), msg: "interrupted (" + sig.String() + ") before the agent started, so it was not started"}
}

// forwardSignals passes each signal on fwd to the agent's init until it has been reaped.
func forwardSignals(fwd <-chan os.Signal, reaped <-chan struct{}, pid int) {
	for {
		select {
		case <-reaped:
			return
		case sig := <-fwd:
			select {
			case <-reaped:
				return
			default:
			}
			if ss, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(pid, ss)
			}
		}
	}
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// echoInsideRetry is echoInside with up to three attempts inside ctx. The first request
// through a tunnel whose handshake has just landed can lose a packet like any other, and a lost
// SYN costs a whole dial timeout; one miss must not cost the user a refused start.
func echoInsideRetry(ctx context.Context, ns *enforce.Namespace, family string) (string, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		ip, err := echoInside(ctx, ns, family)
		if err == nil {
			return ip, nil
		}
		last = err
		select {
		case <-ctx.Done():
			return "", last
		case <-time.After(time.Second):
		}
	}
	return "", last
}

// echoInside asks the keyless echo, from inside the namespace, which source address it saw.
// The echo's name is resolved on the host (the namespace's resolver is the tunnel's, and this
// is the CLI's own lookup, not the agent's); the connection itself is opened inside.
func echoInside(ctx context.Context, ns *enforce.Namespace, family string) (string, error) {
	echo := g.echoURL
	if echo == "" {
		echo = client.DefaultEchoURL
	}
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, family, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("no %s address for the echo", family)
		}
		var last error
		for _, ip := range ips {
			c, derr := ns.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
			if derr == nil {
				return c, nil
			}
			last = derr
		}
		return nil, last
	}
	hc := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{
		DialContext:       dial,
		TLSClientConfig:   &tls.Config{RootCAs: client.RootCAs(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		Proxy:             nil,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echo, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		var ne net.Error
		why := "no answer"
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			why = "timed out"
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
			why = "refused inside the namespace"
		}
		return "", errors.New("the echo could not be reached from inside the namespace: " + why)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var r struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &r) == nil && r.IP != "" {
		return r.IP, nil
	}
	return strings.TrimSpace(string(body)), nil
}
