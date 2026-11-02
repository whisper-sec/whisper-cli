// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// --- parsing ---------------------------------------------------------------------------

func TestParseAcceptRulesTakesThePortAndTheMappingsPeopleType(t *testing.T) {
	cases := map[string]string{
		"22":                 "22 -> 127.0.0.1:22",
		":22":                "22 -> 127.0.0.1:22",
		"2222=22":            "2222 -> 127.0.0.1:22",
		"2222=127.0.0.1:22":  "2222 -> 127.0.0.1:22",
		"2222=[::1]:22":      "2222 -> [::1]:22",
		"2222=localhost:22":  "2222 -> 127.0.0.1:22",
		" 8022 = :22 ":       "8022 -> 127.0.0.1:22",
		"2222=127.0.0.53:22": "2222 -> 127.0.0.53:22",
	}
	for in, want := range cases {
		rules, err := parseAcceptRules([]string{in})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if len(rules) != 1 || rules[0].String() != want {
			t.Errorf("%q = %v, want %s", in, rules, want)
		}
	}
	// Repeated and comma-joined are the same request.
	rules, err := parseAcceptRules([]string{"22,2222=22", "8080"})
	if err != nil || len(rules) != 3 {
		t.Fatalf("repeatable/comma forms: %v %v", rules, err)
	}
}

func TestParseAcceptRulesRefusesWhatItCannotHonour(t *testing.T) {
	for in, why := range map[string]string{
		"0":                     "not a TCP port",
		"70000":                 "not a TCP port",
		"ssh":                   "not a TCP port",
		"443":                   "identity listener",
		"2222=10.0.0.5:22":      "service on this host",
		"2222=db.internal:22":   "service on this host",
		"2222=[2001:db8::1]:22": "service on this host",
		"2222=127.0.0.1:":       "no port given",
		"2222=[::1":             "not host:port",
	} {
		_, err := parseAcceptRules([]string{in})
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: err = %v, want one saying %q", in, err, why)
		}
	}
	if _, err := parseAcceptRules([]string{"22", "22=127.0.0.1:2222"}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a port named twice was accepted: %v", err)
	}
}

func TestAcceptFromAndPublicNeedAnAccept(t *testing.T) {
	if _, err := buildAcceptRequest(nil, []string{"2a04:2a01::/32"}, false); err == nil {
		t.Error("--accept-from with no --accept was accepted")
	}
	if _, err := buildAcceptRequest(nil, nil, true); err == nil {
		t.Error("--accept-public with no --accept was accepted")
	}
	if r, err := buildAcceptRequest(nil, nil, false); r != nil || err != nil {
		t.Errorf("no accept at all must be nothing: %v %v", r, err)
	}
	// A prefix wide enough to be the internet in all but name has to go through the consent
	// --accept-public asks for, not around it.
	for _, wide := range []string{"::/0", "2000::/3", "2a04::/16", "0.0.0.0/0", "10.0.0.0/8"} {
		if _, err := buildAcceptRequest([]string{"22"}, []string{wide}, false); err == nil ||
			!strings.Contains(err.Error(), "--accept-public") {
			t.Errorf("--accept-from %s: %v", wide, err)
		}
	}
	if _, err := buildAcceptRequest([]string{"22"}, []string{"2a04:2a01::/32", "192.0.2.0/24"}, false); err != nil {
		t.Errorf("an ordinary prefix was refused: %v", err)
	}
	if _, err := buildAcceptRequest([]string{"22"}, []string{"db.internal"}, false); err == nil ||
		!strings.Contains(err.Error(), "--accept-from") {
		t.Errorf("a name in --accept-from: %v", err)
	}
}

// A hand edit that sets "public": true without the consent the install records must not open
// a port to the internet.
func TestAConfigWithoutRecordedConsentAdmitsOnlyTheFleet(t *testing.T) {
	var said []string
	logf := func(f string, a ...any) { said = append(said, f) }
	r, err := acceptRequestFromConfig(&projcfg.AcceptConfig{Ports: []string{"22"}, Public: true}, logf)
	if err != nil || r == nil {
		t.Fatalf("%v %v", r, err)
	}
	if r.scope() != whale.ScopeFleet {
		t.Fatalf("scope = %s, want fleet", r.scope())
	}
	if len(said) == 0 || !strings.Contains(said[0], "no consent") {
		t.Fatalf("the downgrade was not said: %q", said)
	}
	// A consent is a moment, not any string at all.
	r, _ = acceptRequestFromConfig(&projcfg.AcceptConfig{Ports: []string{"22"}, Public: true, PublicConsentedAt: "yes"}, nil)
	if r.scope() != whale.ScopeFleet {
		t.Fatal("a consent that is not a timestamp opened the port to the internet")
	}
	// The same width rule holds for a hand-edited config.
	if _, err := acceptRequestFromConfig(&projcfg.AcceptConfig{Ports: []string{"22"}, From: []string{"::/0"}}, nil); err == nil {
		t.Fatal("a config admitting ::/0 through accept.from was taken")
	}
	r, _ = acceptRequestFromConfig(&projcfg.AcceptConfig{Ports: []string{"22"}, Public: true, PublicConsentedAt: "2026-10-27T23:00:00Z"}, nil)
	if r.scope() != whale.ScopeInternet {
		t.Fatalf("recorded consent: scope = %s, want internet", r.scope())
	}
	if r, _ := acceptRequestFromConfig(nil, nil); r != nil {
		t.Fatal("no section must be no accept")
	}
}

// --- who may connect -------------------------------------------------------------------

func stubAcceptFleet(t *testing.T, members []string, err error) {
	t.Helper()
	saved := acceptFleetRefresh
	acceptFleetRefresh = func(_ context.Context, g *fleetGate, _ *client.Client) error {
		if err != nil {
			return err
		}
		next := map[netip.Addr]bool{}
		for _, m := range members {
			next[netip.MustParseAddr(m)] = true
		}
		g.mu.Lock()
		g.members = next
		g.mu.Unlock()
		return nil
	}
	t.Cleanup(func() { acceptFleetRefresh = saved })
}

func newTestAcceptPlan(t *testing.T, req *acceptRequest, logf func(string, ...any)) *acceptPlan {
	t.Helper()
	savedEvery := whaleServeFleetRefresh
	whaleServeFleetRefresh = time.Hour
	t.Cleanup(func() { whaleServeFleetRefresh = savedEvery })
	p := newAcceptPlan(context.Background(), nil, req, logf)
	t.Cleanup(p.close)
	return p
}

// The access decision is the fleet's: a /128 in it is admitted, one outside it is refused, and
// --accept-from widens it by exactly what it names.
func TestAcceptAdmitsTheFleetAndRefusesAStranger(t *testing.T) {
	stubAcceptFleet(t, []string{"2a04:2a01:9::f1"}, nil)
	req, err := buildAcceptRequest([]string{"22"}, []string{"2001:db8:5::/48"}, false)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestAcceptPlan(t, req, nil)
	for addr, want := range map[string]bool{
		"2a04:2a01:9::f1":   true,  // fleet
		"2a04:2a01:9::e1":   false, // a Whisper /128 that is not ours
		"2001:db8:77::6d86": false, // the internet
		"2001:db8:5::9":     true,  // --accept-from
		"::ffff:192.0.2.1":  false,
	} {
		if got := p.permit(netip.MustParseAddr(addr)); got != want {
			t.Errorf("permit(%s) = %v, want %v", addr, got, want)
		}
	}
	if p.permit(netip.Addr{}) {
		t.Error("an address the network did not give is admitted")
	}
}

// A fleet that cannot be read admits NOBODY, and says so: the connection still comes up, the
// ports do not answer strangers while the control plane is away.
func TestAnUnreadableFleetAdmitsNobody(t *testing.T) {
	stubAcceptFleet(t, nil, errors.New("control plane unreachable"))
	var said []string
	req, _ := buildAcceptRequest([]string{"22"}, nil, false)
	p := newTestAcceptPlan(t, req, func(f string, a ...any) { said = append(said, f) })
	if p.permit(netip.MustParseAddr("2a04:2a01:9::f1")) {
		t.Fatal("an unknown fleet admitted a caller")
	}
	if len(said) == 0 || !strings.Contains(said[0], "admit no one") {
		t.Fatalf("the fail-closed start was not said: %q", said)
	}
}

func TestPublicAcceptAdmitsAnyRealAddress(t *testing.T) {
	// The fleet does not decide admission here, so a fleet that cannot be read changes nothing.
	stubAcceptFleet(t, nil, errors.New("control plane unreachable"))
	req, _ := buildAcceptRequest([]string{"22"}, nil, true)
	p := newTestAcceptPlan(t, req, nil)
	if !p.permit(netip.MustParseAddr("2001:db8:77::1")) {
		t.Fatal("public accept refused an internet caller")
	}
	if p.permit(netip.Addr{}) {
		t.Fatal("public accept admitted an invalid address")
	}
	var nilPlan *acceptPlan
	if nilPlan.permit(netip.MustParseAddr("2001:db8:77::1")) {
		t.Fatal("a nil plan admitted a caller")
	}
}

func TestPublicAcceptAsksAndNothingIsOpenedWithoutYes(t *testing.T) {
	req, _ := buildAcceptRequest([]string{"22"}, nil, true)
	r, w, _ := os.Pipe()
	w.Close() // an empty stdin: nobody typed yes
	saved := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = saved }()
	var err error
	out, _ := captureStd(t, func() { err = confirmAcceptPublic(req, false) })
	if err == nil {
		t.Fatal("public accept went ahead without a yes")
	}
	if !strings.Contains(out, "WHOLE INTERNET") {
		t.Fatalf("the question did not say what it opens: %q", out)
	}
	if err := confirmAcceptPublic(req, true); err != nil {
		t.Fatalf("--yes was not honoured: %v", err)
	}
	fleet, _ := buildAcceptRequest([]string{"22"}, nil, false)
	if err := confirmAcceptPublic(fleet, false); err != nil {
		t.Fatalf("a fleet accept asked for consent: %v", err)
	}
}

// --- bring-up, record, status ------------------------------------------------------------

func TestThePlanOpensItsRulesAndRecordsThem(t *testing.T) {
	stubAcceptFleet(t, []string{"2a04:2a01::7"}, nil)
	var gotRules []wgtun.AcceptRule
	var gotPermit func(netip.Addr) bool
	saved := acceptOpener
	acceptOpener = func(_ *wgtun.Tunnel, rules []wgtun.AcceptRule, o wgtun.AcceptOptions) error {
		gotRules, gotPermit = rules, o.Permit
		if o.OnCarry == nil {
			t.Error("the opener was not given the caller recorder")
		}
		if o.Individual == nil {
			t.Error("the opener was not told which callers are fleet members")
		}
		return nil
	}
	t.Cleanup(func() { acceptOpener = saved })
	req, _ := buildAcceptRequest([]string{"22", "2222=22"}, nil, false)
	var said []string
	p := newTestAcceptPlan(t, req, func(f string, a ...any) { said = append(said, f) })
	recs, scope := p.open(&wgtun.Tunnel{})
	if scope != "fleet" || len(recs) != 2 || recs[1].Port != 2222 || recs[1].Target != "127.0.0.1:22" {
		t.Fatalf("records = %v %q", recs, scope)
	}
	if !p.member(netip.MustParseAddr("2a04:2a01::7")) || p.member(netip.MustParseAddr("2a04:2a01::8")) {
		t.Fatal("fleet membership for the limits disagrees with the fleet")
	}
	if len(gotRules) != 2 || gotPermit == nil || !gotPermit(netip.MustParseAddr("2a04:2a01::7")) {
		t.Fatalf("the tunnel was not given the plan's rules and decision: %v", gotRules)
	}
	if len(said) == 0 || !strings.Contains(said[len(said)-1], "accepting") {
		t.Fatalf("the open was not announced: %q", said)
	}
}

// A port that cannot be opened costs the accept, never the connection.
func TestAFailedOpenRecordsNothing(t *testing.T) {
	stubAcceptFleet(t, nil, nil)
	saved := acceptOpener
	acceptOpener = func(*wgtun.Tunnel, []wgtun.AcceptRule, wgtun.AcceptOptions) error {
		return errors.New("could not open port 22")
	}
	t.Cleanup(func() { acceptOpener = saved })
	req, _ := buildAcceptRequest([]string{"22"}, nil, false)
	var said []string
	p := newTestAcceptPlan(t, req, func(f string, a ...any) { said = append(said, f) })
	if recs, _ := p.open(&wgtun.Tunnel{}); recs != nil {
		t.Fatalf("a failed open recorded %v", recs)
	}
	if len(said) == 0 || !strings.Contains(said[len(said)-1], "unaffected") {
		t.Fatalf("the failure was not said: %q", said)
	}
}

func TestInstallAcceptPlanIsProcessWideAndRemovable(t *testing.T) {
	stubAcceptFleet(t, nil, nil)
	req, _ := buildAcceptRequest([]string{"22"}, nil, false)
	p := newTestAcceptPlan(t, req, nil)
	remove := installAcceptPlan(p)
	if currentAcceptPlan() != p {
		t.Fatal("the plan was not installed")
	}
	remove()
	if currentAcceptPlan() != nil {
		t.Fatal("the plan survived its removal")
	}
}

// The record is how `whale status` in another shell learns this host answers on a port.
func TestTheSessionRecordCarriesTheAcceptedPortsAndStatusShowsThem(t *testing.T) {
	dir := t.TempDir()
	savedDir, savedMachine := sessionsDirFn, machineSessionsDirFn
	sessionsDirFn = func() string { return dir }
	machineSessionsDirFn = func() string { return "" }
	t.Cleanup(func() { sessionsDirFn, machineSessionsDirFn = savedDir, savedMachine })
	sess := &egressSession{endpoint: "socks5h://127.0.0.1:18080", addr: "2a04:2a01::22", tier: "wireguard",
		local: stubLocal{}, accepts: []acceptRecord{{Port: 22, Target: "127.0.0.1:22"}}, acceptScope: "internet"}
	writeSessionRecord(sess)
	recs := readSessionRecords()
	if len(recs) != 1 || len(recs[0].Accept) != 1 || recs[0].AcceptScope != "internet" {
		t.Fatalf("records = %+v", recs)
	}
	rows := whaleAccepting([]statusSession{{Address: recs[0].Addr, Accept: recs[0].Accept, AcceptScope: recs[0].AcceptScope}})
	if len(rows) != 1 || rows[0].Scope != "internet" || rows[0].Port != 22 {
		t.Fatalf("rows = %+v", rows)
	}
	stdout, stderr := captureStd(t, func() { renderWhaleAccepting(rows) })
	out := stdout + stderr
	for _, must := range []string{"ACCEPTING", "127.0.0.1:22", "THE INTERNET (public)", "2a04:2a01::22", "admits THE INTERNET"} {
		if !strings.Contains(out, must) {
			t.Errorf("status is missing %q:\n%s", must, out)
		}
	}
	// A hand-edited unknown scope never renders as the permissive one.
	rows = whaleAccepting([]statusSession{{Accept: recs[0].Accept, AcceptScope: "everyone"}})
	if rows[0].Scope != "fleet" {
		t.Fatalf("an unknown scope rendered as %q", rows[0].Scope)
	}
}

// stubLocal is a localEndpoint that does nothing, so a session can be recorded with no proxy.
type stubLocal struct{}

func (stubLocal) Endpoint() string { return "socks5h://127.0.0.1:18080" }
func (stubLocal) Addr() string     { return "127.0.0.1:18080" }
func (stubLocal) Stop()            {}

// --- command surfaces ------------------------------------------------------------------

func TestConnectAcceptRefusesAnEgressTierAndEnsure(t *testing.T) {
	for _, args := range [][]string{
		{"connect", "--accept", "22", "--tier", "socks5"},
		{"connect", "--accept", "22", "--ensure"},
		{"connect", "--accept", "443"},
		{"connect", "--accept-public"},
	} {
		root := NewRootCommand()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetArgs(append([]string{"--key", "whisper_live_test", "--control-url", "http://127.0.0.1:1"}, args...))
		var err error
		captureStd(t, func() { err = root.Execute() })
		if err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}

func TestDaemonAcceptNeedsTheRoutedTier(t *testing.T) {
	var said []string
	saved := daemonLogf
	daemonLogf = func(f string, a ...any) { said = append(said, f) }
	t.Cleanup(func() { daemonLogf = saved })
	cfg := projcfg.Config{Tier: "socks5", Accept: &projcfg.AcceptConfig{Ports: []string{"22"}}}
	if remove := daemonAcceptPlan(nil, cfg, "socks5"); remove != nil {
		remove()
		t.Fatal("a socks5 daemon installed an accept plan")
	}
	if len(said) == 0 || !strings.Contains(said[0], "only the routed") {
		t.Fatalf("the refusal was not said: %q", said)
	}
	cfg.Accept.Ports = []string{"bogus"}
	if remove := daemonAcceptPlan(nil, cfg, "wireguard"); remove != nil {
		remove()
		t.Fatal("a broken accept section was installed")
	}
}

// --- the real caller -------------------------------------------------------------------

func TestTheCallerOfAnAcceptedConnectionCanBeAskedFor(t *testing.T) {
	machine, user := t.TempDir(), t.TempDir()
	savedDir, savedMachine, savedAlive := sessionsDirFn, machineSessionsDirFn, holderAlive
	sessionsDirFn = func() string { return user }
	machineSessionsDirFn = func() string { return machine }
	holderAlive = func(int) bool { return true }
	t.Cleanup(func() { sessionsDirFn, machineSessionsDirFn, holderAlive = savedDir, savedMachine, savedAlive })

	caller := netip.MustParseAddr("2a04:2a01:9::e1")
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53906}
	end := recordAcceptCaller(wgtun.AcceptRule{Port: 22, Target: "127.0.0.1:22"}, caller, local)
	if end == nil {
		t.Fatal("no record was written")
	}
	entries, _ := os.ReadDir(filepath.Join(machine, acceptCallersDir))
	if len(entries) != 1 {
		t.Fatalf("records = %v", entries)
	}
	if fi, _ := entries[0].Info(); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Fatalf("the machine-wide record must be readable by sshd's command user: %v", fi.Mode())
	}
	ask := func(args ...string) (acceptCallerRecord, bool) {
		t.Helper()
		q, err := parseCallerQuery(args)
		if err != nil {
			t.Fatalf("parseCallerQuery(%q): %v", args, err)
		}
		return lookupAcceptCaller(q)
	}
	for _, args := range [][]string{
		{"127.0.0.1", "53906", "127.0.0.1", "22"}, // $SSH_CONNECTION, and %C as sshd_config(5) orders it
		{"127.0.0.1 22 127.0.0.1 53906"},          // %C as OpenSSH 9.9 expands it, one argument
		{"127.0.0.1 53906 22"},                    // $SSH_CLIENT
		{"127.0.0.1:53906"},
		{"127.0.0.1", "53906"},
	} {
		rec, ok := ask(args...)
		if !ok || rec.Caller != caller.String() || rec.Port != 22 {
			t.Fatalf("lookup(%q) = %+v %v", args, rec, ok)
		}
	}
	// The address is part of the key: a local user on 127.0.0.2 with the same port number, or
	// a connection to another service, is not the fleet caller.
	if _, ok := ask("127.0.0.2", "53906", "127.0.0.1", "22"); ok {
		t.Fatal("a different loopback address borrowed the caller")
	}
	if _, ok := ask("127.0.0.1", "53906", "127.0.0.1", "80"); ok {
		t.Fatal("a connection to another service borrowed the caller")
	}
	// A bare port names no address and is refused outright.
	if _, err := parseCallerQuery([]string{"53906"}); err == nil {
		t.Fatal("a bare port was accepted")
	}
	// The same loopback port to two services: the client half alone is ambiguous and answers
	// nothing; the full four-tuple still finds each one.
	end2 := recordAcceptCaller(wgtun.AcceptRule{Port: 8022, Target: "127.0.0.1:8022"},
		netip.MustParseAddr("2a04:2a01::99"), local)
	if _, ok := ask("127.0.0.1:53906"); ok {
		t.Fatal("an ambiguous client half picked one of two services")
	}
	if rec, ok := ask("127.0.0.1", "53906", "127.0.0.1", "8022"); !ok || rec.Caller != "2a04:2a01::99" {
		t.Fatalf("the second service = %+v %v", rec, ok)
	}
	end2()
	// A record whose holder is gone is not an answer.
	holderAlive = func(int) bool { return false }
	if _, ok := ask("127.0.0.1", "53906", "127.0.0.1", "22"); ok {
		t.Fatal("a dead holder's record was believed")
	}
	holderAlive = func(int) bool { return true }
	end()
	if _, ok := ask("127.0.0.1", "53906", "127.0.0.1", "22"); ok {
		t.Fatal("the record outlived its connection")
	}
}

// A fleet refresh reaches the connections already open: the plan asks every tunnel it opened
// ports on to revalidate, and a revoked caller is closed.
func TestAFleetRefreshRevalidatesOpenConnections(t *testing.T) {
	stubAcceptFleet(t, []string{"127.0.0.1"}, nil)
	req, _ := buildAcceptRequest([]string{"22"}, nil, false)
	p := newTestAcceptPlan(t, req, nil)
	if p.gate.onRefresh == nil {
		t.Fatal("the plan did not hook the fleet refresh")
	}
	tun := &wgtun.Tunnel{}
	p.track(tun)
	p.gate.mu.Lock()
	p.gate.members = map[netip.Addr]bool{}
	p.gate.mu.Unlock()
	p.revalidate() // no accept on this tunnel: nothing to close, and it must not panic
}

// The status line names the extra prefixes, so "your fleet only" is never said of a port that
// also admits a named network.
func TestStatusNamesTheExtraPrefixes(t *testing.T) {
	rows := whaleAccepting([]statusSession{{Address: "2a04:2a01::22", Accept: []acceptRecord{{Port: 22, Target: "127.0.0.1:22"}},
		AcceptScope: "fleet", AcceptFrom: []string{"2001:db8:5::/48"}}})
	stdout, stderr := captureStd(t, func() { renderWhaleAccepting(rows) })
	if !strings.Contains(stdout+stderr, "your fleet only and 2001:db8:5::/48") {
		t.Fatalf("status = %s", stdout+stderr)
	}
}

// With the internet admitted, the fleet is still read, because it is what counts a member as
// one agent instead of pooling a whole fleet under its owner's /64.
func TestPublicAcceptStillKnowsTheFleetForTheLimits(t *testing.T) {
	stubAcceptFleet(t, []string{"2a04:2a01:1:2::7"}, nil)
	req, _ := buildAcceptRequest([]string{"22"}, nil, true)
	p := newTestAcceptPlan(t, req, nil)
	if !p.member(netip.MustParseAddr("2a04:2a01:1:2::7")) {
		t.Fatal("a public plan does not know its fleet, so the limits pool the fleet again")
	}
}
