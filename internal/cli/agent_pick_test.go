// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// `whisper run` with an owner key and nothing named took over an existing agent of the
// account, a different one per tier, and replaced its WireGuard peer; it also ignored --create and
// --name. These drive the real commands through the root (so the global flags parse exactly as a
// person types them) against a fake control plane, and pin the rule in agent_pick.go.

const (
	pickDemo    = "2a04:2a01:9::de"   // a long-lived agent nobody in these tests names
	pickFixture = "2a04:2a01:9::f1"   // a test fixture
	pickMinted  = "2a04:2a01:9::2165" // what op:register mints
	pickOwnAddr = "2a04:2a01:9::1d"   // what op:identity answers on an empty account
	pickHost    = "box-under-test"    // this host's name
)

var pickFleet = []agentChoice{{name: "demo", addr: pickDemo}, {name: "fixture", addr: pickFixture}}

// pickPlane is the fake control plane. op:list answers agents; op:register mints pickMinted (or
// answers registerReply when set); op:identity answers pickOwnAddr; op:connect answers for the
// /128 it was asked for, on the tier it was asked for.
type pickPlane struct {
	mu            sync.Mutex
	calls         []recordedCall
	agents        []agentChoice
	registerReply string
	// otherHandles is agent_tenants in the caller's own activityTenants row: how many handles
	// other than the key's own its agents file under. -1 leaves the field out.
	otherHandles int
}

var connectAgentRE = regexp.MustCompile(`agent:'([^']*)'`)

func (p *pickPlane) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := sniffOp(body)
		p.mu.Lock()
		p.calls = append(p.calls, recordedCall{op: op, body: body})
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch op {
		case "register":
			if p.registerReply != "" {
				_, _ = w.Write([]byte(p.registerReply))
				return
			}
			label := "minted"
			if m := regexp.MustCompile(`label:'([^']*)'`).FindStringSubmatch(body); m != nil {
				label = m[1]
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","address","label","api_key","fqdn"],"rows":[["ag_2165","` +
				pickMinted + `","` + label + `","whisper_live_shownonce","x.agents.whisper.online."]]}}`))
		case "identity":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["label","address","fqdn"],"rows":[["own","` +
				pickOwnAddr + `","own.agents.whisper.online."]]}}`))
		case "connect":
			addr := "2a04:2a01:9::bad" // a connect that named nobody: the control plane would pick
			if m := connectAgentRE.FindStringSubmatch(body); m != nil {
				addr = m[1]
			}
			if strings.Contains(body, "tier:'wireguard'") {
				_, _ = w.Write([]byte(strings.ReplaceAll(wgConnectReplyJSON(), "2a04:2a01:9::abcd", addr)))
				return
			}
			_, _ = w.Write([]byte(strings.ReplaceAll(s5ConnectReplyJSON(), "2a04:2a01:9::abcd", addr)))
		default:
			if strings.Contains(body, "activityTenants") {
				extra := ""
				if p.otherHandles >= 0 {
					extra = `,"agent_tenants":` + itoa(p.otherHandles)
				}
				_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["activityTenants",` +
					`{"tenant":"tself","agents":1,"self":true` + extra + `}]]}}`))
				return
			}
			_, _ = w.Write([]byte(listJSON(p.agents)))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (p *pickPlane) ops() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return opsSeen(p.calls)
}

func (p *pickPlane) bodies(op string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, c := range p.calls {
		if c.op == op {
			out = append(out, c.body)
		}
	}
	return out
}

// pickHarness isolates everything a selection reads: home, the session registry, the identity
// store, the host name, the egress tail, and the globals the root's flags write.
func pickHarness(t *testing.T) {
	t.Helper()
	stubSessionsDir(t) // HermeticHome too
	savedM := machineSessionsDirFn
	machineSessionsDirFn = func() string { return "" }
	t.Cleanup(func() { machineSessionsDirFn = savedM })
	t.Cleanup(idkey.SetIdentityDirForTest(t.TempDir()))
	savedHost := osHostname
	osHostname = func() (string, error) { return pickHost + ".local", nil }
	t.Cleanup(func() { osHostname = savedHost })
	t.Cleanup(stubTierAwareTail(t, nil, false))
	t.Cleanup(stubWgBringUp(t, nil))
	savedG := g
	t.Cleanup(func() { g = savedG })
	t.Chdir(t.TempDir()) // no project config above the test
}

// runRoot runs `whisper <args>` through the real root command.
func runRoot(t *testing.T, url string, args ...string) (stderr string, err error) {
	t.Helper()
	g = globalFlags{}
	root := NewRootCommand()
	root.SetArgs(append([]string{"--key", "whisper_live_test", "--control-url", url}, args...))
	_, stderr = captureStd(t, func() { err = root.Execute() })
	return stderr, err
}

// mustNotTouch fails when any op:connect named an agent of the fleet nobody named.
func mustNotTouch(t *testing.T, p *pickPlane, addrs ...string) {
	t.Helper()
	for _, b := range p.bodies("connect") {
		for _, a := range addrs {
			if strings.Contains(b, "'"+a+"'") {
				t.Fatalf("an agent nobody named was connected (%s): %s", a, b)
			}
		}
		if !connectAgentRE.MatchString(b) {
			t.Fatalf("op:connect named no agent, so the control plane would have picked one: %s", b)
		}
	}
}

func TestRunWithNothingNamedCreatesAnAgentForThisHostOnEveryTier(t *testing.T) {
	for _, tier := range []string{"socks5", "wireguard", "auto"} {
		t.Run(tier, func(t *testing.T) {
			pickHarness(t)
			p := &pickPlane{agents: pickFleet}
			srv := p.serve(t)
			af := filepath.Join(t.TempDir(), "agent")
			stderr, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", tier, "--", "true")
			if err != nil {
				t.Fatalf("run: %v\n%s", err, stderr)
			}
			mustNotTouch(t, p, pickDemo, pickFixture)
			reg := p.bodies("register")
			if len(reg) != 1 || !strings.Contains(reg[0], "label:'"+pickHost+"'") {
				t.Fatalf("one agent named after this host is registered, got %v", reg)
			}
			if len(p.bodies("identity")) != 0 {
				t.Fatalf("op:identity hands back an existing agent on this account and must not run: %v", p.ops())
			}
			if c := p.bodies("connect"); len(c) == 0 || !strings.Contains(c[0], pickMinted) {
				t.Fatalf("the created agent is the one connected: %v", c)
			}
			if got := client.ReadAgentFile(af); got != pickMinted {
				t.Fatalf("the created agent is saved for this host's next run, got %q", got)
			}
			for _, want := range []string{"created agent " + pickHost, "2 other agents were left alone"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("the run says what it did (%q): %s", want, stderr)
				}
			}
			if strings.Contains(stderr, "whisper_live_shownonce") {
				t.Fatalf("the minted agent's key must never be printed: %s", stderr)
			}
		})
	}
}

func TestRunUsesThisHostsSavedAgentAndMintsNothing(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: append([]agentChoice{{name: "mine", addr: "2a04:2a01:9::111"}}, pickFleet...)}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::111"); err != nil {
		t.Fatal(err)
	}
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	mustNotTouch(t, p, pickDemo, pickFixture)
	mustNotMint(t, p.ops())
	if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "'2a04:2a01:9::111'") {
		t.Fatalf("the saved agent is connected: %v", c)
	}
	if strings.Contains(stderr, "replaces the one any other host holds") {
		t.Fatalf("this host's own saved agent is not announced as a takeover: %s", stderr)
	}
}

func TestRunNameSelectsAnExistingAgentAndSaysItReplacesItsPeer(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	stderr, err := runRoot(t, srv.URL, "run", "--name", "demo", "--agent-file", af, "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run --name demo: %v\n%s", err, stderr)
	}
	mustNotMint(t, p.ops())
	if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "'"+pickDemo+"'") {
		t.Fatalf("--name demo connects demo: %v", c)
	}
	if !strings.Contains(stderr, "demo ("+pickDemo+")") || !strings.Contains(stderr, "replaces the one any other host holds") {
		t.Fatalf("a WireGuard bind of a named existing agent says what it replaces: %s", stderr)
	}
	if client.ReadAgentFile(af) != "" {
		t.Fatalf("selecting an agent by name does not change this host's saved agent")
	}
}

func TestRunCreateMakesTheNamedAgent(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, pickDemo); err != nil { // even with a saved agent, --create makes one
		t.Fatal(err)
	}
	stderr, err := runRoot(t, srv.URL, "run", "--create", "--name", "new-agent", "--agent-file", af, "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run --create: %v\n%s", err, stderr)
	}
	if reg := p.bodies("register"); len(reg) != 1 || !strings.Contains(reg[0], "label:'new-agent'") {
		t.Fatalf("--create --name registers that agent: %v", p.ops())
	}
	mustNotTouch(t, p, pickDemo, pickFixture)
	if client.ReadAgentFile(af) != pickDemo {
		t.Fatalf("a host's saved agent is not replaced by a --create")
	}
	if !strings.Contains(stderr, "whisper use new-agent") {
		t.Fatalf("the run says how to make the new agent this host's default: %s", stderr)
	}
}

func TestRunCreateRefusesANameTheAccountHasAndConnectsNothing(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--create", "--name", "demo", "--agent-file", filepath.Join(t.TempDir(), "a"), "--", "true")
	if err == nil || !strings.Contains(err.Error(), "already has one called demo") {
		t.Fatalf("--create on a taken name is refused, got %v", err)
	}
	for _, bad := range []string{"register", "identity", "connect"} {
		if containsOp(p.ops(), bad) {
			t.Fatalf("op:%s ran for a refused create: %v", bad, p.ops())
		}
	}
}

func TestRunCreateAndAgentTogetherIsAUsageError(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--create", "--name", "x", "--agent", "demo", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "pass one of them") {
		t.Fatalf("--create with --agent is refused, got %v", err)
	}
	if len(p.ops()) != 0 {
		t.Fatalf("nothing reaches the control plane: %v", p.ops())
	}
}

func TestRunNameNamingNoAgentCreatesItWhenNothingIsSaved(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if _, err := runRoot(t, srv.URL, "run", "--name", "fresh", "--agent-file", af, "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run --name fresh: %v", err)
	}
	if reg := p.bodies("register"); len(reg) != 1 || !strings.Contains(reg[0], "label:'fresh'") {
		t.Fatalf("--name naming no agent creates it: %v", p.ops())
	}
	mustNotTouch(t, p, pickDemo, pickFixture)
}

func TestRunNameNamingNoAgentKeepsTheSavedAgentAndSaysSo(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: append([]agentChoice{{name: "mine", addr: "2a04:2a01:9::111"}}, pickFleet...)}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::111"); err != nil {
		t.Fatal(err)
	}
	stderr, err := runRoot(t, srv.URL, "run", "--name", "box-1", "--agent-file", af, "--tier", "socks5", "--", "true")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	mustNotMint(t, p.ops())
	if !strings.Contains(stderr, "no agent is called box-1, so using mine") {
		t.Fatalf("the unused --name is not silent: %s", stderr)
	}
}

func TestRunRefusesToAdoptAnAgentThatOnlySharesThisHostsName(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: append([]agentChoice{{name: pickHost, addr: "2a04:2a01:9::40"}}, pickFleet...)}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "wireguard", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "--agent "+pickHost) {
		t.Fatalf("an agent carrying this host's name is not adopted unasked, got %v", err)
	}
	for _, bad := range []string{"register", "identity", "connect"} {
		if containsOp(p.ops(), bad) {
			t.Fatalf("op:%s ran: %v", bad, p.ops())
		}
	}
}

func TestRunOnAKeyThatCannotRegisterRefusesAndNeverFallsBackToIdentity(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet,
		registerReply: `{"ok":false,"status":403,"error":"FORBIDDEN_SCOPE","detail":"Missing required scope: admin:dns"}`}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "wireguard", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "cannot create an agent") || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("a key that may not register is told how to name an agent, got %v", err)
	}
	if containsOp(p.ops(), "identity") || containsOp(p.ops(), "connect") {
		t.Fatalf("no op:identity fallback (it hands back an existing agent) and no connect: %v", p.ops())
	}
}

func TestRunOnAnEmptyAccountCreatesThroughIdentity(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{}
	srv := p.serve(t)
	if _, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if id := p.bodies("identity"); len(id) != 1 || !strings.Contains(id[0], "label:'"+pickHost+"'") || containsOp(p.ops(), "register") {
		t.Fatalf("an empty account's first agent is this key's own identity: %v", p.ops())
	}
}

func TestRunAListingThatDidNotAnswerMintsNothing(t *testing.T) {
	pickHarness(t)
	for _, f := range listingFailures() {
		t.Run(f.name, func(t *testing.T) {
			ops := failingListing(t, f)
			url := g.controlURL
			_, err := runRoot(t, url, "--timeout", "400ms", "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--", "true")
			if err == nil {
				t.Fatalf("a run that could not read the account must stop")
			}
			mustNotMint(t, ops(), "connect")
		})
	}
}

func TestIPWithNothingNamedRefusesRatherThanVerifyingSomeoneElsesAgent(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "ip", "--agent-file", filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.Contains(err.Error(), "demo") || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("ip names the fix and the agents, got %v", err)
	}
	mustNotMint(t, p.ops(), "connect")
}

func TestConnectHonoursTheGlobalCreate(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, pickDemo); err != nil {
		t.Fatal(err)
	}
	saved := holdUntilSignal
	holdUntilSignal = func(s *egressSession) { s.Stop() }
	defer func() { holdUntilSignal = saved }()
	if _, err := runRoot(t, srv.URL, "connect", "--create", "--name", "c-new", "--agent-file", af, "--tier", "wireguard"); err != nil {
		t.Fatalf("connect --create: %v", err)
	}
	if reg := p.bodies("register"); len(reg) != 1 || !strings.Contains(reg[0], "label:'c-new'") {
		t.Fatalf("connect --create --name registers that agent: %v", p.ops())
	}
	mustNotTouch(t, p, pickDemo, pickFixture)
}

// Flag parity: --create and --name mean the same on bare `whisper` and on `whisper run`.
func TestCreateAndNameMeanTheSameOnRunAndBareWhisper(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// what both commands must do: register this label, or connect this existing /128
		register string
		connect  string
		refuse   string
	}{
		{name: "create a new name", args: []string{"--create", "--name", "x1"}, register: "x1"},
		{name: "create a taken name", args: []string{"--create", "--name", "demo"}, refuse: "already has one called demo"},
		{name: "name an existing agent", args: []string{"--name", "fixture"}, connect: pickFixture},
		{name: "name a new agent", args: []string{"--name", "x2"}, register: "x2"},
	}
	for _, tc := range cases {
		for _, door := range []string{"run", "bare"} {
			t.Run(tc.name+"/"+door, func(t *testing.T) {
				pickHarness(t)
				p := &pickPlane{agents: pickFleet}
				srv := p.serve(t)
				saved := connectVia
				defer func() { connectVia = saved }()
				args := append([]string{}, tc.args...)
				if door == "run" {
					args = append(append([]string{"run"}, args...), "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "socks5", "--", "true")
				} else {
					// bare `whisper` holds a terminal open on success; headless it connects and returns
					connectVia = func(_ guidedOptions, _ guidedIO, ch agentChoice) error {
						_, _ = recordConnect(t, srv.URL, ch)
						return nil
					}
				}
				_, err := runRoot(t, srv.URL, args...)
				switch {
				case tc.refuse != "":
					if err == nil || !strings.Contains(err.Error(), tc.refuse) {
						t.Fatalf("refused with %q, got %v", tc.refuse, err)
					}
					mustNotMint(t, p.ops(), "connect")
				case tc.register != "":
					if err != nil {
						t.Fatal(err)
					}
					if reg := p.bodies("register"); len(reg) != 1 || !strings.Contains(reg[0], "label:'"+tc.register+"'") {
						t.Fatalf("registers %s: %v", tc.register, p.ops())
					}
					mustNotTouch(t, p, pickDemo, pickFixture)
				default:
					if err != nil {
						t.Fatal(err)
					}
					mustNotMint(t, p.ops())
					if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "'"+tc.connect+"'") {
						t.Fatalf("connects %s: %v", tc.connect, c)
					}
				}
			})
		}
	}
}

// recordConnect sends the op:connect the guided door would, so the parity test reads both doors
// off the same fake plane.
func recordConnect(t *testing.T, url string, ch agentChoice) (*client.Envelope, error) {
	t.Helper()
	c, err := resolveClient(true, false)
	if err != nil {
		return nil, err
	}
	cx, cancel := ctx()
	defer cancel()
	return opConnect(cx, c, map[string]any{"agent": firstNonBlank(ch.addr, ch.name)})
}

func TestDecideFlagSelection(t *testing.T) {
	fleet := []agentChoice{{name: "demo", addr: pickDemo, id: "ag_demo"}}
	for _, tc := range []struct {
		create bool
		name   string
		kind   selKind
		err    bool
	}{
		{false, "", selNone, false},
		{true, "", selCreate, false},
		{true, "new", selCreate, false},
		{true, "demo", 0, true},
		{true, "DEMO", 0, true},
		{true, "ag_demo", 0, true},
		{true, pickDemo, 0, true},
		{false, "demo", selExisting, false},
		{false, " Demo ", selExisting, false},
		{false, "new", selCreate, false},
	} {
		d, err := decideFlagSelection(tc.create, tc.name, fleet)
		if (err != nil) != tc.err || (err == nil && d.kind != tc.kind) {
			t.Fatalf("create=%v name=%q: kind %v err %v", tc.create, tc.name, d.kind, err)
		}
	}
}

func TestPeerReplacementNoteOnlyForAnExplicitExistingAgentOnTheRoutedTier(t *testing.T) {
	named := agentPick{sel: pickDemo, name: "demo", source: pickNamed}
	for _, tier := range []string{"", "auto", "wireguard", "wg"} {
		if peerReplacementNote(named, tier) == "" {
			t.Fatalf("a routed bind of a named agent is announced (tier %q)", tier)
		}
	}
	if peerReplacementNote(named, "socks5") != "" {
		t.Fatalf("the socks5 tier replaces no peer")
	}
	for _, src := range []pickSource{pickFile, pickCreated, pickSession} {
		p := named
		p.source = src
		if src == pickSession {
			p.session = &egressSession{}
		}
		if peerReplacementNote(p, "wireguard") != "" {
			t.Fatalf("%s is not a takeover", src)
		}
	}
}

// An unknown flag, and a known global flag the command does not read, both stop the command
// with a clear error rather than being ignored.
func TestFlagsACommandDoesNotReadAreRefused(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	for _, args := range [][]string{
		{"list", "--create"},
		{"list", "--name", "x"},
		{"list", "--agent", "demo"},
		{"ip", "--name", "x"},
		{"status", "--create"},
	} {
		_, err := runRoot(t, srv.URL, args...)
		if err == nil || !strings.Contains(err.Error(), "refused rather than ignored") || !strings.Contains(err.Error(), "--"+strings.TrimPrefix(args[1], "--")) {
			t.Fatalf("%v: refused naming the flag, got %v", args, err)
		}
	}
	if len(p.ops()) != 0 {
		t.Fatalf("a refused flag reaches nothing: %v", p.ops())
	}
	_, err := runRoot(t, srv.URL, "run", "--frobnicate", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("an unknown flag errors, got %v", err)
	}
}

func TestPolicyAgentScopesToTheDevice(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	if _, err := runRoot(t, srv.URL, "policy", "--agent", "demo", "--default", "deny"); err != nil {
		t.Fatalf("policy --agent: %v", err)
	}
	b := p.bodies("policy")
	if len(b) != 1 || !strings.Contains(b[0], "address:'"+pickDemo+"'") {
		t.Fatalf("--agent scopes op:policy to that device (it used to set the whole tenant): %v", b)
	}
}

// Every path globalFlagReaders names is a real command, so an entry cannot outlive a rename and
// quietly start refusing a flag its command reads.
func TestGlobalFlagReadersAreRealCommands(t *testing.T) {
	root := NewRootCommand()
	paths := map[string]bool{}
	stack := []*cobra.Command{root}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		paths[c.CommandPath()] = true
		stack = append(stack, c.Commands()...)
	}
	for path := range globalFlagReaders {
		if !paths[path] {
			t.Fatalf("globalFlagReaders names %q, which is not a command", path)
		}
	}
}

func TestIPOnAnEmptyAccountPointsAtCreateAndMintsNothing(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "ip", "--agent-file", filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.Contains(err.Error(), "whisper create --name") {
		t.Fatalf("ip verifies and never creates, so it names the create, got %v", err)
	}
	mustNotMint(t, p.ops(), "connect")
}

// `whisper init --name` follows the same meaning: the agent of that name, else a minted one. It
// used to call op:identity, which on an account with agents hands back an existing one.
func TestInitNameUsesOrMintsAndNeverReusesThroughIdentity(t *testing.T) {
	for _, tc := range []struct{ name, want, op string }{
		{"demo", pickDemo, ""},
		{"proj-new", pickMinted, "register"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pickHarness(t)
			p := &pickPlane{agents: pickFleet}
			srv := p.serve(t)
			g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
			sel, _, err := resolveProjectAgent(globalClient(t), initOptions{name: tc.name}, projcfg.Paths{},
				filepath.Join(t.TempDir(), "agent"), nil)
			if err != nil || sel != tc.want {
				t.Fatalf("init --name %s binds %s, got %q %v", tc.name, tc.want, sel, err)
			}
			if containsOp(p.ops(), "identity") || (tc.op == "" && containsOp(p.ops(), "register")) ||
				(tc.op != "" && !containsOp(p.ops(), tc.op)) {
				t.Fatalf("ops %v", p.ops())
			}
		})
	}
}

// A saved agent proven gone on an account with none left is replaced, and the replacement is
// SAVED, so the next command binds it instead of refusing the stale file.
func TestRunRecoversFromAGoneSavedAgentAndTheNextRunBindsTheNewOne(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::dead"); err != nil {
		t.Fatal(err)
	}
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "socks5", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	if got := client.ReadAgentFile(af); got != pickOwnAddr {
		t.Fatalf("the new agent replaces the stale saved one, got %q", got)
	}
	if !strings.Contains(stderr, "saved agent is gone") {
		t.Fatalf("the run says why it created one: %s", stderr)
	}
	p.agents = []agentChoice{{name: pickHost, addr: pickOwnAddr}}
	if _, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("the next run binds the saved replacement: %v", err)
	}
	if c := p.bodies("connect"); len(c) != 2 || !strings.Contains(c[1], pickOwnAddr) {
		t.Fatalf("second connect: %v", c)
	}
}

// An agent's own key may not register; its listing is its one identity, filed under its own
// handle. That is the one agent nobody named that a run still binds.
func TestRunOnAnAgentKeyBindsItsOwnSoleIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		others int
		agents []agentChoice
		binds  bool
	}{
		{"own sole identity", 0, []agentChoice{{name: "worker-7", addr: "2a04:2a01:9::77"}}, true},
		{"a registered agent of the account", 1, []agentChoice{{name: "demo", addr: pickDemo}}, false},
		{"the count is absent", -1, []agentChoice{{name: "worker-7", addr: "2a04:2a01:9::77"}}, false},
		{"two agents", 0, pickFleet, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pickHarness(t)
			p := &pickPlane{agents: tc.agents, otherHandles: tc.others,
				registerReply: `{"ok":false,"status":403,"error":"FORBIDDEN_SCOPE","detail":"Missing required scope: admin:dns"}`}
			srv := p.serve(t)
			stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "wireguard", "--", "true")
			if tc.binds {
				if err != nil {
					t.Fatalf("an agent key with nothing saved runs as itself: %v", err)
				}
				if !strings.Contains(stderr, "replaces the one any other host holds") {
					t.Fatalf("another host using the same key may hold the tunnel, so the run says so: %s", stderr)
				}
				if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "'"+tc.agents[0].addr+"'") {
					t.Fatalf("binds its own /128: %v", c)
				}
				return
			}
			if err == nil || containsOp(p.ops(), "connect") {
				t.Fatalf("not provably the key's own: refused, nothing connected; err %v ops %v", err, p.ops())
			}
		})
	}
}

func TestRunRefusesTheUntrimmedHostNameToo(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: append([]agentChoice{{name: pickHost + ".local", addr: "2a04:2a01:9::41"}}, pickFleet...)}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "a"), "--", "true")
	if err == nil || !strings.Contains(err.Error(), "--agent "+pickHost+".local") {
		t.Fatalf("an agent under the host's untrimmed name is not shadowed by a new one, got %v", err)
	}
	mustNotMint(t, p.ops(), "connect")
}

func TestNameAndAgentSelectionFlagsThatCannotBothHold(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"run", "--agent", "demo", "--name", "x", "--", "true"}, "pass one of them"},
		{[]string{"--agent", "demo", "--name", "x"}, "pass one of them"},
		{[]string{"run", "--create", "--name", "2a04:2a01:9::99", "--", "true"}, "cannot be one"},
		{[]string{"run", "--name", "2a04:2a01:9::99", "--", "true"}, "cannot be one"},
	} {
		_, err := runRoot(t, srv.URL, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: want %q, got %v", tc.args, tc.want, err)
		}
	}
	mustNotMint(t, p.ops(), "connect")
	// An address that IS an agent's still selects it through --name.
	if _, err := runRoot(t, srv.URL, "run", "--name", pickDemo, "--agent-file", filepath.Join(t.TempDir(), "a"), "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("--name <an agent's address>: %v", err)
	}
}

func TestTheMintedAgentsKeyIsNeverPrintedOrSaved(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	var stdout, stderr string
	var err error
	g = globalFlags{}
	root := NewRootCommand()
	root.SetArgs([]string{"--key", "whisper_live_test", "--control-url", srv.URL, "run", "--agent-file", af, "--tier", "socks5", "--", "true"})
	stdout, stderr = captureStd(t, func() { err = root.Execute() })
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(af)
	for where, text := range map[string]string{"stdout": stdout, "stderr": stderr, "the agent file": string(saved)} {
		if strings.Contains(text, "whisper_live_shownonce") {
			t.Fatalf("the minted agent's API key leaked into %s", where)
		}
	}
}

func TestConnectDaemonRefusesAConfigThatNamesNoAgent(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	err := runConnectDaemon(projcfg.Paths{}, projcfg.Config{Tier: "wireguard", Port: 1}, false)
	if err == nil || !strings.Contains(err.Error(), "names no agent") {
		t.Fatalf("a config with no agent is refused, got %v", err)
	}
	if containsOp(p.ops(), "connect") {
		t.Fatalf("no connect with no selector: %v", p.ops())
	}
}

func TestWhaleServeWithNothingNamedRefusesAndNeverConnects(t *testing.T) {
	pickHarness(t)
	control := guidedTestServer(t, pickFleet, nil)
	defer control.Close()
	migrateGlobals(t, control.URL)
	var handler http.Handler
	defer stubServeSeams(t, &handler, nil)()
	called := false
	whaleServeConnect = func(context.Context, *client.Client, string) (*egressSession, *wgtun.Tunnel, error) {
		called = true
		return nil, nil, nil
	}
	_, _, err := runWhale(t, "whale", "serve", "3000", "--state-dir", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "--agent") || strings.Contains(err.Error(), "make a new one with --name") {
		t.Fatalf("whale serve with nothing named refuses (and offers no --name it does not take), got %v", err)
	}
	if called {
		t.Fatalf("whale serve connected an agent nobody named")
	}
}

// The enforced run's options (it runs as root): nothing named is a refusal, never a mint into
// root's saved agent file; --name still makes the agent, and nothing is saved.
func TestEnforcedOptionsNeverMintUnaskedOrSave(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	c := globalClient(t)
	opts := agentPickOpts{useProject: true, noCreate: true, noSave: true, command: "whisper run --enforce"}
	if _, err := pickAgent(c, opts); err == nil || !strings.Contains(err.Error(), "--name {name}") {
		t.Fatalf("nothing named under --enforce refuses, naming --name, got %v", err)
	}
	mustNotMint(t, p.ops(), "connect")
	opts.name = "enforced-new"
	pick, err := pickAgent(c, opts)
	if err != nil || pick.sel != pickMinted || pick.source != pickCreated {
		t.Fatalf("--name under --enforce makes the agent: %+v %v", pick, err)
	}
	if client.ReadAgentFile("") != "" {
		t.Fatalf("the enforced run saves nothing")
	}
}

func TestConnectEnsureRefusesAConfigThatNamesNoAgentBeforeSpawningAnything(t *testing.T) {
	pickHarness(t)
	dir := t.TempDir()
	p := projcfg.PathsFor(dir)
	if err := projcfg.Save(p, projcfg.Config{Tier: "socks5", Port: 1}); err != nil {
		t.Fatal(err)
	}
	saved := ensureDaemon
	spawned := false
	ensureDaemon = func(projcfg.Paths, projcfg.Config) (int, bool, error) { spawned = true; return 0, false, nil }
	defer func() { ensureDaemon = saved }()
	if err := runEnsure(p.ConfigFile, 0); err == nil || !strings.Contains(err.Error(), "names no agent") {
		t.Fatalf("refused with the clear message, got %v", err)
	}
	if spawned {
		t.Fatalf("no daemon is spawned for a config that names no agent")
	}
}
