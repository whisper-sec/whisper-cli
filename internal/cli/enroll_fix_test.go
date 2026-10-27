// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// These tests drive `whisper enroll --force --preview` and `--confirm` against a fake control
// plane that counts every call, so each row can prove what was and was not done.

const (
	fixOwnAddr   = "2a04:2a01:9:1::a1"
	fixOwnAgent  = "agent-000000000000fix1"
	fixNamedAddr = "2a04:2a01:9:2::b2"
	fixNewAddr   = "2a04:2a01:9:3::c3"
	fixAccount   = "tfixaccount000000000000000000000"
)

type fixAgent struct{ label, addr, agent, fqdn string }

// fixPlane is the fake control plane. Every field may be changed between calls.
type fixPlane struct {
	mu                                                  sync.Mutex
	agents                                              []fixAgent
	account                                             string            // "" answers with no self row
	pub                                                 map[string]string // address -> publication JSON; "missing" drops the column; "503" fails
	listFail                                            string            // "", "503", "empty", "notok", "nocolumns"
	failAfter                                           int               // fail every listing after this many (0 = never)
	register                                            string            // "" succeeds; otherwise an error code
	listCalls, agentCalls, registerCalls, identityCalls int
}

func (p *fixPlane) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body struct{ Query string }
	_ = json.Unmarshal(raw, &body)
	q := body.Query
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(s string) { _, _ = w.Write([]byte(s)) }
	switch {
	case strings.Contains(q, "{op:'register'"):
		p.registerCalls++
		if p.register == "_TRANSPORT" {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
		}
		if p.register != "" {
			write(`{"ok":false,"status":409,"error":{"code":"` + p.register + `","message":"refused"}}`)
			return
		}
		write(`{"ok":true,"status":200,"result":{"columns":["agent","address","api_key","fqdn"],"rows":[["agent-new","` +
			fixNewAddr + `","whisper_live_shownonce","anew.agents.whisper.online."]]}}`)
		p.agents = append(p.agents, fixAgent{label: "new", addr: fixNewAddr, agent: "agent-new", fqdn: "anew.agents.whisper.online"})
	case strings.Contains(q, "{op:'identity'"):
		p.identityCalls++
		write(`{"ok":true,"status":200,"result":{"columns":["label","address"],"rows":[["x","2a04:2a01:9::dead"]]}}`)
	case strings.Contains(q, "{op:'agent'"):
		p.agentCalls++
		addr := ""
		for a := range p.pub {
			if strings.Contains(q, a) {
				addr = a
			}
		}
		pub, ok := p.pub[addr]
		if !ok {
			pub = `{"record":"present","forward_published":true,"reverse_published":true,"repairable":false}`
		}
		switch pub {
		case "503":
			w.WriteHeader(503)
			write(`{"ok":false,"status":503,"error":{"code":"UNAVAILABLE","message":"slow"}}`)
		case "missing":
			write(`{"ok":true,"status":200,"result":{"columns":["agent","address"],"rows":[["a","` + addr + `"]]}}`)
		default:
			write(`{"ok":true,"status":200,"result":{"columns":["agent","address","publication"],"rows":[["a","` + addr + `",` + pub + `]]}}`)
		}
	case strings.Contains(q, "'activityTenants'"):
		if p.account == "" {
			write(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[]}}`)
			return
		}
		write(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["activityTenants",{"tenant":"` +
			p.account + `","self":true}]]}}`)
	default:
		p.listCalls++
		fail := p.listFail
		if p.failAfter > 0 && p.listCalls > p.failAfter {
			fail = "503"
		}
		switch fail {
		case "503":
			w.WriteHeader(503)
			write(`{"ok":false,"status":503,"error":{"code":"UNAVAILABLE","message":"down"}}`)
		case "empty":
			write(`{}`)
		case "notok":
			write(`{"ok":true,"status":502,"result":{"columns":["kind","item"],"rows":[]}}`)
		case "nocolumns":
			write(`{"ok":true,"status":200,"result":{}}`)
		default:
			var rows []string
			for _, a := range p.agents {
				item, _ := json.Marshal(map[string]any{"label": a.label, "address": a.addr, "agent": a.agent, "fqdn": a.fqdn})
				rows = append(rows, `["agent",`+string(item)+`]`)
			}
			write(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` + strings.Join(rows, ",") + `]}}`)
		}
	}
}

// init keeps every other test in the package away from a real result record, the same way the
// refusal record is kept away: a connect test that holds a session clears it.
func init() {
	enrollResultFile = func() string { return "" }
}

// enrollResultAt gives one test its own result record.
func enrollResultAt(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enroll-result.json")
	saved := enrollResultFile
	enrollResultFile = func() string { return path }
	t.Cleanup(func() { enrollResultFile = saved })
}

// fixHarness is a hermetic home, a host name, a marker, a saved agent and the fake plane.
func fixHarness(t *testing.T, host string, marker *fixAgent, saved string, agents ...fixAgent) *fixPlane {
	t.Helper()
	testenv.HermeticHome(t)
	refusalAt(t)
	enrollResultAt(t)
	withHostname(t, host)
	if marker != nil {
		if err := client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr(marker.addr),
			marker.fqdn, marker.agent); err != nil {
			t.Fatal(err)
		}
	}
	if saved != "" {
		if err := client.SaveAgent("", saved); err != nil {
			t.Fatal(err)
		}
	}
	p := &fixPlane{agents: agents, account: fixAccount, pub: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(p.handler))
	t.Cleanup(srv.Close)
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	t.Cleanup(func() { g = savedG })
	return p
}

var ownAgent = fixAgent{label: "studio-mac", addr: fixOwnAddr, agent: fixOwnAgent, fqdn: "afix1.agents.whisper.online"}
var namedAgent = fixAgent{label: "box", addr: fixNamedAddr, agent: "agent-000000000000fix2", fqdn: "afix2.agents.whisper.online"}

func mustPreview(t *testing.T) previewView {
	t.Helper()
	v, err := runEnrollPreview("")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	return v
}

func mustConfirm(t *testing.T, tok string) previewView {
	t.Helper()
	v, _, err := runEnrollConfirm("", tok)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return v
}

func fileSnapshot(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range []string{client.DefaultBoundFile(), client.DefaultAgentFile(), connectRefusalFile(), enrollResultFile()} {
		b, err := os.ReadFile(p)
		if err == nil {
			out[p] = string(b)
		}
	}
	return out
}

func sameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Preview reads and changes nothing, on every outcome.
func TestEnrollPreviewWritesNothing(t *testing.T) {
	cases := map[string]func(t *testing.T) *fixPlane{
		"rebind":   func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "agent-0dead", ownAgent) },
		"reuse":    func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "", namedAgent) },
		"register": func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
		"refuse":   func(t *testing.T) *fixPlane { p := fixHarness(t, "box", &ownAgent, ""); p.listFail = "503"; return p },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			p := mk(t)
			writeConnectRefusal(connectRefusal{CheckedAt: "2026-10-15T00:00:00Z", Kind: refusalIdentityGone, Reason: "gone", Source: "file", Selector: "agent-0dead"})
			before := fileSnapshot(t)
			mustPreview(t)
			if p.registerCalls != 0 || p.identityCalls != 0 {
				t.Fatalf("preview called register %d, identity %d", p.registerCalls, p.identityCalls)
			}
			if !sameSnapshot(before, fileSnapshot(t)) {
				t.Fatal("preview changed a file")
			}
		})
	}
}

// The marker's identity is listed and served, and only the saved file is stale.
func TestEnrollConfirmRebindsOwnIdentity(t *testing.T) {
	p := fixHarness(t, "Mac.localdomain", &ownAgent, "agent-0dead", ownAgent)
	v := mustPreview(t)
	if v.Outcome != fixRebindOwn || v.Address != fixOwnAddr || v.SavedReplace == nil || !*v.SavedReplace || v.Token == "" {
		t.Fatalf("preview: %+v", v)
	}
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixRebindOwn || p.registerCalls != 0 || p.identityCalls != 0 {
		t.Fatalf("confirm %+v, register %d identity %d", r, p.registerCalls, p.identityCalls)
	}
	if got := client.ReadAgentFile(""); got != fixOwnAgent {
		t.Fatalf("saved agent: %q", got)
	}
	if _, ok := readEnrollResult(); !ok {
		t.Fatal("confirm must leave the result record")
	}
}

// The saved-agent decision comes from the one listing: a plane that fails every later listing
// changes nothing, on the typed path and the confirm path.
func TestEnrollSavedAgentDecidedFromTheOneListing(t *testing.T) {
	t.Run("typed", func(t *testing.T) {
		p := fixHarness(t, "Mac.localdomain", &ownAgent, "agent-0dead", ownAgent)
		p.failAfter = 1
		if _, err := runEnroll("", true); err != nil {
			t.Fatal(err)
		}
		if got := client.ReadAgentFile(""); got != fixOwnAgent || p.listCalls != 1 {
			t.Fatalf("saved %q after %d listings", got, p.listCalls)
		}
	})
	t.Run("confirm", func(t *testing.T) {
		p := fixHarness(t, "Mac.localdomain", &ownAgent, "agent-0dead", ownAgent)
		v := mustPreview(t)
		p.listCalls, p.failAfter = 0, 1
		mustConfirm(t, v.Token)
		if got := client.ReadAgentFile(""); got != fixOwnAgent || p.listCalls != 1 {
			t.Fatalf("saved %q after %d listings", got, p.listCalls)
		}
	})
}

func TestEnrollConfirmRegistersNew(t *testing.T) {
	p := fixHarness(t, "Mac.localdomain", &ownAgent, fixOwnAgent)
	writeConnectRefusal(connectRefusal{CheckedAt: "2026-10-15T00:00:00Z", Kind: refusalIdentityGone, Reason: "gone", Source: "file", Selector: fixOwnAgent})
	v := mustPreview(t)
	if v.Outcome != fixRegisterNew || v.Name != "Mac" || v.Account != fixAccount {
		t.Fatalf("preview: %+v", v)
	}
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixRegisterNew || r.Address != fixNewAddr || p.registerCalls != 1 || p.identityCalls != 0 {
		t.Fatalf("confirm %+v, register %d identity %d", r, p.registerCalls, p.identityCalls)
	}
	if id, ok := client.ReadBoundFile(""); !ok || id.Addr.String() != fixNewAddr {
		t.Fatalf("marker %+v", id)
	}
	if got := client.ReadAgentFile(""); got != "agent-new" {
		t.Fatalf("saved %q", got)
	}
	if _, ok := readConnectRefusal(); ok {
		t.Fatal("the identity-gone refusal must be cleared")
	}
	fr, ok := readEnrollResult()
	if !ok || fr.Outcome != fixRegisterNew || fr.PreviousAddr != fixOwnAddr {
		t.Fatalf("result record %+v ok=%v", fr, ok)
	}
}

func TestEnrollConfirmReusesNamed(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "", namedAgent)
	v := mustPreview(t)
	if v.Outcome != fixReuseNamed || v.Address != fixNamedAddr {
		t.Fatalf("preview: %+v", v)
	}
	mustConfirm(t, v.Token)
	if p.registerCalls != 0 || p.identityCalls != 0 {
		t.Fatalf("register %d identity %d", p.registerCalls, p.identityCalls)
	}
}

func TestEnrollPreviewRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, shape := range []string{"503", "empty", "notok", "nocolumns"} {
		t.Run(shape, func(t *testing.T) {
			p := fixHarness(t, "box", &ownAgent, "")
			p.listFail = shape
			v := mustPreview(t)
			if v.Outcome != fixRefuse || v.Token != "" || v.RefuseClass != refuseRetryable {
				t.Fatalf("preview: %+v", v)
			}
			// A confirm with a token from a good moment also refuses once the listing fails.
			p.listFail = ""
			good := mustPreview(t)
			p.listFail = shape
			before := fileSnapshot(t)
			r := mustConfirm(t, good.Token)
			if r.Outcome != fixRefuse || p.registerCalls != 0 || !sameSnapshot(before, fileSnapshot(t)) {
				t.Fatalf("confirm %+v register %d", r, p.registerCalls)
			}
		})
	}
}

func TestEnrollPreviewRefusesWithoutAnAccount(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "")
	p.account = ""
	v := mustPreview(t)
	if v.Outcome != fixRefuse || v.Code != "account" || v.Token != "" {
		t.Fatalf("preview: %+v", v)
	}
}

// Every field the token binds is checked on confirm, and named when it changed.
func TestEnrollConfirmRefusesWhenAnythingChanged(t *testing.T) {
	cases := []struct {
		field  string
		setup  func(t *testing.T) *fixPlane
		change func(t *testing.T, p *fixPlane)
	}{
		{"outcome", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) { p.agents = append(p.agents, ownAgent) }},
		{"address", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "", namedAgent) },
			func(t *testing.T, p *fixPlane) { p.agents[0].addr = "2a04:2a01:9:2::b3" }},
		{"agent", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "", namedAgent) },
			func(t *testing.T, p *fixPlane) { p.agents[0].agent = "agent-000000000000fix9" }},
		{"name", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) { withHostname(t, "renamed") }},
		{"account", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) { p.account = "totheraccount00000000000000000000" }},
		{"key", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) { g.key = "whisper_live_other" }},
		{"served", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "", ownAgent) },
			func(t *testing.T, p *fixPlane) { p.pub[fixOwnAddr] = `{"record":"absent"}` }},
		{"saved_agent", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "", ownAgent) },
			func(t *testing.T, p *fixPlane) { _ = client.SaveAgent("", "agent-picked") }},
		{"saved_replace", func(t *testing.T) *fixPlane {
			return fixHarness(t, "box", &ownAgent, namedAgent.agent, ownAgent, namedAgent)
		}, func(t *testing.T, p *fixPlane) { p.agents = p.agents[:1] }},
		{"previous_address", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) {
				_ = client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr("2a04:2a01:9:4::d4"), "x", ownAgent.agent)
			}},
		{"previous_agent", func(t *testing.T) *fixPlane { return fixHarness(t, "box", &ownAgent, "") },
			func(t *testing.T, p *fixPlane) {
				_ = client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr(fixOwnAddr), "x", "agent-other")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			p := tc.setup(t)
			v := mustPreview(t)
			if v.Token == "" {
				t.Fatalf("no token: %+v", v)
			}
			tc.change(t, p)
			before := fileSnapshot(t)
			r := mustConfirm(t, v.Token)
			if r.Outcome != fixChanged {
				t.Fatalf("confirm went ahead after %s changed: %+v", tc.field, r)
			}
			named := false
			for _, ch := range r.Changed {
				if ch.Field == tc.field {
					named = true
				}
			}
			if !named {
				t.Fatalf("%s not named in %+v", tc.field, r.Changed)
			}
			if p.registerCalls != 0 || p.identityCalls != 0 || !sameSnapshot(before, fileSnapshot(t)) {
				t.Fatalf("a changed plan acted: register %d identity %d", p.registerCalls, p.identityCalls)
			}
		})
	}
}

// Adjacent fields cannot shift into each other.
func TestEnrollTokenFieldBoundaries(t *testing.T) {
	a := encodeEnrollToken(enrollPlan{PreviousAgent: "ab", Saved: "c"})
	b := encodeEnrollToken(enrollPlan{PreviousAgent: "a", Saved: "bc"})
	if a == b {
		t.Fatal("two plans with a moved field boundary gave one token")
	}
}

func TestEnrollSecondConfirm(t *testing.T) {
	t.Run("register is not repeated", func(t *testing.T) {
		p := fixHarness(t, "box", &ownAgent, "")
		v := mustPreview(t)
		mustConfirm(t, v.Token)
		r := mustConfirm(t, v.Token)
		if r.Outcome != fixChanged || p.registerCalls != 1 {
			t.Fatalf("second confirm %+v, registers %d", r, p.registerCalls)
		}
	})
	t.Run("rebind is idempotent", func(t *testing.T) {
		p := fixHarness(t, "box", &ownAgent, fixOwnAgent, ownAgent)
		v := mustPreview(t)
		mustConfirm(t, v.Token)
		saved := client.ReadAgentFile("")
		r := mustConfirm(t, v.Token)
		if r.Outcome != fixRebindOwn || p.registerCalls != 0 || client.ReadAgentFile("") != saved {
			t.Fatalf("second rebind %+v", r)
		}
	})
}

func TestEnrollConfirmRegisterRefusals(t *testing.T) {
	for code, class := range map[string]string{
		"FORBIDDEN_SCOPE": refuseTerminal, "AGENT_REVOKED": refuseTerminal, "AGENT_EXPIRED": refuseTerminal,
		"AGENT_LIMIT": refuseTerminal, "BAD_ARGS": refuseTerminal,
		"ALREADY_REGISTERED": refuseRetryable, "REGISTER_IN_PROGRESS": refuseRetryable, "STORE_UNAVAILABLE": refuseRetryable,
	} {
		t.Run(code, func(t *testing.T) {
			p := fixHarness(t, "box", &ownAgent, "")
			v := mustPreview(t)
			p.register = code
			r := mustConfirm(t, v.Token)
			if r.Outcome != fixRefuse || r.RefuseClass != class || p.identityCalls != 0 {
				t.Fatalf("%s: %+v identity %d", code, r, p.identityCalls)
			}
		})
	}
}

// After a race with another registration under the same name, the next look reuses it.
func TestEnrollAlreadyRegisteredThenReuse(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "")
	v := mustPreview(t)
	p.register = "ALREADY_REGISTERED"
	mustConfirm(t, v.Token)
	p.agents = append(p.agents, fixAgent{label: "box", addr: fixNewAddr, agent: "agent-raced"})
	if again := mustPreview(t); again.Outcome != fixReuseNamed || again.Agent != "agent-raced" {
		t.Fatalf("next preview %+v", again)
	}
}

// A crash between the registration and the marker write leaves an agent under the host name;
// the next look reuses it and registers nothing. The crash is real: a child process stopped at
// exactly that point.
func TestEnrollCrashAfterRegisterReuses(t *testing.T) {
	if os.Getenv("WHISPER_FIX_CRASH_CHILD") == "1" {
		testenv.UseHome(t, os.Getenv("WHISPER_FIX_HOME"))
		withHostname(t, "box")
		g = globalFlags{controlURL: os.Getenv("WHISPER_FIX_URL"), key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
		enrollAfterRegister = func() { os.Exit(137) }
		_, _, _ = runEnrollConfirm("", os.Getenv("WHISPER_FIX_TOKEN"))
		t.Fatal("the child should have stopped after the registration")
	}
	p := fixHarness(t, "box", &ownAgent, "")
	v := mustPreview(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnrollCrashAfterRegisterReuses$")
	cmd.Env = append(os.Environ(), "WHISPER_FIX_CRASH_CHILD=1", "WHISPER_FIX_URL="+g.controlURL,
		"WHISPER_FIX_TOKEN="+v.Token, "WHISPER_FIX_HOME="+os.Getenv("HOME"))
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 137 {
		t.Fatalf("child: %v", err)
	}
	p.mu.Lock() // the child's requests were served on the plane's goroutines
	registers := p.registerCalls
	p.agents[len(p.agents)-1].label = "box"
	p.mu.Unlock()
	if registers != 1 {
		t.Fatalf("registers before recovery: %d", registers)
	}
	again := mustPreview(t)
	if again.Outcome != fixReuseNamed || again.Address != fixNewAddr {
		t.Fatalf("after the crash: %+v", again)
	}
	mustConfirm(t, again.Token)
	p.mu.Lock()
	registers = p.registerCalls
	p.mu.Unlock()
	if registers != 1 {
		t.Fatalf("recovery registered again: %d", registers)
	}
}

func TestEnrollFixUsage(t *testing.T) {
	if err := enrollFixFlagsError(true, "x", true); !isUsageError(err) {
		t.Fatalf("preview with confirm: %v", err)
	}
	if err := enrollFixFlagsError(false, " ", true); !isUsageError(err) {
		t.Fatalf("empty confirm: %v", err)
	}
	for _, bad := range []string{"nope", "v2.abc.def", "v1.!!!.00", strings.Repeat("v1.", 2000)} {
		if _, err := decodeEnrollToken(bad); !isUsageError(err) {
			t.Fatalf("%q decoded: %v", bad[:min(len(bad), 20)], err)
		}
	}
	tok := encodeEnrollToken(enrollPlan{Outcome: fixRegisterNew, RawLabel: "box"})
	wrapped := tok[:10] + "\n  " + tok[10:20] + " \r\n" + tok[20:]
	if p, err := decodeEnrollToken(wrapped); err != nil || p.RawLabel != "box" {
		t.Fatalf("wrapped paste: %v %+v", err, p)
	}
	got, err := readTokenArg("-", strings.NewReader(tok+"\n"))
	if err != nil || strings.TrimSpace(got) != tok {
		t.Fatalf("stdin token: %v", err)
	}
}

func TestRefusalFixable(t *testing.T) {
	testenv.HermeticHome(t)
	refusalAt(t)
	_ = client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr(fixOwnAddr), "x", fixOwnAgent)
	_ = client.SaveAgent("", "agent-saved")
	cases := []struct {
		r    connectRefusal
		want bool
	}{
		{connectRefusal{Kind: refusalIdentityGone, Source: "file", Selector: "agent-saved"}, true},
		{connectRefusal{Kind: refusalIdentityGone, Source: "none", Selector: fixOwnAddr}, true},
		{connectRefusal{Kind: refusalIdentityGone, Source: "flag", Selector: "agent-saved"}, false},
		{connectRefusal{Kind: refusalIdentityGone, Source: "config", Selector: "agent-saved"}, false},
		{connectRefusal{Kind: refusalIdentityGone, Source: "file", Selector: "agent-old"}, false},
		{connectRefusal{Kind: refusalEgressCheck, Source: "file", Selector: "agent-saved"}, false},
		{connectRefusal{Kind: refusalIdentityGone, Selector: "agent-saved"}, false},
	}
	for i, c := range cases {
		if got := refusalFixable(c.r, client.ReadAgentFile(""), client.DefaultBoundFile()); got != c.want {
			t.Fatalf("case %d %+v: fixable=%v", i, c.r, got)
		}
	}
	writeConnectRefusal(connectRefusal{CheckedAt: "2026-10-15T00:00:00Z", Kind: refusalIdentityGone, Reason: "gone", Source: "file", Selector: "agent-saved"})
	r, ok := readConnectRefusal()
	if !ok || !r.Fixable || r.FixCommand != "whisper enroll --force --preview" {
		t.Fatalf("read back %+v", r)
	}
}

func TestEnrollFixPrintedLines(t *testing.T) {
	saved := pasteGOOS
	t.Cleanup(func() { pasteGOOS = saved })
	for goos, want := range map[string]string{"linux": "{agent}", "darwin": "{agent}", "windows": `"{agent}"`} {
		pasteGOOS = goos
		r := registerRefusal(&client.ProblemError{Title: "AGENT_LIMIT"}, "box")
		if !strings.Contains(r.Reason, "whisper kill "+want+" --revoke") || strings.Contains(r.Reason, "<") {
			t.Fatalf("%s: %q", goos, r.Reason)
		}
	}
}

func TestDisplayTextStripsHiddenCharacters(t *testing.T) {
	for _, in := range []string{"box\r\nforged", "box\x1b[31m", "evil\u202ecod.exe", "bo\u200bx", "a\u2066b\u2069"} {
		out := displayText(in)
		for _, r := range out {
			if r < 0x20 || r == 0x7f || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
				t.Fatalf("%q kept a hidden character: %q", in, out)
			}
		}
		if !strings.Contains(out, "hidden character") {
			t.Fatalf("%q: removal not marked: %q", in, out)
		}
	}
	// The token carries the raw label, which is what is registered.
	p := fixHarness(t, "evil\u202ebox", nil, "")
	v := mustPreview(t)
	plan, _ := decodeEnrollToken(v.Token)
	if plan.RawLabel != "evil\u202ebox" || strings.ContainsRune(v.Name, '\u202e') {
		t.Fatalf("raw %q shown %q", plan.RawLabel, v.Name)
	}
	_ = p
}

func TestEnrollPreviewJSONContract(t *testing.T) {
	fixHarness(t, "box", &ownAgent, "")
	v := mustPreview(t)
	raw, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"outcome", "name", "account", "previous", "saved_replace", "token"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("preview JSON lacks %q: %s", k, raw)
		}
	}
}

// The publication block decides whether a listed identity is offered; anything short of an
// answer that it is served is never offered, and only a withdrawn one may mention removal.
func TestEnrollPublicationVerdicts(t *testing.T) {
	cases := []struct {
		name, pub, verdict, class string
		revoke                    bool
	}{
		{"absent", `{"record":"absent","forward_published":false,"reverse_published":false,"repairable":false}`, pubWithdrawn, refuseRetryable, true},
		{"repairable", `{"record":"present","forward_published":false,"reverse_published":false,"repairable":true}`, pubRepairable, refuseAction, false},
		{"nulls", `{"record":"present","forward_published":null,"reverse_published":null,"repairable":false}`, pubUnknown, refuseRetryable, false},
		{"reverse missing", `{"record":"present","forward_published":true,"reverse_published":false,"repairable":false,"reason":"reverse zone not loaded"}`, pubUnknown, refuseRetryable, false},
		{"no column", "missing", pubUnknown, refuseRetryable, false},
		{"read failed", "503", pubUnknown, refuseRetryable, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := fixHarness(t, "box", &ownAgent, "", ownAgent)
			p.pub[fixOwnAddr] = c.pub
			v := mustPreview(t)
			if v.Outcome != fixRefuse || v.Token != "" || v.RefuseClass != c.class {
				t.Fatalf("preview %+v", v)
			}
			mentions := strings.Contains(v.Reason+v.Action, "--revoke")
			if mentions != c.revoke {
				t.Fatalf("revoke advice=%v, want %v: %+v", mentions, c.revoke, v)
			}
			if c.verdict == pubRepairable && !strings.Contains(v.Action, "op:'republish', address:'"+fixOwnAddr+"'") {
				t.Fatalf("repair line: %q", v.Action)
			}
		})
	}
	t.Run("served", func(t *testing.T) {
		fixHarness(t, "box", &ownAgent, "", ownAgent)
		v := mustPreview(t)
		plan, _ := decodeEnrollToken(v.Token)
		if v.Outcome != fixRebindOwn || plan.Served != pubServed {
			t.Fatalf("served: %+v", v)
		}
	})
	t.Run("repair line needs a valid address", func(t *testing.T) {
		r := publicationRefusal(enrollPlan{RawLabel: "x", Address: "not-an-address"}, pubRepairable, "")
		if r.Action != "" {
			t.Fatalf("repair line printed for an invalid address: %q", r.Action)
		}
	})
	t.Run("unknown carries the server's reason", func(t *testing.T) {
		r := publicationRefusal(enrollPlan{RawLabel: "x", Address: fixOwnAddr}, pubUnknown, "reverse zone not loaded")
		if r.ServerReason != "reverse zone not loaded" || r.Action != "" {
			t.Fatalf("unknown: server reason %q, action %q (a command field must never hold prose)", r.ServerReason, r.Action)
		}
	})
}

// The result record: written by every confirm, shown only while it names the marker's
// identity, removed by the next confirm.
func TestEnrollResultRecordLifecycle(t *testing.T) {
	fixHarness(t, "box", &ownAgent, "", ownAgent)
	v := mustPreview(t)
	mustConfirm(t, v.Token)
	if fr, ok := readEnrollResult(); !ok || fr.Outcome != fixRebindOwn {
		t.Fatalf("after rebind: %+v %v", fr, ok)
	}
	// Private by the platform's own rule: the mode bits on unix, the DACL on Windows.
	if err := secfile.Verify(enrollResultFile()); err != nil {
		t.Fatalf("the result record is not private: %v", err)
	}
	_ = client.WriteBoundFile(client.DefaultBoundFile(), "register", netip.MustParseAddr("2a04:2a01:9:5::e5"), "x", "agent-other")
	if _, ok := readEnrollResult(); ok {
		t.Fatal("a record for another identity must not be shown")
	}
	clearEnrollResult()
	if _, err := os.Stat(enrollResultFile()); !os.IsNotExist(err) {
		t.Fatalf("not removed: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(enrollResultFile()), ".enroll-result.json.tmp-*")); len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

// A preview run with --name prints a confirm line that carries it, and a confirm pasted without
// --name still uses the name the preview was run with.
func TestEnrollPreviewWithNameThenPastedConfirmActs(t *testing.T) {
	p := fixHarness(t, "studio-mac", &ownAgent, "", ownAgent)
	v, err := runEnrollPreview("other-name")
	if err != nil || v.Outcome != fixRegisterNew || v.Token == "" {
		t.Fatalf("preview --name: %v %+v", err, v)
	}
	if line := confirmLine(v.ExplicitName, v.Token); !strings.Contains(line, "--name other-name --confirm ") {
		t.Fatalf("printed line drops --name: %q", line)
	}
	if line := previewLine(v.ExplicitName); line != "whisper enroll --force --name other-name --preview" {
		t.Fatalf("look-again line: %q", line)
	}
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixRegisterNew || p.registerCalls != 1 {
		t.Fatalf("pasted confirm: %+v, registers %d", r, p.registerCalls)
	}
}

// The name and fqdn the panel shows from the result record have hidden characters removed.
func TestPanelIdentityFixIsEscaped(t *testing.T) {
	fixHarness(t, "evil\u202ebox", &ownAgent, "")
	v := mustPreview(t)
	mustConfirm(t, v.Token)
	fr := panelIdentityFix()
	if fr == nil || strings.ContainsRune(fr.Name, '\u202e') || !strings.Contains(fr.Name, "hidden character") {
		t.Fatalf("panel record %+v", fr)
	}
	raw, _ := os.ReadFile(enrollResultFile())
	if !strings.ContainsRune(string(raw), '\u202e') {
		t.Fatalf("the file must keep the raw label: %s", raw)
	}
}

// A changed confirm says so and can be looked at again.
func TestEnrollChangedIsRetryableWithAReason(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "")
	v := mustPreview(t)
	p.mu.Lock()
	p.agents = append(p.agents, ownAgent)
	p.mu.Unlock()
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixChanged || r.RefuseClass != refuseRetryable || r.Reason == "" {
		t.Fatalf("changed: %+v", r)
	}
}

// A refusal after the registration was sent says the identity may have changed, never that
// nothing changed; one before it says nothing changed.
func TestEnrollMaybeChangedAfterTheAct(t *testing.T) {
	for code, maybe := range map[string]bool{"STORE_UNAVAILABLE": true, "": true, "FORBIDDEN_SCOPE": false, "ALREADY_REGISTERED": false} {
		t.Run(firstNonBlank(code, "unanswered"), func(t *testing.T) {
			p := fixHarness(t, "box", &ownAgent, "")
			v := mustPreview(t)
			p.register = firstNonBlank(code, "_TRANSPORT")
			if code == "" {
				p.register = "_TRANSPORT"
			}
			r := mustConfirm(t, v.Token)
			if r.MaybeChanged != maybe {
				t.Fatalf("%s: maybe_changed=%v", code, r.MaybeChanged)
			}
			_, stderr := captureStd(t, func() { _ = printEnrollView(r, true) })
			says := strings.Contains(stderr, "may have changed")
			if says != maybe {
				t.Fatalf("%s: stderr %q", code, stderr)
			}
		})
	}
}

// A marker cut off mid-write can parse as a nearby address; it is refused, never acted on.
func TestEnrollRefusesAnIncompleteMarker(t *testing.T) {
	full := "mode=register\naddress=" + namedAgent.addr + "\nname=x\nagent=agent-x\nbound_at=2026-10-15T00:00:00Z\n"
	for _, cut := range []int{len("mode=register\naddress=2a04:2a01:9:2::b"), len(full) - 1, len(full) - 5} {
		t.Run(strings.ReplaceAll(full[:cut][max(0, cut-12):], "\n", "|"), func(t *testing.T) {
			p := fixHarness(t, "other-host", nil, "", namedAgent, fixAgent{label: "sib", addr: "2a04:2a01:9:2::b", agent: "agent-sib"})
			if err := os.MkdirAll(filepath.Dir(client.DefaultBoundFile()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(client.DefaultBoundFile(), []byte(full[:cut]), 0o600); err != nil {
				t.Fatal(err)
			}
			v := mustPreview(t)
			if v.Outcome != fixRefuse || v.Code != "marker_incomplete" || v.Token != "" {
				t.Fatalf("torn marker previewed as %+v", v)
			}
			if p.registerCalls != 0 {
				t.Fatal("registered on a torn marker")
			}
		})
	}
	t.Run("a whole record is read", func(t *testing.T) {
		fixHarness(t, "other-host", nil, "", namedAgent)
		_ = os.MkdirAll(filepath.Dir(client.DefaultBoundFile()), 0o700)
		_ = os.WriteFile(client.DefaultBoundFile(), []byte(full), 0o600)
		if v := mustPreview(t); v.Outcome != fixRebindOwn {
			t.Fatalf("whole marker: %+v", v)
		}
	})
}

// The marker and saved agent are replaced whole: no temp file is left and the mode holds.
func TestMarkerAndSavedAgentWritesAreAtomic(t *testing.T) {
	testenv.HermeticHome(t)
	for i := 0; i < 3; i++ {
		if err := client.WriteBoundFile("", "register", netip.MustParseAddr(fixOwnAddr), "x", "agent-x"); err != nil {
			t.Fatal(err)
		}
		if err := client.SaveAgent("", "agent-x"); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Dir(client.DefaultBoundFile())
	left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	for _, p := range []string{client.DefaultBoundFile(), client.DefaultAgentFile()} {
		if err := secfile.Verify(p); err != nil {
			t.Fatalf("%s is not private: %v", p, err)
		}
	}
	if _, st := client.ReadBoundFileStrict(""); st != client.BoundComplete {
		t.Fatalf("the written marker is not a whole record: %v", st)
	}
}

// A token whose plan matches but carries a refusal (an edited token claiming a withdrawn
// identity is fine to bind, say) is still refused: the match proves nothing on its own.
func TestEnrollConfirmNeverActsOnARefusedPlan(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "", ownAgent)
	p.pub[fixOwnAddr] = `{"record":"absent"}`
	c, _ := resolveClient(true, false)
	f, refusal := gatherEnroll(c, "")
	if refusal != nil {
		t.Fatal(refusal)
	}
	plan, r := decideEnroll(f)
	if r == nil {
		t.Fatal("fixture: the withdrawn identity must refuse")
	}
	before := fileSnapshot(t)
	got := mustConfirm(t, encodeEnrollToken(plan))
	if got.Outcome != fixRefuse || p.registerCalls != 0 || p.identityCalls != 0 || !sameSnapshot(before, fileSnapshot(t)) {
		t.Fatalf("a crafted token for a refused plan acted: %+v", got)
	}
}

// The confirm result says what happened: saved_replaced, not the plan's saved_replace.
func TestEnrollConfirmReportsWhatHappened(t *testing.T) {
	fixHarness(t, "box", &ownAgent, "agent-0dead", ownAgent)
	v := mustPreview(t)
	r := mustConfirm(t, v.Token)
	raw, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, has := m["saved_replace"]; has {
		t.Fatalf("result carries the plan field saved_replace: %s", raw)
	}
	if m["saved_replaced"] != true {
		t.Fatalf("saved_replaced: %s", raw)
	}
	t.Run("a plan to replace that changed nothing is reported as not replaced", func(t *testing.T) {
		// The saved agent already names the identity being bound: the plan says replace, the
		// act has nothing to write, and the result must say so.
		fixHarness(t, "box", &ownAgent, fixOwnAgent, ownAgent)
		v := mustPreview(t)
		if v.SavedReplace == nil || !*v.SavedReplace {
			t.Fatalf("fixture: the plan should say replace: %+v", v)
		}
		r := mustConfirm(t, v.Token)
		if r.SavedReplaced == nil || *r.SavedReplaced {
			t.Fatalf("saved_replaced must be false when nothing was written: %+v", r)
		}
	})
}

// The result record goes when the next confirm starts and when connect holds a session.
func TestEnrollResultRecordIsRemovedByConfirmAndConnect(t *testing.T) {
	t.Run("next confirm, even one that then fails", func(t *testing.T) {
		p := fixHarness(t, "box", &ownAgent, "")
		v := mustPreview(t)
		_ = os.MkdirAll(filepath.Dir(enrollResultFile()), 0o700)
		_ = os.WriteFile(enrollResultFile(), []byte(`{"outcome":"stale","address":"`+fixOwnAddr+`"}`), 0o600)
		p.mu.Lock()
		p.register = "FORBIDDEN_SCOPE"
		p.mu.Unlock()
		if r := mustConfirm(t, v.Token); r.Outcome != fixRefuse {
			t.Fatalf("fixture: the register should refuse: %+v", r)
		}
		if _, err := os.Stat(enrollResultFile()); !os.IsNotExist(err) {
			t.Fatalf("a confirm that went ahead must remove the old record first: %v", err)
		}
	})
	t.Run("next confirm", func(t *testing.T) {
		p := fixHarness(t, "box", &ownAgent, "")
		v := mustPreview(t)
		mustConfirm(t, v.Token)
		if _, err := os.Stat(enrollResultFile()); err != nil {
			t.Fatal("first confirm left no record")
		}
		again := mustPreview(t) // now a rebind of the new identity
		p.mu.Lock()
		p.pub[fixNewAddr] = `{"record":"present","forward_published":true,"reverse_published":true}`
		p.mu.Unlock()
		_ = os.WriteFile(enrollResultFile(), []byte(`{"outcome":"stale","address":"`+fixNewAddr+`"}`), 0o600)
		r := mustConfirm(t, again.Token)
		raw, _ := os.ReadFile(enrollResultFile())
		if r.Outcome != fixRebindOwn || strings.Contains(string(raw), "stale") {
			t.Fatalf("the next confirm kept the old record: %+v %s", r, raw)
		}
	})
	t.Run("connect", func(t *testing.T) {
		testenv.HermeticHome(t)
		refusalAt(t)
		enrollResultAt(t)
		_ = os.MkdirAll(filepath.Dir(enrollResultFile()), 0o700)
		_ = os.WriteFile(enrollResultFile(), []byte(`{"outcome":"register_new","address":"`+fixNewAddr+`"}`), 0o600)
		var seen []recordedCall
		srv := recordingServer(t, []agentChoice{{name: "x", addr: "2a04:2a01:9::abcd"}}, &seen)
		defer srv.Close()
		savedG := g
		g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
		defer func() { g = savedG }()
		defer stubEgressTail(t)()
		cmd := newConnectCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd", "--tier", "socks5", "--agent-file", filepath.Join(t.TempDir(), "agent")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("connect: %v", err)
		}
		if _, err := os.Stat(enrollResultFile()); !os.IsNotExist(err) {
			t.Fatalf("a held session must remove the record: %v", err)
		}
	})
}

func TestEnrollTokenToleratesPasteAndBounds(t *testing.T) {
	tok := encodeEnrollToken(enrollPlan{Outcome: fixRegisterNew, RawLabel: "box"})
	dirty := "\ufeff" + tok[:8] + "\u200b" + tok[8:16] + "\u2060\n" + tok[16:]
	if p, err := decodeEnrollToken(dirty); err != nil || p.RawLabel != "box" {
		t.Fatalf("Cf-laden paste: %v", err)
	}
	wrapped := strings.Repeat(" ", 6000) + tok
	got, err := readTokenArg("-", strings.NewReader(wrapped))
	if err != nil {
		t.Fatalf("a whitespace-heavy stdin paste was cut short: %v", err)
	}
	if _, err := decodeEnrollToken(got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := decodeEnrollToken(encodeEnrollToken(enrollPlan{RawLabel: strings.Repeat("x", 5000)})); !isUsageError(err) {
		t.Fatalf("an oversized token decoded: %v", err)
	}
	// A plan whose token would be too long is refused at the preview: no token is printed that
	// its confirm would refuse.
	fixHarness(t, "box", &ownAgent, strings.Repeat("<", 1500))
	if v := mustPreview(t); v.Token != "" || v.Code != "too_large" {
		t.Fatalf("oversized plan previewed with a token: %+v", v)
	}
}

func TestEnrollTokenIntegrityChecks(t *testing.T) {
	tok := encodeEnrollToken(enrollPlan{Outcome: fixRegisterNew, RawLabel: "box"})
	parts := strings.Split(tok, ".")
	bad := parts[0] + "." + parts[1] + ".0000000000000000"
	if _, err := decodeEnrollToken(bad); !isUsageError(err) {
		t.Fatalf("a wrong checksum decoded: %v", err)
	}
	extra := `{"outcome":"register_new","sneaky":1}`
	enc := base64Raw(extra)
	sum := sha256Hex(extra)
	if _, err := decodeEnrollToken("v1." + enc + "." + sum[:16]); !isUsageError(err) {
		t.Fatalf("an unknown field decoded: %v", err)
	}
}

func TestEnrollAddressesAreCanonical(t *testing.T) {
	odd := fixAgent{label: "box", addr: "2A04:2a01:0009:0002:0000:0000:0000:00B2", agent: "agent-odd"}
	p := fixHarness(t, "box", nil, "", odd)
	p.pub["2A04:2a01:0009:0002:0000:0000:0000:00B2"] = `{"record":"present","forward_published":true,"reverse_published":true}`
	v := mustPreview(t)
	if v.Address != "2a04:2a01:9:2::b2" {
		t.Fatalf("address not canonical: %+v", v)
	}
	bad := fixAgent{label: "box", addr: "2a04:2a01:9::\x1b[31m", agent: "agent-bad"}
	fixHarness(t, "box", nil, "", bad)
	if v := mustPreview(t); v.Outcome != fixRefuse || v.Token != "" || strings.ContainsRune(v.Address, 0x1b) {
		t.Fatalf("a non-address was offered: %+v", v)
	}
}

func TestEnrollWithdrawnLineFallsBackToTheAddress(t *testing.T) {
	r := publicationRefusal(enrollPlan{RawLabel: "x", Address: fixOwnAddr}, pubWithdrawn, "")
	if r.Action != "whisper kill "+fixOwnAddr+" --revoke" {
		t.Fatalf("no agent: %q", r.Action)
	}
	r = publicationRefusal(enrollPlan{RawLabel: "x", Agent: "agent-\x1b[2J", Address: fixOwnAddr}, pubWithdrawn, "")
	if strings.ContainsRune(r.Action, 0x1b) || !strings.Contains(r.Action, fixOwnAddr) {
		t.Fatalf("hidden characters reached the command: %q", r.Action)
	}
}

func TestRegisterRefusalReadsTheCodeFromType(t *testing.T) {
	for _, pe := range []*client.ProblemError{
		{Type: "https://whisper.online/problems/FORBIDDEN_SCOPE", Status: 403},
		{Type: "AGENT_LIMIT", Status: 429},
		{Status: 403},
	} {
		if r := registerRefusal(pe, "box"); r.Class != refuseTerminal || r.MaybeChanged {
			t.Fatalf("%+v read as %+v", pe, r)
		}
	}
}

func TestEnrollPreviewNamesASystemService(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "")
	saved := serviceIdentityContextFn
	t.Cleanup(func() { serviceIdentityContextFn = saved })
	installed := false
	serviceIdentityContextFn = func() serviceIdentityContext { return serviceIdentityContext{ConnectionService: installed} }
	if v := mustPreview(t); v.ServiceNote != "" {
		t.Fatalf("no service, but a note: %q", v.ServiceNote)
	}
	installed = true
	v := mustPreview(t)
	if !strings.Contains(v.ServiceNote, "whisper service install --now --agent ") {
		t.Fatalf("service note: %q", v.ServiceNote)
	}
	// After a registration, the note names the agent that was actually made.
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixRegisterNew || !strings.Contains(r.ServiceNote, "--agent agent-new") || p.registerCalls != 1 {
		t.Fatalf("confirm note: %+v", r)
	}
}

func TestEnrollResultIgnoresAnotherAgentAtTheSameAddress(t *testing.T) {
	fixHarness(t, "box", &ownAgent, "", ownAgent)
	_ = os.MkdirAll(filepath.Dir(enrollResultFile()), 0o700)
	_ = os.WriteFile(enrollResultFile(), []byte(`{"outcome":"rebind_own","address":"`+fixOwnAddr+`","agent":"agent-someone-else"}`), 0o600)
	if _, ok := readEnrollResult(); ok {
		t.Fatal("a record for another agent at this address was shown")
	}
}

func base64Raw(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// A --name with a hidden character is bound by the token but never printed in a line to paste.
func TestEnrollHiddenNameIsNeverPrinted(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "")
	v, err := runEnrollPreview("other\u200bname")
	if err != nil || v.Token == "" {
		t.Fatalf("preview: %v %+v", err, v)
	}
	if line := confirmLine(v.ExplicitName, v.Token); strings.Contains(line, "--name") || strings.Contains(line, "hidden") {
		t.Fatalf("printed a display name: %q", line)
	}
	// The line builders refuse a hidden name on their own too, whatever they are handed.
	for _, line := range []string{confirmLine("other\u200bname", "tok"), previewLine("other\u200bname")} {
		if strings.Contains(line, "--name") {
			t.Fatalf("a line builder printed a hidden name: %q", line)
		}
	}
	if r := mustConfirm(t, v.Token); r.Outcome != fixRegisterNew || p.registerCalls != 1 {
		t.Fatalf("a bare confirm with the token must act: %+v", r)
	}
}

// A confirm whose fresh reads are refused shows this device's marker, never the token's fields.
func TestEnrollConfirmRefusalShowsTheMarkerNotTheToken(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "", namedAgent)
	v := mustPreview(t)
	plan, _ := decodeEnrollToken(v.Token)
	plan.Address, plan.PreviousAddr = "2a04:2a01:9::\x1bforged", "2a04:2a01:9::\x1bforged"
	p.mu.Lock()
	p.listFail = "503"
	p.mu.Unlock()
	r := mustConfirm(t, encodeEnrollToken(plan))
	if r.Outcome != fixRefuse || r.Address != "" || r.Previous.Address != fixOwnAddr {
		t.Fatalf("refusal view echoed the token: %+v", r)
	}
	// The same on a preview: the marker rides on the refusal, so a reader can see it moved.
	if pv := mustPreview(t); pv.Previous.Address != fixOwnAddr {
		t.Fatalf("preview refusal lost the marker: %+v", pv)
	}
}

// A changed plan carries no removal line from a refusal the fresh plan holds.
func TestEnrollChangedCarriesNoRefusalAdvice(t *testing.T) {
	p := fixHarness(t, "box", &ownAgent, "", ownAgent)
	v := mustPreview(t)
	p.mu.Lock()
	p.pub[fixOwnAddr] = `{"record":"absent"}`
	p.mu.Unlock()
	r := mustConfirm(t, v.Token)
	if r.Outcome != fixChanged || r.Action != "" || r.Code != "changed" {
		t.Fatalf("changed view: %+v", r)
	}
}

// A marker cut exactly at a line boundary, after the address, still lacks bound_at and is refused.
func TestEnrollRefusesAMarkerCutAtALineBoundary(t *testing.T) {
	fixHarness(t, "other-host", nil, "", fixAgent{label: "sib", addr: "2a04:2a01:9:2::b", agent: "agent-sib"})
	_ = os.MkdirAll(filepath.Dir(client.DefaultBoundFile()), 0o700)
	_ = os.WriteFile(client.DefaultBoundFile(), []byte("mode=register\naddress=2a04:2a01:9:2::b\n"), 0o600)
	if v := mustPreview(t); v.Outcome != fixRefuse || v.Code != "marker_incomplete" {
		t.Fatalf("a marker without bound_at was acted on: %+v", v)
	}
}

// The writes are replacements, not rewrites in place: the path gets a new file each time, so a
// reader can never see a truncated mix.
func TestMarkerAndSavedAgentAreReplacedNotRewritten(t *testing.T) {
	testenv.HermeticHome(t)
	_ = client.WriteBoundFile("", "register", netip.MustParseAddr(fixOwnAddr), "x", "agent-x")
	_ = client.SaveAgent("", "agent-x")
	b1 := testenv.FileIdentity(t, client.DefaultBoundFile())
	a1 := testenv.FileIdentity(t, client.DefaultAgentFile())
	_ = client.WriteBoundFile("", "register", netip.MustParseAddr(fixOwnAddr), "x", "agent-y")
	_ = client.SaveAgent("", "agent-y")
	b2 := testenv.FileIdentity(t, client.DefaultBoundFile())
	a2 := testenv.FileIdentity(t, client.DefaultAgentFile())
	if os.SameFile(b1, b2) || os.SameFile(a1, a2) {
		t.Fatal("a write rewrote the file in place instead of replacing it")
	}
	// The control: an in-place rewrite of the same path must read as the same file, or the
	// check above could never fail on this platform.
	p := client.DefaultAgentFile()
	c1 := testenv.FileIdentity(t, p)
	if err := secfile.WriteFile(p, []byte("agent-z")); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(c1, testenv.FileIdentity(t, p)) {
		t.Fatal("an in-place rewrite read as a new file: this platform's identity check proves nothing")
	}
}
