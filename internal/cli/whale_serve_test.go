// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_serve_test.go starts where a user starts: at NewRootCommand(), with argv. The
// engine test then drives REAL requests through the handler the real command installed, so
// nothing here can pass while the wiring from `whisper whale serve 3000` to the proxy is
// broken - which is exactly the defect this codebase keeps shipping.

// --- reachability ---------------------------------------------------------------------

func TestServeAndFunnelAreReachableWithTheirSubcommands(t *testing.T) {
	for _, verb := range []string{"serve", "funnel"} {
		cmd := whaleSubcommand(t, "whale", verb)
		if cmd.Short == "" || cmd.Long == "" {
			t.Errorf("`whisper whale %s` ships with no help text", verb)
		}
		for _, sub := range []string{"off", "status"} {
			whaleSubcommand(t, "whale", verb, sub)
		}
		for _, flag := range []string{"set-path", "https", "agent", "allow", "compat-headers", "identity-headers", "yes", "bg"} {
			if cmd.Flags().Lookup(flag) == nil {
				t.Errorf("`whisper whale %s` has no --%s", verb, flag)
			}
		}
		if f := cmd.Flags().Lookup("__held"); f == nil || !f.Hidden {
			t.Errorf("`whisper whale %s --__held` is missing or not hidden", verb)
		}
	}
}

// --- refusals that protect the promise --------------------------------------------------

func TestServeRefusesAPortThatCannotBePinned(t *testing.T) {
	_, _, err := runWhale(t, "whale", "serve", "3000", "--https", "8443", "--state-dir", t.TempDir())
	if err == nil {
		t.Fatal("--https 8443 was accepted; the leaf would be unpinnable and the whole trust story lost")
	}
	if !strings.Contains(err.Error(), "_443._tcp") {
		t.Errorf("the refusal does not explain the pin: %v", err)
	}
}

func TestServeRefusesATargetItCannotServe(t *testing.T) {
	for _, bad := range []string{"./public", "0", "ftp://x:21"} {
		if _, _, err := runWhale(t, "whale", "serve", bad, "--state-dir", t.TempDir()); err == nil {
			t.Errorf("`whale serve %s` was accepted", bad)
		}
	}
}

func TestServeWithNoTargetSaysWhatToType(t *testing.T) {
	_, _, err := runWhale(t, "whale", "serve")
	if err == nil {
		t.Fatal("`whale serve` with no target succeeded")
	}
	if !strings.Contains(err.Error(), "whale serve 3000") {
		t.Errorf("the usage error does not show the one line that works: %v", err)
	}
}

// TestFunnelWithoutConsentExposesNothing: the consent gate is the whole point of the verb.
// stdin is not a terminal under `go test`, so the confirmation cannot be satisfied by
// accident - which is itself the property being asserted.
func TestFunnelWithoutConsentExposesNothing(t *testing.T) {
	dir := t.TempDir()
	installed := false
	restore := stubServeSeams(t, nil, func() { installed = true })
	defer restore()

	out, errOut, err := runWhale(t, "whale", "funnel", "3000", "--state-dir", dir)
	if err == nil {
		t.Fatal("a funnel started with no confirmation and no --yes")
	}
	if !strings.Contains(err.Error()+out+errOut, "nothing was exposed") {
		t.Errorf("the refusal does not say the origin is safe: %v / %q", err, out)
	}
	if installed {
		t.Fatal("a handler was installed despite the refusal")
	}
	if _, ok := whale.ReadServeStateRaw(dir); ok {
		t.Fatal("an unconfirmed funnel left a record behind")
	}
}

func TestOffIsIdempotentAtTheCommandLevel(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		out, errOut, err := runWhale(t, "whale", "serve", "off", "--state-dir", dir)
		if err != nil {
			t.Fatalf("`whale serve off` with nothing running failed: %v", err)
		}
		out += errOut // the calm footnote goes to stderr, so stdout stays pipe-clean
		if !strings.Contains(out, "nothing is being served") {
			t.Errorf("call %d said %q", i, out)
		}
	}
}

func TestStatusReadsTheRecordFromAnyShell(t *testing.T) {
	dir := t.TempDir()
	st := whale.ServeState{
		Scope: whale.ScopeInternet, Target: "http://127.0.0.1:3000", Path: "/", Port: 443,
		Address: "2a04:2a01:9::abcd", FQDN: "db-01.acme.agents.whisper.online.",
		PID: os.Getpid(), Since: time.Now(), IdentityHeaders: true,
	}
	if err := whale.WriteServeState(dir, st); err != nil {
		t.Fatal(err)
	}
	out, _, err := runWhale(t, "whale", "funnel", "status", "--state-dir", dir)
	if err != nil {
		t.Fatalf("`whale funnel status`: %v", err)
	}
	if !strings.Contains(out, "THE INTERNET") {
		t.Errorf("a public funnel is not called out as public: %q", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:3000") {
		t.Errorf("status does not name the origin: %q", out)
	}
}

func TestASecondServeIsRefusedWhileOneIsRunning(t *testing.T) {
	dir := t.TempDir()
	st := whale.ServeState{
		Scope: whale.ScopeFleet, Target: "http://127.0.0.1:3000", Port: 443,
		Address: "2a04:2a01:9::abcd", PID: os.Getpid(), Since: time.Now(),
	}
	if err := whale.WriteServeState(dir, st); err != nil {
		t.Fatal(err)
	}
	_, _, err := runWhale(t, "whale", "serve", "4000", "--state-dir", dir)
	if err == nil {
		t.Fatal("a second serve started while one was already running")
	}
	if !strings.Contains(err.Error(), "already") || !strings.Contains(err.Error(), "off") {
		t.Errorf("the refusal does not say how to fix it: %v", err)
	}
}

func TestParseAllowList(t *testing.T) {
	got, err := parseAllowList([]string{"2a04:2a01:1::5", "2001:db8::/32", " "})
	if err != nil || len(got) != 2 {
		t.Fatalf("parseAllowList = %v, %v", got, err)
	}
	if got[0].Bits() != 128 {
		t.Errorf("a bare address became %v, want a /128", got[0])
	}
	if _, err := parseAllowList([]string{"db-01"}); err == nil {
		t.Fatal("a name was accepted as an access rule")
	}
}

// --- the engine, end to end ---------------------------------------------------------

// stubServeSeams replaces the two tunnel seams and the signal hold, so the real command
// runs to completion in a test. onInstall fires when the command installs its handler;
// capture receives it so the test can drive real requests through it.
func stubServeSeams(t *testing.T, capture *http.Handler, onInstall func()) func() {
	t.Helper()
	savedUp, savedInstall, savedHold, savedConnect := whaleServeListenerUp, whaleServeInstall, holdWhaleServe, whaleServeConnect
	whaleServeListenerUp = func(*wgtun.Tunnel) bool { return true }
	whaleServeInstall = func(_ *wgtun.Tunnel, h http.Handler) {
		if h != nil {
			if capture != nil {
				*capture = h
			}
			if onInstall != nil {
				onInstall()
			}
		}
	}
	return func() {
		whaleServeListenerUp, whaleServeInstall, holdWhaleServe = savedUp, savedInstall, savedHold
		whaleServeConnect = savedConnect
	}
}

// TestTheCommandInstallsAWorkingFrontEnd is the anti-unreachable gate for this path. It runs
// the REAL `whisper whale funnel <origin> --yes`, then sends a real request through the
// handler that command installed, and asserts the origin was told who called. Remove the
// wiring at any point between argv and the proxy and this test fails.
func TestTheCommandInstallsAWorkingFrontEnd(t *testing.T) {
	var seen http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.WriteString(w, "origin ok")
	}))
	defer origin.Close()

	control := guidedTestServer(t, []agentChoice{{name: "db-01", addr: "2a04:2a01:9::abcd"}}, nil)
	defer control.Close()
	migrateGlobals(t, control.URL)

	var handler http.Handler
	restore := stubServeSeams(t, &handler, nil)
	defer restore()

	dir := t.TempDir()
	held := make(chan struct{})
	holdWhaleServe = func() { close(held) }
	whaleServeConnect = func(cx context.Context, c *client.Client, sel string) (*egressSession, *wgtun.Tunnel, error) {
		// local stays nil on purpose: this session owns no real tunnel, so nothing in the
		// command may try to tear one down or register it in the session registry.
		return &egressSession{addr: "2a04:2a01:9::abcd", tier: "wireguard"}, &wgtun.Tunnel{}, nil
	}
	var stateDuringHold whale.ServeState
	var wasRecorded bool
	holdWhaleServe = func() {
		stateDuringHold, wasRecorded = whale.ReadServeState(dir)
		close(held)
	}

	if _, _, err := runWhale(t, "whale", "funnel", origin.URL, "--yes", "--compat-headers",
		"--state-dir", dir); err != nil {
		t.Fatalf("`whale funnel` failed: %v", err)
	}
	<-held

	if !wasRecorded {
		t.Fatal("the funnel was not recorded while it ran, so `funnel off` from another shell could never find it")
	}
	if stateDuringHold.Scope != whale.ScopeInternet || stateDuringHold.Address != "2a04:2a01:9::abcd" {
		t.Errorf("the record does not describe the funnel: %+v", stateDuringHold)
	}
	if _, still := whale.ReadServeStateRaw(dir); still {
		t.Error("the record survived the serve exiting; a stale exposure claim is worse than none")
	}
	if handler == nil {
		t.Fatal("the command installed no handler: `whale funnel` reaches nothing")
	}

	// Drive a real request through what the command installed.
	req := httptest.NewRequest(http.MethodGet, "http://db-01.acme.agents.whisper.online/", nil)
	req.RemoteAddr = "[2001:db8::1]:40000"
	req.Header.Set("Whisper-Agent-FQDN", "ceo.acme.agents.whisper.online.") // a forgery attempt
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("the installed front end returned %d: %q", rr.Code, rr.Body.String())
	}
	if seen.Get(whale.HeaderAgentFQDN) != "" {
		t.Fatalf("the forged identity reached the origin: %q", seen.Get(whale.HeaderAgentFQDN))
	}
	if got := seen.Get(whale.HeaderClientAddress); got != "2001:db8::1" {
		t.Errorf("the origin was told the caller was %q", got)
	}
	if got := rr.Header().Get(whale.HeaderServeScope); got != "internet" {
		t.Errorf("the response scope is %q, want internet", got)
	}
}

// TestAFleetServeRefusesAStranger runs the real `whale serve` and proves the gate it built
// from the live fleet actually refuses someone outside it.
func TestAFleetServeRefusesAStranger(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin ok")
	}))
	defer origin.Close()
	control := guidedTestServer(t, []agentChoice{
		{name: "db-01", addr: "2a04:2a01:9::abcd"},
		{name: "web-01", addr: "2a04:2a01:9::beef"},
	}, nil)
	defer control.Close()
	migrateGlobals(t, control.URL)

	var handler http.Handler
	restore := stubServeSeams(t, &handler, nil)
	defer restore()

	dir := t.TempDir()
	held := make(chan struct{})
	holdWhaleServe = func() { close(held) }
	whaleServeConnect = func(cx context.Context, c *client.Client, sel string) (*egressSession, *wgtun.Tunnel, error) {
		return &egressSession{addr: "2a04:2a01:9::abcd", tier: "wireguard"}, &wgtun.Tunnel{}, nil
	}
	if _, _, err := runWhale(t, "whale", "serve", origin.URL, "--state-dir", dir); err != nil {
		t.Fatalf("`whale serve` failed: %v", err)
	}
	<-held
	if handler == nil {
		t.Fatal("no handler was installed")
	}

	cases := map[string]int{
		"[2a04:2a01:9::beef]:40000": http.StatusOK,        // a fleet member
		"[2a04:2a01:9::abcd]:40000": http.StatusOK,        // this node itself
		"[2001:db8::666]:40000":     http.StatusForbidden, // a stranger who found the port
	}
	for from, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "http://db-01.acme.agents.whisper.online/", nil)
		req.RemoteAddr = from
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s got %d, want %d (%q)", from, rr.Code, want, rr.Body.String())
		}
	}
}

// TestAFunnelIsVisibleInWhaleStatus is the anti-unreachable gate for the half of that
// is about being able to SEE an exposure: a funnel started in one shell must show up in
// `whisper whale status` run from any other, because that is the only way an operator who
// has forgotten about it ever finds out. It drives the REAL status command, from argv, so
// removing the record-reading line in whale_status.go fails here.
func TestAFunnelIsVisibleInWhaleStatus(t *testing.T) {
	control := guidedTestServer(t, []agentChoice{{name: "db-01", addr: "2a04:2a01:9::abcd"}}, nil)
	defer control.Close()
	migrateGlobals(t, control.URL)

	// whale status reads the record from the user's own config root, so the test gives it
	// one of its own rather than the developer's.
	home := testenv.HermeticHome(t)
	dir := filepath.Join(home, ".config", "whisper")

	// A real, stoppable stand-in for the holder. It must NOT be this process: `funnel off`
	// stops the recorded pid for real, and a test that recorded its own would kill itself.
	holder := exec.Command("sleep", "120")
	if err := holder.Start(); err != nil {
		t.Skipf("no sleep(1) to stand in for the holder: %v", err)
	}
	defer func() { _ = holder.Process.Kill() }()

	st := whale.ServeState{
		Scope: whale.ScopeInternet, Target: "http://127.0.0.1:3000", Path: "/", Port: 443,
		Address: "2a04:2a01:9::abcd", FQDN: "db-01.acme.agents.whisper.online",
		PID: holder.Process.Pid, Since: time.Now(), IdentityHeaders: true,
	}
	if err := whale.WriteServeState(dir, st); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runWhale(t, "whale", "status", "--peers=false")
	if err != nil {
		t.Fatalf("whale status: %v", err)
	}
	for _, must := range []string{"THE INTERNET (public)", "127.0.0.1:3000", "db-01.acme.agents.whisper.online"} {
		if !strings.Contains(stdout, must) {
			t.Errorf("`whale status` does not show the running funnel (%q missing):\n%s", must, stdout)
		}
	}

	// And in --json, where a script reads it.
	jsonOut, _, jerr := runWhale(t, "--json", "whale", "status", "--peers=false")
	if jerr != nil {
		t.Fatalf("whale status --json: %v", jerr)
	}
	var view struct {
		Serving *whale.ServeState `json:"serving"`
	}
	if uerr := json.Unmarshal([]byte(jsonOut), &view); uerr != nil {
		t.Fatalf("status --json did not parse: %v\n%s", uerr, jsonOut)
	}
	if view.Serving == nil || !view.Serving.Scope.Public() {
		t.Fatalf("status --json does not report the public exposure: %s", jsonOut)
	}

	// One word turns it off, from a different invocation: the holder is really stopped and
	// the record is really gone, so status stops claiming it.
	if _, _, oerr := runWhale(t, "whale", "funnel", "off", "--state-dir", dir); oerr != nil {
		t.Fatalf("funnel off: %v", oerr)
	}
	if _, still := whale.ReadServeStateRaw(dir); still {
		t.Error("`funnel off` left the record behind")
	}
	// The holder is a child of this test, so proving it stopped means reaping it: a
	// signalled child stays visible to signal 0 as a zombie until it is waited for, and
	// asserting on that would be asserting on the harness rather than on the product.
	waited := make(chan error, 1)
	go func() { waited <- holder.Wait() }()
	select {
	case <-waited:
		ws, ok := holder.ProcessState.Sys().(syscall.WaitStatus)
		if ok && !(ws.Signaled() && ws.Signal() == syscall.SIGTERM) {
			t.Errorf("the holder ended, but not by the SIGTERM `funnel off` sends: %v", holder.ProcessState)
		}
	case <-time.After(5 * time.Second):
		t.Error("`funnel off` did not stop the process holding the exposure")
	}
	after, _, aerr := runWhale(t, "whale", "status", "--peers=false")
	if aerr != nil {
		t.Fatalf("whale status after off: %v", aerr)
	}
	if strings.Contains(after, "THE INTERNET (public)") {
		t.Errorf("`whale status` still claims a public funnel after `funnel off`:\n%s", after)
	}
}
