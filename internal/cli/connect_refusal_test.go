// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// connect_refusal_test.go pins what a connect that cannot start leaves behind. On a Mac the
// resident session is a launchd job whose output goes nowhere, and when it began refusing to
// start (the saved identity had been removed from the account) nothing on the machine said why:
// the panel said "not connected, run: whisper connect", which was the command failing.

// init points the record at the null device for every test in this package. Plenty of connect
// tests fail on purpose without isolating HOME, and each failure writes a record; none of them
// may write into the home of whoever runs the suite, and none may leave a record behind for an
// unrelated test to read (a panel test once read a usage error another test had recorded). A
// write there vanishes and a read finds nothing. A test that wants a record uses refusalAt.
func init() {
	connectRefusalFile = func() string { return os.DevNull }
}

// refusalAt gives one test its own record file and returns its path.
func refusalAt(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connect-refusal.json")
	saved := connectRefusalFile
	connectRefusalFile = func() string { return path }
	t.Cleanup(func() { connectRefusalFile = saved })
	return path
}

func mustReadRefusal(t *testing.T) connectRefusal {
	t.Helper()
	r, ok := readConnectRefusal()
	if !ok {
		t.Fatalf("a connect that could not start must leave a refusal record at %s", connectRefusalFile())
	}
	return r
}

// runConnect executes `whisper connect` against srv with args and returns its error and stderr.
func runConnect(t *testing.T, srvURL string, args ...string) (error, string) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: srvURL, key: "whisper_live_test", timeout: 5 * time.Second}
	t.Cleanup(func() { g = savedG })
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	var err error
	_, stderr := captureStd(t, func() { err = cmd.Execute() })
	return err, stderr
}

// failVerify makes the egress check fail with err, through the REAL connectAndVerifyOnPort (a
// pinned port binds a real local proxy, which dials nothing until asked), so the test covers
// the wrapping in the shared connect body and not a stub of it.
func failVerify(t *testing.T, err error) {
	t.Helper()
	saved := verifyEgress
	verifyEgress = func(context.Context, *client.Client, *egressSession) error { return err }
	t.Cleanup(func() { verifyEgress = saved })
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// The live shape. The saved /128 is gone from an account that still has other devices' agents,
// connect refuses (correctly) to bind one of them, and the refusal now lands where a person
// looks: on the line connect prints, which names the fix, and in the record the panel reads.
func TestConnectRefusal_IdentityGoneIsRecordedWithTheFix(t *testing.T) {
	refusalAt(t)
	srv := recordingServer(t, staleAgentAccount(), nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::dead"); err != nil {
		t.Fatal(err)
	}

	err, _ := runConnect(t, srv.URL, "--agent-file", af, "--tier", "wireguard")
	if err == nil {
		t.Fatal("a connect whose saved identity is gone must not start")
	}
	line := friendly(err)
	for _, want := range []string{"connect could not start", "2a04:2a01:9::dead", "no longer in your account",
		"Fix: give this device a fresh identity with: whisper enroll --force"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the printed line must carry %q, got %q", want, line)
		}
	}
	r := mustReadRefusal(t)
	if r.Kind != refusalIdentityGone || r.Fix != fixIdentityGone || !strings.Contains(r.Reason, "2a04:2a01:9::dead") {
		t.Fatalf("the record must say the identity is gone and name the fix, got %+v", r)
	}
	if r.Tier != "wireguard" {
		t.Fatalf("the record must name the tier that was asked for, got %q", r.Tier)
	}
	// What the panel and the job's log read must be the same words.
	if line != r.line() {
		t.Fatalf("the terminal line and the record disagree:\n  %q\n  %q", line, r.line())
	}
	// It is still the 404 it always was, so nothing that checks for that changes.
	if !isNotFoundProblem(err) {
		t.Fatalf("the refusal must still be the resolver's 404, got %T", err)
	}
}

// An account with no agents left falls through to connect's create path, which a headless job
// cannot take (it has no name to give). That is still a refusal about the identity, and it
// keeps its usage-error exit code.
func TestConnectRefusal_EmptyAccountHeadlessIsIdentityGone(t *testing.T) {
	refusalAt(t)
	srv := recordingServer(t, nil, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::dead"); err != nil {
		t.Fatal(err)
	}
	err, _ := runConnect(t, srv.URL, "--agent-file", af, "--tier", "wireguard")
	if err == nil || !isUsageError(err) {
		t.Fatalf("a headless create with no name stays a usage error, got %v", err)
	}
	if r := mustReadRefusal(t); r.Kind != refusalIdentityGone || r.Fix != fixIdentityGone {
		t.Fatalf("an emptied account is an identity that is gone, got %+v", r)
	}
	if !strings.Contains(friendly(err), "whisper enroll --force") {
		t.Fatalf("the printed line must name the fix, got %q", friendly(err))
	}
}

// The egress check failed and the identity is still in the account: the record says so in the
// check's own words and names a fix that is not "run whisper connect again", which for the
// resident job is the command already failing.
func TestConnectRefusal_EgressCheckFailureNamesReasonAndFix(t *testing.T) {
	refusalAt(t)
	srv := recordingServer(t, staleAgentAccount(), nil) // has 2a04:2a01:9::abcd
	defer srv.Close()
	failVerify(t, &client.ProblemError{Status: 502, Detail: "the Whisper egress did not accept this session " +
		"while verifying your address - the session token may have been rejected; run `whisper connect` again to mint a fresh session"})

	err, _ := runConnect(t, srv.URL, "--agent", "2a04:2a01:9::abcd", "--tier", "socks5",
		"--port", strconv.Itoa(freePort(t)))
	if err == nil {
		t.Fatal("a failed egress check must not hold a session")
	}
	r := mustReadRefusal(t)
	if r.Kind != refusalEgressCheck || r.Fix != fixEgressSession {
		t.Fatalf("a refused session is an egress-check refusal with the session fix, got %+v", r)
	}
	line := friendly(err)
	for _, want := range []string{"did not accept this session", "Fix: each attempt mints a fresh session", "whisper connect --tier socks5"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the printed line must carry %q, got %q", want, line)
		}
	}
}

// The check failed AND the account no longer has the identity the session was bound to: that
// is proven, so it is reported as the identity being gone, with the fix that works.
func TestConnectRefusal_EgressCheckThatProvesTheIdentityGone(t *testing.T) {
	refusalAt(t)
	// The stub plane binds 2a04:2a01:9::abcd, and this account does not have it.
	srv := recordingServer(t, []agentChoice{{name: "This browser (Whisper Guard)", addr: "2a04:2a01:9::f55a"}}, nil)
	defer srv.Close()
	failVerify(t, &client.ProblemError{Status: http.StatusProxyAuthRequired,
		Detail: "the Whisper egress rejected this session's token (407) - run `whisper connect` again to mint a fresh session"})

	err, _ := runConnect(t, srv.URL, "--agent", "2a04:2a01:9::abcd", "--tier", "socks5",
		"--port", strconv.Itoa(freePort(t)))
	if err == nil {
		t.Fatal("a failed egress check must not hold a session")
	}
	r := mustReadRefusal(t)
	if r.Kind != refusalIdentityGone || r.Fix != fixIdentityGone {
		t.Fatalf("a check whose identity the account no longer has is identity-gone, got %+v", r)
	}
	for _, want := range []string{"rejected this session's token", "no longer has the agent 2a04:2a01:9::abcd"} {
		if !strings.Contains(r.Reason, want) {
			t.Fatalf("the reason must carry %q, got %q", want, r.Reason)
		}
	}
}

// A listing that fails proves nothing about the identity, so the check's own refusal stands.
func TestProveIdentityAfterCheck_FailedListingProvesNothing(t *testing.T) {
	srv := http500Server(t)
	defer srv.Close()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 2 * time.Second}
	defer func() { g = savedG }()
	c, err := resolveClient(true, false)
	if err != nil {
		t.Fatal(err)
	}
	check := &egressCheckError{cause: errors.New("the check failed"), addr: "2a04:2a01:9::abcd"}
	if got := proveIdentityAfterCheck(c, check); got != check {
		t.Fatalf("a failed listing must leave the check's error alone, got %v", got)
	}
}

// http500Server is a control plane that answers every call with a 500, so a listing fails.
func http500Server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
}

func TestConnectRefusal_PortInUse(t *testing.T) {
	refusalAt(t)
	srv := recordingServer(t, staleAgentAccount(), nil)
	defer srv.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	cerr, _ := runConnect(t, srv.URL, "--agent", "2a04:2a01:9::abcd", "--tier", "socks5", "--port", strconv.Itoa(port))
	if cerr == nil {
		t.Fatal("a taken pinned port must refuse")
	}
	r := mustReadRefusal(t)
	if r.Kind != refusalPortInUse || r.Fix != fixPortInUse || r.Port != port {
		t.Fatalf("a taken port is filed as port-in-use with its port, got %+v", r)
	}
}

// A refusal whose own sentence already carries its remedy is recorded, and printed exactly as
// it always was: no fix is invented for it.
func TestConnectRefusal_OtherKeepsItsOwnSentence(t *testing.T) {
	home := testenv.HermeticHome(t)
	refusalAt(t)
	savedG := g
	g = globalFlags{controlURL: "http://127.0.0.1:1", keyFile: filepath.Join(home, "no-key"), timeout: time.Second}
	defer func() { g = savedG }()
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd", "--agent-file", filepath.Join(home, "agent")})
	var err error
	captureStd(t, func() { err = cmd.Execute() })
	if err == nil {
		t.Fatal("a connect with no key must fail")
	}
	r := mustReadRefusal(t)
	if r.Kind != refusalOther || r.Fix != "" {
		t.Fatalf("a keyless refusal has no invented fix, got %+v", r)
	}
	if strings.Contains(friendly(err), "connect could not start") || !strings.Contains(friendly(err), "whisper login") {
		t.Fatalf("its own sentence must be printed unchanged, got %q", friendly(err))
	}
}

// A connect that holds a session removes the record, so the panel never shows a refusal next
// to a working connection.
func TestConnectRefusal_HeldSessionClearsTheRecord(t *testing.T) {
	path := refusalAt(t)
	// Written by hand, so the control below does not depend on the writer under test.
	if err := os.WriteFile(path, []byte(`{"checked_at":"2026-10-14T12:00:00Z","kind":"other","reason":"an old reason"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readConnectRefusal(); !ok {
		t.Fatal("control: the seeded record must read back before the connect")
	}
	srv := recordingServer(t, staleAgentAccount(), nil)
	defer srv.Close()
	defer stubEgressTail(t)()
	if err, _ := runConnect(t, srv.URL, "--agent", "2a04:2a01:9::abcd", "--tier", "socks5"); err != nil {
		t.Fatalf("connect must succeed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a held session must remove the refusal record, stat=%v", err)
	}
}

func TestEgressCheckFix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		want  string
	}{
		{"407", &client.ProblemError{Status: 407, Detail: "rejected"}, fixEgressSession},
		{"not accepted", &client.ProblemError{Status: 502, Detail: "the Whisper egress did not accept this session while verifying"}, fixEgressSession},
		{"leak", &client.ProblemError{Status: 502, Detail: "your traffic isn't going through Whisper yet"}, fixEgressTunnel},
		{"handshake", &client.ProblemError{Status: 502, Detail: "the WireGuard handshake never completed"}, fixEgressTunnel},
		{"unavailable", &client.ProblemError{Status: 503, Detail: "the egress verification endpoint was unavailable"}, fixEgressOther},
		{"plain", errors.New("the egress verification reply was unreadable"), fixEgressOther},
	} {
		if got := egressCheckFix(tc.cause); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// --- the panel ---------------------------------------------------------------------------

func TestPanelConnectRefusal_OnlyWhileNothingIsConnected(t *testing.T) {
	refusalAt(t)
	writeConnectRefusal(connectRefusal{CheckedAt: time.Now().UTC().Format(time.RFC3339), Kind: refusalIdentityGone,
		Reason: "the saved agent 2a04:2a01:9::dead is no longer in your account", Fix: fixIdentityGone})
	if _, ok := panelConnectRefusal(&statusSession{Address: "2a04:2a01:9::abcd", Port: 1080}); ok {
		t.Fatal("a refusal must never be shown beside a live session")
	}
	if _, ok := panelConnectRefusal(nil); !ok {
		t.Fatal("with nothing connected the panel must read the refusal")
	}
}

// The three places the panel used to say only "run: whisper connect" now say why it is not
// starting, and the first line of `errors` is the same sentence, so the panel app (which
// renders the banner) shows it without a change of its own.
func TestApplyConnectRefusal_NamesTheReasonAndTheFix(t *testing.T) {
	r := connectRefusal{Kind: refusalIdentityGone, AgeSecs: 95,
		Reason: "the saved agent 2a04:2a01:9::dead is no longer in your account.", Fix: fixIdentityGone}
	view := panelView{Errors: []string{"an earlier read failed"}}
	view.Egress.ProxyApps.Detail = "no Whisper connection is up on this host - run: whisper connect"
	view.Egress.SystemApps.CannotEnableReason = "nothing is connected on this host. Run: whisper connect"
	applyConnectRefusal(&view, r)

	want := "the last attempt to connect (1m ago) did not start: the saved agent 2a04:2a01:9::dead is no " +
		"longer in your account. Fix: " + fixIdentityGone
	if len(view.Errors) != 2 || view.Errors[0] != want {
		t.Fatalf("the refusal must lead `errors`, got %q", view.Errors)
	}
	if view.Connection.Refusal == nil || view.Connection.Refusal.Kind != refusalIdentityGone {
		t.Fatalf("connection.refusal must carry the record, got %+v", view.Connection.Refusal)
	}
	for name, s := range map[string]string{
		"proxy_apps.detail":    view.Egress.ProxyApps.Detail,
		"cannot_enable_reason": view.Egress.SystemApps.CannotEnableReason,
	} {
		if !strings.Contains(s, "whisper enroll --force") || !strings.Contains(s, "did not start") {
			t.Fatalf("%s must name the reason and the fix, got %q", name, s)
		}
		if strings.HasSuffix(strings.TrimSpace(s), "Run: whisper connect") || strings.HasSuffix(strings.TrimSpace(s), "run: whisper connect") {
			t.Fatalf("%s must not send the person to the command that is failing, got %q", name, s)
		}
	}
}

func TestReadConnectRefusal_IgnoresJunk(t *testing.T) {
	path := refusalAt(t)
	for _, body := range []string{"", "{", `{"kind":"other"}`, `[]`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if r, ok := readConnectRefusal(); ok {
			t.Fatalf("%q must not read as a refusal, got %+v", body, r)
		}
	}
	clearConnectRefusal()
	if _, ok := readConnectRefusal(); ok {
		t.Fatal("a cleared record must be gone")
	}
}

func TestConnectRefusalRecordIsPrivate(t *testing.T) {
	path := refusalAt(t)
	writeConnectRefusal(connectRefusal{CheckedAt: "2026-10-14T12:00:00Z", Kind: refusalOther, Reason: "x"})
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatalf("the record must be 0600, got %o", mode)
	}
}
