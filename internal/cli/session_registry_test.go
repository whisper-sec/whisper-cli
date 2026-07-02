// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// session_registry_test.go: a one-shot (`whisper ip`, `whisper run`) must DETECT a
// live, locally-held `whisper connect` session for the target /128 and REUSE its proxy —
// never open a competing op:connect (which would replace, and on exit remove, the daemon's
// server-side WG peer, killing the tunnel). Fall-through to a fresh connect stays intact
// when there is no record / a dead record (regression guard).

// stubSessionsDir points the registry at a temp dir and isolates $HOME (so the persisted
// default agent file on a dev box can never leak into a test). Returns a restore func.
func stubSessionsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	saved := sessionsDirFn
	sessionsDirFn = func() string { return dir }
	t.Cleanup(func() { sessionsDirFn = saved })
	t.Setenv("HOME", t.TempDir()) // ReadAgentFile("") must see a clean home, not the dev box's
	return dir
}

// stubProbe pins probeWhisperProxy to a fixed answer and records the probed ports.
func stubProbe(t *testing.T, live bool, ports *[]int) {
	t.Helper()
	saved := probeWhisperProxy
	probeWhisperProxy = func(port int) bool {
		if ports != nil {
			*ports = append(*ports, port)
		}
		return live
	}
	t.Cleanup(func() { probeWhisperProxy = saved })
}

// ownedSession fabricates a session WE own (local != nil), as a held-open connect yields.
type fakeLocal struct{ stopped bool }

func (f *fakeLocal) Endpoint() string { return "socks5h://127.0.0.1:41080" }
func (f *fakeLocal) Addr() string     { return "2a04:2a01:9::abcd" }
func (f *fakeLocal) Stop()            { f.stopped = true }

func ownedSession(addr, endpoint, tier string) *egressSession {
	return &egressSession{endpoint: endpoint, addr: addr, tier: tier, verified: true, local: &fakeLocal{}}
}

func testClient(t *testing.T, url string) *client.Client {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: url, key: "whisper_live_test", timeout: 5 * time.Second}
	t.Cleanup(func() { g = savedG })
	c, err := resolveClient(true, false)
	if err != nil {
		t.Fatalf("resolveClient: %v", err)
	}
	return c
}

// --- the registry itself ------------------------------------------------------------

func TestSessionRecord_WriteReadClearRoundTrip(t *testing.T) {
	dir := stubSessionsDir(t)

	sess := ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard")
	writeSessionRecord(sess)

	recs := readSessionRecords()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Addr != "2a04:2a01:9::abcd" || r.Endpoint != "socks5h://127.0.0.1:41080" ||
		r.Tier != "wireguard" || r.Port != 41080 || r.PID != os.Getpid() {
		t.Fatalf("record round-trip mismatch: %+v", r)
	}
	// No secret shape ever lands on disk (nothing bearer-like in the file).
	b, _ := os.ReadFile(filepath.Join(dir, "2a04_2a01_9__abcd.json"))
	if strings.Contains(string(b), "et_") {
		t.Fatalf("session record must never carry a bearer: %s", b)
	}

	clearSessionRecord(sess)
	if got := readSessionRecords(); len(got) != 0 {
		t.Fatalf("clear must remove the owner's record, still have %+v", got)
	}
}

func TestSessionRecord_ReusedSessionNeverWritesOrClears(t *testing.T) {
	stubSessionsDir(t)

	// A REUSED session (local == nil) must not register itself…
	reused := &egressSession{endpoint: "socks5h://127.0.0.1:41080", addr: "2a04:2a01:9::abcd"}
	writeSessionRecord(reused)
	if got := readSessionRecords(); len(got) != 0 {
		t.Fatalf("a reused session must never write a record, got %+v", got)
	}
	// …and must not unlink the OWNER's record on its own teardown.
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))
	clearSessionRecord(reused)
	if got := readSessionRecords(); len(got) != 1 {
		t.Fatalf("a reused session must never clear the daemon's record, got %+v", got)
	}
}

// --- findLiveSession identity matching ------------------------------------------------

func TestFindLiveSession_MatchingLadder(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	c := testClient(t, srv.URL)

	newRecord := func(addr string) {
		writeSessionRecord(ownedSession(addr, "socks5h://127.0.0.1:41080", "wireguard"))
	}

	t.Run("explicit /128 selector matches (normalized compare)", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		s, ok := findLiveSession(context.Background(), c, "2a04:2a01:0009:0000:0000:0000:0000:abcd")
		if !ok || s.addr != "2a04:2a01:9::abcd" {
			t.Fatalf("expanded-form selector must match the record, ok=%v s=%+v", ok, s)
		}
		if s.local != nil {
			t.Fatal("a reused session must carry local==nil so Stop() is a no-op")
		}
		if s.endpoint != "socks5h://127.0.0.1:41080" || s.tier != "wireguard" {
			t.Fatalf("reused session must carry the record's endpoint+tier, got %+v", s)
		}
	})

	t.Run("a DIFFERENT /128 selector falls through", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		if _, ok := findLiveSession(context.Background(), c, "2a04:2a01:9::dead"); ok {
			t.Fatal("a different /128 must NOT reuse another identity's session")
		}
	})

	t.Run("bare name selector resolves via op:list then matches", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		s, ok := findLiveSession(context.Background(), c, "scout")
		if !ok || s.addr != "2a04:2a01:9::abcd" {
			t.Fatalf("name selector must resolve + match, ok=%v s=%+v", ok, s)
		}
	})

	t.Run("unresolvable name falls through (fail-open)", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		if _, ok := findLiveSession(context.Background(), c, "no-such-agent"); ok {
			t.Fatal("an unresolvable selector must fall through to a fresh connect")
		}
	})

	t.Run("no selector + exactly one record = the live connection", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		if _, ok := findLiveSession(context.Background(), c, ""); !ok {
			t.Fatal("a single held session with no selector must be reused")
		}
	})

	t.Run("no selector + several records is ambiguous — never guess", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		newRecord("2a04:2a01:9::beef")
		if _, ok := findLiveSession(context.Background(), c, ""); ok {
			t.Fatal("multiple held sessions with no selector must fall through, never guess an identity")
		}
	})

	t.Run("persisted default agent file selects among records", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		newRecord("2a04:2a01:9::abcd")
		newRecord("2a04:2a01:9::beef")
		if err := client.SaveAgent("", "2a04:2a01:9::beef"); err != nil {
			t.Fatalf("SaveAgent: %v", err)
		}
		s, ok := findLiveSession(context.Background(), c, "")
		if !ok || s.addr != "2a04:2a01:9::beef" {
			t.Fatalf("the persisted default must pick its record, ok=%v s=%+v", ok, s)
		}
	})

	t.Run("dead record is swept and falls through", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, false, nil) // the daemon crashed / a foreign listener holds the port
		newRecord("2a04:2a01:9::abcd")
		if _, ok := findLiveSession(context.Background(), c, "2a04:2a01:9::abcd"); ok {
			t.Fatal("a dead record must not be reused")
		}
		if got := readSessionRecords(); len(got) != 0 {
			t.Fatalf("a dead record must be lazily swept, still have %+v", got)
		}
	})

	t.Run("empty registry is instant fall-through", func(t *testing.T) {
		stubSessionsDir(t)
		stubProbe(t, true, nil)
		if _, ok := findLiveSession(context.Background(), c, "2a04:2a01:9::abcd"); ok {
			t.Fatal("no records ⇒ no reuse")
		}
	})
}

// --- the one-shot surfaces -----------------------------------------------------------

// TestIP_ReusesLiveDaemonSession: with a live held session for the /128, `whisper ip`
// verifies THROUGH the daemon's proxy and never issues its own op:connect — the call
// counter on the control-plane stub stays free of "connect" (no competing session), and
// the reused session's Stop() (local==nil) cannot touch the daemon's tunnel.
func TestIP_ReusesLiveDaemonSession(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard"))

	// The verify seam: `ip` still verifies through the REUSED endpoint (that's its job).
	savedVerify := verifyEgress
	var verifiedEndpoint string
	verifyEgress = func(_ context.Context, _ *client.Client, s *egressSession) error {
		verifiedEndpoint = s.endpoint
		s.verified = true
		return nil
	}
	defer func() { verifyEgress = savedVerify }()

	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		cmd := newIPCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("ip over a reused session must exit 0, got %v", err)
		}
	})
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("`whisper ip` must NOT open a competing op:connect when reusing, ops=%v", opsSeen(seen))
	}
	if verifiedEndpoint != "socks5h://127.0.0.1:41080" {
		t.Fatalf("ip must verify THROUGH the daemon's endpoint, verified via %q", verifiedEndpoint)
	}
	if !strings.Contains(stdout, "2a04:2a01:9::abcd") || !strings.Contains(stdout, "✓ egress verified") {
		t.Fatalf("expected the verified line, stdout=%q", stdout)
	}
}

// TestIP_FallsBackToFreshConnectWhenRecordDead: a stale record (probe fails) must not
// change today's behavior — op:connect runs exactly as before (regression guard).
func TestIP_FallsBackToFreshConnectWhenRecordDead(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, false, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))

	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()
	defer ipStub(t, "2a04:2a01:9::abcd")() // the fresh-connect tail (stubbed live egress)

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	captureStd(t, func() {
		cmd := newIPCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--agent", "2a04:2a01:9::abcd"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("fallback ip must exit 0, got %v", err)
		}
	})
	if !containsOp(opsSeen(seen), "connect") {
		t.Fatalf("a dead record must fall through to the fresh op:connect path, ops=%v", opsSeen(seen))
	}
}

// TestRun_ReusesLiveDaemonSessionAndInjectsItsEndpoint: `whisper run` routes the child
// through the DAEMON's endpoint (ALL_PROXY == the record's endpoint) and never op:connects.
func TestRun_ReusesLiveDaemonSessionAndInjectsItsEndpoint(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard"))

	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, _ := captureStd(t, func() {
		if err := runWithEgress("2a04:2a01:9::abcd", "", "", "sh", []string{"-c", "printf '%s' \"$ALL_PROXY\""}); err != nil {
			t.Errorf("run over a reused session must succeed, got %v", err)
		}
	})
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("`whisper run` must NOT open a competing op:connect when reusing, ops=%v", opsSeen(seen))
	}
	if stdout != "socks5h://127.0.0.1:41080" {
		t.Fatalf("the child must inherit the DAEMON's endpoint, got %q", stdout)
	}
}

// TestRun_TierMismatchStillReusesWithOneNote: an explicit different --tier must NOT clobber
// the live tunnel — it reuses and says so once on stderr.
func TestRun_TierMismatchStillReusesWithOneNote(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard"))

	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	_, stderr := captureStd(t, func() {
		if err := runWithEgress("2a04:2a01:9::abcd", "", "socks5", "sh", []string{"-c", "true"}); err != nil {
			t.Errorf("tier-mismatch reuse must still succeed, got %v", err)
		}
	})
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("a tier mismatch must reuse, never clobber, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(stderr, "reusing your live wireguard connection") {
		t.Fatalf("expected ONE calm reuse note on stderr, got %q", stderr)
	}
}

// TestGuided_QuietReusesLiveDaemonSession: the guided front door's headless/quiet branch
// prints the DAEMON's endpoint and tears nothing down (Stop() is the nil-local no-op).
func TestGuided_QuietReusesLiveDaemonSession(t *testing.T) {
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))

	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}}, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	var out, errw strings.Builder
	gio := guidedIO{in: nil, out: &out, err: &errw}
	err := connectVia(
		guidedOptions{quiet: true},
		gio,
		agentChoice{name: "scout", addr: "2a04:2a01:9::abcd"})
	if err != nil {
		t.Fatalf("guided quiet reuse must succeed, got %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("guided must NOT open a competing op:connect when reusing, ops=%v", opsSeen(seen))
	}
	if strings.TrimSpace(out.String()) != "socks5h://127.0.0.1:41080" {
		t.Fatalf("quiet guided must print ONLY the daemon's endpoint, got %q", out.String())
	}
}

// endpointPort is load-bearing for the probe — pin its parsing.
func TestEndpointPort(t *testing.T) {
	cases := map[string]int{
		"socks5h://127.0.0.1:41080": 41080,
		"http://127.0.0.1:1080":     1080,
		"127.0.0.1:53":              53,
		"socks5h://127.0.0.1":       0,
		"":                          0,
		"socks5h://127.0.0.1:0":     0,
		"socks5h://127.0.0.1:99999": 0,
	}
	for in, want := range cases {
		if got := endpointPort(in); got != want {
			t.Fatalf("endpointPort(%q) = %d, want %d", in, got, want)
		}
	}
}
