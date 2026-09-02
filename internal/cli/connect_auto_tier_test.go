// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// These tests cover the AUTO tier negotiation: `whisper connect` with NO --tier tries
// Tier-1 (WireGuard) first under a short bound and auto-downgrades to Tier-1.5 (SOCKS5)
// on ANY failure, printing the tier it landed on; both tiers failing yields exactly ONE
// helpful error; an explicit --tier is forced with no downgrade.

// wgConnectReplyJSON is a valid tier:wireguard op:connect envelope (the same shape
// wireguardRecordingServer serves).
func wgConnectReplyJSON() string {
	srvPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return `{"ok":true,"status":200,"result":{` +
		`"columns":["tier","wireguard_config","server_public_key","endpoint","client_public_key","client_private_key","address","allowed_ips","fqdn","ptr","dns","note"],` +
		`"rows":[["wireguard","[Interface]\nAddress = 2a04:2a01:9::abcd/128\nDNS = 2a04:2a01:0:53::1\n\n[Peer]\nPublicKey = ` + srvPub + `\nEndpoint = box.example:51826\nAllowedIPs = ::/0\nPersistentKeepalive = 25\n",` +
		`"` + srvPub + `","box.example:51826","wg-client-pub","","2a04:2a01:9::abcd","2a04:2a01:9::abcd/128","scout.agents.example","...","2a04:2a01:0:53::1","Tier-1 routed WireGuard"]]}}`
}

// s5ConnectReplyJSON is a valid tier:socks5 op:connect envelope (the recordingServer shape).
func s5ConnectReplyJSON() string {
	return `{"ok":true,"status":200,"result":{"columns":["tier","address","http_proxy","socks5_endpoint","connection_string"],` +
		`"rows":[["socks5","2a04:2a01:9::abcd","https://w:et_testbearer@egress.whisper.online:443","egress.whisper.online:443","socks5h://w:et_testbearer@egress.whisper.online:443"]]}}`
}

// autoTierServer stubs the control plane for the negotiation tests: op:list returns one
// existing agent (so connect binds it without a create), and op:connect answers wgReply
// for a tier:'wireguard' body and s5Reply otherwise - so a test can independently make
// either leg succeed or fail at the control plane.
func autoTierServer(t *testing.T, seen *[]recordedCall, wgReply, s5Reply string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		op := sniffOp(string(raw))
		if seen != nil {
			*seen = append(*seen, recordedCall{op: op, body: string(raw)})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch op {
		case "connect":
			if strings.Contains(string(raw), "tier:'wireguard'") {
				_, _ = w.Write([]byte(wgReply))
			} else {
				_, _ = w.Write([]byte(s5Reply))
			}
		default: // list
			_, _ = w.Write([]byte(listJSON([]agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}})))
		}
	}))
}

// stubTierAwareTail replaces the live-egress tail (connectAndVerify) with a stub whose
// behaviour depends on the envelope's tier: the WireGuard leg fails with wgErr when
// non-nil (or, with blockWg, parks until the attempt ctx expires - a hung handshake),
// while the socks5 leg always succeeds. The hold is also stubbed. Restores on return.
func stubTierAwareTail(t *testing.T, wgErr error, blockWg bool) func() {
	t.Helper()
	savedConnect := connectAndVerify
	savedHold := holdUntilSignal
	connectAndVerify = func(cx context.Context, _ *client.Client, res *client.Result, name string, _ *connectKeys) (*egressSession, error) {
		ce, err := parseConnectEnvelope(res)
		if err != nil {
			return nil, err
		}
		if ce.isWireGuard() {
			if blockWg {
				<-cx.Done() // a hung handshake: only the attempt bound ends it
				return nil, cx.Err()
			}
			if wgErr != nil {
				return nil, wgErr
			}
		}
		return &egressSession{endpoint: "socks5h://127.0.0.1:1080", addr: ce.address, name: name, tier: firstNonBlank(ce.tier, "socks5"), verified: true}, nil
	}
	holdUntilSignal = func(sess *egressSession) { sess.Stop() }
	return func() { connectAndVerify = savedConnect; holdUntilSignal = savedHold }
}

// runAutoConnect executes `whisper connect` (no --tier unless passed in extra) against
// srv with an isolated agent file + identity dir, capturing output.
func runAutoConnect(t *testing.T, srv *httptest.Server, extra ...string) (stdout, stderr string, err error) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()
	defer idkey.SetIdentityDirForTest(t.TempDir())()

	af := filepath.Join(t.TempDir(), "agent")
	args := append([]string{"--agent-file", af}, extra...)
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	stdout, stderr = captureStd(t, func() { err = cmd.Execute() })
	return stdout, stderr, err
}

// TestIsAutoTier: the empty default and the explicit "auto" spelling (any case, padded)
// select negotiation; every explicit tier does not.
func TestIsAutoTier(t *testing.T) {
	for _, in := range []string{"", "  ", "auto", "AUTO", " Auto "} {
		if !isAutoTier(in) {
			t.Fatalf("isAutoTier(%q) must be true", in)
		}
	}
	for _, in := range []string{"socks5", "wireguard", "wg", "anyip", "bogus"} {
		if isAutoTier(in) {
			t.Fatalf("isAutoTier(%q) must be false (explicit tiers are forced)", in)
		}
	}
}

// TestConnectAuto_WireGuardSucceeds_LandsTier1 is the happy path: with no --tier the
// FIRST attempt is Tier-1 (op:connect carries tier:'wireguard' + both public keys), it
// succeeds, no socks5 attempt ever runs, and the ONE success line names the landed tier
// and the local proxy string.
func TestConnectAuto_WireGuardSucceeds_LandsTier1(t *testing.T) {
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	stdout, stderr, err := runAutoConnect(t, srv)
	if err != nil {
		t.Fatalf("auto connect (WG healthy) errored: %v", err)
	}
	var connects []string
	for _, c := range seen {
		if c.op == "connect" {
			connects = append(connects, c.body)
		}
	}
	if len(connects) != 1 {
		t.Fatalf("a healthy Tier-1 must take exactly ONE op:connect, got %d (%v)", len(connects), opsSeen(seen))
	}
	if !strings.Contains(connects[0], "tier:'wireguard'") {
		t.Fatalf("the first (and only) attempt must ask for tier:'wireguard'; body=%q", connects[0])
	}
	if !strings.Contains(connects[0], "public_key:") || !strings.Contains(connects[0], "identity_public_key:") {
		t.Fatalf("the Tier-1 attempt must carry the WG + identity public keys; body=%q", connects[0])
	}
	// ONE line, naming the landed tier + the local proxy string.
	if n := strings.Count(strings.TrimRight(stderr, "\n"), "\n"); n != 0 {
		t.Fatalf("the success output must be ONE line, got extra newlines: %q", stderr)
	}
	if !strings.Contains(stderr, "Tier-1 wireguard") {
		t.Fatalf("the success line must name the landed tier, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "socks5h://127.0.0.1:1080") {
		t.Fatalf("the success line must carry the local proxy string, stderr=%q", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("default stdout must stay empty, got %q", stdout)
	}
}

// TestConnectAuto_WgFailureModes_DowngradeToTier15 drives EVERY Tier-1 failure class -
// the control plane rejecting the tier, the tunnel bring-up/verify failing, a hung
// handshake hitting the attempt bound, and local key prep failing - and asserts each one
// downgrades CLEANLY to Tier-1.5: the command succeeds, the retry asks for tier:'socks5'
// with NO leaked WG args, the landed tier is printed, and the Tier-1 failure is silent
// (debug-only, never an error).
func TestConnectAuto_WgFailureModes_DowngradeToTier15(t *testing.T) {
	okWg := wgConnectReplyJSON()
	rejectedWg := `{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`

	cases := []struct {
		name          string
		wgReply       string
		tailWgErr     error
		tailBlockWg   bool
		stubKeyPrep   bool
		wantWgAttempt bool // whether a tier:'wireguard' op:connect reaches the wire at all
	}{
		{"control plane rejects the tier", rejectedWg, nil, false, false, true},
		{"tunnel bring-up/verify fails", okWg, &client.ProblemError{Status: 502, Detail: "could not bring up the WireGuard tunnel - please try again"}, false, false, true},
		{"hung handshake hits the attempt bound", okWg, nil, true, false, true},
		{"local key prep fails", okWg, nil, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tailBlockWg {
				savedTO := tier1AttemptTimeout
				// The bound has to outlast one local HTTP round trip and nothing more: the tail
				// stub blocks only AFTER op:connect has answered, so the assertion below is that
				// the wireguard op REACHED the wire. 60ms did not survive a loaded build machine
				// (the round trip missed its slot and the test read a starved scheduler as a
				// missing op), so it is a budget the assertion can rely on rather than the
				// smallest number that passed on an idle box.
				tier1AttemptTimeout = 750 * time.Millisecond
				defer func() { tier1AttemptTimeout = savedTO }()
			}
			if tc.stubKeyPrep {
				savedPrep := prepareWireGuard
				prepareWireGuard = func(tier string, args map[string]any) (*wgtun.Keypair, error) {
					if isWireGuardTier(tier) {
						return nil, &client.ProblemError{Status: 500, Detail: "couldn't prepare a WireGuard key - please try again"}
					}
					return nil, nil
				}
				defer func() { prepareWireGuard = savedPrep }()
			}
			var seen []recordedCall
			srv := autoTierServer(t, &seen, tc.wgReply, s5ConnectReplyJSON())
			defer srv.Close()
			defer stubTierAwareTail(t, tc.tailWgErr, tc.tailBlockWg)()

			_, stderr, err := runAutoConnect(t, srv)
			if err != nil {
				t.Fatalf("auto connect must downgrade cleanly, not error: %v", err)
			}
			var wgBodies, s5Bodies []string
			for _, c := range seen {
				if c.op != "connect" {
					continue
				}
				if strings.Contains(c.body, "tier:'wireguard'") {
					wgBodies = append(wgBodies, c.body)
				} else {
					s5Bodies = append(s5Bodies, c.body)
				}
			}
			if got := len(wgBodies) > 0; got != tc.wantWgAttempt {
				t.Fatalf("wireguard op:connect on the wire = %v, want %v (ops=%v)", got, tc.wantWgAttempt, opsSeen(seen))
			}
			if len(s5Bodies) != 1 {
				t.Fatalf("the downgrade must take exactly ONE socks5 op:connect, got %d", len(s5Bodies))
			}
			// Args isolation: the Tier-1 attempt's keys must never bleed into the retry.
			if !strings.Contains(s5Bodies[0], "tier:'socks5'") {
				t.Fatalf("the retry must ask for tier:'socks5'; body=%q", s5Bodies[0])
			}
			if strings.Contains(s5Bodies[0], "public_key") || strings.Contains(s5Bodies[0], "identity_public_key") {
				t.Fatalf("the socks5 retry must carry NO WireGuard/identity args; body=%q", s5Bodies[0])
			}
			// The landed tier is printed; the Tier-1 failure is not (debug-only).
			if !strings.Contains(stderr, "Tier-1.5 socks5") {
				t.Fatalf("the success line must name the landed Tier-1.5, stderr=%q", stderr)
			}
			if strings.Contains(stderr, "whisper[debug]") {
				t.Fatalf("the downgrade must be silent without WHISPER_DEBUG, stderr=%q", stderr)
			}
		})
	}
}

// TestConnectAuto_DebugLogsTheDowngrade: with WHISPER_DEBUG set, the Tier-1 failure is
// logged (typed: tier + cause) - and ONLY then; the default run stays silent (covered
// above). The downgrade still lands on Tier-1.5 either way.
func TestConnectAuto_DebugLogsTheDowngrade(t *testing.T) {
	t.Setenv("WHISPER_DEBUG", "1")
	srv := autoTierServer(t, nil, `{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`, s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, stderr, err := runAutoConnect(t, srv)
	if err != nil {
		t.Fatalf("auto connect errored: %v", err)
	}
	if !strings.Contains(stderr, "whisper[debug]: auto tier: wireguard:") {
		t.Fatalf("WHISPER_DEBUG must log the typed Tier-1 failure, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "Tier-1.5 socks5") {
		t.Fatalf("the landed tier line must still print, stderr=%q", stderr)
	}
}

// TestConnectAuto_BothTiersFail_OneHelpfulError: when the two tiers fail for DIFFERENT
// reasons, exactly ONE combined, actionable error names both causes - never two stacked
// errors, never an opaque one. (502 details pass through friendly() verbatim; statuses
// with their own mapped guidance, like 503, surface as that guidance instead - equally
// helpful, covered by the fixture choice here.)
func TestConnectAuto_BothTiersFail_OneHelpfulError(t *testing.T) {
	srv := autoTierServer(t, nil,
		`{"ok":false,"status":502,"error":"the wireguard peer did not answer"}`,
		`{"ok":false,"status":502,"error":"no capacity right now - try again shortly"}`)
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, _, err := runAutoConnect(t, srv)
	if err == nil {
		t.Fatal("both tiers failing must surface an error")
	}
	pe, ok := client.AsProblem(err)
	if !ok {
		t.Fatalf("expected a *client.ProblemError, got %T: %v", err, err)
	}
	for _, want := range []string{"wireguard", "socks5", "peer did not answer", "no capacity", "whisper connect"} {
		if !strings.Contains(pe.Error(), want) {
			t.Fatalf("the combined error must be helpful (mention %q), got: %v", want, err)
		}
	}
	if strings.Count(pe.Error(), "couldn't connect on any tier") != 1 {
		t.Fatalf("exactly ONE combined error line, got: %v", err)
	}
}

// TestConnectAuto_BothTiersFailSameCause_SurfacesTheRealError: an identical failure on
// both tiers (a stale agent, a rejected key) is tier-independent - the ORIGINAL problem
// surfaces as itself, preserving its status and detail (never wrapped into a generic
// combined line a script can't key off).
func TestConnectAuto_BothTiersFailSameCause_SurfacesTheRealError(t *testing.T) {
	notFound := `{"ok":false,"status":404,"error":"agent 2a04:2a01:9::dead not found"}`
	srv := autoTierServer(t, nil, notFound, notFound)
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, _, err := runAutoConnect(t, srv)
	if err == nil {
		t.Fatal("both tiers failing must surface an error")
	}
	pe, ok := client.AsProblem(err)
	if !ok || pe.Status != 404 {
		t.Fatalf("the original problem (404) must surface as itself, got %v", err)
	}
	if !strings.Contains(pe.Error(), "not found") {
		t.Fatalf("the original detail must be preserved, got: %v", err)
	}
	if strings.Contains(pe.Error(), "couldn't connect on any tier") {
		t.Fatalf("a tier-independent cause must NOT be wrapped in the combined line: %v", err)
	}
}

// TestConnect_ExplicitTier_Forced_NoDowngrade: an explicit --tier wireguard that fails
// must ERROR - never silently downgrade - and must never put a socks5 attempt on the
// wire. The forced-tier contract is exact.
func TestConnect_ExplicitTier_Forced_NoDowngrade(t *testing.T) {
	var seen []recordedCall
	srv := autoTierServer(t, &seen,
		`{"ok":false,"status":503,"error":"the wireguard tier is unavailable on this box"}`,
		s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, _, err := runAutoConnect(t, srv, "--tier", "wireguard")
	if err == nil {
		t.Fatal("a failing explicit --tier wireguard must error, not downgrade")
	}
	if !strings.Contains(err.Error(), "unavailable on this box") {
		t.Fatalf("the forced tier's real failure must surface, got: %v", err)
	}
	for _, c := range seen {
		if c.op == "connect" && !strings.Contains(c.body, "tier:'wireguard'") {
			t.Fatalf("an explicit --tier must NEVER fall back to another tier; body=%q", c.body)
		}
	}
}

// TestConnect_ExplicitSocks5_NeverTriesWireGuard: an explicit --tier socks5 goes straight
// to Tier-1.5 (no WG keys minted, no wireguard attempt) and keeps the classic one-line
// success (no landed-tier note - the user chose, so there is nothing to announce).
func TestConnect_ExplicitSocks5_NeverTriesWireGuard(t *testing.T) {
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, stderr, err := runAutoConnect(t, srv, "--tier", "socks5")
	if err != nil {
		t.Fatalf("connect --tier socks5 errored: %v", err)
	}
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("op:connect must run, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "tier:'socks5'") || strings.Contains(body, "public_key") {
		t.Fatalf("an explicit socks5 must carry tier:'socks5' and no WG keys; body=%q", body)
	}
	if strings.Contains(stderr, " via ") {
		t.Fatalf("a forced tier keeps the classic success line (no landed-tier note), stderr=%q", stderr)
	}
}

// TestConnect_ExplicitAutoSpelling: `--tier auto` is the same negotiation as no flag at
// all (Postel: accept the explicit spelling of the default).
func TestConnect_ExplicitAutoSpelling(t *testing.T) {
	var seen []recordedCall
	srv := autoTierServer(t, &seen, wgConnectReplyJSON(), s5ConnectReplyJSON())
	defer srv.Close()
	defer stubTierAwareTail(t, nil, false)()

	_, stderr, err := runAutoConnect(t, srv, "--tier", "auto")
	if err != nil {
		t.Fatalf("connect --tier auto errored: %v", err)
	}
	body, ok := bodyForOp(seen, "connect")
	if !ok || !strings.Contains(body, "tier:'wireguard'") {
		t.Fatalf("--tier auto must negotiate (Tier-1 first); body=%q ops=%v", body, opsSeen(seen))
	}
	if !strings.Contains(stderr, "Tier-1 wireguard") {
		t.Fatalf("--tier auto must print the landed tier, stderr=%q", stderr)
	}
}

// TestWriteSuccessLine_NegotiatedNamesLandedTier: the negotiated success line stays ONE
// line and gains the landed tier + local proxy string; a non-negotiated (forced) session
// keeps the classic line untouched.
func TestWriteSuccessLine_NegotiatedNamesLandedTier(t *testing.T) {
	base := func(tier string, negotiated bool) *egressSession {
		return &egressSession{
			endpoint:   "socks5h://127.0.0.1:1080",
			addr:       "2a04:2a01:4::7",
			name:       "scout",
			tier:       tier,
			verified:   true,
			negotiated: negotiated,
		}
	}
	var sb strings.Builder
	writeSuccessLine(io.Discard, &sb, base("wireguard", true), false)
	line := sb.String()
	if strings.Count(strings.TrimRight(line, "\n"), "\n") != 0 {
		t.Fatalf("the negotiated success output must stay ONE line: %q", line)
	}
	for _, want := range []string{"Connected as scout", "✓ verified", "via Tier-1 wireguard (routed /128)", "socks5h://127.0.0.1:1080"} {
		if !strings.Contains(line, want) {
			t.Fatalf("negotiated WG line must contain %q, got %q", want, line)
		}
	}

	sb.Reset()
	writeSuccessLine(io.Discard, &sb, base("socks5", true), false)
	if !strings.Contains(sb.String(), "via Tier-1.5 socks5 egress") {
		t.Fatalf("negotiated socks5 line must name Tier-1.5, got %q", sb.String())
	}

	sb.Reset()
	writeSuccessLine(io.Discard, &sb, base("wireguard", false), false)
	if strings.Contains(sb.String(), " via ") {
		t.Fatalf("a forced (non-negotiated) session keeps the classic line, got %q", sb.String())
	}

	// --quiet stays exactly the endpoint, negotiated or not (scripts capture one value).
	var out strings.Builder
	writeSuccessLine(&out, io.Discard, base("wireguard", true), true)
	if out.String() != "socks5h://127.0.0.1:1080\n" {
		t.Fatalf("quiet output must be exactly the endpoint, got %q", out.String())
	}
}

// TestFriendlyAttemptErr: the bounded attempt's context errors map to plain words, and
// everything else keeps the friendly rendering - never Go's opaque context strings.
func TestFriendlyAttemptErr(t *testing.T) {
	if got := friendlyAttemptErr(context.DeadlineExceeded); got != "timed out" {
		t.Fatalf("DeadlineExceeded must render as 'timed out', got %q", got)
	}
	if got := friendlyAttemptErr(context.Canceled); got != "cancelled" {
		t.Fatalf("Canceled must render as 'cancelled', got %q", got)
	}
	if got := friendlyAttemptErr(errors.New("plain cause")); got != "plain cause" {
		t.Fatalf("a plain error must keep its message, got %q", got)
	}
}
