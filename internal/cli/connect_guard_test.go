// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// recordingServer stubs the control plane for the connect/create command tests: it records
// every (op, rawBody) it sees so a test can assert WHICH op ran and with WHICH args, and it
// replies sensibly per op. `agents` is what op:list returns (so we can simulate a fresh
// account = nil, or an existing fleet). It NEVER auto-creates anything itself — the point of
// these tests is that the CLI must not silently fire an unnamed create.
type recordedCall struct {
	op   string
	body string
}

// stubEgressTail replaces the WB3 live-egress tail (local proxy bring-up + network echo
// verify) and the persistent hold with in-memory no-ops, so a connect command test runs
// to completion with no real network and no signal park. It returns a restore func.
func stubEgressTail(t *testing.T) func() {
	t.Helper()
	savedConnect := connectAndVerify
	savedHold := holdUntilSignal
	connectAndVerify = func(_ context.Context, _ *client.Client, res *client.Result, name string, _ *wgtun.Keypair) (*egressSession, error) {
		ce, err := parseConnectEnvelope(res)
		if err != nil {
			return nil, err
		}
		return &egressSession{endpoint: "socks5h://127.0.0.1:1080", addr: ce.address, name: name, tier: firstNonBlank(ce.tier, "socks5"), verified: true}, nil
	}
	holdUntilSignal = func(sess *egressSession) { sess.Stop() } // never park on a signal in a test
	return func() { connectAndVerify = savedConnect; holdUntilSignal = savedHold }
}

func recordingServer(t *testing.T, agents []agentChoice, seen *[]recordedCall) *httptest.Server {
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
		case "identity":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["label","address"],"rows":[["created-name","2a04:2a01:9::abcd"]]}}`))
		case "register":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","address","api_key"],"rows":[["ag_1","2a04:2a01:9::beef","whisper_live_oncekey"]]}}`))
		case "connect":
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["tier","address","http_proxy","socks5_endpoint","connection_string"],"rows":[["socks5","2a04:2a01:9::abcd","https://w:et_testbearer@egress.whisper.online:443","egress.whisper.online:443","socks5h://w:et_testbearer@egress.whisper.online:443"]]}}`))
		default: // list
			_, _ = w.Write([]byte(listJSON(agents)))
		}
	}))
}

func opsSeen(seen []recordedCall) []string {
	out := make([]string, 0, len(seen))
	for _, c := range seen {
		out = append(out, c.op)
	}
	return out
}

func bodyForOp(seen []recordedCall, op string) (string, bool) {
	for _, c := range seen {
		if c.op == op {
			return c.body, true
		}
	}
	return "", false
}

// --- Fix #3: `whisper connect` no-name, no-TTY, fresh account → clear error, no unnamed create.
//
// A fresh account (op:list → 0 agents) with no --agent and no --name on a non-interactive
// run must NOT fire op:connect (which would auto-allocate an UNNAMED /128). It must fail with
// a clear usage error and create NOTHING.
func TestConnect_NoNameNoTTYFreshAccount_ErrorsNoUnnamedCreate(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen) // nil ⇒ fresh account
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent") // absent ⇒ no persisted selector
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent-file", af})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("connect on a fresh account with no --name and no TTY must error, not auto-create")
	}
	if !isUsageError(err) {
		t.Fatalf("expected a usage error, got %v", err)
	}
	// The control plane must have been ASKED to list (to discover the fresh account) but
	// NEVER asked to identity (create) or connect (which would mint an unnamed /128).
	if containsOp(opsSeen(seen), "identity") || containsOp(opsSeen(seen), "connect") {
		t.Fatalf("connect must not create/connect for a no-name fresh account, ops=%v", opsSeen(seen))
	}
}

// --- Fix #4: connect --name scout → the agent LABEL is scout (not a friendly_name-only,
// unnamed agent). On a fresh account, the created identity must carry label:'scout', and the
// query must NOT carry the old friendly_name spelling.
func TestConnect_NameMapsToLabelNotFriendlyName(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen) // fresh account ⇒ connect must create a NAMED agent
	defer srv.Close()
	defer stubEgressTail(t)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent") // absent ⇒ no persisted selector
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--name", "scout", "--agent-file", af})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("connect --name scout (fresh account) errored: %v", err)
	}
	body, ok := bodyForOp(seen, "identity")
	if !ok {
		t.Fatalf("expected a named create (op:identity) for a fresh account, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "label:'scout'") {
		t.Fatalf("--name must map to the agent LABEL; create body = %q", body)
	}
	if strings.Contains(body, "friendly_name") {
		t.Fatalf("--name must NOT set friendly_name (that left the agent unnamed); body = %q", body)
	}
}

// Sibling: with an EXISTING agent, connect must NOT create anything — it binds egress to the
// fleet (the zero-config reuse path stays intact; the guard only fires for a fresh account).
func TestConnect_ExistingAgent_NoCreate(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent") // absent ⇒ exercise the list→existing-fleet path
	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent-file", af})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("connect with an existing agent errored: %v", err)
	}
	if containsOp(opsSeen(seen), "identity") {
		t.Fatalf("connect must NOT create when the caller already has an agent, ops=%v", opsSeen(seen))
	}
	if !containsOp(opsSeen(seen), "connect") {
		t.Fatalf("connect with an existing agent must fire op:connect, ops=%v", opsSeen(seen))
	}
}

// --- Fix #6: `create --register --quiet` prints EXACTLY the address on stdout, no chrome.
//
// Mirrors the identity path's quiet short-circuit: under --quiet, --register must emit ONLY
// the load-bearing value (the address) on stdout and nothing on stderr.
func TestCreateRegister_Quiet_OnlyAddressNoChrome(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() {
		cmd := newCreateCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--register", "--name", "scout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("create --register --quiet errored: %v", err)
		}
	})
	if strings.TrimSpace(stdout) != "2a04:2a01:9::beef" {
		t.Fatalf("quiet --register stdout = %q, want ONLY the address", stdout)
	}
	// No chrome: the once-shown key note, the "identity ready" block, etc. must all be gone.
	if stderr != "" {
		t.Fatalf("quiet --register must emit NO chrome on stderr, got %q", stderr)
	}
	// And specifically the once-only API key must NOT leak to stdout under quiet.
	if strings.Contains(stdout, "whisper_live_oncekey") {
		t.Fatalf("quiet --register must print only the address, not the API key; stdout=%q", stdout)
	}
}
