// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// TestResolveAgentSelector covers the #110 op:connect agent-selection precedence:
//
//	--agent flag  >  ~/.config/whisper-ns/agent file  >  "" (server reuse-most-recent default)
//
// Table-driven: each case sets up an (optional) agent file and a flag value, then asserts
// the selector the CLI would send as the op:connect `agent` arg ("" ⇒ omit the arg entirely).
func TestResolveAgentSelector(t *testing.T) {
	dir := t.TempDir()
	withFile := filepath.Join(dir, "agent")
	if err := os.WriteFile(withFile, []byte("a-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blankFile := filepath.Join(dir, "blank")
	if err := os.WriteFile(blankFile, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent")

	cases := []struct {
		name      string
		flagAgent string
		agentFile string
		want      string
	}{
		{"flag wins over file", "a-from-flag", withFile, "a-from-flag"},
		{"flag is trimmed", "  a-from-flag  ", withFile, "a-from-flag"},
		{"flag wins when file absent", "a-from-flag", absent, "a-from-flag"},
		{"file used when no flag", "", withFile, "a-from-file"},
		{"blank flag falls through to file", "   ", withFile, "a-from-file"},
		{"absent file + no flag => empty (most-recent default)", "", absent, ""},
		{"blank file + no flag => empty", "", blankFile, ""},
		{"address selector via flag passes through", "2a04:2a01:9::dead", absent, "2a04:2a01:9::dead"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveAgentSelector(tc.flagAgent, tc.agentFile); got != tc.want {
				t.Fatalf("resolveAgentSelector(%q, file=%q) = %q, want %q",
					tc.flagAgent, tc.agentFile, got, tc.want)
			}
		})
	}
}

// captureStd redirects os.Stdout + os.Stderr around fn and returns what each captured.
// renderConnect writes straight to the process streams (the human/machine split), so we
// capture the real fds to assert the lean contract exactly.
func captureStd(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	bo, _ := io.ReadAll(rOut)
	be, _ := io.ReadAll(rErr)
	return string(bo), string(be)
}

// connectResult is a tiny op:connect result with the load-bearing fields (incl. the
// secret-carrying http_proxy / connection_string, so a test can prove the bearer is
// extracted INTERNALLY and never surfaced).
func connectResult() *client.Result {
	return &client.Result{
		Columns: []string{"tier", "address", "fqdn", "http_proxy", "socks5_endpoint", "connection_string", "dns", "doh_url", "tls", "note"},
		Rows: [][]any{{
			"socks5", "2a04:2a01:4::7", "scout.agents.example",
			"https://w:et_secretbearer@egress.whisper.online:443",
			"egress.whisper.online:443",
			"socks5h://w:et_secretbearer@egress.whisper.online:443",
			"2a04:2a00::53", "https://doh", "on", "ready",
		}},
	}
}

// fakeSession is a verified session with a bearer-free local endpoint, as connectAndVerify
// would yield. It carries NO bearer (the whole point — the bearer stays in the proxy).
func fakeSession() *egressSession {
	return &egressSession{
		endpoint: "socks5h://127.0.0.1:1080",
		addr:     "2a04:2a01:4::7",
		name:     "scout",
		verified: true,
	}
}

// TestRenderConnect_LeanDefaultOneLine: the default path is ONE ✓-verified line on
// stderr and NOTHING on stdout (the bearer-free endpoint is not echoed on the happy path).
func TestRenderConnect_LeanDefaultOneLine(t *testing.T) {
	savedG := g
	g = globalFlags{}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() { renderConnect(fakeSession(), false) })

	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("default stdout must be empty (only --quiet prints the endpoint), got %q", stdout)
	}
	if n := strings.Count(strings.TrimRight(stderr, "\n"), "\n"); n != 0 {
		t.Fatalf("default stderr must be ONE line, got %d extra newlines: %q", n, stderr)
	}
	if !strings.Contains(stderr, "Connected as scout") || !strings.Contains(stderr, "✓ verified") {
		t.Fatalf("expected the one-line ✓-verified message, stderr=%q", stderr)
	}
}

// TestRenderConnect_QuietOnlyValue: --quiet prints EXACTLY the bearer-free local endpoint
// on stdout and absolutely nothing on stderr.
func TestRenderConnect_QuietOnlyValue(t *testing.T) {
	savedG := g
	g = globalFlags{quiet: true}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() { renderConnect(fakeSession(), false) })

	if stdout != "socks5h://127.0.0.1:1080\n" {
		t.Fatalf("quiet stdout = %q, want exactly the local endpoint + newline", stdout)
	}
	if stderr != "" {
		t.Fatalf("quiet must emit NO chrome, stderr=%q", stderr)
	}
}

// TestRenderConnect_VerboseLocalDetailNoBearer: --verbose adds the LOCAL endpoint detail
// only — never a server proxy string, and NEVER the bearer (§4.4 bearer hygiene).
func TestRenderConnect_VerboseLocalDetailNoBearer(t *testing.T) {
	savedG := g
	g = globalFlags{}
	defer func() { g = savedG }()

	stdout, stderr := captureStd(t, func() { renderConnect(fakeSession(), true) })
	if !strings.Contains(stderr, "socks5h://127.0.0.1:1080") {
		t.Fatalf("--verbose must show the LOCAL endpoint, stderr=%q", stderr)
	}
	for _, leak := range []string{"et_secretbearer", "egress.whisper.online", "http_proxy", "connection_string", "doh_url"} {
		if strings.Contains(stdout+stderr, leak) {
			t.Fatalf("--verbose leaked %q — bearer/server-field hygiene violated: out=%q err=%q", leak, stdout, stderr)
		}
	}
}

// TestConnect_BearerNeverInOutput: run the FULL connect command (verbose + quiet) against
// a control plane whose op:connect carries an et_ bearer in http_proxy/connection_string,
// and grep ALL output for the bearer / server proxy host. It must NEVER appear — this is
// the load-bearing §4.4 bearer-hygiene guarantee.
func TestConnect_BearerNeverInOutput(t *testing.T) {
	// "json" is the load-bearing case here: the raw op:connect envelope carries the et_
	// bearer in http_proxy/connection_string, so a naive --json dump would leak it. connect
	// must emit a sanitized, bearer-free shape instead.
	for _, mode := range []string{"default", "verbose", "quiet", "json"} {
		t.Run(mode, func(t *testing.T) {
			var seen []recordedCall
			srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, &seen)
			defer srv.Close()
			defer stubEgressTail(t)()

			savedG := g
			g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: mode == "quiet", jsonOut: mode == "json", timeout: 5 * time.Second}
			defer func() { g = savedG }()

			af := filepath.Join(t.TempDir(), "agent")
			args := []string{"--agent-file", af}
			if mode == "verbose" {
				args = append(args, "--verbose")
			}
			stdout, stderr := captureStd(t, func() {
				cmd := newConnectCmd()
				cmd.SilenceUsage, cmd.SilenceErrors = true, true
				cmd.SetArgs(args)
				if err := cmd.Execute(); err != nil {
					t.Fatalf("connect (%s) errored: %v", mode, err)
				}
			})
			all := stdout + stderr
			for _, leak := range []string{"et_testbearer", "et_", "egress.whisper.online", "Basic ", "Proxy-Authorization"} {
				if strings.Contains(all, leak) {
					t.Fatalf("[%s] bearer/server-field LEAKED %q in output:\nstdout=%q\nstderr=%q", mode, leak, stdout, stderr)
				}
			}
		})
	}
}

// TestParseConnectEnvelope_ExtractsUpstreamAndBearer: the secret-carrying fields are read
// INTERNALLY into the connect inputs (host + bearer + address), and the prefer-https form
// wins. This is the seam that feeds the local proxy; the bearer never leaves the struct.
func TestParseConnectEnvelope_ExtractsUpstreamAndBearer(t *testing.T) {
	ce, err := parseConnectEnvelope(connectResult())
	if err != nil {
		t.Fatalf("parseConnectEnvelope errored: %v", err)
	}
	if ce.upstreamHostPort != "egress.whisper.online:443" {
		t.Fatalf("upstream host = %q, want egress.whisper.online:443", ce.upstreamHostPort)
	}
	if ce.bearer != "et_secretbearer" {
		t.Fatalf("bearer = %q, want et_secretbearer (extracted internally)", ce.bearer)
	}
	if ce.address != "2a04:2a01:4::7" {
		t.Fatalf("address = %q, want the agent /128", ce.address)
	}
	if !ce.tlsToProxy {
		t.Fatalf("the https:// proxy form must set tlsToProxy=true")
	}
}

// TestExtractUpstream covers the proxy-URL parse (scheme/userinfo/host) for both forms.
func TestExtractUpstream(t *testing.T) {
	cases := []struct {
		in           string
		host, bearer string
		isTLS        bool
	}{
		{"https://w:et_abc@egress.whisper.online:443", "egress.whisper.online:443", "et_abc", true},
		{"socks5h://w:et_xyz@egress.whisper.online:443", "egress.whisper.online:443", "et_xyz", false},
		{"http://w:et_q@host:8080/path", "host:8080", "et_q", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		h, b, tls := extractUpstream(tc.in)
		if h != tc.host || b != tc.bearer || tls != tc.isTLS {
			t.Fatalf("extractUpstream(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.in, h, b, tls, tc.host, tc.bearer, tc.isTLS)
		}
	}
}

// TestVerifyRange covers the /128 / Whisper-range assertions verifyEgress relies on.
func TestVerifyRange(t *testing.T) {
	if !inWhisperRange("2a04:2a01:4::7") {
		t.Fatal("an address inside 2a04:2a01::/32 must be in range")
	}
	if inWhisperRange("2001:db8::1") {
		t.Fatal("an address outside 2a04:2a01::/32 must NOT be in range")
	}
	if inWhisperRange("203.0.113.5") {
		t.Fatal("a v4 address must NOT be in the Whisper v6 range")
	}
	if !sameIP("2a04:2a01:0004::7", "2a04:2a01:4::7") {
		t.Fatal("two textual forms of the same /128 must compare equal")
	}
	if sameIP("2a04:2a01:4::7", "2a04:2a01:4::8") {
		t.Fatal("distinct /128s must NOT compare equal")
	}
}
