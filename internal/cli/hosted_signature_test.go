// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// hostedRefusalDetail is the sentence the server answers a hosted-tier call with on a tenant
// that requires node-key enrolment, with the /128 named once as a bare literal.
func hostedRefusalDetail(addr string) string {
	return "this tenant requires node-key enrolment, so egress as " + addr + " over socks5, anyip or" +
		" op:token must be signed by that agent's identity key (identity_signature over the" +
		" node-enrolment challenge with an empty public_key). If you use the whisper CLI and see this," +
		" it is older than the release that signs these calls: upgrade it."
}

func signatureRequiredReply(addr string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, `{"ok":false,"status":403,"error":{"code":"IDENTITY_SIGNATURE_REQUIRED","message":%q,"status":403}}`,
			hostedRefusalDetail(addr))
	}
}

func socksConnectReply(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["tier","address","http_proxy","socks5_endpoint","connection_string"],"rows":[["socks5","` +
		custodyAddr + `","https://w:et_testbearer@egress.whisper.online:443","egress.whisper.online:443","socks5h://w:et_testbearer@egress.whisper.online:443"]]}}`))
}

func tokenReply(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","token","address","scope","expires"],"rows":[["ag_1","et_monitor","` +
		custodyAddr + `","dns:connect",null]]}}`))
}

// heldKey files an identity key for handle in the test's identity store and returns it.
func heldKey(t *testing.T, handle string) *idkey.Keypair {
	t.Helper()
	kp, err := idkey.LoadOrGenerate(handle)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

var (
	sigArg    = regexp.MustCompile(`identity_signature['"]?\s*:\s*['"]([A-Za-z0-9+/=]+)['"]`)
	windowArg = regexp.MustCompile(`identity_signature_window['"]?\s*:\s*([0-9]+)`)
)

// signatureIn pulls the signature and window a query carried, or fails the test.
func signatureIn(t *testing.T, q string) ([]byte, int64) {
	t.Helper()
	m, w := sigArg.FindStringSubmatch(q), windowArg.FindStringSubmatch(q)
	if m == nil || w == nil {
		t.Fatalf("the resent call must carry identity_signature and its window: %q", q)
	}
	sig, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	win, err := strconv.ParseInt(w[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return sig, win
}

// verifiesAsTheServerDoes checks sig the way the server does: SHA-256 over
// the shared challenge for addr, an EMPTY WireGuard key and the window, under the key's SPKI.
// The challenge's bytes are pinned against the server's in idkey's cross-language vectors.
func verifiesAsTheServerDoes(t *testing.T, kp *idkey.Keypair, addr string, sig []byte, window int64) bool {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(kp.MarshalSPKIBase64())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(idkey.EnrolmentChallenge(netip.MustParseAddr(addr), "", window))
	return ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig)
}

func TestHostedSignatureRefusalIsReadFromTheCodeAndNamesTheAddress(t *testing.T) {
	cases := []struct {
		err  error
		ok   bool
		addr string
	}{
		{&client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: hostedRefusalDetail(custodyAddr)}, true, custodyAddr},
		{&client.ProblemError{Status: 403, Type: "identity_signature_required", Detail: hostedRefusalDetail("2a04:2a01:0:1::a1")}, true, "2a04:2a01:0:1::a1"},
		{&client.ProblemError{Status: 403, Detail: hostedRefusalDetail(custodyAddr)}, true, custodyAddr}, // no code came through
		{&client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: "signature required"}, false, ""},
		{&client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_INVALID", Detail: hostedRefusalDetail(custodyAddr)}, false, ""},
		{&client.ProblemError{Status: 403, Detail: "this API key lacks the dns:connect scope for " + custodyAddr}, false, ""},
		{&client.ProblemError{Status: 409, Title: "IDENTITY_KEY_PINNED", Detail: custodyAddr}, false, ""},
		{&client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: "egress as 192.0.2.1 must be signed"}, false, ""},
		{fmt.Errorf("dial tcp: connection refused"), false, ""},
	}
	for _, c := range cases {
		addr, ok := hostedSignatureRefusal(c.err)
		if ok != c.ok || (ok && addr.String() != c.addr) {
			t.Errorf("%v: got (%v, %v), want (%v, %v)", c.err, addr, ok, c.addr, c.ok)
		}
	}
}

func TestSignHostedAfterRefusalSignsTheNamedSlash128WithTheHeldKey(t *testing.T) {
	custodyStore(t)
	kp := heldKey(t, "my-agent")
	args := map[string]any{"tier": "socks5", "agent": "my-agent"}
	now := time.Unix(1_700_000_000, 0)
	refusal := &client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: hostedRefusalDetail(custodyAddr)}

	if !signHostedAfterRefusal(args, "my-agent", refusal, now) {
		t.Fatal("a held key must answer the refusal")
	}
	sig, err := base64.StdEncoding.DecodeString(args["identity_signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if w := args["identity_signature_window"].(int64); w != idkey.EnrolmentWindow(now) {
		t.Fatalf("window = %d, want %d", w, idkey.EnrolmentWindow(now))
	}
	if !verifiesAsTheServerDoes(t, kp, custodyAddr, sig, idkey.EnrolmentWindow(now)) {
		t.Fatal("the signature must verify over the hosted-tier challenge, as the server checks it")
	}
	for _, k := range []string{"identity_public_key", "public_key", "adopt_identity_key"} {
		if _, sent := args[k]; sent {
			t.Fatalf("a hosted-tier proof carries no %s (the server refuses one on this tier)", k)
		}
	}
}

func TestSignHostedAfterRefusalFindsAKeyFiledUnderTheAddress(t *testing.T) {
	custodyStore(t)
	kp := heldKey(t, custodyAddr)
	args := map[string]any{"tier": "socks5"}
	refusal := &client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: hostedRefusalDetail(custodyAddr)}
	if !signHostedAfterRefusal(args, "", refusal, time.Now()) {
		t.Fatal("a key filed under the /128 the server named must answer it")
	}
	sig, _ := base64.StdEncoding.DecodeString(args["identity_signature"].(string))
	if !verifiesAsTheServerDoes(t, kp, custodyAddr, sig, args["identity_signature_window"].(int64)) {
		t.Fatal("signed with the wrong key or over the wrong bytes")
	}
}

func TestSignHostedAfterRefusalNeverMintsAndNeverRepeatsASignedClaim(t *testing.T) {
	dir := custodyStore(t)
	refusal := &client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: hostedRefusalDetail(custodyAddr)}

	args := map[string]any{"tier": "socks5", "agent": "nobody"}
	if signHostedAfterRefusal(args, "nobody", refusal, time.Now()) {
		t.Fatal("a host with no key has nothing to sign with")
	}
	if len(pemFiles(t, dir)) != 0 {
		t.Fatal("answering a refusal must never mint a key")
	}
	if _, sent := args["identity_signature"]; sent {
		t.Fatal("args must be left as they were")
	}

	heldKey(t, "signed")
	signed := map[string]any{"tier": "socks5", "identity_signature": "MEQ=", "identity_signature_window": int64(1)}
	if signHostedAfterRefusal(signed, "signed", refusal, time.Now()) {
		t.Fatal("a refused signed call is never re-signed: it would make the same claim")
	}
}

func TestOpConnectSignsAHostedTierConnectOnceWhenTheTenantRequiresIt(t *testing.T) {
	custodyStore(t)
	kp := heldKey(t, "my-agent")
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr), socksConnectReply)
	c := testClient(t, srv.URL)

	env, err := opConnect(context.Background(), c, map[string]any{"tier": "socks5", "agent": "my-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if perr := envelopeError(env); perr != nil {
		t.Fatalf("the signed resend must succeed, got %v", perr)
	}
	q := queries()
	if len(q) != 2 {
		t.Fatalf("want the refused call and one signed resend, got %d calls", len(q))
	}
	if strings.Contains(q[0], "identity_signature") {
		t.Fatalf("the first call is unsigned, so a tenant that does not require it never sees a signature: %q", q[0])
	}
	if strings.Contains(q[1], "identity_public_key") {
		t.Fatalf("the resend carries no identity_public_key: %q", q[1])
	}
	sig, win := signatureIn(t, q[1])
	if !verifiesAsTheServerDoes(t, kp, custodyAddr, sig, win) {
		t.Fatal("the resent request's signature must verify as the server checks it")
	}
}

func TestOpConnectTheDefaultTierIsHostedToo(t *testing.T) {
	custodyStore(t)
	heldKey(t, custodyAddr)
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr), socksConnectReply)
	c := testClient(t, srv.URL)
	env, err := opConnect(context.Background(), c, map[string]any{"agent": custodyAddr})
	if err != nil || envelopeError(env) != nil {
		t.Fatalf("a connect with no tier is socks5 and is signed the same way: %v %v", err, envelopeError(env))
	}
	if len(queries()) != 2 {
		t.Fatalf("want one signed resend, got %d calls", len(queries()))
	}
}

func TestOpConnectWithNoKeyReturnsTheServersOwnRefusal(t *testing.T) {
	custodyStore(t)
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr))
	c := testClient(t, srv.URL)
	env, err := opConnect(context.Background(), c, map[string]any{"tier": "socks5", "agent": "elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	perr := envelopeError(env)
	if perr == nil || !strings.Contains(perr.Error(), "upgrade it") {
		t.Fatalf("the server's sentence must reach the user as it is, got %v", perr)
	}
	if len(queries()) != 1 {
		t.Fatalf("nothing to sign with, so nothing is resent: %d calls", len(queries()))
	}
}

func TestOpConnectNeverSignsTheRoutedTierHere(t *testing.T) {
	custodyStore(t)
	heldKey(t, custodyAddr)
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr))
	c := testClient(t, srv.URL)
	_, _ = opConnect(context.Background(), c, map[string]any{"tier": "wireguard", "agent": custodyAddr})
	if len(queries()) != 1 {
		t.Fatalf("the routed tier signs over its WireGuard key up front, never through this retry: %d calls", len(queries()))
	}
}

func TestOpTokenSignsOnceWhenTheTenantRequiresIt(t *testing.T) {
	custodyStore(t)
	kp := heldKey(t, "my-agent")
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr), tokenReply)
	c := testClient(t, srv.URL)

	env, err := c.Agents(context.Background(), "token", map[string]any{"agent": "my-agent"})
	if err != nil || envelopeError(env) != nil {
		t.Fatalf("the signed resend must succeed: %v %v", err, envelopeError(env))
	}
	q := queries()
	if len(q) != 2 {
		t.Fatalf("want the refused call and one signed resend, got %d", len(q))
	}
	sig, win := signatureIn(t, q[1])
	if !verifiesAsTheServerDoes(t, kp, custodyAddr, sig, win) {
		t.Fatal("op:token's proof is the hosted-tier one, as the server checks it")
	}
}

func TestTheSignerIsInstalledForEveryCallerOfAgents(t *testing.T) {
	if client.HostedProofSigner == nil {
		t.Fatal("the command layer must install client.HostedProofSigner, so the TUI and the MCP tools sign too")
	}
}

func TestAnOpTokenRevokeIsNeverSigned(t *testing.T) {
	custodyStore(t)
	heldKey(t, "my-agent")
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr))
	c := testClient(t, srv.URL)
	_, _ = c.Agents(context.Background(), "token", map[string]any{"agent": "my-agent", "revoke": true})
	if len(queries()) != 1 {
		t.Fatalf("a revoke hands nothing out, so it is never resent: %d calls", len(queries()))
	}
}

// The MCP control tools reach the plane through mcpAgents, the one path every key-gated tool
// shares, so a connect or op:token an LLM drives through MCP is signed exactly as the CLI's is.
func TestMCPControlPathSignsAHostedTierConnectAndOpToken(t *testing.T) {
	for _, tc := range []struct {
		op    string
		args  map[string]any
		reply func(http.ResponseWriter, *http.Request)
	}{
		{"connect", map[string]any{"tier": "socks5", "agent": "my-agent"}, socksConnectReply},
		{"token", map[string]any{"agent": "my-agent"}, tokenReply},
	} {
		t.Run(tc.op, func(t *testing.T) {
			custodyStore(t)
			kp := heldKey(t, "my-agent")
			srv, queries := renewServer(t, signatureRequiredReply(custodyAddr), tc.reply)
			pinKeyState(t, "whisper_live_test", srv.URL)

			res := mcpAgents(tc.op, tc.args)
			if res.IsError {
				t.Fatalf("the MCP %s must succeed after the signed resend, got %+v", tc.op, res.Content)
			}
			q := queries()
			if len(q) != 2 {
				t.Fatalf("want the refused call and one signed resend, got %d", len(q))
			}
			sig, win := signatureIn(t, q[1])
			if !verifiesAsTheServerDoes(t, kp, custodyAddr, sig, win) {
				t.Fatal("the MCP resend's proof must verify as the server checks it")
			}
		})
	}
}

func TestMCPControlPathWithNoKeyShowsTheServersSentence(t *testing.T) {
	custodyStore(t)
	srv, queries := renewServer(t, signatureRequiredReply(custodyAddr))
	pinKeyState(t, "whisper_live_test", srv.URL)
	res := mcpAgents("connect", map[string]any{"tier": "socks5", "agent": "elsewhere"})
	if !res.IsError || len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "upgrade it") {
		t.Fatalf("with no key on this host the model must see the server's own sentence, got %+v", res)
	}
	if len(queries()) != 1 {
		t.Fatalf("nothing to sign with, so nothing is resent: %d calls", len(queries()))
	}
}

// A signature request is not a rejected API key, so nobody is sent to log in again.
func TestASignatureRequestIsNeverRenderedAsARejectedKey(t *testing.T) {
	pe := &client.ProblemError{Status: 403, Title: "IDENTITY_SIGNATURE_REQUIRED", Detail: hostedRefusalDetail(custodyAddr)}
	line := friendly(pe)
	if strings.Contains(line, "whisper login") || !strings.Contains(line, "upgrade it") {
		t.Fatalf("the server's own sentence must reach the user, got %q", line)
	}
}
