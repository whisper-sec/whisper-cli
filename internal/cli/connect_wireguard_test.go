// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// wireguardRecordingServer is a control-plane stub that, for op:connect, returns a Tier-1
// WireGuard envelope (tier:wireguard + the wg-quick config fields). It records every body so a
// test can assert the CLI sent `public_key` + `tier:wireguard` (the best-practice WG flow: our
// private key never leaves the host). op:list returns one existing agent so connect binds it.
func wireguardRecordingServer(t *testing.T, seen *[]recordedCall) *httptest.Server {
	t.Helper()
	// A valid 32-byte base64 server pubkey so parse/FromWgQuick accept it.
	srvPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
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
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{` +
				`"columns":["tier","wireguard_config","server_public_key","endpoint","client_public_key","client_private_key","address","allowed_ips","fqdn","ptr","dns","note"],` +
				`"rows":[["wireguard","[Interface]\nAddress = 2a04:2a01:9::abcd/128\nDNS = 2a04:2a01:0:53::1\n\n[Peer]\nPublicKey = ` + srvPub + `\nEndpoint = box.example:51826\nAllowedIPs = ::/0\nPersistentKeepalive = 25\n",` +
				`"` + srvPub + `","box.example:51826","wg-client-pub","","2a04:2a01:9::abcd","2a04:2a01:9::abcd/128","scout.agents.example","...","2a04:2a01:0:53::1","Tier-1 routed WireGuard"]]}}`))
		default: // list - one existing agent so connect binds it without a create
			_, _ = w.Write([]byte(listJSON([]agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}})))
		}
	}))
}

// stubWgBringUp replaces ONLY the live tunnel bring-up (connectAndVerify) so a command test
// runs with no real handshake, while STILL exercising prepareWireGuard + prepareIdentityKey (which
// inject the public keys into the op:connect args before the control call). It records the keys
// bundle it was handed so a test can assert real keypairs were generated and threaded through.
// Restores on return.
func stubWgBringUp(t *testing.T, gotKeys **connectKeys) func() {
	t.Helper()
	savedConnect := connectAndVerify
	savedHold := holdUntilSignal
	connectAndVerify = func(_ context.Context, _ *client.Client, res *client.Result, name string, keys *connectKeys) (*egressSession, error) {
		if gotKeys != nil {
			*gotKeys = keys
		}
		ce, err := parseConnectEnvelope(res)
		if err != nil {
			return nil, err
		}
		return &egressSession{endpoint: "socks5h://127.0.0.1:1080", addr: ce.address, name: name, tier: firstNonBlank(ce.tier, "socks5"), verified: true}, nil
	}
	holdUntilSignal = func(sess *egressSession) { sess.Stop() }
	return func() { connectAndVerify = savedConnect; holdUntilSignal = savedHold }
}

// TestConnect_WireGuardTier_SendsPublicKeyNotPrivate is the headline command-layer test:
// `whisper connect --tier wireguard` must (1) mint LOCAL keypairs (WireGuard + identity), (2)
// send ONLY their public halves (+ tier:wireguard) in the op:connect args, and (3) NEVER put a
// private key on the wire or in any output. The private keys staying local is the load-bearing
// identity-security property for BOTH keys.
func TestConnect_WireGuardTier_SendsPublicKeyNotPrivate(t *testing.T) {
	var seen []recordedCall
	srv := wireguardRecordingServer(t, &seen)
	defer srv.Close()
	var gotKeys *connectKeys
	defer stubWgBringUp(t, &gotKeys)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	idDir := t.TempDir()
	defer idkey.SetIdentityDirForTest(idDir)()

	af := filepath.Join(t.TempDir(), "agent")
	stdout, stderr := captureStd(t, func() {
		cmd := newConnectCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--tier", "wireguard", "--agent-file", af})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("connect --tier wireguard errored: %v", err)
		}
	})

	// The op:connect body must carry tier:'wireguard', a public_key (the generated WG one), AND
	// identity_public_key (the generated identity SPKI) - and must NOT carry any private key
	// or PEM anywhere in the body or in stdout/stderr.
	body, ok := bodyForOp(seen, "connect")
	if !ok {
		t.Fatalf("op:connect was never sent, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "tier:'wireguard'") {
		t.Fatalf("op:connect must send tier:'wireguard'; body=%q", body)
	}
	if !strings.Contains(body, "public_key:") {
		t.Fatalf("op:connect must send the locally-generated public_key; body=%q", body)
	}
	if !strings.Contains(body, "identity_public_key:") {
		t.Fatalf("op:connect must send the locally-generated identity_public_key; body=%q", body)
	}
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "private_key") || strings.Contains(lowerBody, "private") {
		t.Fatalf("op:connect must NEVER send a private key; body=%q", body)
	}
	if strings.Contains(body, "-----BEGIN") {
		t.Fatalf("op:connect must NEVER send PEM material; body=%q", body)
	}

	// Real keypairs must have been generated and threaded into bring-up.
	if gotKeys == nil || gotKeys.wg == nil || gotKeys.wg.PublicKeyBase64 == "" || gotKeys.wg.PrivateKeyHex == "" {
		t.Fatalf("a WireGuard keypair must be generated and passed to bring-up, got %+v", gotKeys)
	}
	if gotKeys.identity == nil || gotKeys.identity.MarshalSPKIBase64() == "" {
		t.Fatalf("an identity keypair must be generated and passed to bring-up, got %+v", gotKeys)
	}
	// The public keys sent on the wire must be exactly the ones we generated.
	if !strings.Contains(body, gotKeys.wg.PublicKeyBase64) {
		t.Fatalf("the public_key on the wire must equal the generated key %q; body=%q", gotKeys.wg.PublicKeyBase64, body)
	}
	if !strings.Contains(body, gotKeys.identity.MarshalSPKIBase64()) {
		t.Fatalf("the identity_public_key on the wire must equal the generated SPKI %q; body=%q",
			gotKeys.identity.MarshalSPKIBase64(), body)
	}

	// NEITHER private key/PEM may ever appear in stdout/stderr.
	all := stdout + stderr
	if strings.Contains(all, gotKeys.wg.PrivateKeyHex) {
		t.Fatalf("the WireGuard private key LEAKED into output: out=%q err=%q", stdout, stderr)
	}
	if strings.Contains(all, "-----BEGIN") {
		t.Fatalf("the identity private key PEM LEAKED into output: out=%q err=%q", stdout, stderr)
	}

	// The identity key must be persisted 0600 (idkey's save contract) and REUSED on a second
	// connect for the same (connect-first ⇒ "default"-handle) identity - same SPKI both times.
	entries, rerr := os.ReadDir(idDir)
	if rerr != nil || len(entries) == 0 {
		t.Fatalf("expected the identity key to be persisted under %s, readdir err=%v entries=%v", idDir, rerr, entries)
	}
	info, serr := os.Stat(filepath.Join(idDir, entries[0].Name()))
	if serr != nil {
		t.Fatalf("stat persisted identity key: %v", serr)
	}
	// Unix mode bits only. Windows carries none, so os.Stat reports 0666 whatever the
	// file's real protection is, which is why the assertion below is skipped there.
	// Confidentiality on Windows is not left to the parent directory: idkey's save path goes
	// through secfile, which sets a protected, non-inheriting, owner-only DACL on the
	// file itself before the first byte is written.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted identity key must be mode 0600, got %o", info.Mode().Perm())
	}
}

// TestPrepareWireGuard_NoOpForSocks5: a non-WG tier mints no key and touches no args (the
// socks5/anyip path is untouched - zero behaviour change for the existing tiers).
func TestPrepareWireGuard_NoOpForSocks5(t *testing.T) {
	for _, tier := range []string{"", "socks5", "anyip"} {
		args := map[string]any{"agent": "x"}
		kp, err := prepareWireGuard(tier, args)
		if err != nil {
			t.Fatalf("prepareWireGuard(%q) errored: %v", tier, err)
		}
		if kp != nil {
			t.Fatalf("prepareWireGuard(%q) must not mint a key", tier)
		}
		if _, ok := args["public_key"]; ok {
			t.Fatalf("prepareWireGuard(%q) must not inject public_key", tier)
		}
		if _, ok := args["tier"]; ok {
			t.Fatalf("prepareWireGuard(%q) must not set tier", tier)
		}
	}
}

// TestPrepareWireGuard_AliasWG: the "wg" alias selects WireGuard and normalises the wire tier
// to the canonical "wireguard" (Postel: accept the short form, emit the canonical one).
func TestPrepareWireGuard_AliasWG(t *testing.T) {
	args := map[string]any{}
	kp, err := prepareWireGuard("wg", args)
	if err != nil {
		t.Fatalf("prepareWireGuard(wg): %v", err)
	}
	if kp == nil {
		t.Fatal("the wg alias must select WireGuard and mint a key")
	}
	if args["tier"] != "wireguard" {
		t.Fatalf("the wg alias must normalise tier to 'wireguard', got %v", args["tier"])
	}
	if args["public_key"] != kp.PublicKeyBase64 {
		t.Fatalf("public_key must equal the minted key")
	}
}

// TestPrepareIdentityKey_NoOpForSocks5 (the client-side mirror): the identity keypair is
// minted+injected ONLY for the routed tier - socks5/anyip (and no tier) must touch neither the key
// nor the args.
func TestPrepareIdentityKey_NoOpForSocks5(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	for _, tier := range []string{"", "socks5", "anyip"} {
		args := map[string]any{"agent": "x"}
		kp, err := prepareIdentityKey(tier, args, "")
		if err != nil {
			t.Fatalf("prepareIdentityKey(%q) errored: %v", tier, err)
		}
		if kp != nil {
			t.Fatalf("prepareIdentityKey(%q) must not mint a key", tier)
		}
		if _, ok := args["identity_public_key"]; ok {
			t.Fatalf("prepareIdentityKey(%q) must not inject identity_public_key", tier)
		}
	}
}

// TestPrepareIdentityKey_WireGuard_InjectsPublicSpkiOnly: the routed tier injects ONLY the base64
// SPKI (never a private key/PEM) and returns the in-memory keypair for bring-up.
func TestPrepareIdentityKey_WireGuard_InjectsPublicSpkiOnly(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	args := map[string]any{}
	kp, err := prepareIdentityKey("wireguard", args, "agent-handle-1")
	if err != nil {
		t.Fatalf("prepareIdentityKey(wireguard): %v", err)
	}
	if kp == nil {
		t.Fatal("the routed tier must mint/load an identity key")
	}
	got, ok := args["identity_public_key"].(string)
	if !ok || got == "" {
		t.Fatalf("identity_public_key must be injected as a non-empty string, got %v", args["identity_public_key"])
	}
	if got != kp.MarshalSPKIBase64() {
		t.Fatalf("injected identity_public_key must equal the minted SPKI")
	}
	if strings.Contains(strings.ToLower(got), "private") || strings.Contains(got, "-----BEGIN") {
		t.Fatalf("identity_public_key must never carry private-key material: %q", got)
	}
}

// TestPrepareIdentityKey_ReusesPersistedKeyForTheSameHandle (the client-side mirror): a second
// connect for the SAME handle reuses the SAME persisted key - the server-side idempotent re-pin
// then costs zero zone writes.
func TestPrepareIdentityKey_ReusesPersistedKeyForTheSameHandle(t *testing.T) {
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	args1 := map[string]any{}
	kp1, err := prepareIdentityKey("wireguard", args1, "agent-handle-2")
	if err != nil {
		t.Fatalf("prepareIdentityKey (1st): %v", err)
	}
	args2 := map[string]any{}
	kp2, err := prepareIdentityKey("wireguard", args2, "agent-handle-2")
	if err != nil {
		t.Fatalf("prepareIdentityKey (2nd): %v", err)
	}
	if kp1.MarshalSPKIBase64() != kp2.MarshalSPKIBase64() {
		t.Fatal("a reconnect for the same handle must reuse the SAME identity key")
	}
	if args1["identity_public_key"] != args2["identity_public_key"] {
		t.Fatal("both connects must submit the SAME identity_public_key")
	}
}

// TestParseConnectEnvelope_WireGuard: a tier:wireguard result is parsed into the WG fields
// (server pubkey, endpoint, address, dns) and flagged isWireGuard - the seam bring-up uses.
func TestParseConnectEnvelope_WireGuard(t *testing.T) {
	srvPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	res := &client.Result{
		Columns: []string{"tier", "server_public_key", "endpoint", "address", "dns", "wireguard_config", "client_private_key"},
		Rows: [][]any{{
			"wireguard", srvPub, "box.example:51826", "2a04:2a01:9::abcd", "2a04:2a01:0:53::1",
			"[Interface]\nAddress = 2a04:2a01:9::abcd/128\n", "",
		}},
	}
	ce, err := parseConnectEnvelope(res)
	if err != nil {
		t.Fatalf("parseConnectEnvelope(wireguard): %v", err)
	}
	if !ce.isWireGuard() {
		t.Fatal("a tier:wireguard result must be flagged isWireGuard")
	}
	if ce.wgServerPubKey != srvPub || ce.wgEndpoint != "box.example:51826" {
		t.Fatalf("WG fields not extracted: %+v", ce)
	}
	if ce.address != "2a04:2a01:9::abcd" {
		t.Fatalf("address = %q", ce.address)
	}
	// And it must feed a valid wgtun.Config when combined with a local key.
	kp, _ := wgtun.GenerateKeypair()
	cfg, err := wgtun.FromWgQuick(
		ce.wgServerPubKey, ce.wgEndpoint, ce.address, ce.wgDNS, ce.wgNat64Prefix, ce.wgQuick, kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick from parsed envelope: %v", err)
	}
	if cfg.Address.String() != "2a04:2a01:9::abcd" {
		t.Fatalf("cfg.Address = %q", cfg.Address)
	}
}
