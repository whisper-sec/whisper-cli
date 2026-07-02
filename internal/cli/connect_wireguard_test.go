// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
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
		default: // list — one existing agent so connect binds it without a create
			_, _ = w.Write([]byte(listJSON([]agentChoice{{name: "scout", addr: "2a04:2a01:9::abcd"}})))
		}
	}))
}

// stubWgBringUp replaces ONLY the live tunnel bring-up (connectAndVerify) so a command test
// runs with no real handshake, while STILL exercising prepareWireGuard (which injects the
// public key into the op:connect args before the control call). It records the wgKey it was
// handed so a test can assert a real keypair was generated and threaded through. Restores on return.
func stubWgBringUp(t *testing.T, gotKey **wgtun.Keypair) func() {
	t.Helper()
	savedConnect := connectAndVerify
	savedHold := holdUntilSignal
	connectAndVerify = func(_ context.Context, _ *client.Client, res *client.Result, name string, wgKey *wgtun.Keypair) (*egressSession, error) {
		if gotKey != nil {
			*gotKey = wgKey
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
// `whisper connect --tier wireguard` must (1) mint a LOCAL keypair, (2) send ONLY its public
// half + tier:wireguard in the op:connect args, and (3) NEVER put a private key on the wire or
// in any output. The private key staying local is the load-bearing identity-security property.
func TestConnect_WireGuardTier_SendsPublicKeyNotPrivate(t *testing.T) {
	var seen []recordedCall
	srv := wireguardRecordingServer(t, &seen)
	defer srv.Close()
	var gotKey *wgtun.Keypair
	defer stubWgBringUp(t, &gotKey)()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second}
	defer func() { g = savedG }()

	af := filepath.Join(t.TempDir(), "agent")
	stdout, stderr := captureStd(t, func() {
		cmd := newConnectCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"--tier", "wireguard", "--agent-file", af})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("connect --tier wireguard errored: %v", err)
		}
	})

	// The op:connect body must carry tier:'wireguard' AND a public_key (the generated one), and
	// must NOT carry a private key.
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
	if strings.Contains(strings.ToLower(body), "private_key") {
		t.Fatalf("op:connect must NEVER send a private key; body=%q", body)
	}

	// A real keypair must have been generated and threaded into bring-up.
	if gotKey == nil || gotKey.PublicKeyBase64 == "" || gotKey.PrivateKeyHex == "" {
		t.Fatalf("a WireGuard keypair must be generated and passed to bring-up, got %+v", gotKey)
	}
	// The public key sent on the wire must be exactly the one we generated.
	if !strings.Contains(body, gotKey.PublicKeyBase64) {
		t.Fatalf("the public_key on the wire must equal the generated key %q; body=%q", gotKey.PublicKeyBase64, body)
	}

	// The PRIVATE key must never appear anywhere in output.
	all := stdout + stderr
	if strings.Contains(all, gotKey.PrivateKeyHex) {
		t.Fatalf("the WireGuard private key LEAKED into output: out=%q err=%q", stdout, stderr)
	}
}

// TestPrepareWireGuard_NoOpForSocks5: a non-WG tier mints no key and touches no args (the
// socks5/anyip path is untouched — zero behaviour change for the existing tiers).
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

// TestParseConnectEnvelope_WireGuard: a tier:wireguard result is parsed into the WG fields
// (server pubkey, endpoint, address, dns) and flagged isWireGuard — the seam bring-up uses.
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
	cfg, err := wgtun.FromWgQuick(ce.wgServerPubKey, ce.wgEndpoint, ce.address, ce.wgDNS, ce.wgQuick, kp.PrivateKeyHex)
	if err != nil {
		t.Fatalf("FromWgQuick from parsed envelope: %v", err)
	}
	if cfg.Address.String() != "2a04:2a01:9::abcd" {
		t.Fatalf("cfg.Address = %q", cfg.Address)
	}
}
