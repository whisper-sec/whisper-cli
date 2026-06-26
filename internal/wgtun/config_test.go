// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestGenerateKeypair: a minted keypair is a valid clamped Curve25519 pair — 32-byte hex
// private key, 32-byte base64 public key, and two successive mints differ (real randomness).
func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	priv, err := hex.DecodeString(kp.PrivateKeyHex)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private key not 32-byte hex: %q (err=%v)", kp.PrivateKeyHex, err)
	}
	// RFC 7748 / WireGuard clamping must be applied.
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatalf("private key not clamped: %x", priv)
	}
	pub, err := base64.StdEncoding.DecodeString(kp.PublicKeyBase64)
	if err != nil || len(pub) != 32 {
		t.Fatalf("public key not 32-byte base64: %q (err=%v)", kp.PublicKeyBase64, err)
	}
	kp2, _ := GenerateKeypair()
	if kp.PrivateKeyHex == kp2.PrivateKeyHex {
		t.Fatal("two mints produced identical private keys — randomness is broken")
	}
}

// TestKeyBase64ToHex: a valid 32-byte base64 key converts to 64 hex chars; junk / wrong
// length is a clean error (never a panic).
func TestKeyBase64ToHex(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	hx, err := keyBase64ToHex(b64)
	if err != nil {
		t.Fatalf("keyBase64ToHex(valid): %v", err)
	}
	if hx != hex.EncodeToString(raw) {
		t.Fatalf("hex = %q, want %q", hx, hex.EncodeToString(raw))
	}
	for _, bad := range []string{"", "not-base64!!!", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		if _, err := keyBase64ToHex(bad); err == nil {
			t.Fatalf("keyBase64ToHex(%q) must error", bad)
		}
	}
}

// TestFromWgQuick_StructuredFieldsWin: when the control plane returns the structured fields,
// FromWgQuick uses them (and converts the base64 server key to hex), ignoring the blob.
func TestFromWgQuick_StructuredFieldsWin(t *testing.T) {
	srvKey := base64.StdEncoding.EncodeToString(make([]byte, 32)) // all-zero key (valid 32 bytes)
	priv := strings.Repeat("ab", 32)                              // 64 hex chars
	cfg, err := FromWgQuick(srvKey, "box.example:51826", "2a04:2a01:4::7", "2a04:2a01:0:53::1", "", priv)
	if err != nil {
		t.Fatalf("FromWgQuick: %v", err)
	}
	if cfg.ServerPublicKeyHex != hex.EncodeToString(make([]byte, 32)) {
		t.Fatalf("server pubkey hex = %q", cfg.ServerPublicKeyHex)
	}
	if cfg.Endpoint != "box.example:51826" {
		t.Fatalf("endpoint = %q", cfg.Endpoint)
	}
	if cfg.Address.String() != "2a04:2a01:4::7" {
		t.Fatalf("address = %q", cfg.Address)
	}
	if cfg.DNS.String() != "2a04:2a01:0:53::1" {
		t.Fatalf("dns = %q", cfg.DNS)
	}
	if cfg.PrivateKeyHex != priv {
		t.Fatalf("private key not threaded through: %q", cfg.PrivateKeyHex)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a fully-populated config must validate: %v", err)
	}
}

// TestFromWgQuick_BlobFallback: with NO structured fields, FromWgQuick recovers everything by
// PARSING the wg-quick blob (Postel: liberal-accept a server that returns only the config text).
func TestFromWgQuick_BlobFallback(t *testing.T) {
	srvKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	blob := "[Interface]\n" +
		"Address = 2a04:2a01:4::9/128\n" +
		"DNS = 2a04:2a01:0:53::1, 2a04:2a00::53\n\n" +
		"[Peer]\n" +
		"PublicKey = " + srvKey + "\n" +
		"Endpoint = box.example:51826\n" +
		"AllowedIPs = ::/0\n" +
		"PersistentKeepalive = 25\n"
	priv := strings.Repeat("cd", 32)
	cfg, err := FromWgQuick("", "", "", "", blob, priv)
	if err != nil {
		t.Fatalf("FromWgQuick(blob): %v", err)
	}
	if cfg.ServerPublicKeyHex == "" {
		t.Fatal("server pubkey must be recovered from the blob")
	}
	if cfg.Endpoint != "box.example:51826" {
		t.Fatalf("endpoint from blob = %q", cfg.Endpoint)
	}
	if cfg.Address.String() != "2a04:2a01:4::9" { // /128 stripped
		t.Fatalf("address from blob = %q (prefix len must be stripped)", cfg.Address)
	}
	if cfg.DNS.String() != "2a04:2a01:0:53::1" { // first of the comma list
		t.Fatalf("dns from blob = %q (must take the first listed)", cfg.DNS)
	}
	if cfg.Keepalive != 25 {
		t.Fatalf("keepalive from blob = %d, want 25", cfg.Keepalive)
	}
}

// TestConfigValidate_RejectsMissing: each missing essential field is a clean error.
func TestConfigValidate_RejectsMissing(t *testing.T) {
	full := Config{
		PrivateKeyHex:      strings.Repeat("ab", 32),
		ServerPublicKeyHex: strings.Repeat("cd", 32),
		Endpoint:           "box:51826",
		Address:            mustAddr(t, "2a04:2a01:4::7"),
	}
	if err := full.validate(); err != nil {
		t.Fatalf("full config must validate: %v", err)
	}
	// Each blanked field individually must fail.
	cases := map[string]func(c *Config){
		"no priv":     func(c *Config) { c.PrivateKeyHex = "" },
		"no srv pub":  func(c *Config) { c.ServerPublicKeyHex = "" },
		"no endpoint": func(c *Config) { c.Endpoint = "" },
		"no address":  func(c *Config) { c.Address = invalidAddr() }, // the zero (invalid) Addr
	}
	for name, mut := range cases {
		c := full
		mut(&c)
		if err := c.validate(); err == nil {
			t.Fatalf("validate() must reject %q", name)
		}
	}
}

// TestUapiConfig_ContainsKeysAndKeepalive: the UAPI doc carries the private key, the peer key,
// the endpoint, ::/0 + 0.0.0.0/0 allowed-ips, and the keepalive — the exact wireguard-go form.
func TestUapiConfig_ContainsKeysAndKeepalive(t *testing.T) {
	cfg := Config{
		PrivateKeyHex:      strings.Repeat("11", 32),
		ServerPublicKeyHex: strings.Repeat("22", 32),
		Endpoint:           "box.example:51826",
		Keepalive:          0, // ⇒ defaults to 25
	}
	cfg.Address = mustAddr(t, "2a04:2a01:4::7")
	doc := uapiConfig(cfg)
	for _, want := range []string{
		"private_key=" + cfg.PrivateKeyHex,
		"public_key=" + cfg.ServerPublicKeyHex,
		"endpoint=box.example:51826",
		"allowed_ip=::/0",
		"allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("uapiConfig missing %q in:\n%s", want, doc)
		}
	}
}

// TestResolveEndpoint covers the live bug the IP-only tests missed: the control plane returns a
// HOSTNAME endpoint (ns1.whisper.online:51826), but wireguard-go's IpcSet needs a literal ip:port.
func TestResolveEndpoint(t *testing.T) {
	// a literal IPv6 ip:port passes through unchanged
	if got, err := resolveEndpoint("[2a04:2a01:0:53::5]:51826"); err != nil || got != "[2a04:2a01:0:53::5]:51826" {
		t.Fatalf("literal v6 ip:port: got %q err %v", got, err)
	}
	// a literal IPv4 ip:port passes through
	if got, err := resolveEndpoint("203.0.113.7:51826"); err != nil || got != "203.0.113.7:51826" {
		t.Fatalf("literal v4 ip:port: got %q err %v", got, err)
	}
	// localhost resolves locally (no external DNS) to a literal ip:port
	got, err := resolveEndpoint("localhost:51826")
	if err != nil {
		t.Fatalf("localhost: %v", err)
	}
	if h, _, _ := strings.Cut(got, ":"); !strings.Contains(got, "51826") || (h != "127.0.0.1" && !strings.Contains(got, "::1")) {
		t.Fatalf("localhost resolved to unexpected %q", got)
	}
	// a malformed endpoint errors (not a panic)
	if _, err := resolveEndpoint("not a host port"); err == nil {
		t.Fatal("expected error for malformed endpoint")
	}
}
