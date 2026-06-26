// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Keypair is a freshly-generated Curve25519 WireGuard keypair. The private key NEVER leaves
// this process; only PublicKeyBase64 is sent to the control plane (op:connect public_key arg).
type Keypair struct {
	PrivateKeyHex   string // for the device UAPI (in-memory only; never logged/persisted)
	PublicKeyBase64 string // the wg-quick form sent to the server as `public_key`
}

// GenerateKeypair mints a WireGuard (Curve25519) keypair locally. The private key is clamped
// per RFC 7748 (the standard WireGuard clamping) and used ONLY to drive the userspace device;
// only the public half is shared. This is the best-practice path: the server registers our
// public key as a peer and never sees the private key, so reverse-DNS identity is bound to a
// key that only WE hold (#188). x/crypto/curve25519 is already a transitive dep (wireguard-go).
func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, errors.New("could not generate a WireGuard key")
	}
	// WireGuard/RFC 7748 clamping.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, errors.New("could not derive the WireGuard public key")
	}
	return Keypair{
		PrivateKeyHex:   hex.EncodeToString(priv[:]),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// FromWgQuick builds a Config from the op:connect{tier:wireguard} result fields plus the
// locally-held private key (hex). It is LIBERAL in what it accepts (Postel): it prefers the
// structured fields the control plane returns (server_public_key, endpoint, address, dns,
// allowed_ips) but falls back to PARSING the wg-quick `wireguard_config` blob for any that
// are missing — so a future server that returns only the blob still works.
//
// privKeyHex is OUR key (we generated it; the server never returns it because we supplied the
// public half). If the server DID mint and return a base64 client_private_key (the zero-key
// path), the caller converts it to hex and passes it here. Keys are converted base64→hex.
func FromWgQuick(serverPubB64, endpoint, address, dns, wgQuick, privKeyHex string) (Config, error) {
	cfg := Config{PrivateKeyHex: strings.TrimSpace(privKeyHex)}

	// Pull anything missing from the wg-quick blob (lenient INI-ish parse).
	pq := parseWgQuick(wgQuick)

	if v := strings.TrimSpace(serverPubB64); v != "" {
		hexKey, err := keyBase64ToHex(v)
		if err != nil {
			return Config{}, fmt.Errorf("wireguard: bad server public key")
		}
		cfg.ServerPublicKeyHex = hexKey
	} else if v := pq["PublicKey"]; v != "" {
		hexKey, err := keyBase64ToHex(v)
		if err != nil {
			return Config{}, fmt.Errorf("wireguard: bad server public key")
		}
		cfg.ServerPublicKeyHex = hexKey
	}

	cfg.Endpoint = firstNonEmpty(strings.TrimSpace(endpoint), pq["Endpoint"])

	addrStr := firstNonEmpty(strings.TrimSpace(address), stripPrefixLen(pq["Address"]))
	if a, err := netip.ParseAddr(addrStr); err == nil {
		cfg.Address = a
	}

	dnsStr := firstNonEmpty(strings.TrimSpace(dns), firstField(pq["DNS"]))
	if d, err := netip.ParseAddr(dnsStr); err == nil {
		cfg.DNS = d
	}

	if k := pq["PersistentKeepalive"]; k != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(k)); err == nil {
			cfg.Keepalive = n
		}
	}
	return cfg, nil
}

// PrivateKeyBase64ToHex converts a base64 WireGuard PRIVATE key (the zero-key path, where the
// server minted and returned the keypair) to the hex form the device UAPI needs. The result is
// in-memory only and never logged. Exported so connect_core can use it on the fallback path.
func PrivateKeyBase64ToHex(b64 string) (string, error) {
	return keyBase64ToHex(b64)
}

// keyBase64ToHex converts a standard-base64 WireGuard key (32 bytes) to the hex form the
// wireguard-go UAPI expects. A malformed or wrong-length key is a clean error.
func keyBase64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("not a 32-byte base64 key")
	}
	return hex.EncodeToString(raw), nil
}

// parseWgQuick does a tolerant parse of a wg-quick config blob into a flat key→value map
// (last value wins; section headers ignored). Whitespace around `=` is trimmed. It never
// errors — a value the caller needs but didn't find is simply absent, and the structured
// fields cover the common case.
func parseWgQuick(blob string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// stripPrefixLen turns "2a04:2a01:4::7/128" into "2a04:2a01:4::7" (the Address field carries a
// prefix length; the netstack interface wants the bare address).
func stripPrefixLen(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// firstField returns the first comma- or space-separated token of s (DNS may list several).
func firstField(s string) string {
	s = strings.TrimSpace(s)
	for _, sep := range []string{",", " "} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
