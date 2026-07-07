// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package idkey is the client side of - the tunneled-tier AGENT-HELD identity key. It mints an
// EC P-256 keypair LOCALLY (mirroring wgtun.GenerateKeypair's WireGuard keypair, one level up the
// stack), persists it 0600 under ~/.config/whisper-ns/identity/ so it survives across reconnects, and
// builds the self-signed DANE-EE leaf the routed tunnel serves on :443. The private key NEVER leaves
// this process: only the raw base64 DER SubjectPublicKeyInfo is ever handed to op:connect
// (identity_public_key) - the server pins SHA-256 of THAT exact submission, verbatim, and never
// derives a leaf for a held /128 (the server pins SHA-256 of exactly this submitted SPKI).
package idkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Keypair is a freshly-generated (or loaded) EC P-256 identity keypair. The private key NEVER leaves
// this process; MarshalSPKIBase64 is the ONLY thing ever sent to the control plane.
type Keypair struct {
	Private *ecdsa.PrivateKey
	// spkiDER is the DER SubjectPublicKeyInfo, marshaled EXACTLY ONCE at generation/load time (never
	// re-derived) - the server hashes this SAME byte sequence, verbatim, so it must never drift from
	// what MarshalSPKIBase64 reports.
	spkiDER []byte
}

// GenerateKeypair mints a fresh EC P-256 identity keypair from the host CSPRNG (crypto/rand). The
// private key stays in-memory only; the caller persists it via Save if it wants reuse across runs.
func GenerateKeypair() (*Keypair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("could not generate an identity key")
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, errors.New("could not encode the identity public key")
	}
	return &Keypair{Private: priv, spkiDER: der}, nil
}

// MarshalSPKIBase64 returns the base64 (standard) encoding of the DER SubjectPublicKeyInfo - the
// EXACT, verbatim value sent as op:connect's identity_public_key arg. Marshaled once at generation
// (or load) time; this method never re-encodes, so the submitted bytes are always the same bytes the
// self-signed leaf's own public key encodes to.
func (k *Keypair) MarshalSPKIBase64() string {
	return base64.StdEncoding.EncodeToString(k.spkiDER)
}

// identityDir resolves ~/.config/whisper-ns/identity (a package var so tests point it at a temp dir).
var identityDir = defaultIdentityDir

// SetIdentityDirForTest overrides the identity-key directory for the duration of a test - a seam
// OTHER packages' tests use to isolate persistence without touching the real $HOME/.config. Returns
// a restore func. Test-only; never called from production code.
func SetIdentityDirForTest(dir string) func() {
	saved := identityDir
	identityDir = func() string { return dir }
	return func() { identityDir = saved }
}

func defaultIdentityDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper-ns", "identity")
	}
	return filepath.Join(home, ".config", "whisper-ns", "identity")
}

// PathFor maps a persistence handle (an agent id or a /128 - whatever is already known before the
// FIRST connect that mints this key) to its on-disk PEM path. Colons are not portable in filenames
// (Windows), so they are flattened; a blank handle collapses to "default" (the connect-first case,
// before any agent id/address is known).
func PathFor(handle string) string {
	h := strings.TrimSpace(handle)
	if h == "" {
		h = "default"
	}
	h = strings.ReplaceAll(h, ":", "_")
	h = strings.ReplaceAll(h, "/", "_")
	return filepath.Join(identityDir(), h+".pem")
}

// LoadOrGenerate loads the persisted identity key for handle, or mints + persists a fresh one if none
// exists yet - so the SAME key (and thus the SAME published DANE-EE pin) is reused across reconnects
// rather than re-pinning on every `whisper connect`. Best-effort persistence: a write failure still
// returns the freshly-minted in-memory key (the connect proceeds; it just re-pins next time too).
func LoadOrGenerate(handle string) (*Keypair, error) {
	path := PathFor(handle)
	if kp, err := load(path); err == nil {
		return kp, nil
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	_ = save(path, kp) // best-effort; a persist failure just means next connect mints again
	return kp, nil
}

// load reads + parses a persisted EC PRIVATE KEY PEM file.
func load(path string) (*Keypair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("idkey: not a PEM EC PRIVATE KEY")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("idkey: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("idkey: %w", err)
	}
	return &Keypair{Private: priv, spkiDER: der}, nil
}

// save persists kp as a PEM EC PRIVATE KEY, mode 0600, creating the identity dir (0700) if needed.
// The private key NEVER touches argv/env/logs - this is the ONLY place it is ever written, to a
// single-user-readable file.
func save(path string, kp *Keypair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(kp.Private)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// leafValidity is generous (mirrors the server-side per-agent leaf lifetime): DANE-EE pins the SPKI, not
// the cert's validity window, so a long-lived self-signed leaf is fine - it is re-minted fresh on
// every tunnel bring-up anyway (cheap: one self-signature, no network round-trip).
const leafValidity = 365 * 24 * time.Hour

// SelfSignedLeaf mints a self-signed EC P-256 leaf certificate over kp's key, with SANs
// dNSName=canonicalFqdn, dNSName=friendlyFqdn (when non-blank and distinct), and iPAddress=addr - the
// SAME SAN set the server's per-agent CA leaf carries. DANE-EE (usage 3, selector 1, matching 1) pins
// the SPKI directly, so no chain/root is needed; this leaf never needs to be signed by anyone else.
// The SPKI this leaf carries is BYTE-IDENTICAL to what MarshalSPKIBase64 already submitted (the SANs
// live in the Extensions, never in the SubjectPublicKeyInfo), so the pin submitted before connect
// still matches whatever this method mints after connect returns the fqdn/address.
func (k *Keypair) SelfSignedLeaf(canonicalFqdn, friendlyFqdn string, addr netip.Addr) (tls.Certificate, error) {
	canonical := strings.TrimSuffix(strings.TrimSpace(canonicalFqdn), ".")
	if canonical == "" {
		return tls.Certificate{}, errors.New("idkey: canonicalFqdn is required")
	}
	dnsNames := []string{canonical}
	friendly := strings.TrimSuffix(strings.TrimSpace(friendlyFqdn), ".")
	if friendly != "" && !strings.EqualFold(friendly, canonical) {
		dnsNames = append(dnsNames, friendly)
	}
	var ipAddrs []net.IP
	if addr.IsValid() {
		ipAddrs = []net.IP{net.IP(addr.AsSlice())}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, errors.New("idkey: could not generate a certificate serial")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: canonical},
		NotBefore:             now.Add(-5 * time.Minute), // clock-skew tolerance, mirrors the server leaf
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.Private.PublicKey, k.Private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("idkey: could not mint the self-signed leaf: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k.Private}, nil
}
