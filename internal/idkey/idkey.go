// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package idkey is the client side of the tunneled-tier AGENT-HELD identity key. It mints an
// EC P-256 keypair LOCALLY (mirroring wgtun.GenerateKeypair's WireGuard keypair, one level up the
// stack), persists it 0600 under ~/.config/whisper/identity/ so it survives across reconnects, and
// builds the self-signed DANE-EE leaf the routed tunnel serves on :443. The private key NEVER leaves
// this process: only the raw base64 DER SubjectPublicKeyInfo is ever handed to op:connect
// (identity_public_key) - the server pins SHA-256 of THAT exact submission, verbatim, and never
// derives a leaf for a held /128 (the server pins SHA-256 of exactly this submitted SPKI).
package idkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// Keypair is a freshly-generated (or loaded) EC P-256 identity keypair. The private key NEVER leaves
// this process; MarshalSPKIBase64 is the ONLY thing ever sent to the control plane.
type Keypair struct {
	Private *ecdsa.PrivateKey
	// spkiDER is the DER SubjectPublicKeyInfo, marshaled EXACTLY ONCE at generation/load time (never
	// re-derived) - the server hashes this SAME byte sequence, verbatim, so it must never drift from
	// what MarshalSPKIBase64 reports.
	spkiDER []byte
	// serving and servingUntil are set on a pin reached by a rotation still in its first phase:
	// the outgoing key keeps serving the TLS leaf until then (ServingKey).
	serving      *Keypair
	servingUntil time.Time
	// dir is the identity directory the key was read from ("" for a key minted in this process),
	// so its recorded moves are read from the same store, whoever's it is.
	dir string
	// unstored marks a key from Mint that no store holds yet (Unstored).
	unstored bool
}

// Mint is a fresh key that no store holds yet. Its caller stores it before anything that names
// it leaves this host: under a handle (Link), or as a pending recovery (KeepRecovery), because
// which of the two is right is known only once the identity's key history has been read.
func Mint() (*Keypair, error) {
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	kp.unstored = true
	return kp, nil
}

// Unstored reports a key from Mint that neither Link nor KeepRecovery has stored yet.
func (k *Keypair) Unstored() bool { return k != nil && k.unstored }

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

// PinDigest is the lowercase hex SHA-256 of the key's DER SubjectPublicKeyInfo: the association
// data of the DANE-EE (3 1 1) TLSA an identity publishes once this key is its pin, and the digest
// the control plane names a pin by.
func (k *Keypair) PinDigest() string {
	sum := sha256.Sum256(k.spkiDER)
	return hex.EncodeToString(sum[:])
}

// Held is the identity keys persisted under one address: the address, and every file that names
// it, the canonical spelling (PathFor of the address) first. One /128 may have more than one file
// when it was stored under differently spelt handles.
type Held struct {
	Addr  netip.Addr
	Paths []string
}

// HeldAddresses lists the keys this context has persisted under an IPv6 address, one entry per
// address, in a stable order. A file is named for the handle it was stored under (PathFor), so only
// names that parse back to an IPv6 address count; a name, "default", a temporary link file or
// anything unreadable as an address is skipped. It reads names only: whether a file holds a key,
// and whether that key is anyone's published pin, is for the caller to establish. A missing
// directory is an empty list, never an error.
func HeldAddresses() []Held {
	dir := identityDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	index := map[netip.Addr]int{}
	var out []Held
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".pem") {
			continue
		}
		a, perr := netip.ParseAddr(strings.ReplaceAll(strings.TrimSuffix(name, ".pem"), "_", ":"))
		if perr != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			continue
		}
		path := filepath.Join(dir, name)
		i, seen := index[a]
		if !seen {
			index[a] = len(out)
			out = append(out, Held{Addr: a, Paths: []string{path}})
			continue
		}
		if path == PathFor(a.String()) {
			out[i].Paths = append([]string{path}, out[i].Paths...)
		} else {
			out[i].Paths = append(out[i].Paths, path)
		}
	}
	return out
}

// identityDir resolves ~/.config/whisper/identity (a package var so tests point it at a temp dir).
var identityDir = defaultIdentityDir

// SetIdentityDirForTest overrides the identity-key directory for the duration of a test - a seam
// OTHER packages' tests use to isolate persistence without touching the real $HOME/.config. Returns
// a restore func. Test-only; never called from production code.
func SetIdentityDirForTest(dir string) func() {
	saved := identityDir
	identityDir = func() string { return dir }
	return func() { identityDir = saved }
}

// Dir is the directory this process reads and writes identity keys in, so an error about a key can
// say where the key came from.
func Dir() string {
	return identityDir()
}

func defaultIdentityDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "identity")
	}
	return filepath.Join(home, ".config", "whisper", "identity")
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

// LoadFile reads a persisted identity key from an explicit path, for a caller that has decided
// itself which store to read (the enforced run under sudo reads the invoking user's, read-only).
// It never mints and never writes.
func LoadFile(path string) (*Keypair, error) {
	kp, err := load(path)
	if err != nil {
		return nil, err
	}
	return follow(kp, filepath.Dir(path)), nil
}

// LoadOrGenerate loads the persisted identity key for handle, or mints + persists a fresh one if none
// exists yet - so the SAME key (and thus the SAME published DANE-EE pin) is reused across reconnects
// rather than re-pinning on every `whisper connect`. Best-effort persistence: a write failure still
// returns the freshly-minted in-memory key (the connect proceeds; it just re-pins next time too).
func LoadOrGenerate(handle string) (*Keypair, error) {
	path := PathFor(handle)
	if kp, err := load(path); err == nil {
		return follow(kp, identityDir()), nil
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	_ = save(path, kp) // best-effort; a persist failure just means next connect mints again
	return kp, nil
}

// Load returns the ALREADY-persisted identity keypair for handle, or an error when none
// exists. Unlike LoadOrGenerate it NEVER mints: callers that must present the key whose
// DANE-EE pin is already published (the summary uplink's mTLS client cert) use this,
// because a freshly-minted key would present an unpinned - and thus unverifiable - leaf.
func Load(handle string) (*Keypair, error) {
	kp, err := load(PathFor(handle))
	if err != nil {
		return nil, err
	}
	return follow(kp, identityDir()), nil
}

// ErrLinkedElsewhere is Link's answer when the handle already holds a DIFFERENT key. Nothing is
// replaced: the key already there may be the one an identity's records publish.
var ErrLinkedElsewhere = errors.New("idkey: a different key is already stored for this handle")

// Link stores kp under handle too, so every form that reaches one agent (its /128, a name, or
// the connect-first default) reaches the SAME key. It creates the file exclusively and
// never overwrites: an existing file holding the same key is success, one holding another key is
// ErrLinkedElsewhere and is left exactly as it was.
func Link(handle string, kp *Keypair) error {
	if kp == nil || kp.Private == nil {
		return errors.New("idkey: no key to link")
	}
	path := PathFor(handle)
	if cur, err := load(path); err == nil {
		if cur.MarshalSPKIBase64() == kp.MarshalSPKIBase64() ||
			follow(cur, identityDir()).MarshalSPKIBase64() == kp.MarshalSPKIBase64() {
			kp.unstored = false
			return nil // the handle holds this key, or a key whose recorded moves lead to it
		}
		return ErrLinkedElsewhere
	}
	if err := secfile.MkdirAllFor(path); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(kp.Private)
	if err != nil {
		return err
	}
	// Written whole to a private temporary first and then hard-linked into place: the link never
	// replaces an existing file, and no reader ever sees the handle's file half written.
	tmp := fmt.Sprintf("%s.link-%d-%d", path, os.Getpid(), time.Now().UnixNano())
	f, err := secfile.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_, werr := f.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			if cur, lerr := load(path); lerr == nil && (cur.MarshalSPKIBase64() == kp.MarshalSPKIBase64() ||
				follow(cur, identityDir()).MarshalSPKIBase64() == kp.MarshalSPKIBase64()) {
				kp.unstored = false
				return nil
			}
			return ErrLinkedElsewhere
		}
		return err
	}
	kp.unstored = false
	return nil
}

// Unlink removes the file stored under handle, but only while it still holds kp: it undoes a Link
// whose key turned out not to be wanted, and never removes a key someone else stored meanwhile.
// A file that is already gone is success.
func Unlink(handle string, kp *Keypair) error {
	if kp == nil {
		return errors.New("idkey: no key to unlink")
	}
	path := PathFor(handle)
	cur, err := load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if cur.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		return ErrLinkedElsewhere
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
	return &Keypair{Private: priv, spkiDER: der, dir: filepath.Dir(path)}, nil
}

// save persists kp as a PEM EC PRIVATE KEY that only its owner can read, creating the
// identity dir if needed. The private key NEVER touches argv/env/logs - this is the ONLY
// place it is ever written, to a single-user-readable file.
//
// Through secfile rather than a 0o600 mode argument: this is a PRIVATE KEY, and
// on Windows a mode argument decides nothing but the read-only attribute, so the file
// would have carried whatever DACL its directory happened to grant.
func save(path string, kp *Keypair) error {
	if err := secfile.MkdirAllFor(path); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(kp.Private)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return secfile.WriteFile(path, pem.EncodeToMemory(block))
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
	// The EKU lists both purposes because this one leaf plays both roles (RFC 5280 section
	// 4.2.1.12): the in-tunnel listener SERVES it on the /128:443, and it is also presented as
	// an mTLS CLIENT certificate. Listing only serverAuth would get it refused by a client-cert check that
	// enforces EKU (crypto/tls verifies a client chain for ExtKeyUsageClientAuth).
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: canonical},
		NotBefore:             now.Add(-5 * time.Minute), // clock-skew tolerance, mirrors the server leaf
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
