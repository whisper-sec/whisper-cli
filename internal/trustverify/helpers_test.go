// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- fake Resolver over a canned answer map -------------------------------------------

type mapResolver struct {
	answers map[string]*dns.Msg // key: canonicalName|qtype
}

func newMapResolver() *mapResolver { return &mapResolver{answers: map[string]*dns.Msg{}} }

func rkey(name string, qtype uint16) string {
	return dns.CanonicalName(name) + "|" + strconv.Itoa(int(qtype))
}

func (m *mapResolver) set(name string, qtype uint16, answer []dns.RR) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = answer
	m.answers[rkey(name, qtype)] = msg
}

func (m *mapResolver) Query(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if msg, ok := m.answers[rkey(name, qtype)]; ok {
		return msg.Copy(), nil
	}
	return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, nil
}

// --- signed DNSSEC test hierarchy -----------------------------------------------------

type testKey struct {
	dnskey *dns.DNSKEY
	signer crypto.Signer
}

func genKey(t *testing.T, zone string, flags uint16) testKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate DNSKEY for %s: %v", zone, err)
	}
	return testKey{dnskey: k, signer: priv.(crypto.Signer)}
}

// signRRSet returns an RRSIG over rrset made by key, signed for the given signer zone.
func signRRSet(t *testing.T, key testKey, zone string, rrset []dns.RR, now time.Time) *dns.RRSIG {
	t.Helper()
	owner := rrset[0].Header().Name
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.dnskey.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(14 * 24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-24 * time.Hour).Unix()),
		KeyTag:      key.dnskey.KeyTag(),
		SignerName:  dns.Fqdn(zone),
	}
	if err := sig.Sign(key.signer, rrset); err != nil {
		t.Fatalf("sign %s in %s: %v", dns.TypeToString[sig.TypeCovered], zone, err)
	}
	return sig
}

// hierarchy is a two-level signed test zone: root (".") -> child, with a leaf TLSA in child.
type hierarchy struct {
	res      *mapResolver
	anchors  []AnchorDS
	now      time.Time
	rootKSK  testKey
	rootZSK  testKey
	childKSK testKey
	childZSK testKey
	child    string
}

// buildHierarchy wires a fully-signed root -> child delegation with a TLSA leaf and returns
// the map resolver + the trust anchor for the root KSK.
func buildHierarchy(t *testing.T, child, leafOwner string, tlsaHex string) *hierarchy {
	t.Helper()
	now := time.Now()
	h := &hierarchy{res: newMapResolver(), now: now, child: dns.Fqdn(child)}
	h.rootKSK = genKey(t, ".", 257)
	h.rootZSK = genKey(t, ".", 256)
	h.childKSK = genKey(t, child, 257)
	h.childZSK = genKey(t, child, 256)

	// Root DNSKEY RRset, self-signed by the root KSK.
	rootKeys := []dns.RR{h.rootKSK.dnskey, h.rootZSK.dnskey}
	rootKeySig := signRRSet(t, h.rootKSK, ".", rootKeys, now)
	h.res.set(".", dns.TypeDNSKEY, append(append([]dns.RR{}, rootKeys...), rootKeySig))

	// DS(child) = ToDS(childKSK), signed by the root ZSK.
	ds := h.childKSK.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: dns.Fqdn(child), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	dsSig := signRRSet(t, h.rootZSK, ".", []dns.RR{ds}, now)
	h.res.set(child, dns.TypeDS, []dns.RR{ds, dsSig})

	// Child DNSKEY RRset, self-signed by the child KSK.
	childKeys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	childKeySig := signRRSet(t, h.childKSK, child, childKeys, now)
	h.res.set(child, dns.TypeDNSKEY, append(append([]dns.RR{}, childKeys...), childKeySig))

	// The leaf TLSA, signed by the child ZSK.
	tlsa := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: dns.Fqdn(leafOwner), Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  tlsaHex,
	}
	tlsaSig := signRRSet(t, h.childZSK, child, []dns.RR{tlsa}, now)
	h.res.set(leafOwner, dns.TypeTLSA, []dns.RR{tlsa, tlsaSig})

	// The trust anchor: the root KSK's DS.
	rootDS := h.rootKSK.dnskey.ToDS(dns.SHA256)
	h.anchors = []AnchorDS{{
		KeyTag:     rootDS.KeyTag,
		Algorithm:  rootDS.Algorithm,
		DigestType: rootDS.DigestType,
		Digest:     rootDS.Digest,
	}}
	return h
}

func (h *hierarchy) validator() *Validator { return NewValidator(h.res, h.anchors, h.now) }

// --- DANE cert generation -------------------------------------------------------------

func genLeafCert(t *testing.T, dnsNames []string, ips []net.IP) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	cn := "leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Whisper Agent Identity Issuing CA"},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, priv
}

// --- ES256 JWS test helpers -----------------------------------------------------------

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwkFor(priv *ecdsa.PrivateKey, kid string) JWK {
	return JWK{
		Kty: "EC", Crv: "P-256", Alg: "ES256", Use: "sig", Kid: kid,
		X: b64u(priv.PublicKey.X.FillBytes(make([]byte, 32))),
		Y: b64u(priv.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey, kid, typ string, payload []byte) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ, "kid": kid})
	h := b64u(hdr)
	p := b64u(payload)
	digest := sha256.Sum256([]byte(h + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("es256 sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return h + "." + p + "." + b64u(sig)
}

// --- fake Fetcher ---------------------------------------------------------------------

type fakeFetcher struct {
	get    func(url string) ([]byte, int, error)
	pinned func(hostport, sni, path string) ([]byte, int, error)
}

func (f *fakeFetcher) Get(_ context.Context, url string) ([]byte, int, error) {
	if f.get == nil {
		return nil, 0, errString("no get handler")
	}
	return f.get(url)
}

func (f *fakeFetcher) GetPinned(_ context.Context, hostport, sni, path string, _ TLSAPin) ([]byte, int, error) {
	if f.pinned == nil {
		return nil, 0, errString("no pinned handler")
	}
	return f.pinned(hostport, sni, path)
}

type errString string

func (e errString) Error() string { return string(e) }
