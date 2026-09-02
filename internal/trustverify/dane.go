// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Handshaker performs a TLS handshake and returns the peer's leaf certificate WITHOUT any
// chain or hostname verification -- DANE-EE (RFC 6698/7671) does its own verification against
// the DNSSEC-validated TLSA pin, so a public CA is neither used nor needed.
type Handshaker interface {
	Leaf(ctx context.Context, hostport, sni string) (*x509.Certificate, error)
}

// tlsHandshaker is the production Handshaker.
type tlsHandshaker struct{ dialer *net.Dialer }

// NewTLSHandshaker returns the production Handshaker.
func NewTLSHandshaker() Handshaker {
	return &tlsHandshaker{dialer: &net.Dialer{Timeout: 10 * time.Second}}
}

func (h *tlsHandshaker) Leaf(ctx context.Context, hostport, sni string) (*x509.Certificate, error) {
	d := h.dialer
	if d == nil {
		d = &net.Dialer{Timeout: 10 * time.Second}
	}
	raw, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("dane: dialing %s: %w", hostport, err)
	}
	// InsecureSkipVerify: we intentionally skip WebPKI -- the agent cert is a DANE-EE cert,
	// not a publicly-chained one. We verify it ourselves against the DNSSEC TLSA pin below.
	conn := tls.Client(raw, &tls.Config{
		ServerName:         strings.TrimSuffix(sni, "."),
		InsecureSkipVerify: true, //nolint:gosec // DANE-EE: verified against the DNSSEC-validated pin, not WebPKI
		MinVersion:         tls.VersionTLS12,
	})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("dane: TLS handshake with %s (SNI %s): %w", hostport, sni, err)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("dane: %s presented no certificate", hostport)
	}
	return certs[0], nil
}

// SPKISHA256 is the DANE selector=1 (SubjectPublicKeyInfo), matching=1 (SHA-256)
// certificate-association value (RFC 6698 §2.1.2/): SHA-256 over the leaf's DER SPKI.
func SPKISHA256(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// TLSAPin holds a DANE-EE (usage 3, selector 1, matching 1) certificate-association value
// extracted from a DNSSEC-validated TLSA RRset -- the SHA-256 of the agent's SPKI.
type TLSAPin struct {
	SHA256 []byte // 32 bytes
}

// Hex returns the lowercase-hex form of the pin.
func (p TLSAPin) Hex() string { return hex.EncodeToString(p.SHA256) }

// ExtractDANEEEPin picks EVERY DANE-EE 3 1 1 association from a validated TLSA RRset (a
// make-before-break rotation publishes the OLD and NEW pins side by side, so a single-pin picker
// makes verification a coin flip on RRset ordering). It is otherwise conservative: only a full
// DANE-EE (usage 3), SPKI-selector (1), SHA-256 (1) pin is accepted -- the strong, CA-independent
// profile Whisper publishes. Order is preserved from the RRset (callers must not assume any is
// "the current" one -- CheckDANEEE accepts a match against ANY of them).
func ExtractDANEEEPin(rrs []dns.RR) ([]TLSAPin, error) {
	var pins []TLSAPin
	for _, rr := range rrs {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		if t.Usage == 3 && t.Selector == 1 && t.MatchingType == 1 {
			b, err := hex.DecodeString(t.Certificate)
			if err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("dane: TLSA 3 1 1 association is not a 32-byte SHA-256")
			}
			pins = append(pins, TLSAPin{SHA256: b})
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("dane: no DANE-EE (3 1 1) TLSA record published")
	}
	return pins, nil
}

// CheckDANEEE asserts the served leaf satisfies AT LEAST ONE of the DNSSEC-validated pins
// (RFC 7671 §8 make-before-break: during a rotation overlap both the old and new pins are
// published, and the served leaf legitimately matches only one of them) AND that its SANs bind the
// identity: a DNS-SAN == fqdn, and an IP-SAN == the /128 (RFC 7671 -- the cert is bound to the exact
// address it is served from). The SAN checks are independent of WHICH pin matched.
func CheckDANEEE(cert *x509.Certificate, pins []TLSAPin, addr netip.Addr, fqdn string) error {
	got := SPKISHA256(cert)
	matched := false
	for _, pin := range pins {
		if len(pin.SHA256) == sha256.Size && constEq(got[:], pin.SHA256) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("dane: served SPKI-SHA256 %s does NOT match any DNSSEC TLSA pin (%s)",
			hex.EncodeToString(got[:]), joinPinsHex(pins))
	}
	if !certHasDNSName(cert, fqdn) {
		return fmt.Errorf("dane: served cert has no DNS-SAN for %s (SANs: %v)", trimDot(fqdn), cert.DNSNames)
	}
	if !certHasIP(cert, addr) {
		return fmt.Errorf("dane: served cert has no IP-SAN for %s (IP-SANs: %v)", addr, cert.IPAddresses)
	}
	return nil
}

// joinPinsHex renders every pin's hex digest, comma-separated, for a diagnostic error message.
func joinPinsHex(pins []TLSAPin) string {
	hexes := make([]string, len(pins))
	for i, p := range pins {
		hexes[i] = p.Hex()
	}
	return strings.Join(hexes, ",")
}

func certHasDNSName(cert *x509.Certificate, fqdn string) bool {
	want := strings.ToLower(trimDot(fqdn))
	for _, n := range cert.DNSNames {
		if strings.ToLower(trimDot(n)) == want {
			return true
		}
	}
	return false
}

func certHasIP(cert *x509.Certificate, addr netip.Addr) bool {
	for _, ip := range cert.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == addr.Unmap() {
			return true
		}
	}
	return false
}

// constEq is a length-checked, constant-time byte comparison.
func constEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
