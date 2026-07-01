// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

const (
	testFQDN = "aa.te.agents.example."
	testAddr = "2a04:2a01:9:0:a4df:67f8:5ca4:792a"
)

func daneFixture(t *testing.T) (*dns.TLSA, TLSAPin, netip.Addr) {
	t.Helper()
	addr := netip.MustParseAddr(testAddr)
	cert, _ := genLeafCert(t, []string{trimDot(testFQDN)}, []net.IP{addr.AsSlice()})
	spki := SPKISHA256(cert)
	tlsa := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: "_443._tcp." + testFQDN, Rrtype: dns.TypeTLSA},
		Usage: 3, Selector: 1, MatchingType: 1,
		Certificate: hex.EncodeToString(spki[:]),
	}
	pin, err := ExtractDANEEEPin([]dns.RR{tlsa})
	if err != nil {
		t.Fatalf("extract pin: %v", err)
	}
	return tlsa, pin, addr
}

func TestCheckDANEEE_HappyPath(t *testing.T) {
	addr := netip.MustParseAddr(testAddr)
	cert, _ := genLeafCert(t, []string{trimDot(testFQDN)}, []net.IP{addr.AsSlice()})
	spki := SPKISHA256(cert)
	pin := TLSAPin{SHA256: spki[:]}
	if err := CheckDANEEE(cert, pin, addr, testFQDN); err != nil {
		t.Fatalf("expected PASS, got %v", err)
	}
}

func TestCheckDANEEE_WrongSPKIFails(t *testing.T) {
	addr := netip.MustParseAddr(testAddr)
	cert, _ := genLeafCert(t, []string{trimDot(testFQDN)}, []net.IP{addr.AsSlice()})
	bogus := make([]byte, 32) // all-zero pin, not the served SPKI
	if err := CheckDANEEE(cert, TLSAPin{SHA256: bogus}, addr, testFQDN); err == nil {
		t.Fatal("expected FAIL for a wrong SPKI pin")
	}
}

func TestCheckDANEEE_MissingIPSANFails(t *testing.T) {
	addr := netip.MustParseAddr(testAddr)
	// Cert has the DNS-SAN but NO IP-SAN.
	cert, _ := genLeafCert(t, []string{trimDot(testFQDN)}, nil)
	spki := SPKISHA256(cert)
	if err := CheckDANEEE(cert, TLSAPin{SHA256: spki[:]}, addr, testFQDN); err == nil {
		t.Fatal("expected FAIL for a missing IP-SAN")
	}
}

func TestCheckDANEEE_WrongIPSANFails(t *testing.T) {
	addr := netip.MustParseAddr(testAddr)
	other := netip.MustParseAddr("2a04:2a01:9::dead")
	cert, _ := genLeafCert(t, []string{trimDot(testFQDN)}, []net.IP{other.AsSlice()})
	spki := SPKISHA256(cert)
	if err := CheckDANEEE(cert, TLSAPin{SHA256: spki[:]}, addr, testFQDN); err == nil {
		t.Fatal("expected FAIL when the IP-SAN is a DIFFERENT address")
	}
}

func TestCheckDANEEE_MissingDNSSANFails(t *testing.T) {
	addr := netip.MustParseAddr(testAddr)
	cert, _ := genLeafCert(t, []string{"someone-else.example."}, []net.IP{addr.AsSlice()})
	spki := SPKISHA256(cert)
	if err := CheckDANEEE(cert, TLSAPin{SHA256: spki[:]}, addr, testFQDN); err == nil {
		t.Fatal("expected FAIL when the DNS-SAN does not match the fqdn")
	}
}

func TestExtractDANEEEPin_OnlyAcceptsThreeOneOne(t *testing.T) {
	// A usage-1 (PKIX-EE) TLSA is NOT the CA-independent profile we require.
	tlsa := &dns.TLSA{Hdr: dns.RR_Header{Rrtype: dns.TypeTLSA}, Usage: 1, Selector: 1, MatchingType: 1,
		Certificate: hex.EncodeToString(make([]byte, 32))}
	if _, err := ExtractDANEEEPin([]dns.RR{tlsa}); err == nil {
		t.Fatal("expected FAIL for a non 3-1-1 TLSA")
	}
}

func TestExtractDANEEEPin_HappyPath(t *testing.T) {
	_, pin, _ := daneFixture(t)
	if len(pin.SHA256) != 32 {
		t.Fatalf("pin len = %d, want 32", len(pin.SHA256))
	}
}
