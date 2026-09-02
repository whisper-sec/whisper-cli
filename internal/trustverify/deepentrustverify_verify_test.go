// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

// (deepen-trustverify): the top-level Verify() chain's failure legs - every
// DNSSEC cross-check break (missing PTR/AAAA/TLSA, forward-confirm and PTR mismatches, a
// pin-less TLSA RRset), the DANE handshake failure, the caller-error contract, and the
// zero-config defaults that production runs on.

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type deepentrustverify_refusingHandshaker struct{}

func (deepentrustverify_refusingHandshaker) Leaf(context.Context, string, string) (*x509.Certificate, error) {
	return nil, errString("injected handshake refusal")
}

func TestDeepenTV_Verify_EmptyTargetIsACallerError(t *testing.T) {
	// The ONLY non-nil error Verify may return is a caller-side problem; everything else is
	// carried in the Report. An all-whitespace target is that caller error.
	rep, err := Verify(context.Background(), "   ", Options{})
	if err == nil || rep != nil {
		t.Fatalf("want (nil, error) for an empty target, got rep=%v err=%v", rep, err)
	}
	if !strings.Contains(err.Error(), "empty target") {
		t.Fatalf("the error must say what is wrong: %v", err)
	}
}

func TestDeepenTV_Verify_SkipFlagsKeepTheTrustlessCore(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	fx.opts.SkipTransparency = true
	fx.opts.SkipIdentityDoc = true
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !rep.Verdict {
		t.Fatalf("dnssec+dane alone must prove; report: %+v", rep)
	}
	if len(rep.Checks) != 2 || rep.Checks[0].Name != "dnssec" || rep.Checks[1].Name != "dane" {
		t.Fatalf("want exactly the two trustless checks, got: %+v", rep.Checks)
	}
	// With the identity_doc skipped the tenant comes from the FQDN labels.
	if rep.Tenant != agentTenant || rep.Agent == "" {
		t.Fatalf("agent/tenant must still be read from the fqdn labels: %+v", rep)
	}
	if rep.Address != netip.MustParseAddr(testAddr).String() || rep.FQDN != trimDot(agentFQDN) {
		t.Fatalf("the proven addr/fqdn must be reported: %+v", rep)
	}
}

func TestDeepenTV_Verify_MissingPTRFailsByAddress(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rev, err := dns.ReverseAddr(fx.addr.String())
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	delete(fx.h.res.answers, rkey(rev, dns.TypePTR))
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL without a PTR, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "PTR") {
		t.Fatalf("the detail must name the broken leg: %s", d)
	}
}

func TestDeepenTV_Verify_ForwardConfirmMismatchFails(t *testing.T) {
	// The PTR names the fqdn, but AAAA(fqdn) resolves to a DIFFERENT /128 than the queried
	// one: the classic forward-confirmation fraud check.
	fx := buildAgentFixture(t, "", "")
	other := netip.MustParseAddr("2a04:2a01:9::beef")
	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: agentFQDN, Rrtype: dns.TypeAAAA,
		Class: dns.ClassINET, Ttl: 60}, AAAA: net.IP(other.AsSlice())}
	fx.h.res.set(agentFQDN, dns.TypeAAAA,
		[]dns.RR{aaaa, signRRSet(t, fx.h.childZSK, agentZone, []dns.RR{aaaa}, fx.h.now)})
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL for the forward-confirm break, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "forward-confirm failed") {
		t.Fatalf("the detail must name the forward-confirm break: %s", d)
	}
}

func TestDeepenTV_Verify_UnknownFQDNFailsOnAAAA(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rep, err := Verify(context.Background(), "nosuch.te08.agents.example", fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL for an unresolvable name, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "AAAA") {
		t.Fatalf("the detail must name the AAAA leg: %s", d)
	}
}

func TestDeepenTV_Verify_SignedEmptyAAAARdataFailsCleanly(t *testing.T) {
	// A validly SIGNED AAAA RRset whose record carries empty rdata (a broken or hostile
	// authoritative): the chain must fail with a clear diagnostic, never panic or treat the
	// zero address as proven.
	fx := buildAgentFixture(t, "", "")
	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: agentFQDN, Rrtype: dns.TypeAAAA,
		Class: dns.ClassINET, Ttl: 60}, AAAA: net.IP(nil)}
	fx.h.res.set(agentFQDN, dns.TypeAAAA,
		[]dns.RR{aaaa, signRRSet(t, fx.h.childZSK, agentZone, []dns.RR{aaaa}, fx.h.now)})
	rep, err := Verify(context.Background(), trimDot(agentFQDN), fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL for empty AAAA rdata, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "AAAA had no address") {
		t.Fatalf("the detail must name the empty-rdata break: %s", d)
	}
}

func TestDeepenTV_Verify_MissingPTRFailsByFQDN(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rev, err := dns.ReverseAddr(fx.addr.String())
	if err != nil {
		t.Fatalf("reverse: %v", err)
	}
	delete(fx.h.res.answers, rkey(rev, dns.TypePTR))
	rep, err := Verify(context.Background(), trimDot(agentFQDN), fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL without the reverse proof, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "PTR") {
		t.Fatalf("the detail must name the PTR leg: %s", d)
	}
}

func TestDeepenTV_Verify_PTRMismatchFailsByFQDN(t *testing.T) {
	// Starting FROM the name: AAAA proves an address whose PTR names someone ELSE.
	fx := buildAgentFixture(t, "", "someone-else.agents.example.")
	rep, err := Verify(context.Background(), trimDot(agentFQDN), fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL for the PTR mismatch, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "does not match") {
		t.Fatalf("the detail must show the mismatch: %s", d)
	}
}

func TestDeepenTV_Verify_MissingTLSAFails(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	delete(fx.h.res.answers, rkey("_443._tcp."+agentFQDN, dns.TypeTLSA))
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL without a TLSA pin, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "TLSA") {
		t.Fatalf("the detail must name the TLSA leg: %s", d)
	}
}

func TestDeepenTV_Verify_TLSAWithoutDANEEEPinFails(t *testing.T) {
	// The TLSA RRset validates but publishes only a 2 1 1 (usage=CA-constraint) association:
	// no DANE-EE pin exists, so nothing can anchor the served cert.
	fx := buildAgentFixture(t, "", "")
	leafOwner := "_443._tcp." + agentFQDN
	served := SPKISHA256(fx.cert)
	tlsa := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: dns.Fqdn(leafOwner), Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 2, Selector: 1, MatchingType: 1,
		Certificate: TLSAPin{SHA256: served[:]}.Hex(),
	}
	fx.h.res.set(leafOwner, dns.TypeTLSA,
		[]dns.RR{tlsa, signRRSet(t, fx.h.childZSK, agentZone, []dns.RR{tlsa}, fx.h.now)})
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("want a dnssec FAIL without a 3 1 1 pin, got: %+v", rep.Checks)
	}
	if d := rep.Checks[0].Detail; !strings.Contains(d, "no DANE-EE") {
		t.Fatalf("the detail must name the missing DANE-EE pin: %s", d)
	}
}

func TestDeepenTV_Verify_HandshakeFailureFailsDANE(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	fx.opts.Handshaker = deepentrustverify_refusingHandshaker{}
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict || statusOf(rep, "dane") != StatusFail {
		t.Fatalf("want a dane FAIL when no handshake completes, got: %+v", rep.Checks)
	}
	if statusOf(rep, "dnssec") != StatusPass {
		t.Fatalf("the dnssec leg must still PASS on its own: %+v", rep.Checks)
	}
	if rep.ServedSPKI != "" {
		t.Fatalf("no SPKI may be reported without a handshake, got %q", rep.ServedSPKI)
	}
}

func TestDeepenTV_FillDefaults_ZeroConfigProductionShape(t *testing.T) {
	opts := Options{}
	fillDefaults(&opts)
	if opts.Resolver == nil || opts.Handshaker == nil || opts.Fetcher == nil {
		t.Fatal("every I/O boundary must default to a production implementation")
	}
	if opts.RDAPBase != DefaultRDAPBase {
		t.Fatalf("RDAPBase = %q, want %q", opts.RDAPBase, DefaultRDAPBase)
	}
	if len(opts.JWKSURLs) != 3 ||
		opts.JWKSURLs[0] != DefaultRDAPBase+"/.well-known/jwks.json" ||
		opts.JWKSURLs[1] != "https://whisper.online/.well-known/jwks.json" ||
		opts.JWKSURLs[2] != "https://agents.whisper.online/.well-known/jwks.json" {
		t.Fatalf("JWKSURLs must aggregate the three published surfaces, got: %v", opts.JWKSURLs)
	}
	want := IANARootAnchors()
	if len(opts.RootAnchors) != len(want) || opts.RootAnchors[0] != want[0] {
		t.Fatalf("RootAnchors must default to the IANA set, got: %+v", opts.RootAnchors)
	}
	if opts.KeyAnchorZone != DefaultKeyAnchorZone {
		t.Fatalf("KeyAnchorZone = %q, want %q", opts.KeyAnchorZone, DefaultKeyAnchorZone)
	}
	if opts.Now.IsZero() {
		t.Fatal("Now must default to the wall clock")
	}
	if opts.Port != 443 {
		t.Fatalf("Port = %d, want 443", opts.Port)
	}
}

func TestDeepenTV_FillDefaults_CustomBaseDerivesJWKS(t *testing.T) {
	opts := Options{RDAPBase: "https://rdap.example/", Port: 8443}
	fillDefaults(&opts)
	if opts.JWKSURLs[0] != "https://rdap.example/.well-known/jwks.json" {
		t.Fatalf("the first JWKS URL must derive from the custom base (trailing slash trimmed), got: %v",
			opts.JWKSURLs)
	}
	if opts.Port != 8443 {
		t.Fatalf("an explicit port must be preserved, got %d", opts.Port)
	}
}

func TestDeepenTV_KeyAnchorName_DisplayFallbacks(t *testing.T) {
	if got := keyAnchorName(nil); got != identityAnchorLabel+"."+DefaultKeyAnchorZone {
		t.Fatalf("nil keys: got %q", got)
	}
	if got := keyAnchorName(&DNSAnchoredKeys{}); got != identityAnchorLabel+"."+DefaultKeyAnchorZone {
		t.Fatalf("empty IdentityName: got %q", got)
	}
	if got := keyAnchorName(&DNSAnchoredKeys{IdentityName: "_whisper-identity.example"}); got !=
		"_whisper-identity.example" {
		t.Fatalf("validated owner name must win: got %q", got)
	}
}

func TestDeepenTV_SmallHelpers_EmptyAndMismatchReturns(t *testing.T) {
	if got := ptrTarget(nil); got != "" {
		t.Fatalf("ptrTarget(nil) = %q", got)
	}
	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}}
	if got := ptrTarget([]dns.RR{aaaa}); got != "" {
		t.Fatalf("ptrTarget over non-PTR rrs = %q", got)
	}
	a := netip.MustParseAddr("2a04:2a01::1")
	if containsAddr(nil, a) {
		t.Fatal("containsAddr(nil) must be false")
	}
	if containsAddr([]netip.Addr{netip.MustParseAddr("2a04:2a01::2")}, a) {
		t.Fatal("a non-member must be false")
	}
	// The v4-mapped form of the same address must compare equal (both sides Unmap).
	mapped := netip.AddrFrom16(netip.MustParseAddr("::ffff:192.0.2.1").As16())
	if !containsAddr([]netip.Addr{mapped}, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("a v4-mapped member must match its unmapped form")
	}
}
