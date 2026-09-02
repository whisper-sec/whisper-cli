// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// whale_dns_test.go pins the two rules this verb lives by: the verdict shown is the
// resolver's own signal read off the wire and never recomputed here, and a credential in
// a URL is not printed to a screen that gets pasted into tickets.

// TestPolicySignal_ReadsTheResolversOwnExtendedError: a name declined by policy comes
// back REFUSED with EDE 17, and that is the verdict, straight from the only place a
// verdict is decided.
func TestPolicySignal_ReadsTheResolversOwnExtendedError(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.example.", dns.TypeA)
	msg.Rcode = dns.RcodeRefused
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 17, ExtraText: "declined by tenant policy"})
	msg.Extra = append(msg.Extra, opt)

	signal, detail := policySignal(msg)
	if !strings.Contains(signal, "EDE 17") {
		t.Fatalf("policy signal = %q, want the extended error the resolver attached", signal)
	}
	if detail != "declined by tenant policy" {
		t.Fatalf("detail = %q, want the resolver's own extra text", detail)
	}
}

// TestPolicySignal_ANormalAnswerClaimsNothing: no signal on the wire must render as "no
// signal", not as an inferred allow.
func TestPolicySignal_ANormalAnswerClaimsNothing(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	signal, detail := policySignal(msg)
	if signal != "none" {
		t.Fatalf("policy signal = %q, want %q", signal, "none")
	}
	if strings.Contains(strings.ToLower(detail+signal), "allow") {
		t.Fatalf("a normal answer was rendered as an allow verdict: %q / %q", signal, detail)
	}
}

// TestPolicySignal_ARefusalWithNoEDESaysExactlyThat.
func TestPolicySignal_ARefusalWithNoEDESaysExactlyThat(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeRefused
	signal, detail := policySignal(msg)
	if signal != "REFUSED" || !strings.Contains(detail, "no extended error") {
		t.Fatalf("got (%q,%q), want the refusal reported with its missing detail named", signal, detail)
	}
}

// TestMaskDoHURL_HidesTheDeviceCredential: the DoH URL carries a resolve-only token in
// its path, and `dns status` is a screen people paste.
func TestMaskDoHURL_HidesTheDeviceCredential(t *testing.T) {
	const secret = "et_devicetokenvalue"
	masked := maskDoHURL("https://doh.whisper.online/" + secret + "/dns-query")
	if strings.Contains(masked, secret) {
		t.Fatalf("maskDoHURL leaked the token: %q", masked)
	}
	if !strings.Contains(masked, "doh.whisper.online") {
		t.Fatalf("maskDoHURL lost the host, so the cell says nothing useful: %q", masked)
	}
	// The keyless template carries no credential and must survive intact.
	if got := maskDoHURL("https://doh.whisper.online/dns-query"); got != "https://doh.whisper.online/dns-query" {
		t.Fatalf("maskDoHURL mangled a credential-free URL: %q", got)
	}
	if got := maskDoHURL(""); got != "" {
		t.Fatalf("maskDoHURL(\"\") = %q", got)
	}
}

// TestWhaleResolverAddr_SaysWhereTheChoiceCameFrom: a surprising answer must always be
// traceable to the server that gave it.
func TestWhaleResolverAddr_SaysWhereTheChoiceCameFrom(t *testing.T) {
	addr, via := whaleResolverAddr("2a04:2a01:0:53::1")
	if addr != "[2a04:2a01:0:53::1]:53" {
		t.Fatalf("addr = %q, want the flag value with the default port", addr)
	}
	if via != "--server" {
		t.Fatalf("via = %q, want it to name the flag", via)
	}
	if addr2, _ := whaleResolverAddr("192.0.2.1:5353"); addr2 != "192.0.2.1:5353" {
		t.Fatalf("an explicit port was rewritten: %q", addr2)
	}
	_, via2 := whaleResolverAddr("")
	if via2 == "" {
		t.Fatal("the default resolver choice was not explained at all")
	}
}

// TestWhaleDNSQuery_RendersPolicyAndGraphAsDifferentThings is the security-shaped
// assertion: the resolver's decision and the graph's assessment are two different rows,
// with a footnote saying which is which, so nobody reads the band as a verdict.
func TestWhaleDNSQuery_RendersPolicyAndGraphAsDifferentThings(t *testing.T) {
	view := whaleDNSQueryView{
		Name: "example.com", Type: "A", Resolver: "192.0.2.1:53", Via: "--server",
		Rcode: "NOERROR", RTTMs: 12.5,
		Answer:       []string{"example.com. 60 IN A 192.0.2.9"},
		Policy:       "none",
		PolicyDetail: "the resolver answered normally and attached no policy signal",
		Assessment:   "MALICIOUS", AssessNote: "coverage broad",
	}
	stdout, stderr := captureStd(t, func() { renderWhaleDNSQuery(view) })
	for _, want := range []string{"policy", "graph", "MALICIOUS"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the query table is missing %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "not a second verdict computed here") {
		t.Fatalf("the footnote does not separate the graph's input from the resolver's verdict:\n%s", stderr)
	}
}

// TestWhaleDNSQuery_AResolverThatDidNotAnswerIsAnError, not a table of blanks.
func TestWhaleDNSQuery_AResolverThatDidNotAnswerIsAnError(t *testing.T) {
	whaleTestIsolation(t)
	prev := exchangeDNS
	exchangeDNS = func(context.Context, string, string, uint16) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("i/o timeout")
	}
	t.Cleanup(func() { exchangeDNS = prev })

	var err error
	stdout, _ := captureStd(t, func() {
		err = deepencli_exec(t, newWhaleDNSQueryCmd(), "example.com", "--server", "192.0.2.1")
	})
	if err == nil {
		t.Fatal("a resolver that never answered produced a successful run")
	}
	if !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("error = %q, want it to say the resolver did not answer", err.Error())
	}
	if !strings.Contains(stdout, "example.com") {
		t.Fatalf("the failing run printed no question at all:\n%s", stdout)
	}
}

// TestWhaleDNSQuery_RejectsAnUnknownTypeWithTheTypesItKnows.
func TestWhaleDNSQuery_RejectsAnUnknownTypeWithTheTypesItKnows(t *testing.T) {
	whaleTestIsolation(t)
	err := deepencli_exec(t, newWhaleDNSQueryCmd(), "example.com", "NOTATYPE")
	if err == nil || !isUsageError(err) {
		t.Fatalf("an unknown record type = %v, want a usage error", err)
	}
	if !strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("the error %q does not name any type that would work", err.Error())
	}
}
