// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// allocationVector is one case of testdata/leaf-allocation-vectors.json, which the server's
// own suite reads too.
type allocationVector struct {
	Name           string   `json:"name"`
	SubjectSerials []string `json:"subject_serials"`
	NotBeforeMs    int64    `json:"not_before_ms"`
	Current        struct {
		Kind    string `json:"kind"`
		AllocMs int64  `json:"alloc_ms"`
	} `json:"current"`
	Expect string `json:"expect"`
}

func loadAllocationVectors(t *testing.T) []allocationVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/leaf-allocation-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []allocationVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("the vector file holds no cases")
	}
	return vs
}

// selfSignedWithSerials mints a self-signed leaf whose subject carries each serial as its own
// serialNumber attribute, with the given notBefore.
func selfSignedWithSerials(t *testing.T, serials []string, notBefore time.Time) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subj := pkix.Name{CommonName: "a0000000000000e08"}
	for _, s := range serials {
		subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{Type: oidSerialNumber, Value: s})
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subj, NotBefore: notBefore,
		NotAfter: notBefore.Add(160 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestJudgeAllocationOverTheSharedVectors(t *testing.T) {
	for _, vc := range loadAllocationVectors(t) {
		t.Run(vc.Name, func(t *testing.T) {
			if vc.NotBeforeMs%1000 != 0 {
				t.Fatalf("not_before_ms %d is not a whole second, which no X.509 time can carry", vc.NotBeforeMs)
			}
			leaf := selfSignedWithSerials(t, vc.SubjectSerials, time.UnixMilli(vc.NotBeforeMs))
			if got := leaf.NotBefore.UnixMilli(); got != vc.NotBeforeMs {
				t.Fatalf("the minted notBefore is %d, want %d", got, vc.NotBeforeMs)
			}
			var cur Current
			switch vc.Current.Kind {
			case "none":
				cur = NoCurrentIdentity()
			case "unknown":
				cur = UnknownCurrentAllocation()
			case "known":
				cur = KnownAllocation(vc.Current.AllocMs)
			default:
				t.Fatalf("unknown current kind %q", vc.Current.Kind)
			}
			if got := JudgeAllocation(leaf, cur); string(got) != vc.Expect {
				t.Fatalf("JudgeAllocation = %s, want %s", got, vc.Expect)
			}
		})
	}
}

// The vectors must reach every verdict, or a row of the table goes untested on both sides.
func TestTheSharedVectorsCoverEveryVerdict(t *testing.T) {
	seen := map[string]bool{}
	for _, vc := range loadAllocationVectors(t) {
		seen[vc.Expect] = true
	}
	for _, v := range []Verdict{VerdictPass, VerdictNoCurrentIdentity, VerdictUnknownAllocation,
		VerdictMalformedAllocation, VerdictAllocationMismatch, VerdictIssuedBeforeAllocation} {
		if !seen[string(v)] {
			t.Errorf("no vector expects %s", v)
		}
	}
}

func TestJudgeAllocationReadsSubjectNamesNotSerialNumber(t *testing.T) {
	// Subject.SerialNumber keeps one value; two attributes must still read as malformed.
	leaf := selfSignedWithSerials(t, []string{"alloc-5", "alloc-6"}, time.UnixMilli(1767225600000))
	if leaf.Subject.SerialNumber == "" {
		t.Fatal("precondition: Go keeps one serialNumber in Subject.SerialNumber")
	}
	if got := JudgeAllocation(leaf, KnownAllocation(6)); got != VerdictMalformedAllocation {
		t.Fatalf("got %s", got)
	}
	if got := JudgeAllocation(nil, KnownAllocation(6)); got != VerdictIssuedBeforeAllocation {
		t.Fatalf("a nil leaf never passes a known allocation: %s", got)
	}
	if KnownAllocation(0).Kind != CurrentUnknown || KnownAllocation(-1).Kind != CurrentUnknown {
		t.Fatal("a non-positive allocation is unknown, never known")
	}
}

func idTXT(owner string, strs ...string) *dns.TXT {
	return &dns.TXT{Hdr: hdr(owner, dns.TypeTXT), Txt: strs}
}

func TestParseIdentityTXT(t *testing.T) {
	const o = agentFQDN
	cases := []struct {
		name    string
		rrs     []dns.RR
		present bool
		cur     Current
		errHas  string
	}{
		{"one record", []dns.RR{idTXT(o, "whisper-id1 alloc=1767225900000 status=active")}, true,
			KnownAllocation(1767225900000), ""},
		{"split character-strings are joined", []dns.RR{idTXT(o, "whisper-id1 alloc=17672", "25900000 status=active")},
			true, KnownAllocation(1767225900000), ""},
		{"legacy tag", []dns.RR{idTXT(o, "whisper-rdap1 alloc=42")}, true, KnownAllocation(42), ""},
		{"alloc and allocated agree", []dns.RR{idTXT(o, "whisper-id1 alloc=42 allocated=42")}, true,
			KnownAllocation(42), ""},
		{"no alloc reads as unknown", []dns.RR{idTXT(o, "whisper-id1 status=active")}, true,
			UnknownCurrentAllocation(), ""},
		{"allocated without alloc reads as unknown", []dns.RR{idTXT(o, "whisper-id1 allocated=42")}, true,
			UnknownCurrentAllocation(), ""},
		{"other TXT only", []dns.RR{idTXT(o, "v=spf1 -all")}, false, Current{}, ""},
		{"a token without = is skipped", []dns.RR{idTXT(o, "whisper-id1 junk alloc=42")}, true, KnownAllocation(42), ""},
		{"other TXT beside one record", []dns.RR{idTXT(o, "v=spf1 -all"), idTXT(o, "whisper-id1 alloc=42")}, true,
			KnownAllocation(42), ""},
		{"two whisper-id1", []dns.RR{idTXT(o, "whisper-id1 alloc=42"), idTXT(o, "whisper-id1 alloc=43")}, false,
			Current{}, "more than one"},
		{"whisper-id1 and whisper-rdap1 count together",
			[]dns.RR{idTXT(o, "whisper-rdap1 alloc=42"), idTXT(o, "whisper-id1 alloc=42")}, false, Current{}, "more than one"},
		{"a key said twice", []dns.RR{idTXT(o, "whisper-id1 alloc=42 alloc=43")}, false, Current{}, "twice"},
		{"a key said twice in another case", []dns.RR{idTXT(o, "whisper-id1 alloc=42 ALLOC=42")}, false, Current{}, "twice"},
		{"leading zero", []dns.RR{idTXT(o, "whisper-id1 alloc=042")}, false, Current{}, "leading zero"},
		{"zero", []dns.RR{idTXT(o, "whisper-id1 alloc=0")}, false, Current{}, "alloc="},
		{"sign", []dns.RR{idTXT(o, "whisper-id1 alloc=+42")}, false, Current{}, "alloc="},
		{"non-digit", []dns.RR{idTXT(o, "whisper-id1 alloc=4x2")}, false, Current{}, "alloc="},
		{"empty", []dns.RR{idTXT(o, "whisper-id1 alloc=")}, false, Current{}, "alloc="},
		{"20 digits", []dns.RR{idTXT(o, "whisper-id1 alloc=12345678901234567890")}, false, Current{}, "alloc="},
		{"alloc and allocated disagree", []dns.RR{idTXT(o, "whisper-id1 alloc=42 allocated=43")}, false, Current{},
			"allocated=43"},
		{"allocated malformed", []dns.RR{idTXT(o, "whisper-id1 alloc=42 allocated=042")}, false, Current{},
			"allocated=042"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, err := parseIdentityTXT(c.rrs)
			if c.errHas != "" {
				if err == nil || !errors.Is(err, errAmbiguous) || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("want an ambiguity error containing %q, got %v", c.errHas, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rec.present != c.present || rec.current != c.cur {
				t.Fatalf("got %+v, want present=%v current=%+v", rec, c.present, c.cur)
			}
		})
	}
}

// --- runDANE end to end over the signed fixture -------------------------------------------

// agentCALeaf mints a leaf for the fixture's identity under an issuing CA named exactly as the
// Whisper Agent CA's, naming the given serials, and republishes the TLSA pin to its SPKI.
func agentCALeaf(t *testing.T, fx *agentFixture, serials []string, notBefore time.Time) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{CommonName: AgentIssuingCACN, Organization: []string{AgentIssuingCAOrg}},
		NotBefore: notBefore.Add(-time.Hour), NotAfter: notBefore.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := pkix.Name{CommonName: "a0000000000000e08"}
	for _, s := range serials {
		subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{Type: oidSerialNumber, Value: s})
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: subj, NotBefore: notBefore,
		NotAfter: notBefore.Add(160 * time.Hour), DNSNames: []string{trimDot(agentFQDN)},
		IPAddresses: []net.IP{fx.addr.AsSlice()}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	fx.cert = leaf
	fx.opts.Handshaker = fixedHandshaker{cert: leaf}
	spki := SPKISHA256(leaf)
	owner := "_443._tcp." + agentFQDN
	tlsa := &dns.TLSA{Hdr: hdr(owner, dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1,
		Certificate: hex.EncodeToString(spki[:])}
	fx.h.res.set(owner, dns.TypeTLSA, signed(t, *fx, tlsa))
	// The identity document and transparency legs are not under test here.
	fx.opts.SkipIdentityDoc, fx.opts.SkipTransparency = true, true
}

func reportCheck(rep *Report, name string) Check {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

// withHostedZone makes the fixture's zone stand in for agents.whisper.online.
func withHostedZone(t *testing.T, zone string) {
	t.Helper()
	old := hostedAgentZone
	hostedAgentZone = zone
	t.Cleanup(func() { hostedAgentZone = old })
}

func TestRunDANEJudgesTheAllocation(t *testing.T) {
	const alloc1, alloc2 = int64(1767225900000), int64(1767312300000)
	nb := time.UnixMilli(1767225600000)
	present := func(strs ...string) func(*testing.T, agentFixture) {
		return func(t *testing.T, fx agentFixture) {
			var rrs []dns.RR
			for _, s := range strs {
				rrs = append(rrs, idTXT(agentFQDN, s))
			}
			fx.h.res.set(agentFQDN, dns.TypeTXT, signed(t, fx, rrs...))
		}
	}
	provenAbsent := func(t *testing.T, fx agentFixture) {
		fx.h.res.setMsg(agentFQDN, dns.TypeTXT, dns.RcodeSuccess, nil,
			append(nsecChain(t, fx, zoneNames()), signedSOA(t, fx, 300, 3600)...))
	}
	id := func(ms int64) string { return "whisper-id1 alloc=" + strconv.FormatInt(ms, 10) + " status=active" }
	cases := []struct {
		name     string
		serials  []string
		dns      func(*testing.T, agentFixture)
		hosted   bool
		pass     bool
		detailIn string
	}{
		{"the current allocation passes", []string{"alloc-" + strconv.FormatInt(alloc2, 10)}, present(id(alloc2)),
			false, true, "the current one"},
		{"a later allocation refuses the previous holder's leaf", []string{"alloc-" + strconv.FormatInt(alloc1, 10)},
			present(id(alloc2)), false, false, "a previous holder's certificate"},
		{"a leaf naming none issued before the allocation", nil, present(id(alloc2)), false, false,
			"before the current allocation"},
		{"a leaf naming none issued after the allocation", nil, present(id(alloc1)), false, true,
			"issued after the current allocation"},
		{"two whisper-id1 records fail", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			present(id(alloc2), id(alloc2)), false, false, "more than one whisper-id1"},
		{"a whisper-id1 with no alloc fails", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			present("whisper-id1 status=active"), false, false, "carries no alloc="},
		{"a stripped TXT in an otherwise good NOERROR answer fails", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			func(t *testing.T, fx agentFixture) {
				fx.h.res.setMsg(agentFQDN, dns.TypeTXT, dns.RcodeSuccess, nil, nil)
			}, false, false, "could not be proven present or absent"},
		{"an unsigned TXT fails", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			func(t *testing.T, fx agentFixture) {
				fx.h.res.set(agentFQDN, dns.TypeTXT, []dns.RR{idTXT(agentFQDN, id(alloc2))})
			}, false, false, "could not be proven present or absent"},
		{"a SERVFAIL fails", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			func(t *testing.T, fx agentFixture) {
				fx.h.res.setMsg(agentFQDN, dns.TypeTXT, dns.RcodeServerFailure, nil, nil)
			}, false, false, "could not be proven present or absent"},
		{"proven absent under the hosted zone fails", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			provenAbsent, true, false, "no identity holds it now"},
		{"proven absent for a BYOD name passes unbound", []string{"alloc-" + strconv.FormatInt(alloc2, 10)},
			provenAbsent, false, true, "(unbound)"},
		{"a malformed leaf allocation fails", []string{"alloc-0" + strconv.FormatInt(alloc2, 10)},
			present(id(alloc2)), false, false, "never mints"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := buildAgentFixture(t, "", "")
			if c.hosted {
				withHostedZone(t, agentZone)
			}
			agentCALeaf(t, &fx, c.serials, nb)
			c.dns(t, fx)
			rep, err := Verify(context.Background(), testAddr, fx.opts)
			if err != nil {
				t.Fatal(err)
			}
			dane := reportCheck(rep, "dane")
			if !strings.Contains(dane.Anchor, "allocation consistency check on the DANE path") {
				t.Errorf("the anchor does not label the allocation check: %q", dane.Anchor)
			}
			if !strings.Contains(dane.Detail, c.detailIn) {
				t.Errorf("detail %q does not say %q", dane.Detail, c.detailIn)
			}
			if c.pass {
				if dane.Status != StatusPass || !rep.Verdict {
					t.Fatalf("want a pass, got %s: %s", dane.Status, dane.Detail)
				}
				return
			}
			if dane.Status != StatusFail || rep.Verdict {
				t.Fatalf("want a fail, got %s (verdict %v): %s", dane.Status, rep.Verdict, dane.Detail)
			}
		})
	}
}

// An agent's own certificate (any other issuer, no allocation named) is DANE-EE's alone: the
// TXT is never read, so even a stripped one changes nothing, under the hosted zone or not.
func TestRunDANELeavesAnAgentsOwnCertificateAlone(t *testing.T) {
	for _, hosted := range []bool{false, true} {
		fx := buildAgentFixture(t, "", "")
		if hosted {
			withHostedZone(t, agentZone)
		}
		fx.h.res.setMsg(agentFQDN, dns.TypeTXT, dns.RcodeSuccess, nil, nil)
		rep, err := Verify(context.Background(), testAddr, fx.opts)
		if err != nil {
			t.Fatal(err)
		}
		dane := reportCheck(rep, "dane")
		if dane.Status != StatusPass || !rep.Verdict {
			t.Fatalf("hosted=%v: want a pass, got %s: %s", hosted, dane.Status, dane.Detail)
		}
		if strings.Contains(dane.Anchor, "allocation") || strings.Contains(dane.Detail, "allocation") {
			t.Fatalf("hosted=%v: the allocation check ran on an agent's own certificate: %+v", hosted, dane)
		}
	}
}

// A self-signed leaf that names an allocation is judged even though its issuer is not the
// Agent CA: naming an allocation is a claim, and a claim is checked.
func TestRunDANEJudgesAnySelfSignedLeafThatNamesAnAllocation(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	leaf := selfSignedWithSerials(t, []string{"alloc-5"}, time.UnixMilli(1767225600000))
	if !allocationApplies(leaf) {
		t.Fatal("a leaf naming an allocation must be judged")
	}
	fx.h.res.set(agentFQDN, dns.TypeTXT, signed(t, fx, idTXT(agentFQDN, "whisper-id1 alloc=6")))
	got := fx.h.validator().CheckLeafAllocation(context.Background(), leaf, agentFQDN)
	if got.Pass || !got.Superseded || got.Verdict != VerdictAllocationMismatch {
		t.Fatalf("%+v", got)
	}
}
