// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The service's golden test pins these records for two fixed keys, so a client derivation
// that drifts from the published bytes fails here.
var goldenKeys = []struct {
	spki, tlsa, sshfp, openpgpSHA256 string
}{
	{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEHVe35mgnmuDYtA3f6gZp5xenvYUU7eHF6hcyZhZgJ/b9PUOnV9gveqSO6vdIOR80eXyfv+1S/V9eqGN0pN7GA==",
		"172859127d87517db65e37011164b0da196048224be566b1dff4178cc5561b8f",
		"353d27c6873f8e3b965760085c57d74909aa36da7abc7cd3d9d4259a8abbc0ec",
		"a331eee63406f1f5f60f367abb9244f49fafd0ce675aeb5a9294b76032c8d2bc"},
	{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbOP75kQctcEHXHEn8QRMy2oWvujC7LVTy5wwOjbEaiFrUConxvEPZpPUaPaHRjcZpiwC9V0+trB7dijUWwM8Cw==",
		"7d58e5f18ed01463355dc7a6b1c3221784f1b659a5f3bed53a5688757fa1ba87",
		"a4e4ee04918669e07efbd80f69abf3d7f0037bab63dc2a7e7157a77d4fdb8afd",
		"e4f46db6a04980314d8587bffe1104ad1833d2dcdccea11b6dfc52e1a19fcc07"},
}

// pgpPacket is the v4 ECDSA P-256 public-key packet the service publishes for a point, at its
// fixed creation time.
func pgpPacket(point []byte) []byte {
	body := []byte{4}
	body = binary.BigEndian.AppendUint32(body, 1767225600)
	body = append(body, pgpAlgECDSA, byte(len(pgpOIDP256)))
	body = append(body, pgpOIDP256...)
	body = binary.BigEndian.AppendUint16(body, pgpPointBits)
	body = append(body, point...)
	return append([]byte{pgpTagPubKey, byte(len(body))}, body...)
}

func TestServedPinDerivationsAreTheServicesGoldenBytes(t *testing.T) {
	for _, g := range goldenKeys {
		spki, _ := base64.StdEncoding.DecodeString(g.spki)
		c, err := candidateOf(spki)
		if err != nil {
			t.Fatal(err)
		}
		if c.digest != g.tlsa || c.sshfp != g.sshfp {
			t.Fatalf("tlsa %s sshfp %s", c.digest, c.sshfp)
		}
		pkt := pgpPacket(c.point)
		if sum := sha256.Sum256(pkt); hex.EncodeToString(sum[:]) != g.openpgpSHA256 {
			t.Fatalf("the OpenPGP packet is not the service's: %x", sum)
		}
		point, err := openpgpPoint(base64.StdEncoding.EncodeToString(pkt))
		if err != nil || hex.EncodeToString(point) != hex.EncodeToString(c.point) {
			t.Fatalf("the point does not read back: %v", err)
		}
		p := &ServedPins{TLSA: []string{g.tlsa}, AgentKey: []string{g.tlsa}, SSHFP: []string{g.sshfp},
			OpenPGP: [][]byte{point}}
		served, problems := p.Keys([][]byte{spki})
		if len(served) != 1 || served[0] != g.tlsa || len(problems) != 0 {
			t.Fatalf("served %v problems %v", served, problems)
		}
	}
}

func TestOpenPGPPointRefusesOtherShapes(t *testing.T) {
	good := pgpPacket(append([]byte{4}, make([]byte, 64)...))
	mut := func(f func(b []byte) []byte) string {
		b := f(append([]byte(nil), good...))
		return base64.StdEncoding.EncodeToString(b)
	}
	cases := map[string]string{
		"not base64":         "!!",
		"empty":              "",
		"old-format header":  mut(func(b []byte) []byte { b[0] = 0x99; return b }),
		"length mismatch":    mut(func(b []byte) []byte { return b[:len(b)-1] }),
		"v3":                 mut(func(b []byte) []byte { b[2] = 3; return b }),
		"RSA":                mut(func(b []byte) []byte { b[7] = 1; return b }),
		"another curve":      mut(func(b []byte) []byte { b[16] = 0x08; return b }),
		"compressed point":   mut(func(b []byte) []byte { b[19] = 0x02; return b }),
		"wrong MPI length":   mut(func(b []byte) []byte { b[18] = 0x02; return b }),
		"five-octet length":  mut(func(b []byte) []byte { b[1] = 0xff; return b }),
		"short body":         mut(func(b []byte) []byte { b = b[:30]; b[1] = 28; return b }),
		"two-octet, too big": base64.StdEncoding.EncodeToString([]byte{pgpTagPubKey, 0xc0, 0x00}),
	}
	for name, in := range cases {
		if _, err := openpgpPoint(in); err == nil {
			t.Errorf("%s: read as a key", name)
		}
	}
	// the two-octet length form is accepted when it is right
	long := append([]byte{pgpTagPubKey, 0xc0, 0x00}, make([]byte, 192)...)
	if _, err := openpgpPoint(base64.StdEncoding.EncodeToString(long)); err == nil ||
		!strings.Contains(err.Error(), "ECDSA") {
		t.Fatalf("a well-framed packet of another key: %v", err)
	}
}

func newP256(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pinsFor(t *testing.T, spkis ...[]byte) *ServedPins {
	t.Helper()
	p := &ServedPins{}
	for _, s := range spkis {
		c, err := candidateOf(s)
		if err != nil {
			t.Fatal(err)
		}
		p.TLSA = append(p.TLSA, c.digest)
		p.AgentKey = append(p.AgentKey, c.digest)
		p.SSHFP = append(p.SSHFP, c.sshfp)
		p.OpenPGP = append(p.OpenPGP, c.point)
	}
	return p
}

func TestServedKeysMatcher(t *testing.T) {
	a, b, stranger := newP256(t), newP256(t), newP256(t)
	da, _ := candidateOf(a)
	db, _ := candidateOf(b)

	// both keys of an overlap, served by all four kinds
	served, problems := pinsFor(t, a, b).Keys([][]byte{a, b})
	if len(served) != 2 || len(problems) != 0 || served[0] > served[1] {
		t.Fatalf("overlap: %v %v", served, problems)
	}
	// a key nobody asked about is a problem, the asked key still matches
	served, problems = pinsFor(t, a, stranger).Keys([][]byte{a})
	if len(served) != 1 || served[0] != da.digest || len(problems) != 4 {
		t.Fatalf("stranger: %v %v", served, problems)
	}
	// a key served by some kinds only is a problem and not served
	p := pinsFor(t, a)
	p.OpenPGP = nil
	served, problems = p.Keys([][]byte{a})
	if len(served) != 0 || len(problems) != 1 || !strings.Contains(problems[0], "OPENPGPKEY") {
		t.Fatalf("partial: %v %v", served, problems)
	}
	// a kind DNSSEC proves absent (a service that turned it off) is named in those words, and a
	// kind whose records name another key is still the plain mismatch beside it
	p = pinsFor(t, a)
	p.OpenPGP, p.Absent = nil, []string{"OPENPGPKEY"}
	p.SSHFP = []string{strings.Repeat("0", 64)}
	served, problems = p.Keys([][]byte{a})
	joined := strings.Join(problems, "\n")
	if len(served) != 0 || !strings.Contains(joined, "no OPENPGPKEY record is published at all") ||
		!strings.Contains(joined, "but not by SSHFP") || strings.Contains(joined, "not by SSHFP, OPENPGPKEY") {
		t.Fatalf("absent kind: %v %v", served, problems)
	}
	// every kind absent: said once, in those words
	none := &ServedPins{Absent: []string{"TLSA", "_whisper-agentkey", "SSHFP", "OPENPGPKEY"}}
	if served, problems := none.Keys([][]byte{a}); len(served) != 0 || len(problems) != 1 ||
		!strings.Contains(problems[0], "no key record of any kind is published") {
		t.Fatalf("all absent: %v %v", served, problems)
	}
	// a candidate no kind names is simply not served
	served, problems = pinsFor(t, a).Keys([][]byte{a, b})
	if len(served) != 1 || len(problems) != 0 {
		t.Fatalf("unserved candidate: %v %v", served, problems)
	}
	// the same key twice is one key; an unreadable candidate is named
	served, problems = pinsFor(t, a).Keys([][]byte{a, a, []byte("junk")})
	if len(served) != 1 || len(problems) != 1 || !strings.Contains(problems[0], "candidate 2") {
		t.Fatalf("dupes: %v %v", served, problems)
	}
	// case does not matter in hex
	p = pinsFor(t, b)
	p.TLSA[0] = strings.ToUpper(p.TLSA[0])
	if served, _ := p.Keys([][]byte{b}); len(served) != 1 || served[0] != db.digest {
		t.Fatalf("hex case: %v", served)
	}
	// an Ed25519 or RSA SPKI is not a candidate
	ed := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	ed = append(ed, make([]byte, 32)...)
	if _, problems := (&ServedPins{}).Keys([][]byte{ed}); len(problems) != 1 {
		t.Fatalf("ed25519 candidate: %v", problems)
	}
}

// publishPins puts the four records for spki into the fixture's zone, signed, and denies them
// nothing: every kind is present.
func publishPins(t *testing.T, fx agentFixture, res *mapResolver, spki []byte) {
	t.Helper()
	c, _ := candidateOf(spki)
	tlsa := &dns.TLSA{Hdr: hdr(tlsaPrefix+agentFQDN, dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1,
		Certificate: c.digest}
	other := &dns.TLSA{Hdr: hdr(tlsaPrefix+agentFQDN, dns.TypeTLSA), Usage: 2, Selector: 0, MatchingType: 1,
		Certificate: strings.Repeat("ab", 32)}
	res.set(tlsaPrefix+agentFQDN, dns.TypeTLSA, signed(t, fx, tlsa, other))
	txt := kelTXT(AgentKeyLabel+"."+agentFQDN, "v=whisper1; k=p256; p="+base64.StdEncoding.EncodeToString(spki))
	stray := kelTXT(AgentKeyLabel+"."+agentFQDN, "hello")
	res.set(AgentKeyLabel+"."+agentFQDN, dns.TypeTXT, signed(t, fx, txt, stray))
	fp := &dns.SSHFP{Hdr: hdr(agentFQDN, dns.TypeSSHFP), Algorithm: 3, Type: 2, FingerPrint: c.sshfp}
	ed := &dns.SSHFP{Hdr: hdr(agentFQDN, dns.TypeSSHFP), Algorithm: 4, Type: 2, FingerPrint: strings.Repeat("cd", 32)}
	res.set(agentFQDN, dns.TypeSSHFP, signed(t, fx, fp, ed))
	pgp := &dns.OPENPGPKEY{Hdr: hdr(openpgpPrefix+agentFQDN, dns.TypeOPENPGPKEY),
		PublicKey: base64.StdEncoding.EncodeToString(pgpPacket(c.point))}
	res.set(openpgpPrefix+agentFQDN, dns.TypeOPENPGPKEY, signed(t, fx, pgp))
}

func TestServedPinsReadsTheFourRecords(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	spki := newP256(t)
	publishPins(t, fx, fx.h.res, spki)
	got, err := fx.h.validator().ServedPins(context.Background(), agentFQDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.TLSA) != 1 || len(got.AgentKey) != 1 || len(got.SSHFP) != 1 || len(got.OpenPGP) != 1 {
		t.Fatalf("%+v", got)
	}
	if served, problems := got.Keys([][]byte{spki}); len(served) != 1 || len(problems) != 0 {
		t.Fatalf("%v %v", served, problems)
	}
}

func TestServedPinsProvesAbsentKindsAndRefusesUnprovenOnes(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	// OPENPGPKEY withdrawn, its absence proven by NSEC3
	names := zoneNames()
	spki := newP256(t)
	publishPins(t, fx, fx.h.res, spki)
	fx.h.res.setMsg(openpgpPrefix+agentFQDN, dns.TypeOPENPGPKEY, dns.RcodeNameError, nil,
		nsec3Chain(t, fx, names, 0, 0))
	got, err := fx.h.validator().ServedPins(context.Background(), agentFQDN)
	if err != nil || len(got.OpenPGP) != 0 || len(got.TLSA) != 1 || len(got.Absent) != 1 || got.Absent[0] != "OPENPGPKEY" {
		t.Fatalf("%+v %v", got, err)
	}
	// and the matcher says the kind is not published at all, not that it names another key
	if served, problems := got.Keys([][]byte{spki}); len(served) != 0 || len(problems) != 1 ||
		!strings.Contains(problems[0], "no OPENPGPKEY record is published at all") {
		t.Fatalf("%v %v", served, problems)
	}
	// a kind whose records name no key this check reads is not absent
	fx2 := buildAgentFixture(t, "", "")
	publishPins(t, fx2, fx2.h.res, newP256(t))
	if got2, err := fx2.h.validator().ServedPins(context.Background(), agentFQDN); err != nil || len(got2.Absent) != 0 {
		t.Fatalf("%+v %v", got2, err)
	}
	// the key TXT is named by its label, as the matcher names the kind
	fx3 := buildAgentFixture(t, "", "")
	spki3 := newP256(t)
	publishPins(t, fx3, fx3.h.res, spki3)
	fx3.h.res.setMsg(AgentKeyLabel+"."+agentFQDN, dns.TypeTXT, dns.RcodeNameError, nil, nsec3Chain(t, fx3, names, 0, 0))
	got3, err := fx3.h.validator().ServedPins(context.Background(), agentFQDN)
	if err != nil || len(got3.Absent) != 1 || got3.Absent[0] != AgentKeyLabel {
		t.Fatalf("%+v %v", got3, err)
	}
	if _, problems := got3.Keys([][]byte{spki3}); len(problems) != 1 ||
		!strings.Contains(problems[0], "no "+AgentKeyLabel+" record is published at all") {
		t.Fatalf("%v", problems)
	}
	// each kind that is neither answered nor denied is an error naming it
	for _, k := range []struct {
		owner string
		qtype uint16
	}{{tlsaPrefix + agentFQDN, dns.TypeTLSA}, {AgentKeyLabel + "." + agentFQDN, dns.TypeTXT},
		{agentFQDN, dns.TypeSSHFP}, {openpgpPrefix + agentFQDN, dns.TypeOPENPGPKEY}} {
		fx := buildAgentFixture(t, "", "")
		publishPins(t, fx, fx.h.res, newP256(t))
		fx.h.res.setMsg(k.owner, k.qtype, dns.RcodeNameError, nil, nil)
		if _, err := fx.h.validator().ServedPins(context.Background(), agentFQDN); err == nil ||
			!strings.Contains(err.Error(), dns.TypeToString[k.qtype]) {
			t.Fatalf("%s: %v", dns.TypeToString[k.qtype], err)
		}
	}
	// a broken key record and an unreadable OPENPGPKEY are errors, never skipped
	fx = buildAgentFixture(t, "", "")
	publishPins(t, fx, fx.h.res, newP256(t))
	bad := kelTXT(AgentKeyLabel+"."+agentFQDN, "v=whisper1; k=p256; p=AAAA")
	fx.h.res.set(AgentKeyLabel+"."+agentFQDN, dns.TypeTXT, signed(t, fx, bad))
	if _, err := fx.h.validator().ServedPins(context.Background(), agentFQDN); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Fatalf("broken key: %v", err)
	}
	fx = buildAgentFixture(t, "", "")
	publishPins(t, fx, fx.h.res, newP256(t))
	pgp := &dns.OPENPGPKEY{Hdr: hdr(openpgpPrefix+agentFQDN, dns.TypeOPENPGPKEY), PublicKey: "AAAA"}
	fx.h.res.set(openpgpPrefix+agentFQDN, dns.TypeOPENPGPKEY, signed(t, fx, pgp))
	if _, err := fx.h.validator().ServedPins(context.Background(), agentFQDN); err == nil ||
		!strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("unreadable OpenPGP: %v", err)
	}
	// too many records of one kind
	fx = buildAgentFixture(t, "", "")
	publishPins(t, fx, fx.h.res, newP256(t))
	var many []dns.RR
	for i := 0; i < maxServedPerKind+1; i++ {
		many = append(many, &dns.TLSA{Hdr: hdr(tlsaPrefix+agentFQDN, dns.TypeTLSA), Usage: 3, Selector: 1,
			MatchingType: 1, Certificate: hex.EncodeToString(big.NewInt(int64(i + 1)).FillBytes(make([]byte, 32)))})
	}
	fx.h.res.set(tlsaPrefix+agentFQDN, dns.TypeTLSA, signed(t, fx, many...))
	if _, err := fx.h.validator().ServedPins(context.Background(), agentFQDN); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Fatalf("too many: %v", err)
	}
	if _, err := fx.h.validator().ServedPins(context.Background(), " "); err == nil {
		t.Fatal("a blank name is refused")
	}
}

func TestServedPinsFromEachServerVerifiesAgainstTheValidatedKeys(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	spkiA, spkiB := newP256(t), newP256(t)
	servers := map[string]*mapResolver{"192.0.2.1:53": newMapResolver(), "[2001:db8::2]:53": newMapResolver()}
	publishPins(t, fx, servers["192.0.2.1:53"], spkiA)
	publishPins(t, fx, servers["[2001:db8::2]:53"], spkiB)
	saved := directQuery
	defer func() { directQuery = saved }()
	var asked []string
	directQuery = func(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
		asked = append(asked, server)
		r, ok := servers[server]
		if !ok {
			return nil, errors.New("connection refused")
		}
		return r.Query(ctx, name, qtype)
	}
	got, err := fx.h.validator().ServedPinsFrom(context.Background(), agentFQDN, []string{"192.0.2.1", "[2001:db8::2]:53"})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if s, _ := got[0].Keys([][]byte{spkiA}); len(s) != 1 {
		t.Fatal("the first server serves A")
	}
	if s, _ := got[1].Keys([][]byte{spkiA}); len(s) != 0 {
		t.Fatal("the second server does not serve A: a disagreement must show, not be merged")
	}
	if _, err := fx.h.validator().ServedPinsFrom(context.Background(), agentFQDN, []string{"198.51.100.9"}); err == nil ||
		!strings.Contains(err.Error(), "198.51.100.9:53") {
		t.Fatalf("an unreachable server is named: %v", err)
	}
	if _, err := fx.h.validator().ServedPinsFrom(context.Background(), agentFQDN, nil); err == nil {
		t.Fatal("no server is refused")
	}
	// a server answering with records it signed itself is refused
	forged := newMapResolver()
	evil := genKey(t, agentZone, 256)
	tlsa := &dns.TLSA{Hdr: hdr(tlsaPrefix+agentFQDN, dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1,
		Certificate: strings.Repeat("ee", 32)}
	forged.set(tlsaPrefix+agentFQDN, dns.TypeTLSA, []dns.RR{tlsa, signRRSet(t, evil, agentZone, []dns.RR{tlsa}, fx.h.now)})
	servers["203.0.113.5:53"] = forged
	if _, err := fx.h.validator().ServedPinsFrom(context.Background(), agentFQDN, []string{"203.0.113.5"}); err == nil {
		t.Fatal("a forged answer was accepted")
	}
}

func TestPublishedNameservers(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	ns1 := &dns.NS{Hdr: hdr(agentZone, dns.TypeNS), Ns: "ns1." + agentZone}
	ns2 := &dns.NS{Hdr: hdr(agentZone, dns.TypeNS), Ns: "ns2." + agentZone}
	fx.h.res.set(agentZone, dns.TypeNS, signed(t, fx, ns1, ns2))
	fx.h.res.set("ns1."+agentZone, dns.TypeAAAA, []dns.RR{&dns.AAAA{Hdr: hdr("ns1."+agentZone, dns.TypeAAAA),
		AAAA: net.ParseIP("2001:db8::53")}})
	fx.h.res.set("ns1."+agentZone, dns.TypeA, []dns.RR{&dns.A{Hdr: hdr("ns1."+agentZone, dns.TypeA),
		A: net.ParseIP("192.0.2.53")}, &dns.A{Hdr: hdr("elsewhere.example.", dns.TypeA), A: net.ParseIP("192.0.2.99")}})
	fx.h.res.set("ns2."+agentZone, dns.TypeA, []dns.RR{&dns.A{Hdr: hdr("ns2."+agentZone, dns.TypeA),
		A: net.ParseIP("192.0.2.54")}})
	got, err := PublishedNameservers(context.Background(), fx.h.validator(), agentFQDN)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "ns1."+trimDot(agentZone) ||
		strings.Join(got[0].Addrs, ",") != "[2001:db8::53]:53,192.0.2.53:53" || strings.Join(got[1].Addrs, ",") != "192.0.2.54:53" {
		t.Fatalf("%+v", got)
	}
	// no addresses at all, an unsigned NS set, and an unprovable name are errors
	fx2 := buildAgentFixture(t, "", "")
	fx2.h.res.set(agentZone, dns.TypeNS, signed(t, fx2, ns1))
	if _, err := PublishedNameservers(context.Background(), fx2.h.validator(), agentFQDN); err == nil {
		t.Fatal("no address must be an error")
	}
	fx2.h.res.set(agentZone, dns.TypeNS, []dns.RR{ns1})
	if _, err := PublishedNameservers(context.Background(), fx2.h.validator(), agentFQDN); err == nil {
		t.Fatal("an unsigned NS set must be an error")
	}
	if _, err := PublishedNameservers(context.Background(), fx2.h.validator(), "nowhere.example."); err == nil {
		t.Fatal("an unprovable name must be an error")
	}
}

func TestTheHeadIsReadFromTheSameServerAsThePins(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	srv := newMapResolver()
	owner := KelHeadLabel + "." + agentFQDN
	txt := kelTXT(owner, "v=wkel1", "i=a1")
	srv.set(owner, dns.TypeTXT, signed(t, fx, txt))
	saved := directQuery
	defer func() { directQuery = saved }()
	directQuery = func(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
		if server != "192.0.2.1:53" {
			return nil, errors.New("connection refused")
		}
		return srv.Query(ctx, name, qtype)
	}
	h, err := fx.h.validator().ValidateKelHeadFrom(context.Background(), agentFQDN, "192.0.2.1")
	if err != nil || h.Absent || len(h.Records) != 1 || string(h.Records[0][0]) != "v=wkel1" {
		t.Fatalf("the server's own head is read: %+v %v", h, err)
	}
	if _, err := fx.h.validator().ValidateKelHeadFrom(context.Background(), agentFQDN, "198.51.100.1"); err == nil {
		t.Fatal("a server that cannot be reached proves nothing")
	}
}

// A DS is the parent's: a signer that is a suffix of the zone but not an ancestor by whole labels
// (s.example. for agents.example.), or the zone itself, never anchors the zone's keys.
func TestADSSignedByANonAncestorAnchorsNothing(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	h := fx.h
	const fake = "s.example."
	fKSK, fZSK := genKey(t, fake, 257), genKey(t, fake, 256)
	fKeys := []dns.RR{fKSK.dnskey, fZSK.dnskey}
	h.res.set(fake, dns.TypeDNSKEY, append(append([]dns.RR{}, fKeys...), signRRSet(t, fKSK, fake, fKeys, h.now)))
	fDS := fKSK.dnskey.ToDS(dns.SHA256)
	fDS.Hdr = dns.RR_Header{Name: fake, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(fake, dns.TypeDS, []dns.RR{fDS, signRRSet(t, h.rootZSK, ".", []dns.RR{fDS}, h.now)})
	// the attacker's keys for agents.example., anchored by a DS that s.example. signed
	aKSK := genKey(t, agentZone, 257)
	aKeys := []dns.RR{aKSK.dnskey}
	h.res.set(agentZone, dns.TypeDNSKEY, append(append([]dns.RR{}, aKeys...), signRRSet(t, aKSK, agentZone, aKeys, h.now)))
	aDS := aKSK.dnskey.ToDS(dns.SHA256)
	aDS.Hdr = dns.RR_Header{Name: agentZone, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(agentZone, dns.TypeDS, []dns.RR{aDS, signRRSet(t, fZSK, fake, []dns.RR{aDS}, h.now)})
	tlsaOwner := "_443._tcp." + agentFQDN
	tlsa := &dns.TLSA{Hdr: hdr(tlsaOwner, dns.TypeTLSA), Usage: 3, Selector: 1, MatchingType: 1, Certificate: strings.Repeat("ee", 32)}
	h.res.set(tlsaOwner, dns.TypeTLSA, []dns.RR{tlsa, signRRSet(t, aKSK, agentZone, []dns.RR{tlsa}, h.now)})
	if _, err := h.validator().ValidateRRSet(context.Background(), tlsaOwner, dns.TypeTLSA); err == nil {
		t.Fatal("a DS signed by s.example. anchored agents.example.")
	}
	// a DS signed by the zone itself is refused too, and never recurses
	h.res.set(agentZone, dns.TypeDS, []dns.RR{aDS, signRRSet(t, aKSK, agentZone, []dns.RR{aDS}, h.now)})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.validator().ValidateRRSet(ctx, tlsaOwner, dns.TypeTLSA); err == nil || ctx.Err() != nil {
		t.Fatalf("a self-signed DS is refused at once: %v %v", err, ctx.Err())
	}
}

func TestADNSKEYSetSignedUnderAnotherNameIsNotTheZones(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	h := fx.h
	keys := []dns.RR{h.childKSK.dnskey, h.childZSK.dnskey}
	h.res.set(agentZone, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), signRRSet(t, h.childKSK, "example.", keys, h.now)))
	if _, err := h.validator().ValidateRRSet(context.Background(), "_443._tcp."+agentFQDN, dns.TypeTLSA); err == nil {
		t.Fatal("a DNSKEY RRset whose signature names another signer is not the zone's")
	}
}

// A network that drops UDP/53 still carries TCP: a resolver with no UDP answer is asked again over
// TCP before the next one.
func TestAResolverWithNoUDPAnswerIsAskedOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback TCP")
	}
	srv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: hdr(r.Question[0].Name, dns.TypeA), A: net.ParseIP("192.0.2.1")}}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := NewNetResolver(ln.Addr().String()).Query(ctx, "example.", dns.TypeA) // nothing listens on UDP there
	if err != nil || msg == nil || len(msg.Answer) != 1 {
		t.Fatalf("the TCP retry answers: %v", err)
	}
}
