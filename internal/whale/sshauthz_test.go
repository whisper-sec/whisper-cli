// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	xssh "golang.org/x/crypto/ssh"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// The fixtures use unassigned space and an invented tenant, never a live identity.
const (
	tFleet  = "tfleet"
	tZone   = "tfleet.agents.whisper.online."
	tName   = "db-01.tfleet.agents.whisper.online."
	tSource = "2a04:2a01:9::e1"
)

// fakeLookup is a validated resolver: whatever it returns stands for an RRset that verified
// from the root, with an RRSIG whose label count it controls. Anything it does not hold is a
// validation failure, which is exactly what the real Validator reports for an absent RRset.
type fakeLookup struct {
	rrs    map[string][]dns.RR
	labels map[string]int   // an RRSIG label count to report instead of the owner's own
	errs   map[string]error // a validation failure to report
	block  bool             // wait for the context instead of answering
	asked  []string
}

func key(name string, qtype uint16) string {
	return dns.CanonicalName(name) + "/" + dns.TypeToString[qtype]
}

func (f *fakeLookup) Validated(ctx context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	k := key(name, qtype)
	f.asked = append(f.asked, k)
	if f.block {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	if err := f.errs[k]; err != nil {
		return nil, nil, err
	}
	rrs := f.rrs[k]
	if len(rrs) == 0 {
		return nil, nil, fmt.Errorf("dnssec: no %s record for %s", dns.TypeToString[qtype], name)
	}
	labels := dns.CountLabel(dns.CanonicalName(name))
	if l, ok := f.labels[k]; ok {
		labels = l
	}
	return rrs, &dns.RRSIG{Labels: uint8(labels), SignerName: "agents.whisper.online."}, nil
}

func (f *fakeLookup) add(t *testing.T, rr string) {
	t.Helper()
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatalf("fixture %q: %v", rr, err)
	}
	if f.rrs == nil {
		f.rrs = map[string][]dns.RR{}
	}
	k := key(r.Header().Name, r.Header().Rrtype)
	f.rrs[k] = append(f.rrs[k], r)
}

type agentKey struct {
	typ, b64 string
	blob     []byte
	sshfp    string // SSHFP type 2 hex
	tlsa     string // TLSA 3 1 1 hex
}

func newECDSAKey(t *testing.T) agentKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := xssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	blob := pub.Marshal()
	fp, spki := sha256.Sum256(blob), sha256.Sum256(der)
	return agentKey{typ: pub.Type(), b64: base64.StdEncoding.EncodeToString(blob), blob: blob,
		sshfp: hex.EncodeToString(fp[:]), tlsa: hex.EncodeToString(spki[:])}
}

// fleetAgent is a healthy, active fleet member at tSource whose key is k.
func fleetAgent(t *testing.T, k agentKey) *fakeLookup {
	t.Helper()
	f := &fakeLookup{}
	rev, _ := dns.ReverseAddr(tSource)
	f.add(t, rev+" 60 IN PTR "+tName)
	f.add(t, tName+" 60 IN AAAA "+tSource)
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=active label=db-01 tenant=`+tFleet+`"`)
	f.add(t, tName+" 60 IN SSHFP 3 2 "+k.sshfp)
	f.add(t, "_443._tcp."+tName+" 60 IN TLSA 3 1 1 "+k.tlsa)
	return f
}

func pol() AuthzPolicy { return AuthzPolicy{Fleet: tZone, Tenant: tFleet} }

func req(k agentKey) AuthzRequest {
	return AuthzRequest{User: "deploy", KeyType: k.typ, Key: k.b64, Source: netip.MustParseAddr(tSource)}
}

func mustDeny(t *testing.T, d AuthzDecision, want string) {
	t.Helper()
	if d.Admit || d.Line != "" {
		t.Fatalf("admitted, want a denial containing %q: %+v", want, d)
	}
	if !strings.Contains(d.Reason, want) {
		t.Fatalf("reason = %q, want it to contain %q", d.Reason, want)
	}
}

func TestAFleetAgentsOwnKeyIsAdmittedBySSHFP(t *testing.T) {
	k := newECDSAKey(t)
	d := Authorize(context.Background(), fleetAgent(t, k), pol(), req(k))
	if !d.Admit || d.Via != "sshfp" {
		t.Fatalf("not admitted by SSHFP: %+v", d)
	}
	want := k.typ + " " + k.b64 + " whisper:db-01.tfleet.agents.whisper.online"
	if d.Line != want {
		t.Fatalf("line = %q, want %q", d.Line, want)
	}
	if strings.Contains(d.Line, "\n") || !strings.HasPrefix(d.Fingerprint, "SHA256:") {
		t.Fatalf("line or fingerprint malformed: %+v", d)
	}
}

func TestTheTLSAPinAdmitsWhenNoSSHFPIsPublished(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	delete(f.rrs, key(tName, dns.TypeSSHFP))
	// Off by default: the TLSA pin names the TLS service's key, not necessarily the agent's.
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "no SSHFP record")
	for _, a := range f.asked {
		if strings.Contains(a, "TLSA") {
			t.Fatalf("TLSA was consulted without --allow-tlsa: %v", f.asked)
		}
	}
	p := pol()
	p.AllowTLSA = true
	d := Authorize(context.Background(), f, p, req(k))
	if !d.Admit || d.Via != "tlsa" {
		t.Fatalf("not admitted by TLSA with the opt-in: %+v", d)
	}
}

func TestAnotherKeyIsRefused(t *testing.T) {
	owner, stranger := newECDSAKey(t), newECDSAKey(t)
	d := Authorize(context.Background(), fleetAgent(t, owner), pol(), req(stranger))
	mustDeny(t, d, "is not db-01.tfleet.agents.whisper.online's published key")
	if d.Name == "" {
		t.Fatal("the denial should still name the agent the source proved")
	}
}

func TestAKeyOfAnotherAlgorithmIsRefused(t *testing.T) {
	owner := newECDSAKey(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := xssh.NewPublicKey(pub)
	r := req(owner)
	r.KeyType, r.Key = sp.Type(), base64.StdEncoding.EncodeToString(sp.Marshal())
	f := fleetAgent(t, owner)
	delete(f.rrs, key("_443._tcp."+tName, dns.TypeTLSA))
	mustDeny(t, Authorize(context.Background(), f, pol(), r), "publishes no SSHFP for that algorithm")
}

func TestASHA1OnlySSHFPProvesNothing(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	sum := sha256.Sum256(k.blob)
	f.rrs[key(tName, dns.TypeSSHFP)] = nil
	f.add(t, tName+" 60 IN SSHFP 3 1 "+hex.EncodeToString(sum[:20]))
	delete(f.rrs, key("_443._tcp."+tName, dns.TypeTLSA))
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "SHA-1")
}

func TestASourceOutsideTheFleetIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	rev, _ := dns.ReverseAddr(tSource)
	f.rrs[key(rev, dns.TypePTR)] = nil
	f.add(t, rev+" 60 IN PTR db-01.tother.agents.whisper.online.")
	d := Authorize(context.Background(), f, pol(), req(k))
	mustDeny(t, d, "is not a member of tfleet.agents.whisper.online")
	for _, a := range f.asked {
		if strings.Contains(a, "SSHFP") {
			t.Fatalf("a non-member's key was looked up at all: %v", f.asked)
		}
	}
}

func TestANameDeeperInTheFleetZoneIsNotAMember(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	rev, _ := dns.ReverseAddr(tSource)
	f.rrs[key(rev, dns.TypePTR)] = nil
	f.add(t, rev+" 60 IN PTR x.db-01.tfleet.agents.whisper.online.")
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "is not a member")
}

func TestAPTRThatTheNameDoesNotConfirmIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeAAAA)] = nil
	f.add(t, tName+" 60 IN AAAA 2a04:2a01:9::e2")
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "does not contain it")
}

func TestARevokedAgentIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeTXT)] = nil
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=revoked label=db-01 tenant=`+tFleet+`"`)
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "is revoked, not active")
}

func TestARepeatedStatusCannotOverrideTheFirst(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeTXT)] = nil
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=revoked STATUS=active tenant=`+tFleet+`"`)
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "says status twice")
}

// RRset order is not signed, so two whisper-id1 records are refused in either order rather
// than read first-wins.
func TestTwoWhisperIDRecordsAreRefusedInEitherOrder(t *testing.T) {
	k := newECDSAKey(t)
	active := tName + ` 60 IN TXT "whisper-id1 status=active tenant=` + tFleet + `"`
	revoked := tName + ` 60 IN TXT "whisper-id1 status=revoked tenant=` + tFleet + `"`
	for _, order := range [][]string{{active, revoked}, {revoked, active}} {
		f := fleetAgent(t, k)
		f.rrs[key(tName, dns.TypeTXT)] = nil
		f.add(t, order[0])
		f.add(t, order[1])
		mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "more than one whisper-id1")
	}
}

func TestAnAgentOfAnotherTenantIsRefusedEvenUnderTheFleetName(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeTXT)] = nil
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=active tenant=tother"`)
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "belongs to tenant tother")
}

func TestNoWhisperIDMeansNoProvenStatus(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeTXT)] = nil
	f.add(t, tName+` 60 IN TXT "v=spf1 -all"`)
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "publishes no whisper-id1")
}

func TestAWildcardSynthesisedAnswerIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeTXT, dns.TypeSSHFP} {
		f := fleetAgent(t, k)
		delete(f.rrs, key("_443._tcp."+tName, dns.TypeTLSA))
		f.labels = map[string]int{key(tName, qt): dns.CountLabel(tName) - 1}
		mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "wildcard")
	}
}

func TestAValidationFailureAnywhereIsADenial(t *testing.T) {
	k := newECDSAKey(t)
	rev, _ := dns.ReverseAddr(tSource)
	for _, k2 := range []string{key(rev, dns.TypePTR), key(tName, dns.TypeAAAA), key(tName, dns.TypeTXT)} {
		f := fleetAgent(t, k)
		f.errs = map[string]error{k2: errors.New("dnssec: signature expired")}
		mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "signature expired")
	}
	// Both key proofs failing to validate is a denial, not a fall through to anything.
	f := fleetAgent(t, k)
	f.errs = map[string]error{key(tName, dns.TypeSSHFP): errors.New("bogus"), key("_443._tcp."+tName, dns.TypeTLSA): errors.New("bogus")}
	p := pol()
	p.AllowTLSA = true
	mustDeny(t, Authorize(context.Background(), f, p, req(k)), "bogus")
}

// TestAnUnsignedAnswerIsRefusedByTheRealValidator puts the real in-process validator behind
// the decision, over a resolver that answers everything correctly but WITHOUT signatures.
// That is the forged-answer case: right data, no proof. It must be a denial.
func TestAnUnsignedAnswerIsRefusedByTheRealValidator(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	lk := ValidatorLookup{V: trustverify.NewValidator(unsignedResolver{f}, nil, time.Time{})}
	mustDeny(t, Authorize(context.Background(), lk, pol(), req(k)), "UNSIGNED")
}

type unsignedResolver struct{ f *fakeLookup }

func (u unsignedResolver) Query(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Response = true
	m.Answer = u.f.rrs[key(name, qtype)]
	return m, nil
}

func TestATimeoutIsADenial(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	f.block = true
	cx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	mustDeny(t, Authorize(cx, f, pol(), req(k)), "out of time")
	if time.Since(start) > 5*time.Second {
		t.Fatal("the decision outlived its deadline")
	}
}

func TestRootIsAdmittedOnlyWhenNamed(t *testing.T) {
	k := newECDSAKey(t)
	r := req(k)
	r.User = "root"
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), pol(), r), "root is never a fleet login")
	p := pol()
	p.Users = []string{"root"}
	if d := Authorize(context.Background(), fleetAgent(t, k), p, r); !d.Admit {
		t.Fatalf("root named with --user root was refused: %+v", d)
	}
	p.Users = []string{"deploy"}
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), p, r), "is not one of the accounts")
}

func TestTheAllowlistNarrowsTheFleet(t *testing.T) {
	k := newECDSAKey(t)
	p := pol()
	for _, entry := range []string{"db-01", "DB-01.tfleet.agents.whisper.online.", "db-01.tfleet.agents.whisper.online"} {
		p.Allow = []string{entry}
		if d := Authorize(context.Background(), fleetAgent(t, k), p, req(k)); !d.Admit {
			t.Fatalf("allow %q refused the agent: %+v", entry, d)
		}
	}
	p.Allow = []string{"db-02", "db"}
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), p, req(k)), "not on this node's allowlist")
	// The TXT label= is a display name another agent can choose; it never satisfies an allowlist.
	f := fleetAgent(t, k)
	f.rrs[key(tName, dns.TypeTXT)] = nil
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=active label=prod-db tenant=`+tFleet+`"`)
	p.Allow = []string{"prod-db"}
	mustDeny(t, Authorize(context.Background(), f, p, req(k)), "not on this node's allowlist")
}

func TestRootUnderAnotherNameIsRefused(t *testing.T) {
	saved := UID0
	UID0 = func(name string) (bool, bool) { return name == "toor", true }
	t.Cleanup(func() { UID0 = saved })
	k := newECDSAKey(t)
	r := req(k)
	r.User = "toor"
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), pol(), r), "has uid 0")
	p := pol()
	p.Users = []string{"toor"}
	if d := Authorize(context.Background(), fleetAgent(t, k), p, r); !d.Admit {
		t.Fatalf("a uid-0 account named with --user was refused: %+v", d)
	}
}

func TestAHostedFleetRefusesAnAddressOutsideTheAgentBlockWithoutALookup(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	r := req(k)
	r.Source = netip.MustParseAddr("2001:db8:aa::e1")
	mustDeny(t, Authorize(context.Background(), f, pol(), r), "outside 2a04:2a01::/32")
	if len(f.asked) != 0 {
		t.Fatalf("a stranger caused lookups: %v", f.asked)
	}
}

// RRset order is not signed: when two in-fleet PTR targets come back, every one is tried, so
// a resolver that puts the unconfirmed one first cannot turn an admission into a denial.
func TestEveryInFleetPTRTargetIsTried(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	rev, _ := dns.ReverseAddr(tSource)
	f.rrs[key(rev, dns.TypePTR)] = nil
	f.add(t, rev+" 60 IN PTR old.tfleet.agents.whisper.online.")
	f.add(t, rev+" 60 IN PTR "+tName)
	if d := Authorize(context.Background(), f, pol(), req(k)); !d.Admit || d.Name != strings.TrimSuffix(tName, ".") {
		t.Fatalf("the confirmed PTR target was not tried: %+v", d)
	}
}

func TestLocalAndUnknownSourcesAreRefusedWithoutAnyLookup(t *testing.T) {
	k := newECDSAKey(t)
	for _, src := range []string{"127.0.0.1", "::1", "::"} {
		f := fleetAgent(t, k)
		r := req(k)
		r.Source = netip.MustParseAddr(src)
		mustDeny(t, Authorize(context.Background(), f, pol(), r), "on this host")
		if len(f.asked) != 0 {
			t.Fatalf("%s caused lookups: %v", src, f.asked)
		}
	}
	r := req(k)
	r.Source = netip.Addr{}
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), pol(), r), "unknown")
}

func TestMalformedKeysAreRefused(t *testing.T) {
	k := newECDSAKey(t)
	cases := map[string]AuthzRequest{
		"certificates and unknown types": {KeyType: "ecdsa-sha2-nistp256-cert-v01@openssh.com", Key: k.b64},
		"not valid base64":               {KeyType: k.typ, Key: "%%%"},
		"does not parse":                 {KeyType: k.typ, Key: base64.StdEncoding.EncodeToString([]byte("junk"))},
		"not the ssh-ed25519":            {KeyType: "ssh-ed25519", Key: k.b64},
		"no key type":                    {KeyType: "", Key: k.b64},
	}
	for want, r := range cases {
		r.User, r.Source = "deploy", netip.MustParseAddr(tSource)
		f := fleetAgent(t, k)
		mustDeny(t, Authorize(context.Background(), f, pol(), r), want)
		if len(f.asked) != 0 {
			t.Fatalf("%s: a malformed key caused lookups: %v", want, f.asked)
		}
	}
}

func TestNoFleetAdmitsNobody(t *testing.T) {
	k := newECDSAKey(t)
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), AuthzPolicy{}, req(k)), "no fleet")
	mustDeny(t, Authorize(context.Background(), nil, pol(), req(k)), "no fleet")
	r := req(k)
	r.User = " "
	mustDeny(t, Authorize(context.Background(), fleetAgent(t, k), pol(), r), "no login name")
}

func TestNormalizeFleetReadsWhatPeopleType(t *testing.T) {
	ok := map[string][2]string{
		"tfleet":                              {tZone, tFleet},
		"TFleet.":                             {tZone, tFleet},
		"tfleet.agents.whisper.online":        {tZone, tFleet},
		"db-01.tfleet.agents.whisper.online.": {tZone, tFleet},
		"a.b.tfleet.agents.whisper.online":    {tZone, tFleet},
		"agents.example.com":                  {"agents.example.com.", ""},
	}
	for in, want := range ok {
		z, ten, err := NormalizeFleet(in)
		if err != nil || z != want[0] || ten != want[1] {
			t.Errorf("NormalizeFleet(%q) = %q %q %v, want %q %q", in, z, ten, err, want[0], want[1])
		}
	}
	for _, bad := range []string{"", "  ", "agents.whisper.online", "a..b", "*.example.com", "a b", "x/y"} {
		if z, _, err := NormalizeFleet(bad); err == nil {
			t.Errorf("NormalizeFleet(%q) = %q, want a refusal", bad, z)
		}
	}
}
