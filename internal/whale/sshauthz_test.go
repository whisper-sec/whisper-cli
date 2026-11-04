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

func pol() AuthzPolicy { return AuthzPolicy{Fleets: []AuthzFleet{{Zone: tZone, Tenant: tFleet}}} }

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

// --- a fleet of several tenants ----------------------------------------------

// A second agent of the same owner, in its own tenant, as per-agent tenancy names it.
const (
	tFleet2  = "tsecond"
	tZone2   = "tsecond.agents.whisper.online."
	tName2   = "mac-01.tsecond.agents.whisper.online."
	tSource2 = "2a04:2a01:9::e2"
)

// secondAgent publishes an active agent at tSource2 in tenant tFleet2, whose key is k.
func secondAgent(t *testing.T, f *fakeLookup, k agentKey, txtTenant string) {
	t.Helper()
	rev, _ := dns.ReverseAddr(tSource2)
	f.add(t, rev+" 60 IN PTR "+tName2)
	f.add(t, tName2+" 60 IN AAAA "+tSource2)
	f.add(t, tName2+` 60 IN TXT "whisper-id1 status=active label=mac-01 tenant=`+txtTenant+`"`)
	f.add(t, tName2+" 60 IN SSHFP 3 2 "+k.sshfp)
}

func twoFleets() AuthzPolicy {
	return AuthzPolicy{Fleets: []AuthzFleet{{Zone: tZone, Tenant: tFleet}, {Zone: tZone2, Tenant: tFleet2}}}
}

func req2(k agentKey) AuthzRequest {
	r := req(k)
	r.Source = netip.MustParseAddr(tSource2)
	return r
}

// The bug in an owner's agents each sit in their own tenant, and a node pinned to one
// tenant refused every other. With both tenants in the set, both log in.
func TestEveryTenantInTheSetIsAdmitted(t *testing.T) {
	k1, k2 := newECDSAKey(t), newECDSAKey(t)
	f := fleetAgent(t, k1)
	secondAgent(t, f, k2, tFleet2)
	if d := Authorize(context.Background(), f, twoFleets(), req(k1)); !d.Admit {
		t.Fatalf("the first tenant's agent was refused: %+v", d)
	}
	d := Authorize(context.Background(), f, twoFleets(), req2(k2))
	if !d.Admit || d.Name != strings.TrimSuffix(tName2, ".") {
		t.Fatalf("the second tenant's agent was refused: %+v", d)
	}
	// One agent's key never logs in as the other, whichever tenant it sits in.
	mustDeny(t, Authorize(context.Background(), f, twoFleets(), req2(k1)), "not mac-01.tsecond.agents.whisper.online's published key")
}

func TestATenantOutsideTheSetIsRefused(t *testing.T) {
	k1, k2 := newECDSAKey(t), newECDSAKey(t)
	f := fleetAgent(t, k1)
	secondAgent(t, f, k2, tFleet2)
	mustDeny(t, Authorize(context.Background(), f, pol(), req2(k2)), "is not a member of tfleet.agents.whisper.online")
}

// The tenant a record names must be the tenant of the zone the name sits in. A name in one
// tenant whose record names ANOTHER tenant of the set is refused: the set is a list of zones,
// each vouching only for itself, never a pool of tenants any record may name.
func TestARecordNamingAnotherTenantOfTheSetIsRefused(t *testing.T) {
	k1, k2 := newECDSAKey(t), newECDSAKey(t)
	f := fleetAgent(t, k1)
	secondAgent(t, f, k2, tFleet) // in tsecond, but its record says tfleet
	mustDeny(t, Authorize(context.Background(), f, twoFleets(), req2(k2)),
		"belongs to tenant tfleet, not to tsecond, the tenant its name sits in")
}

func TestARevokedAgentInASecondTenantIsRefused(t *testing.T) {
	k1, k2 := newECDSAKey(t), newECDSAKey(t)
	f := fleetAgent(t, k1)
	secondAgent(t, f, k2, tFleet2)
	f.rrs[key(tName2, dns.TypeTXT)] = nil
	f.add(t, tName2+` 60 IN TXT "whisper-id1 status=revoked label=mac-01 tenant=`+tFleet2+`"`)
	mustDeny(t, Authorize(context.Background(), f, twoFleets(), req2(k2)), "is revoked, not active")
}

// A name deeper in a tenant of the set is not a member of any of them, even when its parent
// is one label under the agents zone.
func TestADeeperNameIsNotAMemberOfAnyFleetInTheSet(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	rev, _ := dns.ReverseAddr(tSource)
	f.rrs[key(rev, dns.TypePTR)] = nil
	f.add(t, rev+" 60 IN PTR x.db-01.tsecond.agents.whisper.online.")
	mustDeny(t, Authorize(context.Background(), f, twoFleets(), req(k)), "is not a member of")
}

// With a fleet in its own domain in the set, a caller outside the agent block may be a member
// of it, so it is looked up; with only hosted tenants it is refused before any lookup.
func TestTheAgentBlockPrefilterHoldsOnlyForAnAllHostedSet(t *testing.T) {
	k := newECDSAKey(t)
	p := twoFleets()
	r := req(k)
	r.Source = netip.MustParseAddr("2001:db8:aa::e1")
	f := fleetAgent(t, k)
	mustDeny(t, Authorize(context.Background(), f, p, r), "outside 2a04:2a01::/32")
	if len(f.asked) != 0 {
		t.Fatalf("an all-hosted set looked a stranger up: %v", f.asked)
	}
	p.Fleets = append(p.Fleets, AuthzFleet{Zone: "agents.example.com."})
	f = fleetAgent(t, k)
	mustDeny(t, Authorize(context.Background(), f, p, r), "PTR")
	if len(f.asked) == 0 {
		t.Fatal("a set with a fleet in its own domain refused without looking")
	}
}

func TestParseFleetsReadsAListAndRefusesAHole(t *testing.T) {
	got, err := ParseFleets([]string{"tfleet", "TFLEET.agents.whisper.online.", "db-01.tsecond.agents.whisper.online", "agents.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []AuthzFleet{{Zone: tZone, Tenant: tFleet}, {Zone: tZone2, Tenant: tFleet2}, {Zone: "agents.example.com."}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, bad := range [][]string{{"tfleet", "agents.whisper.online"}, {"tfleet", "bad name"}, {}, {"tfleet", "x/y.example.com"}} {
		if _, err := ParseFleets(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}

// A fleet goes into sshd_config, so anything sshd would expand or split is refused, as is a
// public suffix, under which anybody may register a name.
func TestNormalizeFleetRefusesTokensAndPublicSuffixes(t *testing.T) {
	for _, bad := range []string{"%u.example.com", "a%C.example.com", "-x.example.com", `x\032y.example.com`,
		"x_y.example.com", "co.uk", "github.io", "co.uk.", "x-.example.com"} {
		if z, _, err := NormalizeFleet(bad); err == nil {
			t.Fatalf("%q normalised to %q", bad, z)
		}
	}
	if z, _, err := NormalizeFleet("agents.example.co.uk"); err != nil || z != "agents.example.co.uk." {
		t.Fatalf("a registrable fleet was refused: %q %v", z, err)
	}
}

func TestHostedTenantZoneIsExact(t *testing.T) {
	good := "t0000000000000000000000000000c0de.agents.whisper.online"
	if tn, ok := HostedTenantZone(good); !ok || tn != "t0000000000000000000000000000c0de" {
		t.Fatalf("%q: %q %v", good, tn, ok)
	}
	for _, bad := range []string{"tfleet.agents.whisper.online", "agents.whisper.online", "x.t0000000000000000000000000000c0de.agents.whisper.online",
		"t0000000000000000000000000000c0dz.agents.whisper.online", "t0000000000000000000000000000c0de.agents.example.com", ""} {
		if _, ok := HostedTenantZone(bad); ok {
			t.Fatalf("%q read as a hosted tenant zone", bad)
		}
	}
}

// A zone cut at the agent's own name would let it sign its own records; the signature must
// come from the fleet's zone or above.
func TestASignerAtTheNameItselfIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	f := &signerOverride{fakeLookup: fleetAgent(t, k), signer: map[string]string{key(tName, dns.TypeTXT): tName}}
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "is signed by db-01.tfleet.agents.whisper.online, not by tfleet.agents.whisper.online")
	// A signature that names no signer proves no zone, so it is refused too.
	f = &signerOverride{fakeLookup: fleetAgent(t, k), signer: map[string]string{key(tName, dns.TypeSSHFP): ""}}
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "is signed by unknown")
}

type signerOverride struct {
	*fakeLookup
	signer map[string]string
}

func (s *signerOverride) Validated(ctx context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	rrs, sig, err := s.fakeLookup.Validated(ctx, name, qtype)
	if sig != nil {
		if sn, ok := s.signer[key(name, qtype)]; ok {
			sig.SignerName = sn
		}
	}
	return rrs, sig, err
}

// A PTR to a literal wildcard owner is not an agent: its records can only ever come back
// signed with one label fewer than the name has.
func TestAPTRToAWildcardOwnerIsRefused(t *testing.T) {
	k := newECDSAKey(t)
	f := fleetAgent(t, k)
	rev, _ := dns.ReverseAddr(tSource)
	star := "*.tfleet.agents.whisper.online."
	f.rrs[key(rev, dns.TypePTR)] = nil
	f.add(t, rev+" 60 IN PTR "+star)
	f.add(t, star+" 60 IN AAAA "+tSource)
	f.labels = map[string]int{key(star, dns.TypeAAAA): dns.CountLabel(star) - 1}
	mustDeny(t, Authorize(context.Background(), f, pol(), req(k)), "wildcard")
}

// In a set that holds a fleet in its own domain the up-front prefilter cannot run, so a name
// that turns out to be in a hosted tenant is still refused for a source outside the agent block.
func TestAHostedNameIsRefusedFromOutsideTheBlockInAMixedSet(t *testing.T) {
	k := newECDSAKey(t)
	stranger := "2001:db8:aa::e1"
	f := &fakeLookup{}
	rev, _ := dns.ReverseAddr(stranger)
	f.add(t, rev+" 60 IN PTR "+tName)
	f.add(t, tName+" 60 IN AAAA "+stranger)
	f.add(t, tName+` 60 IN TXT "whisper-id1 status=active tenant=`+tFleet+`"`)
	f.add(t, tName+" 60 IN SSHFP 3 2 "+k.sshfp)
	p := pol()
	p.Fleets = append(p.Fleets, AuthzFleet{Zone: "agents.example.com."})
	r := req(k)
	r.Source = netip.MustParseAddr(stranger)
	mustDeny(t, Authorize(context.Background(), f, p, r), "where every agent of tfleet.agents.whisper.online lives")
	for _, a := range f.asked {
		if strings.HasPrefix(a, dns.CanonicalName(tName)) {
			t.Fatalf("the hosted name was looked up for a stranger: %v", f.asked)
		}
	}
}

// Two in-fleet names, one revoked and one active, admit in either RRset order: every name is
// tried in full, so the order cannot hide the active one.
func TestARevokedNameCannotHideAnActiveOneInEitherOrder(t *testing.T) {
	k := newECDSAKey(t)
	old := "aaa.tsecond.agents.whisper.online."
	for _, first := range []string{old, tName} {
		f := fleetAgent(t, k)
		rev, _ := dns.ReverseAddr(tSource)
		f.rrs[key(rev, dns.TypePTR)] = nil
		second := tName
		if first == tName {
			second = old
		}
		f.add(t, rev+" 60 IN PTR "+first)
		f.add(t, rev+" 60 IN PTR "+second)
		f.add(t, old+" 60 IN AAAA "+tSource)
		f.add(t, old+` 60 IN TXT "whisper-id1 status=revoked tenant=`+tFleet2+`"`)
		f.add(t, old+" 60 IN SSHFP 3 2 "+k.sshfp)
		if d := Authorize(context.Background(), f, twoFleets(), req(k)); !d.Admit || d.Name != strings.TrimSuffix(tName, ".") {
			t.Fatalf("first=%s: %+v", first, d)
		}
	}
}
