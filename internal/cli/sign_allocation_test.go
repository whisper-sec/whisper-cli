// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// agentCASmimeCred mints an emailProtection leaf under an issuing CA named exactly as the
// Whisper Agent CA's, its subject naming the given serials.
func agentCASmimeCred(t *testing.T, mailbox string, serials ...string) *smimeCred {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: trustverify.AgentIssuingCACN,
			Organization: []string{trustverify.AgentIssuingCAOrg}},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subj := pkix.Name{CommonName: mailbox}
	for _, s := range serials {
		subj.ExtraNames = append(subj.ExtraNames,
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: s})
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: subj,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{mailbox}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &smimeCred{chain: []*x509.Certificate{cert, ca}, key: key, mailbox: mailbox}
}

// fakeSignDNS pins the given SPKI and answers the allocation check with a fixed finding,
// recording the name it was asked about.
type fakeSignDNS struct {
	pin     [32]byte
	pinErr  error
	finding trustverify.AllocationFinding
	asked   string
}

func (f *fakeSignDNS) SmimeaPins(string) ([][32]byte, error) {
	if f.pinErr != nil {
		return nil, f.pinErr
	}
	return [][32]byte{f.pin}, nil
}

func (f *fakeSignDNS) AllocationOf(_ *x509.Certificate, name string) trustverify.AllocationFinding {
	f.asked = name
	return f.finding
}

func TestSignVerifyHoldsTheSignerToTheMailboxsCurrentAllocation(t *testing.T) {
	const mailbox = "agent@a0000000000000e08.te08.agents.whisper.online"
	content := []byte("the signed bytes\n")
	cred := agentCASmimeCred(t, mailbox, "alloc-1767225900000")
	sig, err := cmsSignDetached(content, cred)
	if err != nil {
		t.Fatal(err)
	}
	pin := trustverify.SPKISHA256(cred.chain[0])
	cases := []struct {
		name    string
		finding trustverify.AllocationFinding
		errHas  string
	}{
		{"the current allocation verifies", trustverify.AllocationFinding{Applies: true, Pass: true,
			Verdict: trustverify.VerdictPass, Detail: "the leaf names allocation 1767225900000"}, ""},
		{"an agent's own certificate verifies on the pin", trustverify.AllocationFinding{Pass: true}, ""},
		{"a BYOD name with no whisper-id1 verifies unbound", trustverify.AllocationFinding{Applies: true, Pass: true,
			Unbound: true, Detail: "no allocation binds this leaf (unbound)"}, ""},
		{"a later allocation is a previous holder's signature", trustverify.AllocationFinding{Applies: true,
			Superseded: true, Verdict: trustverify.VerdictAllocationMismatch,
			Detail: "the leaf names allocation 1767225900000; the current allocation is 1767312300000"},
			"signed under a previous allocation of " + mailbox},
		{"an issued-before leaf is a previous holder's signature", trustverify.AllocationFinding{Applies: true,
			Superseded: true, Verdict: trustverify.VerdictIssuedBeforeAllocation, Detail: "issued before"},
			"signed under a previous allocation of " + mailbox},
		{"an unprovable TXT fails closed", trustverify.AllocationFinding{Applies: true,
			Detail: "could not be proven present or absent"}, "the allocation of " + mailbox + " could not be proven"},
		{"no current identity fails closed", trustverify.AllocationFinding{Applies: true,
			Verdict: trustverify.VerdictNoCurrentIdentity, Detail: "no identity holds it now"},
			"the allocation of " + mailbox + " could not be proven"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &fakeSignDNS{pin: pin, finding: c.finding}
			err := verifyDetachedWith(content, sig, d)
			if d.asked != "a0000000000000e08.te08.agents.whisper.online" {
				t.Fatalf("the allocation was read at %q, not the mailbox's domain", d.asked)
			}
			if c.errHas == "" {
				if err != nil {
					t.Fatalf("want verified, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("want an error containing %q, got %v", c.errHas, err)
			}
			if strings.Contains(strings.ToLower(err.Error()), "fraud") {
				t.Fatalf("a previous allocation is not fraud: %v", err)
			}
		})
	}
}

// The allocation is read only after the pin matches: an unpinned signer is refused on the pin.
func TestSignVerifyRefusesAnUnpinnedSignerBeforeTheAllocation(t *testing.T) {
	const mailbox = "agent@a0000000000000e08.te08.agents.whisper.online"
	content := []byte("x")
	cred := agentCASmimeCred(t, mailbox, "alloc-5")
	sig, err := cmsSignDetached(content, cred)
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeSignDNS{finding: trustverify.AllocationFinding{Pass: true}}
	if err := verifyDetachedWith(content, sig, d); err == nil || !strings.Contains(err.Error(), "NOT pinned") {
		t.Fatalf("want the pin refusal, got %v", err)
	}
	if d.asked != "" {
		t.Fatalf("the allocation was read for an unpinned signer: %q", d.asked)
	}
	d = &fakeSignDNS{pinErr: errors.New("bogus")}
	if err := verifyDetachedWith(content, sig, d); err == nil || !strings.Contains(err.Error(), "SMIMEA (DNSSEC)") {
		t.Fatalf("want the SMIMEA refusal, got %v", err)
	}
}
