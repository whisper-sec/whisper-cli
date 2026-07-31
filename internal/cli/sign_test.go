// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// RFC 8162 §3 worked example: the SMIMEA QNAME for hugh@example.com.
func TestSmimeaOwnerMatchesRFC8162Vector(t *testing.T) {
	got, err := smimeaOwner("hugh@example.com")
	if err != nil {
		t.Fatalf("smimeaOwner: %v", err)
	}
	want := "c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com."
	if got != want {
		t.Fatalf("owner = %q, want %q", got, want)
	}
	// Case-insensitive local-part + trailing-dot domain normalize to the same owner.
	up, _ := smimeaOwner("Hugh@example.com.")
	if up != want {
		t.Fatalf("case/dot normalization: %q != %q", up, want)
	}
}

func TestSmimeaOwnerRejectsNonMailbox(t *testing.T) {
	for _, bad := range []string{"nope", "@example.com", "hugh@"} {
		if _, err := smimeaOwner(bad); err == nil {
			t.Errorf("smimeaOwner(%q) should error", bad)
		}
	}
}

// A self-signed emailProtection cert + its key, standing in for the control-plane-issued credential.
func testCred(t *testing.T, mailbox string) (*smimeCred, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: mailbox},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses:        []string{mailbox},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &smimeCred{chain: []*x509.Certificate{cert}, key: key, mailbox: mailbox}, cert
}

func TestCMSSignDetachedRoundTripAndSPKIPin(t *testing.T) {
	mailbox := "agent@a1b2c3.agents.whisper.online"
	cred, cert := testCred(t, mailbox)
	content := []byte("%PDF-1.7\nthe document bytes\n")

	der, err := cmsSignDetached(content, cred)
	if err != nil {
		t.Fatalf("cmsSignDetached: %v", err)
	}

	// A valid detached signature verifies against the signer key (DANE-EE self-root).
	p7, err := pkcs7.Parse(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p7.Content = content
	signer := p7.GetOnlySigner()
	if signer == nil {
		t.Fatal("no single signer")
	}
	pool := x509.NewCertPool()
	pool.AddCert(signer)
	if err := p7.VerifyWithChain(pool); err != nil {
		t.Fatalf("valid signature was rejected: %v", err)
	}

	// The signer the verifier sees is the same key -> SPKI pin the SMIMEA would carry.
	if trustverify.SPKISHA256(signer) != trustverify.SPKISHA256(cert) {
		t.Fatal("signer SPKI does not match the issued cert SPKI")
	}
	// The signer's rfc822 SAN drives the SMIMEA owner (round-trips to the same mailbox).
	if firstRFC822(signer) != mailbox {
		t.Fatalf("signer rfc822 = %q, want %q", firstRFC822(signer), mailbox)
	}

	// Tampered content must NOT verify (fails closed).
	p7b, _ := pkcs7.Parse(der)
	p7b.Content = []byte("tampered bytes")
	if err := p7b.VerifyWithChain(pool); err == nil {
		t.Fatal("tampered content unexpectedly verified")
	}
}
