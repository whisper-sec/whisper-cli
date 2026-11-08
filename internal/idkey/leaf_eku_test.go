// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The agent-held leaf plays two roles, served on the /128:443 by the in-tunnel listener and
// presented as an mTLS client certificate, so its EKU lists both. RFC 5280
// section 4.2.1.12: a certificate that carries the extension is used only for the purposes it
// lists.
func TestSelfSignedLeaf_ListsBothTheRolesItPlays(t *testing.T) {
	cert := mintLeafCert(t)
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if len(cert.ExtKeyUsage) != len(want) || cert.ExtKeyUsage[0] != want[0] || cert.ExtKeyUsage[1] != want[1] {
		t.Fatalf("EKU = %v, want %v", cert.ExtKeyUsage, want)
	}
	if len(cert.UnknownExtKeyUsage) != 0 {
		t.Fatalf("unexpected unknown EKUs %v", cert.UnknownExtKeyUsage)
	}
}

// The check a relying party that enforces EKU makes, in each role. The leaf is self-signed, so the
// pool is the leaf itself (a DANE-EE relying party pins it; this is the strictest PKIX reading).
func TestSelfSignedLeaf_PassesAnEkuEnforcingVerifyInBothRoles(t *testing.T) {
	cert := mintLeafCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("verify for %v: %v", usage, err)
		}
	}
	// Negative: a purpose the leaf does not list is refused, so the EKU is really enforced here.
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	var inv x509.CertificateInvalidError
	if !errors.As(err, &inv) || inv.Reason != x509.IncompatibleUsage {
		t.Fatalf("codeSigning verify: got %v, want IncompatibleUsage", err)
	}
}

// A real handshake: a crypto/tls server with ClientAuth=RequireAndVerifyClientCert (which checks the
// client chain for ExtKeyUsageClientAuth) accepts the leaf as the client certificate.
func TestSelfSignedLeaf_IsAcceptedAsAClientByAGoServerThatVerifiesClientCerts(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	clientLeaf, err := kp.SelfSignedLeaf("c.tdead.agents.whisper.online", "", netip.MustParseAddr("2a04:2a01:9::c"))
	if err != nil {
		t.Fatalf("client leaf: %v", err)
	}
	clientCert, _ := x509.ParseCertificate(clientLeaf.Certificate[0])
	srvKp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	serverLeaf, err := srvKp.SelfSignedLeaf("s.tdead.agents.whisper.online", "", netip.Addr{})
	if err != nil {
		t.Fatalf("server leaf: %v", err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCert)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		s := tls.Server(c, &tls.Config{
			Certificates: []tls.Certificate{serverLeaf},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS12,
		})
		srvErr <- s.Handshake()
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cl := tls.Client(conn, &tls.Config{
		Certificates:       []tls.Certificate{clientLeaf},
		InsecureSkipVerify: true, //nolint:gosec // the server side is under test, not the client's view of it
		MinVersion:         tls.VersionTLS12,
	})
	cerr := cl.Handshake()
	if cerr == nil {
		// TLS 1.3 reports a client-cert refusal on the first read, so read once to surface it.
		_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = cl.Read(make([]byte, 1))
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server refused the agent-held leaf as a client certificate: %v", err)
	}
}

func mintLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	leaf, err := kp.SelfSignedLeaf("a1b2.tdead.agents.whisper.online", "", netip.MustParseAddr("2a04:2a01:9::abcd"))
	if err != nil {
		t.Fatalf("SelfSignedLeaf: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}
