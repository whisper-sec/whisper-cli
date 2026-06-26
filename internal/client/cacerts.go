// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
)

// embeddedCABundle is the Mozilla CA list baked into the binary so verification of the
// *.whisper.online wildcard TLS never depends on the host's system trust store — the
// `curl cli.whisper.online | sh` binary just works on a bare container or a stripped
// host (zero config). Refreshed at build time from ca-certificates.
//
//go:embed cabundle/mozilla-cacert.pem
var embeddedCABundle []byte

// RootCAs returns the trust pool the CLI uses for every HTTPS call. It UNIONS the
// system pool (when present) with the embedded Mozilla bundle, so:
//   - a host with a trust store gets it plus our pinned bundle (max reliability), and
//   - a host with NO trust store still verifies via the embedded bundle (zero config).
//
// Conservative-emit: we never disable verification; liberal-accept: either trust
// source suffices. A nil return is impossible — the embedded bundle is always present.
func RootCAs() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(embeddedCABundle)
	return pool
}

// EmbeddedRootCAs returns a pool of ONLY the embedded Mozilla bundle (no system pool).
// Exposed for tests that must assert the embedded bundle is non-empty and parses.
func EmbeddedRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(embeddedCABundle)
	return pool
}

// TLSConfig is the standard client TLS config: verified against RootCAs, TLS 1.2 floor.
func TLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    RootCAs(),
		MinVersion: tls.VersionTLS12,
	}
}
