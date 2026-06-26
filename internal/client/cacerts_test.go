// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
	"testing"
)

func TestEmbeddedCABundlePresentAndParses(t *testing.T) {
	if len(embeddedCABundle) == 0 {
		t.Fatal("embedded CA bundle is empty — the //go:embed failed")
	}
	if !bytes.Contains(embeddedCABundle, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("embedded CA bundle has no PEM certificates")
	}
	// The embedded-only pool must successfully parse at least one cert (AppendCertsFromPEM
	// silently skips garbage, so an empty pool would mean a corrupt bundle).
	pool := EmbeddedRootCAs()
	if pool == nil {
		t.Fatal("EmbeddedRootCAs returned nil")
	}
	// Subjects() is deprecated but the only way to count without exporting internals;
	// a non-empty subject list proves at least one cert parsed.
	//nolint:staticcheck
	if len(pool.Subjects()) == 0 {
		t.Fatal("embedded CA pool parsed zero certificates")
	}
}

func TestRootCAsUnionsSystemAndEmbedded(t *testing.T) {
	pool := RootCAs()
	if pool == nil {
		t.Fatal("RootCAs returned nil — must always have the embedded bundle")
	}
	//nolint:staticcheck
	if len(pool.Subjects()) == 0 {
		t.Fatal("RootCAs pool is empty")
	}
}

func TestTLSConfigMinVersion(t *testing.T) {
	cfg := TLSConfig()
	if cfg.RootCAs == nil {
		t.Fatal("TLSConfig must pin RootCAs")
	}
	if cfg.MinVersion == 0 {
		t.Fatal("TLSConfig must set a TLS floor (never the implicit default)")
	}
}
