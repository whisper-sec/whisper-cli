// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// `whisper domain submit --webpki` must fire op:domain with the submit sub-op and set
// acme:true (the WebPKI opt-in). Without --webpki it must NOT set acme (DANE-EE-only stays the
// default). Asserts the control-call SHAPE without a live control plane.

func TestDomainSubmit_WebpkiSetsAcmeOptIn(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newDomainCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"submit", "example.com", "--webpki"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("domain submit --webpki errored: %v", err)
	}
	body, ok := bodyForOp(seen, "domain")
	if !ok {
		t.Fatalf("domain submit must fire op:domain, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "op:'submit'") {
		t.Fatalf("domain submit must carry the submit sub-op; body=%q", body)
	}
	if !strings.Contains(body, "acme:true") {
		t.Fatalf("--webpki must set acme:true (the WebPKI opt-in); body=%q", body)
	}
	if !strings.Contains(body, "domain:'example.com'") {
		t.Fatalf("domain submit must carry the apex; body=%q", body)
	}
}

func TestDomainSubmit_WithoutWebpki_NoAcme(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newDomainCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"submit", "example.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("domain submit errored: %v", err)
	}
	body, _ := bodyForOp(seen, "domain")
	if strings.Contains(body, "acme") {
		t.Fatalf("a plain submit must NOT opt into WebPKI; body=%q", body)
	}
}

func TestDomainList_FiresListSubOp(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newDomainCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("domain list errored: %v", err)
	}
	body, ok := bodyForOp(seen, "domain")
	if !ok || !strings.Contains(body, "op:'list'") {
		t.Fatalf("domain list must fire op:domain with the list sub-op; body=%q ops=%v", body, opsSeen(seen))
	}
}
