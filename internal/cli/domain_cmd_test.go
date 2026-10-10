// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// `whisper domain submit --webpki` must REFUSE, and must fire no control call at all. The
// flag used to set acme:true and report success; nothing in the control plane reads that
// argument, so the report was the only thing that ever happened. This test asserts the
// refusal rather than the request, and it asserts the SILENCE on the wire too: an error
// message alongside a submitted domain would still leave the user with a domain onboarded
// under terms they did not get. The message must name the flag, so somebody who scripted it
// can find out why their pipeline stopped.

func TestDomainSubmit_WebpkiRefusesAndSendsNothing(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()

	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()

	cmd := newDomainCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"submit", "example.com", "--webpki"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("domain submit --webpki must refuse, got no error")
	}
	if !strings.Contains(err.Error(), "--webpki") {
		t.Fatalf("the refusal must name the flag so a scripted caller can find it; err=%q", err)
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("the refusal must say the capability is unavailable, not merely fail; err=%q", err)
	}
	if _, ok := bodyForOp(seen, "domain"); ok {
		t.Fatalf("a refused --webpki must not submit the domain anyway; ops=%v", opsSeen(seen))
	}
}

// The CONTROL for the test above: without the flag, the same command must still work and
// still reach op:domain. Without this, a submit path broken in any way would make the
// refusal test pass for the wrong reason.

func TestDomainSubmit_WithoutWebpkiStillSubmits(t *testing.T) {
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
		t.Fatalf("domain submit without --webpki must still work: %v", err)
	}
	body, ok := bodyForOp(seen, "domain")
	if !ok {
		t.Fatalf("domain submit must fire op:domain, ops=%v", opsSeen(seen))
	}
	if !strings.Contains(body, "op:'submit'") {
		t.Fatalf("domain submit must carry the submit sub-op; body=%q", body)
	}
	// The selector key is `name`. This assertion used to require `domain:`, which is the
	// spelling the control plane never read - so the test passed on a wire shape the control plane
	// silently ignored. A wire-shape test mirroring the implementation cannot catch a mismatch with
	// the server; what makes this one load-bearing is that the key it names is one the op accepts.
	if !strings.Contains(body, "name:'example.com'") {
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
