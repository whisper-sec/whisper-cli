// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/resolverprofile"
)

// resolver_test.go - the `whisper resolver` verb: keyed-by-design
// honesty (keyless --print previews, keyless APPLY fails soft with the
// get-a-key step), the Linux :53-first path selection with its probe-gated
// DoH-forwarder fallback, --print emits-not-applies, token mint + reuse (no
// device sprawl), the op:resolver allocation, --off revert + revoke, and the
// --os override. The applier is a recording fake - NO OS state is touched.

const (
	t2rTok  = "whisper_live_DEVICE_res1"
	t2rDoH  = "https://doh.whisper.online/" + t2rTok + "/dns-query"
	t2rAddr = "2a04:2a01:9::fee1"
	t2rIP   = "2a04:2a01:0:53::77"
)

// t2rFakeApplier records Apply/Revert calls; nothing touches the machine.
type t2rFakeApplier struct {
	host     resolverprofile.Host
	applied  []resolverprofile.Rendered
	reverted []resolverprofile.Rendered
	applyErr error
}

func (f *t2rFakeApplier) DetectHost() resolverprofile.Host { return f.host }
func (f *t2rFakeApplier) Apply(r resolverprofile.Rendered) error {
	f.applied = append(f.applied, r)
	return f.applyErr
}
func (f *t2rFakeApplier) Revert(r resolverprofile.Rendered) error {
	f.reverted = append(f.reverted, r)
	return nil
}

// t2rSetup wires every seam for one test: temp state file, fake applier, a
// pinned GOOS, clean env, and restores everything afterwards.
func t2rSetup(t *testing.T, goos string, fake *t2rFakeApplier) {
	t.Helper()
	savedPath, savedFor, savedGOOS, savedG := resolverStatePathFn, resolverApplierFor, resolverGOOS, g
	savedProbe := resolverProbe53
	t.Cleanup(func() {
		resolverStatePathFn, resolverApplierFor, resolverGOOS, g = savedPath, savedFor, savedGOOS, savedG
		resolverProbe53 = savedProbe
	})
	statePath := filepath.Join(t.TempDir(), "resolver.json")
	resolverStatePathFn = func() string { return statePath }
	resolverGOOS = goos
	// The dedicated :53 resolver reads as reachable unless a test says otherwise.
	resolverProbe53 = func(string) error { return nil }
	if fake != nil {
		resolverApplierFor = func(string) (resolverprofile.Applier, bool) { return fake, true }
	} else {
		resolverApplierFor = func(string) (resolverprofile.Applier, bool) { return nil, false }
	}
	// Neutralise the ambient key ladder: no env key, no real key file.
	t.Setenv("WHISPER_API_KEY", "")
	t.Setenv("WHISPER_KEY", "")
	g = globalFlags{keyFile: filepath.Join(t.TempDir(), "no-key"), timeout: 5 * time.Second}
}

// t2rControlServer mocks the control plane: op:register (device), op:resolver,
// op:revoke. It records which ops were called.
func t2rControlServer(t *testing.T, ops *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(body, "op:'register'"):
			*ops = append(*ops, "register")
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{` +
				`"columns":["token","doh_url","dot_host","resolver_ip","address","label"],` +
				`"rows":[["` + t2rTok + `","` + t2rDoH + `","x.dot.whisper.online","","` + t2rAddr + `","resolver-linux"]]}}`))
		case strings.Contains(body, "op:'resolver'"):
			*ops = append(*ops, "resolver")
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{` +
				`"columns":["address","state"],"rows":[["` + t2rIP + `","active"]]}}`))
		case strings.Contains(body, "op:'revoke'"):
			*ops = append(*ops, "revoke")
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{` +
				`"columns":["revoked"],"rows":[[true]]}}`))
		default:
			*ops = append(*ops, "unknown")
			_, _ = w.Write([]byte(`{"ok":false,"status":400,"result":null}`))
		}
	}))
}

func t2rRun(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newResolverCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	stdout, stderr = captureStd(t, func() { err = cmd.Execute() })
	return stdout, stderr, err
}

func TestT2Resolver_KeylessPrintPreviewsWithPlaceholders(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/usr/bin/cloudflared"}}
	t2rSetup(t, "linux", fake)
	// An unroutable control URL proves the keyless path never talks to the
	// control plane at all.
	g.controlURL = "http://127.0.0.1:1"

	// Linux default preview = the dedicated :53 primary, discard-prefix stand-in.
	stdout, stderr, err := t2rRun(t, "--print")
	if err != nil {
		t.Fatalf("keyless --print errored: %v", err)
	}
	if !strings.Contains(stdout, resolverPrintPlaceholderIP) {
		t.Fatalf("keyless linux preview must carry the :53 stand-in on stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "needs a Whisper key") || !strings.Contains(stderr, resolverKeyURL) {
		t.Fatalf("keyless preview must state the get-a-key step:\n%s", stderr)
	}
	if len(fake.applied) != 0 || len(fake.reverted) != 0 {
		t.Fatalf("--print must not touch the applier: %+v", fake)
	}

	// Forcing --doh previews the forwarder profile with the token stand-in.
	stdout, _, err = t2rRun(t, "--print", "--doh")
	if err != nil {
		t.Fatalf("keyless --print --doh errored: %v", err)
	}
	if !strings.Contains(stdout, "YOUR-DEVICE-TOKEN") {
		t.Fatalf("keyless DoH preview must carry the token stand-in:\n%s", stdout)
	}
}

func TestT2Resolver_KeylessDNS53PrintPreviewsWithPlaceholder(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	stdout, stderr, err := t2rRun(t, "--resolver", "--print")
	if err != nil {
		t.Fatalf("keyless --resolver --print errored: %v", err)
	}
	if !strings.Contains(stderr, "needs a Whisper key") {
		t.Fatalf("the key requirement must be explained, not silent:\n%s", stderr)
	}
	if !strings.Contains(stdout, resolverPrintPlaceholderIP) {
		t.Fatalf("keyless --resolver --print must preview the :53 plan with the stand-in:\n%s", stdout)
	}
}

func TestT2Resolver_KeylessApplyFailsSoftWithKeyGuidance(t *testing.T) {
	// Tier-2 DoH is keyed BY DESIGN (the resolver applies the tenant's policy,
	// so anonymous DoH is refused): a keyless apply must NEVER wire a profile
	// that 403s - it fails soft with the get-a-key step and a non-zero exit.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/usr/bin/cloudflared"}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	_, _, err := t2rRun(t)
	if err == nil {
		t.Fatalf("keyless apply must fail soft (non-zero), got success")
	}
	for _, want := range []string{"needs a Whisper key", resolverKeyURL, "whisper resolver"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the fail-soft message must carry %q, got: %v", want, err)
		}
	}
	if len(fake.applied) != 0 || len(fake.reverted) != 0 {
		t.Fatalf("keyless apply must not touch the applier: %+v", fake)
	}
	// --resolver fails soft the same way (the /128 is per-tenant too).
	if _, _, err := t2rRun(t, "--resolver"); err == nil || !strings.Contains(err.Error(), "Whisper key") {
		t.Fatalf("keyless --resolver apply must fail soft with the key guidance, got: %v", err)
	}
}

func TestT2Resolver_KeyedPrintMintsNothing(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	stdout, stderr, err := t2rRun(t, "--print")
	if err != nil {
		t.Fatalf("keyed --print errored: %v", err)
	}
	// A dry run has NO side effects: no mint, no allocation - placeholders only.
	if len(ops) != 0 {
		t.Fatalf("--print must not call the control plane, called: %v", ops)
	}
	if !strings.Contains(stderr, "YOUR-DEVICE-TOKEN") || !strings.Contains(stderr, "dry run") {
		t.Fatalf("keyed dry run must show the clearly-marked stand-ins:\nstderr=%s", stderr)
	}
	// Linux default previews the :53 primary with the discard-prefix stand-in.
	if !strings.Contains(stdout, resolverPrintPlaceholderIP) {
		t.Fatalf("keyed linux dry run must preview the :53 plan:\n%s", stdout)
	}
	if len(fake.applied) != 0 {
		t.Fatalf("--print must not apply: %+v", fake.applied)
	}
}

func TestT2Resolver_KeyedLinuxDefaultPrefers53AndReuses(t *testing.T) {
	// The keyed Linux default is the dedicated :53 resolver - no forwarder, one
	// command on a stock distro. Mint + op:resolver on first run; both reused after.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	if _, stderr, err := t2rRun(t); err != nil {
		t.Fatalf("keyed apply errored: %v (stderr=%s)", err, stderr)
	}
	if len(ops) != 2 || ops[0] != "register" || ops[1] != "resolver" {
		t.Fatalf("first keyed linux apply = mint + op:resolver, got %v", ops)
	}
	if r := fake.applied[0]; r.Mode != resolverprofile.ModeDNS53 || r.ResolverIP != t2rIP {
		t.Fatalf("the linux default must wire the dedicated /128 on :53: %+v", r)
	}
	// The state file persists the credential, and only its owner may read it.
	assertPrivateFile(t, resolverStatePathFn())

	// Re-run: the persisted token AND /128 are REUSED - no new control calls.
	ops = ops[:0]
	if _, _, err := t2rRun(t); err != nil {
		t.Fatalf("re-apply errored: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("re-apply must reuse the persisted device + resolver, called: %v", ops)
	}
}

func TestT2Resolver_KeyedExplicitDoHUsesForwarder(t *testing.T) {
	// --doh passed explicitly: the encrypted forwarder profile, no :53
	// preference, no op:resolver allocation.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x", ForwarderVersion: "2025.11.1"}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	if _, stderr, err := t2rRun(t, "--doh"); err != nil {
		t.Fatalf("keyed --doh apply errored: %v (stderr=%s)", err, stderr)
	}
	if len(ops) != 1 || ops[0] != "register" {
		t.Fatalf("explicit DoH = exactly one device mint, got %v", ops)
	}
	if r := fake.applied[0]; r.Mode != resolverprofile.ModeDoH || r.DoHURL != t2rDoH {
		t.Fatalf("explicit DoH must wire the TENANT DoH URL: %+v", r)
	}
}

func TestT2Resolver_WindowsKeyedDefaultStaysDoH(t *testing.T) {
	// The :53-first preference is a LINUX decision (Windows speaks DoH
	// natively): keyed Windows default remains the encrypted DoH profile.
	fake := &t2rFakeApplier{host: resolverprofile.Host{}}
	t2rSetup(t, "windows", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	if _, stderr, err := t2rRun(t); err != nil {
		t.Fatalf("keyed windows apply errored: %v (stderr=%s)", err, stderr)
	}
	if len(ops) != 1 || ops[0] != "register" {
		t.Fatalf("keyed windows DoH = one mint, no op:resolver, got %v", ops)
	}
	if r := fake.applied[0]; r.Mode != resolverprofile.ModeDoH || r.DoHURL != t2rDoH {
		t.Fatalf("windows default must stay tenant DoH: %+v", r)
	}
}

func TestT2Resolver_KeyedDNS53AllocatesTheTenantResolver(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	_, stderr, err := t2rRun(t, "--resolver")
	if err != nil {
		t.Fatalf("keyed --resolver errored: %v (stderr=%s)", err, stderr)
	}
	if len(ops) != 2 || ops[0] != "register" || ops[1] != "resolver" {
		t.Fatalf("keyed dns53 = mint + op:resolver, got %v", ops)
	}
	r := fake.applied[0]
	if r.Mode != resolverprofile.ModeDNS53 || r.ResolverIP != t2rIP {
		t.Fatalf("the dedicated /128 must be wired: %+v", r)
	}
}

func TestT2Resolver_Linux53UnreachableFallsBackToForwarderDoH(t *testing.T) {
	// The :53 probe fails (no IPv6 route) and a usable forwarder exists: the
	// keyed default falls back to the encrypted DoH forwarder profile, and the
	// unreachable /128 is NOT silently wired anywhere.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "dnscrypt-proxy", ForwarderPath: "/usr/sbin/dnscrypt-proxy", ForwarderVersion: "2.0.45"}}
	t2rSetup(t, "linux", fake)
	resolverProbe53 = func(string) error { return errors.New("dial tcp: network is unreachable") }
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	_, stderr, err := t2rRun(t)
	if err != nil {
		t.Fatalf("probe-failed apply errored: %v (stderr=%s)", err, stderr)
	}
	if len(ops) != 2 || ops[1] != "resolver" {
		t.Fatalf("the primary still allocates the tenant resolver first: %v", ops)
	}
	r := fake.applied[0]
	if r.Mode != resolverprofile.ModeDoH || r.DoHURL != t2rDoH {
		t.Fatalf("the fallback must be the tenant DoH forwarder profile: %+v", r)
	}
	if r.ResolverIP != "" {
		t.Fatalf("the unreachable /128 must not ride the DoH plan: %+v", r)
	}
	if !strings.Contains(stderr, "did not answer") || !strings.Contains(stderr, "DoH forwarder profile instead") {
		t.Fatalf("the fallback must be explained:\n%s", stderr)
	}
}

func TestT2Resolver_Linux53UnreachableNoForwarderFailsClear(t *testing.T) {
	// :53 unreachable AND no usable forwarder: nothing is applied (DNS is never
	// broken) and the error carries the exact install line.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	resolverProbe53 = func(string) error { return errors.New("dial tcp: network is unreachable") }
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	_, _, err := t2rRun(t)
	if err == nil || !strings.Contains(err.Error(), "sudo apt install dnscrypt-proxy") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("must fail clear with the install line and the no-change promise, got: %v", err)
	}
	if len(fake.applied) != 0 {
		t.Fatalf("nothing may be applied when both paths are unavailable: %+v", fake.applied)
	}
}

func TestT2Resolver_OffRevertsAndRevokes(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	// Simulate a prior keyed apply.
	saveResolverState(resolverState{Token: t2rTok, Address: t2rAddr, DoHURL: t2rDoH, Mode: "doh", OS: "linux"})

	_, stderr, err := t2rRun(t, "--off")
	if err != nil {
		t.Fatalf("--off errored: %v (stderr=%s)", err, stderr)
	}
	if len(fake.reverted) != 1 {
		t.Fatalf("--off must run the applier revert once: %+v", fake.reverted)
	}
	// The minted token is revoked by its /128 (a leaked config then stops
	// resolving) and the state file is gone.
	if len(ops) != 1 || ops[0] != "revoke" {
		t.Fatalf("--off must revoke the device token, got %v", ops)
	}
	if _, err := os.Stat(resolverStatePathFn()); !os.IsNotExist(err) {
		t.Fatalf("--off must remove the state file")
	}
}

func TestT2Resolver_OffKeylessIsIdempotentNoOp(t *testing.T) {
	// Nothing applied, no key: --off still succeeds (guards make the revert a
	// no-op) and no control-plane call is made.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	_, stderr, err := t2rRun(t, "--off")
	if err != nil {
		t.Fatalf("keyless --off must be a clean no-op, got: %v (stderr=%s)", err, stderr)
	}
	if len(fake.reverted) != 1 {
		t.Fatalf("--off must still run the (guarded, idempotent) revert: %+v", fake.reverted)
	}
}

func TestT2Resolver_OffPrintEmitsRevertOnly(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	stdout, _, err := t2rRun(t, "--off", "--print")
	if err != nil {
		t.Fatalf("--off --print errored: %v", err)
	}
	if !strings.Contains(stdout, "revert the doh profile") {
		t.Fatalf("--off --print must emit the revert script:\n%s", stdout)
	}
	if len(fake.reverted) != 0 || len(fake.applied) != 0 {
		t.Fatalf("--off --print must not touch the applier: %+v", fake)
	}
}

func TestT2Resolver_OSOverridePrintsOtherOS(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	stdout, _, err := t2rRun(t, "--print", "--os", "windows")
	if err != nil {
		t.Fatalf("--print --os windows errored: %v", err)
	}
	if !strings.Contains(stdout, "Add-DnsClientDohServerAddress") {
		t.Fatalf("--os windows must render the PowerShell plan:\n%s", stdout)
	}
	// macos is accepted liberally and maps to darwin.
	stdout, _, err = t2rRun(t, "--print", "--os", "macos")
	if err != nil {
		t.Fatalf("--print --os macos errored: %v", err)
	}
	if !strings.Contains(stdout, "open whisper-dns.mobileconfig") {
		t.Fatalf("--os macos must render the darwin staging plan:\n%s", stdout)
	}
}

func TestT2Resolver_OSOverrideRefusedForApply(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"

	_, _, err := t2rRun(t, "--os", "windows")
	if err == nil || !isUsageError(err) {
		t.Fatalf("apply with a foreign --os must be a usage error, got: %v", err)
	}
	if len(fake.applied) != 0 {
		t.Fatalf("nothing may be applied under a foreign --os: %+v", fake.applied)
	}
}

func TestT2Resolver_NeedsRootPrintsExactBlock(t *testing.T) {
	fake := &t2rFakeApplier{
		host:     resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"},
		applyErr: resolverprofile.ErrNeedsRoot,
	}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"

	stdout, _, err := t2rRun(t)
	if err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("a not-root apply must name the sudo fix, got: %v", err)
	}
	if !strings.Contains(stdout, "#!/usr/bin/env bash") {
		t.Fatalf("the exact runnable block must be printed on stdout:\n%s", stdout)
	}
}

func TestT2Resolver_QuietPrintsLoadBearingValue(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"
	g.quiet = true

	stdout, stderr, err := t2rRun(t, "--print")
	if err != nil {
		t.Fatalf("--quiet --print errored: %v", err)
	}
	// The linux default previews the :53 primary, so the load-bearing value is
	// the resolver stand-in (a keyed apply prints the real /128 here).
	if strings.TrimSpace(stdout) != resolverPrintPlaceholderIP {
		t.Fatalf("--quiet must print ONLY the load-bearing value, got %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("--quiet prints no chrome, got %q", stderr)
	}
}

func TestT2Resolver_JSONShape(t *testing.T) {
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/x"}}
	t2rSetup(t, "linux", fake)
	g.controlURL = "http://127.0.0.1:1"
	g.jsonOut = true

	stdout, _, err := t2rRun(t, "--print")
	if err != nil {
		t.Fatalf("--json --print errored: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, stdout)
	}
	for _, key := range []string{"mode", "os", "doh_url", "apply", "revert", "applied", "script"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("--json is missing %q: %s", key, stdout)
		}
	}
	if parsed["applied"] != false {
		t.Fatalf("--print must report applied:false: %s", stdout)
	}
}

func TestT2Resolver_ModeConflictIsUsageError(t *testing.T) {
	t2rSetup(t, "linux", &t2rFakeApplier{})
	_, _, err := t2rRun(t, "--doh", "--resolver")
	if err == nil || !isUsageError(err) {
		t.Fatalf("--doh with --resolver must be a usage error, got: %v", err)
	}
}
