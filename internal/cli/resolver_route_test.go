// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/resolverprofile"
)

// The success line is a claim, so it is printed only when the applier
// proved lookups reach our resolver. A shadowed apply says what shadows it and
// exits non-zero; an unreadable check claims nothing either way.

// t2rVerifyingApplier is the recording fake plus a route verdict.
type t2rVerifyingApplier struct {
	t2rFakeApplier
	route    resolverprofile.RouteCheck
	verified int
}

func (f *t2rVerifyingApplier) VerifyRoute(resolverprofile.Rendered) resolverprofile.RouteCheck {
	f.verified++
	return f.route
}

func t2rRouteRun(t *testing.T, route resolverprofile.RouteCheck, args ...string) (*t2rVerifyingApplier, string, string, error) {
	t.Helper()
	fake := &t2rVerifyingApplier{t2rFakeApplier: t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}, route: route}
	t2rSetup(t, "linux", nil)
	resolverApplierFor = func(string) (resolverprofile.Applier, bool) { return fake, true }
	var ops []string
	srv := t2rControlServer(t, &ops)
	t.Cleanup(srv.Close)
	g.controlURL, g.key = srv.URL, "whisper_live_test"
	if len(args) > 0 && args[0] == "--json" {
		// --json is a root flag; the resolver verb reads it from g.
		g.jsonOut, args = true, args[1:]
	}
	stdout, stderr, err := t2rRun(t, args...)
	return fake, stdout, stderr, err
}

func TestResolverRoute_ShadowedNeverClaimsSuccess(t *testing.T) {
	problem := "systemd-resolved's current server is 2001:db8:0:53::99, not " + t2rIP + " (set in /etc/systemd/resolved.conf.d/10-corp-dns.conf); remove that DNS= line"
	fake, _, stderr, err := t2rRouteRun(t, resolverprofile.RouteCheck{State: resolverprofile.RouteShadowed, Want: t2rIP, Problems: []string{problem}})
	if fake.verified != 1 || len(fake.applied) != 1 {
		t.Fatalf("apply then verify exactly once: applied=%d verified=%d", len(fake.applied), fake.verified)
	}
	if strings.Contains(stderr, "now resolves through Whisper") {
		t.Fatalf("a shadowed apply must not print the success line:\n%s", stderr)
	}
	for _, want := range []string{"does NOT resolve only through Whisper", problem, "whisper resolver --off"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must carry %q:\n%s", want, stderr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "NOT in effect") {
		t.Fatalf("a shadowed apply exits non-zero so scripts notice, got %v", err)
	}
	// The state is kept so --off can still revert and revoke what was applied.
	if st := loadResolverState(); st.AppliedAt == "" || st.Token == "" {
		t.Fatalf("state must be saved for --off: %+v", st)
	}
}

func TestResolverRoute_VerifiedPrintsSuccessAndWhatWasProven(t *testing.T) {
	_, _, stderr, err := t2rRouteRun(t, resolverprofile.RouteCheck{State: resolverprofile.RouteOurs, Want: t2rIP})
	if err != nil {
		t.Fatalf("verified apply errored: %v", err)
	}
	if !strings.Contains(stderr, "now resolves through Whisper") || !strings.Contains(stderr, "verified  every lookup goes to "+t2rIP) {
		t.Fatalf("a verified apply prints success and the proof:\n%s", stderr)
	}
}

func TestResolverRoute_UnreadableClaimsNothing(t *testing.T) {
	_, _, stderr, err := t2rRouteRun(t, resolverprofile.RouteCheck{State: resolverprofile.RouteUnknown, Want: t2rIP, Unread: "resolvectl dns: exit status 1"})
	if err != nil {
		t.Fatalf("the apply itself succeeded; an unreadable check is not a failure: %v", err)
	}
	if strings.Contains(stderr, "now resolves through Whisper") {
		t.Fatalf("an unverified apply must not claim the route:\n%s", stderr)
	}
	if !strings.Contains(stderr, "could not be confirmed: resolvectl dns: exit status 1") || !strings.Contains(stderr, "resolvectl status") {
		t.Fatalf("say what could not be read and how to look:\n%s", stderr)
	}
}

func TestResolverRoute_JSONCarriesTheVerdict(t *testing.T) {
	_, stdout, _, err := t2rRouteRun(t, resolverprofile.RouteCheck{State: resolverprofile.RouteShadowed, Want: t2rIP, Problems: []string{"p1"}}, "--json")
	if err == nil {
		t.Fatalf("shadowed exits non-zero under --json too")
	}
	var m map[string]any
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &m); jerr != nil {
		t.Fatalf("--json must emit one JSON object: %v\n%s", jerr, stdout)
	}
	route, _ := m["route"].(map[string]any)
	if route["state"] != "shadowed" || route["want"] != t2rIP {
		t.Fatalf("route verdict missing from JSON: %v", m)
	}
}

func TestResolverRoute_ApplierWithoutVerifierKeepsTheOldLine(t *testing.T) {
	// Windows and macOS appliers have no route check (the OS owns routing
	// there); their success line is unchanged.
	fake := &t2rFakeApplier{host: resolverprofile.Host{ResolvedActive: true}}
	t2rSetup(t, "linux", fake)
	var ops []string
	srv := t2rControlServer(t, &ops)
	defer srv.Close()
	g.controlURL, g.key = srv.URL, "whisper_live_test"
	_, stderr, err := t2rRun(t)
	if err != nil || !strings.Contains(stderr, "now resolves through Whisper") || strings.Contains(stderr, "verified") {
		t.Fatalf("no verifier: unchanged success line, got err=%v\n%s", err, stderr)
	}
}
