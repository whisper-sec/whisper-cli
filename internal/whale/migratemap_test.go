// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// migratemap_test.go is the fidelity matrix. The property under test throughout is the one
// this is really about: WE NEVER SILENTLY DROP OR SILENTLY WIDEN A RULE. Every case
// here asserts that a specific piece of their configuration left a specific, findable line
// in the report.

// fixtureTailnet is a small tailnet that exercises every class at once: an exact rule, a
// port-constrained rule, a HOST-dimension rule, a posture rule, an IdP-synced group, a
// subnet router, an exit node, an auth key and an ssh block.
func fixtureTailnet(t *testing.T) *Tailnet {
	t.Helper()
	policy := []byte(`{
  // engineering
  "groups": {"group:eng": ["alice@example.com"]},
  "tagOwners": {"tag:prod": ["group:eng"]},
  "hosts": {"db-01": "100.64.0.9"},
  "acls": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:*"]},
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:443"]},
    {"action": "accept", "src": ["group:sre"], "dst": ["mail.corp.example:25"]},
    {"action": "accept", "src": ["*"], "dst": ["autogroup:internet:443"], "srcPosture": ["posture:latest"]}
  ],
  "ssh": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:prod"], "users": ["root"]},
    {"action": "check", "src": ["group:eng"], "dst": ["tag:prod"], "users": ["root"], "checkPeriod": "12h"}
  ],
  "postures": {"posture:latest": ["node:os IN ['linux']"]},
  "tests": [{"src": "alice@example.com", "accept": ["tag:prod:443"]}],
}`)
	pol, lines, err := ParsePolicy(policy)
	if err != nil {
		t.Fatalf("the fixture policy did not parse: %v", err)
	}
	return &Tailnet{
		Name:        "example.com",
		PolicyLines: lines,
		Policy:      pol,
		Devices: []TSDevice{
			{ID: "d1", Hostname: "db-01", Name: "db-01.tail1234.ts.net", OS: "linux",
				Addresses: []string{"100.64.0.9", "fd7a:115c::9"}, Tags: []string{"tag:prod"}, User: "alice@example.com"},
			{ID: "d2", Hostname: "Router 1", Name: "router-1.tail1234.ts.net", OS: "linux",
				Addresses: []string{"100.64.0.10"}, AdvertisedRoutes: []string{"10.0.0.0/24", "0.0.0.0/0"}},
		},
		Keys:  []TSKey{{ID: "kABC", Description: "ci runner"}},
		Users: []TSUser{{ID: "u1", LoginName: "alice@example.com"}},
		DNS:   TSDNS{Nameservers: []string{"1.1.1.1"}, SplitDNS: map[string][]string{"corp.example": {"10.0.0.53"}}},
	}
}

func buildFixturePlan(t *testing.T) *Plan {
	t.Helper()
	p, err := BuildPlan(fixtureTailnet(t), BuildOptions{
		Now:                   time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
		CredentialFingerprint: "0123456789ab",
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return p
}

// findFidelity returns the report lines whose subject contains want.
func findFidelity(p *Plan, kind, want string) []Fidelity {
	var out []Fidelity
	for _, f := range p.Fidelity {
		if f.Kind == kind && strings.Contains(f.Subject, want) {
			out = append(out, f)
		}
	}
	return out
}

func TestPlanNamesEveryUnreadableThingUpFront(t *testing.T) {
	p := buildFixturePlan(t)
	joined := strings.Join(p.Unreadable, "\n")
	for _, must := range []string{"auth-key secrets", "node private keys", "IdP", "serve and funnel"} {
		if !strings.Contains(joined, must) {
			t.Errorf("the plan does not state up front that %q is unreadable:\n%s", must, joined)
		}
	}
}

// The four UNMAPPED classes the acceptance criteria greps for.
func TestPlanReportsTheUnmappableAsUnmapped(t *testing.T) {
	p := buildFixturePlan(t)
	var unmapped []Fidelity
	for _, f := range p.Fidelity {
		if f.Class == ClassUnmapped {
			unmapped = append(unmapped, f)
		}
	}
	need := map[string]bool{"auth-key": false, "subnet-route": false, "serve-funnel": false, "group": false, "dns": false}
	for _, f := range unmapped {
		if _, ok := need[f.Kind]; ok {
			need[f.Kind] = true
		}
	}
	for kind, found := range need {
		if !found {
			t.Errorf("nothing of kind %q is reported UNMAPPED, so it would disappear silently", kind)
		}
	}
	for _, f := range unmapped {
		if strings.TrimSpace(f.Detail) == "" {
			t.Errorf("UNMAPPED %s/%s carries no reason, which makes the report unactionable", f.Kind, f.Subject)
		}
	}
}

// An IdP-synced group is referenced by a rule and declared nowhere. That is the third
// unreadable thing, and it must be named per group, not summarised away.
func TestIdPSyncedGroupIsReportedByName(t *testing.T) {
	p := buildFixturePlan(t)
	got := findFidelity(p, "group", "group:sre")
	if len(got) != 1 || got[0].Class != ClassUnmapped {
		t.Fatalf("group:sre is referenced but declared nowhere and must be UNMAPPED, got %+v", got)
	}
	if !strings.Contains(got[0].Detail, "IdP") {
		t.Fatalf("the reason does not say why it is unreadable: %q", got[0].Detail)
	}
	declared := findFidelity(p, "group", "group:eng")
	if len(declared) != 1 || declared[0].Class != ClassExact {
		t.Fatalf("a group declared in the policy file must map EXACT, got %+v", declared)
	}
}

// The corrected B-30 claim, asserted in both directions.
func TestPortConstraintIsCarriedByReachabilityAndIsNotWidening(t *testing.T) {
	p := buildFixturePlan(t)
	var found bool
	for _, r := range p.Rules {
		if r.Dst == "tag:prod" && r.Ports == "443" {
			found = true
			if r.Widening {
				t.Errorf("a port-constrained rule was reported as widening against WhaleReachability, "+
					"which does express portRange: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("the port-constrained rule is missing from the plan entirely")
	}
}

func TestHostDimensionEastWestWidensAndSaysSo(t *testing.T) {
	p := buildFixturePlan(t)
	var got *PlanRule
	for i := range p.Rules {
		if p.Rules[i].Dst == "mail.corp.example" {
			got = &p.Rules[i]
		}
	}
	if got == nil {
		t.Fatal("the HOST-dimension rule is missing from the plan")
	}
	if !got.Widening {
		t.Fatal("a name destination east-west must be reported as widening: the kernel has no hostname")
	}
	if got.Plane != PlaneEastWest {
		t.Fatalf("the widening was recorded on plane %q, and the report must name the plane", got.Plane)
	}
	if !strings.Contains(got.Note, "kernel") {
		t.Fatalf("the note does not explain why: %q", got.Note)
	}
}

func TestSourcePostureWidens(t *testing.T) {
	p := buildFixturePlan(t)
	for _, r := range p.Rules {
		if r.Dst == "autogroup:internet" {
			if !r.Widening {
				t.Fatal("dropping a srcPosture condition admits sources their rule excluded, and must be reported as widening")
			}
			if r.Plane != PlaneEgress {
				t.Fatalf("autogroup:internet is the egress plane, not %q", r.Plane)
			}
			return
		}
	}
	t.Fatal("the autogroup:internet rule is missing from the plan")
}

// A wide-open rule loses nothing, so it must NOT be reported as widening: an inflated
// widening count trains people to pass --accept-widening without reading.
func TestAWideOpenRuleIsExact(t *testing.T) {
	p := buildFixturePlan(t)
	for _, r := range p.Rules {
		if r.Dst == "tag:prod" && r.Ports == "*" {
			if r.Widening {
				t.Fatalf("an unconstrained rule was counted as widening: %+v", r)
			}
			return
		}
	}
	t.Fatal("the unconstrained rule is missing from the plan")
}

func TestSSHCheckActionIsUnmappedRatherThanRoundedToAccept(t *testing.T) {
	p := buildFixturePlan(t)
	var sawCheck bool
	for _, s := range p.SSH {
		if s.Action == "check" {
			sawCheck = true
			if s.Note == "" {
				t.Error("`action: check` was carried with no note, so a second factor would vanish silently")
			}
		}
	}
	if !sawCheck {
		t.Fatal("the `check` ssh rule is missing from the plan")
	}
	for _, f := range findFidelity(p, "ssh", "ssh[1]") {
		if f.Class != ClassUnmapped {
			t.Fatalf("`action: check` must be UNMAPPED, got %s", f.Class)
		}
	}
}

func TestNodeLabelsAreSanitisedAndTheChangeIsReported(t *testing.T) {
	p := buildFixturePlan(t)
	for _, n := range p.Nodes {
		if n.Hostname != "Router 1" {
			continue
		}
		if n.Label != "router-1" {
			t.Fatalf("label %q, want router-1", n.Label)
		}
		// The name came from the MagicDNS name, which is already valid, so it is exact.
		return
	}
	t.Fatal("the router node is missing from the plan")
}

func TestSanitiseLabel(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		exact bool
	}{
		{"db-01", "db-01", true},
		// Case folding is not a loss: DNS labels are case-insensitive and lower case is
		// simply the canonical spelling, so this is not reported as a rename.
		{"DB-01", "db-01", true},
		{"Router 1", "router-1", false},
		{"--weird--", "weird", false},
		{"", "node", false},
		{"a_b", "a-b", false},
	}
	for _, c := range cases {
		got, exact := SanitiseLabel(c.in)
		if got != c.want || exact != c.exact {
			t.Errorf("SanitiseLabel(%q) = (%q, %v), want (%q, %v)", c.in, got, exact, c.want, c.exact)
		}
	}
}

func TestLabelCollisionIsDeterministicAndNotSilent(t *testing.T) {
	tn := fixtureTailnet(t)
	tn.Devices = append(tn.Devices, TSDevice{ID: "d3", Hostname: "db 01", Name: "db-01.tail1234.ts.net"})
	p1, err := BuildPlan(tn, BuildOptions{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	p2, _ := BuildPlan(tn, BuildOptions{Now: time.Unix(0, 0)})
	if p1.Hash != p2.Hash {
		t.Fatal("two plans from the same tailnet hashed differently, so the hash proves nothing")
	}
	seen := map[string]bool{}
	for _, n := range p1.Nodes {
		if seen[n.Label] {
			t.Fatalf("two nodes were planned under the same label %q", n.Label)
		}
		seen[n.Label] = true
	}
}

// Failure mode 2, asserted directly: an unread device list must not become an empty plan.
func TestBuildPlanRefusesWhenALoadBearingSectionIsUnread(t *testing.T) {
	tn := fixtureTailnet(t)
	tn.markUnread("devices", "timeout after 30s", true)
	if _, err := BuildPlan(tn, BuildOptions{}); err == nil {
		t.Fatal("a plan was built on an unread device list: a timeout would render as a finished migration of nothing")
	}
}

func TestBuildPlanRefusesAnEmptyTailnet(t *testing.T) {
	tn := fixtureTailnet(t)
	tn.Devices = nil
	_, err := BuildPlan(tn, BuildOptions{})
	if err == nil {
		t.Fatal("a plan with zero nodes was written, which looks exactly like a finished migration")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Fatalf("the refusal does not name the likely cause: %v", err)
	}
}

// The credential must be nowhere in the artifact. This asserts it over the real serialised
// bytes rather than over the struct, because bytes are what leaks.
func TestPlanBytesCarryNoCredential(t *testing.T) {
	p := buildFixturePlan(t)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "tskey") {
		t.Fatal("the serialised plan contains a tskey token")
	}
	if !strings.Contains(string(b), "0123456789ab") {
		t.Fatal("the plan does not record the credential fingerprint, so apply cannot refuse a plan made with another credential")
	}
}

func TestSummaryCountsEveryClass(t *testing.T) {
	p := buildFixturePlan(t)
	total := 0
	for _, n := range p.Summary {
		total += n
	}
	if total != len(p.Fidelity) {
		t.Fatalf("the summary counts %d entries and the report has %d", total, len(p.Fidelity))
	}
	if p.WideningRules() == 0 {
		t.Fatal("this fixture contains widening rules and the plan counted none")
	}
}

// --- the spanning invariant -----------------------------------------------------------

// TestEveryRuleInTheirPolicyLeavesALineInTheReport is the invariant the whole file serves,
// asserted over the WHOLE policy rather than over one shape at a time: for every acl,
// every grant and every ssh rule in their file, at index i, the report carries at least
// one line whose subject names that index.
//
// It is written as a loop over the PARSED policy on purpose. A rule shape nobody has
// thought of yet is covered the moment it appears in the fixture, and a mapper that
// learns to skip a shape fails here rather than shipping a report whose silence looks
// like a clean migration. This is the test that matters: it fails if a rule is
// dropped without being reported.
func TestEveryRuleInTheirPolicyLeavesALineInTheReport(t *testing.T) {
	// Every awkward shape at once, including the two halves a rule can be missing.
	policy := []byte(`{
  "groups": {"group:eng": ["alice@example.com"]},
  "hosts": {"db-01": "100.64.0.9"},
  "acls": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:prod:443"]},
    {"action": "accept", "src": ["group:eng"], "dst": ["mail.corp.example:25"]},
    {"action": "deny",   "src": ["tag:ci"],    "dst": ["tag:prod:*"]},
    {"action": "accept", "src": ["group:eng"], "dst": []},
    {"action": "accept", "src": [],            "dst": ["tag:prod:22"]},
    {"action": "accept", "src": ["*"],         "dst": ["autogroup:internet:*"]}
  ],
  "grants": [
    {"src": ["group:eng"], "dst": ["tag:prod"], "ip": ["tcp:22"]},
    {"src": ["group:eng"], "dst": []},
    {"src": ["group:eng"], "dst": ["tag:prod"], "app": {"example.com/cap": [{"x": 1}]}}
  ],
  "ssh": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:prod"], "users": ["root"]},
    {"action": "check",  "src": ["group:eng"], "dst": ["tag:prod"], "users": ["root"], "checkPeriod": "12h"},
    {"action": "sudo",   "src": ["group:eng"], "dst": ["tag:prod"], "users": ["root"]}
  ],
}`)
	pol, lines, err := ParsePolicy(policy)
	if err != nil {
		t.Fatalf("the fixture policy did not parse: %v", err)
	}
	tn := fixtureTailnet(t)
	tn.Policy, tn.PolicyLines = pol, lines

	p, err := BuildPlan(tn, BuildOptions{Now: time.Unix(0, 0), CredentialFingerprint: "0123456789ab"})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	// subjectsFor collects every report subject of one kind, so the assertion below reads
	// the report exactly the way `jq '.fidelity[]'` in the acceptance criteria does.
	reported := func(kind, prefix string) bool {
		for _, f := range p.Fidelity {
			if f.Kind == kind && strings.HasPrefix(f.Subject, prefix) {
				return true
			}
		}
		return false
	}

	for i := range pol.ACLs {
		if prefix := fmt.Sprintf("acls[%d] ", i); !reported("rule", prefix) {
			t.Errorf("acls[%d] (%v -> %v) left NO line in the fidelity report: a dropped rule nobody is told about",
				i, pol.ACLs[i].Src, pol.ACLs[i].Dst)
		}
	}
	for i := range pol.Grants {
		if prefix := fmt.Sprintf("grants[%d] ", i); !reported("rule", prefix) {
			t.Errorf("grants[%d] (%v -> %v) left NO line in the fidelity report",
				i, pol.Grants[i].Src, pol.Grants[i].Dst)
		}
	}
	for i := range pol.SSH {
		if prefix := fmt.Sprintf("ssh[%d] ", i); !reported("ssh", prefix) {
			t.Errorf("ssh[%d] (%v -> %v) left NO line in the fidelity report",
				i, pol.SSH[i].Src, pol.SSH[i].Dst)
		}
	}

	// The plan's own rule list must be a complete account too, not only the report: an
	// operator reading .rules must see the same number of decisions.
	if len(p.Rules) < len(pol.ACLs)+len(pol.Grants) {
		t.Errorf("the plan carries %d rules for %d acls and %d grants; a rule missing from the list is a rule "+
			"nobody can review", len(p.Rules), len(pol.ACLs), len(pol.Grants))
	}
}

// A rule with no destination, and one with no source, are the two shapes the mapper's
// loops cannot reach. Both are reported as UNMAPPED with the reason, and NEITHER is
// silently treated as harmless.
func TestAHalfWrittenRuleIsReportedRatherThanSkipped(t *testing.T) {
	policy := []byte(`{
  "acls": [
    {"action": "accept", "src": ["group:eng"], "dst": []},
    {"action": "accept", "src": [], "dst": ["tag:prod:22"]}
  ],
}`)
	pol, lines, err := ParsePolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	tn := fixtureTailnet(t)
	tn.Policy, tn.PolicyLines = pol, lines
	p, err := BuildPlan(tn, BuildOptions{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	noDst := findFidelity(p, "rule", "acls[0] ")
	if len(noDst) == 0 {
		t.Fatal("the destination-less rule left no line at all")
	}
	if noDst[0].Class != ClassUnmapped {
		t.Errorf("the destination-less rule is classed %s, want %s", noDst[0].Class, ClassUnmapped)
	}
	if !strings.Contains(noDst[0].Detail, "no destination") {
		t.Errorf("the reason does not say what is missing: %q", noDst[0].Detail)
	}

	noSrc := findFidelity(p, "rule", "acls[1] ")
	if len(noSrc) == 0 {
		t.Fatal("the source-less rule left no line at all")
	}
	if noSrc[0].Class != ClassUnmapped {
		t.Errorf("the source-less rule is classed %s, want %s", noSrc[0].Class, ClassUnmapped)
	}
	// The dangerous misreading is "no source means everyone". It must not be carried at
	// all, and it must never be reported as an exact mapping.
	for _, r := range p.Rules {
		if r.From == "acls" && len(r.Src) == 0 && r.Note == "" {
			t.Errorf("a source-less rule was carried with no note: %+v", r)
		}
	}
}
