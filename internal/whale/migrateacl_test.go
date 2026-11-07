// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// migrateacl_test.go holds the translation from a Tailscale policy to a WhaleACL to its one
// promise: every token keeps its meaning or narrows, and every narrowing is reported. Each
// case is written from a CLASS of input (a selector kind, an address kind, a protocol kind)
// rather than from the one rule the feature was built against.

// fleetPolicy is the tailnet most tests start from: two users, one tagged server, one
// alias, an ssh block and their own tests block.
const fleetPolicy = `{
  // HuJSON, as their admin console writes it
  "groups": {"group:eng": ["alice@example.com", "bob@example.com"]},
  "hosts":  {"db": "100.64.0.9"},
  "acls": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:Prod:443"]},
  ],
  "ssh": [
    {"action": "accept", "src": ["group:eng"], "dst": ["tag:Prod"], "users": ["ubuntu", "autogroup:nonroot"]},
  ],
  "tests": [
    {"src": "alice@example.com", "accept": ["tag:Prod:443"], "deny": ["tag:Prod:22"]},
  ],
}`

func fleetDevices() []TSDevice {
	return []TSDevice{
		{ID: "d1", Hostname: "db-01", Name: "db-01.tail1234.ts.net.", Addresses: []string{"100.64.0.9", "fd7a:115c:a1e0::9"}, Tags: []string{"tag:Prod"}},
		{ID: "d2", Hostname: "alice-laptop", Name: "alice-laptop.tail1234.ts.net.", Addresses: []string{"100.64.0.10"}, User: "alice@example.com"},
		{ID: "d3", Hostname: "bob-laptop", Name: "bob-laptop.tail1234.ts.net.", Addresses: []string{"100.64.0.11"}, User: "bob@example.com"},
	}
}

var fleetAddrs = map[string]string{"d1": "2a04:2a01:1:4::d1", "d2": "2a04:2a01:1:4::d2", "d3": "2a04:2a01:1:4::d3"}

func planFrom(t *testing.T, policy string, devs []TSDevice) *Plan {
	t.Helper()
	pol, lines, err := ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	p, err := BuildPlan(&Tailnet{Name: "example.com", Policy: pol, PolicyLines: lines, Devices: devs},
		BuildOptions{Now: time.Unix(0, 0), CredentialFingerprint: "abcdef012345"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return p
}

// decoded is the built document as a generic value, so assertions read the JSON the
// control plane will read rather than an internal struct.
type decoded struct {
	Groups map[string][]string `json:"groups"`
	Hosts  map[string]string   `json:"hosts"`
	Grants []struct {
		Src, Dst, IP []string
	} `json:"grants"`
	SSH []struct {
		Action          string
		Src, Dst, Users []string
	} `json:"ssh"`
	Tests []struct {
		Src, Accept, Deny []string
	} `json:"tests"`
}

func build(t *testing.T, p *Plan, addrs map[string]string) (*ACLBuild, decoded) {
	t.Helper()
	b, err := BuildMigrationACL(p, addrs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var d decoded
	if err := json.Unmarshal(b.Document, &d); err != nil {
		t.Fatalf("the document is not JSON: %v\n%s", err, b.Document)
	}
	assertEveryNameResolvesByValue(t, d)
	return b, d
}

// assertEveryNameResolvesByValue is the invariant every built document must hold: a bare
// name anywhere in it (a grant, a group member, an ssh rule, a test) is a `hosts` key, so
// the control plane resolves it to a /128 by value and never by a label lookup another
// agent of the same name could answer; and every group it names is defined in it.
func assertEveryNameResolvesByValue(t *testing.T, d decoded) {
	t.Helper()
	check := func(where, tok string) {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "*" || strings.HasPrefix(tok, "tag:") || strings.HasPrefix(tok, "autogroup:"):
		case strings.HasPrefix(tok, "group:"):
			if _, ok := d.Groups[tok]; !ok {
				t.Errorf("%s names %s, which the document does not define", where, tok)
			}
		case strings.Contains(tok, ":"): // a literal /128
		default:
			if _, ok := d.Hosts[tok]; !ok {
				t.Errorf("%s names %q, which is no hosts key: it would resolve by label, not by value", where, tok)
			}
		}
	}
	for g, members := range d.Groups {
		for _, m := range members {
			check("groups["+g+"]", m)
		}
	}
	for i, g := range d.Grants {
		for _, tok := range append(append([]string{}, g.Src...), g.Dst...) {
			check(fmt.Sprintf("grants[%d]", i), tok)
		}
	}
	for i, r := range d.SSH {
		for _, tok := range append(append([]string{}, r.Src...), r.Dst...) {
			check(fmt.Sprintf("ssh[%d]", i), tok)
		}
	}
	for i, tc := range d.Tests {
		for _, tok := range tc.Src {
			check(fmt.Sprintf("tests[%d].src", i), tok)
		}
		for _, tgt := range append(append([]string{}, tc.Accept...), tc.Deny...) {
			for _, pr := range []string{"tcp:", "udp:", "icmp:", "sctp:"} {
				tgt = strings.TrimPrefix(tgt, pr)
			}
			dst, _ := SplitDst(tgt)
			check(fmt.Sprintf("tests[%d] target", i), dst)
		}
	}
}

func droppedContains(b *ACLBuild, sub string) bool {
	for _, d := range b.Dropped {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

func TestMigrationACLCarriesTheFleetInItsOwnNames(t *testing.T) {
	p := planFrom(t, fleetPolicy, fleetDevices())
	b, d := build(t, p, fleetAddrs)

	// The group's USERS became their untagged nodes, named through hosts entries that hold
	// the minted /128s, so the document resolves by value and reads in their names.
	if got := d.Groups["group:eng"]; !reflect.DeepEqual(got, []string{"alice-laptop", "bob-laptop"}) {
		t.Fatalf("group:eng members = %v", got)
	}
	if d.Hosts["alice-laptop"] != "2a04:2a01:1:4::d2" || d.Hosts["bob-laptop"] != "2a04:2a01:1:4::d3" {
		t.Fatalf("node hosts entries wrong: %v", d.Hosts)
	}
	// Their alias pointed at a tailnet address; it now points at that node's /128.
	if d.Hosts["db"] != "2a04:2a01:1:4::d1" {
		t.Fatalf("the alias was not rewritten to the minted /128: %v", d.Hosts)
	}
	for k, v := range d.Hosts {
		if strings.HasPrefix(v, "100.") || strings.HasPrefix(v, "fd7a:") {
			t.Fatalf("a tailnet address survived into hosts[%s] = %s", k, v)
		}
	}
	// The tag is lower case, as the control plane registers it.
	g := d.Grants[0]
	if !reflect.DeepEqual(g.Src, []string{"group:eng"}) || !reflect.DeepEqual(g.Dst, []string{"tag:prod"}) {
		t.Fatalf("grant 0 = %+v", g)
	}
	// No protocol in an `acls` rule means TCP, UDP and ICMP, never every protocol.
	if !reflect.DeepEqual(g.IP, []string{"tcp:443", "udp:443", "icmp"}) {
		t.Fatalf("grant 0 ip = %v", g.IP)
	}
	// Egress is kept as it is today, said in a note, and proven by its own assertion.
	last := d.Grants[len(d.Grants)-1]
	if !reflect.DeepEqual(last.Dst, []string{"autogroup:internet"}) || len(b.Notes) != 1 {
		t.Fatalf("expected the egress-preserving grant and its note: %+v %v", last, b.Notes)
	}
	foundEgressTest := false
	for _, tc := range d.Tests {
		for _, a := range tc.Accept {
			foundEgressTest = foundEgressTest || a == "autogroup:internet:443"
		}
	}
	if !foundEgressTest {
		t.Fatalf("the egress grant has no assertion of its own: %+v", d.Tests)
	}
	// The ssh rule carried, with its users.
	if len(d.SSH) != 1 || !reflect.DeepEqual(d.SSH[0].Dst, []string{"tag:prod"}) ||
		!reflect.DeepEqual(d.SSH[0].Users, []string{"ubuntu", "autogroup:nonroot"}) {
		t.Fatalf("ssh = %+v", d.SSH)
	}
}

func TestTheirDenyAssertionCarriesSoAWideningIsRefusedAtWriteTime(t *testing.T) {
	p := planFrom(t, fleetPolicy, fleetDevices())
	_, d := build(t, p, fleetAddrs)
	var theirs *struct{ Src, Accept, Deny []string }
	for i := range d.Tests {
		if len(d.Tests[i].Deny) > 0 {
			theirs = &d.Tests[i]
		}
	}
	if theirs == nil {
		t.Fatalf("their deny assertion was not carried: %+v", d.Tests)
	}
	// A test with no proto is a TCP question, as in their grammar: asked as "any protocol" it
	// would also match the ICMP that a rule with no protocol rightly admits, and the
	// faithful translation would be refused by their own deny assertion.
	if !reflect.DeepEqual(theirs.Src, []string{"alice-laptop"}) || !reflect.DeepEqual(theirs.Deny, []string{"tcp:tag:prod:22"}) ||
		!reflect.DeepEqual(theirs.Accept, []string{"tcp:tag:prod:443"}) {
		t.Fatalf("their test translated wrongly: %+v", *theirs)
	}
}

func TestATestThatNamesItsProtocolKeepsIt(t *testing.T) {
	policy := `{"acls":[{"action":"accept","src":["*"],"dst":["db-01:53"]}],
	 "tests":[{"src":"alice@example.com","proto":"udp","accept":["db-01:53"]},
	          {"src":"alice@example.com","proto":"gre","accept":["db-01:53"]}]}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	found := false
	for _, tc := range d.Tests {
		for _, a := range tc.Accept {
			found = found || a == "udp:db-01:53"
		}
	}
	if !found {
		t.Fatalf("a udp test lost its protocol: %+v", d.Tests)
	}
	if !droppedContains(b, "tests[1]") {
		t.Fatalf("a test with a protocol we cannot express was not dropped and reported: %v", b.Dropped)
	}
}

// Scope: `*` and the member/tagged autogroups mean the whole TENANT on this
// side, so they must never be written through.
func TestWildcardsAreScopedToThePlanNeverTheTenant(t *testing.T) {
	policy := `{"acls":[
	  {"action":"accept","src":["*"],"dst":["autogroup:member:*"]},
	  {"action":"accept","src":["autogroup:member"],"dst":["autogroup:tagged:22"]}
	]}`
	p := planFrom(t, policy, fleetDevices())
	_, d := build(t, p, fleetAddrs)
	for _, g := range d.Grants[:2] {
		for _, tok := range append(append([]string{}, g.Src...), g.Dst...) {
			if tok == "*" || strings.HasPrefix(tok, "autogroup:member") || strings.HasPrefix(tok, "autogroup:tagged") {
				t.Fatalf("a tenant-wide selector was written through: %+v", g)
			}
		}
	}
	if !reflect.DeepEqual(d.Grants[0].Src, []string{"group:migrated"}) ||
		!reflect.DeepEqual(d.Grants[0].Dst, []string{"group:migrated-members"}) ||
		!reflect.DeepEqual(d.Grants[1].Dst, []string{"group:migrated-tagged"}) {
		t.Fatalf("grants = %+v", d.Grants)
	}
	if !reflect.DeepEqual(d.Groups["group:migrated"], []string{"alice-laptop", "bob-laptop", "db-01"}) ||
		!reflect.DeepEqual(d.Groups["group:migrated-members"], []string{"alice-laptop", "bob-laptop"}) ||
		!reflect.DeepEqual(d.Groups["group:migrated-tagged"], []string{"db-01"}) {
		t.Fatalf("plan-scoped groups = %v", d.Groups)
	}
}

func TestAPlanScopedGroupNeverCollidesWithOneOfTheirs(t *testing.T) {
	policy := `{"groups":{"group:migrated":["alice@example.com"]},
	  "acls":[{"action":"accept","src":["*"],"dst":["group:migrated:22"]}]}`
	p := planFrom(t, policy, fleetDevices())
	_, d := build(t, p, fleetAddrs)
	if !reflect.DeepEqual(d.Groups["group:migrated"], []string{"alice-laptop"}) {
		t.Fatalf("their group:migrated was overwritten: %v", d.Groups)
	}
	if !reflect.DeepEqual(d.Grants[0].Src, []string{"group:migrated-2"}) {
		t.Fatalf("`*` should have used the suffixed name: %+v", d.Grants[0])
	}
}

// Every address kind: a node's tailnet address, a tailnet address of nobody, a tailnet
// range, and addresses outside their tailnet (reachable there only through a subnet router
// or an exit node, neither of which carries).
func TestAddressesAreRewrittenOrDroppedNeverCarriedVerbatim(t *testing.T) {
	policy := `{"hosts":{"web":"100.64.0.10","ghost":"100.64.0.99","office":"10.8.0.0/24","dns":"9.9.9.9"},
	 "acls":[
	  {"action":"accept","src":["100.64.0.10"],"dst":["fd7a:115c:a1e0::9:22"]},
	  {"action":"accept","src":["web"],"dst":["office:443"]},
	  {"action":"accept","src":["web"],"dst":["10.8.0.5:443"]},
	  {"action":"accept","src":["web"],"dst":["ghost:443"]},
	  {"action":"accept","src":["9.9.9.9"],"dst":["db-01:53"]},
	  {"action":"accept","src":["web"],"dst":["100.64.0.0/16:80"]}
	 ]}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	if len(d.Grants) != 2 { // the first rule, plus the egress grant
		t.Fatalf("expected only the node-to-node rule to carry: %+v", d.Grants)
	}
	if !reflect.DeepEqual(d.Grants[0].Src, []string{"alice-laptop"}) || !reflect.DeepEqual(d.Grants[0].Dst, []string{"db-01"}) {
		t.Fatalf("tailnet literals were not rewritten to nodes: %+v", d.Grants[0])
	}
	if _, kept := d.Hosts["office"]; kept {
		t.Fatal("an alias outside their tailnet was kept, which would grant direct egress to it")
	}
	for _, want := range []string{"office", "10.8.0.5", "ghost", "9.9.9.9", "100.64.0.0/16"} {
		if !droppedContains(b, want) {
			t.Errorf("dropping %s was not reported: %v", want, b.Dropped)
		}
	}
	raw := string(b.Document)
	for _, leak := range []string{"100.64.", "fd7a:", "10.8.0", "9.9.9.9"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("%s reached the document: %s", leak, raw)
		}
	}
}

func TestProtocolsAndPortsKeepTheirMeaning(t *testing.T) {
	cases := []struct {
		from, proto, ports string
		want               []string
		err                bool
	}{
		{"acls", "", "22", []string{"tcp:22", "udp:22", "icmp"}, false},
		{"acls", "", "80,443", []string{"tcp:80", "tcp:443", "udp:80", "udp:443", "icmp"}, false},
		{"acls", "tcp", "1000-2000", []string{"tcp:1000-2000"}, false},
		{"acls", "6", "*", []string{"tcp:*"}, false},
		{"acls", "", "*", []string{"tcp:*", "udp:*", "icmp"}, false},
		{"acls", "icmp", "*", []string{"icmp"}, false},
		{"acls", "58", "", []string{"icmp"}, false},
		{"grants", "", "*", []string{"*"}, false},
		{"grants", "", "443", []string{"tcp:443", "udp:443"}, false},
		{"grants", "udp", "53", []string{"udp:53"}, false},
		{"acls", "gre", "*", nil, true},
		{"acls", "47", "*", nil, true},
		{"acls", "tcp", "22-", nil, true},
		{"acls", "tcp", "70000", nil, true},
	}
	for _, c := range cases {
		got, err := ipEntries(c.from, c.proto, c.ports)
		if c.err {
			if err == nil {
				t.Errorf("%s proto %q ports %q: accepted as %v, but dropping that constraint would widen the rule", c.from, c.proto, c.ports, got)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s proto %q ports %q = %v, %v; want %v", c.from, c.proto, c.ports, got, err, c.want)
		}
	}
}

// What cannot carry is NOT carried, and says so: a deny rule, an IdP group, a user with
// no node, an autogroup with no equivalent, a source autogroup:self, and an unknown protocol.
func TestWhatCannotCarryNarrowsAndIsReported(t *testing.T) {
	policy := `{"acls":[
	  {"action":"deny","src":["*"],"dst":["db-01:22"]},
	  {"action":"accept","src":["group:okta-sre"],"dst":["db-01:22"]},
	  {"action":"accept","src":["carol@example.com"],"dst":["db-01:22"]},
	  {"action":"accept","src":["autogroup:admin"],"dst":["db-01:22"]},
	  {"action":"accept","src":["autogroup:self"],"dst":["db-01:22"]},
	  {"action":"accept","proto":"gre","src":["*"],"dst":["db-01:*"]},
	  {"action":"accept","src":["alice@example.com","group:okta-sre"],"dst":["db-01:5432"]}
	 ]}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	// Only the last rule carries, narrowed to alice's node.
	if len(d.Grants) != 2 || !reflect.DeepEqual(d.Grants[0].Src, []string{"alice-laptop"}) {
		t.Fatalf("grants = %+v", d.Grants)
	}
	for _, want := range []string{"deny", "okta-sre", "carol@example.com", "autogroup:admin", "autogroup:self", "gre"} {
		if !droppedContains(b, want) {
			t.Errorf("not carrying %s was not reported: %v", want, b.Dropped)
		}
	}
}

func TestSSHDestinationsAreNodesAndADroppedBlockIsReported(t *testing.T) {
	policy := `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
	 "ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["autogroup:nonroot"]},
	        {"action":"check","src":["group:x"],"dst":["db-01"],"users":["root"]}]}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	if len(d.SSH) != 0 {
		t.Fatalf("an ssh rule with an autogroup destination was carried: %+v", d.SSH)
	}
	if !droppedContains(b, "autogroup:self is not an ssh destination") || !droppedContains(b, "none of their 2 ssh rule(s) carried") {
		t.Fatalf("the dropped ssh block was not reported: %v", b.Dropped)
	}
}

func TestAnInternetRuleOfTheirsIsCarriedAndNoEgressGrantIsAdded(t *testing.T) {
	policy := `{"acls":[{"action":"accept","src":["group:eng"],"dst":["autogroup:internet:443"]}],
	 "groups":{"group:eng":["alice@example.com"]}}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	if len(d.Grants) != 1 || len(b.Notes) != 0 {
		t.Fatalf("their own internet rule should be the only egress grant: %+v %v", d.Grants, b.Notes)
	}
	if !reflect.DeepEqual(d.Grants[0].Dst, []string{"autogroup:internet"}) {
		t.Fatalf("grant = %+v", d.Grants[0])
	}
}

func TestALabelTakenByOneOfTheirAliasesIsWrittenAsTheAddress(t *testing.T) {
	// Their alias "db-01" points at bob's laptop; the node db-01 must not be confused with it.
	policy := `{"hosts":{"db-01":"100.64.0.11"},"acls":[{"action":"accept","src":["db-01.tail1234.ts.net"],"dst":["db-01:22"]}]}`
	p := planFrom(t, policy, fleetDevices())
	_, d := build(t, p, fleetAddrs)
	g := d.Grants[0]
	if !reflect.DeepEqual(g.Src, []string{"2a04:2a01:1:4::d1"}) {
		t.Fatalf("the node db-01 should be named by its /128 because their alias owns the name: %+v", g)
	}
	if !reflect.DeepEqual(g.Dst, []string{"db-01"}) || d.Hosts["db-01"] != "2a04:2a01:1:4::d3" {
		t.Fatalf("their alias db-01 should still mean bob's laptop: %+v %v", g, d.Hosts)
	}
}

func TestTheDocumentIsAPureFunctionOfThePlan(t *testing.T) {
	var first []byte
	for i := 0; i < 20; i++ {
		p := planFrom(t, fleetPolicy, fleetDevices())
		b, err := BuildMigrationACL(p, fleetAddrs)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b.Document
			continue
		}
		if string(b.Document) != string(first) {
			t.Fatalf("run %d produced different bytes:\n%s\n%s", i, first, b.Document)
		}
	}
}

func TestTheBuildRefusesWhatItCannotBuildFaithfully(t *testing.T) {
	p := planFrom(t, fleetPolicy, fleetDevices())

	// A node with no address yet.
	partial := map[string]string{"d1": fleetAddrs["d1"]}
	if _, err := BuildMigrationACL(p, partial); err == nil || !strings.Contains(err.Error(), "alice-laptop") {
		t.Fatalf("a node with no /128 was not named: %v", err)
	}
	// An address that is not an IPv6 /128.
	bad := map[string]string{"d1": "100.64.0.9", "d2": fleetAddrs["d2"], "d3": fleetAddrs["d3"]}
	if _, err := BuildMigrationACL(p, bad); err == nil {
		t.Fatal("a tailnet IPv4 address was accepted as a Whisper /128")
	}
	// A plan from a build that did not record groups, hosts or tests.
	old := *p
	old.Groups, old.Hosts, old.Tests = nil, nil, nil
	_, err := BuildMigrationACL(&old, fleetAddrs)
	if err == nil || !strings.Contains(err.Error(), "group") || !strings.Contains(err.Error(), "hosts") ||
		!strings.Contains(err.Error(), "tests") || !strings.Contains(err.Error(), "Re-run") {
		t.Fatalf("an older plan was not refused with what it lacks: %v", err)
	}
	// Nothing carries at all.
	none := planFrom(t, `{"acls":[{"action":"accept","src":["group:idp-only"],"dst":["db-01:22"]}]}`, fleetDevices())
	b, err := BuildMigrationACL(none, fleetAddrs)
	if !errors.Is(err, ErrNothingToPublish) || b == nil || !droppedContains(b, "idp-only") {
		t.Fatalf("expected ErrNothingToPublish with the reason: %v %+v", err, b)
	}
}

func TestPlanTagsThatCannotBeCarriedAreRefusedBeforeAnyWrite(t *testing.T) {
	devs := fleetDevices()
	devs[1].Tags = []string{"tag:prod"} // db-01 carries tag:Prod; same tag, other case
	p := planFrom(t, `{"acls":[{"action":"accept","src":["tag:prod"],"dst":["tag:Prod:22"]}]}`, devs)
	if err := ValidatePlanTags(p); err == nil || !strings.Contains(err.Error(), "tag:Prod and tag:prod") {
		t.Fatalf("two tags differing only in case were not refused: %v", err)
	}

	devs = fleetDevices()
	devs[0].Tags = []string{"tag:under_score"}
	p = planFrom(t, `{"acls":[]}`, devs)
	if err := ValidatePlanTags(p); err == nil || !strings.Contains(err.Error(), "under_score") {
		t.Fatalf("a malformed tag was not refused: %v", err)
	}

	devs = fleetDevices()
	devs[0].Tags = nil
	for i := 0; i < MaxNodeTags+1; i++ {
		devs[0].Tags = append(devs[0].Tags, "tag:t"+string(rune('a'+i)))
	}
	p = planFrom(t, `{"acls":[]}`, devs)
	if err := ValidatePlanTags(p); err == nil || !strings.Contains(err.Error(), "17 tags") {
		t.Fatalf("too many tags were not refused: %v", err)
	}

	// CONTROL: the ordinary fleet passes, so the refusals above are about their inputs.
	if err := ValidatePlanTags(planFrom(t, fleetPolicy, fleetDevices())); err != nil {
		t.Fatalf("an ordinary plan was refused: %v", err)
	}
	if got := NodeTags(PlanNode{Tags: []string{"tag:Web", "tag:db", "tag:web"}}); !reflect.DeepEqual(got, []string{"tag:db", "tag:web"}) {
		t.Fatalf("NodeTags = %v", got)
	}
}

func TestSameACLDocumentComparesMeaning(t *testing.T) {
	ours := `{"hosts":{"b":"2a04::2","a":"2a04::1"},"grants":[{"src":["a"],"dst":["b"],"ip":["tcp:22"]}]}`
	// The control plane's canonical form: keys sorted at every level, default stated.
	canonical := `{"hosts":{"a":"2a04::1","b":"2a04::2"},"grants":[{"dst":["b"],"ip":["tcp:22"],"src":["a"]}],"default":"deny"}`
	if !SameACLDocument(ours, canonical) {
		t.Fatal("the canonical form of our own document was read as a different document")
	}
	for name, other := range map[string]string{
		"array order is meaning": `{"hosts":{"a":"2a04::1","b":"2a04::2"},"grants":[{"src":["a"],"dst":["b"],"ip":["tcp:22"]}],"tests":[{"src":["a"],"accept":["b:22"]}]}`,
		"default allow":          `{"hosts":{"a":"2a04::1","b":"2a04::2"},"grants":[{"src":["a"],"dst":["b"],"ip":["tcp:22"]}],"default":"allow"}`,
		"another port":           `{"hosts":{"a":"2a04::1","b":"2a04::2"},"grants":[{"src":["a"],"dst":["b"],"ip":["tcp:23"]}]}`,
		"not json":               `{"grants":`,
		"empty":                  ``,
	} {
		if SameACLDocument(ours, other) {
			t.Errorf("%s: two different documents compared equal", name)
		}
	}
}

// An UNDECLARED group of theirs (IdP or SCIM membership) is still their name. A
// plan-scoped group must never take it, or a rule naming theirs is granted every planned
// node, and which rule came first would decide it.
func TestAPlanScopedGroupNeverTakesTheNameOfTheirUndeclaredGroup(t *testing.T) {
	for _, order := range []string{
		`{"acls":[{"action":"accept","src":["*"],"dst":["db-01:22"]},{"action":"accept","src":["group:migrated"],"dst":["db-01:80"]}]}`,
		`{"acls":[{"action":"accept","src":["group:migrated"],"dst":["db-01:80"]},{"action":"accept","src":["*"],"dst":["db-01:22"]}]}`,
	} {
		p := planFrom(t, order, fleetDevices())
		b, d := build(t, p, fleetAddrs)
		for _, g := range d.Grants {
			for _, ip := range g.IP {
				if strings.Contains(ip, ":80") {
					t.Fatalf("their undeclared group:migrated was granted through ours: %+v\n%s", g, b.Document)
				}
			}
		}
		if _, taken := d.Groups["group:migrated"]; taken {
			t.Fatalf("the plan-scoped group took their name group:migrated: %v", d.Groups)
		}
		if !droppedContains(b, "group:migrated is not carried") {
			t.Fatalf("their undeclared group was not reported as dropped: %v", b.Dropped)
		}
	}
}

func TestTagCaseIsCheckedInEverySelectorNotOnlyRules(t *testing.T) {
	devs := fleetDevices()
	devs[0].Tags = []string{"tag:web"}
	for name, policy := range map[string]string{
		"ssh":    `{"acls":[],"ssh":[{"action":"accept","src":["*"],"dst":["tag:Web"],"users":["root"]}]}`,
		"tests":  `{"acls":[],"tests":[{"src":"alice@example.com","accept":["tag:Web:443"]}]}`,
		"groups": `{"acls":[],"groups":{"group:g":["tag:Web"]}}`,
	} {
		if err := ValidatePlanTags(planFrom(t, policy, devs)); err == nil || !strings.Contains(err.Error(), "tag:Web and tag:web") {
			t.Errorf("%s: a tag differing only in case was not refused: %v", name, err)
		}
	}
}

func TestANumericProtocolInTheirTestsIsHonoured(t *testing.T) {
	policy := `{"acls":[{"action":"accept","proto":"udp","src":["*"],"dst":["db-01:53"]}],
	 "tests":[{"src":"alice@example.com","proto":17,"accept":["db-01:53"]},
	          {"src":"alice@example.com","proto":47,"accept":["db-01:53"]}]}`
	p := planFrom(t, policy, fleetDevices())
	b, d := build(t, p, fleetAddrs)
	found := false
	for _, tc := range d.Tests {
		for _, a := range tc.Accept {
			found = found || a == "udp:db-01:53"
			if a == "tcp:db-01:53" {
				t.Fatalf("a numeric proto was silently read as tcp: %+v", d.Tests)
			}
		}
	}
	if !found || !droppedContains(b, "tests[1]") {
		t.Fatalf("proto 17 should be udp and proto 47 dropped and reported: %+v %v", d.Tests, b.Dropped)
	}
}

func TestSelfDestinationsAndGroupCyclesBuildCleanly(t *testing.T) {
	policy := `{"groups":{"group:a":["group:b","alice@example.com"],"group:b":["group:a"]},
	 "acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:22"]},
	         {"action":"accept","src":["group:a"],"dst":["db-01:443"]}]}`
	p := planFrom(t, policy, fleetDevices())
	_, d := build(t, p, fleetAddrs)
	if !reflect.DeepEqual(d.Grants[0].Dst, []string{"autogroup:self"}) {
		t.Fatalf("an autogroup:self destination did not carry: %+v", d.Grants[0])
	}
	if !reflect.DeepEqual(d.Groups["group:a"], []string{"alice-laptop"}) {
		t.Fatalf("a group cycle did not resolve to its real members: %v", d.Groups)
	}
}
