// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// A node another of the account's agents registered sees only its own part of the account in its
// roster, so the governed view names the zones its sources sit in. These tests pin how install
// carries those zones into the fleets file, and how check refuses that wider file unless the ACL
// file beside it is the very view it was written for.

const (
	nestedZone = "t000000000000000000000000000000cc.agents.whisper.online"
	nestedName = "ops-01." + nestedZone
	otherHash  = "sha256:00000000000000000000000000000000000000000000000000000000000000bb"
)

func nestedEntry() whale.SSHACLEntry {
	return whale.SSHACLEntry{Names: []string{nestedName}, Addr: netip.MustParseAddr(authzSourceB), Users: []string{"deploy"}}
}

func readText(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAGovernedViewWidensTheFleetsFileWithItsSourcesZonesAndBindsItToTheView(t *testing.T) {
	run, _, fleets, _ := installWithACL(t)
	v := okView(nestedEntry())
	// one zone a listed source sits in, one no listed source sits in, and a domain of the account's own
	v.Fleets = []string{nestedZone, "t000000000000000000000000000000dd.agents.whisper.online", "agents.example.com"}
	stubACLView(t, aclTestNode, &viewStub{view: v})
	out, stderr, err := run()
	if err != nil {
		t.Fatal(err)
	}
	text := readText(t, fleets)
	if !strings.Contains(text, "\n"+nestedZone+"\n") {
		t.Fatalf("the source's zone is missing:\n%s", text)
	}
	if !strings.Contains(text, "\n"+sshAuthzFleetsBinding+aclTestHash+"\n") {
		t.Fatalf("the widened file is not bound to the view:\n%s", text)
	}
	if strings.Contains(text, "000dd.") || strings.Contains(text, "example.com") {
		t.Fatalf("a zone no listed source sits in, or a domain of the account's own, became a fleet:\n%s", text)
	}
	lines, bound, err := readSSHAuthzFleets(fleets)
	if err != nil || bound != aclTestHash || len(lines) < 2 {
		t.Fatalf("check cannot read what install wrote: %v %q %v", lines, bound, err)
	}
	if !strings.Contains(out, "the ssh view admits sources from") || !strings.Contains(stderr, "beyond your roster") {
		t.Fatalf("install did not say it widened the fleets:\n%s\n%s", out, stderr)
	}
}

func TestAViewWhoseSourcesAreAllInTheRosterLeavesTheFleetsFileUnbound(t *testing.T) {
	run, _, fleets, _ := installWithACL(t)
	v := okView(admitFixture("deploy"))
	v.Fleets = []string{"tfleet.agents.whisper.online"} // not a hosted tenant zone, and the roster's own
	stubACLView(t, aclTestNode, &viewStub{view: v})
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	if text := readText(t, fleets); strings.Contains(text, sshAuthzFleetsBinding) {
		t.Fatalf("nothing was widened, so nothing should be bound:\n%s", text)
	}
}

func TestAnUngovernedViewNeverWidensTheFleetsFile(t *testing.T) {
	run, _, fleets, _ := installWithACL(t)
	v := sshAuthzView{State: "no_ssh_block", Node: aclTestNode, ACLHash: aclTestHash, ArtifactHash: aclTestHash,
		Fleets: []string{nestedZone}}
	stubACLView(t, aclTestNode, &viewStub{view: v})
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	if text := readText(t, fleets); strings.Contains(text, nestedZone) || strings.Contains(text, sshAuthzFleetsBinding) {
		t.Fatalf("an ungoverned view widened the fleets:\n%s", text)
	}
}

func TestAnOrphanedNodeIsWrittenGovernedWithNobodyAdmitted(t *testing.T) {
	run, _, _, acl := installWithACL(t)
	v := sshAuthzView{State: "orphaned", Governed: true, Node: aclTestNode, Declared: 0}
	stubACLView(t, aclTestNode, &viewStub{view: v})
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	a, present, err := loadSSHAuthzACL(acl)
	if err != nil || !present || !a.Governed || len(a.Entries) != 0 {
		t.Fatalf("orphaned must govern and admit nobody: %+v %v %v", a, present, err)
	}
}

func TestAnOrphanedViewThatStillSendsSourcesIsKeptNotWritten(t *testing.T) {
	run, _, _, acl := installWithACL(t)
	v := sshAuthzView{State: "orphaned", Governed: true, Node: aclTestNode, Entries: []whale.SSHACLEntry{admitFixture("deploy")}}
	stubACLView(t, aclTestNode, &viewStub{view: v})
	if _, _, err := run(); err != nil {
		t.Fatal(err) // no file yet: the node stays flags-only and says so
	}
	if _, present, _ := loadSSHAuthzACL(acl); present {
		t.Fatal("a self-contradicting view was written")
	}
}

func TestTheRetiredNestedNodeStateIsStillKept(t *testing.T) {
	run, _, _, acl := installWithACL(t)
	stubACLView(t, aclTestNode, &viewStub{view: sshAuthzView{State: "nested_node", Node: aclTestNode}})
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	if _, present, _ := loadSSHAuthzACL(acl); present {
		t.Fatal("nested_node was written")
	}
}

// boundFleets writes a fleets file widened for view hash.
func boundFleets(t *testing.T, hash string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "whisper-ssh-authz.fleets")
	body := "tfleet.agents.whisper.online\n" + nestedZone + "\n" + sshAuthzFleetsBinding + hash + "\n"
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckRefusesABoundFleetsFileBesideAnotherViewOrNoView(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	fleets := boundFleets(t, otherHash)

	// the ACL file is a governed view that admits the caller, but not the view the fleets were widened for
	acl := aclFile(t, true, admitFixture("deploy"))
	if out := checkAs(t, "deploy", typ, b64, "--fleet-file", fleets, "--acl-file", acl); out != "" {
		t.Fatalf("admitted: %q", out)
	}
	if e := lastLog(t, logged); e.admit || !strings.Contains(e.line, "acl: the fleets file was written for ssh view "+otherHash) {
		t.Fatalf("log = %+v", e)
	}

	// no ACL file at all
	missing := filepath.Join(t.TempDir(), sshAuthzACLName)
	if out := checkAs(t, "deploy", typ, b64, "--fleet-file", fleets, "--acl-file", missing); out != "" {
		t.Fatalf("admitted with no ACL file: %q", out)
	}

	// an ungoverned ACL file
	if out := checkAs(t, "deploy", typ, b64, "--fleet-file", fleets, "--acl-file", aclFile(t, false)); out != "" {
		t.Fatalf("admitted beside an ungoverned view: %q", out)
	}
}

func TestCheckAdmitsThroughABoundFleetsFileBesideItsOwnView(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	stubAuthz(t, z)
	trustTempFiles(t)
	fleets := boundFleets(t, aclTestHash)
	acl := aclFile(t, true, admitFixture("deploy"))
	if out := checkAs(t, "deploy", typ, b64, "--fleet-file", fleets, "--acl-file", acl); out != typ+" "+b64+" whisper:"+authzNameBare+"\n" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestTheFleetsBindingLineParsesStrictly(t *testing.T) {
	for name, body := range map[string]string{
		"two bindings": "tfleet.agents.whisper.online\n" + sshAuthzFleetsBinding + aclTestHash + "\n" + sshAuthzFleetsBinding + otherHash + "\n",
		"not a hash":   "tfleet.agents.whisper.online\n" + sshAuthzFleetsBinding + "nope\n",
		"only a bind":  sshAuthzFleetsBinding + aclTestHash + "\n",
	} {
		if _, _, err := parseSSHAuthzFleets("f", []byte(body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	lines, bound, err := parseSSHAuthzFleets("f", []byte("tfleet.agents.whisper.online # a comment\n"))
	if err != nil || bound != "" || len(lines) != 1 {
		t.Fatalf("an unbound file: %v %q %v", lines, bound, err)
	}
}

// A refresh the control plane cannot answer keeps BOTH files when an ACL file is there: the
// install refuses before the fleets file is touched, so a widened, bound fleets file is never
// rewritten from the roster alone beside a kept view.
func TestAKeptViewKeepsABoundFleetsFileToo(t *testing.T) {
	run, _, fleets, _ := installWithACL(t)
	v := okView(nestedEntry())
	v.Fleets = []string{nestedZone}
	stub := &viewStub{view: v}
	stubACLView(t, aclTestNode, stub)
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	before := readText(t, fleets)
	if !strings.Contains(before, sshAuthzFleetsBinding) {
		t.Fatalf("setup: the fleets file was not widened:\n%s", before)
	}
	stub.view = sshAuthzView{State: "not_compiled_here", Node: aclTestNode}
	if _, _, err := run(); err == nil {
		t.Fatal("a refresh that cannot read the view must refuse while an ACL file is there")
	}
	if after := readText(t, fleets); after != before {
		t.Fatalf("the bound fleets file was rewritten beside a kept view:\n%s\n---\n%s", before, after)
	}
}
