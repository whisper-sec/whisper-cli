// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// The fixtures use unassigned space and invented tenants, never a live identity.
const (
	aclNode = "2a04:2a01:9::d1"
	aclSrc  = "2a04:2a01:9::e1"
	aclName = "ops-01.tfleet.agents.whisper.online"
	aclHash = "sha256:00000000000000000000000000000000000000000000000000000000000000aa"
)

func governedView() SSHACL {
	return SSHACL{
		Node: netip.MustParseAddr(aclNode), Governed: true, ACLHash: aclHash, ArtifactHash: aclHash,
		Entries: []SSHACLEntry{{
			Names: []string{"a1.tfleet.agents.whisper.online", aclName},
			Addr:  netip.MustParseAddr(aclSrc),
			Users: []string{"deploy", "root"},
		}},
	}
}

func TestSSHACLRoundTripsByteForByte(t *testing.T) {
	text := governedView().Format()
	got, err := ParseSSHACL([]byte(text))
	if err != nil {
		t.Fatalf("parse what Format wrote: %v\n%s", err, text)
	}
	if again := got.Format(); again != text {
		t.Fatalf("the same view wrote different bytes:\n%s\n---\n%s", text, again)
	}
	if !got.Governed || len(got.Entries) != 1 || got.Node != netip.MustParseAddr(aclNode) {
		t.Fatalf("parsed %+v", got)
	}
}

func TestSSHACLToleratesABomCrlfCommentsAndBlankLines(t *testing.T) {
	text := "\ufeff# a comment\r\n\r\n" + strings.ReplaceAll(governedView().Format(), "\n", "\r\n")
	if _, err := ParseSSHACL([]byte(text)); err != nil {
		t.Fatal(err)
	}
}

func TestSSHACLRefusesEveryMalformedFile(t *testing.T) {
	ok := governedView().Format()
	header := SSHACLHeader + "\nnode " + aclNode + "\n"
	cases := map[string]string{
		"empty":                     "",
		"no header":                 strings.Replace(ok, SSHACLHeader+"\n", "", 1),
		"another version":           strings.Replace(ok, SSHACLHeader, "whisper-ssh-acl 2", 1),
		"unknown keyword":           ok + "permit everyone\n",
		"two node lines":            ok + "node " + aclSrc + "\n",
		"no node":                   SSHACLHeader + "\ngoverned no\n",
		"no governed line":          header,
		"governed maybe":            header + "governed maybe\n",
		"two governed lines":        header + "governed no\ngoverned no\n",
		"admit while not governed":  header + "governed no\nadmit " + aclName + " " + aclSrc + " root\n",
		"a hash that is not sha256": header + "governed no\nacl_hash md5:abc\n",
		"a hash twice":              header + "governed no\nacl_hash " + aclHash + "\nacl_hash " + aclHash + "\n",
		"a bad name":                header + "governed yes\nadmit ops_01!.example " + aclSrc + " root\n",
		"a bare label":              header + "governed yes\nadmit ops-01 " + aclSrc + " root\n",
		"a bad address":             header + "governed yes\nadmit " + aclName + " 2a04:zz::1 root\n",
		"a zoned address":           header + "governed yes\nadmit " + aclName + " fe80::1%eth0 root\n",
		"an upper-case user":        header + "governed yes\nadmit " + aclName + " " + aclSrc + " Root\n",
		"a flag-shaped user":        header + "governed yes\nadmit " + aclName + " " + aclSrc + " -oProxy\n",
		"another autogroup":         header + "governed yes\nadmit " + aclName + " " + aclSrc + " autogroup:self\n",
		"too few fields":            header + "governed yes\nadmit " + aclName + " " + aclSrc + "\n",
		"too many fields":           header + "governed yes\nadmit " + aclName + " " + aclSrc + " root extra\n",
		"an address twice":          header + "governed yes\nadmit " + aclName + " " + aclSrc + " root\nadmit x.tfleet.agents.whisper.online " + aclSrc + " root\n",
	}
	for name, text := range cases {
		if _, err := ParseSSHACL([]byte(text)); err == nil {
			t.Errorf("%s: parsed, want a refusal:\n%s", name, text)
		}
	}
}

func TestSSHACLRefusesMoreAdmitLinesThanAViewHolds(t *testing.T) {
	var b strings.Builder
	b.WriteString(SSHACLHeader + "\nnode " + aclNode + "\ngoverned yes\n")
	for i := 0; i <= SSHACLMaxEntries; i++ {
		fmt.Fprintf(&b, "admit n%d.tfleet.agents.whisper.online 2a04:2a01:9::%x root\n", i, i+1)
	}
	if _, err := ParseSSHACL([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "admit lines") {
		t.Fatalf("err = %v", err)
	}
}

func TestSSHACLAdmitsOnlyTheListedNameAddressAndAccount(t *testing.T) {
	v := governedView()
	src := netip.MustParseAddr(aclSrc)
	if ok, why := v.Admits(aclName+".", src, "root"); !ok {
		t.Fatalf("listed name (with a trailing dot), address and account: %s", why)
	}
	if ok, _ := v.Admits(strings.ToUpper(aclName), src, "deploy"); !ok {
		t.Fatal("a name is compared without case")
	}
	if ok, why := v.Admits(aclName, src, "postgres"); ok || !strings.Contains(why, "as postgres") || !strings.Contains(why, "deploy, root") {
		t.Fatalf("an account no rule names: %v %s", ok, why)
	}
	if ok, why := v.Admits("db-09.tother.agents.whisper.online", src, "root"); ok || !strings.Contains(why, "someone else's") {
		t.Fatalf("an address re-held by another agent must not inherit the line: %v %s", ok, why)
	}
	if ok, _ := v.Admits(aclName, netip.MustParseAddr("2a04:2a01:9::e9"), "root"); ok {
		t.Fatal("an address no line names")
	}
	if !v.ListsAddr(src) || v.ListsAddr(netip.MustParseAddr("2a04:2a01:9::e9")) {
		t.Fatal("ListsAddr")
	}
}

func TestSSHACLNonrootIsEveryAccountButRootByAnyName(t *testing.T) {
	saved := UID0
	UID0 = func(name string) (bool, bool) { return name == "toor", true }
	t.Cleanup(func() { UID0 = saved })
	v := governedView()
	v.Entries[0].Users = []string{SSHACLNonroot}
	src := netip.MustParseAddr(aclSrc)
	if ok, _ := v.Admits(aclName, src, "deploy"); !ok {
		t.Fatal("nonroot admits an ordinary account")
	}
	if ok, _ := v.Admits(aclName, src, "root"); ok {
		t.Fatal("nonroot admitted root")
	}
	if ok, _ := v.Admits(aclName, src, "toor"); ok {
		t.Fatal("nonroot admitted a uid-0 alias")
	}
}

func TestAnUngovernedViewLeavesTheDecisionToTheFlags(t *testing.T) {
	v := SSHACL{Node: netip.MustParseAddr(aclNode)}
	if ok, _ := v.Admits("anything.example.com", netip.MustParseAddr(aclSrc), "root"); !ok {
		t.Fatal("an ungoverned view must not narrow anything")
	}
}

func TestTheSummaryCarriesTheSshStateAndALoginDenialIsADenial(t *testing.T) {
	s := ACLSummaryFrom([][2]string{{"whale.acl.hash", aclHash}, {"whale.acl.ssh", "enforced"}})
	if s.SSH != "enforced" {
		t.Fatalf("ssh = %q", s.SSH)
	}
	if (ACLTestVerdict{Verdict: "allow", SSH: "admit"}).Denied() {
		t.Fatal("an open port and an admitted login is not a denial")
	}
	if !(ACLTestVerdict{Verdict: "allow", SSH: "deny"}).Denied() {
		t.Fatal("an open port with no ssh rule for the account refuses the login")
	}
	if (ACLTestVerdict{Verdict: "allow", SSH: "ungoverned"}).Denied() {
		t.Fatal("ungoverned is not a refusal: the target's flags decide")
	}
}
