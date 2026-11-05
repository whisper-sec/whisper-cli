// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// Every test in this package runs as a keyless host with no ACL file, unless it says
// otherwise: the default path points at a directory that never exists, and this host has
// neither a Whisper address nor a control-plane view. No test can read the real
// /etc/ssh/whisper-ssh-authz.acl of the machine it runs on.
func init() {
	sshAuthzACLDefault = filepath.Join(os.TempDir(), "whisper-cli-test-no-acl-"+strconv.Itoa(os.Getpid()), sshAuthzACLName)
	sshAuthzSelfAddr = func(context.Context) (netip.Addr, error) {
		return netip.Addr{}, errors.New("this host has no Whisper address it can name")
	}
	sshAuthzACLView = func(context.Context, string) (sshAuthzView, error) {
		return sshAuthzView{}, errors.New("no key in effect on this host")
	}
}

const (
	aclTestNode = "2a04:2a01:9::d1"
	aclTestHash = "sha256:00000000000000000000000000000000000000000000000000000000000000aa"
)

var authzNameBare = strings.TrimSuffix(authzName, ".")

func aclFile(t *testing.T, governed bool, entries ...whale.SSHACLEntry) string {
	t.Helper()
	a := whale.SSHACL{Node: netip.MustParseAddr(aclTestNode), Governed: governed, ACLHash: aclTestHash, ArtifactHash: aclTestHash,
		Entries: entries}
	return writeACLText(t, a.Format())
}

func writeACLText(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), sshAuthzACLName)
	if err := os.WriteFile(p, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func admitFixture(users ...string) whale.SSHACLEntry {
	return whale.SSHACLEntry{Names: []string{authzNameBare}, Addr: netip.MustParseAddr(authzSource), Users: users}
}

// checkAs runs check for the fixture agent as user, with the ACL file at acl.
func checkAs(t *testing.T, user, typ, b64 string, flags ...string) string {
	t.Helper()
	args := append(append([]string{"check", "--fleet", "tfleet"}, flags...), "--", user, typ, b64, authzSource, "50022", authzSelf, "22")
	out, _, err := runAuthz(t, args...)
	if err != nil {
		t.Fatalf("check %v: %v", flags, err)
	}
	return out
}

func lastLog(t *testing.T, logged *[]authzLogEntry) authzLogEntry {
	t.Helper()
	if len(*logged) == 0 {
		t.Fatal("nothing reached the auth log")
	}
	return (*logged)[len(*logged)-1]
}

// --- check ------------------------------------------------------------------------------

func TestCheckAdmitsALoginTheACLListsAndSaysBothHalvesAgreed(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	acl := aclFile(t, true, admitFixture("deploy"))
	out := checkAs(t, "deploy", typ, b64, "--acl-file", acl)
	if out != typ+" "+b64+" whisper:"+authzNameBare+"\n" {
		t.Fatalf("stdout = %q", out)
	}
	if e := lastLog(t, logged); !e.admit || !strings.Contains(e.line, "an ACL ssh rule admits "+authzNameBare+" as deploy") {
		t.Fatalf("log = %+v", e)
	}
}

func TestCheckDeniesAnAccountNoSshRuleGrantsAndSaysTheACLRefused(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	acl := aclFile(t, true, admitFixture("postgres"))
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", acl); out != "" {
		t.Fatalf("printed %q for an account no rule grants", out)
	}
	e := lastLog(t, logged)
	if e.admit || !strings.Contains(e.line, ": acl: no ssh rule admits "+authzNameBare+" as deploy") {
		t.Fatalf("log = %+v", e)
	}
}

// countingLookup fails the test if the decision asks it anything.
type countingLookup struct{ n *int }

func (c countingLookup) Validated(context.Context, string, uint16) ([]dns.RR, *dns.RRSIG, error) {
	*c.n++
	return nil, nil, errors.New("asked")
}

func TestCheckRefusesACallerTheACLDoesNotListBeforeWalkingAnyChain(t *testing.T) {
	_, typ, b64 := authzFixture(t)
	asked := 0
	logged := stubAuthz(t, countingLookup{&asked})
	trustTempFiles(t)
	other := whale.SSHACLEntry{Names: []string{"x.tfleet.agents.whisper.online"}, Addr: netip.MustParseAddr("2a04:2a01:9::e9"), Users: []string{"deploy"}}
	acl := aclFile(t, true, other)
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", acl); out != "" {
		t.Fatalf("printed %q", out)
	}
	if asked != 0 {
		t.Fatalf("a caller the view does not list made this host ask %d DNSSEC question(s)", asked)
	}
	if e := lastLog(t, logged); !strings.Contains(e.line, "acl: no ssh rule admits "+authzSource) {
		t.Fatalf("log = %+v", e)
	}
}

func TestCheckRefusesAnAddressTheACLListsForAnotherName(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	reheld := whale.SSHACLEntry{Names: []string{"old-01.tfleet.agents.whisper.online"}, Addr: netip.MustParseAddr(authzSource), Users: []string{"deploy"}}
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", aclFile(t, true, reheld)); out != "" {
		t.Fatalf("an address re-held by another agent inherited the old holder's line: %q", out)
	}
	if e := lastLog(t, logged); !strings.Contains(e.line, "acl: the ACL lists") {
		t.Fatalf("log = %+v", e)
	}
}

func TestCheckDeniesOnAnACLFileItCannotReadOrTrust(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	for name, text := range map[string]string{
		"malformed":         "whisper-ssh-acl 1\nnode " + aclTestNode + "\ngoverned perhaps\n",
		"not ours":          "# something else\nadmit everyone\n",
		"truncated":         "whisper-ssh-acl 1\nnode " + aclTestNode + "\n",
		"admit, ungoverned": "whisper-ssh-acl 1\nnode " + aclTestNode + "\ngoverned no\nadmit " + authzNameBare + " " + authzSource + " deploy\n",
	} {
		if out := checkAs(t, "deploy", typ, b64, "--acl-file", writeACLText(t, text)); out != "" {
			t.Fatalf("%s: a file the operator turned on and check cannot read admitted %q", name, out)
		}
		if e := lastLog(t, logged); e.admit || !strings.Contains(e.line, ": acl: ") {
			t.Fatalf("%s: log = %+v", name, e)
		}
	}
	// A file check cannot trust (not root's, or writable by others) refuses just the same.
	sshAuthzPathUnsafe = func(string) string { return "it is not owned by root" }
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", aclFile(t, true, admitFixture("deploy"))); out != "" {
		t.Fatalf("an untrusted file admitted %q", out)
	}
	if e := lastLog(t, logged); !strings.Contains(e.line, "acl: ") || !strings.Contains(e.line, "cannot be trusted") {
		t.Fatalf("log = %+v", e)
	}
}

func TestNoACLFileOrAnUngovernedOneLeavesTheFlagsDecisionAsItWas(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	stubAuthz(t, z)
	trustTempFiles(t)
	want := typ + " " + b64 + " whisper:" + authzNameBare + "\n"
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", filepath.Join(t.TempDir(), "absent")); out != want {
		t.Fatalf("no file: stdout = %q", out)
	}
	if out := checkAs(t, "deploy", typ, b64, "--acl-file", aclFile(t, false)); out != want {
		t.Fatalf("an ungoverned file: stdout = %q", out)
	}
}

// The ACL can only narrow: a rule granting root does not override the flags' refusal of
// root, and the log says the flags refused, so the operator knows where to look.
func TestAFlagsDenialSaysItWasTheFlagsEvenWhenTheACLWouldAdmit(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	acl := aclFile(t, true, admitFixture("root"))
	if out := checkAs(t, "root", typ, b64, "--acl-file", acl); out != "" {
		t.Fatalf("root was admitted without --user root: %q", out)
	}
	if e := lastLog(t, logged); !strings.Contains(e.line, ": flags: root is never a fleet login") {
		t.Fatalf("log = %+v", e)
	}
	if out := checkAs(t, "root", typ, b64, "--acl-file", acl, "--user", "root"); out == "" {
		t.Fatal("with --user root and an ACL rule for root, the login is admitted")
	}
}

func TestCheckFindsTheACLFileBesideTheFleetsFile(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	dir := t.TempDir()
	fleets := filepath.Join(dir, "fleets")
	if err := os.WriteFile(fleets, []byte("tfleet\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	a := whale.SSHACL{Node: netip.MustParseAddr(aclTestNode), Governed: true, Entries: []whale.SSHACLEntry{admitFixture("postgres")}}
	if err := os.WriteFile(filepath.Join(dir, sshAuthzACLName), []byte(a.Format()), 0o640); err != nil {
		t.Fatal(err)
	}
	out, _, err := runAuthz(t, "check", "--fleet-file", fleets, "--", "deploy", typ, b64, authzSource, "50022", authzSelf, "22")
	if err != nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if e := lastLog(t, logged); !strings.Contains(e.line, "acl: no ssh rule admits") {
		t.Fatalf("the file beside the fleets file was not read: %+v", e)
	}
}

func TestTheDryRunAppliesTheACLToo(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	stubAuthz(t, z)
	trustTempFiles(t)
	acl := aclFile(t, true, admitFixture("postgres"))
	out, stderr, err := runAuthz(t, "check", "--fleet", "tfleet", "--acl-file", acl, "--from", authzSource, "--", "deploy", typ, b64)
	if err != nil || out != "" || !strings.HasPrefix(stderr, "DENY ") || !strings.Contains(stderr, "acl: ") {
		t.Fatalf("out=%q stderr=%q err=%v", out, stderr, err)
	}
}

// --- install ----------------------------------------------------------------------------

type viewStub struct {
	view sshAuthzView
	err  error
	asks int
}

func stubACLView(t *testing.T, self string, v *viewStub) {
	t.Helper()
	savedS, savedV := sshAuthzSelfAddr, sshAuthzACLView
	sshAuthzSelfAddr = func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(self), nil }
	sshAuthzACLView = func(_ context.Context, node string) (sshAuthzView, error) {
		v.asks++
		if node != self {
			t.Errorf("install asked for the view of %q, not of this node %q", node, self)
		}
		return v.view, v.err
	}
	t.Cleanup(func() { sshAuthzSelfAddr, sshAuthzACLView = savedS, savedV })
}

func okView(entries ...whale.SSHACLEntry) sshAuthzView {
	return sshAuthzView{State: "ok", Governed: true, Node: aclTestNode, ACLHash: aclTestHash, ArtifactHash: aclTestHash, Entries: entries}
}

// installWithACL is one root install --write over a temp layout; it returns the paths.
func installWithACL(t *testing.T) (run func() (string, string, error), snippet, fleets, acl string) {
	t.Helper()
	bin := rootOwnedBinary(t)
	snippet, fleets = installLayout(t)
	acl = filepath.Join(filepath.Dir(fleets), sshAuthzACLName)
	stubInstall(t, 0, bin, func(string) (string, error) { return effectiveOf(t, snippet), nil })
	stubRoster(t, roster())
	trustTempFiles(t)
	run = func() (string, string, error) {
		return runAuthz(t, "install", "--write", "--path", snippet, "--fleet-file", fleets)
	}
	return run, snippet, fleets, acl
}

func TestInstallWritesTheGovernedViewBesideTheFleetsFileAndPrintsTheTransition(t *testing.T) {
	run, snippet, _, acl := installWithACL(t)
	v := &viewStub{view: okView(admitFixture("deploy", "root"))}
	stubACLView(t, aclTestNode, v)
	out, stderr, err := run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "wrote "+acl+"\n") {
		t.Fatalf("out = %s", out)
	}
	if !strings.Contains(stderr, "ssh ACL: flags-only -> governed by the WhaleACL, 1 source(s) may log in here") {
		t.Fatalf("the transition was not printed: %s", stderr)
	}
	a, present, rerr := loadSSHAuthzACL(acl)
	if rerr != nil || !present || !a.Governed || len(a.Entries) != 1 || a.ArtifactHash != aclTestHash {
		t.Fatalf("check cannot read what install wrote: %+v %v %v", a, present, rerr)
	}
	if fi, _ := os.Stat(acl); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	if b, _ := os.ReadFile(snippet); strings.Contains(string(b), "--acl-file") {
		t.Fatalf("the default place needs no flag in the snippet: %s", b)
	}
	first, _ := os.ReadFile(acl)
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(acl); string(again) != string(first) {
		t.Fatalf("the same view wrote different bytes:\n%s\n---\n%s", first, again)
	}
}

func TestARefreshThatCannotReadTheViewKeepsTheACLFileAndChangesNothing(t *testing.T) {
	run, _, fleets, acl := installWithACL(t)
	v := &viewStub{view: okView(admitFixture("deploy"))}
	stubACLView(t, aclTestNode, v)
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(acl)
	fleetsBefore, _ := os.ReadFile(fleets)
	for name, stub := range map[string]viewStub{
		"a network error":     {err: errors.New("connection refused")},
		"not compiled here":   {view: sshAuthzView{State: "not_compiled_here", Node: aclTestNode, Note: "retry"}},
		"invalid stored":      {view: sshAuthzView{State: "invalid_stored", Node: aclTestNode, Note: "ssh[0].action"}},
		"a state not known":   {view: sshAuthzView{State: "rebuilding", Node: aclTestNode}},
		"ok but not governed": {view: sshAuthzView{State: "ok", Node: aclTestNode}},
		"another node":        {view: okView(admitFixture("deploy"), admitFixture("root")), err: nil},
		"an older plane":      {err: &client.ProblemError{Status: 400, Detail: "view must be one of nodes|peers|acltest for kind:'whale'"}},
		"owner not named":     {view: sshAuthzView{State: "owner_not_named"}},
		"a nested node":       {view: sshAuthzView{State: "nested_node"}},
		"store unavailable":   {view: sshAuthzView{State: "store_unavailable", Node: aclTestNode}},
		"unreadable":          {view: sshAuthzView{State: "unreadable", Node: aclTestNode}},
	} {
		s := stub
		if name == "another node" {
			s.view.Node = "2a04:2a01:9::d2"
		}
		*v = s
		_, _, err := run()
		if err == nil || !strings.Contains(err.Error(), "left as it is") {
			t.Fatalf("%s: err = %v", name, err)
		}
		if after, _ := os.ReadFile(acl); string(after) != string(before) {
			t.Fatalf("%s: a transient state replaced a governed file:\n%s", name, after)
		}
		if after, _ := os.ReadFile(fleets); string(after) != string(fleetsBefore) {
			t.Fatalf("%s: the refused refresh still rewrote the fleets file", name)
		}
	}
}

func TestWithNoFileAnUnreadableViewLeavesTheNodeFlagsOnlyAndSaysSo(t *testing.T) {
	run, _, _, acl := installWithACL(t)
	stubACLView(t, aclTestNode, &viewStub{err: &client.ProblemError{Status: 400, Detail: "view must be one of nodes|peers|acltest"}})
	_, stderr, err := run()
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Lstat(acl); serr == nil {
		t.Fatal("an older control plane produced an ACL file")
	}
	if !strings.Contains(stderr, "does not serve the compiled ssh view yet") || !strings.Contains(stderr, "stays flags-only") {
		t.Fatalf("stderr = %s", stderr)
	}
}

func TestADocumentWithoutAnSshBlockTurnsAGovernedNodeBackToFlagsOnlyAndSaysSo(t *testing.T) {
	run, _, _, acl := installWithACL(t)
	v := &viewStub{view: okView(admitFixture("deploy"))}
	stubACLView(t, aclTestNode, v)
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	v.view = sshAuthzView{State: "no_ssh_block", Node: aclTestNode, ACLHash: aclTestHash, ArtifactHash: aclTestHash}
	_, stderr, err := run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "ssh ACL: governed, 1 source(s) -> flags-only") {
		t.Fatalf("stderr = %s", stderr)
	}
	if a, _, _ := loadSSHAuthzACL(acl); a.Governed {
		t.Fatal("the file still says governed")
	}
	v.view = sshAuthzView{State: "no_document", Node: aclTestNode}
	if _, _, err := run(); err != nil {
		t.Fatalf("no document at all writes an ungoverned file too: %v", err)
	}
}

func TestARefreshListsWhoCameAndWentAndWarnsWhenNobodyIsLeft(t *testing.T) {
	run, _, _, _ := installWithACL(t)
	v := &viewStub{view: okView(admitFixture("deploy"))}
	stubACLView(t, aclTestNode, v)
	if _, _, err := run(); err != nil {
		t.Fatal(err)
	}
	b := whale.SSHACLEntry{Names: []string{strings.TrimSuffix(authzNameB, ".")}, Addr: netip.MustParseAddr(authzSourceB), Users: []string{"root"}}
	v.view = okView(b)
	_, stderr, err := run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "+ "+authzSourceB) || !strings.Contains(stderr, "- "+authzSource) {
		t.Fatalf("the change was not listed: %s", stderr)
	}
	v.view = okView()
	_, stderr, err = run()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "WARNING: this node's ssh view admits NOBODY") {
		t.Fatalf("an empty governed view must warn: %s", stderr)
	}
}

func TestTheDryRunShowsTheACLFileItWouldWrite(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	stubRoster(t, roster())
	stubACLView(t, aclTestNode, &viewStub{view: okView(admitFixture("deploy"))})
	out, _, err := runAuthz(t, "install")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "#   "+whale.SSHACLHeader+"\n") || !strings.Contains(out, "#   admit "+authzNameBare+" "+authzSource+" deploy\n") {
		t.Fatalf("out = %s", out)
	}
}

func TestAnACLFileNamedByHandGoesIntoTheSnippet(t *testing.T) {
	run, snippet, _, _ := installWithACL(t)
	stubACLView(t, aclTestNode, &viewStub{view: okView(admitFixture("deploy"))})
	_ = run
	named := filepath.Join(t.TempDir(), "node.acl")
	_, _, err := runAuthz(t, "install", "--write", "--path", snippet, "--fleet-file",
		filepath.Join(filepath.Dir(filepath.Dir(snippet)), "whisper-ssh-authz.fleets"), "--acl-file", named)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(snippet); !strings.Contains(string(b), "--acl-file "+named+" ") {
		t.Fatalf("snippet = %s", b)
	}
	if _, present, rerr := loadSSHAuthzACL(named); !present || rerr != nil {
		t.Fatalf("the named file: %v %v", present, rerr)
	}
}

func TestTheViewRowsParseStrictly(t *testing.T) {
	env := func(items ...map[string]any) *client.Envelope {
		r := &client.Result{Columns: []string{"type", "item"}}
		for _, it := range items {
			r.Rows = append(r.Rows, []any{"whale-ssh", it})
		}
		return &client.Envelope{Ok: true, Status: 200, Result: r}
	}
	header := map[string]any{"state": "ok", "governed": true, "node": aclTestNode, "acl_hash": aclTestHash, "artifact_hash": aclTestHash}
	good := map[string]any{"src": authzSource, "names": []any{authzName}, "users": []any{"deploy"}}
	v, err := sshAuthzViewFrom(env(header, good, map[string]any{"src": authzSourceB, "names": []any{}, "users": []any{"root"}}))
	if err != nil || len(v.Entries) != 1 || v.Skipped != 1 || v.Entries[0].Names[0] != authzNameBare {
		t.Fatalf("v=%+v err=%v", v, err)
	}
	for name, e := range map[string]*client.Envelope{
		"no header":    env(good),
		"two headers":  env(header, header),
		"a bad source": env(header, map[string]any{"src": "nope", "names": []any{authzName}, "users": []any{"deploy"}}),
		"a bad user":   env(header, map[string]any{"src": authzSource, "names": []any{authzName}, "users": []any{"Deploy;id"}}),
		"no users":     env(header, map[string]any{"src": authzSource, "names": []any{authzName}}),
		"no rows":      {Ok: true, Status: 200},
		"a short list": env(map[string]any{"state": "ok", "governed": true, "node": aclTestNode, "entries": 2}, good),
	} {
		if _, err := sshAuthzViewFrom(e); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The reply the live control plane gives a build without the ssh view: a 400 naming its views,
// carried inside the envelope. It must surface as that 400, so install can tell "an older
// server" from a fault.
func TestAnOlderControlPlanesRefusalReachesInstallAsThe400ItIs(t *testing.T) {
	body := `{"columns":["op","ok","status","result","error","retry_after","elapsed_ms"],"rows":[{"op":"list","ok":false,` +
		`"status":400,"result":null,"error":{"code":"BAD_ARGS","message":"view must be one of nodes|peers|acltest for ` +
		`kind:'whale' (absent means nodes); 'ssh' is not a view this build serves","retryable":false},"retry_after":null,` +
		`"elapsed_ms":49}],"statistics":{"rowCount":1,"executionTimeMs":49}}`
	env, err := client.DecodeEnvelope([]byte(body), 200)
	if err != nil {
		t.Fatal(err)
	}
	_, verr := sshAuthzViewFrom(env)
	var pe *client.ProblemError
	if !errors.As(verr, &pe) || pe.Status != 400 || !strings.Contains(pe.Detail+" "+pe.Title, "view must be one of") {
		t.Fatalf("err = %#v", verr)
	}
}
