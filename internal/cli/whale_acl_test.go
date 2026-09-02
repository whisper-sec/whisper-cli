// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_acl_test.go proves the PRODUCTION path of `whisper whale acl`.
//
// Every test here starts at NewRootCommand(), the tree the binary actually builds, and
// ends at the bytes a control plane received. Delete the newWhaleACLCmd() line from
// whale.go and every one of them fails on "does not exist", which is the point: the
// defect this repository keeps hitting is a feature that passes its unit tests and can
// never be reached by a person.

// aclFixture is a control plane that answers op:policy and op:list{view:'acltest'} and
// records what it was asked.
type aclFixture struct {
	policy     string // the key/value rows op:policy reads back
	afterWrite string // what a policy WRITE reads back, when it differs from the read
	acltest    string // the rows op:list{kind:'whale',view:'acltest'} returns
	failWrite  int    // when non-zero, a policy WRITE fails with this status
	failBody   string // the error body for that failure

	mu    sync.Mutex
	calls []recordedCall
}

func (f *aclFixture) recorded() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

// writes returns only the calls that would MUTATE something, which is the set a guard is
// supposed to keep empty.
func (f *aclFixture) writes() []recordedCall {
	var out []recordedCall
	for _, c := range f.recorded() {
		if c.op == "policy:write" {
			out = append(out, c)
		}
	}
	return out
}

func (f *aclFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := "unknown"
		switch {
		case strings.Contains(body, "op:'policy'") && strings.Contains(body, "whale:"):
			op = "policy:write"
		case strings.Contains(body, "op:'policy'"):
			op = "policy:read"
		case strings.Contains(body, "op:'list'"):
			op = "list:acltest"
		}
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{op: op, body: body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch op {
		case "list:acltest":
			_, _ = w.Write(carried("list", `"ok":true,"status":200,"result":{"columns":["kind","item"],`+
				`"rows":[`+f.acltest+`]},"error":null`))
		case "policy:write":
			if f.failWrite != 0 {
				_, _ = w.Write(carried("policy", `"ok":false,"status":`+itoa(f.failWrite)+
					`,"result":null,"error":{"code":"FORBIDDEN_SCOPE","status":`+itoa(f.failWrite)+
					`,"detail":`+f.failBody+`}`))
				return
			}
			rows := f.policy
			if f.afterWrite != "" {
				rows = f.afterWrite
			}
			_, _ = w.Write(carried("policy", `"ok":true,"status":200,"result":{"columns":["key","value"],`+
				`"rows":[`+rows+`]},"error":null`))
		default:
			_, _ = w.Write(carried("policy", `"ok":true,"status":200,"result":{"columns":["key","value"],`+
				`"rows":[`+f.policy+`]},"error":null`))
		}
	}))
}

// runWhaleACL drives the REAL command tree from the root, the way a shell does. The endpoint
// and the key ride as FLAGS, never as pokes at the global: building the root re-registers
// every persistent flag and pflag writes each default back over the variable it is bound
// to, so a test that set the global first would quietly talk to production.
func runWhaleACL(t *testing.T, srv *httptest.Server, argv ...string) (stdout, stderr string, err error) {
	t.Helper()
	saved := g
	defer func() { g = saved }()
	full := append(append([]string{}, argv...),
		"--control-url", srv.URL, "--key", "whisper_live_test", "--timeout", "10s")
	stdout, stderr = captureStd(t, func() {
		root := NewRootCommand()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetArgs(full)
		err = root.Execute()
	})
	return stdout, stderr, err
}

// A published document, as the live control plane reads it back (op:policy
// emits {key,value} rows and the notes are numbered).
const aclPublishedRows = `["default","block"],["mode","hybrid"],` +
	`["whale.acl.hash","sha256:32f4f68a5010"],["whale.acl.version","3"],` +
	`["whale.acl.artifact","sha256:cfdcc729aa11"],["whale.acl.default","allow"],` +
	`["whale.acl.nodes","118"],["whale.acl.clauses","4"],["whale.acl.clauses.connect_only","1"],` +
	`["whale.acl.refusals","0"],["whale.acl.last_refusal",""],` +
	`["whale.acl.note.1","the Tier-1 kernel plane enforces TENANCY only today"],` +
	`["whale.acl.note.0","tag:prod resolves to no node in this fleet yet"],` +
	`["whale.acl.document","{\"default\":\"allow\",\"grants\":[]}"]`

// A tenant with a policy but no ACL: the shape that predates the ACL document, byte for byte.
const aclAbsentRows = `["default","block"],["mode","hybrid"],["retention","90"]`

func TestWhaleACLShowIsReachableFromTheRootAndReadsTheRealDocument(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runWhaleACL(t, srv, "whale", "acl", "show")
	if err != nil {
		t.Fatalf("show failed: %v", err)
	}
	for _, want := range []string{"sha256:32f4f68a5010", "118", "clauses", "allow"} {
		if !strings.Contains(out, want) {
			t.Fatalf("show did not report %q:\n%s", want, out)
		}
	}
	// The notes are numbered, and the numbers are the order the compiler produced them.
	// A map would have shuffled these two. They ride stderr, so stdout stays a clean
	// table for a pipe.
	i0 := strings.Index(stderr, "tag:prod resolves")
	i1 := strings.Index(stderr, "Tier-1 kernel plane")
	if i0 < 0 || i1 < 0 || i0 > i1 {
		t.Fatalf("compiler notes are missing or out of order:\n%s", stderr)
	}
	calls := f.recorded()
	if len(calls) != 1 || calls[0].op != "policy:read" {
		t.Fatalf("show must be exactly one policy READ, got %+v", calls)
	}
	if len(f.writes()) != 0 {
		t.Fatalf("show wrote something: %+v", f.writes())
	}
}

func TestWhaleACLShowReportsNoDocumentWithoutInventingOne(t *testing.T) {
	f := &aclFixture{policy: aclAbsentRows}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runWhaleACL(t, srv, "whale", "acl", "show")
	if err != nil {
		t.Fatalf("an unpublished fleet is a real answer, not an error: %v", err)
	}
	all := out + stderr
	if !strings.Contains(all, "none published") {
		t.Fatalf("show must say plainly that nothing is published:\n%s", all)
	}
	if !strings.Contains(all, "tenancy") {
		t.Fatalf("show must say what still governs the fleet with no document:\n%s", all)
	}
}

func TestWhaleACLShowRawPrintsTheDocumentAndNothingElse(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runWhaleACL(t, srv, "whale", "acl", "show", "--raw")
	if err != nil {
		t.Fatalf("show --raw failed: %v", err)
	}
	if strings.TrimSpace(out) != `{"default":"allow","grants":[]}` {
		t.Fatalf("--raw must emit the document alone, ready to edit:\n%q", out)
	}
}

func TestWhaleACLTestExitsNonZeroWhenTheDocumentRefuses(t *testing.T) {
	f := &aclFixture{
		policy: aclPublishedRows,
		acltest: `["whale-acltest",{"src":"group:sre","dst":"tag:db:5432","state":"ok",` +
			`"note":"evaluated against artifact sha256:cfdcc729aa11"}],` +
			`["whale-acltest",{"src":"2a04:2a01::5","src_name":"db-01","dst":"tag:db","proto":"tcp",` +
			`"port":5432,"verdict":"deny","why":"default"}]`,
	}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runWhaleACL(t, srv, "whale", "acl", "test", "group:sre", "tag:db:5432")
	if err == nil {
		t.Fatal("a refusal must exit non-zero so it can gate a deploy")
	}
	if !strings.Contains(err.Error(), "group:sre") || !strings.Contains(err.Error(), "tag:db:5432") {
		t.Fatalf("the refusal must name the pair it refused: %v", err)
	}
	if !strings.Contains(out, "DENY") || !strings.Contains(out, "db-01") {
		t.Fatalf("the verdict table must show the node and the verdict:\n%s", out)
	}
	// A port must never be printed as a float: 5432 arrives as JSON 5432.
	if strings.Contains(out, "5432.") {
		t.Fatalf("port rendered as a float:\n%s", out)
	}
	if len(f.writes()) != 0 {
		t.Fatalf("a dry run mutated something: %+v", f.writes())
	}
}

func TestWhaleACLTestExitsZeroWhenTheDocumentAllows(t *testing.T) {
	f := &aclFixture{
		policy: aclPublishedRows,
		acltest: `["whale-acltest",{"src":"group:sre","dst":"tag:prod:22","state":"ok","note":"ok"}],` +
			`["whale-acltest",{"src":"2a04:2a01::5","src_name":"db-01","dst":"tag:prod","proto":"tcp",` +
			`"port":22,"verdict":"allow","why":"grants[0]"}]`,
	}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runWhaleACL(t, srv, "whale", "acl", "test", "group:sre", "tag:prod:22")
	if err != nil {
		t.Fatalf("an allow must exit zero: %v", err)
	}
	if !strings.Contains(out, "ALLOW") {
		t.Fatalf("the verdict is missing:\n%s", out)
	}
}

func TestWhaleACLTestWithNoDocumentIsNotReportedAsADenial(t *testing.T) {
	f := &aclFixture{
		policy: aclAbsentRows,
		acltest: `["whale-acltest",{"src":"a","dst":"b","state":"no_document",` +
			`"note":"this tenant has published no WhaleACL, so the document decides nothing here"}]`,
	}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runWhaleACL(t, srv, "whale", "acl", "test", "a", "b")
	if err != nil {
		t.Fatalf("no opinion is not a refusal: %v", err)
	}
	if !strings.Contains(out+stderr, "no_document") && !strings.Contains(out+stderr, "published no WhaleACL") {
		t.Fatalf("the state must be reported rather than rounded to allow:\n%s", out+stderr)
	}
}

// TestWhaleACLSetRefusesTheSilentFleetWideDenyBeforeItReachesTheWire pins the incident of
// An empty document publishes cleanly and puts the whole fleet into
// deny-everything with a 200. The refusal has to happen before the request, because a
// client cannot assume the server it is talking to carries the same guard.
func TestWhaleACLSetRefusesTheSilentFleetWideDenyBeforeItReachesTheWire(t *testing.T) {
	f := &aclFixture{policy: aclAbsentRows}
	srv := f.server(t)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte("// nothing yet\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runWhaleACL(t, srv, "whale", "acl", "set", path)
	if err == nil {
		t.Fatal("an empty document must be refused, not published")
	}
	if !strings.Contains(err.Error(), "EVERY flow") || !strings.Contains(err.Error(), "withdraw") {
		t.Fatalf("the refusal must say what it would do and offer the three ways out: %v", err)
	}
	if len(f.recorded()) != 0 {
		t.Fatalf("the guard let the request out: %+v", f.recorded())
	}
}

func TestWhaleACLSetNamesTheDocumentItWouldReplaceRatherThanClobberingIt(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:internet"],"ip":["tcp:443"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runWhaleACL(t, srv, "whale", "acl", "set", path)
	if err == nil {
		t.Fatal("replacing a document without naming it must be refused")
	}
	if !strings.Contains(err.Error(), "sha256:32f4f68a5010") {
		t.Fatalf("the refusal must carry the hash to pass back: %v", err)
	}
	if len(f.writes()) != 0 {
		t.Fatalf("it wrote anyway: %+v", f.writes())
	}
}

func TestWhaleACLSetSendsTheDocumentIntactWithItsBase(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	// An apostrophe in a comment, which is how an operator writes English. Before the
	// escaper was corrected this became a 400 at our own front door.
	doc := "// the SRE group's own rule\n{\n  \"grants\": [\n    {\"src\": [\"group:sre\"], \"dst\": [\"tag:prod\"], \"ip\": [\"tcp:22\"]},\n  ],\n}\n"
	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runWhaleACL(t, srv, "whale", "acl", "set", path, "--base", "sha256:32f4f68a5010"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	writes := f.writes()
	if len(writes) != 1 {
		t.Fatalf("expected exactly one write, got %+v", writes)
	}
	var sent struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(writes[0].body), &sent); err != nil {
		t.Fatalf("the request body is not the {query} shape the plane reads: %v", err)
	}
	body := sent.Query
	if !strings.Contains(body, "base:'sha256:32f4f68a5010'") {
		t.Fatalf("the base did not ride the write: %s", body)
	}
	// The document must arrive as ONE argument the far end can take back apart: the
	// apostrophe escaped with a backslash (which the control plane's map-literal reader
	// decodes) and never doubled (which it reads as end-of-string).
	if !strings.Contains(body, `group\'s own rule`) {
		t.Fatalf("the apostrophe was not escaped the way the reader decodes: %s", body)
	}
	if strings.Contains(body, "group''s") {
		t.Fatalf("the apostrophe was doubled, which our own front door reads as end-of-string: %s", body)
	}
	if strings.Contains(body, "\n") {
		t.Fatalf("raw newlines rode the query instead of being escaped: %q", body)
	}
}

// TestWhaleACLSetSurfacesTheScopeRefusalAsItIsWritten is the whole scope-refusal path
// with nothing faked in the middle: a real front-door error body, decoded by
// the real envelope decoder into a ProblemError, rendered by the real friendly().
//
// The assertion is on friendly(err) and not on err.Error(), and that distinction is the
// point rather than a detail. err.Error() carries the problem's Detail whatever the
// renderer does with it, so this test asserted the grant survived while `whisper` on a
// terminal was printing "your key was not accepted - run: whisper login" and throwing
// the whole sentence away. Measured: with the fix in mapProblem reverted, this test
// stayed green and only the hand-built one in output_scope_test.go went red. So it was
// testing the wire and calling it the user experience. root.go:280 is the one place a
// returned error reaches a person, and it renders friendly(err); this now asks the same
// function.
func TestWhaleACLSetSurfacesTheScopeRefusalAsItIsWritten(t *testing.T) {
	f := &aclFixture{
		policy:    aclAbsentRows,
		failWrite: 403,
		failBody: `"Missing required scope: dns:whale:write - this is a dedicated operator grant, ` +
			`deliberately never auto-enrolled"`,
	}
	srv := f.server(t)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(`{"grants":[{"src":["group:sre"],"dst":["tag:prod"],"ip":["tcp:22"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runWhaleACL(t, srv, "whale", "acl", "set", path)
	if err == nil {
		t.Fatal("a 403 must not read as success")
	}
	if !strings.Contains(err.Error(), "dns:whale:write") {
		t.Fatalf("the grant the operator needs must survive to the terminal: %v", err)
	}

	// What a person actually reads.
	rendered := friendly(err)
	if strings.Contains(rendered, "your key was not accepted") {
		t.Fatalf("the key WAS accepted; it authenticated and was declined one operation. Sending "+
			"somebody to re-login and be refused identically is the loop the server sentence exists "+
			"to end: %q", rendered)
	}
	if !strings.Contains(rendered, "dns:whale:write") {
		t.Fatalf("the grant an administrator has to give must reach the terminal: %q", rendered)
	}
	if !strings.Contains(rendered, "never auto-enrolled") {
		t.Fatalf("the part that says retrying cannot obtain it must survive too: %q", rendered)
	}
}

func TestWhaleACLSetShoutsWhenWhatCompiledRefusesEverything(t *testing.T) {
	f := &aclFixture{
		policy: aclAbsentRows,
		afterWrite: `["whale.acl.hash","sha256:deadbeef"],["whale.acl.version","1"],` +
			`["whale.acl.default","deny"],["whale.acl.nodes","118"],["whale.acl.clauses","0"],` +
			`["whale.acl.document","{\"default\":\"deny\"}"]`,
	}
	srv := f.server(t)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(`{"default":"deny"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runWhaleACL(t, srv, "whale", "acl", "set", path)
	if err != nil {
		t.Fatalf("an explicit lock-down is allowed on purpose: %v", err)
	}
	if !strings.Contains(out+stderr, "READ THAT AGAIN") {
		t.Fatalf("a document that refuses every flow must say so at the moment it lands:\n%s", out+stderr)
	}
}

func TestWhaleACLWithdrawSendsNullAndNamesWhatItRemoves(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	if _, _, err := runWhaleACL(t, srv, "whale", "acl", "withdraw", "--base", "sha256:32f4f68a5010"); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	writes := f.writes()
	if len(writes) != 1 {
		t.Fatalf("expected exactly one write, got %+v", writes)
	}
	if !strings.Contains(writes[0].body, "acl:null") {
		t.Fatalf("withdraw must send an explicit null, which is what the control plane reads as "+
			"'remove it': %s", writes[0].body)
	}
	if !strings.Contains(writes[0].body, "base:'sha256:32f4f68a5010'") {
		t.Fatalf("withdraw must name the document it removes: %s", writes[0].body)
	}
}

func TestWhaleACLWithdrawOnAnUngovernedFleetIsNotAnError(t *testing.T) {
	f := &aclFixture{policy: aclAbsentRows}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runWhaleACL(t, srv, "whale", "acl", "withdraw")
	if err != nil {
		t.Fatalf("withdrawing nothing is a no-op, not a failure: %v", err)
	}
	if !strings.Contains(out+stderr, "Nothing to withdraw") {
		t.Fatalf("it must say why it did nothing:\n%s", out+stderr)
	}
	if len(f.writes()) != 0 {
		t.Fatalf("it wrote anyway: %+v", f.writes())
	}
}

func TestWhaleACLBaseAndForceAreRefusedTogether(t *testing.T) {
	f := &aclFixture{policy: aclPublishedRows}
	srv := f.server(t)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(`{"grants":[{"src":["group:sre"],"dst":["tag:prod"],"ip":["tcp:22"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runWhaleACL(t, srv, "whale", "acl", "set", path, "--base", "sha256:x", "--force")
	if err == nil {
		t.Fatal("two flags that say opposite things must be a usage error, not a coin toss")
	}
	if len(f.writes()) != 0 {
		t.Fatalf("it wrote anyway: %+v", f.writes())
	}
}

// TestSSHNoteReadsTheDocumentTheControlPlaneReallySends is a regression on a function that
// could only ever answer "no". It looked for a nested item.whale.acl.ssh map, a shape
// op:policy has never emitted, so `whisper whale ssh` told every account it publishes no
// ssh block, including the accounts that publish one.
func TestSSHNoteReadsTheDocumentTheControlPlaneReallySends(t *testing.T) {
	withSSH := carried("policy", `"ok":true,"status":200,"result":{"columns":["key","value"],"rows":[`+
		`["whale.acl.hash","sha256:abc"],`+
		`["whale.acl.document","{\"ssh\":[{\"action\":\"accept\",\"src\":[\"group:sre\"],`+
		`\"dst\":[\"tag:prod\"],\"users\":[\"root\"]}]}"]]},"error":null`)
	env, err := client.DecodeEnvelope(withSSH, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !sshACLPublished(env) {
		t.Fatal("an ssh block in the published document must be seen")
	}

	withoutSSH, err := client.DecodeEnvelope(carried("policy",
		`"ok":true,"status":200,"result":{"columns":["key","value"],"rows":[`+
			`["whale.acl.hash","sha256:abc"],["whale.acl.document","{\"default\":\"allow\"}"]]},"error":null`), 200)
	if err != nil {
		t.Fatal(err)
	}
	if sshACLPublished(withoutSSH) {
		t.Fatal("a document with no ssh block must not be reported as having one")
	}

	none, err := client.DecodeEnvelope(carried("policy",
		`"ok":true,"status":200,"result":{"columns":["key","value"],"rows":[`+aclAbsentRows+`]},"error":null`), 200)
	if err != nil {
		t.Fatal(err)
	}
	if sshACLPublished(none) {
		t.Fatal("no document at all is not an ssh block")
	}
}
