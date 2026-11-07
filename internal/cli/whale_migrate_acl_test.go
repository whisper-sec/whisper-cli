// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_migrate_acl_test.go drives the ACL half of `whisper whale migrate apply` and its
// rollback through the REAL root command, against the stub control plane and its WhaleACL
// compare-and-set fake. Each test names one branch of the state machine in
// whale_migrate_acl.go, so deleting a branch fails the test that names it.

func aclReceipt(t *testing.T, plan string) whale.Receipt {
	t.Helper()
	p, err := whale.LoadPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.ReceiptFor(stepACL, aclSubject)
	if !ok {
		t.Fatalf("the plan holds no ACL receipt: %+v", p.Receipts)
	}
	return r
}

func noLagWait(t *testing.T) {
	t.Helper()
	saved := aclLagDelay
	aclLagDelay = time.Millisecond
	t.Cleanup(func() { aclLagDelay = saved })
}

const foreignDoc = `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}],"default":"deny"}`

// The wiring itself: apply publishes, on an empty tenant with no base, a document that
// names the minted /128s and none of their addresses, and records what it published.
func TestApplyPublishesTheWhaleACLOnAnEmptyTenant(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	stdout, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	writes := srv.acl.recorded()
	if len(writes) != 1 || writes[0].base != "" || writes[0].withdraw {
		t.Fatalf("expected one create with no base, got %+v", writes)
	}
	doc, hash := srv.acl.current()
	// web-01 is named (through group:eng, as alice's laptop), so its minted /128 is in the
	// document; db-01 is reached through tag:prod, which its registration carries.
	if addr := srv.fleet()["web-01"]; !strings.Contains(doc, `"web-01":"`+addr+`"`) {
		t.Errorf("the document does not name web-01 by its minted /128 %s:\n%s", addr, doc)
	}
	if strings.Contains(doc, "100.64.") {
		t.Fatalf("a tailnet address reached the published document:\n%s", doc)
	}
	for _, want := range []string{`"tag:prod"`, `"group:eng"`, `"ssh"`, `"deny":["tcp:tag:prod:22"]`, "autogroup:internet"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document lacks %s:\n%s", want, doc)
		}
	}
	r := aclReceipt(t, plan)
	if r.Result != whale.ResultApplied || r.ACLHash != hash || r.ACLReplaced != "" || r.ACLDocument != doc {
		t.Fatalf("the receipt does not record what was published: %+v", r)
	}
	if !strings.Contains(stdout, "WHALE ACL") || !strings.Contains(stdout, "published") {
		t.Fatalf("the summary does not report the ACL:\n%s", stdout)
	}
}

// Tags ride the register, lower-cased and sorted; an untagged node's register is unchanged.
func TestApplyRegistersEachNodeWithItsTags(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	tags := srv.tagsOf()
	if strings.Join(tags["db-01"], ",") != "tag:prod" {
		t.Fatalf("db-01 was registered with tags %v", tags["db-01"])
	}
	if _, has := tags["web-01"]; has {
		t.Fatalf("an untagged node was registered with whale settings: %v", tags["web-01"])
	}
	for _, c := range calls {
		if c.op == "register" && strings.Contains(c.body, "web-01") && strings.Contains(c.body, "whale:") {
			t.Fatalf("the untagged register is no longer byte-identical to before: %s", c.body)
		}
	}
}

func TestSkipACLWritesNoPolicy(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--skip-acl"); err != nil {
		t.Fatalf("apply --skip-acl: %v", err)
	}
	if n := countOp(calls, "policy"); n != 0 || len(srv.acl.recorded()) != 0 {
		t.Fatalf("--skip-acl made %d policy calls", n)
	}
	// CONTROL: the same plan without the flag does publish, so the zero above is the flag's.
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(srv.acl.recorded()) != 1 {
		t.Fatal("the control apply published nothing")
	}
}

// A document this plan did not write is never published over silently; with
// --replace-acl it is replaced under compare-and-set, and rollback puts it back.
func TestAForeignDocumentIsReplacedOnlyOnRequestAndRestoredOnRollback(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.set(foreignDoc)
	_, foreignHash := srv.acl.current()

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "--replace-acl") || !strings.Contains(err.Error(), foreignHash) {
		t.Fatalf("publishing over a foreign document was not refused by name: %v", err)
	}
	if len(srv.acl.recorded()) != 0 {
		t.Fatal("the refused apply wrote a document")
	}

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--replace-acl"); err != nil {
		t.Fatalf("apply --replace-acl: %v", err)
	}
	w := srv.acl.recorded()
	if len(w) != 1 || w[0].base != foreignHash {
		t.Fatalf("the replacement did not name the document it replaced: %+v", w)
	}
	r := aclReceipt(t, plan)
	if r.ACLReplaced != foreignHash {
		t.Fatalf("the receipt does not record what it replaced: %+v", r)
	}

	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	doc, _ := srv.acl.current()
	if doc != foreignDoc {
		t.Fatalf("rollback did not restore the replaced document; in force now:\n%s", doc)
	}
	if last := srv.acl.recorded()[1]; last.base != r.ACLHash {
		t.Fatalf("the restore did not name our hash as its base, so it could overwrite a later edit: %+v", last)
	}
}

// Rollback withdraws first and revokes after; never the other way round.
func TestRollbackWithdrawsTheACLBeforeAnyIdentityIsRevoked(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	ours := aclReceipt(t, plan).ACLHash
	calls = calls[:0]
	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	firstRevoke, withdraw := -1, -1
	for i, c := range calls {
		if c.op == "revoke" && firstRevoke < 0 {
			firstRevoke = i
		}
		if c.op == "policy" && strings.Contains(c.body, "acl:null") {
			withdraw = i
		}
	}
	if withdraw < 0 || firstRevoke < 0 || withdraw > firstRevoke {
		t.Fatalf("expected the withdraw (call %d) before the first revoke (call %d)", withdraw, firstRevoke)
	}
	if w := srv.acl.recorded(); w[len(w)-1].base != ours {
		t.Fatalf("the withdraw did not name our hash: %+v", w[len(w)-1])
	}
	if doc, _ := srv.acl.current(); doc != "" {
		t.Fatalf("a document is still in force after rollback:\n%s", doc)
	}
	if len(srv.fleet()) != 0 {
		t.Fatalf("identities left after rollback: %v", srv.fleet())
	}
	if r := aclReceipt(t, plan); r.RolledBackAt == "" {
		t.Fatalf("the ACL receipt is not marked rolled back: %+v", r)
	}
}

// Somebody edited the document after this plan published it: rollback must not overwrite
// that edit, and must not revoke the identities the edited document still names.
func TestRollbackAfterAnOutOfBandEditRevokesNothing(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	srv.acl.set(foreignDoc)
	before := countOp(calls, "revoke")

	_, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes")
	if err == nil || !strings.Contains(err.Error(), "no identity was revoked") {
		t.Fatalf("rollback over an edited document did not stop: %v", err)
	}
	if doc, _ := srv.acl.current(); doc != foreignDoc {
		t.Fatalf("rollback overwrote somebody's later edit:\n%s", doc)
	}
	if countOp(calls, "revoke") != before || len(srv.fleet()) != 2 {
		t.Fatalf("identities were revoked under a document that still names them: %v", srv.fleet())
	}
}

// The publish landed and its reply was lost. The next run must adopt it, keeping the
// pre-image recorded BEFORE the send, never record our own document as the one replaced.
func TestALostReplyIsReconciledAndThePreImageSurvives(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.set(foreignDoc)
	_, foreignHash := srv.acl.current()
	srv.acl.loseNext = true

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--replace-acl")
	if err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("a lost reply was not reported as unconfirmed: %v", err)
	}
	if r := aclReceipt(t, plan); r.Result != whale.ResultPending || r.ACLReplaced != foreignHash {
		t.Fatalf("the receipt did not hold the pre-image before the send: %+v", r)
	}

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--replace-acl"); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if n := len(srv.acl.recorded()); n != 1 {
		t.Fatalf("the re-run sent the document again (%d writes) instead of adopting the one in force", n)
	}
	r := aclReceipt(t, plan)
	if r.Result != whale.ResultApplied || r.ACLReplaced != foreignHash {
		t.Fatalf("reconciliation lost the pre-image: %+v", r)
	}
	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if doc, _ := srv.acl.current(); doc != foreignDoc {
		t.Fatalf("rollback after a lost reply did not get the tenant's own document back:\n%s", doc)
	}
}

// The send was lost before it landed: the next run sends it again over the same pre-image.
func TestALostSendThatNeverLandedIsSentAgain(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.dropNext = true
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err == nil {
		t.Fatal("a lost send was reported as published")
	}
	if doc, _ := srv.acl.current(); doc != "" {
		t.Fatal("the fake let a dropped send land")
	}
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	r := aclReceipt(t, plan)
	if r.Result != whale.ResultApplied || len(srv.acl.recorded()) != 2 {
		t.Fatalf("the never-landed send was not retried: %+v, %d writes", r, len(srv.acl.recorded()))
	}
	p, _ := whale.LoadPlan(plan)
	n := 0
	for _, x := range p.Receipts {
		if x.Step == stepACL {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the retry made a second ACL receipt (%d), so rollback would undo twice", n)
	}
}

// A refusal about the document is final for this run, recorded with the control plane's
// words, and exits non-zero; a re-run retries it.
func TestARefusedPublishIsRecordedAndRetriedOnTheNextRun(t *testing.T) {
	noLagWait(t)
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.refuse = "tests[1].deny[0]: assertion failed: web-01 -> tag:prod:22 expected DENY"
	srv.acl.refuseN = 1

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "tests[1].deny[0]") {
		t.Fatalf("the refusal did not carry the control plane's pointer: %v", err)
	}
	if len(srv.acl.recorded()) != 1 {
		t.Fatalf("a refusal about the document was retried: %d writes", len(srv.acl.recorded()))
	}
	if r := aclReceipt(t, plan); r.Result != whale.ResultRefused || !strings.Contains(r.Detail, "expected DENY") {
		t.Fatalf("the refusal is not recorded: %+v", r)
	}
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if aclReceipt(t, plan).Result != whale.ResultApplied {
		t.Fatal("the re-run did not publish")
	}
}

// The publish reaching a box that has not seen the registers yet is retried, boundedly.
func TestReplicationLagIsRetriedThenPublished(t *testing.T) {
	noLagWait(t)
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.refuse = `grants[0].dst[0]: "db-01" is the hosts alias for 2a04:2a01:1:4::a, which is not one of your nodes' /128s`
	srv.acl.refuseN = 2
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply did not ride out the lag: %v", err)
	}
	if n := len(srv.acl.recorded()); n != 3 {
		t.Fatalf("expected two lag refusals then a publish, got %d writes", n)
	}
	// And it is bounded: a box that never converges ends in a refusal, not a loop.
	srv2 := migrateControlServer(t, nil)
	defer srv2.Close()
	migrateGlobals(t, srv2.URL)
	plan2 := writeTestPlan(t, t.TempDir(), false)
	srv2.acl.refuse, srv2.acl.refuseN = srv.acl.refuse, 1000
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan2); err == nil {
		t.Fatal("an endless lag refusal was reported as published")
	}
	if n := len(srv2.acl.recorded()); n != aclLagAttempts {
		t.Fatalf("the retry is not bounded at %d attempts: %d", aclLagAttempts, n)
	}
}

func TestTagDriftRefusesTheACLStep(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--skip-acl"); err != nil {
		t.Fatalf("apply --skip-acl: %v", err)
	}
	// An extra tag is as wrong as a missing one: it hands the node grants their tailnet never gave it.
	srv.setTags("db-01", []string{"tag:admin", "tag:prod"})
	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "db-01") || !strings.Contains(err.Error(), "tag:admin") {
		t.Fatalf("tag drift was not refused by name: %v", err)
	}
	if len(srv.acl.recorded()) != 0 {
		t.Fatal("a document was published over tag drift")
	}
	srv.setTags("db-01", []string{"tag:prod"})
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("CONTROL: with the tags right the publish should go through: %v", err)
	}
}

func TestAgentsOutsideThePlanNeedConsentBecauseTheDocumentGovernsThemToo(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.addAgent("payments-bot", "2a04:2a01:1:4::99")

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "1 agent(s)") || !strings.Contains(err.Error(), "--accept-fleet-wide") {
		t.Fatalf("a fleet-wide document was published without consent: %v", err)
	}
	if len(srv.acl.recorded()) != 0 {
		t.Fatal("the refused apply published")
	}
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--accept-fleet-wide"); err != nil {
		t.Fatalf("apply --accept-fleet-wide: %v", err)
	}
	if len(srv.acl.recorded()) != 1 {
		t.Fatal("consent given and nothing published")
	}
}

// The restore is refused (today's checks against today's roster): rollback saves the
// document, names the fallback, and revokes nothing.
func TestARefusedRestoreStopsBeforeTheRevokesAndSavesTheDocument(t *testing.T) {
	noLagWait(t)
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	dir := t.TempDir()
	plan := writeTestPlan(t, dir, false)
	srv.acl.set(foreignDoc)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--replace-acl"); err != nil {
		t.Fatalf("apply --replace-acl: %v", err)
	}
	ours := aclReceipt(t, plan).ACLHash
	srv.acl.refuse, srv.acl.refuseN = `grants[0].src[0]: "old-box" names nothing`, 1
	before := countOp(calls, "revoke")

	_, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes")
	if err == nil || !strings.Contains(err.Error(), "acl withdraw --base "+ours) || !strings.Contains(err.Error(), "no identity was revoked") {
		t.Fatalf("a refused restore did not name its fallback and stop: %v", err)
	}
	saved := plan + ".acl-restore.json"
	assertPrivateFile(t, saved)
	body, _ := os.ReadFile(saved)
	if strings.TrimSpace(string(body)) != foreignDoc {
		t.Fatalf("the saved document is not the one being restored:\n%s", body)
	}
	if countOp(calls, "revoke") != before {
		t.Fatal("identities were revoked after the ACL undo failed")
	}
}

func TestStatusReportsTheACLState(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	out, _, err := runWhale(t, "whale", "migrate", "status", "-f", plan)
	if err != nil || !strings.Contains(out+stderrOf(t, plan, srv), "WhaleACL: live") {
		t.Fatalf("status does not say the ACL is live: %v\n%s", err, out)
	}
	srv.acl.set(foreignDoc)
	if got := stderrOf(t, plan, srv); !strings.Contains(got, "WhaleACL: drifted") {
		t.Fatalf("status does not report an edited document as drift:\n%s", got)
	}
}

// stderrOf runs status and returns everything it printed: notes go to stderr.
func stderrOf(t *testing.T, plan string, _ *migrateControl) string {
	t.Helper()
	out, errOut, _ := runWhale(t, "whale", "migrate", "status", "-f", plan)
	return out + errOut
}

// --dry-run reads the document before it is published, and writes nothing.
func TestDryRunPrintsTheDocumentOnceTheIdentitiesExist(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--skip-acl"); err != nil {
		t.Fatalf("apply --skip-acl: %v", err)
	}
	n := len(calls)
	out, errOut, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--dry-run")
	if err != nil {
		t.Fatalf("--dry-run: %v", err)
	}
	if len(calls) != n {
		t.Fatalf("--dry-run made %d control calls", len(calls)-n)
	}
	all := out + errOut
	if !strings.Contains(all, `"grants"`) || !strings.Contains(all, srv.fleet()["web-01"]) {
		t.Fatalf("--dry-run did not print the document with the minted /128s:\n%s", all)
	}
}

// Tags this control plane cannot hold are refused before the first register.
func TestUncarryableTagsAreRefusedBeforeAnyWrite(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	pol, lines, err := whale.ParsePolicy([]byte(`{"acls":[{"action":"accept","src":["tag:Prod"],"dst":["tag:prod:22"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := whale.BuildPlan(&whale.Tailnet{Name: "example.com", Policy: pol, PolicyLines: lines,
		Devices: []whale.TSDevice{
			{ID: "d1", Hostname: "a", Name: "a.ts.net", Addresses: []string{"100.64.0.1"}, Tags: []string{"tag:Prod"}},
			{ID: "d2", Hostname: "b", Name: "b.ts.net", Addresses: []string{"100.64.0.2"}, Tags: []string{"tag:prod"}},
		}}, whale.BuildOptions{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(t.TempDir(), "p.json")
	if err := whale.SavePlan(plan, p); err != nil {
		t.Fatal(err)
	}
	_, _, err = runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "tag:Prod and tag:prod") {
		t.Fatalf("case-colliding tags were not refused: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("%d control calls were made before the refusal", len(calls))
	}
}

// The write's read-back can show a concurrent writer's document. Recording THEIR hash as
// ours would let rollback overwrite their edit, so the receipt must stay pending, and
// rollback must then refuse rather than guess.
func TestAReplyShowingSomeoneElsesDocumentIsNotRecordedAsOurs(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.stomp = foreignDoc

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil {
		t.Fatal("a reply that did not show our document was taken as a publish")
	}
	r := aclReceipt(t, plan)
	if r.Result != whale.ResultPending || r.ACLHash != "" {
		t.Fatalf("the receipt adopted a hash that is not ours: %+v", r)
	}
	before := countOp(calls, "revoke")
	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err == nil {
		t.Fatal("rollback guessed over a document that is neither ours nor the one we replaced")
	}
	if doc, _ := srv.acl.current(); doc != foreignDoc {
		t.Fatalf("rollback overwrote the other writer's document:\n%s", doc)
	}
	if countOp(calls, "revoke") != before {
		t.Fatal("identities were revoked while the ACL state was unsettled")
	}
}

// An outside agent carrying a plan tag TAKES that tag's grants, and the consent request
// must say so by name, not only count it as governed.
func TestAnOutsideAgentCarryingAPlanTagIsNamed(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.addAgent("payments-bot", "2a04:2a01:1:4::99")
	srv.setTags("payments-bot", []string{"tag:prod"})
	srv.addAgent("quiet-bot", "2a04:2a01:1:4::98")

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "2 agent(s)") || !strings.Contains(err.Error(), "payments-bot (tag:prod)") {
		t.Fatalf("the tagged outsider was not named: %v", err)
	}
	if strings.Contains(err.Error(), "quiet-bot") {
		t.Fatalf("an untagged outsider was named as taking grants: %v", err)
	}
}

// A tagged node the listing does not show yet is lag, not drift: re-read within the budget,
// then say "not visible yet" and never advise a re-register, which would cost the node its
// /128 and its name.
func TestATaggedNodeNotYetListedIsLagNotDrift(t *testing.T) {
	noLagWait(t)
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--skip-acl"); err != nil {
		t.Fatalf("apply --skip-acl: %v", err)
	}
	srv.hideTags("db-01")
	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil || !strings.Contains(err.Error(), "not visible yet") || strings.Contains(err.Error(), "re-register") {
		t.Fatalf("an unlisted tagged node was reported as drift: %v", err)
	}
	if len(srv.acl.recorded()) != 0 {
		t.Fatal("published while a tagged node was not visible")
	}
	srv.setTags("db-01", []string{"tag:prod"})
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("CONTROL: once visible it should publish: %v", err)
	}
}

// An answered 5xx can follow a committed write. Recording it as refused would make the next
// run see "a document this plan did not write" and, with --replace-acl, record our own
// document as the pre-image. It must stay pending, and the next run must adopt it.
func TestAnAnswered500StaysPendingAndIsAdoptedNextRun(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	srv.acl.fail500 = true
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err == nil {
		t.Fatal("an answered 500 was reported as published")
	}
	if r := aclReceipt(t, plan); r.Result != whale.ResultPending {
		t.Fatalf("an answered 500 was recorded as %s; it can follow a commit, so it must stay pending: %+v", r.Result, r)
	}
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	r := aclReceipt(t, plan)
	if r.Result != whale.ResultApplied || r.ACLReplaced != "" || len(srv.acl.recorded()) != 1 {
		t.Fatalf("the landed write was not adopted with its pre-image (none): %+v, %d writes", r, len(srv.acl.recorded()))
	}
}
