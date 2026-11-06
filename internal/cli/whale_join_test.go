// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_join_test.go proves the join lifecycle verbs from the root of the real
// command tree to the bytes a control plane received, so a verb that cannot be reached, or
// that sends something other than what its help promises, fails here.

type joinFixture struct {
	list      string // the rows op:list{kind:'whale'} returns
	receipt   string // the row op:firewall returns: agent, address, tags, reusable, ephemeral, approved, east_west, connects
	policy    string // the key/value rows op:policy reads back
	failOp    string // when set, this op fails with failCode/failStatus/failBody
	failCode  string
	failState int
	failBody  string

	mu    sync.Mutex
	calls []recordedCall
}

func (f *joinFixture) ops() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

// query returns the Cypher of the n-th call with that op, decoded from the {query} body.
func (f *joinFixture) query(t *testing.T, op string) string {
	t.Helper()
	for _, c := range f.ops() {
		if c.op == op {
			var sent struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal([]byte(c.body), &sent); err != nil {
				t.Fatalf("not the {query} shape: %v", err)
			}
			return sent.Query
		}
	}
	t.Fatalf("no %s call was made; calls: %+v", op, f.ops())
	return ""
}

func (f *joinFixture) count(op string) int {
	n := 0
	for _, c := range f.ops() {
		if c.op == op {
			n++
		}
	}
	return n
}

func (f *joinFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := "unknown"
		for _, o := range []string{"register", "firewall", "policy", "list"} {
			if strings.Contains(body, `op:'`+o+`'`) {
				op = o
				break
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{op: op, body: body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if op == f.failOp && f.failOp != "" {
			// The error object exactly as the control front door emits it: code, message,
			// retryable. A fixture in some other shape would test a decoder path production never takes.
			_, _ = w.Write(carried(op, `"ok":false,"status":`+itoa(f.failState)+`,"result":null,"error":{"code":"`+
				f.failCode+`","message":`+f.failBody+`,"retryable":false}`))
			return
		}
		switch op {
		case "register":
			_, _ = w.Write(carried(op, `"ok":true,"status":200,"result":{"columns":["agent","address","fqdn","api_key"],`+
				`"rows":[["agent-a1","2a04:2a01:9::a1","a1.t1.agents.whisper.online.","whisper_live_NEW"]]},"error":null`))
		case "firewall":
			_, _ = w.Write(carried(op, `"ok":true,"status":200,"result":{"columns":["agent","address","tags","reusable",`+
				`"ephemeral","approved","east_west","connects"],"rows":[`+f.receipt+`]},"error":null`))
		case "policy":
			_, _ = w.Write(carried(op, `"ok":true,"status":200,"result":{"columns":["key","value"],"rows":[`+
				f.policy+`]},"error":null`))
		case "list":
			_, _ = w.Write(carried(op, `"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[`+
				f.list+`]},"error":null`))
		}
	}))
}

func runJoin(t *testing.T, srv *httptest.Server, argv ...string) (string, string, error) {
	t.Helper()
	return runWhaleACL(t, srv, argv...)
}

// withFleet pins the fleet listing (and forbids public DNS) for one test.
func withFleet(t *testing.T, peers []whalePeer, err error) {
	t.Helper()
	savedFleet, savedDNS := whaleFleet, lookupWhaleAAAA
	whaleFleet = func(context.Context, *client.Client) ([]whalePeer, error) { return peers, err }
	lookupWhaleAAAA = func(context.Context, string) ([]netip.Addr, error) {
		t.Errorf("an approval consulted public DNS, which it must never do")
		return []netip.Addr{netip.MustParseAddr("2a04:2a01:dead::1")}, nil
	}
	t.Cleanup(func() { whaleFleet, lookupWhaleAAAA = savedFleet, savedDNS })
}

var joinPeers = []whalePeer{
	{Name: "agent-a1", Address: "2a04:2a01:9::a1", Label: "db-01", FQDN: "a1.t1.agents.whisper.online"},
	{Name: "agent-b2", Address: "2a04:2a01:9::b2", Label: "web-01", FQDN: "b2.t1.agents.whisper.online"},
}

const receiptA1Pending = `["agent-a1","2a04:2a01:9::a1",["tag:prod"],false,false,false,"pending_approval",1]`
const receiptA1Admitted = `["agent-a1","2a04:2a01:9::a1",["tag:prod"],false,false,true,"admitted",1]`

// --- wiring -----------------------------------------------------------------------------

func TestWhaleJoinVerbsAreReachableFromTheRoot(t *testing.T) {
	for _, v := range []string{"nodes", "approve", "deny", "approval"} {
		if c := whaleSubcommand(t, "whale", v); c.RunE == nil {
			t.Fatalf("`whisper whale %s` has no RunE, so reaching it does nothing", v)
		}
	}
}

// --- minting ----------------------------------------------------------------------------

func TestCreateJoinFlagsRideOneWhaleSubMapPinnedToTheVersion(t *testing.T) {
	f := &joinFixture{}
	srv := f.server(t)
	defer srv.Close()
	// No --register: a join flag implies it, as --idempotency-key does.
	_, stderr, err := runJoin(t, srv, "create", "--name", "db-01", "--tag", "tag:prod,tag:db", "--tag", " tag:PROD ",
		"--single-use", "--ephemeral", "--preapproved")
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	q := f.query(t, "register")
	want := `whale:{ephemeral:true,preapproved:true,reusable:false,tags:['tag:prod','tag:db'],v:1}`
	if !strings.Contains(q, want) {
		t.Fatalf("the join settings did not ride as one pinned intent:\n got %s\nwant %s", q, want)
	}
	if strings.Contains(q, "ttl_seconds") {
		t.Fatalf("no --ttl was given, so no expiry may be sent: %s", q)
	}
	if !strings.Contains(stderr, "join") || !strings.Contains(stderr, "single-use") ||
		!strings.Contains(stderr, "whisper connect") {
		t.Fatalf("the mint must say what the key carries and how the node joins: %q", stderr)
	}
}

func TestCreateWithoutJoinFlagsSendsNoWhaleAtAll(t *testing.T) {
	f := &joinFixture{}
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runJoin(t, srv, "create", "--register", "--name", "plain"); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if q := f.query(t, "register"); strings.Contains(q, "whale") || strings.Contains(q, "ttl_seconds") {
		t.Fatalf("a register with no join flag must be byte-identical to before them: %s", q)
	}
}

func TestCreateReuseWithAJoinFlagIsRefusedBeforeAnyRequest(t *testing.T) {
	for _, flag := range [][]string{{"--tag", "tag:x"}, {"--single-use"}, {"--ephemeral"}, {"--preapproved"},
		{"--ttl", "1h"}} {
		f := &joinFixture{}
		srv := f.server(t)
		argv := append([]string{"create", "--register", "--reuse", "--name", "db-01"}, flag...)
		_, _, err := runJoin(t, srv, argv...)
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "--reuse") {
			t.Fatalf("%v: --reuse would silently drop a security setting; it must be refused: %v", flag, err)
		}
		if n := len(f.ops()); n != 0 {
			t.Fatalf("%v: refused, but %d request(s) were sent anyway", flag, n)
		}
	}
}

func TestCreateTagWithTTLIsRefusedBeforeAnyRequestAndSaysWhy(t *testing.T) {
	f := &joinFixture{}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "create", "--name", "db-01", "--tag", "tag:prod", "--ttl", "24h")
	if err == nil || !strings.Contains(err.Error(), "outlives") {
		t.Fatalf("tags and an expiry are different governance models and must be refused in terms: %v", err)
	}
	if len(f.ops()) != 0 {
		t.Fatal("refused, but a request was sent anyway")
	}
}

func TestCreateTTLIsSentInSecondsFromADurationOrANumber(t *testing.T) {
	for in, want := range map[string]string{"2h": "ttl_seconds:7200", "90": "ttl_seconds:90", "1m30s": "ttl_seconds:90"} {
		f := &joinFixture{}
		srv := f.server(t)
		_, _, err := runJoin(t, srv, "create", "--name", "tmp", "--ttl", in)
		srv.Close()
		if err != nil {
			t.Fatalf("--ttl %s: %v", in, err)
		}
		if q := f.query(t, "register"); !strings.Contains(q, want) || strings.Contains(q, "whale") {
			t.Fatalf("--ttl %s: want %s and no whale intent, got %s", in, want, q)
		}
	}
	for _, bad := range []string{"soon", "-5", "0", "10ms"} {
		f := &joinFixture{}
		srv := f.server(t)
		_, _, err := runJoin(t, srv, "create", "--name", "tmp", "--ttl", bad)
		srv.Close()
		if err == nil || len(f.ops()) != 0 {
			t.Fatalf("--ttl %q must be a usage error with no request (err=%v, calls=%d)", bad, err, len(f.ops()))
		}
	}
}

func TestCreateRunTwiceSendsByteIdenticalArgs(t *testing.T) {
	var qs []string
	for i := 0; i < 2; i++ {
		f := &joinFixture{}
		srv := f.server(t)
		_, _, err := runJoin(t, srv, "create", "--name", "db-01", "--tag", "tag:b,tag:a,tag:b", "--single-use",
			"--idempotency-key", "k1")
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		qs = append(qs, f.query(t, "register"))
	}
	if qs[0] != qs[1] {
		t.Fatalf("a keyed retry must send the same args or it reads as a different request:\n%s\n%s", qs[0], qs[1])
	}
	if !strings.Contains(qs[0], "tags:['tag:b','tag:a']") {
		t.Fatalf("tags must be de-duplicated in the order given: %s", qs[0])
	}
}

// --- approve / deny ---------------------------------------------------------------------

func TestApproveByFleetNameSendsTheAgentIdAndPrintsTheServersReceipt(t *testing.T) {
	withFleet(t, joinPeers, nil)
	f := &joinFixture{receipt: receiptA1Admitted}
	srv := f.server(t)
	defer srv.Close()
	stdout, _, err := runJoin(t, srv, "whale", "approve", "DB-01.", "--reason", "joined for the migration")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	q := f.query(t, "firewall")
	if !strings.Contains(q, "agent:'agent-a1'") || strings.Contains(q, "address:") {
		t.Fatalf("a fleet match must select by the agent id, which cannot be re-handed to another node: %s", q)
	}
	if !strings.Contains(q, "whale:{op:'approve',reason:'joined for the migration',v:1}") {
		t.Fatalf("the approval intent is not what was sent: %s", q)
	}
	if !strings.Contains(stdout, "admitted") || !strings.Contains(stdout, "agent-a1") {
		t.Fatalf("the receipt must be the server's row: %q", stdout)
	}
}

func TestApproveByLiteralAddressSendsTheAddress(t *testing.T) {
	withFleet(t, nil, errors.New("must not be read for a literal"))
	f := &joinFixture{receipt: receiptA1Admitted}
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runJoin(t, srv, "whale", "approve", "[2a04:2a01:9:0::a1]"); err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if q := f.query(t, "firewall"); !strings.Contains(q, "address:'2a04:2a01:9::a1'") {
		t.Fatalf("a literal /128 is the selector, canonicalised: %s", q)
	}
}

func TestDenySendsDenyAndReportsThePendingState(t *testing.T) {
	withFleet(t, joinPeers, nil)
	f := &joinFixture{receipt: receiptA1Pending}
	srv := f.server(t)
	defer srv.Close()
	stdout, _, err := runJoin(t, srv, "whale", "deny", "agent-a1")
	if err != nil {
		t.Fatalf("deny failed: %v", err)
	}
	if q := f.query(t, "firewall"); !strings.Contains(q, "op:'deny'") || !strings.Contains(q, "v:1") {
		t.Fatalf("deny is not what was sent: %s", q)
	}
	if !strings.Contains(stdout, "pending_approval") || !strings.Contains(stdout, "single-use") {
		t.Fatalf("the receipt must show the held state the server reports: %q", stdout)
	}
}

func TestApprovalVerbsNeverSelectANodeThroughPublicDNS(t *testing.T) {
	withFleet(t, joinPeers, nil) // lookupWhaleAAAA fails the test if it is called
	for _, name := range []string{"db-01.other.example", "cache-01", "db-01.staging"} {
		f := &joinFixture{receipt: receiptA1Admitted}
		srv := f.server(t)
		_, _, err := runJoin(t, srv, "whale", "approve", name)
		srv.Close()
		if err == nil || f.count("firewall") != 0 {
			t.Fatalf("%q is not exactly a node of this fleet; nothing may be approved (err=%v)", name, err)
		}
	}
}

func TestApproveRefusesANameTwoNodesAnswerTo(t *testing.T) {
	peers := append([]whalePeer(nil), joinPeers...)
	peers = append(peers, whalePeer{Name: "agent-c3", Address: "2a04:2a01:9::c3", Label: "db-01"})
	withFleet(t, peers, nil)
	f := &joinFixture{receipt: receiptA1Admitted}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "whale", "approve", "db-01")
	if err == nil || !strings.Contains(err.Error(), "agent-a1") || !strings.Contains(err.Error(), "agent-c3") {
		t.Fatalf("an ambiguous name must be refused naming both candidates: %v", err)
	}
	if f.count("firewall") != 0 {
		t.Fatal("an ambiguous name reached the control plane")
	}
}

func TestApproveRefusesWhenTheFleetCannotBeReadRatherThanGuessing(t *testing.T) {
	withFleet(t, nil, errors.New("503 from the listing"))
	f := &joinFixture{receipt: receiptA1Admitted}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "whale", "deny", "db-01")
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("a failed listing must refuse, not fall through: %v", err)
	}
	if f.count("firewall") != 0 {
		t.Fatal("a deny was sent on a guess")
	}
}

func TestAReceiptAboutAnotherNodeIsNeverReportedAsDone(t *testing.T) {
	withFleet(t, joinPeers, nil)
	f := &joinFixture{receipt: `["agent-b2","2a04:2a01:9::b2",[],true,false,true,"admitted",0]`}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "whale", "approve", "db-01")
	if err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("a receipt for agent-b2 after approving agent-a1 must exit non-zero: %v", err)
	}
}

func TestTheOwnerOnlyRefusalReachesTheTerminalWordForWord(t *testing.T) {
	withFleet(t, joinPeers, nil)
	// The control plane's own sentence for this refusal, verbatim.
	detail := `"a node's admission to the fleet (whale approve, deny or status on op:firewall) is the` +
		` account owner's; an agent or device key cannot manage it, for itself or another node"`
	f := &joinFixture{failOp: "firewall", failCode: "WHALE_OWNER_ONLY", failState: 403, failBody: detail}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "whale", "approve", "agent-a1")
	if err == nil {
		t.Fatal("a 403 must not read as success")
	}
	rendered := friendly(err)
	if strings.Contains(rendered, "your key was not accepted") {
		t.Fatalf("the key authenticated and was declined one decision; a re-login loop helps nobody: %q", rendered)
	}
	if !strings.Contains(rendered, "account owner's") || !strings.Contains(rendered, "agent or device key") {
		t.Fatalf("the server's sentence, with its remedy, must reach the person: %q", rendered)
	}
}

// TestARejectedKeyStillGetsTheLoginHint pins the other side of the owner-only rule: only
// a *_OWNER_ONLY code is read as "authenticated, but not yours to decide". A key the
// control plane did not accept keeps the line that sends the person to log in.
func TestARejectedKeyStillGetsTheLoginHint(t *testing.T) {
	for _, code := range []string{"INVALID_KEY", "AGENT_REVOKED", "OWNER_ONLY_SOMETHING_ELSE"} {
		pe := &client.ProblemError{Status: 403, Title: code, Detail: "rejected"}
		if got := friendly(pe); !strings.Contains(got, "whisper login") {
			t.Fatalf("%s is a refused key, not an owner decision; it must keep the login hint: %q", code, got)
		}
	}
	if got := friendly(&client.ProblemError{Status: 403, Title: "EDGE_OWNER_ONLY", Detail: "the owner's"}); strings.Contains(got, "whisper login") {
		t.Fatalf("every *_OWNER_ONLY refusal is the owner's decision, not a rejected key: %q", got)
	}
}

// --- nodes ------------------------------------------------------------------------------

const joinListRows = `["whale",{"agent":"agent-a1","address":"2a04:2a01:9::a1","tags":["tag:prod"],"reusable":false,` +
	`"ephemeral":true,"approved":false,"east_west":"pending_approval","connects":1,"created_at":1700000000000}],` +
	`["whale",{"agent":"agent-b2","address":"2a04:2a01:9::b2","tags":[],"reusable":true,"ephemeral":false,` +
	`"approved":true,"east_west":"admitted","connects":3,"created_at":1700000100000}]`

func TestNodesListsJoinStateAndPutsPendingFirst(t *testing.T) {
	f := &joinFixture{list: joinListRows}
	srv := f.server(t)
	defer srv.Close()
	stdout, stderr, err := runJoin(t, srv, "whale", "nodes")
	if err != nil {
		t.Fatalf("nodes failed: %v", err)
	}
	if q := f.query(t, "list"); !strings.Contains(q, "kind:'whale'") || strings.Contains(q, "view:") {
		t.Fatalf("nodes reads the join records, not a view: %s", q)
	}
	ia, ib := strings.Index(stdout, "agent-a1"), strings.Index(stdout, "agent-b2")
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("both nodes, pending first: %q", stdout)
	}
	for _, want := range []string{"tag:prod", "single-use", "ephemeral", "pending_approval", "reusable", "admitted"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in %q", want, stdout)
		}
	}
	if !strings.Contains(stderr, "1 node(s) pending approval") {
		t.Fatalf("a pending node must come with what it means and what to run: %q", stderr)
	}
}

func TestNodesPendingKeysOnTheServersApprovedField(t *testing.T) {
	f := &joinFixture{list: joinListRows}
	srv := f.server(t)
	defer srv.Close()
	stdout, _, err := runJoin(t, srv, "whale", "nodes", "--pending")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "agent-a1") || strings.Contains(stdout, "agent-b2") {
		t.Fatalf("--pending shows exactly the unapproved node: %q", stdout)
	}
}

func TestNodesEmptySaysWhatEmptyMeansWithoutClaimingTheFleetIsEmpty(t *testing.T) {
	f := &joinFixture{}
	srv := f.server(t)
	defer srv.Close()
	stdout, stderr, err := runJoin(t, srv, "whale", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != "" || !strings.Contains(stderr, "whisper list") {
		t.Fatalf("an empty join list must point at the full agent list, never read as no agents: %q / %q",
			stdout, stderr)
	}
}

// --- the approval rule ------------------------------------------------------------------

func TestApprovalReadsTheRuleInForce(t *testing.T) {
	f := &joinFixture{policy: `["default","block"],["whale_approval","auto"]`}
	srv := f.server(t)
	defer srv.Close()
	stdout, _, err := runJoin(t, srv, "whale", "approval")
	if err != nil {
		t.Fatal(err)
	}
	if q := f.query(t, "policy"); strings.Contains(q, "whale") {
		t.Fatalf("a read must not carry a whale intent (that is a write needing dns:whale:write): %s", q)
	}
	if !strings.Contains(stdout, "auto") {
		t.Fatalf("the rule in force: %q", stdout)
	}
}

func TestApprovalWritePinsTheVersionAndChecksTheReadBack(t *testing.T) {
	f := &joinFixture{policy: `["whale_approval","manual"]`}
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runJoin(t, srv, "whale", "approval", "MANUAL"); err != nil {
		t.Fatal(err)
	}
	if q := f.query(t, "policy"); !strings.Contains(q, "whale:{approval:'manual',v:1}") {
		t.Fatalf("the write: %s", q)
	}

	g2 := &joinFixture{policy: `["whale_approval","auto"]`}
	srv2 := g2.server(t)
	defer srv2.Close()
	if _, _, err := runJoin(t, srv2, "whale", "approval", "manual"); err == nil {
		t.Fatal("a read-back that disagrees with the write must not be reported as done")
	}
}

func TestApprovalRefusesAnUnknownModeWithNoRequest(t *testing.T) {
	f := &joinFixture{}
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runJoin(t, srv, "whale", "approval", "sometimes"); err == nil || len(f.ops()) != 0 {
		t.Fatalf("an unknown mode is a usage error before anything is sent (err=%v)", err)
	}
}

func TestApprovalScopeRefusalNamesTheDedicatedGrant(t *testing.T) {
	f := &joinFixture{failOp: "policy", failCode: "FORBIDDEN_SCOPE", failState: 403,
		failBody: `"Missing required scope: dns:whale:write - this is a dedicated operator grant, deliberately never auto-enrolled"`}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runJoin(t, srv, "whale", "approval", "manual")
	if err == nil {
		t.Fatal("a 403 must not read as success")
	}
	if r := friendly(err); !strings.Contains(r, "dns:whale:write") || strings.Contains(r, "your key was not accepted") {
		t.Fatalf("the grant to ask for must reach the person: %q", r)
	}
}

func TestApprovalOnABoxWithoutTheRuleSaysSoRatherThanGuessing(t *testing.T) {
	f := &joinFixture{policy: `["default","block"]`}
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runJoin(t, srv, "whale", "approval"); err == nil || !strings.Contains(err.Error(), "whale_approval") {
		t.Fatalf("a read-back with no rule row must not render as a rule: %v", err)
	}
}
