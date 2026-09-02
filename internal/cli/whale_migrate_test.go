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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_migrate_test.go drives `whisper whale migrate` through the REAL root command, from
// the argv a person types down to the control call it makes. Every test here starts at
// NewRootCommand(), so removing the registration line in whale.go fails the file rather
// than leaving code that compiles, passes its own unit tests, and can never execute.

// --- harness ---------------------------------------------------------------------------

type migrateCall struct {
	op   string
	body string
}

// migrateControlServer stands in for the control plane. It records every op it was asked
// for, mints an address per label, and refuses a second register for a label it already
// holds by returning it from op:list, which is exactly how idempotency is meant to work.
// migrateControl is the stub plus a way to read the identities it currently holds, so a
// test can diff the fleet before an apply against the fleet after a rollback the way the
// acceptance criteria do. It embeds the server, so .URL and .Close() read unchanged.
type migrateControl struct {
	*httptest.Server
	// fleet is the live identity set, label -> address, as op:list would answer it.
	fleet func() map[string]string
}

func migrateControlServer(t *testing.T, calls *[]migrateCall) *migrateControl {
	t.Helper()
	var mu sync.Mutex
	registered := map[string]string{} // label -> address
	next := 1
	ctl := &migrateControl{}
	ctl.fleet = func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]string{}
		for k, v := range registered {
			out[k] = v
		}
		return out
	}
	ctl.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := sniffOp(body)
		if calls != nil {
			*calls = append(*calls, migrateCall{op: op, body: body})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch op {
		case "register":
			label := argFromBody(body, "label")
			addr := "2a04:2a01:1:4::" + string(rune('a'+next-1))
			next++
			registered[label] = addr
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["agent","label","address","fqdn","api_key"],` +
				`"rows":[["ag_` + label + `","` + label + `","` + addr + `","` + label + `.t.agents.example","whisper_live_minted_` + label + `"]]}}`))
		case "revoke":
			for label := range registered {
				if strings.Contains(body, "ag_"+label) {
					delete(registered, label)
				}
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["ok"],"rows":[[true]]}}`))
		default: // list
			var rows []string
			for label, addr := range registered {
				rows = append(rows, `["agent",{"label":"`+label+`","agent":"ag_`+label+`","address":"`+addr+
					`","fqdn":"`+label+`.t.agents.example","state":"active"}]`)
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[` +
				strings.Join(rows, ",") + `]}}`))
		}
	}))
	return ctl
}

// argFromBody digs one string argument out of the Cypher literal the client sends.
func argFromBody(body, key string) string {
	for _, quote := range []string{"'", `"`} {
		marker := key + ":" + quote
		i := strings.Index(body, marker)
		if i < 0 {
			marker = key + ": " + quote
			i = strings.Index(body, marker)
		}
		if i < 0 {
			continue
		}
		rest := body[i+len(marker):]
		if j := strings.Index(rest, quote); j >= 0 {
			return rest[:j]
		}
	}
	return ""
}

// writeTestPlan builds a real plan (through the real mapper) and saves it, so the CLI
// tests exercise the same artifact `plan` produces rather than a hand-written stand-in.
func writeTestPlan(t *testing.T, dir string, widening bool) string {
	t.Helper()
	policy := `{"acls":[{"action":"accept","src":["group:eng"],"dst":["tag:prod:443"]}]}`
	if widening {
		policy = `{"acls":[{"action":"accept","src":["group:eng"],"dst":["mail.corp.example:25"]}]}`
	}
	pol, lines, err := whale.ParsePolicy([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	tn := &whale.Tailnet{
		Name: "example.com", Policy: pol, PolicyLines: lines,
		Devices: []whale.TSDevice{
			{ID: "d1", Hostname: "db-01", Name: "db-01.tail1234.ts.net", Addresses: []string{"100.64.0.9"}},
			{ID: "d2", Hostname: "web-01", Name: "web-01.tail1234.ts.net", Addresses: []string{"100.64.0.10"}},
		},
	}
	p, err := whale.BuildPlan(tn, whale.BuildOptions{
		Now: time.Unix(0, 0), CredentialFingerprint: "abcdef012345",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "whalenet.plan.json")
	if err := whale.SavePlan(path, p); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWhale runs one argv through the REAL root command tree. The control endpoint and the
// key are passed as the real persistent FLAGS rather than poked into the package globals,
// because NewRootCommand rebinds those globals to its flag defaults: a test that set them
// directly would be testing a state the binary never has.
func runWhale(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	full := append([]string{"--key", migrateTestKey, "--control-url", migrateTestControlURL,
		"--timeout", "5s", "--key-file", migrateTestKeyFile}, args...)
	root.SetArgs(full)
	stdout, stderr = captureStd(t, func() { err = root.Execute() })
	return stdout, stderr, err
}

// The values runWhale threads onto every invocation, set by migrateGlobals.
var (
	migrateTestKey        = "whisper_live_test"
	migrateTestControlURL = "http://127.0.0.1:1"
	migrateTestKeyFile    = ""
)

// migrateGlobals points the CLI at the stub control plane and clears any Tailscale
// credential the developer's own shell may be carrying, so a test never depends on the
// environment it runs in.
func migrateGlobals(t *testing.T, controlURL string) {
	t.Helper()
	savedURL, savedFile := migrateTestControlURL, migrateTestKeyFile
	migrateTestControlURL = controlURL
	// An empty key file keeps the ladder off the developer's own ~/.config/whisper/key.
	migrateTestKeyFile = filepath.Join(t.TempDir(), "no-such-key")
	t.Cleanup(func() { migrateTestControlURL, migrateTestKeyFile = savedURL, savedFile })
	for _, k := range []string{"TS_API_KEY", "TAILSCALE_API_KEY", "TAILSCALE_APIKEY",
		"TS_OAUTH_CLIENT_ID", "TS_OAUTH_CLIENT_SECRET", "TAILSCALE_OAUTH_CLIENT_ID", "TAILSCALE_OAUTH_CLIENT_SECRET"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// --- the tests ---------------------------------------------------------------------------

// The whole subtree must be reachable from the binary a user runs.
func TestWhaleMigrateSubtreeIsReachable(t *testing.T) {
	for _, sub := range []string{"plan", "apply", "status", "collect", "rollback"} {
		c := whaleSubcommand(t, "whale", "migrate", sub)
		if c.RunE == nil {
			t.Fatalf("`whisper whale migrate %s` has no RunE, so reaching it does nothing", sub)
		}
		if c.Short == "" {
			t.Errorf("`whisper whale migrate %s` ships with no help text", sub)
		}
	}
}

// Idempotency, asserted the way the acceptance criteria state it: apply twice, no second
// identity. The proof is the number of op:register calls the control plane saw.
func TestApplyIsIdempotentAndMintsNoSecondIdentity(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	firstRegisters := countOp(calls, "register")
	if firstRegisters != 2 {
		t.Fatalf("the first apply made %d register calls for 2 nodes", firstRegisters)
	}

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if got := countOp(calls, "register"); got != firstRegisters {
		t.Fatalf("a second apply minted %d more identities; apply must be idempotent", got-firstRegisters)
	}

	p, err := whale.LoadPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// The second apply adds NO receipt, because it did nothing: a step already recorded
	// as applied is skipped before any call is made.
	if len(p.Receipts) != 2 {
		t.Fatalf("expected exactly the 2 receipts of the first apply, got %d", len(p.Receipts))
	}
	for _, r := range p.Receipts {
		if !r.Applied() {
			t.Fatalf("receipt %d is not applied: %+v", r.Seq, r)
		}
	}
	if err := p.VerifyHash(); err != nil {
		t.Fatalf("apply invalidated the plan's own hash: %v", err)
	}
}

var errUnavailable = errors.New("exec: \"tailscale\": executable file not found in $PATH")

func countOp(calls []migrateCall, op string) int {
	n := 0
	for _, c := range calls {
		if c.op == op {
			n++
		}
	}
	return n
}

// The widening gate. Refused without the flag, accepted with it, and the consent recorded.
func TestApplyRefusesAWideningPlanUntilTheOperatorAccepts(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), true)

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil {
		t.Fatal("a plan containing a widening rule applied with no consent")
	}
	if !strings.Contains(err.Error(), "--accept-widening") {
		t.Fatalf("the refusal does not say how to proceed: %v", err)
	}
	if !strings.Contains(err.Error(), "mail.corp.example") {
		t.Fatalf("the refusal does not name the rule that widens, which would just train people to pass the flag: %v", err)
	}
	if n := countOp(calls, "register"); n != 0 {
		t.Fatalf("%d identities were written before the refusal; a refused apply must write nothing", n)
	}

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--accept-widening"); err != nil {
		t.Fatalf("apply --accept-widening: %v", err)
	}
	p, err := whale.LoadPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AcceptedWidening || p.AcceptedWideningAt == "" {
		t.Fatal("the widening consent was not recorded in the plan file, so it cannot be audited afterwards")
	}
	// And having consented once, a resumed apply does not ask again.
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("a resumed apply asked for consent that was already recorded: %v", err)
	}
}

// Rollback undoes in reverse receipt order and leaves nothing behind.
func TestRollbackUndoesInReverseReceiptOrder(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	before, _ := whale.LoadPlan(plan)
	var order []int
	for _, r := range before.Receipts {
		if r.Applied() {
			order = append(order, r.Seq)
		}
	}

	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after, err := whale.LoadPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after.Receipts {
		if r.Applied() {
			t.Fatalf("receipt %d is still applied after a rollback", r.Seq)
		}
	}
	// The undo calls must have been made highest sequence first.
	var revoked []string
	for _, c := range calls {
		if c.op == "revoke" {
			revoked = append(revoked, c.body)
		}
	}
	if len(revoked) != len(order) {
		t.Fatalf("%d revoke calls for %d applied receipts", len(revoked), len(order))
	}
	if len(revoked) >= 2 && !strings.Contains(revoked[0], "web-01") {
		t.Fatalf("rollback did not start from the LAST receipt: first revoke was %q", revoked[0])
	}

	// A second rollback is a no-op rather than a second revoke.
	callsBefore := countOp(calls, "revoke")
	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("second rollback: %v", err)
	}
	if countOp(calls, "revoke") != callsBefore {
		t.Fatal("a second rollback revoked something again")
	}
}

// A plan edited under a half-finished apply must be caught, not trusted.
func TestApplyRefusesAnEditedPlan(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	raw, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	nodes := doc["nodes"].([]any)
	nodes[0].(map[string]any)["label"] = "somebody-elses-node"
	edited, _ := json.Marshal(doc)
	if err := os.WriteFile(plan, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil {
		t.Fatal("an edited plan applied; the hash would then vouch for nothing")
	}
	if !strings.Contains(err.Error(), "edited") {
		t.Fatalf("the refusal does not say what happened: %v", err)
	}
}

// The credential gate: a plan made with one Tailscale credential must not be applied while
// looking at another tailnet.
func TestApplyRefusesAPlanFromADifferentCredential(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)
	t.Setenv("TS_API_KEY", "tskey-api-someotherkey-1234567890")

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil {
		t.Fatal("a plan built from a different credential applied without complaint")
	}
	if !strings.Contains(err.Error(), "abcdef012345") {
		t.Fatalf("the refusal does not name the plan's credential fingerprint: %v", err)
	}
	if strings.Contains(err.Error(), "someotherkey") {
		t.Fatalf("the refusal echoed the credential: %v", err)
	}
}

// Failure mode 2: a fleet read that FAILS must not render as a fleet of zero.
func TestStatusRefusesToCallAnUnreadFleetAnEmptyOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"ok":false,"status":500,"error":"upstream unavailable"}`))
	}))
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	_, _, err := runWhale(t, "whale", "migrate", "status", "-f", plan)
	if err == nil {
		t.Fatal("status reported drift against a fleet it could not read")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("the error does not distinguish an unread fleet from an empty one: %v", err)
	}
}

func TestStatusReportsLivePendingAndMissing(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	stdout, _, err := runWhale(t, "whale", "migrate", "status", "-f", plan)
	if err != nil {
		t.Fatalf("status before apply: %v", err)
	}
	if !strings.Contains(stdout, "pending") {
		t.Fatalf("an unapplied plan does not read as pending:\n%s", stdout)
	}

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	stdout, _, err = runWhale(t, "whale", "migrate", "status", "-f", plan)
	if err != nil {
		t.Fatalf("status after apply: %v", err)
	}
	if !strings.Contains(stdout, "live") {
		t.Fatalf("an applied plan does not read as live:\n%s", stdout)
	}
}

// --dry-run writes nothing at all.
func TestApplyDryRunWritesNothing(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--dry-run"); err != nil {
		t.Fatalf("--dry-run: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("--dry-run made %d control calls", len(calls))
	}
	p, _ := whale.LoadPlan(plan)
	if len(p.Receipts) != 0 {
		t.Fatal("--dry-run wrote receipts")
	}
}

// The minted per-agent key must never reach the plan file, and must reach --keys-out only
// when the operator explicitly asked for it.
func TestMintedKeysNeverLandInThePlanAndOnlyLandInKeysOutWhenAsked(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	dir := t.TempDir()
	plan := writeTestPlan(t, dir, false)

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	raw, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "whisper_live_minted") {
		t.Fatal("a minted API key was written into the plan file")
	}
	if strings.Contains(strings.ToLower(string(raw)), "tskey") {
		t.Fatal("the plan file contains a tailscale key")
	}

	_ = dir
}

// --keys-out is the ONLY way a minted key is retained, and it lands mode 0600.
func TestKeysOutCapturesTheMintedKeys(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	dir := t.TempDir()
	plan := writeTestPlan(t, dir, false)
	keys := filepath.Join(dir, "keys.txt")

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--keys-out", keys); err != nil {
		t.Fatalf("apply --keys-out: %v", err)
	}
	assertPrivateFile(t, keys)
	body, _ := os.ReadFile(keys)
	if !strings.Contains(string(body), "whisper_live_minted_db-01") {
		t.Fatalf("--keys-out did not capture the minted key:\n%s", body)
	}
	// And the plan itself is still clean.
	raw, _ := os.ReadFile(plan)
	if strings.Contains(string(raw), "whisper_live_minted") {
		t.Fatal("a minted key reached the plan file even with --keys-out")
	}
}

// Postel at the boundary: a node auth key in the API-credential slot gets the sentence
// that unblocks the person.
func TestPlanRecognisesANodeAuthKey(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	t.Setenv("TS_API_KEY", "tskey-auth-kNOTAREALKEY-abcdefghijklmnop")
	_, _, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com")
	if err == nil {
		t.Fatal("a node auth key was accepted as an API credential")
	}
	if !strings.Contains(err.Error(), "NODE auth key") {
		t.Fatalf("the error does not name the mistake: %v", err)
	}
	if strings.Contains(err.Error(), "kNOTAREALKEY") {
		t.Fatalf("the error echoed the key: %v", err)
	}
}

func TestPlanWithNoCredentialSaysHowToSupplyOne(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	_, _, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com")
	if err == nil {
		t.Fatal("plan ran with no Tailscale credential")
	}
	for _, want := range []string{"TS_OAUTH_CLIENT_ID", "TS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "shell history") {
		t.Fatalf("the error does not explain why there is no --api-key flag: %v", err)
	}
}

func TestOAuthClientNeedsBothHalves(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	t.Setenv("TS_OAUTH_CLIENT_SECRET", "some-secret-value")
	_, _, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com")
	if err == nil || !strings.Contains(err.Error(), "TS_OAUTH_CLIENT_ID") {
		t.Fatalf("a half-configured OAuth client must say which half is missing, got %v", err)
	}
}

// collect must run with no tailscale on the box and say so, rather than writing an empty
// config that reads as "nothing is served".
func TestCollectOnAHostWithNoTailscale(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	saved := collectRunner
	collectRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errUnavailable
	}
	t.Cleanup(func() { collectRunner = saved })

	dir := t.TempDir()
	out := filepath.Join(dir, "collect.json")
	stdout, stderr, err := runWhale(t, "whale", "migrate", "collect", "-o", out)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains(stdout, whale.CollectNoBinary) {
		t.Fatalf("collect did not report the missing binary:\n%s", stdout)
	}
	if !strings.Contains(stderr, "on the node") {
		t.Fatalf("collect did not tell the operator where to run it:\n%s", stderr)
	}
	if _, serr := os.Stat(out); serr != nil {
		t.Fatalf("collect wrote no file: %v", serr)
	}
}

// fakeTailnetServer stands in for api.tailscale.com and records the METHOD of every
// request, so "changes nothing on either side" can be asserted rather than asserted about.
func fakeTailnetServer(t *testing.T, methods *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if methods != nil {
			*methods = append(*methods, r.Method+" "+r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/devices"):
			_, _ = w.Write([]byte(`{"devices":[{"id":"d1","hostname":"db-01","name":"db-01.tail1234.ts.net",` +
				`"addresses":["100.64.0.9"],"os":"linux","tags":["tag:prod"],"user":"alice@example.com"}]}`))
		case strings.HasSuffix(r.URL.Path, "/acl"):
			_, _ = w.Write([]byte("{\n // prod\n \"groups\": {\"group:eng\": [\"alice@example.com\"]},\n" +
				"  \"acls\": [{\"action\":\"accept\",\"src\":[\"group:eng\"],\"dst\":[\"tag:prod:443\"]},\n" +
				"            {\"action\":\"accept\",\"src\":[\"group:sre\"],\"dst\":[\"mail.corp.example:25\"]},],\n}"))
		case strings.HasSuffix(r.URL.Path, "/routes"):
			_, _ = w.Write([]byte(`{"advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":[]}`))
		case strings.HasSuffix(r.URL.Path, "/keys"):
			_, _ = w.Write([]byte(`{"keys":[{"id":"kABC","description":"ci runner"}]}`))
		case strings.HasSuffix(r.URL.Path, "/users"):
			_, _ = w.Write([]byte(`{"users":[{"id":"u1","loginName":"alice@example.com"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

// The headline acceptance criterion: plan changes nothing on either side.
func TestPlanIsReadOnlyOnBothSides(t *testing.T) {
	var methods []string
	ts := fakeTailnetServer(t, &methods)
	defer ts.Close()
	var control []migrateCall
	ctrl := migrateControlServer(t, &control)
	defer ctrl.Close()
	migrateGlobals(t, ctrl.URL)
	t.Setenv("TS_API_KEY", "tskey-api-planonly-0123456789")

	out := filepath.Join(t.TempDir(), "whalenet.plan.json")
	stdout, stderr, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com",
		"--api-base", ts.URL+"/api/v2", "-o", out)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, m := range methods {
		if !strings.HasPrefix(m, "GET ") {
			t.Fatalf("plan issued a non-GET against their API: %s", m)
		}
	}
	if len(control) != 0 {
		t.Fatalf("plan called OUR control plane %d times; it must change nothing on either side", len(control))
	}
	if !strings.Contains(stdout, "NOTHING HAS BEEN CHANGED") {
		t.Fatalf("the plan report does not say that nothing changed:\n%s", stdout)
	}

	p, err := whale.LoadPlan(out)
	if err != nil {
		t.Fatalf("the plan file did not load: %v", err)
	}
	if err := p.VerifyHash(); err != nil {
		t.Fatalf("the written plan does not verify: %v", err)
	}
	if p.CredentialFingerprint == "" {
		t.Fatal("the plan records no credential fingerprint")
	}
	raw, _ := os.ReadFile(out)
	if strings.Contains(strings.ToLower(string(raw)), "tskey") {
		t.Fatal("the plan file contains a tailscale key")
	}
	if strings.Contains(stdout+stderr, "planonly") {
		t.Fatal("the credential was echoed to the terminal")
	}

	// The HuJSON policy (comments AND a trailing comma) was really read, and the widening
	// rule inside it was really found.
	if p.WideningRules() == 0 {
		t.Fatal("the HOST-dimension rule in their policy file did not produce a widening finding")
	}
	if p.Source.PolicyLines == 0 {
		t.Fatal("the policy line count is zero, so the policy file was not read")
	}
	var sawUnmapped bool
	for _, f := range p.Fidelity {
		if f.Class == whale.ClassUnmapped {
			sawUnmapped = true
		}
	}
	if !sawUnmapped {
		t.Fatal("nothing was reported UNMAPPED, and this tailnet has an auth key and a subnet route")
	}
}

// Planning twice against an unchanged tailnet produces the same hash. Without that, the
// hash cannot be used to prove a plan was not edited.
func TestPlanIsDeterministic(t *testing.T) {
	ts := fakeTailnetServer(t, nil)
	defer ts.Close()
	ctrl := migrateControlServer(t, nil)
	defer ctrl.Close()
	migrateGlobals(t, ctrl.URL)
	t.Setenv("TS_API_KEY", "tskey-api-planonly-0123456789")

	dir := t.TempDir()
	var hashes []string
	for i := 0; i < 2; i++ {
		out := filepath.Join(dir, "plan-"+string(rune('a'+i))+".json")
		if _, _, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com",
			"--api-base", ts.URL+"/api/v2", "-o", out); err != nil {
			t.Fatalf("plan %d: %v", i, err)
		}
		p, err := whale.LoadPlan(out)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, p.Hash)
	}
	if hashes[0] != hashes[1] {
		t.Fatalf("two plans of the same tailnet hashed differently: %s vs %s", hashes[0], hashes[1])
	}
}

// The duplicate-mint guard: idempotency is answered from a fleet read, so a FAILED read
// must stop the run rather than answer "nothing exists" for every node.
func TestApplyRefusesWhenTheFleetCannotBeRead(t *testing.T) {
	var calls []migrateCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls = append(calls, migrateCall{op: sniffOp(string(raw)), body: string(raw)})
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"ok":false,"status":503,"error":"upstream unavailable"}`))
	}))
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	_, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan)
	if err == nil {
		t.Fatal("apply ran against a fleet it could not read, and would mint a duplicate for every node")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("the refusal does not name the risk: %v", err)
	}
	if n := countOp(calls, "register"); n != 0 {
		t.Fatalf("%d register calls were made after an unreadable fleet", n)
	}
}

// Rollback must undo what THIS plan did, and nothing else. An identity that already
// existed before the migration is recorded, but it is not ours to revoke.
func TestRollbackDoesNotRevokeAPreExistingIdentity(t *testing.T) {
	var calls []migrateCall
	srv := migrateControlServer(t, &calls)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	dir := t.TempDir()

	// Apply once to create both identities, then apply a SECOND, independent plan for the
	// same nodes: its steps all resolve to "existing".
	first := writeTestPlan(t, dir, false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", first); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	second := writeTestPlan(t, t.TempDir(), false)
	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", second); err != nil {
		t.Fatalf("second plan apply: %v", err)
	}
	p, err := whale.LoadPlan(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Receipts {
		if r.Result != whale.ResultExisting {
			t.Fatalf("expected every step of the second plan to resolve to existing, got %+v", r)
		}
		if r.Undo != nil {
			t.Fatalf("a pre-existing identity carries an undo, so rolling this plan back would revoke it: %+v", r)
		}
	}

	before := countOp(calls, "revoke")
	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", second, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if countOp(calls, "revoke") != before {
		t.Fatal("rolling back a plan that created nothing revoked something")
	}
}

// The rollback criterion as it is actually written: diff the identities before the apply
// against the identities after the rollback, and they are the same set. Counting revoke
// calls proves we asked; this proves the fleet ANSWERED, which is the part an operator
// cares about.
func TestRollbackReturnsTheFleetToItsPreApplyState(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	plan := writeTestPlan(t, t.TempDir(), false)

	before := srv.fleet()

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	during := srv.fleet()
	if len(during) <= len(before) {
		t.Fatalf("apply added no identity: %d before, %d after", len(before), len(during))
	}

	if _, _, err := runWhale(t, "whale", "migrate", "rollback", "-f", plan, "--yes"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after := srv.fleet()
	if len(after) != len(before) {
		t.Fatalf("the fleet did not come back to its pre-apply state: %d identities before, %d after "+
			"(left over: %v)", len(before), len(after), after)
	}
	for label := range before {
		if _, ok := after[label]; !ok {
			t.Errorf("%s was in the fleet before the apply and is gone after the rollback", label)
		}
	}
}

// The credential criterion, run the way it is written: after a plan, `grep -ri tskey`
// over the plan file AND the user's config directory finds nothing. This asserts the
// stronger property behind it - the run writes NOTHING under the config root at all - so a
// future cache that quietly remembered the tailnet credential would fail here.
func TestPlanPersistsNothingInTheUserConfigDir(t *testing.T) {
	ts := fakeTailnetServer(t, nil)
	defer ts.Close()
	ctrl := migrateControlServer(t, nil)
	defer ctrl.Close()
	migrateGlobals(t, ctrl.URL)

	home := testenv.HermeticHome(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	const secret = "tskey-api-neverpersisted-0123456789"
	t.Setenv("TS_API_KEY", secret)

	out := filepath.Join(t.TempDir(), "whalenet.plan.json")
	stdout, stderr, err := runWhale(t, "whale", "migrate", "plan", "--tailnet", "example.com",
		"--api-base", ts.URL+"/api/v2", "-o", out)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	var wrote []string
	_ = filepath.Walk(home, func(path string, info os.FileInfo, werr error) error {
		if werr == nil && info != nil && !info.IsDir() {
			wrote = append(wrote, path)
		}
		return nil
	})
	if len(wrote) != 0 {
		t.Errorf("plan wrote %d file(s) under the user's config root: %v", len(wrote), wrote)
	}

	// And the literal grep, over everything this run could have touched.
	for _, path := range append(wrote, out) {
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(raw)), "tskey") {
			t.Errorf("%s contains a tailscale credential", path)
		}
	}
	if strings.Contains(stdout+stderr, secret) || strings.Contains(stdout+stderr, "neverpersisted") {
		t.Error("the credential was echoed to the terminal")
	}
}
