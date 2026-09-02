// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/alerts"
)

// alerts_test.go proves the PRODUCTION path, not the model. The model has its own suite in
// internal/alerts; what these tests exist for is the failure this codebase keeps hitting -
// a feature that ships, passes its unit tests, and can never actually execute because
// nothing wires it to a user's keystroke. Every test here starts at the cobra command a
// person types and ends at the bytes the control plane received.

// alertsFixture is a control plane that answers the five reads the surface makes, and
// records every op it was asked for.
type alertsFixture struct {
	standing    string // the rows JSON for op:list{kind:'standing'}
	coverage    string
	agents      string
	audit       string
	failKinds   map[string]int // kind -> HTTP status to fail with
	suppression string
	suppressErr int

	// calls is written from the httptest handler goroutines and read from the test
	// goroutine, so it is behind a mutex. readBook fires several ops CONCURRENTLY,
	// which makes two handler goroutines append at once; -race reports it, and the
	// ubuntu lane's `go test -race ./...` has been one scheduling accident away from
	// it all along (found while running this package on Windows).
	mu    sync.Mutex
	calls []recordedCall
}

// recorded snapshots what the fixture has been asked for.
func (f *alertsFixture) recorded() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

func (f *alertsFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := "unknown"
		switch {
		case strings.Contains(body, "op:'list'"):
			op = "list"
		case strings.Contains(body, "op:'task'"):
			op = "task"
		case strings.Contains(body, "op:'partner'"):
			op = "partner"
		}
		kind := ""
		for _, k := range []string{"standing", "coverage", "agents", "audit"} {
			if strings.Contains(body, "kind:'"+k+"'") {
				kind = k
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{op: op + ":" + kind, body: body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		if op == "partner" {
			if f.suppressErr != 0 {
				w.WriteHeader(200)
				_, _ = w.Write(carried("partner", `"ok":false,"status":`+itoa(f.suppressErr)+
					`,"result":null,"error":{"type":"FORBIDDEN_SCOPE","status":`+itoa(f.suppressErr)+
					`,"detail":"this account has not been granted authority over a partner organization"}`))
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write(carried("partner", `"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[`+
				f.suppression+`]},"error":null`))
			return
		}
		if op == "task" {
			w.WriteHeader(200)
			_, _ = w.Write(carried("task", `"ok":true,"status":200,"result":{"columns":["id","state"],"rows":[["T1486","open"]]},"error":null`))
			return
		}
		if status, bad := f.failKinds[kind]; bad {
			w.WriteHeader(200)
			_, _ = w.Write(carried("list", `"ok":false,"status":`+itoa(status)+
				`,"result":null,"error":{"status":`+itoa(status)+`,"detail":"the `+kind+` read faulted"}`))
			return
		}
		rows := ""
		switch kind {
		case "standing":
			rows = f.standing
		case "coverage":
			rows = f.coverage
		case "agents":
			rows = f.agents
		case "audit":
			rows = f.audit
		}
		w.WriteHeader(200)
		_, _ = w.Write(carried("list", `"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[`+rows+`]},"error":null`))
	}))
}

// carried wraps one whisper.agents op envelope in the Cypher result table the LIVE control
// plane actually transports it in. Checked against the live control plane: it never
// answers with the op envelope at the top level.
//
// This matters more than it looks. A fixture that answered with the flat envelope would
// let `whisper alerts list --json | jq '.result.columns'` pass in the suite and read null
// against every real endpoint, which is exactly what it did until this fixture was
// corrected: a guard cannot fail if it is pointed at a shape the plane never sends.
func carried(op, envelope string) []byte {
	return []byte(`{"columns":["op","ok","status","result","error","retry_after","elapsed_ms"],` +
		`"rows":[{"op":"` + op + `",` + envelope + `,"retry_after":null,"elapsed_ms":3}]}`)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// quietFixture: an estate with nothing standing and every stream answering.
func quietFixture() *alertsFixture {
	return &alertsFixture{
		standing: "",
		coverage: `["coverage",{"computed_at_ms":1756500000000,"endpoints":36,"sensor_shipping":34,` +
			`"sensor_slow":2,"sensor_stale":0,"sensor_absent":0,"tier_wireguard":20,"tier_socks":10,` +
			`"tier_resolver":6,"conn_online":30,"conn_idle":6,"conn_offline":0,"act_now_at":45.0,` +
			`"review_at":30.0,"open":0,"act_now":0,"review":0,"handled":0,"unscored":0,"unacknowledged":0}]`,
		agents:      `["agents",{"agent":"scout","address":"2a04:2a01:9::1","connectivity_status":"online","sensor":"shipping"}]`,
		audit:       "",
		suppressErr: 403,
	}
}

// busyFixture: one act-now ransomware detection nobody has, plus one review row somebody
// already took.
func busyFixture() *alertsFixture {
	f := quietFixture()
	f.standing = `["standing",{"agent":"scout","address":"2a04:2a01:9::1","id":"T1486","technique":"T1486",` +
		`"kind":"detection","title":"nine files were encrypted in 40 seconds","lane":"act-now","priority":61.0,` +
		`"fusedPriority":61.0,"exposure":"high","state":"open","firstSeen":1756499000000,"ageMs":1140000,` +
		`"confidence":1.0,"origin":"host","evidence":"{\"whatHappened\":\"held\"}","remediation":"",` +
		`"ack":"","ackAt":null,"assignee":""}],` +
		`["standing",{"agent":"runner-02","address":"2a04:2a01:9::2","id":"T1021.004","technique":"T1021.004",` +
		`"kind":"detection","title":"svc-backup opened SMB to three hosts it had never reached","lane":"review",` +
		`"priority":32.0,"fusedPriority":32.0,"exposure":"low","state":"open","firstSeen":1756480000000,` +
		`"ageMs":14400000,"confidence":0.8,"origin":"host","evidence":"","remediation":"","ack":"","ackAt":null,` +
		`"assignee":"operator-a"}]`
	f.coverage = `["coverage",{"computed_at_ms":1756500000000,"endpoints":36,"sensor_shipping":36,` +
		`"sensor_slow":0,"sensor_stale":0,"sensor_absent":0,"tier_wireguard":20,"tier_socks":10,` +
		`"tier_resolver":6,"conn_online":36,"conn_idle":0,"conn_offline":0,"act_now_at":45.0,` +
		`"review_at":30.0,"open":61,"act_now":1,"review":1,"handled":59,"unscored":0,"unacknowledged":2}]`
	f.agents = `["agents",{"agent":"scout","address":"2a04:2a01:9::1","connectivity_status":"online","sensor":"shipping"}],` +
		`["agents",{"agent":"runner-02","address":"2a04:2a01:9::2","connectivity_status":"online","sensor":"shipping"}]`
	return f
}

// runAlerts drives the REAL command tree from the root, the way a shell does.
//
// The endpoint and the key are passed as FLAGS rather than by poking the global: building
// the root command re-registers every persistent flag, and pflag writes each one's default
// back over the variable it is bound to. A test that set the global first would silently
// end up talking to the production control plane, which is exactly the class of probe that
// reports a defect that is not there.
func runAlerts(t *testing.T, srv *httptest.Server, argv ...string) (stdout, stderr string, err error) {
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

// The harness has to be shown to work before anything it reports can be believed. If the
// fixture were not actually reached, every assertion below would be measuring the live
// plane instead.
func TestAlertsFixture_TheHarnessReachesTheFixtureAndNotTheLivePlane(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	if _, _, err := runAlerts(t, srv, "alerts"); err != nil {
		t.Fatalf("whisper alerts against the fixture: %v", err)
	}
	if len(f.recorded()) == 0 {
		t.Fatal("the fixture recorded no calls; the harness is talking to something else")
	}
}

// runAlertsJSON is runAlerts with --json, which is a different rendering path.
func runAlertsJSON(t *testing.T, srv *httptest.Server, argv ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runAlerts(t, srv, append(argv, "--json")...)
}

// The wiring test. It fails if `alerts` stops being registered on the root command, which
// is the exact shape of the defect where a finished feature can never be reached.
func TestAlerts_IsReachableFromTheRootCommandAndItsAliases(t *testing.T) {
	names := map[string]bool{}
	for _, c := range NewRootCommand().Commands() {
		names[c.Name()] = true
		for _, a := range c.Aliases {
			names[a] = true
		}
	}
	for _, want := range []string{"alerts", "alert", "attention"} {
		if !names[want] {
			t.Fatalf("`whisper %s` is not registered; the surface ships unreachable", want)
		}
	}
}

// The ten-second answer, end to end: the real command, the real reads, the real block.
func TestAlerts_BriefReadsEveryStreamAndAnswersInOneBlock(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()

	out, errOut, err := runAlerts(t, srv, "alerts")
	if err != nil {
		t.Fatalf("whisper alerts: %v", err)
	}
	for _, must := range []string{
		"wants a decision",
		"act now",
		"scout/T1486",
		"review",
		"runner-02/T1021.004",
		"open        61 detections",
		"heard from  36 of 36 endpoints",
		"contained   nothing severed",
		"read        ",
	} {
		if !strings.Contains(out, must) {
			t.Fatalf("the answer is missing %q:\n%s", must, out)
		}
	}
	// The hint is commentary, not the answer.
	if strings.Contains(out, "whisper alerts show") {
		t.Fatalf("the next-command hint leaked into stdout:\n%s", out)
	}
	if !strings.Contains(errOut, "whisper alerts show scout/T1486") {
		t.Fatalf("the next command is missing from stderr:\n%s", errOut)
	}
	// All four op:list reads, plus the mute register, actually happened.
	calls := f.recorded()
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.op] = true
	}
	for _, want := range []string{"list:standing", "list:coverage", "list:agents", "list:audit", "partner:"} {
		if !seen[want] {
			t.Fatalf("the surface never read %q; calls = %v", want, calls)
		}
	}
}

// A quiet estate proves its quiet, and a broken pipeline says so instead. Against the real
// command, with a real fixture that faults.
func TestAlerts_AFaultedReadIsNeverRenderedAsQuiet(t *testing.T) {
	quiet := quietFixture()
	qsrv := quiet.server(t)
	defer qsrv.Close()
	quietOut, _, err := runAlerts(t, qsrv, "alerts")
	if err != nil {
		t.Fatalf("whisper alerts on a quiet estate: %v", err)
	}

	broken := quietFixture()
	broken.failKinds = map[string]int{"coverage": 500, "standing": 500}
	bsrv := broken.server(t)
	defer bsrv.Close()
	brokenOut, _, err := runAlerts(t, bsrv, "alerts")
	if err != nil {
		t.Fatalf("whisper alerts on a faulted read must still answer, got: %v", err)
	}

	if quietOut == brokenOut {
		t.Fatal("a quiet estate and a faulted read rendered identically")
	}
	if !strings.Contains(quietOut, "nothing is asking for you") || strings.Contains(quietOut, "floors") {
		t.Fatalf("the quiet render is wrong:\n%s", quietOut)
	}
	if !strings.Contains(brokenOut, "the counts above are floors") ||
		!strings.Contains(brokenOut, "coverage") || !strings.Contains(brokenOut, "detections") {
		t.Fatalf("a faulted read must name its streams and mark its counts as floors:\n%s", brokenOut)
	}
	for _, banned := range []string{"no threats detected", "all clear", "you are protected", "0 alerts"} {
		if strings.Contains(strings.ToLower(quietOut), banned) {
			t.Fatalf("the quiet render says %q:\n%s", banned, quietOut)
		}
	}
}

// The gate. Its exit code IS its output, and the three codes are three different answers.
func TestAlertsCheck_TheExitCodeIsTheAnswer(t *testing.T) {
	quiet := quietFixture()
	qsrv := quiet.server(t)
	defer qsrv.Close()
	out, _, err := runAlerts(t, qsrv, "alerts", "check")
	if err != nil {
		t.Fatalf("a quiet estate must exit 0, got: %v", err)
	}
	if out != "" {
		t.Fatalf("a passing gate must print nothing on stdout, got:\n%s", out)
	}

	busy := busyFixture()
	bsrv := busy.server(t)
	defer bsrv.Close()
	_, errOut, err := runAlerts(t, bsrv, "alerts", "check")
	if err == nil {
		t.Fatal("an open, unacknowledged act-now condition must trip the gate")
	}
	code, ok := exitCodeOf(err)
	if !ok || code != alertsExitGate {
		t.Fatalf("the gate exited %d (asked=%v); want %d", code, ok, alertsExitGate)
	}
	if !strings.Contains(errOut, "scout/T1486") {
		t.Fatalf("a tripped gate must name what tripped it:\n%s", errOut)
	}

	// And a gate that could not read must NOT pass, and must not look like a verdict.
	blind := quietFixture()
	blind.failKinds = map[string]int{"standing": 500}
	blindSrv := blind.server(t)
	defer blindSrv.Close()
	_, _, err = runAlerts(t, blindSrv, "alerts", "check")
	if err == nil {
		t.Fatal("a gate that could not read must never pass")
	}
	if _, asked := exitCodeOf(err); asked {
		t.Fatal("a failed read must exit 1 (could not tell), never the gate's verdict code")
	}
}

// Execute maps the gate's request to a real process exit code. Without this, the whole
// distinction lives in a type nobody reads.
func TestExecute_HonoursTheGateExitCode(t *testing.T) {
	busy := busyFixture()
	srv := busy.server(t)
	defer srv.Close()
	saved := g
	defer func() { g = saved }()

	savedArgs := os.Args
	defer func() { os.Args = savedArgs }()
	os.Args = []string{"whisper", "alerts", "check", "--control-url", srv.URL, "--key", "whisper_live_test"}

	// Execute() is the real process entry point: it builds the root command, runs it
	// against os.Args, and maps the result to an exit code. Anything short of calling it
	// would test the mapping in a copy of itself.
	var code int
	_, _ = captureStd(t, func() { code = Execute() })
	if code != alertsExitGate {
		t.Fatalf("Execute returned %d for a tripped gate; want %d", code, alertsExitGate)
	}
}

// --json on the single-op read is the plane's own envelope, verbatim: a script sees the
// columns the server sent, not a re-encoding of ours.
func TestAlertsList_JSONIsThePlanesOwnEnvelope(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	saved := g
	defer func() { g = saved }()

	out, _, err := runAlertsJSON(t, srv, "alerts", "list")
	if err != nil {
		t.Fatalf("whisper alerts list --json: %v", err)
	}
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			Columns []string `json:"columns"`
		} `json:"result"`
	}
	if e := json.Unmarshal([]byte(out), &env); e != nil {
		t.Fatalf("the envelope did not decode: %v\n%s", e, out)
	}
	if len(env.Result.Columns) != 2 || env.Result.Columns[0] != "kind" || env.Result.Columns[1] != "item" {
		t.Fatalf("the plane's own columns were not passed through: %v", env.Result.Columns)
	}
	// The documented pipe is `| jq '.result.columns'`, and on the live wire the op envelope
	// arrives inside a Cypher table whose OWN columns are op/ok/status/result/... Echoing
	// the carrier would satisfy "verbatim" and still read null at that path, so assert the
	// carrier is not what came out.
	var top map[string]any
	if e := json.Unmarshal([]byte(out), &top); e != nil {
		t.Fatalf("the emitted JSON did not decode: %v\n%s", e, out)
	}
	if _, carrier := top["elapsed_ms"]; !carrier {
		t.Errorf("the op envelope lost the plane's own fields:\n%s", out)
	}
	if cols, ok := top["columns"].([]any); ok && len(cols) > 0 && cols[0] == "op" {
		t.Errorf("the Cypher carrier was emitted instead of the op envelope it carries:\n%s", out)
	}
	// Byte-level: a decode-and-re-encode would turn the plane's 61.0 into 61.
	if !strings.Contains(out, "\"priority\":61.0") {
		t.Errorf("the plane's own bytes were re-encoded on the way out:\n%s", out)
	}
}

// The composite document is stable and says what it is, so a script can gate on it without
// parsing prose.
func TestAlerts_JSONDocumentCarriesItsVersionAndReadStatus(t *testing.T) {
	f := busyFixture()
	f.failKinds = map[string]int{"audit": 500}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runAlertsJSON(t, srv, "alerts")
	if err != nil {
		t.Fatalf("whisper alerts --json: %v", err)
	}
	var doc alerts.Document
	if e := json.Unmarshal([]byte(out), &doc); e != nil {
		t.Fatalf("the document did not decode: %v\n%s", e, out)
	}
	if doc.AlertVersion != alerts.AlertVersion {
		t.Fatalf("alert_version = %d, want %d", doc.AlertVersion, alerts.AlertVersion)
	}
	if doc.Complete {
		t.Fatal("a document with a failed stream must not claim to be complete")
	}
	var sawFailure bool
	for _, s := range doc.Streams {
		if s.Name == "containment" && s.Status == "failed" {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatalf("the failed stream is not declared in the document: %+v", doc.Streams)
	}
	if len(doc.Alerts) != 2 {
		t.Fatalf("the document carries %d alerts; want 2", len(doc.Alerts))
	}
	if doc.Alerts[0].Ref != "scout/T1486" || doc.Alerts[0].Interrupt != alerts.InterruptPage {
		t.Fatalf("the worst row is not first or is not paging: %+v", doc.Alerts[0])
	}
	if !doc.Alerts[0].NeverQuiet {
		t.Fatal("a ransomware detection must be marked never-quiet in the document")
	}
}

// THE lifecycle trace: a keystroke, resolved against the standing book, written through
// op:task with the address and the id the plane keys on. This test fails if that wiring is
// removed, which is the whole point of it.
func TestAlertsAck_WritesOneTaskAcknowledgeForTheResolvedRow(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runAlerts(t, srv, "alerts", "ack", "scout/T1486")
	if err != nil {
		t.Fatalf("whisper alerts ack: %v", err)
	}
	var writes []recordedCall
	for _, c := range f.recorded() {
		if strings.HasPrefix(c.op, "task") {
			writes = append(writes, c)
		}
	}
	if len(writes) != 1 {
		t.Fatalf("expected exactly one op:task write, got %d: %v", len(writes), writes)
	}
	for _, must := range []string{"op:'task'", "action:'acknowledge'", "address:'2a04:2a01:9::1'", "id:'T1486'"} {
		if !strings.Contains(writes[0].body, must) {
			t.Fatalf("the write is missing %q:\n%s", must, writes[0].body)
		}
	}
	if !strings.Contains(out, "acknowledged") || !strings.Contains(out, "still open") {
		t.Fatalf("the confirmation must say the row is still open:\n%s", out)
	}
}

// Postel on the target: every way a person writes the same row reaches the same write.
func TestAlertsAck_AcceptsEveryFormOfTheTarget(t *testing.T) {
	for _, target := range []string{
		"scout/T1486",
		"scout/t1486",
		"2a04:2a01:9::1/T1486",
		"2a04:2a01:9::1/128/T1486",
		"T1486",
		"scout",
	} {
		f := busyFixture()
		srv := f.server(t)
		if _, _, err := runAlerts(t, srv, "alerts", "ack", target); err != nil {
			srv.Close()
			t.Fatalf("ack %q: %v", target, err)
		}
		found := false
		for _, c := range f.recorded() {
			if strings.HasPrefix(c.op, "task") && strings.Contains(c.body, "id:'T1486'") {
				found = true
			}
		}
		srv.Close()
		if !found {
			t.Fatalf("ack %q did not reach the row it names", target)
		}
	}
}

// A typo is a sentence naming what was expected, never an opaque not_found from the plane -
// and nothing is written.
func TestAlertsAck_AnUnknownTargetWritesNothing(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runAlerts(t, srv, "alerts", "ack", "scoutt/T1486")
	if err == nil {
		t.Fatal("acknowledging a condition that is not standing must fail")
	}
	if !strings.Contains(err.Error(), "nothing standing matches") {
		t.Fatalf("the error must name what was expected, got: %v", err)
	}
	for _, c := range f.recorded() {
		if strings.HasPrefix(c.op, "task") {
			t.Fatalf("a mistyped target still reached the plane: %v", c)
		}
	}
}

// A read that did not answer must never become a write against a guess.
func TestAlertsAck_APartialReadWritesNothing(t *testing.T) {
	f := busyFixture()
	f.failKinds = map[string]int{"standing": 500}
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runAlerts(t, srv, "alerts", "ack", "scout/T1486")
	if err == nil {
		t.Fatal("a partial read must not be acknowledged through")
	}
	if !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("the refusal must say nothing was written, got: %v", err)
	}
	for _, c := range f.recorded() {
		if strings.HasPrefix(c.op, "task") {
			t.Fatalf("a write happened on a read we could not make: %v", c)
		}
	}
}

// Snooze on this plane hides a row until somebody reopens it: there is no wake-up time.
// The command has to say that out loud, because a control that promises a timer it does
// not have is a promise the product cannot keep.
func TestAlertsSnooze_SaysWhatItActuallyDoes(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	_, errOut, err := runAlerts(t, srv, "alerts", "snooze", "scout/T1486")
	if err != nil {
		t.Fatalf("whisper alerts snooze: %v", err)
	}
	if !strings.Contains(errOut, "no wake-up timer") {
		t.Fatalf("snooze must say it has no timer:\n%s", errOut)
	}
	if !strings.Contains(errOut, "whisper alerts reopen") {
		t.Fatalf("snooze must name the command that undoes it:\n%s", errOut)
	}
}

// --silent shows what is being carried quietly, and it REFUSES to hide a never-quiet
// technique. A filter that could bury ransomware because somebody asked for the quiet rows
// would be the tuning project this product exists not to need.
func TestAlertsList_SilentNeverHidesANeverQuietTechnique(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	out, _, err := runAlerts(t, srv, "alerts", "list", "--silent")
	if err != nil {
		t.Fatalf("whisper alerts list --silent: %v", err)
	}
	if !strings.Contains(out, "scout/T1486") {
		t.Fatalf("--silent hid a ransomware detection:\n%s", out)
	}
}

// A mute register the caller has no access to is a definite answer, not a fault: nothing
// can be holding quiet, and no count becomes a floor because of it.
func TestAlertsMuteList_NoRegisterIsAnAnswerNotAFault(t *testing.T) {
	f := quietFixture()
	srv := f.server(t)
	defer srv.Close()
	out, _, err := runAlerts(t, srv, "alerts", "mute", "list")
	if err != nil {
		t.Fatalf("whisper alerts mute list: %v", err)
	}
	if !strings.Contains(out, "nothing is holding quiet") {
		t.Fatalf("a scope refusal must read as an answer:\n%s", out)
	}
}

// show ends with the commands that do something, and none of them is a new containment
// verb: the response ladder stays the one that already exists.
func TestAlertsShow_EndsWithCommandsThatExist(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	out, errOut, err := runAlerts(t, srv, "alerts", "show", "scout/T1486")
	if err != nil {
		t.Fatalf("whisper alerts show: %v", err)
	}
	for _, slot := range []string{"WHAT HAPPENED", "WHY WE THINK SO", "WHAT IS TRUE NOW", "WHAT TO DO"} {
		if !strings.Contains(out, slot) {
			t.Fatalf("the fixed slot %q is missing:\n%s", slot, out)
		}
	}
	have := map[string]bool{}
	for _, c := range NewRootCommand().Commands() {
		have[c.Name()] = true
		for _, a := range c.Aliases {
			have[a] = true
		}
	}
	found := 0
	for _, line := range strings.Split(errOut, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "whisper ") {
			continue
		}
		found++
		verb := strings.Fields(line)[1]
		if !have[verb] {
			t.Fatalf("show offers `whisper %s`, which this binary does not have", verb)
		}
	}
	if found < 2 {
		t.Fatalf("show must end with the commands that do something, found %d:\n%s", found, errOut)
	}
}
