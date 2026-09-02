// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// deepentui_control spins an httptest control plane that answers every POST with the
// given status + JSON body, records the last query text, and returns a keyed client
// pointed at it. The server closes with the test.
func deepentui_control(t *testing.T, status int, body string) (*client.Client, *string) {
	t.Helper()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if q, ok := req["query"].(string); ok {
			lastQuery = q
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := client.New(client.Config{
		ControlURL: srv.URL,
		MonitorURL: srv.URL + "/monitor",
		Cred:       client.Credential{Value: "whisper-0000000000000000"},
		HTTPClient: srv.Client(),
	})
	return c, &lastQuery
}

// deepentui_env wraps a result table in the dev-guide envelope shape.
func deepentui_env(columns string, rows string) string {
	return `{"ok":true,"status":200,"result":{"columns":[` + columns + `],"rows":[` + rows + `]}}`
}

// TestLoadFleetMapsAndSorts runs op:list against a live-shaped reply: item rows map to
// Agents, key-less rows are skipped, and the fleet sorts created-desc.
func TestLoadFleetMapsAndSorts(t *testing.T) {
	c, lastQ := deepentui_control(t, 200, deepentui_env(`"item"`,
		`[{"agent":"old","address":"2a04:2a01::1","label":"old","created":100}],`+
			`[{"agent":"new","address":"2a04:2a01::2","label":"new","created":900}],`+
			`[{"label":"keyless-row-skipped"}]`))
	msg := loadFleet(c)().(fleetMsg)
	if msg.err != nil {
		t.Fatalf("fleet load failed: %v", msg.err)
	}
	if len(msg.agents) != 2 {
		t.Fatalf("a key-less row must be skipped; got %d agents", len(msg.agents))
	}
	if msg.agents[0].ID != "new" || msg.agents[1].ID != "old" {
		t.Errorf("fleet must sort created-desc; got %s,%s", msg.agents[0].ID, msg.agents[1].ID)
	}
	if !strings.Contains(*lastQ, "whisper.agents") || !strings.Contains(*lastQ, "'list'") {
		t.Errorf("the wire query should be the op:list call; got %q", *lastQ)
	}
}

// TestLoadFleetErrors covers the ok:false problem and the transport failure.
func TestLoadFleetErrors(t *testing.T) {
	c, _ := deepentui_control(t, 403, `{"ok":false,"status":403,"error":{"status":403,"detail":"scope denied"}}`)
	msg := loadFleet(c)().(fleetMsg)
	if msg.err == nil || !strings.Contains(msg.err.Error(), "scope denied") {
		t.Errorf("an ok:false reply must surface its detail; got %v", msg.err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := client.New(client.Config{ControlURL: srv.URL,
		Cred: client.Credential{Value: "whisper-0000000000000000"}, HTTPClient: srv.Client()})
	srv.Close()
	if msg := loadFleet(dead)().(fleetMsg); msg.err == nil {
		t.Error("a transport failure must come back as an error, never an empty fleet")
	}
}

// TestLoadAgentDetailMergesAndNarrows asserts the detail op narrows by address when the
// agent has one (id otherwise) and merges the counters into the agent.
func TestLoadAgentDetailMergesAndNarrows(t *testing.T) {
	c, lastQ := deepentui_control(t, 200, deepentui_env(
		`"agent","address","dns_queries","dns_blocked","bytes_up"`,
		`["a1","2a04:2a01::1",1200,34,4096]`))
	base := model.Agent{ID: "a1", Address: "2a04:2a01::1", Label: "scraper"}
	msg := loadAgentDetail(c, base)().(agentDetailMsg)
	if msg.err != nil {
		t.Fatalf("detail load failed: %v", msg.err)
	}
	if msg.key != base.Key() {
		t.Errorf("the reply must carry the agent key for the stale-select guard; got %q", msg.key)
	}
	if !msg.agent.Detailed || msg.agent.DNSQueries != 1200 || msg.agent.DNSBlocked != 34 {
		t.Errorf("counters must merge: %+v", msg.agent)
	}
	if msg.agent.Label != "scraper" {
		t.Error("the merge must keep known summary fields")
	}
	if !strings.Contains(*lastQ, "address") {
		t.Errorf("an addressed agent narrows by address; query %q", *lastQ)
	}

	// An address-less agent narrows by id.
	_ = loadAgentDetail(c, model.Agent{ID: "only-id"})()
	if !strings.Contains(*lastQ, "agent") || strings.Contains(*lastQ, "address") {
		t.Errorf("an address-less agent narrows by id; query %q", *lastQ)
	}
}

// TestLoadLogsAndPolls maps op:logs rows to events for all three read paths (LOGS query,
// backfill, poll) and carries the token / error contract of each.
func TestLoadLogsAndPolls(t *testing.T) {
	body := deepentui_env(`"ts","kind","qname","decision","peer","bytes_up","bytes_down"`,
		`[1700000000000,"dns","x.example.","block",null,0,0],`+
			`[1700000000500,"conn",null,null,"9.9.9.9:443",10,20]`)

	c, _ := deepentui_control(t, 200, body)
	lm := loadLogs(c, map[string]any{"limit": 5}, 7)().(logsMsg)
	if lm.err != nil || lm.token != 7 || len(lm.events) != 2 {
		t.Fatalf("loadLogs contract broken: %+v", lm)
	}
	if lm.events[0].QName != "x.example." || lm.events[0].Decision != "block" {
		t.Errorf("dns row mapped wrong: %+v", lm.events[0])
	}
	if lm.events[1].PeerHost != "9.9.9.9" || lm.events[1].PeerPort != 443 {
		t.Errorf("the peer column must split host:port: %+v", lm.events[1])
	}

	bm := loadMonitorBackfill(c, "2a04:2a01::1", "-15m", 3)().(monitorBackfillMsg)
	if bm.err != nil || bm.token != 3 || len(bm.events) != 2 {
		t.Fatalf("backfill contract broken: %+v", bm)
	}

	pm := loadMonitorPoll(c, "", "-2m")().(monitorPollMsg)
	if pm.err != nil || len(pm.events) != 2 {
		t.Fatalf("poll contract broken: %+v", pm)
	}

	// The error paths carry the problem through.
	ce, _ := deepentui_control(t, 500, `{"ok":false,"status":500,"error":{"status":500,"detail":"warm store sad"}}`)
	if m := loadLogs(ce, nil, 1)().(logsMsg); m.err == nil || m.token != 1 {
		t.Error("loadLogs must keep the token on error")
	}
	if m := loadMonitorBackfill(ce, "", "-15m", 9)().(monitorBackfillMsg); m.err == nil || m.token != 9 {
		t.Error("backfill must keep the token on error")
	}
	if m := loadMonitorPoll(ce, "", "-2m")().(monitorPollMsg); m.err == nil {
		t.Error("poll must surface the error")
	}
}

// TestLoadPolicyAndRunWrite covers the policy read-back mapping and the generic write
// (summary = first row; the ok:false error keeps the envelope).
func TestLoadPolicyAndRunWrite(t *testing.T) {
	c, _ := deepentui_control(t, 200, deepentui_env(`"key","value"`,
		`["default","allow"],["block","ads.example"]`))
	pm := loadPolicy(c)().(policyMsg)
	if pm.err != nil || len(pm.rows) != 2 {
		t.Fatalf("policy read-back broken: %+v", pm)
	}
	if pm.rows[0].Key != "default" || pm.rows[1].Value != "ads.example" {
		t.Errorf("policy rows mapped wrong: %+v", pm.rows)
	}

	wc, _ := deepentui_control(t, 200, deepentui_env(`"agent","address"`, `["a9","2a04:2a01::9"]`))
	wm := runWrite(wc, "identity", map[string]any{"label": "x"})().(writeResultMsg)
	if wm.err != nil || wm.op != "identity" {
		t.Fatalf("write contract broken: %+v", wm)
	}
	if wm.summary["address"] != "2a04:2a01::9" {
		t.Errorf("the summary must be the first row, column-keyed: %v", wm.summary)
	}

	we, _ := deepentui_control(t, 409, `{"ok":false,"status":409,"error":{"status":409,"detail":"name taken"}}`)
	if m := runWrite(we, "register", nil)().(writeResultMsg); m.err == nil || m.env == nil {
		t.Error("a failed write must keep both the error and the envelope")
	}
}

// TestLgEnrichASNFailOpen covers the one-round-trip ASN enrichment: a hit, an honest
// empty miss, and a transport error that folds as a miss (never load-bearing).
func TestLgEnrichASNFailOpen(t *testing.T) {
	hit, _ := deepentui_control(t, 200,
		`{"columns":["asn","org"],"rows":[{"asn":"AS13335","org":"Cloudflare, Inc."}],"statistics":{"rowCount":1}}`)
	m := lgEnrichASN(hit, "162.159.140.245")().(lgAsnMsg)
	if m.asn != "AS13335" || m.org != "Cloudflare, Inc." || m.ip != "162.159.140.245" {
		t.Errorf("ASN hit mapped wrong: %+v", m)
	}

	empty, _ := deepentui_control(t, 200, `{"columns":["asn","org"],"rows":[]}`)
	if m := lgEnrichASN(empty, "10.0.0.1")().(lgAsnMsg); m.asn != "" || m.ip != "10.0.0.1" {
		t.Errorf("an unknown IP folds as an honest miss: %+v", m)
	}

	sad, _ := deepentui_control(t, 500, `{"status":500,"detail":"graph sad"}`)
	if m := lgEnrichASN(sad, "10.0.0.2")().(lgAsnMsg); m.asn != "" {
		t.Errorf("an errored enrichment folds as a miss: %+v", m)
	}
}

// TestEnvErrBranches pins the envelope-to-error mapping.
func TestEnvErrBranches(t *testing.T) {
	if err := envErr(nil); err == nil || !strings.Contains(err.Error(), "empty control-plane reply") {
		t.Errorf("a nil envelope is a 502 problem; got %v", err)
	}
	if err := envErr(&client.Envelope{Ok: true}); err != nil {
		t.Errorf("an ok envelope yields nil; got %v", err)
	}
	pe := &client.ProblemError{Status: 403, Detail: "denied"}
	if err := envErr(&client.Envelope{Ok: false, Err: pe}); err != pe {
		t.Errorf("the server's own problem must pass through; got %v", err)
	}
	err := envErr(&client.Envelope{Ok: false, Status: 500})
	if err == nil || !strings.Contains(err.Error(), "control plane reported failure") {
		t.Errorf("ok:false without a problem synthesises one; got %v", err)
	}
}

// TestAsStrRendering pins the display renderer for every decoded JSON kind.
func TestAsStrRendering(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"x", "x"},
		{true, "true"},
		{false, "false"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
		{json.Number("977"), "977"},
		{map[string]any{"a": float64(1)}, `{"a":1}`},
	}
	for _, tc := range cases {
		if got := asStr(tc.in); got != tc.want {
			t.Errorf("asStr(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestTickDelivers proves the 4Hz tick command actually delivers a tickMsg.
func TestTickDelivers(t *testing.T) {
	if _, ok := tick()().(tickMsg); !ok {
		t.Error("tick must deliver a tickMsg")
	}
}

// --- App.Update routing + fleet folding ---------------------------------------------

// TestUpdateFleetAndDetailFold folds a fleet reply then a detail reply through Update
// and asserts the merge + the detail request wiring.
func TestUpdateFleetAndDetailFold(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.loading = true
	_, cmd := a.Update(fleetMsg{agents: []model.Agent{
		{ID: "a1", Address: "2a04:2a01::1", Label: "one", Created: 2},
	}})
	if a.loading {
		t.Error("a fleet reply clears loading")
	}
	if len(a.agents) != 1 {
		t.Fatalf("fleet not installed: %v", a.agents)
	}
	if cmd == nil {
		t.Error("an un-enriched selection should fire its detail load")
	}

	// The detail folds onto the matching entry.
	enriched := a.agents[0]
	enriched.Detailed = true
	enriched.DNSQueries = 777
	a.Update(agentDetailMsg{key: enriched.Key(), agent: enriched})
	if !a.agents[0].Detailed || a.agents[0].DNSQueries != 777 {
		t.Errorf("the detail must fold into the fleet: %+v", a.agents[0])
	}

	// A detail error is silently dropped (reads fail open).
	a.Update(agentDetailMsg{key: enriched.Key(), err: &client.ProblemError{Status: 500}})
	if a.agents[0].DNSQueries != 777 {
		t.Error("an errored detail must not clobber the fleet")
	}

	// An errored fleet reply keeps the last-known roster and toasts.
	a.Update(fleetMsg{err: &client.ProblemError{Status: 502, Detail: "list down"}})
	if len(a.agents) != 1 || !strings.Contains(a.toast, "list down") {
		t.Error("a fleet error fails open with a toast")
	}
}

// TestMergeFleetPreservesEnrichment is the adjacent contract: a refresh must keep
// already-fetched counters, refresh the summary fields, retain stream-discovered agents,
// and re-derive the tenant handle from the fleet itself.
func TestMergeFleetPreservesEnrichment(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.agents = []model.Agent{
		{ID: "a1", Address: "2a04:2a01::1", Label: "old-label", State: "active",
			Detailed: true, DNSQueries: 500, Contact: "ops@example.org"},
		{ID: "ghost", Address: "2a04:2a01::f", State: "active", SeenInStream: true},
	}
	a.selected = 0
	a.mergeFleet([]model.Agent{
		{ID: "a1", Address: "2a04:2a01::1", Label: "new-label", State: "released", Created: 9},
		{ID: "a2", Address: "2a04:2a01::2", State: "active",
			FQDN: "a2.t0123456789.agents.whisper.agents."},
	})
	if len(a.agents) != 3 {
		t.Fatalf("the stream-only agent must survive the merge: %v", a.agents)
	}
	got := a.agents[0]
	if got.DNSQueries != 500 || !got.Detailed {
		t.Error("enriched counters must survive a refresh")
	}
	if got.Label != "new-label" || got.State != "released" {
		t.Error("summary fields must refresh from the list")
	}
	if got.Contact != "ops@example.org" {
		t.Error("an empty fresh contact must not clobber the known one")
	}
	if a.opts.Tenant != "t0123456789" {
		t.Errorf("the tenant should derive from the fleet's fqdn; got %q", a.opts.Tenant)
	}

	// Selection clamps when the fleet shrinks under it.
	a.selected = 5
	a.mergeFleet(nil)
	if a.selected != 0 {
		t.Errorf("selection must clamp into the merged fleet; got %d", a.selected)
	}
}

// TestUpsertStreamAgentNoPhantoms is the phantom-row contract: an event carrying
// only ONE of the two handles must still collapse onto the roster entry.
func TestUpsertStreamAgentNoPhantoms(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.agents = []model.Agent{{ID: "a1", Address: "2a04:2a01::1", State: "active"}}
	a.upsertStreamAgent("", "")
	a.upsertStreamAgent("", "a1")             // id-only: matches by ID
	a.upsertStreamAgent("2a04:2a01::1", "")   // addr-only: matches by Address
	a.upsertStreamAgent("2a04:2a01::1", "a1") // both: matches by Key
	if len(a.agents) != 1 {
		t.Fatalf("no event shape may mint a duplicate row; fleet=%v", a.agents)
	}
	a.upsertStreamAgent("2a04:2a01::9", "a9")
	if len(a.agents) != 2 || !a.agents[1].SeenInStream || a.agents[1].State != "active" {
		t.Errorf("a genuinely new agent unions in as stream-discovered: %v", a.agents)
	}
}

// TestSelectedAgentBounds pins the selection accessor at its edges.
func TestSelectedAgentBounds(t *testing.T) {
	a := newTestApp(t, 100, 30)
	if _, ok := a.SelectedAgent(); ok {
		t.Error("an empty fleet has no selection")
	}
	deepentui_seedAgents(a)
	a.selected = -1
	if _, ok := a.SelectedAgent(); ok {
		t.Error("a negative index has no selection")
	}
	a.selected = 1
	if sel, ok := a.SelectedAgent(); !ok || sel.ID != "agent-2" {
		t.Errorf("the selection should read through: %+v", sel)
	}
}

// TestFriendlyErr prefers the RFC-7807 detail and falls back to Error().
func TestFriendlyErr(t *testing.T) {
	pe := &client.ProblemError{Status: 429, Detail: "slow down"}
	if got := friendlyErr(pe); !strings.Contains(got, "slow down") {
		t.Errorf("a problem error renders its detail: %q", got)
	}
	if got := friendlyErr(errors.New("plain failure")); got != "plain failure" {
		t.Errorf("a plain error renders its message: %q", got)
	}
}

// TestUpdateSmallMessages covers the small Update arms: toast, pollFire, lgAsn.
func TestUpdateSmallMessages(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.Update(toastMsg{text: "hi there", isErr: false})
	if a.toast != "hi there" || a.toastErr {
		t.Error("toastMsg should set the toast")
	}

	// pollFire while the stream is back: disarm, no new poll.
	a.stream = streamConn
	a.pollArmed = true
	_, cmd := a.Update(pollFireMsg{addr: ""})
	if a.pollArmed || cmd != nil {
		t.Error("a reconnected stream must disarm the poll chain")
	}
	// pollFire while still down: a fresh poll command.
	a.stream = streamRetry
	if _, cmd = a.Update(pollFireMsg{addr: ""}); cmd == nil {
		t.Error("a down stream must keep polling")
	}

	// An ASN reply folds into the live graph and re-drains the queue.
	a.lgraph.queued["9.9.9.9"] = true
	a.lgraph.inFlight = 1
	a.Update(lgAsnMsg{ip: "9.9.9.9", asn: "AS19281", org: "Quad9"})
	if got, ok := a.lgraph.asn["9.9.9.9"]; !ok || got.ASN != "AS19281" {
		t.Errorf("the ASN fold must land in the graph cache: %+v", got)
	}
}

// TestGraphEnrichCmdKeyedOnly asserts enrichment never fires keyless, fires once per
// queued IP with a key, and goes quiet when the queue drains.
func TestGraphEnrichCmdKeyedOnly(t *testing.T) {
	a := newTestApp(t, 100, 30) // keyless
	a.foldEvent(model.Event{Kind: "conn", TsMicros: 1, Addr128: "2a04:2a01::1",
		PeerHost: "198.51.100.7", PeerPort: 443}, true)
	if a.graphEnrichCmd() != nil {
		t.Fatal("keyless enrichment must stay off (the graph is keyed-only)")
	}

	kc := client.New(client.Config{Cred: client.Credential{Value: "whisper-0000000000000000"}})
	b := New(Options{Client: kc, ThemeName: a.th.Name, Version: "test"})
	b.foldEvent(model.Event{Kind: "conn", TsMicros: 1, Addr128: "2a04:2a01::1",
		PeerHost: "198.51.100.7", PeerPort: 443}, true)
	if b.graphEnrichCmd() == nil {
		t.Fatal("a keyed client with a queued IP must fire the enrichment")
	}
	if b.graphEnrichCmd() != nil {
		t.Error("a drained queue fires nothing")
	}
}

// TestInitWiresLaunch asserts Init returns the launch batch, arms the stream channel,
// and a keyless EXPLORE launch lands the honest fixture demo.
func TestInitWiresLaunch(t *testing.T) {
	a := newTestApp(t, 100, 30)
	if a.Init() == nil {
		t.Error("Init must return the launch commands")
	}
	if a.streamCh == nil {
		t.Error("Init must arm the stream channel")
	}
	a.stopStream()

	b := New(Options{Client: client.New(client.Config{}), ThemeName: a.th.Name, StartOnExplore: true, Version: "test"})
	if b.Init() == nil {
		t.Error("an EXPLORE launch still returns the batch")
	}
	if b.exploreVw.deck.focus.Value == "" {
		t.Error("a keyless EXPLORE launch must land the fixture deck at Init")
	}
	if !strings.Contains(b.toast, "fixture demo") {
		t.Errorf("keyless EXPLORE must say it is the demo; toast=%q", b.toast)
	}
	b.stopStream()
}
