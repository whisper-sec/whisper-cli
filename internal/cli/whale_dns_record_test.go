// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// whale_dns_record_test.go proves the PRODUCTION path of `whisper whale dns record`
// item 10), and it proves it two levels down from the root, which is where a
// broken AddCommand orphans a whole without breaking anything that compiles.

type recordFixture struct {
	list   string // rows for op:list{kind:'records'}
	write  string // rows for op:host (statuses are the live lowercase forms: upserted / deleted / not_found)
	refuse string // when set, op:host answers 400 with this detail (a JSON string)

	mu    sync.Mutex
	calls []recordedCall
}

func (f *recordFixture) recorded() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

func (f *recordFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		op := "unknown"
		switch {
		case strings.Contains(body, "op:'host'"):
			op = "host"
		case strings.Contains(body, "op:'list'"):
			op = "list"
		}
		f.mu.Lock()
		f.calls = append(f.calls, recordedCall{op: op, body: body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if op == "host" {
			if f.refuse != "" {
				_, _ = w.Write(carried("host", `"ok":false,"status":400,"result":null,`+
					`"error":{"code":"BAD_ARGS","status":400,"detail":`+f.refuse+`}`))
				return
			}
			_, _ = w.Write(carried("host", `"ok":true,"status":200,"result":{"columns":`+
				`["record_id","fqdn","type","value","ttl","status"],"rows":[`+f.write+`]},"error":null`))
			return
		}
		_, _ = w.Write(carried("list", `"ok":true,"status":200,"result":{"columns":["kind","item"],`+
			`"rows":[`+f.list+`]},"error":null`))
	}))
}

func runRecord(t *testing.T, srv *httptest.Server, argv ...string) (stdout, stderr string, err error) {
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

func TestWhaleDNSRecordIsReachableTwoLevelsDownFromTheRoot(t *testing.T) {
	f := &recordFixture{list: `["records",{"record_id":"rec-1","fqdn":"api","type":"CNAME",` +
		`"value":"db-01.t9ab.agents.whisper.online.","ttl":300}]`}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runRecord(t, srv, "whale", "dns", "record", "list")
	if err != nil {
		t.Fatalf("record list failed: %v", err)
	}
	for _, want := range []string{"api", "CNAME", "300", "db-01.t9ab.agents.whisper.online."} {
		if !strings.Contains(out, want) {
			t.Fatalf("the record table is missing %q:\n%s", want, out)
		}
	}
	calls := f.recorded()
	if len(calls) != 1 || calls[0].op != "list" {
		t.Fatalf("list must be exactly one op:list, got %+v", calls)
	}
	if !strings.Contains(calls[0].body, "kind:'records'") {
		t.Fatalf("the wrong kind was asked for: %s", calls[0].body)
	}
}

func TestWhaleDNSRecordListSaysSoWhenYouPublishNothing(t *testing.T) {
	f := &recordFixture{}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runRecord(t, srv, "whale", "dns", "record", "list")
	if err != nil {
		t.Fatalf("an empty namespace is an answer, not an error: %v", err)
	}
	if !strings.Contains(out+stderr, "you publish no records") {
		t.Fatalf("an empty list must say so:\n%s", out+stderr)
	}
	// And it must not leave the reader thinking their node names went missing.
	if !strings.Contains(out+stderr, "identity plane") {
		t.Fatalf("an empty list must say where the node names are:\n%s", out+stderr)
	}
}

func TestWhaleDNSRecordSetSendsWhatWasTypedWithTheTypeUppercased(t *testing.T) {
	f := &recordFixture{write: `["rec-1","api","CNAME","db-01.t9ab.agents.whisper.online.",300,"upserted"]`}
	srv := f.server(t)
	defer srv.Close()

	out, _, err := runRecord(t, srv, "whale", "dns", "record", "set",
		"api", "cname", "db-01.t9ab.agents.whisper.online.", "--ttl", "300")
	if err != nil {
		t.Fatalf("set failed: %v", err)
	}
	calls := f.recorded()
	if len(calls) != 1 || calls[0].op != "host" {
		t.Fatalf("set must be exactly one op:host, got %+v", calls)
	}
	var sent struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(calls[0].body), &sent); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name:'api'", "type:'CNAME'", "ttl:300",
		"value:'db-01.t9ab.agents.whisper.online.'"} {
		if !strings.Contains(sent.Query, want) {
			t.Fatalf("the write did not carry %q: %s", want, sent.Query)
		}
	}
	if !strings.Contains(out, "upserted") {
		t.Fatalf("the control plane's own result must be reported:\n%s", out)
	}
}

// TestWhaleDNSRecordSetWithoutTtlLetsTheZoneDecide: an unset flag must never be sent, or
// every write would silently stamp the zone default onto records that had their own.
func TestWhaleDNSRecordSetWithoutTtlLetsTheZoneDecide(t *testing.T) {
	f := &recordFixture{write: `["rec-1","api","TXT","hello",0,"upserted"]`}
	srv := f.server(t)
	defer srv.Close()

	if _, _, err := runRecord(t, srv, "whale", "dns", "record", "set", "api", "TXT", "hello"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if strings.Contains(f.recorded()[0].body, "ttl:") {
		t.Fatalf("an unset --ttl must not ride the write: %s", f.recorded()[0].body)
	}
}

// TestWhaleDNSRecordRefusalsBelongToTheControlPlane is the acceptance row for refusals. Each of
// these three names is refused by a rule the box owns, and the verb's whole job is to let
// that sentence through intact rather than keeping a second copy of the rule.
func TestWhaleDNSRecordRefusalsBelongToTheControlPlane(t *testing.T) {
	// The detail strings are the ones the control plane really sends, captured by running
	// exactly these four commands against it. A fixture that invented friendlier sentences
	// would pass here and prove nothing about the server.
	cases := []struct {
		name, rtype, detail, want string
	}{
		{"*", "AAAA", `"wildcard owners are not allowed"`, "wildcard owners are not allowed"},
		{"@", "AAAA",
			`"cannot write the tenant subtree apex: t9ab.agents.whisper.online."`,
			"tenant subtree apex"},
		{"_whisper-agentkey", "TXT",
			`"_whisper-agentkey records are published by the identity plane itself (the agent's ` +
				`verification key, minted together with its DANE-EE pin) and cannot be set or deleted with op:host"`,
			"identity plane itself"},
		{"db-01", "CNAME",
			`"db-01.t9ab.agents.whisper.online. is the member name of a registered agent - an alias ` +
				`the identity plane maintains pointing at that agent's canonical name"`,
			"member name of a registered agent"},
	}
	for _, c := range cases {
		f := &recordFixture{refuse: c.detail}
		srv := f.server(t)
		out, stderr, err := runRecord(t, srv, "whale", "dns", "record", "set", c.name, c.rtype, "x")
		srv.Close()
		if err == nil {
			t.Fatalf("%s must be refused, not published", c.name)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("the control plane's reason for %s did not reach the terminal (%q): %v",
				c.name, c.want, err)
		}
		// Never a 500, and never our own invented sentence in place of theirs.
		if strings.Contains(out+stderr, "panic") {
			t.Fatalf("a refusal must be a clean message: %s", out+stderr)
		}
	}
}

func TestWhaleDNSRecordDeleteOfSomethingAbsentIsNotAFailure(t *testing.T) {
	f := &recordFixture{write: `["","api","CNAME",null,0,"not_found"]`}
	srv := f.server(t)
	defer srv.Close()

	out, stderr, err := runRecord(t, srv, "whale", "dns", "record", "delete", "api", "cname")
	if err != nil {
		t.Fatalf("deleting what is not there must be safe to repeat: %v", err)
	}
	if !strings.Contains(f.recorded()[0].body, "delete:true") {
		t.Fatalf("the delete flag did not ride the call: %s", f.recorded()[0].body)
	}
	// The report must be the control plane's word, not ours: saying "removed" here costs
	// somebody an hour when the record they meant is still resolving.
	if !strings.Contains(out+stderr, "not_found") || !strings.Contains(out+stderr, "Nothing was there") {
		t.Fatalf("a NOT_FOUND must be reported as itself:\n%s", out+stderr)
	}
}
