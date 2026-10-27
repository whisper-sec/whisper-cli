// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// `whisper domain status/list/submit` printed "no agents yet" and exited 0, because
// every reply went through renderFleet, the agent-table renderer, whatever its shape.
//
// The golden tests run the REAL sub-command, end to end through the client and the
// envelope decoder, against a server answering with a recorded reply. status_verified.json
// is the live capture of `whisper domain status everwatch.io --json` from 2026-10-20 (CLI
// 0.228.0); the others are built from the control plane's own row vocabulary and wording
// for op:domain's submit, status and list replies.
//
// Regenerate the goldens after a deliberate output change with:
//
//	WHISPER_UPDATE_GOLDEN=1 go test ./internal/cli -run TestDomainGolden

// domainServer answers every control call with the bytes of one fixture.
func domainServer(t *testing.T, fixture string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "domain", fixture))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return domainServerBody(t, body)
}

func domainServerBody(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(body)
	}))
}

// runDomain runs `whisper domain <args...>` against srv and returns what it printed.
func runDomain(t *testing.T, srv *httptest.Server, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", quiet: true, noColor: true, timeout: 5 * time.Second}
	defer func() { g = savedG }()
	stdout, stderr = captureStd(t, func() {
		cmd := newDomainCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs(args)
		err = cmd.Execute()
	})
	return stdout, stderr, err
}

func TestDomainGolden(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		args    []string
		wantErr bool
	}{
		{"submit_pending", "submit_pending.json", []string{"submit", "everwatch.io"}, false},
		{"submit_verified", "submit_verified.json", []string{"submit", "everwatch.io"}, false},
		{"status_verified", "status_verified.json", []string{"status", "everwatch.io"}, false},
		{"status_pending", "status_pending.json", []string{"status", "everwatch.io"}, false},
		{"status_never_observed", "status_never_observed.json", []string{"status", "everwatch.io"}, false},
		{"status_unknown", "status_unknown.json", []string{"status", "nothere.example"}, true},
		{"status_pending_check", "status_pending.json", []string{"status", "everwatch.io", "--check"}, true},
		{"status_verified_check", "status_verified.json", []string{"status", "everwatch.io", "--check"}, false},
		{"list", "list.json", []string{"list"}, false},
		{"list_empty", "list_empty.json", []string{"list"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := domainServer(t, c.fixture)
			defer srv.Close()
			stdout, stderr, err := runDomain(t, srv, c.args...)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v\nstdout:\n%s\nstderr:\n%s", err, c.wantErr, stdout, stderr)
			}
			var got bytes.Buffer
			got.WriteString(stdout)
			got.WriteString("--- stderr ---\n")
			got.WriteString(stderr)
			if err != nil {
				got.WriteString("--- error ---\n")
				got.WriteString(friendly(err) + "\n")
			}
			path := filepath.Join("testdata", "domain", c.name+".golden")
			if os.Getenv("WHISPER_UPDATE_GOLDEN") == "1" {
				if werr := os.WriteFile(path, got.Bytes(), 0o644); werr != nil {
					t.Fatal(werr)
				}
				return
			}
			want, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("read golden (regenerate with WHISPER_UPDATE_GOLDEN=1): %v", rerr)
			}
			if got.String() != string(want) {
				t.Fatalf("output differs from %s\n--- got ---\n%s--- want ---\n%s", path, got.String(), want)
			}
		})
	}
}

// The assertions the goldens encode, stated on their own so a regenerated golden cannot
// quietly lose them.

func TestDomainStatus_VerifiedShowsWhatWeObserved(t *testing.T) {
	srv := domainServer(t, "status_verified.json")
	defer srv.Close()
	stdout, _, err := runDomain(t, srv, "status", "everwatch.io")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"everwatch.io  verified",
		"ns1.whisper.online", "ns2.whisper.online",
		"61903 13 2 DC1DFA1AE92A8B25F7F74970551C85092A12C2DBC23763C00EFB8CBAAB6F6917",
		"served here", "yes",
		"parent DS TTL", "3600s",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "pending:") || strings.Contains(stdout, "also:") {
		t.Errorf("a verified domain has nothing to do:\n%s", stdout)
	}
}

func TestDomainStatus_PendingSaysWhyAndWhatToDo(t *testing.T) {
	srv := domainServer(t, "status_pending.json")
	defer srv.Close()
	stdout, _, err := runDomain(t, srv, "status", "everwatch.io")
	if err != nil {
		t.Fatalf("a pending domain is an answer, not a failure: exit 0 without --check; err=%v", err)
	}
	if !strings.Contains(stdout, "pending: we looked at your parent and it publishes no DS") {
		t.Errorf("the output must lead with 'pending: <reason>':\n%s", stdout)
	}
	if strings.Count(stdout, "\n  also: ") != 1 || !strings.Contains(stdout, "also: DNSSEC delegation chain") {
		t.Errorf("every further gap must be its own line:\n%s", stdout)
	}
}

func TestDomainStatus_CheckExitsNonZeroOnlyWhenNotVerified(t *testing.T) {
	pending := domainServer(t, "status_pending.json")
	defer pending.Close()
	if _, _, err := runDomain(t, pending, "status", "everwatch.io", "--check"); err == nil ||
		!strings.Contains(err.Error(), "everwatch.io is pending") {
		t.Fatalf("--check on a pending domain must fail naming the state; err=%v", err)
	}
	verified := domainServer(t, "status_verified.json")
	defer verified.Close()
	if _, _, err := runDomain(t, verified, "status", "everwatch.io", "--check"); err != nil {
		t.Fatalf("--check on a verified domain must pass; err=%v", err)
	}
}

func TestDomainStatus_UnknownDomainIsNotFoundNotEmpty(t *testing.T) {
	srv := domainServer(t, "status_unknown.json")
	defer srv.Close()
	_, _, err := runDomain(t, srv, "status", "nothere.example")
	if err == nil {
		t.Fatal("a domain the account does not hold must not read as a clean, empty success")
	}
	msg := friendly(err)
	if !strings.Contains(msg, "nothere.example is not a domain on this account") ||
		!strings.Contains(msg, "whisper domain submit nothere.example") {
		t.Fatalf("the refusal must name the domain and the fix; got %q", msg)
	}
}

func TestDomainSubmit_PrintsTheRecordsToPublish(t *testing.T) {
	srv := domainServer(t, "submit_pending.json")
	defer srv.Close()
	stdout, _, err := runDomain(t, srv, "submit", "everwatch.io")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"everwatch.io  pending", "Publish these records",
		"everwatch.io. 3600 IN NS ns1.whisper.online.", "IN DS 61903 13 2", "We poll your parent"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("submit output lacks %q:\n%s", want, stdout)
		}
	}
}

func TestDomainSubmit_VerifiedSaysKeepNotPublish(t *testing.T) {
	// The other half of the resubmit fix: re-submitting a verified domain must not read as an
	// instruction to go and change the registrar.
	srv := domainServer(t, "submit_verified.json")
	defer srv.Close()
	stdout, _, err := runDomain(t, srv, "submit", "everwatch.io")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "keep them in place") || strings.Contains(stdout, "Publish these records") {
		t.Errorf("a verified re-submit must say keep, not publish:\n%s", stdout)
	}
}

// --- the guards ------------------------------------------------------------------------

// agentWords are what an agent renderer says when it finds nothing. None of them may come
// out of a domain command, whatever the reply. (The list mirrors emptyAccountWords.)
var agentWords = []string{"no agents yet", "agent(s)", "whisper create", "isn't in your account"}

func TestNoDomainCommandPrintsAgentWording(t *testing.T) {
	// Every sub-command, against every reply shape we have - its own, the others', an empty
	// result, and the fleet shape the old code assumed - must say nothing about agents.
	fleetShaped := []byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],` +
		`"rows":[["domain",{"label":"example.com","fqdn":"example.com.","state":"pending"}]]}}`)
	emptyResult := []byte(`{"ok":true,"status":200,"result":{"columns":[],"rows":[]}}`)
	bodies := map[string][]byte{"fleet-shaped": fleetShaped, "empty": emptyResult}
	for _, f := range []string{"submit_pending.json", "status_verified.json", "status_pending.json",
		"status_unknown.json", "list.json", "list_empty.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", "domain", f))
		if err != nil {
			t.Fatal(err)
		}
		bodies[f] = b
	}
	for name, body := range bodies {
		for _, args := range [][]string{{"submit", "example.com"}, {"status", "example.com"}, {"list"}} {
			srv := domainServerBody(t, body)
			stdout, stderr, err := runDomain(t, srv, args...)
			srv.Close()
			all := stdout + stderr
			if err != nil {
				all += friendly(err)
			}
			for _, w := range agentWords {
				if strings.Contains(all, w) {
					t.Errorf("`whisper domain %s` against %s printed agent wording %q:\n%s",
						strings.Join(args, " "), name, w, all)
				}
			}
		}
	}
}

func TestAnUnexpectedReplyShapeIsShownNotSwallowed(t *testing.T) {
	// The old renderer turned an unexpected shape into silence. These print what arrived.
	var buf bytes.Buffer
	res := &client.Result{Columns: []string{"kind", "item"}, Rows: [][]any{{"domain", "something"}}}
	if _, err := renderDomainStatus(&buf, res, "example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "kind") || !strings.Contains(buf.String(), "something") {
		t.Fatalf("an unexpected shape must be printed as it is:\n%s", buf.String())
	}
}

// renderFleetCallersAllowed is every function permitted to call renderFleet: the agent
// listing, and nothing else. A domain sub-command reaching it is; any other
// non-agent command reaching it is the same defect with another name.
var renderFleetCallersAllowed = map[string]bool{"newListCmd": true}

func TestRenderFleetIsReachedOnlyFromTheAgentListing(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	calls, scanned := 0, 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scanned++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || id.Name != "renderFleet" {
					return true
				}
				calls++
				if !renderFleetCallersAllowed[fn.Name.Name] {
					t.Errorf("%s: %s reaches renderFleet, the agent table; give it its own renderer",
						fset.Position(id.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
	// A walk that finds nothing passes on mutual absence; it must see the one legitimate call.
	if scanned < 20 || calls == 0 {
		t.Fatalf("the walk saw %d files and %d references to renderFleet; it is not looking at the package", scanned, calls)
	}
}

func TestListOfANonAgentKindIsNotReportedAsNoAgents(t *testing.T) {
	var out, errb bytes.Buffer
	res := &client.Result{Columns: []string{"kind", "item"}, Rows: [][]any{
		{"identities", map[string]any{"address": "2a04:2a01:1::1", "fqdn": "a1.agents.whisper.online.", "state": "active"}},
	}}
	renderListItems(&out, &errb, res, "identities")
	if !strings.Contains(out.String(), "2a04:2a01:1::1") || !strings.Contains(out.String(), "ADDRESS") {
		t.Fatalf("identities must render as a table:\n%s", out.String())
	}
	out.Reset()
	errb.Reset()
	renderListItems(&out, &errb, &client.Result{Columns: []string{"kind", "item"}}, "records")
	if strings.Contains(errb.String(), "agent") || !strings.Contains(errb.String(), "no records") {
		t.Fatalf("an empty records listing must say so in its own words; stderr=%q", errb.String())
	}
}
