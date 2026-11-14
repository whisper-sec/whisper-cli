// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// enroll_listing_test.go pins one rule over every path through `whisper enroll`: a listing of
// the account that did not genuinely answer is never read as an account with no agent in it.
// Read that way, the name check finds nothing and the ladder registers a second identity for a
// device that may already have one. So enroll refuses, changes nothing, and names the commands
// to run.

// listingFailure is one way a listing can fail to answer (the shared corpus in testenv).
type listingFailure struct {
	name string
	// serve answers op:list; nil means the server is not there at all.
	serve func(w http.ResponseWriter, r *http.Request)
}

func writeBody(status int, body string) func(http.ResponseWriter, *http.Request) {
	return testenv.WriteBody(status, body)
}

func listingFailures() []listingFailure {
	var out []listingFailure
	for _, f := range testenv.ListingFailures() {
		out = append(out, listingFailure{name: f.Name, serve: f.Serve})
	}
	return out
}

// failingListing points the client at a stub whose op:list fails as f does and whose register
// and identity would both succeed, so a mint on a failed read is visible rather than an error.
func failingListing(t *testing.T, f listingFailure) func() []string {
	t.Helper()
	var mu sync.Mutex
	var ops []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 8192)
		n, _ := r.Body.Read(raw)
		op := sniffOp(string(raw[:n]))
		mu.Lock()
		ops = append(ops, op)
		mu.Unlock()
		if op == "list" {
			f.serve(w, r)
			return
		}
		writeBody(http.StatusOK, `{"ok":true,"status":200,"result":{"columns":["agent","address","fqdn"],`+
			`"rows":[["ag_new","2a04:2a01:9::1","ag-new.agents.whisper.online."]]}}`)(w, r)
	}))
	url := srv.URL
	t.Cleanup(srv.Close)
	if f.serve == nil {
		// No server at all: a port held refused for the whole test. A server that was started
		// and closed would leave its number free for another process to answer on.
		addr, _ := testenv.RefusedPort(t)
		url = "http://" + addr
	}
	savedG := g
	g = globalFlags{controlURL: url, key: "whisper_live_test", timeout: 400 * time.Millisecond, quiet: true}
	t.Cleanup(func() { g = savedG })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), ops...)
	}
}

// enrollPath is one way into the ladder.
type enrollPath struct {
	name       string
	marker     bool   // the device has an identity file
	flagName   string // --name
	force      bool
	wantRetry  string // the command the refusal must name to run again
	wantChoose bool   // the refusal must also offer --name with a placeholder
}

func enrollPaths() []enrollPath {
	return []enrollPath{
		{name: "no identity file", wantRetry: "'whisper enroll'", wantChoose: true},
		{name: "no identity file, --force", force: true, wantRetry: "'whisper enroll --force'", wantChoose: true},
		{name: "no identity file, --name", flagName: "box-1", wantRetry: "'whisper enroll --name box-1'"},
		{name: "identity file, --force", marker: true, force: true, wantRetry: "'whisper enroll --force'", wantChoose: true},
		{name: "identity file, --force --name", marker: true, force: true, flagName: "box-1",
			wantRetry: "'whisper enroll --force --name box-1'"},
	}
}

func TestEnrollRefusesOnAListingThatDidNotAnswer(t *testing.T) {
	for _, p := range enrollPaths() {
		for _, f := range listingFailures() {
			t.Run(p.name+"/"+f.name, func(t *testing.T) {
				if p.marker {
					seedMarkedDevice(t)
				} else {
					testenv.HermeticHome(t)
				}
				withHostname(t, "this-host.lan")
				opsSeen := failingListing(t, f)

				_, err := runEnroll(p.flagName, p.force)
				if err == nil {
					t.Fatalf("enroll must refuse when the listing did not answer; ops %v", opsSeen())
				}
				for _, op := range opsSeen() {
					if op == "register" || op == "identity" {
						t.Fatalf("enroll called op:%s although the listing did not answer; ops %v", op, opsSeen())
					}
				}
				msg := err.Error()
				for _, want := range []string{"could not read this account's agents", "Nothing was changed", p.wantRetry} {
					if !strings.Contains(msg, want) {
						t.Fatalf("the refusal must say %q, got: %v", want, err)
					}
				}
				choose := "--name " + pastePlaceholder("name")
				if p.wantChoose != strings.Contains(msg, choose) {
					t.Fatalf("offering %q: want %v, got: %v", choose, p.wantChoose, err)
				}
				id, had := client.ReadBoundFile("")
				if had != p.marker || (p.marker && id.Addr.String() != markedAddr) {
					t.Fatalf("a refusal must leave the identity file as it was, got %+v present=%v", id, had)
				}
				wantAgent := ""
				if p.marker {
					wantAgent = "agent-0dead0dead0dead0"
				}
				if got := client.ReadAgentFile(""); got != wantAgent {
					t.Fatalf("a refusal must leave the saved agent as it was, got %q want %q", got, wantAgent)
				}
			})
		}
	}
}

// A listing is read once, and every rung reads that one. Two reads would let the identity
// check see an answer and the name check, a second later, see a failure.
func TestEnrollListsTheAccountOnce(t *testing.T) {
	seedDeadIdentity(t, "ag_dead")
	withHostname(t, "this-mac")
	seen := enrollRecording(t, staleAgentAccount())
	if _, err := runEnroll("", true); err != nil {
		t.Fatalf("enroll --force: %v", err)
	}
	lists := 0
	for _, op := range opsSeen(*seen) {
		if op == "register" {
			break
		}
		if op == "list" {
			lists++
		}
	}
	if lists != 1 {
		t.Fatalf("enroll must list the account exactly once before it registers, listed %d times; ops %v",
			lists, opsSeen(*seen))
	}
}

// The control: a listing that answered with no agent in it is a real answer, and the ladder
// registers, on every path that can reach the name check.
func TestEnrollRegistersWhenTheListingAnswersEmpty(t *testing.T) {
	for _, p := range []enrollPath{
		{name: "no identity file"},
		{name: "no identity file, --force", force: true},
		{name: "no identity file, --name", flagName: "box-1"},
		{name: "identity file, --force --name", marker: true, force: true, flagName: "box-1"},
	} {
		t.Run(p.name, func(t *testing.T) {
			if p.marker {
				seedMarkedDevice(t)
			} else {
				testenv.HermeticHome(t)
			}
			withHostname(t, "this-host.lan")
			seen := enrollRecording(t, nil)
			res, err := runEnroll(p.flagName, p.force)
			if err != nil {
				t.Fatalf("enroll on an empty account: %v", err)
			}
			want := firstNonBlank(p.flagName, "this-host")
			if body, ok := bodyForOp(*seen, "register"); !ok || !strings.Contains(body, want) {
				t.Fatalf("an empty account must get an agent registered under %q, register body %q ok=%v ops %v",
					want, body, ok, opsSeen(*seen))
			}
			if res.addr != "2a04:2a01:9::beef" || res.reused {
				t.Fatalf("want the minted /128, got %+v", res)
			}
		})
	}
}

// The live control plane wraps the listing in an outer row; an empty one is still an answer.
func TestEnrollRegistersOnAnEmptyListingInTheLiveShape(t *testing.T) {
	testenv.HermeticHome(t)
	withHostname(t, "this-host")
	opsSeen := failingListing(t, listingFailure{name: "live empty", serve: writeBody(http.StatusOK,
		`{"columns":["op","ok","status","result","error","retry_after","elapsed_ms"],"rows":[{"op":"list",`+
			`"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[]},"error":null,`+
			`"retry_after":null,"elapsed_ms":3}]}`)})
	res, err := runEnroll("", false)
	if err != nil {
		t.Fatalf("enroll on an empty live-shaped listing: %v (ops %v)", err, opsSeen())
	}
	if res.addr != "2a04:2a01:9::1" {
		t.Fatalf("want the minted /128, got %+v ops %v", res, opsSeen())
	}
}

// The other control: a listing that answered with the agent reuses it and registers nothing.
func TestEnrollReusesTheAgentTheListingAnsweredWith(t *testing.T) {
	for _, p := range []enrollPath{
		{name: "no identity file"},
		{name: "no identity file, --force", force: true},
		{name: "no identity file, --name", flagName: "this-host"},
	} {
		t.Run(p.name, func(t *testing.T) {
			testenv.HermeticHome(t)
			withHostname(t, "this-host.lan")
			seen := enrollRecording(t, []agentChoice{{name: "this-host", addr: "2a04:2a01:9::7e57"}})
			res, err := runEnroll(p.flagName, p.force)
			if err != nil {
				t.Fatalf("enroll: %v", err)
			}
			if registered(*seen) || res.addr != "2a04:2a01:9::7e57" || !res.reused {
				t.Fatalf("the agent under this name must be reused, got %+v ops %v", res, opsSeen(*seen))
			}
		})
	}
}

// A placeholder in a pasted line is {braces}, which every POSIX shell passes through; on
// Windows it is quoted, because PowerShell reads an unquoted brace as a script block.
func TestPastePlaceholderIsQuotedOnWindows(t *testing.T) {
	saved := pasteGOOS
	t.Cleanup(func() { pasteGOOS = saved })
	pasteGOOS = "linux"
	if got := pastePlaceholder("name"); got != "{name}" {
		t.Fatalf("POSIX placeholder = %q", got)
	}
	pasteGOOS = "windows"
	if got := pastePlaceholder("name"); got != `"{name}"` {
		t.Fatalf("Windows placeholder = %q", got)
	}
}

// A name a person chose goes back into the retry line as one word in any shell.
func TestPasteWordQuotesOnlyWhatNeedsIt(t *testing.T) {
	saved := pasteGOOS
	t.Cleanup(func() { pasteGOOS = saved })
	pasteGOOS = "linux"
	for in, want := range map[string]string{"box-1": "box-1", "db.example.com": "db.example.com",
		"my box": "'my box'", "it's": `'it'\''s'`} {
		if got := pasteWord(in); got != want {
			t.Errorf("pasteWord(%q) on POSIX = %q, want %q", in, got, want)
		}
	}
	pasteGOOS = "windows"
	if got := pasteWord("my box"); got != `"my box"` {
		t.Errorf("pasteWord on Windows = %q", got)
	}
}
