// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The browser-trusted (WebPKI) leaf is asked for only when the domain's status carries the
// capability witness: a webpki row that is not "unavailable". These tests drive the commands
// against a stub control plane and assert what goes on the wire, because an opt-in sent to a
// control plane that does not offer it is a 400, and an opt-in silently not sent would leave a
// user believing a leaf was coming.

type webpkiStub struct {
	mu        sync.Mutex
	witness   string // the webpki status row, "" for none (an older control plane)
	noDomain  bool   // status answers no rows for the domain
	oddShape  bool   // status answers a shape the CLI does not read
	refuseOpt bool   // op:webpki answers 409
	subOps    []string
	bodies    []string
}

func (s *webpkiStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		sub := ""
		for _, op := range []string{"status", "webpki", "submit"} {
			if strings.Contains(body, "op:'"+op+"'") {
				sub = op
			}
		}
		s.mu.Lock()
		s.subOps = append(s.subOps, sub)
		s.bodies = append(s.bodies, body)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		switch sub {
		case "status":
			if s.oddShape {
				_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["what"],"rows":[["?"]]}}`))
				return
			}
			if s.noDomain {
				_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["name","state","key","value"],"rows":[]}}`))
				return
			}
			rows := `["example.com","pending","served_here","false"]`
			if s.witness != "" {
				rows += `,["example.com","pending","webpki","` + s.witness + `"]`
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["name","state","key","value"],"rows":[` + rows + `]}}`))
		case "webpki":
			if s.refuseOpt {
				_, _ = w.Write([]byte(`{"ok":false,"status":409,"error":{"status":409,"code":"WEBPKI_LIMIT","detail":"the most one account may have"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","value"],"rows":[["name","example.com"],["webpki","pending_verification"],["note","webpki is on"]]}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["kind","value"],"rows":[["state","pending"],["name","example.com"]]}}`))
		}
	}))
}

func runWebpkiDomain(t *testing.T, srvURL string, args ...string) error {
	return runWebpkiDomainJSON(t, srvURL, false, args...)
}

func runWebpkiDomainJSON(t *testing.T, srvURL string, jsonOut bool, args ...string) error {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: srvURL, key: "whisper_live_test", quiet: true, timeout: 5 * time.Second,
		jsonOut: jsonOut}
	defer func() { g = savedG }()
	cmd := newDomainCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(args)
	return cmd.Execute()
}

func (s *webpkiStub) sent(sub string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, o := range s.subOps {
		if o == sub {
			return s.bodies[i], true
		}
	}
	return "", false
}

func TestDomainWebpkiOn_WithTheWitnessSendsTheOptIn(t *testing.T) {
	stub := &webpkiStub{witness: "off"}
	srv := stub.server(t)
	defer srv.Close()
	if err := runWebpkiDomain(t, srv.URL, "webpki", "example.com", "on"); err != nil {
		t.Fatalf("webpki on with the witness must succeed: %v", err)
	}
	body, ok := stub.sent("webpki")
	if !ok {
		t.Fatalf("webpki on must send op:'webpki'; sub-ops=%v", stub.subOps)
	}
	if !strings.Contains(body, "name:'example.com'") || !strings.Contains(body, "enabled:true") {
		t.Fatalf("the opt-in must name the domain and enabled:true; body=%q", body)
	}
	if stub.subOps[0] != "status" {
		t.Fatalf("the witness must be read before anything is asked for; sub-ops=%v", stub.subOps)
	}
}

func TestDomainWebpkiOn_WithoutTheWitnessRefusesAndAsksForNothing(t *testing.T) {
	for _, witness := range []string{"", "unavailable"} {
		stub := &webpkiStub{witness: witness}
		srv := stub.server(t)
		err := runWebpkiDomain(t, srv.URL, "webpki", "example.com", "on")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "not offered") {
			t.Fatalf("witness %q: webpki on must refuse and say why; err=%v", witness, err)
		}
		if _, ok := stub.sent("webpki"); ok {
			t.Fatalf("witness %q: a refused opt-in must not be sent", witness)
		}
	}
}

func TestDomainWebpkiOff_IsAlwaysSentWithoutAWitness(t *testing.T) {
	stub := &webpkiStub{}
	srv := stub.server(t)
	defer srv.Close()
	if err := runWebpkiDomain(t, srv.URL, "webpki", "example.com", "OFF"); err != nil {
		t.Fatalf("webpki off must always go through: %v", err)
	}
	body, ok := stub.sent("webpki")
	if !ok || !strings.Contains(body, "enabled:false") {
		t.Fatalf("webpki off must send enabled:false; body=%q sub-ops=%v", body, stub.subOps)
	}
	if _, read := stub.sent("status"); read {
		t.Fatalf("turning it off needs no witness; sub-ops=%v", stub.subOps)
	}
}

func TestDomainWebpki_ABadChoiceIsAUsageError(t *testing.T) {
	stub := &webpkiStub{witness: "off"}
	srv := stub.server(t)
	defer srv.Close()
	err := runWebpkiDomain(t, srv.URL, "webpki", "example.com", "maybe")
	if err == nil || !strings.Contains(err.Error(), "on|off") {
		t.Fatalf("a value that is no choice must be a usage error naming on|off; err=%v", err)
	}
	if len(stub.subOps) != 0 {
		t.Fatalf("nothing must be sent; sub-ops=%v", stub.subOps)
	}
}

func TestDomainSubmitWebpki_SubmitsThenReadsTheWitnessThenOptsIn(t *testing.T) {
	stub := &webpkiStub{witness: "off"}
	srv := stub.server(t)
	defer srv.Close()
	if err := runWebpkiDomain(t, srv.URL, "submit", "example.com", "--webpki"); err != nil {
		t.Fatalf("submit --webpki with the witness must succeed: %v", err)
	}
	want := []string{"submit", "status", "webpki"}
	if strings.Join(stub.subOps, ",") != strings.Join(want, ",") {
		t.Fatalf("sub-ops=%v, want %v", stub.subOps, want)
	}
	body, _ := stub.sent("submit")
	if strings.Contains(body, "acme") || strings.Contains(body, "webpki") {
		t.Fatalf("the submit itself must carry no opt-in argument an older control plane would refuse; body=%q", body)
	}
}

func TestDomainSubmitWebpki_WithoutTheWitnessSubmitsAndSaysTheLeafWasNotAskedFor(t *testing.T) {
	stub := &webpkiStub{}
	srv := stub.server(t)
	defer srv.Close()
	err := runWebpkiDomain(t, srv.URL, "submit", "example.com", "--webpki")
	if err == nil || !strings.Contains(err.Error(), "was submitted, but --webpki was not") {
		t.Fatalf("the error must say the submit went through and the leaf did not; err=%v", err)
	}
	if _, ok := stub.sent("submit"); !ok {
		t.Fatalf("the domain must still be submitted; sub-ops=%v", stub.subOps)
	}
	if _, ok := stub.sent("webpki"); ok {
		t.Fatalf("no opt-in may be sent without the witness; sub-ops=%v", stub.subOps)
	}
}

func TestDomainStatus_RendersTheWebpkiRowsAndTheCaaHint(t *testing.T) {
	res := &client.Result{
		Columns: []string{"name", "state", "key", "value"},
		Rows: [][]any{
			{"example.com", "verified", "webpki", "backing_off"},
			{"example.com", "verified", "webpki_reason", "the CAA does not authorise letsencrypt.org"},
			{"example.com", "verified", "webpki_caa_hint", "your CAA admits Let's Encrypt for this node"},
		},
	}
	var out bytes.Buffer
	if _, err := renderDomainStatus(&out, res, "example.com"); err != nil {
		t.Fatalf("render: %v", err)
	}
	text := out.String()
	for _, want := range []string{"WebPKI", "retrying later", "WebPKI reason", "CAA: your CAA admits"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status must show %q; got:\n%s", want, text)
		}
	}
}

func TestParseOnOff_IsLiberal(t *testing.T) {
	for in, want := range map[string]bool{"on": true, "TRUE": true, "yes": true, "enable": true, "off": false,
		"False": false, "no": false, "disabled": false} {
		got, ok := parseOnOff(in)
		if !ok || got != want {
			t.Fatalf("parseOnOff(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}
	if _, ok := parseOnOff("maybe"); ok {
		t.Fatalf("parseOnOff(maybe) must not be a choice")
	}
}

func TestDomainWebpkiOn_UnderJSONTheWitnessIsReadNotPrinted(t *testing.T) {
	stub := &webpkiStub{witness: "off"}
	srv := stub.server(t)
	defer srv.Close()
	if err := runWebpkiDomainJSON(t, srv.URL, true, "webpki", "example.com", "on"); err != nil {
		t.Fatalf("--json must not turn an offered leaf into a refusal: %v", err)
	}
	if _, ok := stub.sent("webpki"); !ok {
		t.Fatalf("the opt-in must be sent under --json; sub-ops=%v", stub.subOps)
	}
}

func TestDomainWebpkiOn_TellsANotSubmittedDomainAndAnOddReplyApartFromNotOffered(t *testing.T) {
	stub := &webpkiStub{noDomain: true}
	srv := stub.server(t)
	err := runWebpkiDomain(t, srv.URL, "webpki", "example.com", "on")
	srv.Close()
	if err == nil || !strings.Contains(err.Error(), "submit it first") {
		t.Fatalf("a domain not on the account must say so; err=%v", err)
	}
	odd := &webpkiStub{oddShape: true}
	srv2 := odd.server(t)
	err = runWebpkiDomain(t, srv2.URL, "webpki", "example.com", "on")
	srv2.Close()
	if err == nil || !strings.Contains(err.Error(), "no shape") || strings.Contains(err.Error(), "not offered") {
		t.Fatalf("an unreadable reply must not claim a capability; err=%v", err)
	}
	none := &webpkiStub{}
	srv3 := none.server(t)
	err = runWebpkiDomain(t, srv3.URL, "webpki", "example.com", "on")
	srv3.Close()
	if code, ok := exitCodeOf(err); !ok || code != 4 {
		t.Fatalf("not offered must exit 4, never verify's retryable 3; err=%v", err)
	}
}

func TestDomainSubmitWebpki_ARefusedOptInStillSaysTheDomainWasSubmitted(t *testing.T) {
	stub := &webpkiStub{witness: "off", refuseOpt: true}
	srv := stub.server(t)
	defer srv.Close()
	err := runWebpkiDomain(t, srv.URL, "submit", "example.com", "--webpki")
	if err == nil || !strings.Contains(err.Error(), "was submitted, but --webpki was not") {
		t.Fatalf("every opt-in failure after a submit must say the submit went through; err=%v", err)
	}
	none := &webpkiStub{}
	srv2 := none.server(t)
	defer srv2.Close()
	err = runWebpkiDomain(t, srv2.URL, "submit", "example.com", "--webpki")
	if code, ok := exitCodeOf(err); !ok || code != webpkiNotOfferedExit {
		t.Fatalf("submit --webpki not offered keeps the exit code; err=%v", err)
	}
}

func TestDomainWebpki_EitherArgumentOrderIsRead(t *testing.T) {
	stub := &webpkiStub{}
	srv := stub.server(t)
	defer srv.Close()
	if err := runWebpkiDomain(t, srv.URL, "webpki", "off", "example.com"); err != nil {
		t.Fatalf("webpki off <apex> must be read: %v", err)
	}
	body, ok := stub.sent("webpki")
	if !ok || !strings.Contains(body, "name:'example.com'") || !strings.Contains(body, "enabled:false") {
		t.Fatalf("the swapped order must send the same opt-out; body=%q", body)
	}
}

func TestDomainStatus_AServerStringCannotReachTheTerminalRaw(t *testing.T) {
	res := &client.Result{
		Columns: []string{"name", "state", "key", "value"},
		Rows:    [][]any{{"example.com", "verified", "webpki_reason", "bad\x1b[2Jthing"}},
	}
	var out bytes.Buffer
	if _, err := renderDomainStatus(&out, res, "example.com"); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("an escape sequence from the server reached the terminal: %q", out.String())
	}
}
