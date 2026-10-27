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
)

// `whisper domain verify <apex>` on a verified bring-your-own domain used to fail with a sentence
// about agents, because it only ever asked the agent question. These tests drive the real
// command against a stub of the two keyless endpoints and pin each answer it can give.

const (
	notAnAgentBody = `{"is_whisper_agent":false,"evidence":{"fqdn":"everwatch.io"},"detail":"no Whisper agent identity anchors this name"}`
	agentBody      = `{"is_whisper_agent":true,"fqdn":"demo.everwatch.io.","operator":"everwatch.io.","dane_ok":true,"jws_ok":true}`
	verifiedDomain = `{"domain":"everwatch.io","is_whisper_domain":true,"state":"verified",` +
		`"verdict":"everwatch.io is a verified Whisper bring-your-own domain: its parent delegates it to Whisper's nameservers",` +
		`"checks":{"delegated_to_whisper":true,"ds_matches_key":true,"validates_from_root":true,"served_by_every_node":true},` +
		`"nameservers":["ns1.whisper.online","ns2.whisper.online"],"ds":[],"detail":"","checked_at":1}`
	notOursDomain = `{"domain":"example.com","is_whisper_domain":false,"state":"not_served",` +
		`"verdict":"Whisper does not serve example.com as a bring-your-own domain.",` +
		`"checks":{"delegated_to_whisper":null,"ds_matches_key":null,"validates_from_root":null,"served_by_every_node":null},` +
		`"nameservers":[],"ds":[],"detail":"","checked_at":1}`
	notApexDomain = `{"domain":"x.everwatch.io","is_whisper_domain":false,"state":"not_apex",` +
		`"verdict":"x.everwatch.io is a name inside the bring-your-own domain everwatch.io, not its apex. Verify everwatch.io for the domain.",` +
		`"checks":{},"nameservers":[],"ds":[],"detail":"","checked_at":1}`
)

type verifyStub struct {
	mu       sync.Mutex
	identity string
	domain   string
	domainSC int
	paths    []string
}

func (s *verifyStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/verify-identity"):
			_, _ = w.Write([]byte(s.identity))
		case strings.HasPrefix(r.URL.Path, "/verify-domain/"):
			if s.domainSC != 0 {
				w.WriteHeader(s.domainSC)
			}
			_, _ = w.Write([]byte(s.domain))
		default:
			w.WriteHeader(404)
		}
	}))
}

func (s *verifyStub) asked(prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.paths {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func runDomainVerify(t *testing.T, url string, jsonOut bool, target string) (stdout, stderr string, err error) {
	t.Helper()
	saved := g
	g = globalFlags{verifyURL: url, timeout: 5 * time.Second, jsonOut: jsonOut}
	defer func() { g = saved }()
	cmd := newDomainVerifyCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{target})
	stdout, stderr = captureStd(t, func() { err = cmd.Execute() })
	return stdout, stderr, err
}

func TestDomainVerify_AVerifiedApexIsAVerifiedDomain(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: verifiedDomain}
	srv := stub.server(t)
	defer srv.Close()

	stdout, stderr, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if err != nil {
		t.Fatalf("a verified bring-your-own domain must verify, got %v", err)
	}
	if !strings.Contains(stderr, "verified Whisper bring-your-own domain") {
		t.Fatalf("stderr = %q, want the domain verdict", stderr)
	}
	for _, want := range []string{"delegated_to_whisper", "ds_matches_key", "validates_from_root", "served_by_every_node"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout = %q, want the %s row", stdout, want)
		}
	}
	if strings.Contains(stdout+stderr, "not a verified Whisper agent") {
		t.Fatalf("a verified domain must not be described as a failed agent: %q", stdout+stderr)
	}
}

func TestDomainVerify_AnAgentUnderTheApexKeepsTodaysAnswer(t *testing.T) {
	stub := &verifyStub{identity: agentBody, domain: verifiedDomain}
	srv := stub.server(t)
	defer srv.Close()

	_, stderr, err := runDomainVerify(t, srv.URL, false, "demo.everwatch.io")
	if err != nil {
		t.Fatalf("a verified agent must verify, got %v", err)
	}
	if !strings.Contains(stderr, "is a verified Whisper agent (DANE-anchored)") {
		t.Fatalf("stderr = %q, want the agent verdict", stderr)
	}
	if stub.asked("/verify-domain/") {
		t.Fatal("an agent name must not be asked the domain question")
	}
}

func TestDomainVerify_AnApexNotDelegatedToUsIsACleanExitOne(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: notOursDomain}
	srv := stub.server(t)
	defer srv.Close()

	_, _, err := runDomainVerify(t, srv.URL, false, "example.com")
	if err == nil {
		t.Fatal("a domain that is not ours must not verify")
	}
	if isUsageError(err) {
		t.Fatalf("a negative verdict is exit 1, not a usage error: %v", err)
	}
	if !strings.Contains(err.Error(), "does not serve example.com") {
		t.Fatalf("err = %q, want the domain verdict's reason", err)
	}
}

func TestDomainVerify_ABareLabelIsAUsageErrorWithNoNetwork(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: notOursDomain}
	srv := stub.server(t)
	defer srv.Close()

	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch")
	if err == nil || !isUsageError(err) {
		t.Fatalf("a bare label must be a usage error, got %v", err)
	}
	if !strings.Contains(err.Error(), "single label") {
		t.Fatalf("err = %q, want it to say what is wrong", err)
	}
	if stub.asked("/") {
		t.Fatal("a bare label must be refused before any request")
	}
}

func TestDomainVerify_AServerWithoutTheEndpointFallsBackToTheAgentAnswer(t *testing.T) {
	// Before the server half is deployed, /verify-domain is the gateway's default deny. That is
	// "cannot ask", never a domain verdict, so the answer is the agent one exactly as before.
	stub := &verifyStub{identity: notAnAgentBody, domain: `{"error":"forbidden"}`, domainSC: 403}
	srv := stub.server(t)
	defer srv.Close()

	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if err == nil || !strings.Contains(err.Error(), "is not a verified Whisper agent") {
		t.Fatalf("err = %v, want today's agent answer", err)
	}
}

func TestDomainVerify_ANameInsideADomainGetsTheAgentAnswerAndTheApex(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: notApexDomain}
	srv := stub.server(t)
	defer srv.Close()

	_, _, err := runDomainVerify(t, srv.URL, false, "x.everwatch.io")
	if err == nil {
		t.Fatal("a name that is neither an agent nor an apex must not verify")
	}
	for _, want := range []string{"is not a verified Whisper agent", "Verify everwatch.io"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to contain %q", err, want)
		}
	}
}

func TestDomainVerify_JSONIsTheDomainBodyVerbatim(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: verifiedDomain}
	srv := stub.server(t)
	defer srv.Close()

	stdout, _, err := runDomainVerify(t, srv.URL, true, "everwatch.io")
	if err != nil {
		t.Fatalf("--json verify of a verified domain: %v", err)
	}
	if strings.TrimSpace(stdout) != verifiedDomain {
		t.Fatalf("stdout = %q, want the server's domain body verbatim", stdout)
	}
}

func TestDomainVerify_CouldNotTellIsExitThreeNotOne(t *testing.T) {
	busy := `{"domain":"everwatch.io","is_whisper_domain":false,"state":"busy","verdict":"could not verify everwatch.io right now","checks":{}}`
	stub := &verifyStub{identity: notAnAgentBody, domain: busy}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if code, ok := exitCodeOf(err); !ok || code != 3 {
		t.Fatalf("err = %v (code %d, %v), want exit 3 for could-not-tell", err, code, ok)
	}
}

func TestDomainVerify_AVerdictForAnotherDomainIsRefused(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: strings.Replace(verifiedDomain, `"domain":"everwatch.io"`, `"domain":"elsewhere.io"`, 1)}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if err == nil || !strings.Contains(err.Error(), "answered for") {
		t.Fatalf("err = %v, want a refusal of a verdict about a different domain", err)
	}
}

func TestDomainVerify_ServerStringsCannotCarryTerminalEscapes(t *testing.T) {
	evil := strings.Replace(notOursDomain, `"verdict":"Whisper does`, `"verdict":"\u001b]0;pwned\u0007Whisper does`, 1)
	if evil == notOursDomain {
		t.Fatal("fixture did not inject the escape; the test would prove nothing")
	}
	stub := &verifyStub{identity: notAnAgentBody, domain: evil}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "example.com")
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Fatalf("err = %q, want the escape sequence stripped", err)
	}
}

func TestDomainVerify_ARateLimitIsCouldNotTellNotNo(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: `{"error":"rate_limited","detail":"too many"}`, domainSC: 429}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if code, ok := exitCodeOf(err); !ok || code != 3 {
		t.Fatalf("err = %v, want exit 3 for a 429", err)
	}
	if strings.Contains(err.Error(), "not a verified Whisper agent") {
		t.Fatalf("a 429 was turned into the agent no: %v", err)
	}
}

func TestDomainVerify_AUnicodeTargetMatchesTheServersALabel(t *testing.T) {
	body := strings.Replace(verifiedDomain, `"domain":"everwatch.io"`, `"domain":"xn--bcher-kva.example"`, 1)
	stub := &verifyStub{identity: notAnAgentBody, domain: body}
	srv := stub.server(t)
	defer srv.Close()
	if _, _, err := runDomainVerify(t, srv.URL, false, "b\u00fccher.example"); err != nil {
		t.Fatalf("a U-label target must match the server's A-label, got %v", err)
	}
}

func TestDomainVerify_AnUnsettledStateIsExitThree(t *testing.T) {
	body := `{"domain":"everwatch.io","is_whisper_domain":false,"state":"not_yet_validated","settled":false,"verdict":"try again shortly","checks":{}}`
	stub := &verifyStub{identity: notAnAgentBody, domain: body}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if code, ok := exitCodeOf(err); !ok || code != 3 {
		t.Fatalf("err = %v, want exit 3 for settled:false", err)
	}
}

func TestTermSafeDropsFormatCharacters(t *testing.T) {
	if got := termSafe("a\u202eb\u200bc\ufeffd"); got != "abcd" {
		t.Fatalf("termSafe = %q, want bidi and zero-width characters removed", got)
	}
}

func TestDomainVerify_ANonJSONShedIsStillCouldNotTell(t *testing.T) {
	stub := &verifyStub{identity: notAnAgentBody, domain: "<html>busy</html>", domainSC: 503}
	srv := stub.server(t)
	defer srv.Close()
	_, _, err := runDomainVerify(t, srv.URL, false, "everwatch.io")
	if code, ok := exitCodeOf(err); !ok || code != 3 {
		t.Fatalf("err = %v, want exit 3 for a non-JSON 503", err)
	}
}
