// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
	"time"
)

// verify_dane_state_test.go: /verify-identity grades DANE on the leaf an agent's address actually
// serves, and says how the check ended (dane_state), why it did not pass (dane_reason) and which
// leaf it saw (evidence.dane.served_leaf). `whisper verify` shows all three. A server that predates
// them still renders exactly as before, and a field of an unexpected type never costs the verdict.

const daneMismatchBody = `{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","operator":"t1",` +
	`"tenant":"t1","dane_ok":false,"dane_state":"mismatch",` +
	`"dane_reason":"the leaf served on [2a04:2a01::1]:443 has SPKI SHA-256 129e4a94, which matches no TLSA 3 1 1 pin",` +
	`"jws_ok":true,"verified_at":1,"evidence":{"dane_tlsa_sha256":"b653a4ef","dane":{"usage":3,` +
	`"served_leaf_matches":false,"served_leaf":{"spki_sha256":"129e4a94","subject":"CN=*.whisper.online"}}}}`

// runVerify drives `whisper verify` against a stub answering body, returning stdout, stderr and
// the command's error.
func runVerify(t *testing.T, body string) (string, string, error) {
	t.Helper()
	srv := problemServer(t, 200, body)
	defer srv.Close()
	saved := g
	g = globalFlags{verifyURL: srv.URL, timeout: 5 * time.Second}
	defer func() { g = saved }()
	var err error
	out, errOut := captureStd(t, func() {
		cmd := newVerifyCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs([]string{"2a04:2a01::1"})
		err = cmd.Execute()
	})
	return out, errOut, err
}

// row reports whether the FIELD/VALUE table has a row for field whose value contains want.
func row(table, field, want string) bool {
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == field && strings.Contains(line, want) {
			return true
		}
	}
	return false
}

func TestVerify_ShowsDaneStateReasonAndServedLeaf(t *testing.T) {
	out, _, err := runVerify(t, daneMismatchBody)
	if err == nil {
		t.Fatal("a mismatch must exit non-zero")
	}
	for _, want := range [][2]string{
		{"dane_ok", "no"},
		{"dane_state", "mismatch"},
		{"dane_reason", "matches no TLSA 3 1 1 pin"},
		{"served_leaf_matches", "no"},
		{"served_leaf_sha256", "129e4a94"},
		{"served_leaf_subject", "CN=*.whisper.online"},
		{"dane_tlsa_sha256", "b653a4ef"},
	} {
		if !row(out, want[0], want[1]) {
			t.Fatalf("no %s row carrying %q in:\n%s", want[0], want[1], out)
		}
	}
	// The exit line carries the state and the reason, so a script's one line says why.
	if !strings.Contains(err.Error(), "(mismatch): the leaf served on") {
		t.Fatalf("the exit line does not carry the state and reason: %q", err.Error())
	}
}

// An older server sends none of the new fields: the table is the one it always printed, with
// no empty dane_state row and no served_leaf rows, and the exit line is unchanged.
func TestVerify_OlderServerWithoutDaneStateStillRenders(t *testing.T) {
	old := `{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","operator":"t1","dane_ok":false,` +
		`"jws_ok":true,"evidence":{"dane_tlsa_sha256":"b653a4ef","dane":{"served_leaf_matches":false}}}`
	out, _, err := runVerify(t, old)
	if err == nil || err.Error() != "a1.t1.agents.whisper.online is a Whisper agent but DANE did not fully verify" {
		t.Fatalf("exit line changed for an older server: %v", err)
	}
	for _, absent := range []string{"dane_state", "dane_reason", "served_leaf_sha256", "served_leaf_subject"} {
		if strings.Contains(out, absent) {
			t.Fatalf("an older server's verdict grew a %s row:\n%s", absent, out)
		}
	}
	if !row(out, "dane_ok", "no") || !row(out, "served_leaf_matches", "no") || !row(out, "jws_ok", "yes") {
		t.Fatalf("the older table lost a row:\n%s", out)
	}
}

// A verified agent shows its state but no reason (the server sends none, and a stray one is not
// shown beside a pass), and exits 0.
func TestVerify_VerifiedShowsStateWithoutReason(t *testing.T) {
	body := `{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","dane_ok":true,"dane_state":"verified",` +
		`"dane_reason":"stray","jws_ok":true,"evidence":{"dane":{"served_leaf_matches":true,"served_leaf":{"spki_sha256":"b653a4ef"}}}}`
	out, errOut, err := runVerify(t, body)
	if err != nil {
		t.Fatalf("a verified agent must exit 0: %v", err)
	}
	if !row(out, "dane_state", "verified") || strings.Contains(out, "dane_reason") || strings.Contains(out, "stray") {
		t.Fatalf("verified table wrong:\n%s", out)
	}
	if !row(out, "served_leaf_sha256", "b653a4ef") || strings.Contains(out, "served_leaf_subject") {
		t.Fatalf("served leaf rows wrong:\n%s", out)
	}
	if !strings.Contains(errOut, "is a verified Whisper agent") {
		t.Fatalf("no success line: %q", errOut)
	}
}

// Liberal in what we accept: new fields of the wrong type read as absent and never turn the
// answer into "a non-JSON body"; a state this CLI does not know is shown as the server sent it;
// a reason carrying a newline cannot break the table.
func TestVerify_OddlyTypedNewFieldsNeverCostTheVerdict(t *testing.T) {
	cases := []struct {
		name, body string
		check      func(t *testing.T, out string, err error)
	}{
		{"numeric state, object reason, string leaf",
			`{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","dane_ok":false,"dane_state":5,` +
				`"dane_reason":{"x":1},"jws_ok":true,"evidence":{"dane":{"served_leaf":"129e4a94"}}}`,
			func(t *testing.T, out string, err error) {
				if err == nil || strings.Contains(err.Error(), "non-JSON") {
					t.Fatalf("an odd field cost the verdict: %v", err)
				}
				if !row(out, "dane_ok", "no") || strings.Contains(out, "dane_state") || strings.Contains(out, "served_leaf") {
					t.Fatalf("odd fields were shown:\n%s", out)
				}
			}},
		{"null fields",
			`{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","dane_ok":false,"dane_state":null,` +
				`"dane_reason":null,"evidence":{"dane":{"served_leaf":null}}}`,
			func(t *testing.T, out string, err error) {
				if err == nil || strings.Contains(out, "dane_state") || strings.Contains(out, "served_leaf") {
					t.Fatalf("null fields mishandled: %v\n%s", err, out)
				}
			}},
		{"unknown state, multi-line reason, numeric spki",
			`{"is_whisper_agent":true,"fqdn":"a1.t1.agents.whisper.online.","dane_ok":false,"dane_state":" Stale_Pin ",` +
				`"dane_reason":"line one\nline two","evidence":{"dane":{"served_leaf":{"spki_sha256":7,"subject":"CN=x"}}}}`,
			func(t *testing.T, out string, err error) {
				if !row(out, "dane_state", "stale_pin") {
					t.Fatalf("an unknown state was not shown as sent:\n%s", out)
				}
				if !row(out, "dane_reason", "line one line two") || !strings.Contains(err.Error(), "(stale_pin): line one line two") {
					t.Fatalf("the reason was not kept on one line: %v\n%s", err, out)
				}
				if strings.Contains(out, "served_leaf") {
					t.Fatalf("a leaf with no readable spki was shown:\n%s", out)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := runVerify(t, c.body)
			c.check(t, out, err)
		})
	}
}

// The panel's unverified detail falls back to notVerifiedReason, so it carries the reason too.
func TestNotVerifiedReason_CarriesStateAndReason(t *testing.T) {
	_, _, err := runVerify(t, strings.Replace(daneMismatchBody, `"dane_reason"`, `"x_reason"`, 1))
	if err == nil || !strings.HasSuffix(err.Error(), "did not fully verify (mismatch)") {
		t.Fatalf("a state without a reason should end the line with the state: %v", err)
	}
}
