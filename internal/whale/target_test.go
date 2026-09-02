// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"strings"
	"testing"
)

// TestParseTarget_AcceptsEverySpellingOfTheSameNode is the Postel half: the shapes a
// person or a script actually has an address in must all arrive as one canonical Text.
func TestParseTarget_AcceptsEverySpellingOfTheSameNode(t *testing.T) {
	want := "2a04:2a01:1:4::b"
	for _, in := range []string{
		"2a04:2a01:1:4::b",
		"  2a04:2a01:1:4::b  ",
		"[2a04:2a01:1:4::b]",
		"2A04:2A01:1:4::B",
		"2a04:2a01:0001:0004:0000:0000:0000:000b",
	} {
		got, err := ParseTarget(in)
		if err != nil {
			t.Fatalf("ParseTarget(%q) errored: %v", in, err)
		}
		if got.Kind != KindAddress {
			t.Fatalf("ParseTarget(%q).Kind = %q, want %q", in, got.Kind, KindAddress)
		}
		if got.Text != want {
			t.Fatalf("ParseTarget(%q).Text = %q, want the canonical %q", in, got.Text, want)
		}
		if !got.IsAddress() || got.Addr.String() != want {
			t.Fatalf("ParseTarget(%q) did not carry the parsed address", in)
		}
	}
}

// TestParseTarget_NamesNormaliseTheSameWay covers the naming half: trailing dot optional,
// case-insensitive, and a single label recognised as one.
func TestParseTarget_NamesNormaliseTheSameWay(t *testing.T) {
	cases := []struct {
		in   string
		text string
		kind Kind
	}{
		{"db-01", "db-01", KindLabel},
		{"DB-01", "db-01", KindLabel},
		{"db-01.t9f.agents.whisper.online", "db-01.t9f.agents.whisper.online", KindFQDN},
		{"db-01.t9f.agents.whisper.online.", "db-01.t9f.agents.whisper.online", KindFQDN},
		{"  DB-01.T9F.Agents.Whisper.Online.  ", "db-01.t9f.agents.whisper.online", KindFQDN},
		{"_whisper-agentkey.example.com", "_whisper-agentkey.example.com", KindFQDN},
		{"agent-af392aa87c7f2b274", "agent-af392aa87c7f2b274", KindLabel},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("ParseTarget(%q) errored: %v", c.in, err)
		}
		if got.Text != c.text || got.Kind != c.kind {
			t.Fatalf("ParseTarget(%q) = (%q,%q), want (%q,%q)", c.in, got.Text, got.Kind, c.text, c.kind)
		}
		if got.IsAddress() {
			t.Fatalf("ParseTarget(%q) claimed to be an address", c.in)
		}
	}
}

// TestParseTarget_RoundTripsThroughItself: the canonical form must itself parse to the
// same canonical form, or a value printed by one command cannot be pasted into the next.
func TestParseTarget_RoundTripsThroughItself(t *testing.T) {
	for _, in := range []string{"[2A04:2A01:1:4::B]", "DB-01.Agents.Whisper.Online.", "db-01"} {
		once, err := ParseTarget(in)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", in, err)
		}
		twice, err := ParseTarget(once.Text)
		if err != nil {
			t.Fatalf("re-parsing %q: %v", once.Text, err)
		}
		if twice.Text != once.Text || twice.Kind != once.Kind {
			t.Fatalf("%q does not round-trip: %q/%q then %q/%q", in, once.Text, once.Kind, twice.Text, twice.Kind)
		}
	}
}

// TestParseTarget_RefusesWithASentenceThatNamesTheExpectation is the conservative half.
// Every rejection must say what was expected; none may be a bare parse failure, and none
// may panic on a hostile shape.
func TestParseTarget_RefusesWithASentenceThatNamesTheExpectation(t *testing.T) {
	cases := []struct {
		in   string
		want string // a phrase the message must carry
	}{
		{"", "agent id"},
		{"   ", "agent id"},
		{"10.0.0.1", "IPv6-only"},
		{"192.168.1.1", "IPv6-only"},
		{"::ffff:10.0.0.1", "IPv6-only"},
		{"https://db-01.example.com/", "URL"},
		{"db-01:443", "no port"},
		{"db..01", "empty label"},
		{"-db-01", "hyphen"},
		{"db-01-", "hyphen"},
		{"db 01", "not a letter"},
		{"db_01!", "not a letter"},
		{strings.Repeat("a", 64) + ".example.com", "label"},
		{strings.Repeat("a.", 200) + "example", "at most"},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if err == nil {
			t.Fatalf("ParseTarget(%q) accepted it as %+v; it must be refused", c.in, got)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("ParseTarget(%q) said %q; it must name the expectation (%q)", c.in, err.Error(), c.want)
		}
		if strings.Contains(err.Error(), "goroutine") || strings.Contains(err.Error(), "panic") {
			t.Fatalf("ParseTarget(%q) leaked a stack trace: %q", c.in, err.Error())
		}
	}
}

// TestParseTarget_AnIPv4LiteralIsRefusedByNameNotByAccident: the v4 message is the one a
// person actually needs, so it must fire for both a parseable v4 address and a
// v4-looking string, not fall through to a generic "not a name".
func TestParseTarget_AnIPv4LiteralIsRefusedByNameNotByAccident(t *testing.T) {
	for _, in := range []string{"1.1.1.1", "999.1.1.1"} {
		_, err := ParseTarget(in)
		if err == nil || !strings.Contains(err.Error(), "IPv6-only") {
			t.Fatalf("ParseTarget(%q) = %v, want the IPv6-only sentence", in, err)
		}
	}
}
