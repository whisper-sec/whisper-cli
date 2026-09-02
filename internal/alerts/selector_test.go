// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package alerts

import "testing"

// A target is data somebody typed, not a syntax to police. Every one of these is a way a
// real person writes the same thing, and every one of them has to land on the same row.
func TestParseSelector_AcceptsEveryWayAPersonTypesIt(t *testing.T) {
	cases := []struct {
		in            string
		wantSubject   string
		wantCondition string
	}{
		{"scout/T1486", "scout", "T1486"},
		{"scout/t1486", "scout", "T1486"},
		{"  scout/T1021.004  ", "scout", "T1021.004"},
		{"T1486", "", "T1486"},
		{"t1486", "", "T1486"},
		{"scout", "scout", ""},
		{"2a04:2a01:9::50/T1486", "2a04:2a01:9::50", "T1486"},
		{"2a04:2a01:9::50/128", "2a04:2a01:9::50/128", ""},
		{"2a04:2a01:9::50/128/T1486", "2a04:2a01:9::50/128", "T1486"},
		{"scout.t-abc.agents.whisper.online./T1486", "scout.t-abc.agents.whisper.online", "T1486"},
		{"scout.t-abc.agents.whisper.online.", "scout.t-abc.agents.whisper.online", ""},
		{"CVE-2026-1234", "", "CVE-2026-1234"},
		{"build-07/cve-2026-1234", "build-07", "cve-2026-1234"},
		{"", "", ""},
		{"   ", "", ""},
	}
	for _, c := range cases {
		got := ParseSelector(c.in)
		if got.Subject != c.wantSubject || got.Condition != c.wantCondition {
			t.Errorf("ParseSelector(%q) = {%q,%q}, want {%q,%q}",
				c.in, got.Subject, got.Condition, c.wantSubject, c.wantCondition)
		}
	}
}

// A /128 is how every other Whisper surface writes an address. If the alerting surface
// were the one place a prefix length broke the parse, that would be resistance for its
// own sake - so the prefix-length form has to resolve to the SAME row as the bare form.
func TestSelector_PrefixLengthFormFindsTheSameRow(t *testing.T) {
	r := Row{Agent: "scout", Address: "2a04:2a01:9::50", Technique: "T1486", ID: "T1486"}
	for _, target := range []string{
		"2a04:2a01:9::50/T1486",
		"2a04:2a01:9::50/128/T1486",
		"2a04:2a01:9:0:0:0:0:50/T1486",
		"scout/T1486",
		"T1486",
	} {
		if !ParseSelector(target).Matches(r, Endpoint{}) {
			t.Errorf("%q did not match the row it names", target)
		}
	}
}

func TestSelector_MatchesAnFQDNAndItsFirstLabel(t *testing.T) {
	r := Row{Address: "2a04:2a01:9::50", Technique: "T1486"}
	e := Endpoint{Address: "2a04:2a01:9::50", FQDN: "scout.t-abc.agents.whisper.online", known: true}
	for _, target := range []string{
		"scout.t-abc.agents.whisper.online",
		"scout.t-abc.agents.whisper.online.",
		"SCOUT.T-ABC.AGENTS.WHISPER.ONLINE",
		"scout",
	} {
		if !ParseSelector(target).Matches(r, e) {
			t.Errorf("%q did not match its own endpoint", target)
		}
	}
}

func TestSelector_DoesNotMatchSomethingElse(t *testing.T) {
	r := Row{Agent: "scout", Address: "2a04:2a01:9::50", Technique: "T1486", ID: "T1486"}
	for _, target := range []string{"runner-02", "scout/T1055", "T1055", "2a04:2a01:9::51"} {
		if ParseSelector(target).Matches(r, Endpoint{}) {
			t.Errorf("%q matched a row it does not name", target)
		}
	}
}

func TestSameAddress_ComparesByValueNotByText(t *testing.T) {
	if !SameAddress("2a04:2a01:0:0:0:0:0:50", "2a04:2a01::50") {
		t.Error("a compressed and an expanded form of one address must compare equal")
	}
	if !SameAddress("2a04:2a01::50/128", "2a04:2a01::50") {
		t.Error("a prefix length must not change which address this is")
	}
	if SameAddress("scout", "scout") {
		t.Error("a name that is not an address must never compare equal to one")
	}
	if SameAddress("", "") {
		t.Error("two absences are not one address")
	}
}

func TestIsTechnique(t *testing.T) {
	for _, ok := range []string{"T1486", "T1021.004", "t1486"} {
		if !IsTechnique(ok) {
			t.Errorf("%q is a technique", ok)
		}
	}
	for _, no := range []string{"", "T148", "T14867", "cve-2026-1234", "T1021.4", "TABCD"} {
		if IsTechnique(no) {
			t.Errorf("%q is not a technique", no)
		}
	}
}

// Sub-techniques inherit the never-quiet property of their parent. T1003.001 is
// credential dumping just as much as T1003 is, and a list that missed it would be a
// closed list with a hole in it.
func TestNeverQuietTechnique_CoversSubTechniques(t *testing.T) {
	for _, yes := range []string{"T1486", "T1490", "T1003", "T1003.001", "T1562", "T1562.001", "T1070", "t1486"} {
		if !NeverQuietTechnique(yes) {
			t.Errorf("%q must be on the never-quiet list", yes)
		}
	}
	for _, no := range []string{"", "T1055", "T1021.004", "cve-2026-1234"} {
		if NeverQuietTechnique(no) {
			t.Errorf("%q must not be on the never-quiet list", no)
		}
	}
}
