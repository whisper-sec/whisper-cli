// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"testing"
)

// tspolicy_test.go covers their grammar, and in particular the destination split, which is
// where a wrong answer silently loses a rule's destination or invents a port constraint.

func TestSplitDstFindsThePortAfterTheLastColon(t *testing.T) {
	cases := []struct{ in, target, ports string }{
		{"tag:prod:443", "tag:prod", "443"},
		{"tag:prod", "tag:prod", ""},
		{"group:eng:22", "group:eng", "22"},
		{"group:eng", "group:eng", ""},
		{"*:*", "*", "*"},
		{"100.64.0.1:80,443", "100.64.0.1", "80,443"},
		{"fd7a:115c::/48:443", "fd7a:115c::/48", "443"},
		{"fd7a:115c::/48", "fd7a:115c::/48", ""},
		{"db-01:5432", "db-01", "5432"},
		{"autogroup:internet:*", "autogroup:internet", "*"},
		{"autogroup:internet", "autogroup:internet", ""},
		{"tag:prod:1000-2000", "tag:prod", "1000-2000"},
	}
	for _, c := range cases {
		target, ports := SplitDst(c.in)
		if target != c.target || ports != c.ports {
			t.Errorf("SplitDst(%q) = (%q, %q), want (%q, %q)", c.in, target, ports, c.target, c.ports)
		}
	}
}

// The negative that matters: `tag:prod` must never be read as target "tag" with port
// "prod", because that silently retargets somebody's rule.
func TestSplitDstNeverInventsAPortFromAName(t *testing.T) {
	for _, in := range []string{"tag:prod", "group:eng", "autogroup:member", "ipset:corp", "host-alias"} {
		if _, ports := SplitDst(in); ports != "" {
			t.Errorf("SplitDst(%q) invented the port %q", in, ports)
		}
	}
}

func TestIsPortConstrained(t *testing.T) {
	for _, in := range []string{"443", "80,443", "1000-2000"} {
		if !IsPortConstrained(in) {
			t.Errorf("%q should narrow the rule", in)
		}
	}
	for _, in := range []string{"", "*", "  "} {
		if IsPortConstrained(in) {
			t.Errorf("%q narrows nothing and must not be reported as a constraint", in)
		}
	}
}

func TestSplitProtoPorts(t *testing.T) {
	cases := []struct{ in, proto, ports string }{
		{"tcp:443", "tcp", "443"},
		{"udp:*", "udp", "*"},
		{"443", "", "443"},
		{"icmp", "icmp", "*"},
		{"*", "", "*"},
	}
	for _, c := range cases {
		proto, ports := SplitProtoPorts(c.in)
		if proto != c.proto || ports != c.ports {
			t.Errorf("SplitProtoPorts(%q) = (%q, %q), want (%q, %q)", c.in, proto, ports, c.proto, c.ports)
		}
	}
}

// Their files really do carry a bare string where the schema says list. Accepting both is
// the difference between migrating a fleet and telling its owner their file is wrong.
func TestStringListAcceptsAStringOrAList(t *testing.T) {
	pol, _, err := ParsePolicy([]byte(`{"acls":[{"action":"accept","src":"group:eng","dst":["tag:prod:443"]}]}`))
	if err != nil {
		t.Fatalf("a policy with a scalar src did not parse: %v", err)
	}
	if len(pol.ACLs) != 1 || len(pol.ACLs[0].Src) != 1 || pol.ACLs[0].Src[0] != "group:eng" {
		t.Fatalf("the scalar src did not become a one-element list: %+v", pol.ACLs)
	}
}

func TestParsePolicyCountsLinesAndKeepsUnknownSections(t *testing.T) {
	src := []byte("{\n // a comment\n \"acls\": [],\n \"somethingNew\": {\"a\": 1}\n}")
	pol, lines, err := ParsePolicy(src)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if lines != 5 {
		t.Fatalf("line count %d, want 5 (the header line the report prints)", lines)
	}
	extras := pol.ExtraSections()
	if len(extras) != 1 || extras[0] != "somethingNew" {
		t.Fatalf("an unmodelled policy section was not recorded: %v", extras)
	}
}

func TestParsePolicyReportsMalformedInputClearly(t *testing.T) {
	_, _, err := ParsePolicy([]byte(`{"acls": [`))
	if err == nil {
		t.Fatal("a truncated policy file parsed successfully")
	}
}
