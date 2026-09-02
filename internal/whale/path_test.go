// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"strings"
	"testing"
)

// TestPathFor_NeverRendersDirectWithoutEvidence is the load-bearing test of this package.
//
// direct paths made a direct path possible for two topologies, so `direct` is no longer a
// word this build can never print. What has NOT changed is the rule underneath: it may be
// printed only when an Observation says a direct path was actually established. A
// topology claim, a control-plane row, a hopeful default - none of those are evidence, and
// none of them may produce the word.
func TestPathFor_NeverRendersDirectWithoutEvidence(t *testing.T) {
	for _, measured := range []bool{false, true} {
		for _, reachable := range []bool{false, true} {
			for _, class := range []string{"", PathDirectLocal, PathDirectPublic, "made-up"} {
				o := Observation{Measured: measured, Reachable: reachable, Class: class}
				got := PathFor(o) // Direct is deliberately left false: no evidence
				if strings.Contains(strings.ToLower(got), "direct") {
					t.Fatalf("PathFor(%+v) = %q; nothing proved a direct path, so none may be rendered", o, got)
				}
			}
		}
	}
}

// TestPathFor_RendersTheClassItWasGivenEvidenceFor: with evidence, the cell names WHICH of
// the two original cases it was, because "direct" alone does not tell a reader whether they
// got it by sharing a LAN or by being publicly dialable - and those fail differently.
func TestPathFor_RendersTheClassItWasGivenEvidenceFor(t *testing.T) {
	if got := PathFor(Observation{Measured: true, Reachable: true, Direct: true, Class: PathDirectLocal}); got != PathDirectLocal {
		t.Fatalf("got %q, want %q", got, PathDirectLocal)
	}
	if got := PathFor(Observation{Measured: true, Reachable: true, Direct: true, Class: PathDirectPublic}); got != PathDirectPublic {
		t.Fatalf("got %q, want %q", got, PathDirectPublic)
	}
	// Evidence but no class: the generic word, never a guess at which case it was.
	if got := PathFor(Observation{Measured: true, Reachable: true, Direct: true}); got != "direct" {
		t.Fatalf("got %q, want the generic direct", got)
	}
	// An unrecognised class is not a direct path we can name, so it is not one we claim.
	if got := PathFor(Observation{Measured: true, Reachable: true, Direct: true, Class: "punched"}); got != "direct" {
		t.Fatalf("got %q, want the generic direct for an unknown class", got)
	}
}

// TestPathForClass_RefusesAnythingItCannotName: the translation from the control plane's
// token to the PATH cell is the only place a renderer gets the word, so it has to be
// closed. Anything unrecognised is relayed, which is the truth for every pair the first step
// does not cover.
func TestPathForClass_RefusesAnythingItCannotName(t *testing.T) {
	for _, bad := range []string{"", "direct", "punched", "DIRECT-LOCAL", "relayed", "no path"} {
		if got := PathForClass(bad); got != PathRelayed {
			t.Fatalf("PathForClass(%q) = %q, want %q", bad, got, PathRelayed)
		}
	}
	if PathForClass(PathDirectLocal) != PathDirectLocal || PathForClass(PathDirectPublic) != PathDirectPublic {
		t.Fatal("the two classes that are carried must round-trip")
	}
}

// TestUniversalDirectPathIsStillFalse is the tripwire that matters now, and the punch
// narrowed the reason it holds without removing it. NAT traversal exists: a node behind an
// ordinary NAT gets a direct path by punching. What it does not reach is a pair where BOTH
// ends sit behind a NAT that gives each destination a different external port, and until
// something covers that, a path between ANY two nodes cannot be assumed. Everything that
// needs one - subnet routes, exit nodes - reads this flag and refuses, because a route is
// ridden by every node that uses it and cannot be granted per-pair from evidence.
func TestUniversalDirectPathIsStillFalse(t *testing.T) {
	if UniversalDirectPathAvailable {
		t.Fatal("UniversalDirectPathAvailable is true. A direct path between ANY two nodes " +
			"needs the both-ends-port-varying case covered, and the relay is what carries it " +
			"today. If that has landed, open the subnet-route and exit-node refusals in the " +
			"same commit and change this test with them.")
	}
}

// TestPathVocabularyIsClosed: the exported set is what renderers may print, and it stays
// closed. The punch added exactly one member; adding a word to what a surface
// may claim about somebody's network is a decision, and it belongs in this list first.
func TestPathVocabularyIsClosed(t *testing.T) {
	v := PathVocabulary()
	want := map[string]bool{PathRelayed: true, PathNoPath: true, "direct": true,
		PathDirectLocal: true, PathDirectPublic: true, PathDirectPunched: true}
	if len(v) != len(want) {
		t.Fatalf("PathVocabulary() = %v, want exactly %d values", v, len(want))
	}
	for _, s := range v {
		if !want[s] {
			t.Fatalf("PathVocabulary() offers %q, which is outside the closed set", s)
		}
	}
}

// TestPathFor_AMeasuredSilenceIsNoPath: the point of measuring is that a probe which got
// nothing back must not render as the same cell as a peer nobody probed.
func TestPathFor_AMeasuredSilenceIsNoPath(t *testing.T) {
	if got := PathFor(Observation{Measured: true, Reachable: false}); got != PathNoPath {
		t.Fatalf("a measured silence rendered as %q, want %q", got, PathNoPath)
	}
	if got := PathFor(Observation{Measured: true, Reachable: true}); got != PathRelayed {
		t.Fatalf("a measured answer rendered as %q, want %q", got, PathRelayed)
	}
	if got := PathFor(Observation{}); got != PathRelayed {
		t.Fatalf("an unmeasured peer rendered as %q, want the topology fact %q", got, PathRelayed)
	}
}

// TestPathNote_SaysWhatWasNotMeasured: the footnote is what keeps the column from being
// read as a promise, so it has to carry both halves of the truth.
func TestPathNote_SaysWhatWasNotMeasured(t *testing.T) {
	n := PathNote()
	// It has to carry the win AND the limit in the same breath: a partial win that reads as
	// a general one is the failure this keeps hitting.
	// The win AND the limit, in the same breath: NAT traversal now exists, so the note must
	// name it - and must say in the same sentence what it still does not reach, because a
	// partial win that reads as a general one is the failure this keeps hitting.
	for _, want := range []string{"relayed", "direct-local", "direct-public", "direct-punch",
		"varies its port per destination", "split across two boxes", "measured"} {
		if !strings.Contains(n, want) {
			t.Fatalf("PathNote() = %q, missing %q", n, want)
		}
	}
}
