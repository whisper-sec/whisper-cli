// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import "testing"

// These are the regression tests: banding follows the graph's RECONCILED
// verdict (verdictLevel / verdictScore / isThreat), never the raw feed evidence
// (threatScore). github.com carries threatScore 40 next to verdictLevel INFO +
// isThreat false; before the fix that raw score family banded it MEDIUM.

// TestBandFromVerdictNotRawEvidence: the live github.com shape must read clean
// (BENIGN, no alert) even though the raw evidence fields look MEDIUM-ish.
func TestBandFromVerdictNotRawEvidence(t *testing.T) {
	github := nodeFromInspect("github.com", map[string]any{
		"labels": []any{"HOSTNAME"},
		"props": map[string]any{
			"verdictLevel": "INFO",
			"verdictScore": float64(16),
			"isThreat":     false,
			"threatScore":  float64(40),
			"threatLevel":  "MEDIUM",
			"advisory":     "multi-tenant-apex",
		},
	})
	if github.Band != "BENIGN" {
		t.Errorf("verdictLevel INFO + isThreat false must band BENIGN (never MEDIUM from raw threatScore), got %q", github.Band)
	}
	if github.Band == "SUSPICIOUS" || github.Band == "MALICIOUS" {
		t.Errorf("isThreat false must NEVER alert, got %q", github.Band)
	}
	// The card's number is the band-consistent verdictScore, plain.
	if github.Props["verdictScore"] != "16" {
		t.Errorf("verdictScore is the one displayable score, got %v", github.Props["verdictScore"])
	}
	// threatScore survives ONLY as labelled evidence, never a bare severity-like number.
	if github.Props["threatScore"] != "40 (evidence)" {
		t.Errorf("threatScore must display as evidence only, got %v", github.Props["threatScore"])
	}
	// advisory is context (a suppressor note), shown as a plain fact.
	if github.Props["advisory"] != "multi-tenant-apex" {
		t.Errorf("advisory must survive as context, got %v", github.Props["advisory"])
	}
}

// TestBandFromVerdictGenuineThreat: a real HIGH verdict with isThreat true still
// bands MALICIOUS; the fix must not soften genuine verdicts.
func TestBandFromVerdictGenuineThreat(t *testing.T) {
	bad := nodeFromInspect("evil.example", map[string]any{
		"labels": []any{"HOSTNAME"},
		"props": map[string]any{
			"verdictLevel": "HIGH",
			"verdictScore": float64(91),
			"isThreat":     true,
			"threatScore":  float64(93),
		},
	})
	if bad.Band != "MALICIOUS" {
		t.Errorf("verdictLevel HIGH + isThreat true must band MALICIOUS, got %q", bad.Band)
	}
}

// TestBandFromVerdictIsThreatClamp: the allowlisted-resolver shape (no verdictLevel,
// a raw threatLevel MEDIUM, isThreat false) clamps to BENIGN; with isThreat true
// the same raw level keeps its SUSPICIOUS band.
func TestBandFromVerdictIsThreatClamp(t *testing.T) {
	resolver := bandFromVerdict(map[string]any{
		"threatLevel": "MEDIUM",
		"isThreat":    false,
	})
	if resolver != "BENIGN" {
		t.Errorf("raw MEDIUM + isThreat false must clamp to BENIGN, got %q", resolver)
	}
	real := bandFromVerdict(map[string]any{
		"threatLevel": "MEDIUM",
		"isThreat":    true,
	})
	if real != "SUSPICIOUS" {
		t.Errorf("raw MEDIUM + isThreat true keeps SUSPICIOUS, got %q", real)
	}
	// No verdict at all stays honestly unassessed, not clean.
	if got := bandFromVerdict(map[string]any{"isThreat": false}); got != "" {
		t.Errorf("no level + isThreat false stays unassessed, got %q", got)
	}
}

// TestCuratePropsSourcesAreEvidence: the sources field reads as feed evidence.
func TestCuratePropsSourcesAreEvidence(t *testing.T) {
	out := curateProps(map[string]any{
		"sources": []any{"feed-a", "feed-b", "feed-c"},
	})
	if out["sources"] != "listed in 3 feeds" {
		t.Errorf("sources must read as feed evidence, got %v", out["sources"])
	}
	one := curateProps(map[string]any{"sources": float64(1)})
	if one["sources"] != "listed in 1 feed" {
		t.Errorf("a numeric sources count must read as feed evidence, got %v", one["sources"])
	}
}
