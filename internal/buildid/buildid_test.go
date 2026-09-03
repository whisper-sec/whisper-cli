// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package buildid

import (
	"runtime/debug"
	"testing"
)

// buildid_test.go drives resolve directly rather than ID/Time, because the
// package variables are fixed at init from THIS binary's own build info and a
// `go test` binary carries no VCS stamp at all (verified: ID() is "" under
// go test and a real revision in a `go build` artifact). Testing through the
// accessors would therefore assert "" against "" and prove nothing.

// info builds a BuildInfo carrying exactly the settings named.
func info(kv ...string) *debug.BuildInfo {
	bi := &debug.BuildInfo{}
	for i := 0; i+1 < len(kv); i += 2 {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
	}
	return bi
}

const fullRev = "d6d4c5f4998e776648641163671166481b277a08"

func TestResolveAbbreviatesTheRevisionAndKeepsTheTime(t *testing.T) {
	id, when := resolve(info("vcs.revision", fullRev, "vcs.time", "2026-09-01T14:29:59Z", "vcs.modified", "false"), true)
	if id != "d6d4c5f4998e" {
		t.Errorf("id = %q, want the first %d hex digits of the revision", id, shortLen)
	}
	if when != "2026-09-01T14:29:59Z" {
		t.Errorf("time = %q, want the commit time verbatim", when)
	}
}

func TestResolveMarksADirtyTree(t *testing.T) {
	id, _ := resolve(info("vcs.revision", fullRev, "vcs.modified", "true"), true)
	if id != "d6d4c5f4998e"+dirtySuffix {
		t.Errorf("id = %q, want the dirty marker: the revision alone would name a commit "+
			"whose content this binary does not have", id)
	}
}

// A revision shorter than the abbreviation must survive whole rather than be
// sliced out of range.
func TestResolveKeepsAShortRevisionWhole(t *testing.T) {
	if id, _ := resolve(info("vcs.revision", "abc123"), true); id != "abc123" {
		t.Errorf("id = %q, want the short revision unchanged", id)
	}
}

// The absence cases, which are the ones that matter: every one must produce an
// empty identity so the consumer omits the field. A build id nobody can look
// up is worse than none, because a console renders it as a fleet fact.
func TestResolveReportsNothingWhenTheToolchainRecordedNothing(t *testing.T) {
	cases := []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
	}{
		{"ReadBuildInfo said no", nil, false},
		{"nil info with ok true", nil, true},
		{"no settings at all", info(), true},
		{"settings but no vcs keys", info("-trimpath", "true", "CGO_ENABLED", "0"), true},
		{"blank revision", info("vcs.revision", "   "), true},
		// A time with no revision is the trap: it looks like an identity and is
		// shared by every binary built in that second.
		{"time but no revision", info("vcs.time", "2026-09-01T14:29:59Z"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, when := resolve(c.bi, c.ok)
			if id != "" || when != "" {
				t.Errorf("resolve = (%q, %q), want both empty", id, when)
			}
		})
	}
}

// The control for the table above: the same resolve, given a real stamp, does
// return something. Without this an empty result would be indistinguishable
// from a resolve that can never answer.
func TestResolveControlDoesAnswerWhenTheStampIsThere(t *testing.T) {
	if id, _ := resolve(info("vcs.revision", fullRev), true); id == "" {
		t.Fatal("resolve returned nothing for a well-formed stamp, so the absence " +
			"cases above prove nothing")
	}
}

// The accessors must agree with resolve over this binary's own build info,
// whatever that happens to be, so a future refactor cannot leave ID() reading
// a different source than the one under test.
func TestAccessorsMatchResolveOverThisBinary(t *testing.T) {
	wantID, wantTime := resolve(debug.ReadBuildInfo())
	if ID() != wantID || Time() != wantTime {
		t.Errorf("ID()/Time() = (%q, %q), want (%q, %q)", ID(), Time(), wantID, wantTime)
	}
}

// The link-time stamp. build-all.sh passes the revision in because the
// toolchain's own does not survive the checkout shape we build in: a git
// worktree stamps the main clone's HEAD when it is nested inside it, and
// records nothing at all when it is not. Both measured; the published v0.211.0
// assets carry no vcs.* settings whatsoever.

func TestResolveStampedPrefersTheLinkTimeValue(t *testing.T) {
	// The toolchain half is deliberately a DIFFERENT, valid revision. If the
	// stamp were ignored this would still return something that looks correct,
	// which is how the wrong commit gets believed.
	other := "0000111122223333444455556666777788889999"
	id, when := resolveStamped(fullRev, "2026-09-02T05:36:16Z", info("vcs.revision", other, "vcs.time", "2026-01-01T00:00:00Z"), true)
	if id != "d6d4c5f4998e" {
		t.Errorf("id = %q, want the stamped revision abbreviated, not the toolchain's %q", id, other)
	}
	if when != "2026-09-02T05:36:16Z" {
		t.Errorf("time = %q, want the stamped commit time", when)
	}
}

func TestResolveStampedCarriesTheDirtyMarkerThrough(t *testing.T) {
	id, _ := resolveStamped(fullRev+dirtySuffix, "", nil, false)
	if id != "d6d4c5f4998e"+dirtySuffix {
		t.Errorf("id = %q, want the abbreviated revision with the dirty marker kept on the end", id)
	}
}

func TestResolveStampedFallsBackWhenNothingWasStamped(t *testing.T) {
	// An unstamped build must still report whatever the toolchain managed to
	// record. The stamp is an addition, never a replacement.
	id, when := resolveStamped("", "", info("vcs.revision", fullRev, "vcs.time", "2026-09-01T14:29:59Z"), true)
	if id != "d6d4c5f4998e" || when != "2026-09-01T14:29:59Z" {
		t.Errorf("resolveStamped(\"\", \"\", ...) = (%q, %q), want the toolchain values", id, when)
	}
}

func TestResolveStampedTreatsBlankAsUnstamped(t *testing.T) {
	// A build that passes -X with an empty value must not shadow a usable
	// toolchain revision with nothing.
	id, _ := resolveStamped("   ", "  ", info("vcs.revision", fullRev), true)
	if id != "d6d4c5f4998e" {
		t.Errorf("id = %q, want the toolchain revision - whitespace is not a stamp", id)
	}
}

func TestResolveStampedReportsUnknownWhenNeitherSideHasOne(t *testing.T) {
	id, when := resolveStamped("", "", nil, false)
	if id != "" || when != "" {
		t.Errorf("resolveStamped with nothing anywhere = (%q, %q), want empty - unknown must read as unknown", id, when)
	}
}
