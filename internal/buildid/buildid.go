// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package buildid answers the one question a version string cannot: WHICH
// BINARY is this?
//
// The version string is stamped by hand at release time and is therefore only
// as honest as the person who stamped it. A host in the lab reported version
// 0.115.0 - a June tag - from a binary built at the end of August, because the
// build that produced it never passed the version ldflag and fell back to the
// literal compiled into the source. A fleet-wide "which hosts run an old
// binary" answered from that string is not merely imprecise, it is wrong.
//
// What DOES discriminate is already inside every binary the Go toolchain
// produces and nobody has to remember to pass it: the toolchain stamps the VCS
// revision, its commit time, and whether the tree was dirty, into the build
// info section. That section survives the release link flags - verified on a
// binary built with the exact release invocation (-trimpath -ldflags "-s -w"):
// -s strips the symbol table and -w strips DWARF, but neither touches
// .go.buildinfo. So the identity rides along for free and cannot drift from
// the source it was built from.
//
// It can still be absent: a build from an exported tarball has no repository
// to read, and -buildvcs=false switches the stamping off. Absent is reported
// as the empty string and every consumer omits the field rather than inventing
// one. An unknown build must read as unknown, never as a build id nobody can
// look up.
//
// Two toolchain behaviours are worth knowing before reading a value from here,
// both measured rather than assumed:
//
//   - A `go test` binary carries NO vcs stamp, only a real `go build` artifact
//     does. Anything under test that reads this package directly therefore sees
//     "" and cannot tell a working wiring from a deleted one, which is why the
//     sensor reaches it through a seam.
//   - Building inside a git worktree (a `.git` FILE rather than a directory)
//     never stamps THIS tree. Nested inside the main clone, the walk up finds
//     the main clone's .git and stamps the OUTER HEAD and dirty state. Anywhere
//     else, it finds no .git directory and records nothing at all, and
//     -buildvcs=true does not make that an error. The published v0.211.0 assets
//     carry no vcs.* settings for exactly that reason, which is why build-all.sh
//     now passes the revision in through Stamped rather than hoping for one.
package buildid

import (
	"runtime/debug"
	"strings"
)

// shortLen is how much of the revision we carry. Twelve hex digits is the
// length git itself grows an abbreviation to on a repository of this size, so
// it is directly greppable in the log of the tree that produced the binary,
// and it stays short enough to sit in a table cell next to a version.
const shortLen = 12

// dirtySuffix marks a binary built from a tree with uncommitted changes. The
// revision alone would name a commit whose content the binary does NOT have,
// which is the same lie the version string was telling.
const dirtySuffix = "-dirty"

// Stamped and StampedTime are set at link time by build-all.sh:
//
//	-X github.com/whisper-sec/whisper-cli/internal/buildid.Stamped=<40-hex>[-dirty]
//	-X github.com/whisper-sec/whisper-cli/internal/buildid.StampedTime=<RFC 3339 UTC>
//
// They exist because the toolchain's own stamp is not reliable where we
// build. `go build` finds the repository by walking up for a .git
// DIRECTORY, and every agent on this project works in a `git worktree`
// checkout whose .git is a FILE. Measured both shapes:
//
//   - a worktree NESTED inside the main clone: the walk steps over the .git
//     file and finds the main clone's, so the binary is stamped with the
//     MAIN checkout's HEAD and dirty state. Not this tree's.
//   - a worktree ANYWHERE ELSE: the walk finds no .git directory at all and
//     -buildvcs=auto silently records nothing. -buildvcs=true does not even
//     turn that into an error, because from its point of view there is no
//     repository to read.
//
// The published v0.211.0 assets have no vcs.* settings whatsoever, so this
// package was inert in every binary we shipped: `whisper version` printed a
// version and nothing to check it against, which is the exact failure it was
// written for. A value the build computes and passes in cannot be lost that
// way, so it wins over the toolchain's when both are present.
var (
	Stamped     string
	StampedTime string
)

var id, buildTime = func() (string, string) {
	bi, ok := debug.ReadBuildInfo()
	return resolveStamped(Stamped, StampedTime, bi, ok)
}()

// ID is this binary's build identity: the abbreviated VCS revision it was
// built from, with a dirty marker when the tree had uncommitted changes.
// Empty when the toolchain recorded no revision, which a caller must render
// as unknown rather than as a value.
func ID() string { return id }

// Time is when the revision ID names was committed, in the toolchain's RFC 3339
// UTC form, or empty when unrecorded. It answers "how old is this binary"
// without a lookup table from revision to date, which is the question an
// operator actually asks first.
func Time() string { return buildTime }

// resolveStamped prefers the value the build passed in and falls back to what
// the toolchain recorded. Split out from the package variables so a test can
// drive both halves; an empty stamp is not a value, so it never shadows a
// usable toolchain revision.
func resolveStamped(stamped, stampedTime string, bi *debug.BuildInfo, ok bool) (string, string) {
	rev := strings.TrimSpace(stamped)
	if rev == "" {
		return resolve(bi, ok)
	}
	dirty := strings.HasSuffix(rev, dirtySuffix)
	rev = strings.TrimSuffix(rev, dirtySuffix)
	if len(rev) > shortLen {
		rev = rev[:shortLen]
	}
	if dirty {
		rev += dirtySuffix
	}
	return rev, strings.TrimSpace(stampedTime)
}

// resolve is the whole of the logic, split out from the package variables so a
// test can drive it with a constructed BuildInfo instead of the test binary's
// own. Returns ("", "") for every shape it cannot read: a nil info, a build
// with no VCS settings, a blank revision.
func resolve(bi *debug.BuildInfo, ok bool) (string, string) {
	if !ok || bi == nil {
		return "", ""
	}
	var rev, when, modified string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = strings.TrimSpace(s.Value)
		case "vcs.time":
			when = strings.TrimSpace(s.Value)
		case "vcs.modified":
			modified = strings.TrimSpace(s.Value)
		}
	}
	if rev == "" {
		// No revision means no identity. A build time on its own would look
		// like an identity while being shared by every binary built in that
		// second, so it is withheld too.
		return "", ""
	}
	if len(rev) > shortLen {
		rev = rev[:shortLen]
	}
	if modified == "true" {
		rev += dirtySuffix
	}
	return rev, when
}
