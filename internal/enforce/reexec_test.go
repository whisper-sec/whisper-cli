// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import "testing"

// Every helper process this package re-executes the CLI as has an entry in the dispatch the CLI's main runs first,
// and nothing else does: a probe the dispatch did not know would be taken for a command line and refused by the
// command tree, and every containment on a host that needs that probe would then refuse.
func TestEveryHelperTheCLIStartsHasAnEntry(t *testing.T) {
	for _, arg := range []string{InitArg, ProbeArg, PlaceProbeArg} {
		if ReexecEntry([]string{"whisper", arg}) == nil {
			t.Errorf("%s has no entry", arg)
		}
	}
	for _, args := range [][]string{nil, {"whisper"}, {"whisper", "contain"}, {"whisper", "__whisper-unknown"}} {
		if ReexecEntry(args) != nil {
			t.Errorf("%q was taken for a helper", args)
		}
	}
}
