// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// `whale migrate plan --help` used to open with "This command performs GETs and nothing else."
// A reader takes that literally, and it is not true on the host they are standing on: the command's whole
// purpose is to write a plan file, and the very next thing the story asks them to do is `jq` it.
//
// The claim it was reaching for is true and worth keeping - every call to EITHER SIDE is a GET, and that is
// structural rather than a promise because whale.HTTPReader has exactly one method. It just has to be said
// about the sides rather than about the command. Being conservative in what we emit cuts this way too: help
// text is something we emit, and a sentence a reader can catch out is a sentence they stop believing the
// rest of.
//
// TestPlanIsReadOnlyOnBothSides is the other half and stays where it is: it drives the real command against a
// fake tailnet and asserts every recorded method is a GET. This one holds the prose to what that test proves.
func TestPlanHelpDoesNotClaimItWritesNothingAtAll(t *testing.T) {
	help := planHelp(t)

	if strings.Contains(help, "performs GETs and nothing else") {
		t.Error("`plan` writes the plan file it exists to produce, so it does not perform GETs and " +
			"nothing else. Say the true thing about the two SIDES instead.")
	}
	for _, want := range []string{
		"Every call it makes to either side is a GET",
		"no write\nmethod at all",
		"the plan file you name with -o",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("`plan --help` no longer says %q.\n--- help ---\n%s", want, help)
		}
	}
}

// The control, so the test above is reading real help text and not an empty string. A cobra command answers
// almost anything, so "the assertion passed" and "there was nothing to assert on" look identical without it.
func TestPlanHelpIsActuallyBeingRead(t *testing.T) {
	help := planHelp(t)
	if len(help) < 200 {
		t.Fatalf("only %d bytes of help came back; the test above would be asserting over nothing", len(help))
	}
	if !strings.Contains(help, "Read a Tailscale tailnet") {
		t.Fatalf("this is not the plan help at all:\n%s", help)
	}
}

func planHelp(t *testing.T) string {
	t.Helper()
	cmd := whaleSubcommand(t, "whale", "migrate", "plan")
	return cmd.Long + "\n" + cmd.Short
}
