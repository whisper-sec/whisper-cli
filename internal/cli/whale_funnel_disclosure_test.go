// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// This file carries a standing requirement that outlives the feature it is waiting for: until a funnelled
// /128 can be reached by another tenant's agent, `whale funnel --help` and the public doc must keep
// saying plainly that a funnel reaches the internet AND that another tenant's Whisper agent is
// governed by the east-west plane. Both were true when this file was written; nothing made them
// stay true. A sentence is the only warning a customer gets before they publish a port and find
// that one class of caller - another Whisper customer - is refused, so it is worth a test.
//
// The disclosure sits in newWhaleExposeCmd's ScopeInternet arm, so it renders only for `funnel`.
// Asserting it on `funnel` AND asserting `serve` does not carry it is deliberate: a well-meaning
// edit that hoists the paragraph into the shared `long` would put a cross-tenant caveat on a
// command whose whole point is that only your own fleet is answered, which is a different lie.

// the load-bearing halves of the disclosure, as a reader has to be able to read them.
var funnelDisclosure = []string{
	"ANOTHER tenant",
	"east-west plane",
	"refused",
}

func TestFunnelHelpDisclosesTheCrossTenantLimit(t *testing.T) {
	long := whaleSubcommand(t, "whale", "funnel").Long
	if long == "" {
		t.Fatal("`whisper whale funnel` has no long help at all, so it discloses nothing")
	}
	for _, want := range funnelDisclosure {
		if !strings.Contains(long, want) {
			t.Errorf("`whisper whale funnel --help` no longer says %q.\n"+
				"A caller that is itself a Whisper /128 in another tenant is governed by the\n"+
				"east-west plane and can be refused while the rest of the internet is answered.\n"+
				"While that is true, the help text is the only place a customer learns it.\n"+
				"Restore the sentence, or remove the limit and delete this test.\n"+
				"help was:\n%s", want, long)
		}
	}
}

func TestFunnelHelpStillPromisesTheInternet(t *testing.T) {
	// The other half of the same requirement. A caveat with nothing to caveat is not a disclosure.
	long := whaleSubcommand(t, "whale", "funnel").Long
	if !strings.Contains(long, "INTERNET") {
		t.Errorf("`whisper whale funnel --help` no longer says it exposes the port to the internet;"+
			" the standing requirement is that it says BOTH things.\nhelp was:\n%s", long)
	}
}

func TestServeHelpDoesNotCarryTheCrossTenantCaveat(t *testing.T) {
	// The control for the two tests above: `serve` answers your fleet only, so the east-west
	// caveat does not apply to it. If this ever fires alongside a green funnel test, the
	// paragraph was hoisted into shared help and now says something untrue about `serve`.
	long := whaleSubcommand(t, "whale", "serve").Long
	if strings.Contains(long, "ANOTHER tenant") {
		t.Errorf("`whisper whale serve --help` carries the funnel caveat. serve answers only"+
			" your own fleet, so a cross-tenant caveat there describes a limit that is not the"+
			" one serve has.\nhelp was:\n%s", long)
	}
}
