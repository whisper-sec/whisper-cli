// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

// the search-domain work - the tenant namespace the resolver profile installs as a search
// domain is derived from the device's own FQDN, and a name we cannot read that
// way yields NOTHING rather than a guess (a guessed suffix would silently send a
// bare hostname into somebody else's namespace).
func TestParentOfFqdn(t *testing.T) {
	cases := []struct{ in, want string }{
		{"resolver-linux.t9ab.agents.whisper.online.", "t9ab.agents.whisper.online"},
		{"  Resolver-Linux.T9AB.Agents.Whisper.Online  ", "t9ab.agents.whisper.online"},
		{"a1b2.example.com", "example.com"},
		{"host.localdomain", ""}, // a bare parent label is never a tenant namespace
		{"single", ""},
		{"", ""},
		{".", ""},
		{"trailing.", ""},
	}
	for _, c := range cases {
		if got := parentOfFqdn(c.in); got != c.want {
			t.Errorf("parentOfFqdn(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSearchSuffixPrefersTheMemberNamespace: the search domain must be the FLEET
// namespace, which is where the member name lives, not the agent's own island, which is
// where the canonical a<hex> name lives. op:register returns both; picking `fqdn`
// installs the one suffix under which the name a person types does not exist.
func TestSearchSuffixPrefersTheMemberNamespace(t *testing.T) {
	fleet := "t0123456789abcdef0123456789abcdef.agents.whisper.online"
	island := "tfedcba9876543210fedcba9876543210.agents.whisper.online"

	reparented := map[string]any{
		"fqdn":   "a124d220cdcd4b538." + island + ".",
		"member": "db-01." + fleet + ".",
	}
	if got := parentOfFqdn(field(reparented, "member", "fqdn")); got != fleet {
		t.Errorf("re-parented agent: search suffix = %q, want the fleet namespace %q", got, fleet)
	}

	// A control plane from before the member column returns no `member` at all; the fqdn's
	// parent is still the right answer there, so the fallback is not a degradation.
	legacyShape := map[string]any{"fqdn": "a124d220cdcd4b538." + island + "."}
	if got := parentOfFqdn(field(legacyShape, "member", "fqdn")); got != island {
		t.Errorf("legacy-shape agent: search suffix = %q, want %q", got, island)
	}

	// And an empty member column behaves exactly like an absent one.
	blank := map[string]any{"fqdn": "a1." + island + ".", "member": ""}
	if got := parentOfFqdn(field(blank, "member", "fqdn")); got != island {
		t.Errorf("blank member column: search suffix = %q, want %q", got, island)
	}
}
