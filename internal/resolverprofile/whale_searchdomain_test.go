// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"strings"
	"testing"
)

// search domains - the REAL OS search domain, which is the primary mechanism behind
// `ping db-01`. What looked like a search list was
// systemd-resolved ROUTING syntax ("~example.com"), which never completes a bare
// name. These rows pin the difference on all three platforms, and pin the two
// properties that keep the apply safe: we only ever ADD our suffix, and revert
// removes exactly ours.

const (
	wbIP     = "2a04:2a01:0:53::5"
	wbSuffix = "t9ab.agents.whisper.online"
)

func TestLinuxDropInCarriesRoutingAndSearchSeparately(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{wbIP}, SearchDomains: []string{wbSuffix}}
	r := p.Render(Host{ResolvedActive: true})

	content := r.Apply[0].File.Content
	want := "Domains=~. " + wbSuffix + "\n"
	if !strings.Contains(content, want) {
		t.Fatalf("the drop-in must carry the routing entry AND an untilded search domain:\n%s", content)
	}
}

func TestLinuxDropInWithNoSearchDomainIsByteIdenticalToBefore(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{wbIP}}
	r := p.Render(Host{ResolvedActive: true})

	if !strings.Contains(r.Apply[0].File.Content, "Domains=~.\n") {
		t.Fatalf("a profile with no search domain must render exactly the original line:\n%s", r.Apply[0].File.Content)
	}
}

func TestLinuxResolvConfFallbackGetsARealSearchLine(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{wbIP}, SearchDomains: []string{wbSuffix}}
	r := p.Render(Host{ResolvedActive: false})

	var got string
	for _, s := range r.Apply {
		if s.File != nil && s.File.Path == LinuxResolvConf {
			got = s.File.Content
		}
	}
	if got != "nameserver "+wbIP+"\nsearch "+wbSuffix+"\n" {
		t.Fatalf("resolv.conf fallback must carry a search line, got %q", got)
	}
}

func TestLinuxResolvConfHasNoEmptySearchDirective(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{wbIP}}
	r := p.Render(Host{ResolvedActive: false})

	for _, s := range r.Apply {
		if s.File != nil && s.File.Path == LinuxResolvConf && strings.Contains(s.File.Content, "search") {
			t.Fatalf("no search domain must mean NO search directive, got %q", s.File.Content)
		}
	}
}

func TestSearchDomainsAreNormalisedNeverEmittedRaw(t *testing.T) {
	p := Profile{
		Mode: ModeDNS53, OS: "linux", ResolverIPs: []string{wbIP},
		// A caller may hand us routing syntax, a trailing dot, blanks and duplicates.
		SearchDomains: []string{"~" + wbSuffix + ".", " ", wbSuffix, ".", "corp.example"},
	}
	r := p.Render(Host{ResolvedActive: true})

	want := "Domains=~. " + wbSuffix + " corp.example\n"
	if !strings.Contains(r.Apply[0].File.Content, want) {
		t.Fatalf("search domains must be trimmed, untilded, undotted and deduplicated:\n%s", r.Apply[0].File.Content)
	}
}

func TestDarwinProfileCarriesSearchDomains(t *testing.T) {
	got := AppleMobileconfigWithSearch("https://doh.whisper.online/tok/dns-query", []string{wbSuffix})

	if !strings.Contains(got, "<key>SearchDomains</key>") || !strings.Contains(got, "<string>"+wbSuffix+"</string>") {
		t.Fatalf("the macOS DNS payload must carry SearchDomains:\n%s", got)
	}
}

func TestDarwinProfileWithoutSearchIsUnchangedAndStillDeterministic(t *testing.T) {
	url := "https://doh.whisper.online/tok/dns-query"
	if AppleMobileconfigWithSearch(url, nil) != AppleMobileconfig(url) {
		t.Fatal("an empty search list must render the original profile byte-identically")
	}
	if AppleMobileconfigWithSearch(url, []string{wbSuffix}) == AppleMobileconfig(url) {
		t.Fatal("a search list must actually change the profile")
	}
	// The UUIDs stay keyed on the URL alone, so macOS upgrades the profile in place.
	withSearch := AppleMobileconfigWithSearch(url, []string{wbSuffix})
	uuid := deterministicUUID("whisper-resolver-cfg:", url)
	if !strings.Contains(withSearch, uuid) {
		t.Fatal("the profile UUID must stay keyed on the URL so a re-render upgrades in place")
	}
}

func TestWindowsSuffixListIsAdditiveAndRevertRemovesOnlyOurs(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{wbIP}, SearchDomains: []string{wbSuffix}}
	r := p.Render(Host{})

	var apply, revert string
	for _, s := range r.Apply {
		if strings.Contains(s.Shell, "SuffixSearchList") {
			apply = s.Shell
		}
	}
	for _, s := range r.Revert {
		if strings.Contains(s.Shell, "SuffixSearchList") {
			revert = s.Shell
		}
	}
	if apply == "" || revert == "" {
		t.Fatalf("windows must both set and unset the suffix search list\napply=%q\nrevert=%q", apply, revert)
	}
	if !strings.Contains(apply, "Get-DnsClientGlobalSetting") || !strings.Contains(apply, "$cur +") {
		t.Fatalf("the apply must UNION with the machine's existing list, never replace it: %q", apply)
	}
	if !strings.Contains(revert, "-notcontains") {
		t.Fatalf("the revert must remove exactly our suffixes and leave the rest: %q", revert)
	}
	if !strings.Contains(apply, "'"+wbSuffix+"'") {
		t.Fatalf("the suffix must be PowerShell-quoted: %q", apply)
	}
}

func TestWindowsWithNoSearchDomainTouchesTheSuffixListAtAll(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "windows", ResolverIPs: []string{wbIP}}
	r := p.Render(Host{})

	for _, s := range append(append([]Step{}, r.Apply...), r.Revert...) {
		if strings.Contains(s.Shell, "SuffixSearchList") {
			t.Fatalf("with no search domain we must not touch the machine's suffix list: %q", s.Shell)
		}
	}
}

func TestDohModeAlsoInstallsTheSearchDomainOnEveryOS(t *testing.T) {
	// The search list is orthogonal to the transport: a DoH profile needs it just
	// as much as a :53 one, and forgetting one mode is exactly how a bare name
	// works on one machine and not on the next.
	lin := Profile{Mode: ModeDoH, OS: "linux", DohTemplate: "https://doh.whisper.online/tok/dns-query", SearchDomains: []string{wbSuffix}}
	r := lin.Render(Host{ResolvedActive: true, ForwarderKind: "cloudflared", ForwarderPath: "/usr/bin/cloudflared"})
	found := false
	for _, s := range r.Apply {
		if s.File != nil && s.File.Path == LinuxDropIn && strings.Contains(s.File.Content, " "+wbSuffix+"\n") {
			found = true
		}
	}
	if !found {
		t.Fatal("the linux DoH plan must install the search domain too")
	}

	win := Profile{Mode: ModeDoH, OS: "windows", DohTemplate: "https://doh.whisper.online/tok/dns-query", SearchDomains: []string{wbSuffix}}
	rw := win.Render(Host{})
	found = false
	for _, s := range rw.Apply {
		if strings.Contains(s.Shell, "SuffixSearchList") {
			found = true
		}
	}
	if !found {
		t.Fatal("the windows DoH plan must install the search domain too")
	}
}
