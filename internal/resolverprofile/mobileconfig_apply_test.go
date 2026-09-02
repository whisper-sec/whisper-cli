// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

// The apply-cluster tests for the DARWIN side of the Tier-2 plan: the
// .mobileconfig renders valid XML and round-trips, the deterministic UUIDs
// hold the Java UUID.nameUUIDFromBytes contract, and the darwin plan stays
// HONEST about the one gesture Apple requires. Pure - they run anywhere.

func TestT2ApplyMobileconfigValidXML(t *testing.T) {
	doc := AppleMobileconfig("https://doh.whisper.online/dns-query")
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		if _, err := dec.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("the rendered .mobileconfig is not well-formed XML: %v\n%s", err, doc)
		}
	}
	for _, want := range []string{
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"`,
		"<plist version=\"1.0\">",
		"com.apple.dnsSettings.managed",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("profile is missing %q:\n%s", want, doc)
		}
	}
}

func TestT2ApplyMobileconfigRoundTrip(t *testing.T) {
	// The ServerURL must survive render -> parse byte-exact, including a URL
	// that needs XML escaping (defensive; the real grammar is closed).
	for _, url := range []string{
		"https://doh.whisper.online/dns-query",
		"https://doh.whisper.online/tok_abc123/dns-query",
		"https://doh.whisper.online/a&b<c>d/dns-query",
	} {
		doc := AppleMobileconfig(url)
		if got := plistStringValue(t, doc, "ServerURL"); got != url {
			t.Fatalf("ServerURL round-trip: got %q, want %q", got, url)
		}
		if got := plistStringValue(t, doc, "DNSProtocol"); got != "HTTPS" {
			t.Fatalf("DNSProtocol = %q, want HTTPS", got)
		}
		// macOS refuses a managed-DNS payload without system scope.
		if got := plistStringValue(t, doc, "PayloadScope"); got != "System" {
			t.Fatalf("PayloadScope = %q, want System", got)
		}
	}
}

func TestT2ApplyMobileconfigDeterministicUUIDs(t *testing.T) {
	url := "https://doh.whisper.online/dns-query"
	// Golden vectors computed independently (MD5-based RFC 4122 v3, the Java
	// UUID.nameUUIDFromBytes contract): same seed, same UUID, forever.
	doc := AppleMobileconfig(url)
	for _, uuid := range []string{
		"63F707EE-6272-3B9B-9043-3C7BF1EAAB02", // dns payload (salt whisper-resolver-dns:)
		"EEF35138-97BB-383C-89C3-E387EA28AA2E", // configuration (salt whisper-resolver-cfg:)
	} {
		if !strings.Contains(doc, uuid) {
			t.Fatalf("deterministic UUID %s missing (nameUUIDFromBytes contract broken):\n%s", uuid, doc)
		}
	}
	if doc != AppleMobileconfig(url) {
		t.Fatalf("the render must be byte-stable for a given URL")
	}
	// Version and variant bits: xxxxxxxx-xxxx-3xxx-[89AB]xxx-...
	u := deterministicUUID("whisper-resolver-dns:", "any-seed")
	if u[14] != '3' {
		t.Fatalf("UUID version nibble = %c, want 3 (name-based md5): %s", u[14], u)
	}
	if !strings.ContainsRune("89AB", rune(u[19])) {
		t.Fatalf("UUID variant nibble = %c, want RFC 4122 (8/9/A/B): %s", u[19], u)
	}
	if u != strings.ToUpper(u) {
		t.Fatalf("UUIDs are uppercased in Apple profiles: %s", u)
	}
}

func TestT2ApplyMobileconfigStableIdentifiers(t *testing.T) {
	doc := AppleMobileconfig("https://doh.whisper.online/dns-query")
	// Stable identifiers are what `--off` addresses; they must not drift.
	for _, want := range []string{
		"<string>online.whisper.resolver</string>",
		"<string>online.whisper.resolver.dns</string>",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("stable PayloadIdentifier %q missing:\n%s", want, doc)
		}
	}
}

func TestT2ApplyDarwinPlanKeyedUsesSignedProfile(t *testing.T) {
	p := Profile{
		Mode:            ModeDoH,
		OS:              "darwin",
		DohTemplate:     "https://doh.whisper.online/tok_abc/dns-query",
		AppleProfileURL: "https://resolver.whisper.online/apple/tok_abc.mobileconfig",
	}
	r := p.Render(Host{})
	if len(r.Apply) != 2 {
		t.Fatalf("keyed darwin DoH = download + open, got %v", r.Apply)
	}
	curl := r.Apply[0].Cmd
	if len(curl) == 0 || curl[0] != "curl" || curl[len(curl)-1] != p.AppleProfileURL {
		t.Fatalf("keyed darwin must download the CMS-SIGNED profile: %v", curl)
	}
	if open := r.Apply[1].Cmd; len(open) != 2 || open[0] != "open" {
		t.Fatalf("the staged profile must be opened for approval: %v", open)
	}
}

func TestT2ApplyDarwinPlanKeylessRendersLocally(t *testing.T) {
	p := Profile{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"}
	r := p.Render(Host{})
	if len(r.Apply) == 0 || r.Apply[0].File == nil {
		t.Fatalf("keyless darwin DoH must write the profile locally: %v", r.Apply)
	}
	if got := r.Apply[0].File.Content; got != AppleMobileconfig(p.DohTemplate) {
		t.Fatalf("the written profile must be the canonical render")
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "unsigned") {
		t.Fatalf("an unsigned local profile must say so plainly: %v", r.Notes)
	}
}

func TestT2ApplyDarwinPlanIsHonestAboutApproval(t *testing.T) {
	// Modern macOS refuses a silent CLI profile install, so the
	// plan must say the approval gesture out loud and never claim otherwise.
	for _, p := range []Profile{
		{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"},
		{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/t/dns-query",
			AppleProfileURL: "https://resolver.whisper.online/apple/t.mobileconfig"},
	} {
		notes := strings.Join(p.Render(Host{}).Notes, "\n")
		if !strings.Contains(notes, "System Settings") || !strings.Contains(notes, "VPN & Device Management") {
			t.Fatalf("darwin DoH notes must name the exact approval step: %v", notes)
		}
		if !strings.Contains(notes, "no silent") {
			t.Fatalf("darwin DoH notes must state that no silent install exists: %v", notes)
		}
	}
}

func TestT2ApplyDarwinPlanDNS53NoGUI(t *testing.T) {
	p := Profile{Mode: ModeDNS53, OS: "darwin", ResolverIPs: []string{"2a04:2a01:0:53::42"}}
	r := p.Render(Host{})
	if len(r.Apply) != 1 || !strings.Contains(r.Apply[0].Shell, `networksetup -setdnsservers "$s" 2a04:2a01:0:53::42`) {
		t.Fatalf("darwin dns53 must apply via networksetup per service: %v", r.Apply)
	}
	if !strings.Contains(r.Revert[0].Shell, `networksetup -setdnsservers "$s" Empty`) {
		t.Fatalf("darwin dns53 revert must return services to automatic: %v", r.Revert)
	}
	// Unlike DoH, no GUI gesture may be demanded here - this is the one
	// genuinely no-approval macOS path.
	if notes := strings.Join(r.Notes, "\n"); strings.Contains(notes, "System Settings") {
		t.Fatalf("dns53 must not require the GUI: %v", notes)
	}
}

func TestT2ApplyDarwinRevertAddressesStableIdentifier(t *testing.T) {
	p := Profile{Mode: ModeDoH, OS: "darwin", DohTemplate: "https://doh.whisper.online/dns-query"}
	r := p.Render(Host{})
	joined := ""
	for _, s := range r.Revert {
		joined += s.String() + "\n"
	}
	if !strings.Contains(joined, "profiles remove -identifier online.whisper.resolver") {
		t.Fatalf("DoH revert must address the profile by its stable identifier: %s", joined)
	}
	if !strings.Contains(joined, "remove "+darwinMobileconfigFile) {
		t.Fatalf("DoH revert must clean up the staged file: %s", joined)
	}
}

// plistStringValue walks the plist and returns the <string> immediately
// following <key>key</key>.
func plistStringValue(t *testing.T, doc, key string) string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	expectValue := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "key":
			var k string
			if err := dec.DecodeElement(&k, &start); err != nil {
				t.Fatalf("decode key: %v", err)
			}
			expectValue = k == key
		case "string":
			var v string
			if err := dec.DecodeElement(&v, &start); err != nil {
				t.Fatalf("decode string: %v", err)
			}
			if expectValue {
				return v
			}
		default:
			// a dict/array between the key and a string value resets nothing:
			// plist puts the value element right after its key.
		}
	}
	t.Fatalf("<key>%s</key> with a string value not found in:\n%s", key, doc)
	return ""
}
