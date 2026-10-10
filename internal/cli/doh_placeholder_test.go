// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

// The control plane stopped interpolating the raw credential into doh_url: it returned the
// secret twice under two names and only one of them announced itself, which is how a live key
// reached a transcript. The URL still has to work, so the substitution moved to the client,
// against the credential in the SAME record. These pin both halves: that it is filled when a
// credential is there, and that it is NOT quietly emptied when one is not.

func TestSubstituteDoHKey_FillsFromApiKeyOnAnAgentMint(t *testing.T) {
	rec := map[string]any{
		"doh_url": "https://doh.whisper.online/{api_key}/dns-query",
		"api_key": "whisper_live_example",
	}
	got := substituteDoHKey(rec["doh_url"].(string), rec)
	want := "https://doh.whisper.online/whisper_live_example/dns-query"
	if got != want {
		t.Fatalf("api_key must fill the placeholder\n got %q\nwant %q", got, want)
	}
}

func TestSubstituteDoHKey_FillsFromTokenOnADeviceMint(t *testing.T) {
	// A device mint names its credential `token`, not `api_key`. Missing this column was the
	// difference between a paste-able URL and one a user would paste with {api_key} still in it.
	rec := map[string]any{
		"doh_url": "https://doh.whisper.online/{api_key}/dns-query",
		"token":   "device_token_example",
	}
	got := substituteDoHKey(rec["doh_url"].(string), rec)
	want := "https://doh.whisper.online/device_token_example/dns-query"
	if got != want {
		t.Fatalf("token must fill the placeholder on a device mint\n got %q\nwant %q", got, want)
	}
}

func TestSubstituteDoHKey_LeavesThePlaceholderVisibleWhenNoCredentialRides(t *testing.T) {
	// The failure mode this guards is the quiet one. A URL that silently lost its key would be
	// written into an OS resolver profile and fail later, somewhere with no explanation; a URL
	// that still says {api_key} tells its reader exactly what is missing.
	rec := map[string]any{"doh_url": "https://doh.whisper.online/{api_key}/dns-query"}
	got := substituteDoHKey(rec["doh_url"].(string), rec)
	if got != "https://doh.whisper.online/{api_key}/dns-query" {
		t.Fatalf("with no credential the placeholder must stay visible, got %q", got)
	}
}

func TestSubstituteDoHKey_LeavesAnAlreadyKeyedURLAlone(t *testing.T) {
	// An older control plane still interpolates. The client must not corrupt that URL, so a
	// string with no placeholder comes back byte-identical.
	url := "https://doh.whisper.online/some_existing_key/dns-query"
	rec := map[string]any{"doh_url": url, "api_key": "whisper_live_example"}
	if got := substituteDoHKey(url, rec); got != url {
		t.Fatalf("a URL without the placeholder must pass through unchanged\n got %q\nwant %q", got, url)
	}
}

func TestSubstituteDoHKey_IgnoresABlankCredentialAndFallsThrough(t *testing.T) {
	// An empty api_key column must not win over a populated token: substituting "" would build
	// https://host//dns-query, which is a valid-looking URL that can never authenticate.
	rec := map[string]any{
		"doh_url": "https://doh.whisper.online/{api_key}/dns-query",
		"api_key": "   ",
		"token":   "device_token_example",
	}
	got := substituteDoHKey(rec["doh_url"].(string), rec)
	want := "https://doh.whisper.online/device_token_example/dns-query"
	if got != want {
		t.Fatalf("a blank api_key must fall through to token\n got %q\nwant %q", got, want)
	}
}
