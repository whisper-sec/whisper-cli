// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// mcp_readme_counts_test.go reads the npm package's README the way a person deciding whether to
// install it does, and holds it to what the server actually lists. The README said "45
// tools" for the keyless server at 0.220.0, when 45 was the keyed count and five was the keyless
// one. A published count goes stale on the edit that changes the catalogue, and nothing read the
// prose. This test reads it: the keyless count in words, the keyless tool names, and the keyed
// count, each against tools/list driven keyless and keyed.

var numberWords = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
	"nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
	"fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}

// readmeCount parses a count written as a word or as digits.
func readmeCount(t *testing.T, s string) int {
	t.Helper()
	if n, ok := numberWords[strings.ToLower(s)]; ok {
		return n
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("the README states the count %q, which is neither a number word nor digits", s)
	}
	return n
}

// mustFind returns the first submatch of re in text, or fails naming the sentence that went
// missing: a reworded README must fail here, never pass because there is nothing left to check.
func mustFind(t *testing.T, re *regexp.Regexp, text string) []string {
	t.Helper()
	m := re.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("npm-mcp/README.md no longer carries a sentence matching %q; reword this test with the README, do not delete the check", re)
	}
	return m
}

var (
	readmeKeylessCount = regexp.MustCompile(`No key, no signup, (\w+) tools, real answers:`)
	readmeKeyedCount   = regexp.MustCompile(`Add an API key and the same server lists (\w+) tools`)
	// The keyless bullets: from the keyless heading to the next paragraph that is not a bullet.
	readmeKeylessSection = regexp.MustCompile(`(?s)## It does something useful with no account\n(.*?)\n\nAdd an API key`)
	readmeBulletName     = regexp.MustCompile("(?m)^- `([a-z_]+)`")
)

func TestMCP_NpmReadmeCountsAreTheToolsListCounts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "npm-mcp", "README.md"))
	if err != nil {
		t.Fatalf("read npm-mcp/README.md: %v", err)
	}
	// A Windows checkout with core.autocrlf rewrites the README to CRLF, and the section regex
	// below matches LF paragraph breaks, so read it as the LF bytes the repository holds.
	readme := strings.ReplaceAll(string(raw), "\r\n", "\n")

	pinKeyState(t, "", "")
	keyless, _ := listToolNames(t)
	pinKeyState(t, "whisper_live_test", "")
	keyed, _ := listToolNames(t)

	if got := readmeCount(t, mustFind(t, readmeKeylessCount, readme)[1]); got != len(keyless) {
		t.Errorf("the README says %d tools with no key; a keyless tools/list has %d: %v", got, len(keyless), keyless)
	}
	if got := readmeCount(t, mustFind(t, readmeKeyedCount, readme)[1]); got != len(keyed) {
		t.Errorf("the README says %d tools with a key; a keyed tools/list has %d", got, len(keyed))
	}

	section := mustFind(t, readmeKeylessSection, readme)[1]
	var named []string
	for _, m := range readmeBulletName.FindAllStringSubmatch(section, -1) {
		named = append(named, m[1])
	}
	want := append([]string(nil), keyless...)
	sort.Strings(named)
	sort.Strings(want)
	if strings.Join(named, ",") != strings.Join(want, ",") {
		t.Errorf("the README's keyless list names %v; a keyless tools/list has %v", named, want)
	}
}
