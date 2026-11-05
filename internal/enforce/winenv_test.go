// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"strings"
	"testing"
)

func decodeBlock(t *testing.T, b []uint16) []string {
	t.Helper()
	if len(b) < 2 || b[len(b)-1] != 0 || b[len(b)-2] != 0 {
		t.Fatalf("the block must end in two NULs: %v", b)
	}
	var out []string
	var cur []rune
	for _, c := range b[:len(b)-1] {
		if c == 0 {
			if len(cur) > 0 {
				out = append(out, string(cur))
			}
			cur = cur[:0]
			continue
		}
		cur = append(cur, rune(c))
	}
	return out
}

func TestEnvBlockLetsALaterEntryWinWhateverItsCase(t *testing.T) {
	got := decodeBlock(t, envBlock([]string{"Path=C:\\x", "https_proxy=http://evil:1", "HTTPS_PROXY=http://127.0.0.1:5", "path=C:\\y"}))
	want := []string{"HTTPS_PROXY=http://127.0.0.1:5", "path=C:\\y"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestEnvBlockSortsCaseInsensitivelyAndKeepsDriveEntries(t *testing.T) {
	got := decodeBlock(t, envBlock([]string{"b=1", "=C:=C:\\w", "A=2", "c=3"}))
	want := []string{"=C:=C:\\w", "A=2", "b=1", "c=3"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestEnvBlockDropsWhatIsNotAnEntry(t *testing.T) {
	got := decodeBlock(t, envBlock([]string{"", "NOEQUALS", "=", "=nope", "X=a\x00b", "OK="}))
	if strings.Join(got, "|") != "OK=" {
		t.Fatalf("got %q", got)
	}
	if b := envBlock(nil); len(b) != 2 || b[0] != 0 || b[1] != 0 {
		t.Fatalf("an empty environment is two NULs: %v", b)
	}
}
