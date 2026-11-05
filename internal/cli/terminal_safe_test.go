// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

// TestAnErrorLineCannotDriveTheTerminal: the control plane's sentence is printed as it came, so
// whatever escape it carries must arrive as inert text. Newlines and tabs are ours and survive.
func TestAnErrorLineCannotDriveTheTerminal(t *testing.T) {
	cases := map[string]string{
		"title \x1b]0;pwned\x07 set":       "title  ]0;pwned  set",
		"link \x1b]8;;https://x\x1b\\here": "link  ]8;;https://x \\here",
		"bidi ‮evil":                       "bidi  evil",
		"c1 \u009bcursor":                  "c1  cursor",
		"line one\n\tline two":             "line one\n\tline two",
		"plain sentence, untouched":        "plain sentence, untouched",
	}
	for in, want := range cases {
		if got := terminalSafe(in); got != want {
			t.Errorf("terminalSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
