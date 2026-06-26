// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os/exec"
	"runtime"
)

// openBrowser makes a BEST-EFFORT attempt to open url in the user's default browser. It
// NEVER blocks (it does not wait for the browser to exit) and NEVER errors fatally —
// failure is fine: the device flow always also prints the URL + code on stderr so the
// user can open it by hand (Postel: zero needless friction, graceful degradation). The
// returned error is purely informational for callers that want to log a soft note.
func openBrowser(url string) error {
	if url == "" {
		return nil
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		// `cmd /c start "" <url>` — the empty "" is the (ignored) window title so a URL
		// with characters cmd would treat as a title is not swallowed.
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default: // linux, *bsd, etc.
		cmd = exec.Command("xdg-open", url)
	}
	// Start, don't Run: we don't want to wait on the browser process. A missing opener
	// (e.g. headless box without xdg-open) simply returns an error we ignore upstream.
	return cmd.Start()
}
