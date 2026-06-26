// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// TestCreateAgent_RejectsBlankNames is the negative test for the ONE mandatory-name guard
// (§3.2). createAgent must refuse an empty/blank/whitespace name with a usage error — and
// it must do so WITHOUT touching the control plane (a blank name never reaches the server).
func TestCreateAgent_RejectsBlankNames(t *testing.T) {
	// A client whose URL would fail loudly if it were ever called — proving the guard is
	// purely local (we never hit the server for a blank name).
	c := client.New(client.Config{
		ControlURL: "http://127.0.0.1:1", // unroutable on purpose
		Cred:       client.Credential{Value: "k", Source: client.SourceFlag},
		Timeout:    2 * time.Second,
	})
	for _, name := range []string{"", " ", "\t", "\n", "   \t  "} {
		_, err := createAgent(c, name)
		if err == nil {
			t.Fatalf("createAgent(%q) must error on a blank name", name)
		}
		if !isUsageError(err) {
			t.Fatalf("createAgent(%q) = %v, want a usage error", name, err)
		}
		if !strings.Contains(err.Error(), "name is required") {
			t.Fatalf("createAgent(%q) message = %q, want it to mention the required name", name, err.Error())
		}
	}
}

// TestRequireName_HeadlessNoNameErrors covers the headless rung of the mandatory-name
// helper: no --name + no TTY ⇒ a clear usage error, never a hang.
func TestRequireName_HeadlessNoNameErrors(t *testing.T) {
	gio := guidedIO{in: bufio.NewReader(strings.NewReader("")), out: &bytes.Buffer{}, err: &bytes.Buffer{}}
	_, err := requireName(guidedOptions{tty: false}, gio)
	if err == nil || !isUsageError(err) {
		t.Fatalf("headless no-name must be a usage error, got %v", err)
	}
}

// TestRequireName_TTYRePromptsThenAccepts covers the TTY rung: an empty line re-prompts,
// then a non-blank name is accepted (the door never gets stuck, never accepts a blank).
func TestRequireName_TTYRePromptsThenAccepts(t *testing.T) {
	errb := &bytes.Buffer{}
	// First line blank (re-prompt), second line a real name.
	gio := guidedIO{in: bufio.NewReader(strings.NewReader("\n  scout  \n")), out: &bytes.Buffer{}, err: errb}
	name, err := requireName(guidedOptions{tty: true}, gio)
	if err != nil {
		t.Fatalf("re-prompt then accept errored: %v", err)
	}
	if name != "scout" {
		t.Fatalf("name = %q, want the trimmed 'scout'", name)
	}
	if !strings.Contains(errb.String(), "a name is required") {
		t.Fatalf("expected a re-prompt message after the blank line, stderr=%q", errb.String())
	}
}

// TestRequireName_FlagWins: --name short-circuits any prompting (it's trimmed).
func TestRequireName_FlagWins(t *testing.T) {
	gio := guidedIO{in: bufio.NewReader(strings.NewReader("")), out: &bytes.Buffer{}, err: &bytes.Buffer{}}
	name, err := requireName(guidedOptions{name: "  runner ", tty: true}, gio)
	if err != nil || name != "runner" {
		t.Fatalf("requireName flag path = (%q, %v), want runner", name, err)
	}
}
