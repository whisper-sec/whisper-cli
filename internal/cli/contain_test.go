// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"
)

// contain_test.go covers the command surface of `whisper contain` on every platform.

func TestParsePidIsLiberal(t *testing.T) {
	for in, want := range map[string]int{"4242": 4242, " 4242\n": 4242, "pid 4242": 4242, "PID:4242": 4242, "pid=7": 7} {
		got, err := parsePid(in)
		if err != nil || got != want {
			t.Errorf("parsePid(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "0", "-5", "42x", "pid"} {
		if _, err := parsePid(bad); err == nil || !strings.Contains(err.Error(), "not a process id") {
			t.Errorf("parsePid(%q) must refuse with a clear sentence, got %v", bad, err)
		}
	}
}

func TestContainNeedsExactlyOnePid(t *testing.T) {
	for _, args := range [][]string{{"contain"}, {"contain", "1", "2"}} {
		root := NewRootCommand()
		root.SetArgs(args)
		root.SilenceUsage, root.SilenceErrors = true, true
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "name the process to contain") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestContainUnsupportedSaysNothingChanged(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		msg := containUnsupported(goos).Error()
		if !strings.Contains(msg, "nothing was changed") || !strings.Contains(msg, goos) || !strings.Contains(msg, "whisper run") {
			t.Errorf("%s: %q", goos, msg)
		}
	}
}

func TestContainHelpIsHonestAboutWhatItDoesNotCover(t *testing.T) {
	long := newContainCmd().Long
	for _, must := range []string{"run --enforce", "--release", "stays cut", "sudo or a setuid program", "unix socket", "root"} {
		if !strings.Contains(long, must) {
			t.Errorf("the help does not say %q", must)
		}
	}
	if strings.ContainsRune(long, '\u2014') {
		t.Error("no em-dashes in the help")
	}
}
