// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"path"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// fakeHost is a filesystem described by which directories exist and which elements sshd's
// safe_path refuses, walked the way commandPathRefusal walks the real one.
type fakeHost struct {
	dirs    map[string]bool   // directories (and files) that exist
	refused map[string]string // element -> why sshd refuses it
}

func (f fakeHost) probe(group string) placementProbe {
	return placementProbe{
		refusal: func(p string) (string, string) {
			for q := p; ; q = path.Dir(q) {
				if why, bad := f.refused[q]; bad {
					return q, why
				}
				if path.Dir(q) == q {
					return "", ""
				}
			}
		},
		exists:    func(p string) bool { return f.dirs[p] || p == "/" },
		rootGroup: group,
	}
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// targetsOf is every directory a hint tells the operator to create or install into.
var hintTarget = regexp.MustCompile(`sudo install (?:-d -m 755 -o root -g \S+ (\S+)|-m 755 -o root -g \S+ \S+ (\S+))\n`)

func targetsOf(hint string) []string {
	var out []string
	for _, m := range hintTarget.FindAllStringSubmatch(hint, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else if !strings.HasPrefix(m[2], "{") {
			out = append(out, path.Dir(m[2]))
		}
	}
	return out
}

// assertNeverSuggestsARefusedPlace is the invariant this hint exists for: whatever it names as
// a destination passes the same check that refused the binary.
func assertNeverSuggestsARefusedPlace(t *testing.T, hint string, h placementProbe) {
	t.Helper()
	for _, dir := range targetsOf(hint) {
		check := dir
		for !h.exists(check) && path.Dir(check) != check {
			check = path.Dir(check)
		}
		if at, why := h.refusal(check); at != "" {
			t.Fatalf("the hint suggests %s, which the same check refuses (%s):\n%s", dir, why, hint)
		}
	}
}

// The reported case: Homebrew owns /usr/local/bin on a Mac, so the old fixed "such as
// /usr/local/bin" named the directory just refused.
func TestPlacementHintOnHomebrewMacNamesAnotherDirectory(t *testing.T) {
	host := fakeHost{
		dirs:    set("/usr", "/usr/local", "/usr/local/bin", "/usr/local/bin/whisper", "/opt"),
		refused: map[string]string{"/usr/local/bin": "/usr/local/bin is not owned by root"},
	}
	h := host.probe("wheel")
	hint := sshAuthzPlacementHint("/usr/local/bin/whisper", h)
	if strings.Contains(hint, " /usr/local/bin/whisper\n") || strings.Contains(hint, "-g wheel /usr/local/bin\n") {
		t.Fatalf("the hint suggests the refused /usr/local/bin:\n%s", hint)
	}
	for _, want := range []string{
		"sudo install -d -m 755 -o root -g wheel /usr/local/libexec/whisper-cli\n",
		"sudo install -m 755 -o root -g wheel /usr/local/bin/whisper /usr/local/libexec/whisper-cli/whisper\n",
		"sudo /usr/local/libexec/whisper-cli/whisper whale ssh-authz install --write",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("hint lacks %q:\n%s", want, hint)
		}
	}
	assertNeverSuggestsARefusedPlace(t, hint, h)
}

// On Linux the conventional place is fine and is the one offered, with group root.
func TestPlacementHintOffersUsrLocalBinWhereRootOwnsIt(t *testing.T) {
	host := fakeHost{
		dirs:    set("/usr", "/usr/local", "/usr/local/bin", "/home", "/home/u", "/home/u/bin", "/home/u/bin/whisper"),
		refused: map[string]string{"/home/u": "/home/u is not owned by root"},
	}
	h := host.probe("root")
	hint := sshAuthzPlacementHint("/home/u/bin/whisper", h)
	want := "Copy it to /usr/local/bin, which root owns along its whole path here:\n" +
		"  sudo install -m 755 -o root -g root /home/u/bin/whisper /usr/local/bin/whisper\n"
	if !strings.HasPrefix(hint, want) {
		t.Fatalf("hint = %q, want it to start %q", hint, want)
	}
	if strings.Contains(hint, "install -d") {
		t.Fatalf("an existing directory was offered for creation:\n%s", hint)
	}
	assertNeverSuggestsARefusedPlace(t, hint, h)
}

// Only the file is wrong: fix it where it is, which keeps the path the snippet names.
func TestPlacementHintFixesTheFileInPlaceWhenOnlyTheFileIsWrong(t *testing.T) {
	host := fakeHost{
		dirs:    set("/usr", "/usr/local", "/usr/local/bin", "/usr/local/bin/whisper"),
		refused: map[string]string{"/usr/local/bin/whisper": "/usr/local/bin/whisper is not owned by root"},
	}
	hint := sshAuthzPlacementHint("/usr/local/bin/whisper", host.probe("root"))
	if !strings.Contains(hint, "sudo chown root:root /usr/local/bin/whisper && sudo chmod 755 /usr/local/bin/whisper\n") {
		t.Fatalf("hint = %q", hint)
	}
	if strings.Contains(hint, "install") {
		t.Fatalf("a file that only needs chown was told to move:\n%s", hint)
	}
}

// A place that exists and passes is used as it is, after the ones that do not.
func TestPlacementHintSkipsRefusedPlacesForOneThatPasses(t *testing.T) {
	host := fakeHost{
		dirs: set("/usr", "/usr/local", "/usr/local/bin", "/usr/local/libexec", "/usr/local/libexec/whisper-cli",
			"/opt", "/opt/whisper", "/opt/whisper/bin", "/Users", "/Users/k", "/Users/k/whisper"),
		refused: map[string]string{
			"/usr/local/bin":     "/usr/local/bin is not owned by root",
			"/usr/local/libexec": "/usr/local/libexec can be written by accounts other than its owner",
			"/Users/k":           "/Users/k is not owned by root",
		},
	}
	h := host.probe("wheel")
	hint := sshAuthzPlacementHint("/Users/k/whisper", h)
	if !strings.HasPrefix(hint, "Copy it to /opt/whisper/bin,") {
		t.Fatalf("hint = %q", hint)
	}
	assertNeverSuggestsARefusedPlace(t, hint, h)
}

// A place to be made is offered only when what it would be made in passes.
func TestPlacementHintDoesNotOfferToMakeADirectoryUnderARefusedParent(t *testing.T) {
	host := fakeHost{
		dirs: set("/usr", "/usr/local", "/usr/local/bin", "/opt", "/home", "/home/u", "/home/u/whisper"),
		refused: map[string]string{
			"/usr/local": "/usr/local is not owned by root",
			"/home/u":    "/home/u is not owned by root",
		},
	}
	h := host.probe("root")
	hint := sshAuthzPlacementHint("/home/u/whisper", h)
	if !strings.Contains(hint, "sudo install -d -m 755 -o root -g root /opt/whisper/bin\n") {
		t.Fatalf("hint = %q", hint)
	}
	assertNeverSuggestsARefusedPlace(t, hint, h)
}

// No offered place passes: say so, with each reason, and name no directory as if it would work.
func TestPlacementHintWhenNoPlacePasses(t *testing.T) {
	host := fakeHost{
		dirs: set("/usr", "/usr/local", "/usr/local/bin", "/opt", "/home", "/home/u", "/home/u/whisper"),
		refused: map[string]string{
			"/usr/local": "/usr/local is not owned by root",
			"/opt":       "/opt can be written by accounts other than its owner",
			"/home/u":    "/home/u is not owned by root",
		},
	}
	h := host.probe("root")
	hint := sshAuthzPlacementHint("/home/u/whisper", h)
	for _, want := range []string{
		"None of the usual places passes the same check on this host",
		"/usr/local is not owned by root",
		"/opt can be written by accounts other than its owner",
		"sudo install -m 755 -o root -g root /home/u/whisper {dir}/whisper\n",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("hint lacks %q:\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "install -d") || strings.Contains(hint, "Copy it to") {
		t.Fatalf("a refused place was offered:\n%s", hint)
	}
	if got := targetsOf(hint); len(got) != 0 {
		t.Fatalf("the no-place hint names destinations %v:\n%s", got, hint)
	}
}

// The place the binary already is in is never offered back, even when nothing else is refused
// (the refusal was further up the binary's own path).
func TestPlacementHintNeverOffersTheBinarysOwnDirectory(t *testing.T) {
	host := fakeHost{
		dirs:    set("/usr", "/usr/local", "/usr/local/bin", "/usr/local/bin/whisper", "/opt"),
		refused: map[string]string{"/usr/local/bin/whisper": "/usr/local/bin/whisper can be written by accounts other than its owner", "/usr/local/bin": "/usr/local/bin is not owned by root"},
	}
	hint := sshAuthzPlacementHint("/usr/local/bin/whisper", host.probe("root"))
	if strings.Contains(hint, "chown") || strings.Contains(hint, " /usr/local/bin/whisper\n") {
		t.Fatalf("the refused directory came back:\n%s", hint)
	}
}

func TestRootGroupNameIsGroupZero(t *testing.T) {
	want := map[string]string{"linux": "root", "darwin": "wheel"}[runtime.GOOS]
	if want == "" {
		t.Skip("no fixed expectation for " + runtime.GOOS)
	}
	if got := rootGroupName(); got != want {
		t.Fatalf("rootGroupName() = %q, want %q", got, want)
	}
}
