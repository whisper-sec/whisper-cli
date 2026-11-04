// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// whale_ssh_authz_place.go answers "then where should it go?" when install refuses a binary
// sshd would ignore. The answer used to be a fixed "such as /usr/local/bin", which on a
// Mac with Homebrew is the very directory just refused. Now every suggestion is run through the
// same check that refused the binary, on this host, so a place is only named when sshd would
// actually accept a root-owned binary there.

// sshAuthzPlaces are the directories offered, in order: the conventional one first, then two
// that a package manager does not normally claim.
var sshAuthzPlaces = []string{"/usr/local/bin", "/usr/local/libexec/whisper-cli", "/opt/whisper/bin"}

// placementProbe is what the hint reads from the host, so a test can stand in for it.
type placementProbe struct {
	// refusal is commandPathRefusal: the first element of the path sshd would refuse, and why.
	refusal func(path string) (at, why string)
	// exists reports whether path is there at all.
	exists func(path string) bool
	// rootGroup is the name of group 0: root on Linux, wheel on macOS and the BSDs.
	rootGroup string
}

func hostPlacementProbe() placementProbe {
	return placementProbe{
		refusal: commandPathRefusal,
		exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		rootGroup: rootGroupName(),
	}
}

func rootGroupName() string {
	if g, err := user.LookupGroupId("0"); err == nil && g.Name != "" {
		return g.Name
	}
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return "wheel"
	}
	return "root"
}

// sshAuthzPlacementHint is the next step for a binary at real that sshd would refuse: the exact
// commands that put a root-owned copy somewhere this host's directory chain passes the same
// check, or, when no offered place passes, what such a place needs. It never names a directory
// the check refuses. The places and the commands are sshd's, so the hint works in slash paths
// on every host: on Windows filepath would join a Unix-form place with a backslash.
func sshAuthzPlacementHint(real string, h placementProbe) string {
	real = filepath.ToSlash(real)
	at, _ := h.refusal(real)
	g := h.rootGroup
	// Only the file is wrong (installed by a user, or group-writable) in a directory that is
	// fine: fix the file in place, which also keeps the path the snippet already names.
	if at == real {
		if dirAt, _ := h.refusal(path.Dir(real)); dirAt == "" {
			return "Its directory is fine; make root own the file and only root write it:\n" +
				"  sudo chown root:" + g + " " + real + " && sudo chmod 755 " + real + "\n" +
				"then run this again."
		}
	}
	var tried []string
	for _, dir := range sshAuthzPlaces {
		if dir == path.Dir(real) {
			continue // where it already is, which is what was just refused
		}
		target := path.Join(dir, "whisper")
		if h.exists(dir) {
			if dirAt, why := h.refusal(dir); dirAt != "" {
				tried = append(tried, why)
				continue
			}
			return "Copy it to " + dir + ", which root owns along its whole path here:\n" +
				"  sudo install -m 755 -o root -g " + g + " " + real + " " + target + "\n" +
				"then run this again from there: sudo " + target + " whale ssh-authz install --write\n" +
				"(copy it again after an upgrade)."
		}
		// Not there yet: it can be made, if what it would be made in passes.
		anc := path.Dir(dir)
		for !h.exists(anc) && path.Dir(anc) != anc {
			anc = path.Dir(anc)
		}
		if ancAt, why := h.refusal(anc); ancAt != "" {
			tried = append(tried, why)
			continue
		}
		return "Make " + dir + " (everything above it is root's) and copy it there:\n" +
			"  sudo install -d -m 755 -o root -g " + g + " " + dir + "\n" +
			"  sudo install -m 755 -o root -g " + g + " " + real + " " + target + "\n" +
			"then run this again from there: sudo " + target + " whale ssh-authz install --write\n" +
			"(copy it again after an upgrade)."
	}
	return "None of the usual places passes the same check on this host (" + strings.Join(tried, "; ") + "). " +
		"Pick a directory {dir} that root owns and only root can write, as is every directory above it, then\n" +
		"  sudo install -m 755 -o root -g " + g + " " + real + " {dir}/whisper\n" +
		"and run this again from there."
}
