// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ReownForSudo hands a file this process wrote back to the user who invoked
// sudo, when that file landed inside their home directory.
//
// The service-install path tells an operator, correctly, to finish
// onboarding as root:
//
//	sudo whisper enroll --name <the name you already enrolled>
//	sudo whisper service restart --sensor
//
// sudo preserves HOME, so `enroll` writes ~/.config/whisper/bound into the
// INVOKING USER's directory - owned by root, at the 0600 this package exists to
// guarantee. The sensor (root) reads it and reports perfectly. The user's own
// `whisper status` cannot open it, reports no_bound_identity, and prints the
// very command that just produced this state. Running it again writes the same
// root-owned file, so the documented fix is a loop with no exit, over a sensor
// that was working the whole time. Measured on a real host; one chown ended it.
//
// The scope is deliberately narrow, because the fix must not undo the thing
// this package is for:
//
//   - root only, and only when SUDO_UID/SUDO_GID name a non-root user. Without
//     sudo there is no second party to hand anything to.
//   - only INSIDE that user's home. A genuine root-owned path (/etc/whisper,
//     /var/lib/whisper-sensor, /var/root) keeps root's ownership; handing those
//     to a user would be a privilege bug, not a fix for one.
//   - the mode is untouched. 0600 stays 0600; only the owner moves, from a user
//     who cannot read their own file to the one who is supposed to.
//
// Best-effort by design: a chown that cannot happen leaves exactly today's
// behaviour, so this can never turn a working write into a failed one.
func ReownForSudo(path string) {
	abs, uid, gid, ok := reownTarget(path, runtime.GOOS, os.Geteuid())
	if !ok {
		return
	}
	_ = os.Chown(abs, uid, gid)
}

// reownTarget decides whether path changes hands and to whom, and does nothing.
//
// The split is not stylistic. The scoping above IS the safety argument, and the
// failure mode of getting it wrong is handing a root-owned credential to an
// unprivileged user - worse than the bug it fixes. Folded into ReownForSudo, the
// argument could not be tested: the second statement was os.Geteuid() != 0, so an
// ordinary test process returned there and every branch after it - windows, no
// sudo, SUDO_UID=0, outside HOME - was unreachable. The two halves had tests and
// their COMPOSITION, which is where such a mistake would live, had none. Taking
// goos and euid as arguments puts the whole matrix within reach of a normal test
// run, and leaves exactly one untestable statement, the chown itself.
func reownTarget(path, goos string, euid int) (abs string, uid, gid int, ok bool) {
	if goos == "windows" {
		return "", 0, 0, false // no uid/gid to hand over, and sudo is not how privilege is raised here
	}
	if euid != 0 {
		return "", 0, 0, false
	}
	uid, gid, ok = sudoInvoker()
	if !ok {
		return "", 0, 0, false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", 0, 0, false
	}
	if !underInvokerHome(abs) {
		return "", 0, 0, false
	}
	return abs, uid, gid, true
}

// sudoInvoker reads the non-root user sudo says invoked us. Root invoking sudo
// on itself (SUDO_UID=0) is not a handover and reports false.
func sudoInvoker() (int, int, bool) {
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil || uid <= 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// underInvokerHome reports whether abs sits inside the HOME sudo preserved.
// Uses a cleaned path-segment comparison rather than a string prefix, so
// /Users/alice-other is not mistaken for a child of /Users/alice.
func underInvokerHome(abs string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	homeAbs, err := filepath.Abs(home)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(homeAbs, abs)
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
