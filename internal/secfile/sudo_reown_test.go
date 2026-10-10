// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// The scoping is the whole safety argument, so it is what gets tested.
// ReownForSudo must refuse every case except "root, invoked via sudo by a real
// user, writing inside that user's own home" - because the failure mode of a
// too-broad version is handing a root-owned credential to an unprivileged user,
// which is a worse bug than the one it fixes.
func TestReownForSudoRefusesEverythingOutsideItsOneCase(t *testing.T) {
	// HermeticHome, not t.Setenv("HOME"): the repo's own gate refuses a hand-set
	// HOME because the family (HOME/USERPROFILE/...) has to move together, or the
	// test reads the real user's config on the platform it did not set.
	home := testenv.HermeticHome(t)

	inside := filepath.Join(home, ".config", "whisper", "bound")
	outside := filepath.Join(t.TempDir(), "bound")

	if !underInvokerHome(inside) {
		t.Fatal("a path inside HOME must be recognised as inside it")
	}
	if underInvokerHome(outside) {
		t.Fatal("a path outside HOME must NOT be - /etc and /var/root keep root's ownership")
	}
	if underInvokerHome(home) {
		t.Fatal("HOME itself is not a file this wrote; it must not be re-owned")
	}
	// The sibling-prefix trap: /home/alice-other is not inside /home/alice, and a
	// naive strings.HasPrefix says it is.
	if underInvokerHome(home + "-other/bound") {
		t.Fatal("a sibling directory sharing HOME's prefix must not count as inside it")
	}
}

func TestSudoInvokerOnlyAcceptsARealNonRootUser(t *testing.T) {
	for _, tc := range []struct {
		name, uid, gid string
		want           bool
	}{
		{"unset", "", "", false},
		{"root invoking sudo on itself", "0", "0", false},
		{"non-numeric", "alice", "20", false},
		{"negative", "-1", "20", false},
		{"a real user", "501", "20", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tc.uid)
			t.Setenv("SUDO_GID", tc.gid)
			if _, _, ok := sudoInvoker(); ok != tc.want {
				t.Fatalf("sudoInvoker() ok = %v, want %v", ok, tc.want)
			}
		})
	}
}

// Not running as root, ReownForSudo must be a no-op that cannot fail - this is
// the path every ordinary `whisper` invocation takes through WriteFile.
func TestReownForSudoIsANoOpWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, so the not-root arm cannot be exercised here")
	}
	home := testenv.HermeticHome(t)
	t.Setenv("SUDO_UID", "501")
	t.Setenv("SUDO_GID", "20")
	p := filepath.Join(home, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	ReownForSudo(p) // must not panic, must not error, must not change the mode
	after, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("mode changed %v -> %v; this only ever moves the owner", before.Mode(), after.Mode())
	}
}

// The composition, which is where a scoping mistake would actually live. Each
// arm below is a way the handover must NOT happen; the last is the only way it
// must. Before the split below, none of this was reachable outside a root test
// run, so the one function whose failure mode is a privilege bug was the one
// function with no test of its decision.
func TestReownTargetHandsOverInExactlyOneSituation(t *testing.T) {
	home := testenv.HermeticHome(t)
	inside := filepath.Join(home, ".config", "whisper", "bound")
	outside := filepath.Join(t.TempDir(), "bound")

	const realUID, realGID = 501, 20
	sudoAs := func(t *testing.T, uid, gid string) {
		t.Helper()
		t.Setenv("SUDO_UID", uid)
		t.Setenv("SUDO_GID", gid)
	}

	t.Run("windows has no handover to make", func(t *testing.T) {
		sudoAs(t, "501", "20")
		if _, _, _, ok := reownTarget(inside, "windows", 0); ok {
			t.Fatal("windows raises privilege differently and carries no SUDO_UID to hand back to")
		}
	})

	t.Run("not root", func(t *testing.T) {
		sudoAs(t, "501", "20")
		if _, _, _, ok := reownTarget(inside, "linux", realUID); ok {
			t.Fatal("a non-root process owns what it wrote already; there is nothing to hand over")
		}
	})

	t.Run("root but not under sudo", func(t *testing.T) {
		sudoAs(t, "", "")
		if _, _, _, ok := reownTarget(inside, "linux", 0); ok {
			t.Fatal("without sudo there is no second party, so the file stays root's")
		}
	})

	t.Run("root invoking sudo on itself", func(t *testing.T) {
		sudoAs(t, "0", "0")
		if _, _, _, ok := reownTarget(inside, "linux", 0); ok {
			t.Fatal("handing root's file to root is not a handover")
		}
	})

	t.Run("a genuinely root-owned path outside HOME", func(t *testing.T) {
		sudoAs(t, "501", "20")
		if _, _, _, ok := reownTarget(outside, "linux", 0); ok {
			t.Fatal("/etc/whisper and /var/lib/whisper-sensor keep root's ownership; " +
				"handing those to a user is a privilege bug, not a fix for one")
		}
	})

	t.Run("the one case", func(t *testing.T) {
		sudoAs(t, "501", "20")
		abs, uid, gid, ok := reownTarget(inside, "linux", 0)
		if !ok {
			t.Fatal("root, under sudo, writing inside the invoking user's own home IS the case " +
				"this exists for; refusing it leaves the operator in the loop where the " +
				"printed fix is what created the state it is meant to fix")
		}
		if uid != realUID || gid != realGID {
			t.Fatalf("handover to uid/gid %d/%d, want %d/%d", uid, gid, realUID, realGID)
		}
		if abs != inside {
			t.Fatalf("chown target %q, want %q", abs, inside)
		}
	})

	t.Run("a relative path is resolved before it is judged", func(t *testing.T) {
		// The caller passes whatever it was given. Judging HOME-membership on an
		// unresolved "bound" would compare a bare filename against HOME and refuse
		// the very case this exists for.
		sudoAs(t, "501", "20")
		if _, _, _, ok := reownTarget("bound", "linux", 0); ok {
			t.Fatal("relative to a working directory outside HOME, this must not hand anything over")
		}
		t.Chdir(home)
		abs, _, _, ok := reownTarget("bound", "linux", 0)
		if !ok {
			t.Fatal("relative to a working directory inside HOME, the same name IS inside HOME")
		}
		// Compared structurally rather than against a joined literal: on darwin
		// t.TempDir() hands back a /var symlink and Getwd returns /private/var,
		// so an equality check there fails on the symlink, not on the behaviour.
		if !filepath.IsAbs(abs) || filepath.Base(abs) != "bound" {
			t.Fatalf("chown target %q is not the resolved absolute path of the input", abs)
		}
	})
}
