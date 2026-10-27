// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux || darwin

package enforce

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var lockAgent = netip.MustParseAddr("2a04:2a01:8000::a")

func useTempLockDir(t *testing.T) string {
	t.Helper()
	oldDir, oldOwner := LockDir, lockOwner
	// The parent is checked as the lock directory is, and t.TempDir's own directory follows the
	// umask (0775 under 002), so the parent is made here with an explicit mode, as /run/whisper is.
	parent := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	LockDir = filepath.Join(parent, "locks")
	lockOwner = os.Geteuid()
	t.Cleanup(func() { LockDir, lockOwner = oldDir, oldOwner })
	return LockDir
}

func TestAnEnforcedRunExcludesAConnectAndAnotherRun(t *testing.T) {
	useTempLockDir(t)
	ex, err := LockExclusive(lockAgent)
	if err != nil || ex == nil {
		t.Fatalf("first exclusive lock: %v", err)
	}
	defer ex.Release()
	_, err = LockShared(lockAgent)
	var held *HeldError
	if !errors.As(err, &held) || !held.Exclusive || held.PID != os.Getpid() {
		t.Fatalf("a connect must be refused naming the run's pid, got %#v", err)
	}
	if !strings.Contains(err.Error(), "whisper run --enforce") {
		t.Fatalf("the refusal must name the holder: %v", err)
	}
	if _, err := LockExclusive(lockAgent); !errors.As(err, &held) {
		t.Fatalf("a second enforced run must be refused, got %v", err)
	}
}

func TestConnectsShareButExcludeAnEnforcedRun(t *testing.T) {
	useTempLockDir(t)
	a, err := LockShared(lockAgent) // the owner creates the file, as root would
	if err != nil || a == nil {
		t.Fatalf("first shared lock: %v", err)
	}
	defer a.Release()
	b, err := LockShared(lockAgent)
	if err != nil || b == nil {
		t.Fatalf("a second connect for the same agent is legitimate: %v", err)
	}
	defer b.Release()
	_, err = LockExclusive(lockAgent)
	var held *HeldError
	if !errors.As(err, &held) || held.Exclusive {
		t.Fatalf("an enforced run must be refused while connects hold the agent, got %v", err)
	}
	if !strings.Contains(err.Error(), "whisper connect") {
		t.Fatalf("the refusal must name the connect: %v", err)
	}
}

func TestReleaseFreesTheAgent(t *testing.T) {
	useTempLockDir(t)
	ex, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	ex.Release()
	ex.Release() // twice is safe
	again, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatalf("a released lock must be free: %v", err)
	}
	again.Release()
	var nilLock *AgentLock
	nilLock.Release()
}

func TestTheLockIsNotInheritedByAProcessTheRunStarts(t *testing.T) {
	useTempLockDir(t)
	ex, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("sleep", "5")
	if err := child.Start(); err != nil {
		t.Skipf("no sleep binary: %v", err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ex.Release()
	again, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatalf("the child still holds the lock after the run released it (descriptor inherited): %v", err)
	}
	again.Release()
}

func TestAKilledHolderLeavesNoStaleLock(t *testing.T) {
	dir := useTempLockDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHolderHelper")
	cmd.Env = append(os.Environ(), "WHISPER_LOCK_HELPER=1", "WHISPER_LOCK_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil || string(buf[:4]) != "HELD" {
		t.Fatalf("helper did not take the lock: %q %v", buf, err)
	}
	if _, err := LockExclusive(lockAgent); err == nil {
		t.Fatal("the helper's lock was not seen")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		l, err := LockExclusive(lockAgent)
		if err == nil {
			l.Release()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a SIGKILLed holder left the lock held: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestLockHolderHelper is the helper process for TestAKilledHolderLeavesNoStaleLock.
func TestLockHolderHelper(t *testing.T) {
	if os.Getenv("WHISPER_LOCK_HELPER") != "1" {
		t.Skip("helper process only")
	}
	LockDir = os.Getenv("WHISPER_LOCK_DIR")
	lockOwner = os.Geteuid()
	if _, err := LockExclusive(lockAgent); err != nil {
		os.Stdout.WriteString("FAIL\n")
		os.Exit(1)
	}
	os.Stdout.WriteString("HELD\n")
	time.Sleep(30 * time.Second)
}

func TestASymlinkInPlaceOfTheLockIsRefusedNotFollowed(t *testing.T) {
	dir := useTempLockDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, lockName(lockAgent))); err != nil {
		t.Fatal(err)
	}
	if _, err := LockExclusive(lockAgent); err == nil {
		t.Fatal("a symlinked lock file must be refused")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep\n" {
		t.Fatalf("the symlink target was written: %q", b)
	}
}

func TestADirectoryOthersCanWriteIsNotTrusted(t *testing.T) {
	dir := useTempLockDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LockExclusive(lockAgent); err == nil || !strings.Contains(err.Error(), "writable by nobody else") {
		t.Fatalf("a world-writable lock directory must be refused, got %v", err)
	}
}

func TestANonRootConnectSeesTheRunButCannotHoldOrBlockIt(t *testing.T) {
	dir := useTempLockDir(t)
	ex, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	old := isPrivileged
	isPrivileged = func() bool { return false }
	defer func() { isPrivileged = old }()
	_, err = LockShared(lockAgent)
	var held *HeldError
	if !errors.As(err, &held) || held.PID != os.Getpid() {
		t.Fatalf("a non-root connect must see the enforced run by its holder file, got %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, lockName(lockAgent))); st.Mode().Perm() != 0o600 {
		t.Fatalf("the lock file must be 0600 so no other account can hold it, got %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(dir, holderName(lockAgent))); st.Mode().Perm() != 0o644 {
		t.Fatalf("the holder file must be readable, got %v", st.Mode().Perm())
	}
	ex.Release()
	if _, err := os.Stat(filepath.Join(dir, holderName(lockAgent))); !os.IsNotExist(err) {
		t.Fatal("Release must remove the holder file")
	}
	if l, err := LockShared(lockAgent); err != nil || l != nil {
		t.Fatalf("after the run a non-root connect has nothing to coordinate with: %v %v", l, err)
	}
}

func TestAHolderFileNamingAnotherProcessIsIgnored(t *testing.T) {
	dir := useTempLockDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Our own pid with a start time that is not ours: a recycled pid, so the file names nobody.
	if err := os.WriteFile(filepath.Join(dir, holderName(lockAgent)), []byte(strconv.Itoa(os.Getpid())+" 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs: start times cannot be compared")
	}
	if pid := liveHolder(lockAgent); pid != 0 {
		t.Fatalf("a holder file whose start time does not match names a different process, got pid %d", pid)
	}
}

func TestAConnectWithNothingToCoordinateWithIsNotRefused(t *testing.T) {
	useTempLockDir(t)
	lockOwner = os.Geteuid() + 1 // "not root" for this test, and the directory does not exist
	l, err := LockShared(lockAgent)
	if err != nil || l != nil {
		t.Fatalf("no lock directory means no enforced run has held this agent: got %v, %v", l, err)
	}
}

// Step 11: the enforced run is root's and the connect is not. kill(pid, 0) from another account
// answers EPERM for a process that exists, and the holder must still be seen; only ESRCH means gone.
func TestAHolderOwnedByAnotherAccountIsSeenThroughEPERM(t *testing.T) {
	useTempLockDir(t)
	withoutKernelLockTable(t) // the pid fallback: darwin, or a /proc/locks that cannot be read
	ex, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Release()
	old := signalZero
	defer func() { signalZero = old }()

	signalZero = func(int) error { return unix.EPERM }
	if pid := liveHolder(lockAgent); pid != os.Getpid() {
		t.Fatalf("EPERM means the holder exists under another account; want pid %d, got %d", os.Getpid(), pid)
	}
	oldPriv := isPrivileged
	isPrivileged = func() bool { return false }
	defer func() { isPrivileged = oldPriv }()
	_, err = LockShared(lockAgent)
	var held *HeldError
	if !errors.As(err, &held) || held.PID != os.Getpid() {
		t.Fatalf("a non-root connect must be refused by a root-held run it can only see through EPERM, got %v", err)
	}

	signalZero = func(int) error { return unix.ESRCH }
	if pid := liveHolder(lockAgent); pid != 0 {
		t.Fatalf("ESRCH means the holder is gone, got pid %d", pid)
	}
}

// The kernel's lock table confirms a holder that kill(pid, 0) cannot see from here: a run in another pid
// namespace answers ESRCH, yet its exclusive flock is listed, so it is still a live holder.
func TestTheKernelLockTableConfirmsAHolderTheSignalCannotSee(t *testing.T) {
	if _, err := os.Stat("/proc/locks"); err != nil {
		t.Skip("no kernel lock table on this platform")
	}
	useTempLockDir(t)
	ex, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer ex.Release()
	old := signalZero
	defer func() { signalZero = old }()
	signalZero = func(int) error { return unix.ESRCH }
	if pid := liveHolder(lockAgent); pid != os.Getpid() {
		t.Fatalf("a held exclusive flock names its holder even when the signal says ESRCH, got %d", pid)
	}
	ex.Release()
	if pid := liveHolder(lockAgent); pid != 0 {
		t.Fatalf("released and gone: nobody, got %d", pid)
	}
}

// The holder is published relative to the directory that was checked. A directory swapped in
// under the same path after the check never receives it; the checked one does.
func TestAHolderIsWrittenToTheCheckedDirectoryNotOneSwappedIn(t *testing.T) {
	dir := useTempLockDir(t)
	dfd, err := openLockDir(true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd)
	moved := dir + ".checked"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeHolder(dfd, lockAgent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, holderName(lockAgent))); err == nil {
		t.Fatal("the holder was written into the directory swapped in after the check")
	}
	b, err := os.ReadFile(filepath.Join(moved, holderName(lockAgent)))
	if err != nil {
		t.Fatalf("the checked directory did not receive the holder: %v", err)
	}
	if !strings.HasPrefix(string(b), strconv.Itoa(os.Getpid())+" ") {
		t.Fatalf("holder content %q", b)
	}
	st, err := os.Stat(filepath.Join(moved, holderName(lockAgent)))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("holder mode %v, %v", st.Mode(), err)
	}
	ents, _ := os.ReadDir(moved)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".holder-") {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// A parent that others can write could swap the lock directory itself, so it is refused.
func TestAParentOthersCanWriteIsNotTrusted(t *testing.T) {
	dir := useTempLockDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(dir), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := LockExclusive(lockAgent); err == nil || !strings.Contains(err.Error(), "writable by nobody else") {
		t.Fatalf("a group-writable parent must be refused, got %v", err)
	}
}

// A parent that is a symlink is not followed.
func TestASymlinkedParentIsRefused(t *testing.T) {
	useTempLockDir(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(filepath.Join(real, "locks"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	LockDir = filepath.Join(link, "locks")
	if _, err := LockExclusive(lockAgent); err == nil {
		t.Fatal("a symlinked parent must be refused")
	}
	if _, err := os.Lstat(filepath.Join(real, "locks", lockName(lockAgent))); err == nil {
		t.Fatal("a lock file was created through the symlinked parent")
	}
}

// Release removes the holder it published.
func TestReleaseRemovesTheHolder(t *testing.T) {
	dir := useTempLockDir(t)
	l, err := LockExclusive(lockAgent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, holderName(lockAgent))); err != nil {
		t.Fatalf("no holder published: %v", err)
	}
	l.Release()
	if _, err := os.Lstat(filepath.Join(dir, holderName(lockAgent))); err == nil {
		t.Fatal("the holder outlived Release")
	}
}
