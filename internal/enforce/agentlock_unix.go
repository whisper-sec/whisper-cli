// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux || darwin

package enforce

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The box binds one WireGuard peer per /128, so two local commands that both bring up the same
// agent replace each other's peer there. An enforced run that loses its peer fails closed (its kill
// switch refuses everything after 180 s), but the better answer is for the second command to refuse
// up front and say who holds the agent. So:
//
//   - `whisper run --enforce` holds an EXCLUSIVE lock on the agent's file for the whole run;
//   - a root `whisper connect` holds a SHARED lock on it while it serves the agent, because several
//     connects for one agent are legitimate (one terminal and the resident service) but none of them
//     may coexist with an enforced run.
//
// The lock lives under a ROOT-OWNED directory that nobody else can write, so no other account can
// plant a file or a symlink there, and the lock files themselves are 0600: only root can open one, so
// only root can hold one, and no other account can sit on a lock to keep an enforced run from
// starting. A non-root connect instead READS the holder file an enforced run publishes beside its lock
// (0644, "<pid> <start time>") and refuses while that very process is alive. Lock files are never
// removed (unlinking races a second opener into locking an orphan); the holder file is removed on
// Release and is ignored when its process is gone or the pid now names a different process.
// flock is released by the kernel when the descriptor's last holder exits, so a crash leaves no stale
// lock, and every descriptor here is close-on-exec, so an agent the run starts never inherits it.

// LockDir is where the per-/128 lock files live. A var so a test can point it at a temp dir.
var LockDir = "/run/whisper/locks"

// lockOwner is the uid the lock directory and its files must belong to. A var for the same reason.
var lockOwner = 0

// isPrivileged says whether this process can open lock files (it is their owner). A var for tests.
var isPrivileged = func() bool { return os.Geteuid() == lockOwner }

// AgentLock is a held lock; Release it when the command stops serving the agent.
type AgentLock struct {
	f      *os.File
	holder string // the name of the holder file an exclusive lock published in LockDir, removed on Release
}

// Release drops the lock. Safe on a nil lock and safe to call twice.
func (l *AgentLock) Release() {
	if l == nil || l.f == nil {
		return
	}
	if l.holder != "" {
		// Before the unlock: never a moment where the file names a released lock. Removed relative
		// to a freshly checked directory, never by a path someone could have re-pointed.
		if dfd, err := openLockDir(false); err == nil {
			_ = unix.Unlinkat(dfd, l.holder, 0)
			unix.Close(dfd)
		}
		l.holder = ""
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

func lockName(a netip.Addr) string {
	return strings.ReplaceAll(a.Unmap().String(), ":", "_") + ".lock"
}

func holderName(a netip.Addr) string { return strings.TrimSuffix(lockName(a), ".lock") + ".holder" }

// openLockDir opens LockDir without following a symlink and refuses it unless it belongs to
// lockOwner and nobody else can write it. Its PARENT is held to the same rule and the lock directory
// is opened relative to the checked parent's descriptor, so nobody who could write the parent can
// swap the directory out between the check and the use. Every later file operation is relative to
// the descriptor this returns.
func openLockDir(create bool) (int, error) {
	if create {
		if err := os.MkdirAll(LockDir, 0o755); err != nil {
			return -1, fmt.Errorf("cannot create the agent lock directory %s: %w", LockDir, err)
		}
	}
	parent := filepath.Dir(LockDir)
	pfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	if err := checkLockDirFd(pfd, parent); err != nil {
		return -1, err
	}
	fd, err := unix.Openat(pfd, filepath.Base(LockDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := checkLockDirFd(fd, LockDir); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// checkLockDirFd refuses a directory, by its open descriptor, unless it belongs to lockOwner and
// neither its group nor anybody else can write it.
func checkLockDirFd(fd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != lockOwner || st.Mode&0o022 != 0 {
		return fmt.Errorf("refusing the agent lock directory %s: it must belong to uid %d and be writable by nobody else", name, lockOwner)
	}
	return nil
}

func checkLockFile(f *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != lockOwner || st.Nlink != 1 {
		return fmt.Errorf("refusing %s: not a plain lock file owned by uid %d", f.Name(), lockOwner)
	}
	return nil
}

func openLock(dfd int, a netip.Addr, flags int) (*os.File, error) {
	fd, err := unix.Openat(dfd, lockName(a), flags|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the agent lock for %s: %w", a, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(LockDir, lockName(a)))
	if err := checkLockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// LockExclusive takes the agent's lock for an enforced run, creating it when needed. It never
// waits: a held lock is a *HeldError at once.
func LockExclusive(a netip.Addr) (*AgentLock, error) {
	dfd, err := openLockDir(true)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	f, err := openLock(dfd, a, unix.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			if pid := liveHolder(a); pid > 0 {
				return nil, &HeldError{Addr: a, PID: pid, Exclusive: true}
			}
			return nil, &HeldError{Addr: a} // shared holders: one or more root connects
		}
		return nil, fmt.Errorf("cannot lock the agent %s: %w", a, err)
	}
	// Publish who holds it, AFTER the lock, by rename so a reader never sees a half-written file.
	if err := writeHolder(dfd, a); err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, err
	}
	return &AgentLock{f: f, holder: holderName(a)}, nil
}

// LockShared is what a `whisper connect` takes while it serves an agent. As root it holds a shared lock,
// so a later enforced run of the same agent sees it and refuses. Not as root it holds nothing (only root
// can open a lock file) and refuses while an enforced run's holder file names a live process; otherwise
// it returns (nil, nil): there is nothing to coordinate with.
func LockShared(a netip.Addr) (*AgentLock, error) {
	if !isPrivileged() {
		if pid := liveHolder(a); pid > 0 {
			return nil, &HeldError{Addr: a, PID: pid, Exclusive: true}
		}
		return nil, nil
	}
	dfd, err := openLockDir(true)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	f, err := openLock(dfd, a, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, &HeldError{Addr: a, PID: liveHolder(a), Exclusive: true}
		}
		return nil, fmt.Errorf("cannot lock the agent %s: %w", a, err)
	}
	return &AgentLock{f: f}, nil
}

// EnforcedHolders lists every agent a live enforced run other than this process holds on this host, for
// a caller that has no /128 to ask about (a connect that names no agent). Never blocks; empty when the
// lock directory is absent or untrusted.
func EnforcedHolders() []netip.Addr {
	ents, err := os.ReadDir(LockDir)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".holder") {
			continue
		}
		a, perr := netip.ParseAddr(strings.ReplaceAll(strings.TrimSuffix(name, ".holder"), "_", ":"))
		if perr != nil {
			continue
		}
		if EnforcedHolder(a) > 0 {
			out = append(out, a)
		}
	}
	return out
}

// EnforcedHolder is the pid of a live enforced run holding a, or 0. It reads the holder file, so it
// answers the same for root and for any other account, and it never names the calling process: an
// enforced run reconnecting its own agent is not in its own way. It takes no lock and never blocks,
// which is what lets every op:connect ask it first.
func EnforcedHolder(a netip.Addr) int {
	if pid := liveHolder(a); pid > 0 && pid != os.Getpid() {
		return pid
	}
	return 0
}

// startTime is field 22 of /proc/<pid>/stat: with the pid it names one process, never a recycled one.
// Empty where there is no procfs (darwin), and then a holder can only be named while it is alive.
func startTime(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')') // the command name may hold spaces and parentheses
	if i < 0 {
		return ""
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}

// writeHolder publishes "<pid> <start time>" as the holder of a, entirely relative to dfd, the
// lock directory openLockDir checked: created exclusively without following a link, made readable
// by its descriptor, and renamed into place within that same directory. A path-based create, chmod
// or rename would act on whatever directory the path names at that moment, which need not be the
// one that was checked.
func writeHolder(dfd int, a netip.Addr) error {
	tmp, fd, err := createHolderTemp(dfd)
	if err != nil {
		return fmt.Errorf("cannot publish the agent lock holder: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	pid := os.Getpid()
	_, werr := fmt.Fprintf(f, "%d %s\n", pid, startTime(pid))
	if werr == nil {
		werr = unix.Fchmod(fd, 0o644)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat(dfd, tmp, dfd, holderName(a))
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("cannot publish the agent lock holder: %w", werr)
	}
	return nil
}

// createHolderTemp creates a fresh, private temporary file in dfd, never reusing or following an
// existing name.
func createHolderTemp(dfd int) (string, int, error) {
	var b [8]byte
	for i := 0; i < 16; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return "", -1, err
		}
		name := ".holder-" + hex.EncodeToString(b[:])
		fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, err
		}
	}
	return "", -1, errors.New("no free temporary name")
}

// signalZero asks the kernel whether pid names a process (kill with signal 0). A var so a test can
// answer as the kernel does for a process owned by another account.
var signalZero = func(pid int) error { return unix.Kill(pid, 0) }

// liveHolder is the pid of the enforced run holding a, or 0. The holder file must name a process that is
// alive AND (where procfs exists) started when the file says, so a recycled pid is never named.
func liveHolder(a netip.Addr) int {
	dfd, err := openLockDir(false)
	if err != nil {
		return 0
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, holderName(a), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	f := os.NewFile(uintptr(fd), holderName(a))
	defer f.Close()
	if checkLockFile(f) != nil {
		return 0
	}
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	fields := strings.Fields(string(buf[:n]))
	if len(fields) < 1 {
		return 0
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return 0
	}
	// The kernel's own lock table CONFIRMS a holder: an exclusive flock on THIS lock file means an enforced
	// run holds the agent, whatever kill(pid, 0) says from here (another pid namespace answers ESRCH for a
	// live run). It never rules one out: the table hides locks whose owner is not visible in this /proc's pid
	// namespace, and on some filesystems stat's device differs from the one it prints, so "not listed" can
	// be a live run. A run that is really gone is caught below by ESRCH and the start time.
	if held, known := exclusiveFlockHeld(dfd, lockName(a)); known && held {
		return pid
	}
	// Only ESRCH says the process is gone. EPERM is the kernel saying it exists and belongs to another
	// account, which is exactly what a root run looks like to a non-root connect: reading that
	// as "dead" let every non-root connect cut a live enforced run's tunnel. A recycled pid is still
	// caught below, by the start time.
	if errors.Is(signalZero(pid), unix.ESRCH) {
		return 0
	}
	if st := startTime(pid); st != "" && (len(fields) < 2 || fields[1] != st) {
		return 0
	}
	return pid
}
