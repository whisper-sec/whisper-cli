// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// networkd_fs_linux.go reads what the placed-device check judges without trusting what it reads: a networkd's root
// can be a container tenant's, or one the contained process made itself, and so can a namespace's mount points and a
// process's descriptors. Every path is resolved with openat2(RESOLVE_IN_ROOT) from a descriptor of the root, so no
// symbolic link or ".." leaves it; everything is first opened O_PATH, which never waits and never opens a device, and
// only a regular file (or an nsfs file, for a namespace) is opened again to be read, through /proc/self/fd; every
// read is bounded.

func init() {
	readUnder = readUnderLinux
	listUnder = listUnderLinux
}

// nsfsMagic is NSFS_MAGIC, the file system of namespace files.
const nsfsMagic = 0x6e736673

// openUnder opens path under root (the command's own root for "") with flags, resolved inside root.
func openUnder(root, path string, flags uint64) (int, error) {
	if root == "" {
		root = "/"
	}
	rfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rfd)
	rel := strings.TrimLeft(path, "/")
	if rel == "" {
		rel = "."
	}
	for {
		fd, err := unix.Openat2(rfd, rel, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue // a rename raced the lookup; it is safe to look again
		}
		return fd, err
	}
}

// notThere reports whether an open failed because nothing usable is there: no entry, a link that ends nowhere or in
// a loop, a file where a directory should be.
func notThere(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP)
}

func readUnderLinux(root, path string) ([]byte, fs.FileInfo, error) {
	fd, err := openUnder(root, path, unix.O_PATH)
	if errors.Is(err, unix.ENOSYS) {
		return nil, nil, errors.New("this kernel has no openat2 (Linux 5.6), which reading a configuration safely needs")
	}
	if err != nil {
		if notThere(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, nil
	}
	if fi.Size() > maxConfFile {
		return nil, fi, fmt.Errorf("%s is larger than %d bytes", quoteText(path), maxConfFile)
	}
	rfd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	r := os.NewFile(uintptr(rfd), path)
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxConfFile+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxConfFile {
		return nil, fi, fmt.Errorf("%s is larger than %d bytes", quoteText(path), maxConfFile)
	}
	return b, fi, nil
}

func listUnderLinux(root, path string) ([]string, []fs.FileInfo, error) {
	var chain []fs.FileInfo
	cur := ""
	for _, part := range append([]string{""}, strings.Split(strings.Trim(path, "/"), "/")...) {
		cur = filepath.Join("/", cur, part)
		fd, err := openUnder(root, cur, unix.O_PATH|unix.O_DIRECTORY)
		if errors.Is(err, unix.ENOSYS) {
			return nil, nil, errors.New("this kernel has no openat2 (Linux 5.6), which reading a configuration safely needs")
		}
		if err != nil {
			if notThere(err) {
				return nil, nil, fs.ErrNotExist
			}
			return nil, nil, err
		}
		f := os.NewFile(uintptr(fd), cur)
		fi, err := f.Stat()
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		chain = append(chain, fi)
	}
	fd, err := openUnder(root, path, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		if notThere(err) {
			return nil, nil, fs.ErrNotExist
		}
		return nil, nil, err
	}
	d := os.NewFile(uintptr(fd), path)
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, nil, err
	}
	return names, chain, nil
}

// openNamespace opens the namespace file at path (under root when root is not "", else as it stands, for a /proc
// magic link) for use as a descriptor, or reports that it is none: it is opened O_PATH, so a FIFO or a device put
// there does nothing, and opened again only if it is on nsfs.
func openNamespace(root, path string) (int, bool) {
	var fd int
	var err error
	if root != "" {
		fd, err = openUnder(root, path, unix.O_PATH)
	} else {
		fd, err = unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return -1, false
	}
	defer unix.Close(fd)
	var sfs unix.Statfs_t
	if unix.Fstatfs(fd, &sfs) != nil || sfs.Type != nsfsMagic {
		return -1, false
	}
	rfd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false
	}
	return rfd, true
}

// changedSinceStart lists what changed in a running networkd's configuration after it started: every entry (a file, a
// link, a directory) under its configuration directories whose change time is after its start, a directory counting
// for what was added, renamed or removed in it. networkd reads its files when it starts and on a reload, a reload
// leaves no trace, and a changed file cannot be read as it was, so any of these means networkd may hold what is no
// longer on disk. The start is known to the clock tick, so a change within a tick of it counts as after.
func changedSinceStart(in networkdInstance) []string {
	if in.pid == 0 {
		return nil
	}
	started, ok := processStart(in.pid)
	if !ok {
		return nil
	}
	return changedSince(in.reader.root, started.Add(-10*time.Millisecond))
}

// changedSince is changedSinceStart for a configuration under root, against the time after.
func changedSince(root string, after time.Time) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		fd, err := openUnder(root, dir, unix.O_RDONLY|unix.O_DIRECTORY)
		if err != nil {
			return
		}
		d := os.NewFile(uintptr(fd), dir)
		defer d.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && time.Unix(st.Ctim.Unix()).After(after) {
			out = append(out, dir)
		}
		names, _ := d.Readdirnames(-1)
		for _, n := range names {
			var est unix.Stat_t
			if unix.Fstatat(fd, n, &est, unix.AT_SYMLINK_NOFOLLOW) != nil {
				continue
			}
			p := filepath.Join(dir, n)
			if time.Unix(est.Ctim.Unix()).After(after) {
				out = append(out, p)
				continue
			}
			if est.Mode&unix.S_IFMT == unix.S_IFLNK {
				// A link names what it points at: that, and the directory it sits in, may have changed since.
				if t := linkTargetChanged(root, p, after); t != "" {
					out = append(out, p+" (through "+t+")")
					continue
				}
				if depth == 0 && strings.HasSuffix(n, ".d") {
					walk(p, 1) // a linked drop-in directory, walked where it leads
				}
				continue
			}
			if est.Mode&unix.S_IFMT == unix.S_IFDIR && depth == 0 {
				walk(p, 1) // a drop-in directory
			}
		}
	}
	for _, d := range networkDirs {
		walk(d, 0)
	}
	return out
}

// linkTargetChanged names what the link at path under root leads to when that, or the directory it is in, changed
// after after, or answers "". A link whose target is gone names where it pointed, if that directory changed.
func linkTargetChanged(root, path string, after time.Time) string {
	if fd, err := openUnder(root, path, unix.O_PATH); err == nil {
		defer unix.Close(fd)
		var st unix.Stat_t
		target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if unix.Fstat(fd, &st) == nil && time.Unix(st.Ctim.Unix()).After(after) {
			return quoteText(target)
		}
	}
	// Every directory on the way, resolved under the root from each link's own text: a link to a link to a file
	// that was removed leaves only the last directory changed.
	cur := path
	for hop := 0; hop < 16; hop++ {
		dirFD, err := openUnder(root, filepath.Dir(cur), unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return ""
		}
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(dirFD, filepath.Base(cur), buf)
		unix.Close(dirFD)
		if err != nil {
			return "" // not a link: the end of the chain, judged above
		}
		t := string(buf[:n])
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(cur), t)
		}
		pd, err := openUnder(root, filepath.Dir(t), unix.O_PATH|unix.O_DIRECTORY)
		if err != nil {
			return ""
		}
		var st unix.Stat_t
		changed := unix.Fstat(pd, &st) == nil && time.Unix(st.Ctim.Unix()).After(after)
		unix.Close(pd)
		if changed {
			return quoteText(filepath.Dir(t))
		}
		cur = t
	}
	return ""
}

// processStart is when pid started: its start in clock ticks after boot (/proc/<pid>/stat), placed on the wall clock
// by the boot clock read now.
func processStart(pid int) (time.Time, bool) {
	ticks, err := strconv.ParseUint(startTime(pid), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	var boot, now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_REALTIME, &now) != nil {
		return time.Time{}, false
	}
	booted := time.Unix(now.Unix()).Add(-time.Duration(boot.Nano()))
	return booted.Add(time.Duration(ticks) * time.Second / 100), true // USER_HZ is 100 on every Linux ABI Go supports
}
