// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// attribution_linux.go proves, before a containment, that this kernel tells a cgroup's programs about
// the sockets made in it. A containment rests on that: its cgroup/sock_create program marks every new
// socket, and its egress gate judges every packet, of a process in its cgroup. On a kernel before
// 5.15 the cgroup v1 net_cls or net_prio controller, once anything has used it, turns that off for
// every socket on the host until the next boot: sockets are then counted to the root cgroup, the
// containment's programs see none of them, and the process walks out unmarked. That cannot be read
// from what is mounted (a controller used and unmounted earlier in the boot leaves no trace, and one
// mounted and never used does no harm), so it is tested: a process is put in a cgroup carrying the
// containment's socket program and asked what mark its new sockets carry.

// ProbeArg re-executes this binary as the attribution probe's process. It is dispatched before the
// command tree, like InitArg.
const ProbeArg = "__whisper-attribution-probe"

// probeMark is what the probe's program gives a socket: generation 0, which no containment is given.
const probeMark = hostMarkSig

// attributionProbe runs the probe on the v2 hierarchy mounted at root. A variable so the refusals that
// come before it can be tested without a cgroup to make.
var attributionProbe = probeSocketAttribution

// attributionProven is set once a probe passed in this process, which then asks once, not twice
// (runContain's preflight and Contain's). On 5.15 and later what it tests holds for the boot; before
// 5.15 it holds until something uses a v1 net_cls or net_prio hierarchy, which Preflight refuses while
// one is mounted.
var attributionProven atomic.Bool

// probeSpec is the program the probe attaches; a variable so a test can give it one that marks nothing.
var probeSpec = func() *ebpf.ProgramSpec { return markSpec(probeMark) }

// RunProbe is the probe's process. It waits for one line on stdin, by which time it is in the probe's
// cgroup, opens an IPv4 and an IPv6 datagram socket, prints their marks in hex ("-" for a family this
// host does not have) and exits. It sends nothing.
func RunProbe() {
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	var out []string
	for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			out = append(out, "-")
			continue
		}
		m, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
		unix.Close(fd)
		if err != nil {
			out = append(out, "-")
			continue
		}
		out = append(out, strconv.FormatUint(uint64(uint32(m)), 16))
	}
	fmt.Println(strings.Join(out, " "))
	os.Exit(0)
}

// probeSocketAttribution makes a short-lived cgroup under ContainParent with the containment's socket
// program on it, starts this binary as RunProbe, moves it in before it opens anything, and checks the
// marks it reports. Everything it makes is gone when it returns.
func probeSocketAttribution(root string) error {
	if attributionProven.Load() {
		return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return containErr("could not lift the locked-memory limit for BPF: %v", err)
	}
	parent := filepath.Join(root, ContainParent)
	reapProbeCgroups(parent)
	dir := filepath.Join(parent, probeName(os.Getpid()))
	if err := mkdirUnder(dir); err != nil {
		return err
	}
	defer os.Remove(parent) // only when no containment lives there
	defer os.Remove(dir)
	prog, err := ebpf.NewProgram(probeSpec())
	if err != nil {
		return containErr("this kernel refused the containment's socket program (cgroup/sock_create): %v", err)
	}
	defer prog.Close()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return containErr("could not open the cgroup %s: %v", dir, err)
	}
	defer unix.Close(fd)
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: fd, Program: prog, Attach: ebpf.AttachCGroupInetSockCreate}); err != nil {
		return containErr("could not attach the containment's socket program to a cgroup: %v", err)
	}
	got, err := runProbe(dir)
	if err != nil {
		return containErr("could not test whether this kernel tells a cgroup's programs about its sockets (%v), which "+
			"containment rests on; nothing was changed", err)
	}
	opened := 0
	for _, f := range strings.Fields(got) {
		if f == "-" {
			continue
		}
		opened++
		if m, err := strconv.ParseUint(f, 16, 32); err != nil || uint32(m) != probeMark {
			return containErr("this kernel does not tell a cgroup's programs about the sockets made in it (a new socket in " +
				"a test cgroup carried no mark), so the containment's programs would see none of the process's " +
				"sockets; nothing was changed. On a kernel before 5.15 a cgroup v1 net_cls or net_prio controller that " +
				"anything has used turns this off for the whole boot; it takes a reboot with neither in use")
		}
	}
	if opened == 0 {
		return containErr("the attribution test could open no socket at all (%q); nothing was changed", got)
	}
	attributionProven.Store(true)
	return nil
}

// probeName names a command's probe cgroup by its pid and its start time, so a pid used again is not
// taken for the command that made it.
func probeName(pid int) string { return fmt.Sprintf("probe-%d-%s", pid, startTime(pid)) }

// reapProbeCgroups removes the probe cgroups of commands that died during a probe; removing one fails
// while anything is in it.
func reapProbeCgroups(parent string) {
	ents, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), "probe-")
		if !ok || !e.IsDir() {
			continue
		}
		pid, _, _ := strings.Cut(rest, "-")
		n, err := strconv.Atoi(pid)
		if err != nil {
			continue
		}
		if processGone(n) || e.Name() != probeName(n) {
			_ = os.Remove(filepath.Join(parent, e.Name()))
		}
	}
}

// runProbe starts the probe's process, moves it into dir and returns what it printed.
func runProbe(dir string) (string, error) {
	cmd := exec.Command("/proc/self/exe", ProbeArg)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := false
	defer func() {
		if !done {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	if err := writeFile(filepath.Join(dir, "cgroup.procs"), strconv.Itoa(cmd.Process.Pid)); err != nil {
		return "", fmt.Errorf("the test process could not be moved into its cgroup: %v", err)
	}
	if _, err := io.WriteString(in, "\n"); err != nil {
		return "", err
	}
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case s := <-line:
		done = true
		return s, nil
	case <-time.After(5 * time.Second):
		return "", errors.New("the test process did not answer within 5 s")
	}
}
