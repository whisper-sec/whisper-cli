// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// init_linux.go is the agent's init: the CLI re-executed as pid 1 of a new PID namespace and
// a new mount namespace, inside the agent's network namespace. It is the last code that runs
// as root on the agent's side, and its whole job is to make the agent's world before the
// agent exists:
//
//   - prove it is where it should be: pid 1, in the agent's network namespace and not the
//     host's, with loopback, the tunnel interface and nothing else but the idle fallback
//     devices a host's tunnel modules put in every namespace (links_linux.go). If not, it
//     refuses (exit 125), naming each interface and why.
//   - make every mount private, so nothing below propagates back to the host.
//   - a fresh /proc for the new PID namespace, so no host process is visible to signal,
//     ptrace or borrow a network from.
//   - DNS that can only mean the tunnel: resolv.conf naming the tunnel's resolvers, an
//     nsswitch.conf whose hosts line is `files dns`, and an empty tmpfs over every local
//     resolver and service socket that would answer a lookup or start a process on the host's
//     network (systemd-resolved, nscd, avahi, sssd, the system and session buses, container
//     runtimes).
//   - mark every inherited descriptor close-on-exec, so nothing the CLI was handed reaches
//     the agent, and refuse an IP socket as stdin, stdout or stderr.
//   - drop to the agent's user, with its own groups, no capabilities and no_new_privs.
//   - reap every orphan, forward SIGTERM and SIGHUP, and exit with the agent's status, which
//     ends every process left in the namespace.
//
// Every step is fatal on failure. A half-built world is never handed to an agent.

// InitArg is the argv[1] that selects this entry point in the CLI's main.
const InitArg = "__whisper-enforce-init"

// ExitSetup is the status for "the agent was never started": init could not build its world.
const ExitSetup = 125

// Spec is what the parent hands init over an inherited pipe (never argv or the environment,
// which the agent could read).
type Spec struct {
	Path      string   // the agent's executable, absolute
	Args      []string // argv, argv[0] included
	Env       []string
	Dir       string
	UID       uint32
	GID       uint32
	Groups    []uint32
	Resolvers []string
	NetInode  uint64 // the agent's network namespace
	HostInode uint64 // the host's, which init must not be in
	Seccomp   string // SeccompDefault (also ""), SeccompStrict or SeccompOff
}

// hiddenDirs are covered by an empty tmpfs inside the agent's mount namespace. Each but the last
// two holds a socket that a library or a command line tool uses to have a host daemon resolve a
// name or start a process for it, and that daemon lives on the host's network.
var hiddenDirs = []string{
	"/run/systemd/resolve",
	"/run/nscd",
	"/var/run/nscd",
	"/run/avahi-daemon",
	"/var/lib/sss/pipes",
	"/run/dbus",
	"/var/run/dbus",
	"/run/podman",
	"/run/containerd",
	"/run/docker",
	"/run/lxd",
	"/var/snap/lxd/common/lxd",
	// Not sockets: where `ip netns` and CNI mount the network namespaces they name. A descriptor of one is a namespace
	// the agent could put the far end of a veth or netkit pair in, on a kernel without the peer-namespace check
	// (networkd.go), and it has no use for any of them.
	"/run/netns",
	"/var/run/netns",
}

// hiddenFiles are sockets mounted over with /dev/null.
var hiddenFiles = []string{
	"/run/docker.sock",
	"/var/run/docker.sock",
	"/run/snapd.socket",
	"/run/snapd-snap.socket",
	"/var/lib/lxd/unix.socket",
}

// RunInit is init's entry point. It never returns.
func RunInit() {
	runtime.LockOSThread() // the agent is forked from this thread, which carries no_new_privs
	code, err := runInit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "whisper: enforce: %s - the agent was not started\n", err)
		os.Exit(ExitSetup)
	}
	os.Exit(code)
}

func runInit() (int, error) {
	f := os.NewFile(3, "spec")
	if f == nil {
		return 0, errors.New("no specification from the parent")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return 0, errors.New("could not read the specification")
	}
	var s Spec
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, errors.New("unreadable specification")
	}
	if err := checkPlace(s); err != nil {
		return 0, err
	}
	if err := buildMounts(s); err != nil {
		return 0, err
	}
	if err := sealDescriptors(); err != nil {
		return 0, err
	}
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	return supervise(s)
}

// checkPlace refuses to go on anywhere but the agent's network namespace.
func checkPlace(s Spec) error { return checkPlaceWith(s, livePlace) }

// placeProbe is how checkPlace reads where it is: its pid, its network namespace's inode and that
// namespace's links. Tests hand it a fake, so the rule it applies is held to without root.
type placeProbe struct {
	pid   func() int
	inode func() (uint64, error)
	links func() (linkView, error)
}

var livePlace = placeProbe{
	pid:   os.Getpid,
	inode: nsInode,
	links: func() (linkView, error) { return readLinkView("lo", IfName) },
}

func checkPlaceWith(s Spec, p placeProbe) error {
	if p.pid() != 1 {
		return errors.New("init is not pid 1 of its own PID namespace")
	}
	ino, err := p.inode()
	if err != nil {
		return errors.New("cannot read this process's network namespace")
	}
	if ino != s.NetInode || ino == s.HostInode {
		return errors.New("not inside the agent's network namespace")
	}
	v, err := p.links()
	if err != nil {
		return fmt.Errorf("cannot read the namespace's interfaces: %w", err)
	}
	if err := agentPlaceError(v); err != nil {
		return err
	}
	if s.UID == 0 {
		return errors.New("the agent would run as root, which could leave the namespace")
	}
	if !filepath.IsAbs(s.Path) || len(s.Args) == 0 {
		return errors.New("the command is not an absolute path")
	}
	return nil
}

func buildMounts(s Spec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("cannot make the mounts private: %w", err)
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("cannot mount /proc for the agent: %w", err)
	}
	covered := map[string]bool{}
	for _, d := range hiddenDirs {
		real, ok := existingDir(d)
		if !ok || covered[real] {
			continue
		}
		if err := unix.Mount("tmpfs", real, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=64k"); err != nil {
			return fmt.Errorf("cannot cover %s: %w", real, err)
		}
		covered[real] = true
	}
	// The session runtime directory holds the user's session bus and the user's systemd, either
	// of which can start a process on the host's network. The agent gets an empty one of its
	// own, so a program that wants $XDG_RUNTIME_DIR still finds a private directory there.
	if real, ok := existingDir("/run/user/" + strconv.FormatUint(uint64(s.UID), 10)); ok && !covered[real] {
		opts := fmt.Sprintf("mode=0700,uid=%d,gid=%d,size=16m", s.UID, s.GID)
		if err := unix.Mount("tmpfs", real, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
			return fmt.Errorf("cannot cover %s: %w", real, err)
		}
		covered[real] = true
	}
	for _, p := range hiddenFiles {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || underAny(real, covered) {
			continue
		}
		if st, err := os.Lstat(real); err != nil || st.IsDir() {
			continue
		}
		if err := unix.Mount("/dev/null", real, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("cannot cover %s: %w", real, err)
		}
	}
	if err := placeFile("/etc/resolv.conf", resolvConf(s.Resolvers), covered, true); err != nil {
		return err
	}
	if host, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		if err := placeFile("/etc/nsswitch.conf", nsswitch(string(host)), covered, false); err != nil {
			return err
		}
	}
	return nil
}

func existingDir(p string) (string, bool) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	st, err := os.Stat(real)
	if err != nil || !st.IsDir() {
		return "", false
	}
	return real, true
}

func underAny(p string, dirs map[string]bool) bool {
	for d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// placeFile makes path read content inside this mount namespace. path is commonly a symlink
// (resolv.conf into systemd-resolved's run directory), and mount(2) follows a symlink, so the
// content goes where the link LEADS: written straight into a tmpfs this init laid down, or
// bind-mounted read-only over the real file anywhere else. A dangling link has nowhere to put
// it; required says whether that ends the start.
func placeFile(path, content string, covered map[string]bool, required bool) error {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Dangling: follow the link by hand, and accept only a target inside a covered tmpfs.
		link, lerr := os.Readlink(path)
		if lerr != nil {
			if required {
				return fmt.Errorf("cannot read %s: %w", path, err)
			}
			return nil
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(path), link)
		}
		target = filepath.Clean(link)
		if !underAny(target, covered) {
			if required {
				return fmt.Errorf("%s points at %s, which does not exist, so the agent cannot be given its resolver", path, target)
			}
			return nil
		}
	}
	if underAny(target, covered) {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("cannot prepare %s: %w", target, err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return fmt.Errorf("cannot write %s: %w", target, err)
		}
		return nil
	}
	src, err := os.CreateTemp("", ".whisper-enforce-*")
	if err != nil {
		return fmt.Errorf("cannot stage %s: %w", path, err)
	}
	name := src.Name()
	defer os.Remove(name) // the bind mount keeps the inode; the name is not needed after it
	if _, err := src.WriteString(content); err != nil {
		src.Close()
		return fmt.Errorf("cannot stage %s: %w", path, err)
	}
	src.Close()
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("cannot stage %s: %w", path, err)
	}
	if err := unix.Mount(name, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("cannot place %s: %w", path, err)
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("cannot make %s read-only: %w", path, err)
	}
	return nil
}

// resolvConf names the tunnel's resolvers and nothing else.
func resolvConf(resolvers []string) string {
	var b strings.Builder
	b.WriteString("# Written by whisper run --enforce: DNS goes to the Whisper tunnel's resolvers only.\n")
	for _, r := range resolvers {
		if a, err := netip.ParseAddr(r); err == nil {
			b.WriteString("nameserver " + a.String() + "\n")
		}
	}
	b.WriteString("options edns0\n")
	return b.String()
}

// nsswitch is the host's nsswitch.conf with the hosts line replaced by `files dns`, so glibc
// resolves through resolv.conf alone. Every other database (users, groups) stays as it was.
func nsswitch(host string) string {
	var b strings.Builder
	found := false
	for _, line := range strings.Split(strings.TrimRight(host, "\n"), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "hosts:") {
			if !found {
				b.WriteString("hosts:          files dns\n")
				found = true
			}
			continue
		}
		b.WriteString(line + "\n")
	}
	if !found {
		b.WriteString("hosts:          files dns\n")
	}
	return b.String()
}

// sealDescriptors marks every descriptor above stderr close-on-exec, which covers anything
// the CLI inherited without the flag, and refuses any socket on stdio but a unix one. A socket
// there is handed to the agent as it is, made in the host's namespace: an IP socket is a
// connection outside the tunnel, and a vsock, packet or TIPC socket is a way off the host that
// seccomp, which only stops the agent making one, does not see. A unix socket (socket activation,
// a supervisor's log stream) reaches only this host; a pipe, a terminal or a file is not a socket.
func sealDescriptors() error {
	if err := closeOnExecAboveStderr(); err != nil {
		return err
	}
	for fd := 0; fd <= 2; fd++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			continue
		}
		dom, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			return fmt.Errorf("descriptor %d is a socket whose family cannot be read", fd)
		}
		if dom != unix.AF_UNIX {
			return fmt.Errorf("descriptor %d is a socket of family %d made in the host's namespace; only a unix socket may be the agent's stdio", fd, dom)
		}
	}
	return nil
}

// closeOnExecAboveStderr marks every descriptor above stderr close-on-exec. Go opens its own
// descriptors with the flag but leaves the ones a process inherits alone, and exec passes those
// on, so this is what keeps a descriptor this process was handed out of the processes it starts.
func closeOnExecAboveStderr() error {
	if err := unix.CloseRange(3, math.MaxUint32, unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return nil
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return errors.New("cannot seal inherited descriptors")
	}
	for _, e := range ents {
		if fd, aerr := strconv.Atoi(e.Name()); aerr == nil && fd > 2 {
			unix.CloseOnExec(fd)
		}
	}
	return nil
}

// supervise starts the agent and is its pid 1 until it exits.
func supervise(s Spec) (int, error) {
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT) // the terminal delivers these to the agent itself
	fwd := make(chan os.Signal, 8)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 0, errors.New("cannot set no_new_privs")
	}
	// The seccomp filter goes on after no_new_privs and before the fork, on every thread, so the agent
	// is born under it. A mode this init cannot honour refuses the start rather than running bare.
	mode, merr := NormalizeSeccomp(s.Seccomp)
	if merr != nil {
		return 0, merr
	}
	if err := installSeccomp(mode); err != nil {
		return 0, err
	}
	pid, err := syscall.ForkExec(s.Path, s.Args, &syscall.ProcAttr{
		Dir:   s.Dir,
		Env:   s.Env,
		Files: []uintptr{0, 1, 2},
		Sys: &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: s.UID, Gid: s.GID, Groups: s.Groups},
			Pdeathsig:  syscall.SIGKILL,
		},
	})
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EACCES) {
			return 127, fmt.Errorf("cannot run %s as the agent's user: %w", s.Path, err)
		}
		return 0, fmt.Errorf("cannot start the agent: %w", err)
	}
	go func() {
		for sig := range fwd {
			_ = syscall.Kill(pid, sig.(syscall.Signal))
		}
	}()
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return 1, nil
		}
		if got != pid {
			continue // an orphan re-parented to us: reaped, nothing else
		}
		switch {
		case ws.Exited():
			return ws.ExitStatus(), nil
		case ws.Signaled():
			return 128 + int(ws.Signal()), nil
		}
	}
}

// Spawn starts init for spec inside the namespace and waits for it, returning the agent's
// exit status. Its body blocks in cmd.Wait for the whole of the agent's life, so the thread run
// holds it on stays inside the namespace and locked until the agent exits: the kernel ties
// PR_SET_PDEATHSIG to the thread that forked, and if the CLI process dies that thread dies with it,
// killing init and every process in the agent's PID namespace. The thread goes home only once the
// agent has exited (awayAndBack), so its end no longer kills init: any way out of the body before
// Wait has reported init's end (a Wait error, a callback that ends its goroutine) kills init itself.
func (n *Namespace) Spawn(spec Spec, started func(pid int)) (int, error) {
	spec.NetInode = n.Inode
	spec.HostInode = n.HostInode
	body, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}
	code := 0
	err = n.run(func() error {
		r, w, perr := os.Pipe()
		if perr != nil {
			return perr
		}
		self, xerr := os.Executable()
		if xerr != nil {
			self = "/proc/self/exe"
		}
		cmd := exec.Command(self, InitArg)
		cmd.Args = []string{"whisper-enforce-init", InitArg}
		cmd.Env = []string{}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.ExtraFiles = []*os.File{r}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
			Pdeathsig:  syscall.SIGKILL,
		}
		if serr := cmd.Start(); serr != nil {
			r.Close()
			w.Close()
			return fmt.Errorf("enforce: cannot start the agent's init: %w", serr)
		}
		// Until Wait has reported init's end, leaving the body kills it: the thread no longer ends
		// here and fires init's parent-death signal, it goes home.
		ended := false
		defer func() {
			if !ended {
				_ = cmd.Process.Kill()
			}
		}()
		r.Close()
		_, werr := w.Write(body)
		w.Close()
		if werr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			ended = true
			return errors.New("enforce: cannot hand the agent's init its specification")
		}
		if started != nil {
			started(cmd.Process.Pid)
		}
		werr = cmd.Wait()
		var ee *exec.ExitError
		switch {
		case werr == nil:
			ended = true
			code = 0
		case errors.As(werr, &ee):
			ended = true
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			} else {
				code = ee.ExitCode()
			}
		default:
			// Not init's exit status, so whether init still runs is unknown: the deferred kill ends it.
			return werr
		}
		return nil
	})
	return code, err
}
