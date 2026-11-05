// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// contain_linux.go is the mechanism behind contain.go: the cgroup, its two BPF programs, the
// move, and the sockets made before it. Everything here needs root (CAP_SYS_ADMIN for the cgroup
// and the BPF attachment, CAP_NET_ADMIN for SO_BINDTODEVICE, CAP_SYS_PTRACE for pidfd_getfd);
// Contain checks for root first and says so.

// procRoot and the cgroup mount are variables so the refusals can be tested without root.
var (
	procRoot      = "/proc"
	mountinfoPath = "/proc/self/mountinfo"
	containState  = "/run/whisper/contain"
	geteuid       = os.Geteuid
	freezeWait    = 10 * time.Second
	settleRounds  = 64
	// beforeMove runs between the preflight and the first move; tests use it to make the process
	// exit at exactly that moment.
	beforeMove = func() {}
)

// __sk_buff.ifindex and bpf_sock.mark, from include/uapi/linux/bpf.h.
const (
	skbIfindexOff  = 40
	bpfSockMarkOff = 16
)

// Containment is a running containment.
type Containment struct {
	Pid     int
	Members []int
	Sockets SocketReport

	dir       string // the cgroup's directory
	root      string // the v2 hierarchy's mount point
	origin    map[int]string
	gate      *ebpf.Program
	mark      *ebpf.Program
	pinned    []pinnedSock
	route     HostRoute
	statePath string
}

// pinnedSock is a socket the containment pinned and left working: on release its device binding
// is put back as it was. It is found again by pid, descriptor and inode, never kept open, so the
// program closing it really closes it.
type pinnedSock struct {
	Pid, Fd int
	Ino     uint64
	Was     string
}

// containRecord is what a containment leaves under /run/whisper/contain, so that one which was
// killed can still be released by `whisper contain --release`.
type containRecord struct {
	Pid    int            `json:"pid"`
	Slot   int            `json:"slot"`
	Origin map[int]string `json:"origin"`
	Pinned []pinnedSock   `json:"pinned"`
}

// Preflight refuses, before anything is touched, every reason a containment of pid cannot be
// done or cannot be honest: no root, no such process, a kernel thread, init, this process or one
// of its ancestors, a privileged process, a kernel with no cgroup v2.
func Preflight(pid int) error {
	if geteuid() != 0 {
		return containErr("containing a running process needs root: it creates a cgroup, attaches BPF programs to it " +
			"(CAP_SYS_ADMIN, CAP_BPF), adds a route (CAP_NET_ADMIN) and reaches into the process's sockets " +
			"(CAP_SYS_PTRACE). Run it as `sudo whisper contain <pid>`")
	}
	if pid <= 0 {
		return containErr("%d is not a process id", pid)
	}
	if pid == 1 {
		return containErr("pid 1 is this host's init and cannot be contained")
	}
	st, parent, err := readTask(pid)
	if err != nil {
		return err
	}
	if isAncestor(parent, pid, os.Getpid()) {
		return containErr("pid %d is this command or one of its parents (your shell, sudo); it cannot contain itself", pid)
	}
	if why := st.privileged(); why != "" {
		return containErr("pid %d (%s) cannot be contained because %s, and a privileged process can move itself "+
			"out of a cgroup or detach its programs. Contain an unprivileged process, or start it under "+
			"`sudo whisper run --enforce`, which no process inside can undo", pid, st.Name, why)
	}
	mi, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return containErr("cannot read %s: %v", mountinfoPath, err)
	}
	if _, err := cgroup2Mount(string(mi)); err != nil {
		return containErr("this kernel has no cgroup v2 hierarchy mounted, which containment needs (it moves the " +
			"process into a cgroup of its own). Mount one (mount -t cgroup2 none /sys/fs/cgroup) or boot with " +
			"systemd.unified_cgroup_hierarchy=1")
	}
	return nil
}

// readTask reads one process's status, and the parent map of every process on the host.
func readTask(pid int) (procStatus, map[int]int, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return procStatus{}, nil, &ContainError{Msg: fmt.Sprintf("there is no process with pid %d", pid)}
		}
		return procStatus{}, nil, containErr("cannot read pid %d: %v", pid, err)
	}
	st := parseStatus(string(b))
	if sb, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat")); err == nil {
		if _, fl, ok := statPPidFlags(string(sb)); ok && fl&pfKthread != 0 {
			st.Kthread = true
		}
	}
	if st.Kthread {
		return st, nil, containErr("pid %d is a kernel thread, which has no sockets of its own to contain", pid)
	}
	return st, parentMap(), nil
}

// parentMap reads every process's parent from /proc.
func parentMap() map[int]int {
	out := map[int]int{}
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		if pp, _, ok := statPPidFlags(string(b)); ok {
			out[p] = pp
		}
	}
	return out
}

// Contain moves pid and its descendants into the containment's cgroup and applies the route.
// The order never leaves a window: the cgroup is made frozen and its programs attached while it
// is empty, so a process is frozen and steered the moment it enters; the tree is moved until a
// pass finds nobody left outside; the sockets made before are then dealt with while nothing in it
// can run; only then is it thawed. On any failure the process is put back as it was.
func Contain(pid int, self netip.Addr, route HostRoute, logf func(string, ...any)) (*Containment, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := Preflight(pid); err != nil {
		return nil, err
	}
	mi, _ := os.ReadFile(mountinfoPath)
	root, _ := cgroup2Mount(string(mi))
	c := &Containment{Pid: pid, root: root, route: route, origin: map[int]string{},
		dir: filepath.Join(root, ContainParent, containCgroupName(self))}
	c.statePath = filepath.Join(containState, containCgroupName(self)+".json")
	if err := c.makeCgroup(); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.undo()
		}
	}()
	if err := c.attach(); err != nil {
		return nil, err
	}
	beforeMove()
	if err := c.moveTree(); err != nil {
		return nil, err
	}
	if err := c.waitFrozen(); err != nil {
		return nil, err
	}
	// Frozen: nothing in the cgroup can fork, so one more pass proves the tree complete.
	if err := c.moveTree(); err != nil {
		return nil, err
	}
	if err := c.checkMembers(); err != nil {
		return nil, err
	}
	if err := c.sockets(); err != nil {
		return nil, err
	}
	c.writeRecord()
	if err := writeFile(filepath.Join(c.dir, "cgroup.freeze"), "0"); err != nil {
		return nil, containErr("could not thaw the contained process: %v", err)
	}
	ok = true
	return c, nil
}

func (c *Containment) makeCgroup() error {
	parent := filepath.Dir(c.dir)
	if err := os.Mkdir(parent, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return containErr("could not create the cgroup %s: %v", parent, err)
	}
	if err := os.Mkdir(c.dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return containErr("could not create the cgroup %s: %v", c.dir, err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "cgroup.freeze")); err != nil {
		return containErr("this kernel's cgroup v2 has no freezer (cgroup.freeze, Linux 5.2+), which containment " +
			"needs so that nothing in the process can fork or open a socket while it is moved")
	}
	// A killed containment of this agent left this cgroup, with whoever was in it still cut off.
	// Its record says where they came from; they are taken over and released with this one.
	if rec, err := readRecord(c.statePath); err == nil {
		for p, o := range rec.Origin {
			c.origin[p] = o
		}
		c.pinned = append(c.pinned, rec.Pinned...)
		RemoveStaleRules(rec.Slot)
	}
	if err := writeFile(filepath.Join(c.dir, "cgroup.freeze"), "1"); err != nil {
		return containErr("could not freeze the containment's cgroup: %v", err)
	}
	return nil
}

// attach loads and attaches the two programs. They are attached with the classic
// BPF_PROG_ATTACH, not a link, so they stay attached to the cgroup if this process dies: a killed
// containment fails closed (the device and its route are gone, the gate still refuses).
// Attaching without BPF_F_ALLOW_MULTI replaces whatever a killed containment left, in one step.
func (c *Containment) attach() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return containErr("could not lift the locked-memory limit for BPF: %v", err)
	}
	lo := 1
	if ifc, err := net.InterfaceByName("lo"); err == nil {
		lo = ifc.Index
	}
	gate, err := ebpf.NewProgram(gateSpec(c.route.Index, lo))
	if err != nil {
		return containErr("this kernel refused the containment's egress program (cgroup_skb): %v", err)
	}
	mark, err := ebpf.NewProgram(markSpec(c.route.Mark))
	if err != nil {
		gate.Close()
		return containErr("this kernel refused the containment's socket program (cgroup/sock_create): %v", err)
	}
	c.gate, c.mark = gate, mark
	fd, err := unix.Open(c.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return containErr("could not open the cgroup: %v", err)
	}
	defer unix.Close(fd)
	for _, a := range []struct {
		p  *ebpf.Program
		at ebpf.AttachType
	}{{gate, ebpf.AttachCGroupInetEgress}, {mark, ebpf.AttachCGroupInetSockCreate}} {
		if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: fd, Program: a.p, Attach: a.at}); err != nil {
			return containErr("could not attach the containment's program to its cgroup: %v", err)
		}
	}
	return nil
}

// gateSpec passes a packet only when it leaves through the tunnel device or loopback.
func gateSpec(tunIdx, loIdx int) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name: "whisper_gate",
		Type: ebpf.CGroupSKB, AttachType: ebpf.AttachCGroupInetEgress, License: "MIT",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, skbIfindexOff, asm.Word),
			asm.JEq.Imm(asm.R2, int32(tunIdx), "allow"),
			asm.JEq.Imm(asm.R2, int32(loIdx), "allow"),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
			asm.Return(),
		},
	}
}

// markSpec gives every new IP socket in the cgroup the route's mark.
func markSpec(mark uint32) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name: "whisper_mark",
		Type: ebpf.CGroupSock, AttachType: ebpf.AttachCGroupInetSockCreate, License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm32(asm.R2, int32(mark)),
			asm.StoreMem(asm.R1, bpfSockMarkOff, asm.R2, asm.Word),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	}
}

// moveTree moves the root and every descendant not yet inside, until a pass moves nobody. A
// descendant that exits on the way is not an error; the root exiting is.
func (c *Containment) moveTree() error {
	procs := filepath.Join(c.dir, "cgroup.procs")
	for round := 0; round < settleRounds; round++ {
		parent := parentMap()
		want := append([]int{c.Pid}, descendants(parent, c.Pid)...)
		moved := 0
		for _, p := range want {
			if c.inside(p) {
				continue
			}
			if _, seen := c.origin[p]; !seen {
				if b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "cgroup")); err == nil {
					if cg, ok := cgroupPath(string(b)); ok {
						c.origin[p] = cg
					}
				}
			}
			if err := writeFile(procs, strconv.Itoa(p)); err != nil {
				if errors.Is(err, syscall.ESRCH) {
					if p == c.Pid {
						return &ContainError{Msg: fmt.Sprintf("pid %d exited before it could be contained", p)}
					}
					delete(c.origin, p)
					continue
				}
				return containErr("could not move pid %d into the containment's cgroup: %v", p, err)
			}
			moved++
		}
		if moved == 0 {
			return nil
		}
	}
	return containErr("pid %d's tree kept changing while it was moved (%d rounds), so it was not contained", c.Pid, settleRounds)
}

// inside reports whether p is in the containment's cgroup now.
func (c *Containment) inside(p int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "cgroup"))
	if err != nil {
		return false
	}
	cg, ok := cgroupPath(string(b))
	return ok && filepath.Join(c.root, cg) == c.dir
}

func (c *Containment) members() []int {
	b, err := os.ReadFile(filepath.Join(c.dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if p, err := strconv.Atoi(f); err == nil {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

func (c *Containment) waitFrozen() error {
	deadline := time.Now().Add(freezeWait)
	for {
		b, err := os.ReadFile(filepath.Join(c.dir, "cgroup.events"))
		if err == nil && strings.Contains(string(b), "frozen 1") {
			return nil
		}
		if time.Now().After(deadline) {
			return containErr("pid %d did not freeze within %s (a task stuck in the kernel?), so it was not contained", c.Pid, freezeWait)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkMembers re-checks privilege for everything that was moved: a descendant can be a setuid
// program or hold a capability the root did not.
func (c *Containment) checkMembers() error {
	c.Members = c.members()
	if len(c.Members) == 0 {
		return &ContainError{Msg: fmt.Sprintf("pid %d exited before it could be contained", c.Pid)}
	}
	for _, p := range c.Members {
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "status"))
		if err != nil {
			continue // gone
		}
		st := parseStatus(string(b))
		if why := st.privileged(); why != "" {
			return containErr("pid %d (%s), in pid %d's tree, cannot be contained because %s; nothing was changed", p, st.Name, c.Pid, why)
		}
	}
	return nil
}

// sockets deals with every socket the members made before they were moved. Each is reached
// through pidfd_getfd, a duplicate of the member's own descriptor, and the duplicate is closed at
// once. A socket shared by several members is handled once.
func (c *Containment) sockets() error {
	seen := map[uint64]bool{}
	var rep SocketReport
	type todo struct {
		pid, fd int
		ino     uint64
	}
	var refuse []string
	var work []todo
	for _, p := range c.Members {
		dir := filepath.Join(procRoot, strconv.Itoa(p), "fd")
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			target, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			fd, ferr := strconv.Atoi(e.Name())
			if err != nil || ferr != nil || seen[ino] {
				continue
			}
			seen[ino] = true
			work = append(work, todo{p, fd, ino})
		}
	}
	type decided struct {
		todo
		dup    int
		action sockAction
		was    string
	}
	var plan []decided
	defer func() {
		for _, d := range plan {
			unix.Close(d.dup)
		}
	}()
	for _, w := range work {
		dup, err := getfd(w.pid, w.fd)
		if err != nil {
			if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EBADF) {
				continue // the member exited, or closed it: nothing left to contain
			}
			if errors.Is(err, unix.ENOSYS) {
				return containErr("this kernel has no pidfd_getfd (Linux 5.6+), so the sockets pid %d opened before "+
					"containment could not be reached; it was not contained", c.Pid)
			}
			return containErr("could not reach pid %d's socket (fd %d): %v; it was not contained", w.pid, w.fd, err)
		}
		fam, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_DOMAIN)
		listening, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		local, peer, connected := sockAddrs(dup)
		a := classifySocket(fam, local, peer, connected, listening == 1)
		if a == sockRefuse {
			refuse = append(refuse, fmt.Sprintf("pid %d fd %d: %s", w.pid, w.fd, familyName(fam)))
		}
		was, _ := unix.GetsockoptString(dup, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		plan = append(plan, decided{w, dup, a, was})
	}
	if len(refuse) > 0 {
		return containErr("pid %d holds socket%s no route reaches (%s), which a containment cannot close off; "+
			"nothing was changed. `sudo whisper run --enforce` is the form that covers every socket family",
			c.Pid, plural(len(refuse)), strings.Join(refuse, "; "))
	}
	// Decided for all before acting on any, so a refusal above changed nothing.
	for _, d := range plan {
		switch d.action {
		case sockKeep:
			rep.Kept++
			continue
		}
		if err := unix.SetsockoptString(d.dup, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, c.route.Name); err != nil {
			return containErr("could not pin pid %d's socket (fd %d) to the tunnel: %v; it was not contained", d.pid, d.fd, err)
		}
		if got, err := unix.GetsockoptString(d.dup, unix.SOL_SOCKET, unix.SO_BINDTODEVICE); err != nil || got != c.route.Name {
			return containErr("pid %d's socket (fd %d) did not stay pinned to the tunnel; it was not contained", d.pid, d.fd)
		}
		if d.action == sockCut {
			_ = unix.Shutdown(d.dup, unix.SHUT_RDWR)
			rep.Cut++
			continue
		}
		rep.Pinned++
		c.pinned = append(c.pinned, pinnedSock{Pid: d.pid, Fd: d.fd, Ino: d.ino, Was: d.was})
	}
	c.Sockets = rep
	return nil
}

// getfd duplicates pid's descriptor fd into this process.
func getfd(pid, fd int) (int, error) {
	pfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	return unix.PidfdGetfd(pfd, fd, 0)
}

// sockAddrs returns a socket's local and peer addresses, unmapped, and whether it has a peer.
func sockAddrs(fd int) (local, peer netip.Addr, connected bool) {
	if sa, err := unix.Getsockname(fd); err == nil {
		local = saAddr(sa)
	}
	if sa, err := unix.Getpeername(fd); err == nil {
		peer = saAddr(sa)
		connected = true
	}
	return local, peer, connected
}

func saAddr(sa unix.Sockaddr) netip.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(a.Addr).Unmap()
	}
	return netip.Addr{}
}

// Populated reports whether anything is still in the containment.
func (c *Containment) Populated() bool {
	b, err := os.ReadFile(filepath.Join(c.dir, "cgroup.events"))
	if err != nil {
		return false
	}
	return !strings.Contains(string(b), "populated 0")
}

// Release lets the process go: the pinned sockets are given back their binding, every member is
// moved back to the cgroup it came from (or the hierarchy's root, when that one is gone), the
// programs are detached and the cgroup removed. The tunnel itself is the caller's to stop.
func (c *Containment) Release() []string {
	return c.undo()
}

// undo is Release, and also what a failed Contain runs. It returns a note per thing it could
// not put back.
func (c *Containment) undo() []string {
	var notes []string
	_ = writeFile(filepath.Join(c.dir, "cgroup.freeze"), "1") // nobody forks while they are moved back
	for _, s := range c.pinned {
		if err := restorePin(s); err != nil {
			notes = append(notes, err.Error())
		}
	}
	fallback := c.origin[c.Pid]
	for round := 0; round < settleRounds; round++ {
		ms := c.members()
		if len(ms) == 0 {
			break
		}
		for _, p := range ms {
			o, ok := c.origin[p]
			if !ok {
				o = fallback
			}
			if err := c.moveOut(p, o); err != nil {
				notes = append(notes, err.Error())
			}
		}
	}
	_ = writeFile(filepath.Join(c.dir, "cgroup.freeze"), "0")
	c.detach()
	if err := os.Remove(c.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		notes = append(notes, fmt.Sprintf("the cgroup %s could not be removed: %v", c.dir, err))
	}
	_ = os.Remove(filepath.Dir(c.dir)) // only succeeds when no other containment lives there
	_ = os.Remove(c.statePath)
	return notes
}

// moveOut moves p to origin, or to the hierarchy's root when origin is gone or refuses it (a
// systemd scope removes itself once it is empty).
func (c *Containment) moveOut(p int, origin string) error {
	if origin != "" {
		dst := filepath.Join(c.root, filepath.Clean("/"+origin), "cgroup.procs")
		if err := writeFile(dst, strconv.Itoa(p)); err == nil || errors.Is(err, syscall.ESRCH) {
			return nil
		}
	}
	if err := writeFile(filepath.Join(c.root, "cgroup.procs"), strconv.Itoa(p)); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("pid %d could not be moved out of the containment: %v", p, err)
	}
	return nil
}

// detach removes the programs from the cgroup, the ones this process loaded or, for a killed
// containment's, whatever is attached.
func (c *Containment) detach() {
	fd, err := unix.Open(c.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	for _, at := range []ebpf.AttachType{ebpf.AttachCGroupInetEgress, ebpf.AttachCGroupInetSockCreate} {
		res, err := link.QueryPrograms(link.QueryOptions{Target: fd, Attach: at})
		if err != nil {
			continue
		}
		for _, ap := range res.Programs {
			p, err := ebpf.NewProgramFromID(ap.ID)
			if err != nil {
				continue
			}
			_ = link.RawDetachProgram(link.RawDetachProgramOptions{Target: fd, Program: p, Attach: at})
			p.Close()
		}
	}
	if c.gate != nil {
		c.gate.Close()
	}
	if c.mark != nil {
		c.mark.Close()
	}
}

// restorePin gives a pinned socket its device binding back, if the descriptor still names it.
func restorePin(s pinnedSock) error {
	dup, err := getfd(s.Pid, s.Fd)
	if err != nil {
		return nil // the process or the socket is gone
	}
	defer unix.Close(dup)
	var st unix.Stat_t
	if unix.Fstat(dup, &st) != nil || st.Ino != s.Ino {
		return nil // the descriptor now names another socket, which was never pinned
	}
	if err := unix.SetsockoptString(dup, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, s.Was); err != nil {
		return fmt.Errorf("pid %d's socket (fd %d) stays pinned to the removed tunnel: %v", s.Pid, s.Fd, err)
	}
	return nil
}

func (c *Containment) writeRecord() {
	rec := containRecord{Pid: c.Pid, Slot: c.route.Slot, Origin: c.origin, Pinned: c.pinned}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := secureDir(containState); err != nil {
		return
	}
	f, err := os.OpenFile(c.statePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(b)
	_ = f.Close()
}

func readRecord(path string) (containRecord, error) {
	var rec containRecord
	if err := secureDir(filepath.Dir(path)); err != nil {
		return rec, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return rec, err
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Uid != 0 || st.Mode&0o022 != 0 {
		return rec, errors.New("the containment record is not root's own")
	}
	err = json.NewDecoder(f).Decode(&rec)
	return rec, err
}

// secureDir makes dir (0700, root's) if it is missing and refuses one anybody else could write.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
		return fmt.Errorf("%s is not a directory only root can write", dir)
	}
	return nil
}

// ReleaseStale releases a containment whose `whisper contain` was killed, found by a pid that
// is still inside it (or, when pid is 0, by the agent's /128). It returns what it moved.
func ReleaseStale(pid int, self netip.Addr) ([]int, []string, error) {
	if geteuid() != 0 {
		return nil, nil, containErr("releasing a containment needs root: run it as `sudo whisper contain --release <pid>`")
	}
	mi, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return nil, nil, containErr("cannot read %s: %v", mountinfoPath, err)
	}
	root, err := cgroup2Mount(string(mi))
	if err != nil {
		return nil, nil, containErr("this kernel has no cgroup v2 hierarchy, so nothing here was contained")
	}
	name := ""
	if pid > 0 {
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			return nil, nil, &ContainError{Msg: fmt.Sprintf("there is no process with pid %d", pid)}
		}
		cg, _ := cgroupPath(string(b))
		dir, leaf := filepath.Split(strings.TrimSuffix(cg, "/"))
		if filepath.Clean(dir) != "/"+ContainParent || leaf == "" {
			return nil, nil, containErr("pid %d is not contained (its cgroup is %s)", pid, cg)
		}
		name = leaf
	} else {
		name = containCgroupName(self)
	}
	c := &Containment{Pid: pid, root: root, origin: map[int]string{}, dir: filepath.Join(root, ContainParent, name),
		statePath: filepath.Join(containState, name+".json")}
	if _, err := os.Stat(c.dir); err != nil {
		return nil, nil, containErr("there is no containment %s on this host", name)
	}
	if rec, err := readRecord(c.statePath); err == nil {
		c.origin, c.pinned = rec.Origin, rec.Pinned
		if c.Pid == 0 {
			c.Pid = rec.Pid
		}
		defer RemoveStaleRules(rec.Slot)
	}
	moved := c.members()
	notes := c.undo()
	return moved, notes, nil
}

// writeFile writes s to a cgroup or proc file, returning the kernel's own error.
func writeFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(s)
	cerr := f.Close()
	if werr != nil {
		var pe *os.PathError
		if errors.As(werr, &pe) {
			return pe.Err
		}
		return werr
	}
	return cerr
}
