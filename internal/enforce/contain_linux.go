// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"encoding/binary"
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

// contain_linux.go is the mechanism behind contain.go: the cgroup, its two BPF programs, the gate
// on the root cgroup, the move, and the sockets made before it. Everything here needs root
// (CAP_SYS_ADMIN for the cgroups and the BPF attachments, CAP_NET_ADMIN for SO_MARK and
// SO_BINDTOIFINDEX, CAP_SYS_PTRACE for pidfd_getfd and kcmp); Contain checks for root first and
// says so.

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

// kcmpFiles is KCMP_FILES from linux/kcmp.h: whether two tasks share one descriptor table.
const kcmpFiles = 2

// Containment is a running containment.
type Containment struct {
	Pid     int
	Members []int
	Sockets SocketReport

	self      netip.Addr // the agent's /128
	dir       string     // the cgroup's directory
	root      string     // the v2 hierarchy's mount point
	origin    map[int]string
	gate      *ebpf.Program
	mark      *ebpf.Program
	adopted   []uint32     // generations of killed containments of this agent whose gates it took over
	isolated  map[int]bool // members in a loopback-only network namespace: nothing of theirs leaves the host
	touched   []touchedSock
	route     HostRoute
	statePath string
	notes     []string // what detach could not undo
	// releasedFrom is who was in the containment when it was released, for Finish.
	releasedFrom []int
	// prev is the record of a killed containment of this agent that this one is taking over, and how
	// many sockets it had touched: a takeover that fails puts it back.
	prev        *containRecord
	prevTouched int
	// moved is every process this containment wrote into its cgroup, with its start time (so a pid
	// used again is not taken for it): a takeover that fails moves out exactly these.
	moved map[int]string
	// clearing is every mark release takes off (this containment's, and that of each killed one it
	// took over), kept for Finish.
	clearing map[uint32]bool
}

// touchedSock is a socket the containment marked (and pinned, when Bound says so) and left
// working: on release its mark and its binding are put back as they were. It is found again by
// pid, thread, descriptor and inode, never kept open, so the program closing it really closes it.
// Was is how a release before marks recorded a pin (the device's name); a record of that age is
// still given back.
type touchedSock struct {
	Pid, Tid, Fd int
	Ino          uint64
	Was          string `json:",omitempty"`
	WasIndex     int
	WasMark      uint32
	Bound        bool
	Marked       bool
}

// containRecord is what a containment leaves under /run/whisper/contain, so that one which was
// killed can still be released by `whisper contain --release`. Gen, Mark and Index are absent in a
// record from before marks were a containment's own.
type containRecord struct {
	Pid    int            `json:"pid"`
	Slot   int            `json:"slot"`
	Gen    uint32         `json:"gen,omitempty"`
	Mark   uint32         `json:"mark,omitempty"`
	Index  int            `json:"index,omitempty"`
	Adopt  []uint32       `json:"adopted,omitempty"`
	Origin map[int]string `json:"origin"`
	Pinned []touchedSock  `json:"pinned"`
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
	if exited(pid) {
		return containErr("pid %d has exited and is only waiting for its parent to reap it; there is nothing to contain", pid)
	}
	if leaderExited(pid) {
		return containErr("pid %d's main thread has exited while its other threads run on; such a process cannot be moved "+
			"into a cgroup whole, so it was not contained", pid)
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
	if !inInitialNamespace("pid", initPidNsIno) {
		return containErr("this command runs in a pid namespace of its own, so it cannot see every process that could " +
			"share the target's descriptors or follow its tree. Run `sudo whisper contain` from the host")
	}
	if !inInitialNamespace("cgroup", initCgroupNsIno) {
		return containErr("this command runs in a cgroup namespace of its own, so the root it sees is not the host's and " +
			"its gate there would not see every socket. Run `sudo whisper contain` from the host")
	}
	if !sameNamespace(strconv.Itoa(pid), "thread-self", "net") {
		return containErr("pid %d is in another network namespace (a container's, most likely): its sockets never meet "+
			"this host's routes or its tunnel. Run `sudo whisper run --enforce` inside that namespace instead", pid)
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		cg, _ := os.ReadFile(filepath.Join(procRoot, "cgroups"))
		if c := v1SocketClassifier(unix.ByteSliceToString(u.Release[:]), string(cg)); c != "" {
			return containErr("this kernel (before 5.15) has the cgroup v1 %s controller mounted, and once anything uses it "+
				"the kernel stops telling cgroup v2 programs which cgroup a socket belongs to, so the containment would "+
				"see none of the process's sockets; it was not contained", c)
		}
	}
	// What is mounted cannot show a controller used and unmounted earlier in the boot, so the mechanism
	// itself is tested too.
	root, _ := cgroup2Mount(string(mi))
	return attributionProbe(root)
}

// v1SocketClassifier names a cgroup v1 controller that, on a kernel before 5.15, turns off the
// cgroup v2 attribution of sockets the containment's programs rely on, for every socket on the host,
// once anything uses it (Mullvad's split tunnelling does, and so does a container runtime that joins
// every mounted v1 controller). Mounted, it can be used at any moment, after a containment began as
// well, so it is refused. It returns "" when there is none, or when the kernel keeps both (5.15+).
func v1SocketClassifier(release, cgroups string) string {
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil || major > 5 || (major == 5 && minor >= 15) {
		return ""
	}
	for _, line := range strings.Split(cgroups, "\n") {
		f := strings.Fields(line)
		// subsys_name hierarchy num_cgroups enabled: a hierarchy other than 0 is a mounted v1 one.
		if len(f) >= 4 && (f[0] == "net_cls" || f[0] == "net_prio") && f[1] != "0" && f[3] == "1" {
			return f[0]
		}
	}
	return ""
}

// The initial pid and cgroup namespaces' inodes are fixed by the kernel (PROC_PID_INIT_INO and
// PROC_CGROUP_INIT_INO in include/linux/proc_ns.h), so a command in a container that has its own
// procfs, where /proc/1 is the container's init, is still told apart. Variables only for tests.
var (
	initPidNsIno    uint64 = 0xEFFFFFFC
	initCgroupNsIno uint64 = 0xEFFFFFFB
)

// inInitialNamespace reports whether the calling thread is in the host's own namespace of kind.
func inInitialNamespace(kind string, ino uint64) bool {
	var st unix.Stat_t
	return unix.Stat(filepath.Join(procRoot, "thread-self", "ns", kind), &st) == nil && st.Ino == ino
}

// exited reports whether pid has exited entirely (a zombie, or dead) and is only waiting to be reaped.
func exited(pid int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) || (b[i+2] != 'Z' && b[i+2] != 'X') {
		return false
	}
	return len(threadsOf(pid)) <= 1
}

// leaderExited reports whether pid's main thread has exited while other threads of it still run.
func leaderExited(pid int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) || b[i+2] != 'Z' {
		return false
	}
	return len(threadsOf(pid)) > 1
}

// sameNamespace reports whether two tasks (pids, or "thread-self") are in the same namespace of kind.
// This command's side is the calling thread's, which is where its sockets are made: a namespace
// belongs to a thread, and a thread of this process may have entered another one. A namespace that
// cannot be read is not the same.
func sameNamespace(a, b, kind string) bool {
	var sa, sb unix.Stat_t
	if unix.Stat(filepath.Join(procRoot, a, "ns", kind), &sa) != nil || unix.Stat(filepath.Join(procRoot, b, "ns", kind), &sb) != nil {
		return false
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
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
	if route.Gen == 0 || route.Mark != markFor(route.Gen) || route.Index <= 0 || route.gate == nil {
		return nil, containErr("the containment's tunnel carries no mark of its own (generation %d, mark %#x), so pid %d "+
			"was not contained", route.Gen, route.Mark, pid)
	}
	mi, _ := os.ReadFile(mountinfoPath)
	root, _ := cgroup2Mount(string(mi))
	c := &Containment{Pid: pid, self: self, root: root, route: route, origin: map[int]string{}, isolated: map[int]bool{},
		dir: filepath.Join(root, ContainParent, containCgroupName(self))}
	c.statePath = filepath.Join(containState, containCgroupName(self)+".json")
	if err := c.makeCgroup(); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if ok {
			return
		}
		// A takeover that fails leaves the killed containment's members held, as they were: releasing
		// them would let a process that was cut off out onto the host's network.
		if c.prev != nil {
			c.undoTakeover()
			return
		}
		c.undo(true)
	}()
	// The record goes down before anything is attached, so a killed command never leaves a program
	// that `whisper contain --release` cannot find again.
	if err := c.writeRecord(); err != nil {
		return nil, err
	}
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
	if err := c.writeRecord(); err != nil { // the origins, before anything of theirs is touched
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		err := c.sockets()
		if err == nil {
			break
		}
		// Descriptors in flight on a unix socket are often a passing moment in a busy program: it is let
		// run until they have been received, frozen again, and swept again from the start.
		// Not in a takeover: letting the tree run would run the killed containment's members under this
		// attempt's programs, and a child they fork then is one more to tell apart on a failure.
		var fl *inFlightError
		if !errors.As(err, &fl) || attempt >= inFlightRetries || c.prev != nil {
			return nil, err
		}
		logf("whisper: pid %d has descriptors in flight on a unix socket; letting it run until they are received, "+
			"then sweeping again", c.Pid)
		if err := c.waitInFlight(fl.socks); err != nil {
			return nil, err
		}
		// As the first pass: move, wait for frozen, and once more while frozen proves the tree complete.
		if err := c.moveTree(); err != nil {
			return nil, err
		}
		if err := c.waitFrozen(); err != nil {
			return nil, err
		}
		if err := c.moveTree(); err != nil {
			return nil, err
		}
		if err := c.checkMembers(); err != nil {
			return nil, err
		}
		if err := c.writeRecord(); err != nil {
			return nil, err
		}
	}
	if err := c.writeRecord(); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(c.dir, "cgroup.freeze"), "0"); err != nil {
		return nil, containErr("could not thaw the contained process: %v", err)
	}
	ok = true
	if note := ptraceNote(); note != "" {
		logf("whisper: %s", note)
	}
	return c, nil
}

func (c *Containment) makeCgroup() error {
	if err := mkdirUnder(c.dir); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(c.dir, "cgroup.freeze")); err != nil {
		return containErr("this kernel's cgroup v2 has no freezer (cgroup.freeze, Linux 5.2+), which containment " +
			"needs so that nothing in the process can fork or open a socket while it is moved")
	}
	// A killed containment of this agent left this cgroup, with whoever was in it still cut off.
	// Its record says where they came from; they are taken over and released with this one.
	// Its gate on the root cgroup stays, adopted: it holds sockets of that containment this one may
	// never see, and it goes when this one is released.
	rec, err := readRecord(c.statePath)
	switch {
	case err == nil:
		prev := rec
		prev.Origin = make(map[int]string, len(rec.Origin))
		for p, o := range rec.Origin {
			prev.Origin[p] = o
		}
		prev.Pinned = append([]touchedSock(nil), rec.Pinned...)
		prev.Adopt = append([]uint32(nil), rec.Adopt...)
		c.prev, c.prevTouched = &prev, len(rec.Pinned)
		for p, o := range rec.Origin {
			c.origin[p] = o
		}
		c.touched = append(c.touched, rec.Pinned...)
		c.adopted = append(c.adopted, rec.Adopt...)
		if rec.Gen != 0 {
			c.adopted = append(c.adopted, rec.Gen)
		}
		// Its address rules are already gone (CreateHostDevice cleared the agent's on every slot), and
		// the slot is usually this containment's own now, whose address rules must stay.
		RemoveStaleRules(rec.Slot, rec.Mark, netip.Addr{})
	case !errors.Is(err, os.ErrNotExist):
		return containErr("a killed containment of this agent left a record that cannot be read (%v), so what it changed "+
			"cannot be given back; nothing was changed. Remove %s once you have released what it held", err, c.statePath)
	}
	if err := writeFile(filepath.Join(c.dir, "cgroup.freeze"), "1"); err != nil {
		return containErr("could not freeze the containment's cgroup: %v", err)
	}
	return nil
}

// mkdirUnder makes dir and its parent cgroup (ContainParent). Another containment's release removes
// that parent when it leaves it empty, which can land between the two: then both are made again.
func mkdirUnder(dir string) error {
	parent := filepath.Dir(dir)
	for try := 0; ; try++ {
		if err := os.Mkdir(parent, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return containErr("could not create the cgroup %s: %v", parent, err)
		}
		err := os.Mkdir(dir, 0o755)
		if err == nil || errors.Is(err, os.ErrExist) {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) || try >= 8 {
			return containErr("could not create the cgroup %s: %v", dir, err)
		}
	}
}

// attach loads and attaches the cgroup's programs, and names the cgroup to the tunnel's gate on
// the root cgroup (hostroute_linux.go). They are attached with the classic BPF_PROG_ATTACH, not a
// link, so they stay attached if this process dies: a killed containment fails closed (the device
// and its route are gone, the gates still refuse). Attaching without BPF_F_ALLOW_MULTI replaces
// whatever a killed containment left on the cgroup, in one step.
//
// The root gate is what holds a socket made before the move: it sits in its old cgroup, where this
// cgroup's gate never sees it, and pinning it is not enough (a datagram socket's
// connect(AF_UNSPEC) drops its device binding without privilege, and IP_PKTINFO overrides one for
// IPv4). Marked and adopted by the sweep, it is held wherever it is and whatever is done to it.
func (c *Containment) attach() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return containErr("could not lift the locked-memory limit for BPF: %v", err)
	}
	id, err := cgroupID(c.dir)
	if err != nil {
		return containErr("could not read the containment cgroup's id: %v", err)
	}
	if err := c.route.gate.setCgroup(id); err != nil {
		return containErr("could not name the containment's cgroup to its gate: %v", err)
	}
	lo := loIndex()
	gate, err := ebpf.NewProgram(gateSpec(c.route.Index, lo))
	if err != nil {
		return containErr("this kernel refused the containment's egress program (cgroup_skb): %v", err)
	}
	c.gate = gate
	mark, err := ebpf.NewProgram(markSpec(c.route.Mark))
	if err != nil {
		return containErr("this kernel refused the containment's socket program (cgroup/sock_create): %v", err)
	}
	c.mark = mark
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

func loIndex() int {
	if ifc, err := net.InterfaceByName("lo"); err == nil {
		return ifc.Index
	}
	return 1
}

// cgroupID is a cgroup's id, the one a BPF program sees: the 8-byte handle cgroupfs gives its
// directory.
func cgroupID(dir string) (uint64, error) {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		return 0, err
	}
	b := h.Bytes()
	if len(b) != 8 {
		return 0, fmt.Errorf("a cgroup handle of %d bytes", len(b))
	}
	return binary.NativeEndian.Uint64(b), nil
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
			// An exited child its parent has not reaped yet cannot be moved (the kernel skips it) and has
			// nothing left to contain.
			if c.inside(p) || exited(p) {
				continue
			}
			if other := c.heldElsewhere(p); other != "" {
				return containErr("pid %d, in pid %d's tree, is held by another agent's containment (%s): moving it here "+
					"would make it speak as this agent; nothing was changed", p, c.Pid, other)
			}
			if _, seen := c.origin[p]; !seen {
				if b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "cgroup")); err == nil {
					if cg, ok := cgroupPath(string(b)); ok {
						c.origin[p] = cg
					}
				}
			}
			started := startTime(p)
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
			if c.moved == nil {
				c.moved = map[int]string{}
			}
			c.moved[p] = started
			moved++
		}
		if moved == 0 {
			return nil
		}
	}
	return containErr("pid %d's tree kept changing while it was moved (%d rounds), so it was not contained", c.Pid, settleRounds)
}

// heldElsewhere names the cgroup of another containment p is in, or "".
func (c *Containment) heldElsewhere(p int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "cgroup"))
	if err != nil {
		return ""
	}
	cg, ok := cgroupPath(string(b))
	if !ok {
		return ""
	}
	if rest, under := strings.CutPrefix(cg, "/"+ContainParent+"/"); under && filepath.Join(c.root, cg) != c.dir &&
		!strings.HasPrefix(rest, "probe-") {
		return cg
	}
	return ""
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
		if leaderExited(p) {
			return containErr("pid %d (%s), in pid %d's tree, has a main thread that exited while its other threads run "+
				"on, which cannot be moved whole; nothing was changed", p, st.Name, c.Pid)
		}
		if !sameNamespace(strconv.Itoa(p), "thread-self", "net") {
			// A sandboxed child (a browser's renderer) in a namespace that holds only loopback has no
			// way off the host at all, and nothing of it needs containing.
			if loopbackOnly(p) {
				c.isolated[p] = true
				continue
			}
			return containErr("pid %d (%s), in pid %d's tree, is in another network namespace that reaches past loopback, "+
				"where this host's routes and tunnel do not reach; nothing was changed", p, st.Name, c.Pid)
		}
	}
	return nil
}

// loopbackOnly reports whether pid's network namespace has no interface but loopback.
func loopbackOnly(pid int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "net", "dev"))
	if err != nil {
		return false
	}
	ifs := 0
	for _, line := range strings.Split(string(b), "\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.Contains(name, "|") || name == "" {
			continue // the two header lines
		}
		if name != "lo" {
			return false
		}
		ifs++
	}
	return ifs > 0
}

// sockRef is one descriptor in a member's descriptor table: tid names the table (the process's
// own when tid == pid).
type sockRef struct {
	pid, tid, fd int
	ino          uint64
}

// tableSockets lists the sockets and io_uring instances in every descriptor table the processes
// hold: the process's own, and any a thread keeps for itself (unshare(CLONE_FILES), or the threads
// of a leader that has exited, whose own /proc/<pid>/fd shows nothing). A socket in several tables
// is listed once, where it is first found, the process's own table first. It also names each
// process that has an io_uring instance mapped without a descriptor for it in any of its tables.
func tableSockets(pids []int) (socks, rings []sockRef, ringless []int) {
	seen := map[uint64]bool{}
	for _, p := range pids {
		hasRing := false
		for _, tid := range tablesOf(p) {
			dir := filepath.Join(procRoot, strconv.Itoa(p), "task", strconv.Itoa(tid), "fd")
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue // the thread is gone, or a leader that has exited holds no table
			}
			for _, e := range ents {
				fd, ferr := strconv.Atoi(e.Name())
				target, err := os.Readlink(filepath.Join(dir, e.Name()))
				if err != nil || ferr != nil {
					continue
				}
				if target == "anon_inode:[io_uring]" {
					rings = append(rings, sockRef{pid: p, tid: tid, fd: fd})
					hasRing = true
					continue
				}
				if !strings.HasPrefix(target, "socket:[") {
					continue
				}
				ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
				if err != nil || seen[ino] {
					continue
				}
				seen[ino] = true
				socks = append(socks, sockRef{p, tid, fd, ino})
			}
		}
		if !hasRing && mapsIoUring(p) {
			ringless = append(ringless, p)
		}
	}
	return socks, rings, ringless
}

// threadGone reports whether thread tid of pid has gone (a fatal signal reaches a frozen thread).
func threadGone(pid, tid int) bool {
	_, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "task", strconv.Itoa(tid)))
	return err != nil
}

// processGone reports whether pid has no thread left.
func processGone(pid int) bool {
	ents, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), "task"))
	return err != nil || len(ents) == 0
}

// outsideSharers names every process outside the tree that uses a descriptor table of one of the
// members (one made with CLONE_FILES and left outside, a child reparented away). It is not frozen,
// so after the thaw it could put a socket of its own, made in its own cgroup and so unmarked and
// ungated, into the table the member uses. A kernel without kcmp answers nothing here.
func outsideSharers(members []int) []string {
	in := map[int]bool{}
	var tables [][2]int // pid, tid of a thread in each member table
	for _, p := range members {
		in[p] = true
		for _, tid := range tablesOf(p) {
			tables = append(tables, [2]int{p, tid})
		}
	}
	var out []string
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	for _, e := range ents {
		p, err := strconv.Atoi(e.Name())
		if err != nil || in[p] || p == self {
			continue
		}
	threads:
		for _, tid := range threadsOf(p) {
			for _, mt := range tables {
				r, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(mt[1]), uintptr(tid), kcmpFiles, 0, 0, 0)
				switch {
				case e == 0 && r == 0:
					out = append(out, fmt.Sprintf("pid %d, outside the containment, shares pid %d's descriptor table", p, mt[0]))
					break threads
				case e != 0 && e != unix.ESRCH:
					out = append(out, fmt.Sprintf("whether pid %d, outside the containment, shares pid %d's descriptor table "+
						"cannot be checked (%v)", p, mt[0], e))
					break threads
				}
			}
		}
	}
	return out
}

// tablesOf names one thread in each descriptor table pid's threads use, the process's own first.
// A thread whose table cannot be listed (a leader that has exited holds none) names nothing.
func tablesOf(p int) []int {
	var tables []int
	for _, tid := range threadsOf(p) {
		if _, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(p), "task", strconv.Itoa(tid), "fd")); err != nil {
			continue
		}
		if !sharesATable(tid, tables) {
			tables = append(tables, tid)
		}
	}
	return tables
}

// threadsOf lists pid's threads, the leader first.
func threadsOf(pid int) []int {
	ents, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), "task"))
	if err != nil {
		return nil
	}
	out := []int{}
	for _, e := range ents {
		if t, err := strconv.Atoi(e.Name()); err == nil && t != pid {
			out = append(out, t)
		}
	}
	sort.Ints(out)
	return append([]int{pid}, out...)
}

// sharesATable reports whether tid uses the same descriptor table as one of tables. A kernel
// without kcmp, or a thread that is gone, answers no, and the table is then simply listed: a
// shared table read twice only finds sockets already seen.
func sharesATable(tid int, tables []int) bool {
	for _, t := range tables {
		if r, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(t), uintptr(tid), kcmpFiles, 0, 0, 0); e == 0 && r == 0 {
			return true
		}
	}
	return false
}

// mapsIoUring reports whether pid has an io_uring instance mapped.
func mapsIoUring(pid int) bool {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasSuffix(sc.Text(), "[io_uring]") {
			return true
		}
	}
	return false
}

// fdinfo reads /proc/<pid>/task/<tid>/fdinfo/<fd>.
func fdinfo(r sockRef) (string, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(r.pid), "task", strconv.Itoa(r.tid), "fdinfo", strconv.Itoa(r.fd)))
	return string(b), err
}

// scmInFlight reads how many descriptors are in flight in a unix socket's receive queue, from its
// fdinfo's "scm_fds:" line (Linux 5.8+). ok is false when the line is not there.
func scmInFlight(info string) (n int, ok bool) {
	for _, line := range strings.Split(info, "\n") {
		if v, found := strings.CutPrefix(line, "scm_fds:"); found {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			return n, err == nil
		}
	}
	return 0, false
}

// ringHeldFiles counts the files an io_uring instance holds as fixed files or direct descriptors,
// from its fdinfo: "UserFiles:\tN", then one line per slot, "%5u: <name>" or "%5u: <none>". The name
// is the file's bare dentry name ("UDPv6" for a socket, "hostname" for a file), so a socket cannot
// be told from a file by it. ok is false when the slots are not all listed: the kernel lists them
// only when it gets the ring's lock at once, and a count it did not show is not a count of none.
func ringHeldFiles(info string) (held int, ok bool) {
	want, listed, in := -1, 0, false
	for _, line := range strings.Split(info, "\n") {
		if v, found := strings.CutPrefix(line, "UserFiles:"); found {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return 0, false
			}
			want, in = n, true
			continue
		}
		if !in {
			continue
		}
		idx, name, found := strings.Cut(strings.TrimSpace(line), ": ")
		if _, err := strconv.Atoi(idx); !found || err != nil {
			break
		}
		listed++
		if name != "<none>" {
			held++
		}
	}
	if want < 0 {
		return 0, true // no registered-file table at all
	}
	return held, listed >= want
}

// sockets deals with every socket the members made before they were moved. Each is reached
// through pidfd_getfd, a duplicate of the member's own descriptor, which is checked to be the very
// socket the table showed, and the duplicate is closed at once. A socket shared by several
// members, or several tables, is handled once.
//
// Every IP socket is given the containment's mark, so the gate on the root cgroup holds it from
// then on wherever it is: its packets leave through the tunnel or loopback, or not at all.
// Loopback sockets keep working (kept); listeners and unconnected sockets are also pinned to the
// tunnel by index, and go on working through it (pinned); connections to anywhere else are pinned
// and shut down (cut). Anything the containment cannot reach or cannot judge refuses it, and is
// decided for all before anything is changed: a family no route reaches, descriptors in flight
// on a unix socket, a socket held by an io_uring instance, or by a thread's own table this kernel
// gives no way into.
func (c *Containment) sockets() error {
	var rep SocketReport
	swept := c.Members
	hostNet, err := nsInode()
	if err != nil {
		return containErr("cannot read this host's network namespace (%v), so the sockets of pid %d cannot be told "+
			"apart from a sandbox's; it was not contained", err, c.Pid)
	}
	// The namespaces of members that hold nothing but loopback: a socket made in one of them has no
	// way off the host. A socket made in any other namespace (a container's, with its own route out)
	// is refused.
	sealedNets := map[uint64]bool{}
	for p := range c.isolated {
		var st unix.Stat_t
		if unix.Stat(filepath.Join(procRoot, strconv.Itoa(p), "ns", "net"), &st) == nil {
			sealedNets[st.Ino] = true
		}
	}
	socks, rings, ringless := tableSockets(swept)
	hostOwn := map[netip.Addr]bool{}
	if as, err := hostAddrs(); err == nil {
		for _, a := range as {
			if !a.IsLoopback() && a != c.self && a != CLATv4 {
				hostOwn[a] = true
			}
		}
	}
	var refuse []string
	var inFlight []sockRef // the unix sockets refused for descriptors in flight, and only for that
	if _, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(c.Pid), uintptr(c.Pid), kcmpFiles, 0, 0, 0); e != 0 {
		return containErr("kcmp is not available here (%v: CONFIG_KCMP off, or a security module denies it), so whether a "+
			"process outside pid %d's tree shares its descriptor table cannot be checked; it was not contained", e, c.Pid)
	}
	refuse = append(refuse, outsideSharers(swept)...)
	for _, p := range ringless {
		refuse = append(refuse, fmt.Sprintf("pid %d has an io_uring instance mapped that it holds no descriptor for, so what "+
			"it holds cannot be read", p))
	}
	for _, r := range rings {
		info, err := fdinfo(r)
		if err != nil {
			continue // closed, or the process exited
		}
		if n, ok := ringHeldFiles(info); !ok {
			refuse = append(refuse, fmt.Sprintf("pid %d fd %d: an io_uring instance whose registered files could not be "+
				"read", r.pid, r.fd))
		} else if n > 0 {
			refuse = append(refuse, fmt.Sprintf("pid %d fd %d: an io_uring instance with %d registered file%s, outside every "+
				"descriptor table, and io_uring does not say which are sockets", r.pid, r.fd, n, plural(n)))
		}
	}
	type decided struct {
		sockRef
		dup       int
		ip        bool
		listening bool
		action    sockAction
	}
	var plan []decided
	defer func() {
		for _, d := range plan {
			unix.Close(d.dup)
		}
	}()
	for _, w := range socks {
		dup, err := getfdAt(w.pid, w.tid, w.fd)
		if err != nil {
			if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EBADF) {
				// The tree is frozen, so a descriptor it listed cannot go away by its own doing: only
				// a process that has gone entirely may answer so.
				if processGone(w.pid) || (w.tid != w.pid && threadGone(w.pid, w.tid)) {
					continue
				}
				refuse = append(refuse, fmt.Sprintf("pid %d fd %d: listed while frozen, then not there (%v), so something "+
					"outside the containment changes its descriptor table", w.pid, w.fd, err))
				continue
			}
			if errors.Is(err, unix.ENOSYS) {
				return containErr("this kernel has no pidfd_getfd (Linux 5.6+), so the sockets pid %d opened before "+
					"containment could not be reached; it was not contained", c.Pid)
			}
			if w.tid != w.pid && errors.Is(err, unix.EINVAL) {
				refuse = append(refuse, fmt.Sprintf("pid %d thread %d keeps a descriptor table of its own holding a socket "+
					"(fd %d), which this kernel gives no way into (that needs Linux 6.9)", w.pid, w.tid, w.fd))
				continue
			}
			if errors.Is(err, unix.EPERM) && readTrim(yamaScopePath) == "3" {
				return containErr("kernel.yama.ptrace_scope is 3 here, which refuses pidfd_getfd even to root, so the "+
					"sockets pid %d opened before containment cannot be reached; it was not contained", c.Pid)
			}
			return containErr("could not reach pid %d's socket (fd %d): %v; it was not contained", w.pid, w.fd, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(dup, &st); err != nil || st.Ino != w.ino || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			unix.Close(dup)
			return containErr("pid %d's descriptor %d changed while the process was frozen, so something outside the "+
				"containment shares its descriptor table; it was not contained", w.pid, w.fd)
		}
		fam, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_DOMAIN)
		listening, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
		local, peer, connected := sockAddrs(dup)
		a := classifySocket(fam, local, peer, connected, listening == 1)
		ip := fam == afInet || fam == afInet6
		netns, known := socketNetns(dup)
		switch {
		case ip && known && netns != hostNet && sealedNets[netns]:
			a = sockKeep // made in a loopback-only namespace (a sandboxed child's): it never leaves the host
			ip = false
		case ip && known && netns != hostNet:
			refuse = append(refuse, fmt.Sprintf("pid %d fd %d: a socket made in another network namespace that reaches "+
				"past loopback (a container's), where this host's routes and tunnel do not reach", w.pid, w.fd))
		case a == sockCut && hostOwn[peer]:
			a = sockKeep // a connection to this host's own address never leaves it; marked, it stays local
		case a == sockPin && fam != afUnix && synSent(dup):
			a = sockCut // still connecting from the host's address: it can never complete through the tunnel
		}
		switch {
		case a == sockRefuse:
			refuse = append(refuse, fmt.Sprintf("pid %d fd %d: %s", w.pid, w.fd, familyName(fam)))
		case fam == afUnix:
			info, err := fdinfo(w)
			n, ok := scmInFlight(info)
			switch {
			case err != nil:
			case !ok:
				refuse = append(refuse, fmt.Sprintf("pid %d fd %d: a unix socket whose descriptors in flight this kernel "+
					"does not show (that needs Linux 5.8)", w.pid, w.fd))
			case n > 0:
				refuse = append(refuse, fmt.Sprintf("pid %d fd %d: %d descriptor%s in flight on a unix socket, sent and not "+
					"yet received, which nothing can reach until they are (often a passing moment: try again)", w.pid, w.fd, n, plural(n)))
				inFlight = append(inFlight, w)
			}
		}
		plan = append(plan, decided{w, dup, ip, listening == 1, a})
	}
	if len(refuse) > 0 {
		err := containErr("pid %d holds socket%s a containment cannot reach or close off (%s); nothing was changed. "+
			"`sudo whisper run --enforce` is the form that covers every socket", c.Pid, plural(len(refuse)), strings.Join(refuse, "; "))
		if len(inFlight) == len(refuse) {
			return &inFlightError{error: err, socks: inFlight}
		}
		return err
	}
	// Decided for all before acting on any, so a refusal above changed nothing. What it is about to
	// change is in the record first, so a command killed halfway leaves a record that gives back all
	// of it (giving back a socket it never reached changes nothing).
	base := len(c.touched)
	for _, d := range plan {
		if !d.ip {
			continue
		}
		t := touchedSock{Pid: d.pid, Tid: d.tid, Fd: d.fd, Ino: d.ino, Marked: true, Bound: d.action != sockKeep}
		wasMark, _ := unix.GetsockoptInt(d.dup, unix.SOL_SOCKET, unix.SO_MARK)
		t.WasMark = uint32(wasMark)
		t.WasIndex, _ = unix.GetsockoptInt(d.dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX)
		c.touched = append(c.touched, t)
	}
	if err := c.writeRecord(); err != nil {
		return err
	}
	var ended []uint64
	for _, d := range plan {
		if !d.ip {
			rep.Kept++ // unix, netlink, crypto: no way off the host
			continue
		}
		if err := c.route.gate.adopt(d.dup); err != nil {
			return containErr("could not adopt pid %d's socket (fd %d) into the containment: %v; it was not contained", d.pid, d.fd, err)
		}
		if err := unix.SetsockoptInt(d.dup, unix.SOL_SOCKET, unix.SO_MARK, int(c.route.Mark)); err != nil {
			return containErr("could not mark pid %d's socket (fd %d): %v; it was not contained", d.pid, d.fd, err)
		}
		if got, err := unix.GetsockoptInt(d.dup, unix.SOL_SOCKET, unix.SO_MARK); err != nil || uint32(got) != c.route.Mark {
			return containErr("pid %d's socket (fd %d) did not keep the containment's mark; it was not contained", d.pid, d.fd)
		}
		if d.action == sockKeep {
			rep.Kept++
			continue
		}
		if err := bindToDevice(d.dup, c.route.Index, c.route.Name); err != nil {
			return containErr("could not pin pid %d's socket (fd %d) to the tunnel: %v; it was not contained", d.pid, d.fd, err)
		}
		if got, err := unix.GetsockoptInt(d.dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX); err != nil || got != c.route.Index {
			return containErr("pid %d's socket (fd %d) did not stay pinned to the tunnel; it was not contained", d.pid, d.fd)
		}
		if d.listening {
			rep.Cut += c.drainAcceptQueue(d.dup)
		}
		if d.action == sockCut {
			_ = unix.Shutdown(d.dup, unix.SHUT_RDWR)
			ended = append(ended, d.ino) // ended: nothing to give back
			rep.Cut++
			continue
		}
		rep.Pinned++
	}
	if len(ended) > 0 {
		gone := map[uint64]bool{}
		for _, ino := range ended {
			gone[ino] = true
		}
		kept := c.touched[:base]
		for _, t := range c.touched[base:] {
			if !gone[t.Ino] {
				kept = append(kept, t)
			}
		}
		c.touched = kept
	}
	c.Sockets = rep
	return nil
}

// drainAcceptQueue ends every connection waiting in a listener's accept queue. Each finished its
// handshake before the listener was marked and pinned, so it was made from the host's own address,
// carries neither, and is in no descriptor table: accepted after the thaw, it would talk outside the
// tunnel. Each is taken here, pinned so not even its FIN leaves another way, and shut down. The
// listener's open file is the program's own, so it is never made non-blocking: poll says whether a
// connection waits before each accept. It returns how many it ended.
func (c *Containment) drainAcceptQueue(listener int) int {
	// A process outside the tree holding the same open file could take the connection between the
	// poll and the accept; a short receive timeout keeps the accept from waiting on it. The program is
	// frozen, so it never sees the timeout, and the old one is put back.
	if old, err := unix.GetsockoptTimeval(listener, unix.SOL_SOCKET, unix.SO_RCVTIMEO); err == nil {
		_ = unix.SetsockoptTimeval(listener, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 50000})
		defer unix.SetsockoptTimeval(listener, unix.SOL_SOCKET, unix.SO_RCVTIMEO, old)
	}
	n := 0
	for i := 0; i < 1<<16; i++ {
		pfd := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		if k, err := unix.Poll(pfd, 0); err != nil || k == 0 || pfd[0].Revents&unix.POLLIN == 0 {
			return n
		}
		child, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err != nil {
			return n
		}
		_ = unix.SetsockoptInt(child, unix.SOL_SOCKET, unix.SO_MARK, int(c.route.Mark))
		_ = bindToDevice(child, c.route.Index, c.route.Name)
		_ = unix.Shutdown(child, unix.SHUT_RDWR)
		unix.Close(child)
		n++
	}
	return n
}

// inFlightError is a sweep refused only because unix sockets had descriptors in flight.
type inFlightError struct {
	error
	socks []sockRef
}

func (e *inFlightError) Unwrap() error { return e.error }

// inFlightRetries and inFlightWait bound how often, and for how long each time, a containment lets the
// process run so that descriptors in flight are received.
var (
	inFlightRetries = 2
	inFlightWait    = 100 * time.Millisecond
)

// waitInFlight thaws the tree until every one of socks shows no descriptor in flight, or inFlightWait
// has passed, and freezes it again. While it runs, the target's sockets from before are as they were
// before the containment began: none has been touched yet (the sweep decides for all before acting
// on any), and Contain has not returned. A takeover's earlier members stay under their root gates.
func (c *Containment) waitInFlight(socks []sockRef) error {
	freeze := filepath.Join(c.dir, "cgroup.freeze")
	if err := writeFile(freeze, "0"); err != nil {
		return containErr("could not let pid %d run for its descriptors in flight: %v; it was not contained", c.Pid, err)
	}
	deadline := time.Now().Add(inFlightWait)
	for time.Now().Before(deadline) {
		clear := true
		for _, r := range socks {
			if info, err := fdinfo(r); err == nil {
				if n, ok := scmInFlight(info); ok && n > 0 {
					clear = false
					break
				}
			}
		}
		if clear {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := writeFile(freeze, "1"); err != nil {
		return containErr("could not freeze pid %d again: %v; it was not contained", c.Pid, err)
	}
	return c.waitFrozen()
}

// undoTakeover is what a failed takeover of a killed containment runs instead of undo: only what this
// attempt changed is undone, and the killed containment is left holding its members as it did. The
// processes this attempt moved in go back; the sockets it touched get back exactly what they had (a
// mark a killed containment gave them included); the killed containment's own programs go back on the
// cgroup (its gate, which lets out only through its device, gone with its command, and loopback, and
// its mark); its record is written back as it was read. Its gates on the root cgroup were never
// touched. A socket this attempt shut down stays shut down: that cannot be undone.
func (c *Containment) undoTakeover() []string {
	var notes []string
	freeze := filepath.Join(c.dir, "cgroup.freeze")
	_ = writeFile(freeze, "1")
	_ = c.waitFrozen()
	for i := len(c.touched) - 1; i >= c.prevTouched; i-- {
		if err := restoreSockExact(c.touched[i], c.route.gate); err != nil {
			notes = append(notes, err.Error())
		}
	}
	fallback := c.origin[c.Pid]
	for _, p := range c.takenOverIn() {
		o, ok := c.origin[p]
		if !ok {
			o = fallback
		}
		if err := c.moveOut(p, o); err != nil {
			notes = append(notes, err.Error())
		}
	}
	reattached := true
	if err := c.reattachPrev(); err != nil {
		// What stays attached is this attempt's, whose gate lets out through this attempt's device while
		// it lives. So the process stays frozen, which holds it whatever is attached, until a release.
		reattached = false
		notes = append(notes, err.Error()+fmt.Sprintf("; pid %d stays frozen in the containment until "+
			"`sudo whisper contain --release %d`", c.prev.Pid, c.prev.Pid))
	}
	if err := writeRecordValue(c.statePath, *c.prev); err != nil {
		notes = append(notes, "the killed containment's record could not be written back: "+err.Error())
	}
	if reattached {
		_ = writeFile(freeze, "0")
	}
	if c.gate != nil {
		c.gate.Close()
	}
	if c.mark != nil {
		c.mark.Close()
	}
	return notes
}

// takenOverIn names the members a failed takeover gives back: exactly the processes it moved in
// itself, each still the same process (its start time). Nothing is given back by ancestry: a process
// the killed containment held may have a parent this attempt moved in, and a child can be given any
// parent (CLONE_PARENT, a subreaper). A takeover never lets the tree run, and a process written into
// the frozen cgroup freezes on entry, so nothing it moved in has forked since; anything else in the
// cgroup stays held, as it was.
func (c *Containment) takenOverIn() []int {
	var give []int
	for _, p := range c.members() {
		if started, ours := c.moved[p]; ours && started != "" && startTime(p) == started {
			give = append(give, p)
		}
	}
	return give
}

// reattachPrev puts the killed containment's own programs back on the cgroup in place of this
// attempt's: its gate, for its device's index (a record from before indexes has none, which matches
// no device), and its mark program (a record from before generations used the slot's mark).
func (c *Containment) reattachPrev() error {
	prev := c.prev
	mark := prev.Mark
	if mark == 0 {
		mark = legacyMarkBase | uint32(prev.Slot)
	}
	gate, err := ebpf.NewProgram(gateSpec(prev.Index, loIndex()))
	if err != nil {
		return fmt.Errorf("the killed containment's gate could not be loaded again: %v", err)
	}
	defer gate.Close()
	markp, err := ebpf.NewProgram(markSpec(mark))
	if err != nil {
		return fmt.Errorf("the killed containment's mark program could not be loaded again: %v", err)
	}
	defer markp.Close()
	fd, err := unix.Open(c.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("the killed containment's cgroup could not be opened: %v", err)
	}
	defer unix.Close(fd)
	for _, a := range []struct {
		p  *ebpf.Program
		at ebpf.AttachType
	}{{gate, ebpf.AttachCGroupInetEgress}, {markp, ebpf.AttachCGroupInetSockCreate}} {
		if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: fd, Program: a.p, Attach: a.at}); err != nil {
			return fmt.Errorf("the killed containment's programs could not be put back: %v", err)
		}
	}
	return nil
}

// socketNetns returns the inode of the network namespace a socket was made in. known is false on a
// kernel that cannot say (no SIOCGSKNS), and the socket is then judged as one of the host's.
func socketNetns(fd int) (ino uint64, known bool) {
	nfd, err := unix.IoctlRetInt(fd, unix.SIOCGSKNS)
	if err != nil {
		return 0, false
	}
	defer unix.Close(nfd)
	var st unix.Stat_t
	if unix.Fstat(nfd, &st) != nil {
		return 0, false
	}
	return st.Ino, true
}

// synSent reports whether a TCP socket is still connecting.
func synSent(fd int) bool {
	if typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || typ != unix.SOCK_STREAM {
		return false
	}
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	return err == nil && info.State == 2 // TCP_SYN_SENT
}

// getfdAt duplicates descriptor fd of the table tid uses, in process pid, into this process. The
// process's own table is reached through its pidfd; a thread's own needs a pidfd for the thread
// (PIDFD_THREAD, Linux 6.9), and an older kernel answers EINVAL.
func getfdAt(pid, tid, fd int) (int, error) {
	flags := 0
	target := pid
	if tid > 0 && tid != pid {
		target, flags = tid, unix.PIDFD_THREAD
	}
	pfd, err := unix.PidfdOpen(target, flags)
	if err != nil {
		return -1, err
	}
	defer unix.Close(pfd)
	return unix.PidfdGetfd(pfd, fd, 0)
}

// getfd duplicates pid's descriptor fd into this process.
func getfd(pid, fd int) (int, error) { return getfdAt(pid, pid, fd) }

// ptraceNote says what the host's ptrace policy leaves open, or "" when it leaves nothing.
func ptraceNote() string {
	b, err := os.ReadFile(yamaScopePath)
	return ptraceNoteFor(strings.TrimSpace(string(b)), err)
}

var yamaScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// ptraceNoteFor is ptraceNote for the contents of kernel.yama.ptrace_scope, or the error reading it.
// Scope 0, like no Yama at all, lets any process attach to every other process of its user. The
// contained process could then make one outside the containment send for it (ptrace), or take its
// sockets (pidfd_getfd), with no help from it. That is said, not refused: the same user's service
// manager or session bus starts a process outside the cgroup on request at any scope, and the
// boundary that holds against a process working to get out is `whisper run --enforce`.
func ptraceNoteFor(scope string, err error) string {
	const tail = " kernel.yama.ptrace_scope=1 closes ptrace and pidfd_getfd; the boundary that holds against a process working " +
		"to get out is `sudo whisper run --enforce`."
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist):
		return "this kernel has no Yama, so the contained process may attach to any process of its own user outside the " +
			"containment (ptrace, pidfd_getfd) and send through it." + " Starting it under `sudo whisper run --enforce` closes that."
	case err == nil && scope == "0":
		return "kernel.yama.ptrace_scope is 0 here, so the contained process may attach to any process of its own user " +
			"outside the containment (ptrace, pidfd_getfd) and send through it." + tail
	}
	return ""
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
	return c.undo(false)
}

// Finish runs once the tunnel has stopped, after Release. It takes the containment's mark off the
// sockets the release ended, which kept it so that nothing of their goodbye ever took the host's own
// routes. They keep their pin to the device that is gone, so they reach nothing; what is taken off is
// only a mark nothing routes any more.
func (c *Containment) Finish() {
	if c == nil {
		return
	}
	c.clearMarks(c.releasedFrom, nil, c.clearing)
}

// undo is Release, and also what a failed Contain and `whisper contain --release` run. tunnelGone
// says the tunnel is gone already, or is about to go without the caller calling Finish, so the
// sockets it ends lose the mark at once. It returns a note per thing it could not put back.
func (c *Containment) undo(tunnelGone bool) []string {
	var notes []string
	_ = writeFile(filepath.Join(c.dir, "cgroup.freeze"), "1") // nobody forks while they are moved back
	_ = c.waitFrozen()                                        // best effort: what follows reads their tables
	c.releasedFrom = c.members()
	c.clearing = c.ourMarks() // before the adopted generations are let go below
	cut := c.cutAgentSockets()
	// From here only this command's own dials enter the tunnel: unnaming the cgroup voids every tag the
	// sweep gave as well (rootGateSpec). A socket that the release below cannot reach (in flight on a
	// unix socket, passed out of the tree, waiting in an adopted listener's queue) still carries the
	// mark, and without this it would go on leaving as the agent until the tunnel stops; so would a
	// socket just ended, which TCP lets connect again.
	_ = c.route.gate.setCgroup(0)
	// The gates a takeover adopted come off first: they would hold every socket they tagged, given
	// back below, to the tunnel that is gone.
	var left []uint32 // still named by the record if it is kept, so nothing is left unnamed
	for _, g := range c.adopted {
		if !detachRootGatesOf(c.root, g) {
			left = append(left, g)
			c.notes = append(c.notes, fmt.Sprintf("the gate %s stays on the root cgroup %s; `bpftool cgroup show %s` names it", rootGateName(g), c.root, c.root))
		}
	}
	c.adopted = left
	// Last touched first: a socket a killed containment of this agent touched and this one touched
	// again gets back what it had before either. One just ended because it speaks from the agent's
	// address keeps its pin: given back its old binding, its last packets would leave by the host.
	// A socket is found again wherever it is now (the member that held it when it was touched may
	// be gone while another still holds it, or the descriptor may have moved), and only then by the
	// place it was recorded at.
	where := map[uint64]sockRef{}
	if socks, _, _ := tableSockets(c.members()); len(socks) > 0 {
		for _, r := range socks {
			where[r.ino] = r
		}
	}
	var owed []touchedSock // what could not be given back, for a later release
	for i := len(c.touched) - 1; i >= 0; i-- {
		t := c.touched[i]
		if cut[t.Ino] {
			continue
		}
		at := t
		if r, ok := where[t.Ino]; ok {
			at.Pid, at.Tid, at.Fd = r.pid, r.tid, r.fd
		}
		if err := restoreSock(at, c.route.gate); err != nil {
			notes = append(notes, err.Error())
			owed = append([]touchedSock{t}, owed...)
		}
	}
	c.touched = owed
	// What the members made inside carries the containment's mark from its first moment, and kept it
	// for good. It is taken off now, while they are frozen, so a released process speaks as itself from
	// the moment it is let go. The sockets just ended keep it, and their pin, until the tunnel has stopped
	// (Finish): what is left of their goodbye then leaves through the tunnel or nowhere.
	if tunnelGone {
		cut = nil
	}
	c.clearMarks(c.releasedFrom, cut, c.clearing)
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
	notes = append(notes, c.notes...)
	c.notes = nil
	if err := os.Remove(c.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		notes = append(notes, fmt.Sprintf("the cgroup %s could not be removed: %v", c.dir, err))
	}
	_ = os.Remove(filepath.Dir(c.dir)) // only succeeds when no other containment lives there
	if len(notes) == 0 {
		_ = os.Remove(c.statePath)
	} else if _, err := os.Stat(c.statePath); err == nil {
		// Kept while something could not be given back, for another --release, and naming only that:
		// a socket ended because it speaks from the agent's address must never get its binding back.
		// The tunnel's own gate is not named: it belongs to the device, whose own record finds it if
		// this command dies before the device closes.
		gen := c.route.Gen
		c.route.Gen = 0
		if err := c.writeRecord(); err != nil {
			notes = append(notes, "the containment's record could not be rewritten: "+err.Error())
		}
		c.route.Gen = gen
	}
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
// containment's, whatever is attached. The gates on the root cgroup are not its: the device's goes
// when the device closes, and the ones a takeover adopted came off earlier in undo.
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

// restoreSock gives a socket the containment touched its mark and binding back, if the descriptor
// still names it.
func restoreSock(s touchedSock, gate *rootGate) error {
	dup, err := getfdAt(s.Pid, s.Tid, s.Fd)
	if err != nil {
		return nil // the process or the socket is gone
	}
	defer unix.Close(dup)
	var st unix.Stat_t
	if unix.Fstat(dup, &st) != nil || st.Ino != s.Ino {
		return nil // the descriptor now names another socket, which was never touched
	}
	if !s.Bound && !s.Marked {
		if err := unix.SetsockoptString(dup, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, s.Was); err != nil {
			return fmt.Errorf("pid %d's socket (fd %d) stays pinned to the removed tunnel: %v", s.Pid, s.Fd, err)
		}
		return nil
	}
	gate.forget(dup)
	if s.Bound {
		if err := unix.SetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, s.WasIndex); err != nil {
			return fmt.Errorf("pid %d's socket (fd %d) stays pinned to the removed tunnel: %v", s.Pid, s.Fd, err)
		}
	}
	if s.Marked {
		was := s.WasMark
		if _, ours := genOf(was); ours {
			was = 0 // a killed containment's mark, on a socket it made: nothing to give back
		}
		if err := unix.SetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK, int(was)); err != nil {
			return fmt.Errorf("pid %d's socket (fd %d) keeps the containment's mark: %v", s.Pid, s.Fd, err)
		}
	}
	return nil
}

// restoreSockExact gives a socket back exactly the mark and binding it had before this containment
// touched it, a killed containment's mark included: what a failed takeover gives back.
func restoreSockExact(s touchedSock, gate *rootGate) error {
	dup, err := getfdAt(s.Pid, s.Tid, s.Fd)
	if err != nil {
		return nil
	}
	defer unix.Close(dup)
	var st unix.Stat_t
	if unix.Fstat(dup, &st) != nil || st.Ino != s.Ino {
		return nil
	}
	gate.forget(dup)
	if s.Bound {
		if err := unix.SetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, s.WasIndex); err != nil {
			return fmt.Errorf("pid %d's socket (fd %d) could not be given its binding back: %v", s.Pid, s.Fd, err)
		}
	}
	if s.Marked {
		if err := unix.SetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK, int(s.WasMark)); err != nil {
			return fmt.Errorf("pid %d's socket (fd %d) could not be given its mark back: %v", s.Pid, s.Fd, err)
		}
	}
	return nil
}

// cutAgentSockets ends the members' sockets whose local address is the agent's (the /128, or
// 192.0.0.2 for a translated one). They were made inside the containment and leave from an
// address this host holds only while the tunnel does: once it is gone their next packet would take
// the host's own uplink with the agent's address as source. Each is pinned to the tunnel by index,
// so it never leaves another way, and shut down while the tunnel still carries the goodbye; a
// retransmission of that goodbye after the release is refused like anything else of the cgroup's.
func (c *Containment) cutAgentSockets() map[uint64]bool {
	cut := map[uint64]bool{}
	if !c.self.IsValid() {
		return cut
	}
	socks, _, _ := tableSockets(c.members())
	for _, r := range socks {
		dup, err := getfdAt(r.pid, r.tid, r.fd)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		fam, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if unix.Fstat(dup, &st) == nil && st.Ino == r.ino && (fam == unix.AF_INET || fam == unix.AF_INET6) {
			if local, _, _ := sockAddrs(dup); local == c.self || local == CLATv4 {
				if c.route.Index > 0 {
					_ = bindToDevice(dup, c.route.Index, c.route.Name)
				}
				// The goodbye leaves inside shutdown, while the gate still lets the cgroup's sockets in.
				// Then the socket stops being the containment's: TCP lets it connect again, and the gate
				// must not take that into the tunnel.
				_ = unix.Shutdown(dup, unix.SHUT_RDWR)
				c.route.gate.forget(dup)
				cut[r.ino] = true
			}
		}
		unix.Close(dup)
	}
	return cut
}

// ourMarks is this containment's mark and that of every killed containment of the agent it took over.
func (c *Containment) ourMarks() map[uint32]bool {
	ours := map[uint32]bool{}
	if c.route.Mark != 0 {
		ours[c.route.Mark] = true
	}
	for _, g := range c.adopted {
		ours[markFor(g)] = true
	}
	return ours
}

// clearMarks takes the marks in ours (compared under their mask) off every IP socket in pids'
// descriptor tables, except the ones in skip. Release gave back every socket it touched already, so
// what still carries the mark is what the members made inside it, or a socket it ended. A socket
// passed out of the tree keeps it: nothing routes it once the tunnel is gone.
func (c *Containment) clearMarks(pids []int, skip map[uint64]bool, ours map[uint32]bool) {
	if len(ours) == 0 || len(pids) == 0 {
		return
	}
	socks, _, _ := tableSockets(pids)
	for _, r := range socks {
		if skip[r.ino] {
			continue
		}
		dup, err := getfdAt(r.pid, r.tid, r.fd)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		fam, _ := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if unix.Fstat(dup, &st) == nil && st.Ino == r.ino && (fam == unix.AF_INET || fam == unix.AF_INET6) {
			if m, err := unix.GetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK); err == nil && ours[uint32(m)&hostMarkMask] {
				_ = unix.SetsockoptInt(dup, unix.SOL_SOCKET, unix.SO_MARK, 0)
			}
		}
		unix.Close(dup)
	}
}

// addrOfCgroupName reads the agent's /128 back from a containment's cgroup name (containCgroupName).
func addrOfCgroupName(name string) netip.Addr {
	if len(name) != 32 {
		return netip.Addr{}
	}
	var b [16]byte
	for i := range b {
		v, err := strconv.ParseUint(name[2*i:2*i+2], 16, 8)
		if err != nil {
			return netip.Addr{}
		}
		b[i] = byte(v)
	}
	return netip.AddrFrom16(b)
}

// writeRecord replaces the record whole (a new file renamed over the old one), so a command killed
// while it writes leaves the old record or the new one, never an empty one. A record that cannot be
// written refuses the containment: without it a killed command would leave what nobody can undo.
func (c *Containment) writeRecord() error {
	rec := containRecord{Pid: c.Pid, Slot: c.route.Slot, Gen: c.route.Gen, Mark: c.route.Mark, Index: c.route.Index,
		Adopt: c.adopted, Origin: c.origin, Pinned: c.touched}
	if err := writeRecordValue(c.statePath, rec); err != nil {
		return containErr("could not write the containment's record under %s (%v), without which a killed command "+
			"would leave what nobody can undo; it was not contained", containState, err)
	}
	return nil
}

// writeRecordValue replaces the record at path whole, by rename.
func writeRecordValue(path string, rec containRecord) error {
	b, err := json.Marshal(rec)
	if err == nil {
		err = secureDir(containState)
	}
	var f *os.File
	if err == nil {
		f, err = os.CreateTemp(containState, ".record-*")
	}
	if err == nil {
		_, err = f.Write(b)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(f.Name(), path)
		}
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}
	return err
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
		// Its rules and its sockets are the host namespace's, where the process is: a release run from
		// another one would read and tidy that one instead.
		if !sameNamespace(strconv.Itoa(pid), "thread-self", "net") {
			return nil, nil, containErr("this command runs in another network namespace than pid %d, whose containment's "+
				"rules and sockets it could not reach; nothing was changed. Run `sudo whisper contain --release %d` from "+
				"the host", pid, pid)
		}
		name = leaf
	} else {
		name = containCgroupName(self)
	}
	c := &Containment{Pid: pid, root: root, origin: map[int]string{}, dir: filepath.Join(root, ContainParent, name),
		statePath: filepath.Join(containState, name+".json"), self: addrOfCgroupName(name)}
	if _, err := os.Stat(c.dir); err != nil {
		return nil, nil, containErr("there is no containment %s on this host", name)
	}
	// A live `whisper contain` holds the agent's lock for as long as it holds the process, and the
	// kernel drops the lock of one that was killed. So a lock that cannot be taken is a containment
	// that is not stale: tearing it down would leave it running with nothing behind it.
	if !c.self.IsValid() {
		return nil, nil, containErr("the containment %s is not named for an agent's address, so whether it is still held "+
			"cannot be checked; nothing was changed", name)
	}
	{
		l, err := LockExclusive(c.self)
		if err != nil {
			var held *HeldError
			if errors.As(err, &held) {
				return nil, nil, containErr("the containment of %s is live, not left behind (%v); stop that `whisper contain` "+
					"(Ctrl-C) and it releases the process itself", c.self, err)
			}
			return nil, nil, containErr("cannot take the agent lock of %s: %v", c.self, err)
		}
		defer l.Release()
	}
	rec, rerr := readRecord(c.statePath)
	if rerr == nil || errors.Is(rerr, os.ErrNotExist) {
		// Last, still under the agent's lock: the TCP sockets that could still send from the /128 are
		// ended, and its refusal goes once nothing needs it (refusals_linux.go). Not on a refusal: then
		// nothing is changed.
		defer func() {
			if !containedAgents()[c.self] { // a record kept for what could not be given back holds them still
				endAgentSockets(c.self)
			}
			pruneAgentRefusals(c.self, 0)
		}()
	}
	switch {
	case rerr == nil:
		c.origin, c.touched = rec.Origin, rec.Pinned
		c.route = HostRoute{Slot: rec.Slot, Gen: rec.Gen, Mark: rec.Mark, Index: rec.Index}
		c.adopted = append(c.adopted, rec.Adopt...)
		if rec.Gen != 0 {
			c.adopted = append(c.adopted, rec.Gen) // its own gate, left by the killed command
		}
		if c.Pid == 0 {
			c.Pid = rec.Pid
		}
		defer RemoveStaleRules(rec.Slot, rec.Mark, c.self)
		defer reapDeadDevices() // last: the killed command's device record, once the gate is off
	case !errors.Is(rerr, os.ErrNotExist):
		return nil, nil, containErr("the containment's record %s cannot be read (%v), so what it changed cannot be given "+
			"back; nothing was changed", c.statePath, rerr)
	}
	moved := c.members()
	notes := c.undo(true) // the killed command's tunnel is gone
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
