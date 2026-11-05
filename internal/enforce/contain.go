// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// contain.go is the platform-independent half of `whisper contain <pid>`: the decisions, kept
// here so they are tested on every platform. The mechanism is contain_linux.go.
//
// A process that is already running cannot be put in a network namespace: no system call moves
// another process into one, and its sockets keep the namespace they were made in. It can be
// moved into a cgroup, and a cgroup can carry BPF programs that the kernel runs for every socket
// made inside it. A containment is three of those, all on one cgroup of its own:
//
//  1. at socket creation, the socket is given a mark, and the mark selects a routing table whose
//     only route is the containment's tunnel device, with the agent's /128 as preferred source.
//     So a new connection leaves from the /128 without the program knowing or agreeing;
//  2. at egress, a packet from the cgroup passes only if it leaves through that device or
//     through loopback. Anything else (a flushed rule, a socket bound to another interface, the
//     tunnel gone) is refused with EPERM at the socket, never sent;
//  3. sockets made BEFORE the move keep their old cgroup, so neither program sees them. Each is
//     found through the process's file table and either kept (loopback, unix, netlink), pinned to
//     the tunnel device (a listener, an unconnected datagram socket: from then on every packet it
//     sends reaches the tunnel's filter, which passes only the /128), or cut (a connection to
//     somewhere else: pinned, then shut down). A socket family that no route reaches (packet,
//     vsock, ...) makes the containment refuse and undo itself.
//
// What it does not cover, and says so: a process that can become root again (a saved uid 0, a
// capability, sudo, a setuid program it may run) can move itself out; another process on the host
// that dials on the contained one's behalf (over loopback, a unix socket or a passed descriptor)
// is outside it; a process the tree already detached from itself (a daemon that double-forked) is
// not followed. `whisper run --enforce` has none of those gaps, which is why this is a separate verb.

// ContainError is a containment refusal the CLI reports as a usage-class error: the process was
// left exactly as it was.
type ContainError struct{ Msg string }

func (e *ContainError) Error() string { return e.Msg }

func containErr(format string, args ...any) error {
	return &ContainError{Msg: fmt.Sprintf(format, args...)}
}

// Errors the CLI and the tests tell apart.
var (
	ErrNoSuchProcess = errors.New("no such process")
	ErrProcessExited = errors.New("the process exited before it could be contained")
	ErrNoCgroup2     = errors.New("no cgroup v2 hierarchy")
)

// capability numbers from linux/capability.h. Any capability at all refuses a containment (see
// procStatus.privileged), but these are the ones named in the refusal, because they are the
// ones that undo it directly.
var undoCaps = map[int]string{
	1:  "CAP_DAC_OVERRIDE",
	7:  "CAP_SETUID",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
	39: "CAP_BPF",
}

// procStatus is what /proc/<pid>/status says about a process's privilege.
type procStatus struct {
	Name           string
	Uids           [4]int // real, effective, saved, filesystem
	CapPrm, CapEff uint64
	CapAmb         uint64
	PPid           int
	Kthread        bool
}

// parseStatus reads the fields a containment decides on. Missing fields leave their zero value,
// except the uids, which default to 0 so that a status the parser cannot read is refused as
// privileged rather than trusted.
func parseStatus(s string) procStatus {
	var st procStatus
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			st.Name = v
		case "PPid":
			st.PPid, _ = strconv.Atoi(v)
		case "Uid":
			f := strings.Fields(v)
			for i := 0; i < 4 && i < len(f); i++ {
				st.Uids[i], _ = strconv.Atoi(f[i])
			}
		case "CapPrm":
			st.CapPrm, _ = strconv.ParseUint(v, 16, 64)
		case "CapEff":
			st.CapEff, _ = strconv.ParseUint(v, 16, 64)
		case "CapAmb":
			st.CapAmb, _ = strconv.ParseUint(v, 16, 64)
		case "Kthread":
			st.Kthread = v == "1"
		}
	}
	return st
}

// privileged says why a process could undo its own containment, or "" when it could not. Any
// uid of 0 (a saved one included, which can be switched back to) or any permitted, effective or
// ambient capability is enough.
func (st procStatus) privileged() string {
	for i, u := range st.Uids {
		if u == 0 {
			return fmt.Sprintf("it runs with uid 0 (%s uid)", [4]string{"real", "effective", "saved", "filesystem"}[i])
		}
	}
	caps := st.CapPrm | st.CapEff | st.CapAmb
	if caps == 0 {
		return ""
	}
	var named []string
	for bit, name := range undoCaps {
		if caps&(1<<uint(bit)) != 0 {
			named = append(named, name)
		}
	}
	sort.Strings(named)
	if len(named) > 0 {
		return "it holds " + strings.Join(named, ", ")
	}
	return fmt.Sprintf("it holds capabilities (0x%x)", caps)
}

// statPPidFlags reads the parent pid and the flags from /proc/<pid>/stat. The command name is in
// parentheses and may itself hold spaces and parentheses, so the fields are counted from the
// LAST closing parenthesis.
func statPPidFlags(stat string) (ppid int, flags uint64, ok bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(stat[i+1:])
	// f[0] state, f[1] ppid, ..., f[6] flags (fields 3, 4 and 9 of proc(5)).
	if len(f) < 7 {
		return 0, 0, false
	}
	p, err1 := strconv.Atoi(f[1])
	fl, err2 := strconv.ParseUint(f[6], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return p, fl, true
}

// pfKthread is PF_KTHREAD from linux/sched.h.
const pfKthread = 0x00200000

// descendants returns every pid whose chain of parents reaches root, root excluded, in a stable
// order. parent maps each pid to its parent.
func descendants(parent map[int]int, root int) []int {
	children := map[int][]int{}
	for p, pp := range parent {
		if p != pp {
			children[pp] = append(children[pp], p)
		}
	}
	var out []int
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		kids := children[p]
		sort.Ints(kids)
		for _, c := range kids {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

// isAncestor reports whether a is self or one of self's ancestors, by parent.
func isAncestor(parent map[int]int, a, self int) bool {
	for p, hops := self, 0; p > 0 && hops < 1<<16; hops++ {
		if p == a {
			return true
		}
		next, ok := parent[p]
		if !ok || next == p {
			return false
		}
		p = next
	}
	return false
}

// cgroup2Mount finds the cgroup v2 hierarchy in a /proc/self/mountinfo. A hybrid host (v1
// controllers at /sys/fs/cgroup, v2 beside them, usually at /sys/fs/cgroup/unified) is accepted:
// a containment needs only the v2 hierarchy's cgroup.procs, cgroup.freeze and BPF attachment.
func cgroup2Mount(mountinfo string) (string, error) {
	best := ""
	for _, line := range strings.Split(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if len(pf) < 5 || len(qf) < 1 || qf[0] != "cgroup2" {
			continue
		}
		mp := unescapeMount(pf[4])
		// The shortest mount point is the hierarchy's own; a container may bind deeper copies.
		if best == "" || len(mp) < len(best) {
			best = mp
		}
	}
	if best == "" {
		return "", ErrNoCgroup2
	}
	return best, nil
}

// unescapeMount undoes the octal escapes mountinfo uses for space, tab, newline and backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// cgroupPath reads a process's v2 cgroup from /proc/<pid>/cgroup (the "0::" line).
func cgroupPath(s string) (string, bool) {
	for _, line := range strings.Split(s, "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(p), true
		}
	}
	return "", false
}

// ContainParent is the cgroup every containment lives under, relative to the v2 root.
const ContainParent = "whisper-contain"

// containCgroupName names a containment's cgroup after the agent's /128, so a second containment
// of the same agent (which the per-/128 lock already refuses while one is live) finds a killed
// one's cgroup and takes it over rather than leaving it.
func containCgroupName(self netip.Addr) string {
	return strings.ReplaceAll(self.StringExpanded(), ":", "")
}

// Socket handling (contain_linux.go applies it).
type sockAction int

const (
	sockKeep   sockAction = iota // not a path off the host: loopback, unix, netlink, crypto
	sockPin                      // pinned to the tunnel device and left working
	sockCut                      // pinned, then shut down: a connection to somewhere else
	sockRefuse                   // a family no route reaches: the containment cannot be honest
)

func (a sockAction) String() string {
	return [...]string{"kept", "pinned", "cut", "refused"}[a]
}

// Socket families (linux/socket.h), named here so this file builds everywhere.
const (
	afUnix    = 1
	afInet    = 2
	afInet6   = 10
	afNetlink = 16
	afPacket  = 17
	afAlg     = 38
)

// classifySocket decides one socket made before the containment. local and peer are unmapped;
// connected says the socket has a peer, listening that it accepts connections.
func classifySocket(family int, local, peer netip.Addr, connected, listening bool) sockAction {
	switch family {
	case afUnix, afNetlink, afAlg:
		return sockKeep
	case afInet, afInet6:
	default:
		return sockRefuse
	}
	if local.IsLoopback() || (connected && peer.IsLoopback()) {
		return sockKeep
	}
	switch {
	case listening:
		// A listener pinned to the device accepts only what arrives through the tunnel, which is
		// the /128's traffic: inside policy, and the program keeps serving.
		return sockPin
	case connected:
		return sockCut
	}
	// Not connected: a datagram socket, or one made and not yet used. Pinned, its next packet is
	// routed into the tunnel, and from an unbound socket it leaves from the /128.
	return sockPin
}

// familyName is for refusals.
func familyName(f int) string {
	switch f {
	case afPacket:
		return "packet (AF_PACKET)"
	case 40:
		return "vsock (AF_VSOCK)"
	case 44:
		return "XDP (AF_XDP)"
	}
	return "family " + strconv.Itoa(f)
}

// SocketReport counts what the containment did with the sockets it found.
type SocketReport struct {
	Kept, Pinned, Cut int
}

func (r SocketReport) String() string {
	return fmt.Sprintf("%d existing socket%s cut, %d pinned to the tunnel, %d kept (loopback, unix, netlink)",
		r.Cut, plural(r.Cut), r.Pinned, r.Kept)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
