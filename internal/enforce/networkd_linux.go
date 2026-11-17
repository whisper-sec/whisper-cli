// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// networkd_linux.go is the half of the placed-device check (networkd.go) that reads the host: every
// systemd-networkd that could manage a device a contained process places, the configuration each would apply, a
// device such a process already placed, and whether this kernel lets a process without a capability over a namespace
// place a device there at all.
//
// Every networkd counts, not only the host's: a process in the host's pid namespace names any process's network
// namespace by its pid, so a container whose own networkd brings a placed device up and masquerades it out of the
// container hands the process the container's way off the host, which a container manager NATs there.
//
// User-namespace sysctls (user.max_user_namespaces, kernel.unprivileged_userns_clone) are not counted: they stop new
// user namespaces, not one the process's user already owns (a browser's sandbox, a rootless container), which the
// owner rule lets it enter with every capability.

// PlaceProbeArg re-executes this binary as the placement probe's processes. It is dispatched before the command
// tree, like InitArg.
const PlaceProbeArg = "__whisper-placement-probe"

// placedDeviceCheck is Preflight's check; a variable so the refusals before it can be tested on a host it would
// refuse, and its own tests can give it a configuration.
var placedDeviceCheck = checkPlacedDevices

// networkdInstance is one systemd-networkd that would manage a device placed in its namespace.
type networkdInstance struct {
	pid       int    // 0 for one that does not run but would start
	host      bool   // it runs on the host itself, in PID 1's pid namespace, not in a container
	ownNS     bool   // it manages the namespace this command and the process are in
	nsPid     int    // a process in the namespace it manages (itself, or the init that would start it)
	why       string // how it comes to manage a new device there
	container string // the container it runs in, for the refusal ("" on the host)
	initPid   int    // a container's init (its pid 1), through which a fix enters the container
	version   int    // the networkd release, 0 when it cannot be told
	keeps     bool   // networkd.conf turns off its deletion of rules and routes it did not make
	reader    networkdReader
	facts     hostFacts
	taken     map[string]bool
	fwd       hostForwarding
}

// findNetworkd finds the networkd instances to judge for a process with the uids of st; a variable so the check's
// tests can give it a configuration.
var findNetworkd = networkdInstances

// placedCheckWait bounds the whole check: whatever it reads, it answers in this time, or refuses.
var placedCheckWait = 60 * time.Second

// checkPlacedDevices refuses a containment of pid on a host where the process could reach the network through a
// device it places: one some networkd would bring up and let out, or one it placed before and is up now. It refuses
// too when it cannot finish in placedCheckWait.
func checkPlacedDevices(pid int, st procStatus) error {
	done := make(chan error, 1)
	find := findNetworkd // read here, so a check left running past its deadline reads nothing a caller may change
	go func() { done <- checkPlacedDevicesNow(pid, st, find) }()
	select {
	case err := <-done:
		return err
	case <-time.After(placedCheckWait):
		return containErr("pid %d was not contained: this command could not finish judging, within %s, whether "+
			"systemd-networkd would bring up a device the process could make; nothing was changed", pid, placedCheckWait)
	}
}

func checkPlacedDevicesNow(pid int, st procStatus, find func(procStatus) ([]networkdInstance, error)) error {
	instances, err := find(st)
	if err != nil {
		return containErr("pid %d was not contained: this command could not tell whether systemd-networkd would bring up a "+
			"device the process could make (%v); nothing was changed", pid, err)
	}
	// A device placed before: in this namespace, and in every one a networkd manages.
	checked := map[int]bool{}
	for _, nsPid := range append([]int{0}, instancePids(instances)...) {
		if checked[nsPid] {
			continue
		}
		checked[nsPid] = true
		link, why, err := placedLinkUpIn(nsPid, st)
		if err != nil {
			return containErr("pid %d was not contained: this command could not read the network devices %s (%v), so it "+
				"cannot tell whether one the process placed before is up; nothing was changed", pid, nsWhere(nsPid), err)
		}
		if why != "" {
			return containErr("pid %d (%s) was not contained: %s, which no program of the containment would see. Nothing "+
				"was changed. Find what made it, then remove it:\n    %s\nand contain the process again", pid, quoteText(st.Name),
				why, nsDelCommand(nsPid, link))
		}
	}
	type judged struct {
		in      networkdInstance
		views   [][]networkFile // one per networkd release the files are read for: the running one, or the newest and the oldest
		changed []string
	}
	var candidates []judged
	for _, in := range instances {
		j := judged{in: in, changed: changedSinceStart(in)}
		versions := []int{in.version}
		if in.version == 0 {
			versions = []int{0, oldestNetworkd} // which release runs is unknown: a way out either reads counts
		}
		for _, v := range versions {
			r := in.reader
			r.version = v
			files, err := loadNetworkFiles(r)
			if err != nil {
				return containErr("pid %d was not contained: this command could not read the configuration of systemd-networkd "+
					"%s (%v), so it cannot tell what that networkd does with a device the process could make; nothing was "+
					"changed", pid, in.where(), err)
			}
			j.views = append(j.views, files)
		}
		if !in.host {
			for _, files := range j.views {
				if placedCanForward(files, in.taken, in.facts, placeKinds) {
					j.in.fwd = hostForwarding{v4: true, v6: true, byPlacement: true} // one placed device turns it on for the next
				}
			}
		}
		open := len(j.changed) > 0
		for _, files := range j.views {
			open = open || len(findPlacedPaths(files, j.in.taken, j.in.facts, j.in.fwd, in.host, placeKinds)) > 0
		}
		if open {
			candidates = append(candidates, j)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	probe := probePlacement()
	kinds := probe.placeable()
	if len(kinds) == 0 {
		return nil // this kernel places no device in a namespace its creator holds no capability over
	}
	var findings []placedFinding
	for _, j := range candidates {
		in := j.in
		f := placedFinding{where: in.where(), why: in.why, host: in.host, running: in.pid > 0, pid: in.pid,
			container: quoteText(in.container), inUse: linksConfiguredBy(in), initPid: in.initPid, keeps: in.keeps}
		var files []networkFile
		for _, v := range j.views { // the first release whose reading finds a way out
			if p := findPlacedPaths(v, in.taken, in.facts, in.fwd, in.host, kinds); len(p) > 0 {
				f.paths, files = p, v
				break
			}
		}
		if len(j.changed) > 0 {
			f.unknown, f.stale = true, j.changed
			if f.paths == nil {
				f.staleOnly = true
			}
		}
		if in.host && files != nil {
			f.leftover = findPlacedPaths(withUnmanagedFirst(files), in.taken, in.facts, in.fwd, true, kinds)
			f.unread = fixFileUnreadable(in)
			if f.running && !f.keeps && in.ownNS {
				f.foreign = foreignRules()
			}
		}
		findings = append(findings, f)
	}
	return &ContainError{Msg: placedRefusal(pid, quoteText(st.Name), findings, probe.sentence(kinds))}
}

// instancePids are the processes whose namespaces the instances manage.
func instancePids(instances []networkdInstance) []int {
	var out []int
	for _, in := range instances {
		out = append(out, in.nsPid)
	}
	return out
}

func nsWhere(nsPid int) string {
	if nsPid == 0 {
		return "of this host's namespace"
	}
	return fmt.Sprintf("of the namespace of pid %d", nsPid)
}

// nsDelCommand is the command that deletes link in the namespace of nsPid (0: this one), or a sentence for a name no
// command should carry.
func nsDelCommand(nsPid int, link string) string {
	if !pasteable(link) {
		return "(its name holds bytes that are not printable, so remove it by its index: `ip -d link` shows it)"
	}
	if nsPid == 0 {
		return "sudo ip link del dev " + shellWord(link)
	}
	return fmt.Sprintf("sudo nsenter -t %d -n -- ip link del dev %s", nsPid, shellWord(link))
}

// fixFileUnreadable reports whether the refusal's fix file is already there for a host networkd, but its own user
// cannot read it, so networkd ignores it.
func fixFileUnreadable(in networkdInstance) bool {
	_, fi, err := readUnder(in.reader.root, filepath.Join("/etc/systemd/network", unmanagedFixFile))
	return err == nil && fi != nil && in.reader.access != nil && !in.reader.access(fi, 4)
}

// foreignRules are the priorities of this namespace's routing policy rules that neither the kernel nor networkd made
// (their protocol is neither kernel nor static), which networkd deletes when it starts, at its defaults.
func foreignRules() []string {
	var out []string
	seen := map[string]bool{}
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		r, err := openRTNL()
		if err != nil {
			return out
		}
		body := make([]byte, 12) // struct fib_rule_hdr
		body[0] = fam
		_, _ = r.dumpAll(unix.RTM_GETRULE, body, func(data []byte) error {
			if len(data) < 12 {
				return nil
			}
			proto, prio := -1, uint32(0)
			eachAttr(data[12:], func(typ uint16, val []byte) {
				switch typ {
				case unix.FRA_PROTOCOL:
					if len(val) >= 1 {
						proto = int(val[0])
					}
				case unix.FRA_PRIORITY:
					if len(val) >= 4 {
						prio = binary.NativeEndian.Uint32(val)
					}
				}
			})
			if proto != unix.RTPROT_KERNEL && proto != unix.RTPROT_STATIC {
				if p := strconv.FormatUint(uint64(prio), 10); !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			return nil
		})
		r.close()
	}
	return out
}

func (in networkdInstance) where() string {
	switch {
	case in.host && in.ownNS:
		return "in this host's namespace"
	case in.host:
		return fmt.Sprintf("in the network namespace of pid %d on this host", in.nsPid)
	}
	if in.pid == 0 {
		return fmt.Sprintf("in the container %s (init pid %d)", quoteText(in.container), in.initPid)
	}
	return fmt.Sprintf("in the container %s (networkd pid %d)", quoteText(in.container), in.pid)
}

// networkdInstances finds every networkd that would manage a device a process with the uids of st places in its
// namespace: each one running, on the host or in a container, and, where none runs, the one PID 1 or a container's
// init would start (it holds networkd's routing socket, or networkd's service is enabled, which lets any process
// start it over D-Bus). Each one's files are read through its own root, so the command's own mount namespace does not
// matter. One in a namespace that a user namespace a uid of the process owns holds is left out: the process can do
// what it likes there already, and it must not be able to make the check refuse, or feed it, from there. A /proc
// that cannot be read is an error.
func networkdInstances(st procStatus) ([]networkdInstance, error) {
	var self unix.Stat_t
	if err := unix.Stat(filepath.Join(procRoot, "thread-self", "ns", "net"), &self); err != nil {
		return nil, fmt.Errorf("cannot read this command's network namespace: %w", err)
	}
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot list %s: %w", procRoot, err)
	}
	var out []networkdInstance
	covered := map[uint64]bool{} // network namespaces a running networkd manages
	owned := func(pid int) bool {
		fd, err := unix.Open(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return false
		}
		defer unix.Close(fd)
		o := netnsOwner(fd)
		for _, u := range st.Uids {
			if o >= 0 && u == o {
				return true
			}
		}
		return false
	}
	nsIno := func(pid int) (uint64, bool) {
		var ns unix.Stat_t
		if unix.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"), &ns) != nil {
			return 0, false
		}
		return ns.Ino, true
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !isNetworkd(pid) {
			continue
		}
		ino, ok := nsIno(pid)
		if !ok || owned(pid) || !managesItsNamespace(pid) {
			continue
		}
		covered[ino] = true
		root := filepath.Join(procRoot, e.Name(), "root")
		in := networkdInstance{pid: pid, nsPid: pid, ownNS: ino == self.Ino, reader: networkdReader{root: root, access: credsAccess(pid)},
			version: runningVersion(pid), host: sameNamespace(e.Name(), "1", "pid")}
		// A container runs its own init in a pid namespace of its own; a service of the host's (networkd has a mount
		// namespace of its own, from its unit's sandboxing) shares PID 1's.
		if conf, err := readNetworkdConf(networkdReader{root: root}); err == nil {
			in.keeps = conf.keeps
		}
		in.why = fmt.Sprintf("where it runs as pid %d", pid)
		if in.host {
			in.facts = hostFactsNow()
		} else {
			in.container = containerName(pid)
			in.initPid = containerInit(pid)
			in.facts = containerFacts(root)
		}
		in.taken, in.fwd = namespaceState(pid, in.reader)
		out = append(out, in)
	}
	// Where no networkd runs: PID 1's namespace, and each container's that has an init of its own.
	inits := []int{1}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == 1 || sameNamespace(e.Name(), "1", "pid") || !isInit(pid) {
			continue
		}
		inits = append(inits, pid)
	}
	for _, ip := range inits {
		ino, ok := nsIno(ip)
		if !ok || covered[ino] || (ip != 1 && (owned(ip) || !managesItsNamespace(ip))) {
			continue
		}
		root := filepath.Join(procRoot, strconv.Itoa(ip), "root")
		why := networkdWouldStart(root, ip)
		if why == "" {
			continue
		}
		covered[ino] = true
		in := networkdInstance{nsPid: ip, ownNS: ino == self.Ino, host: ip == 1, why: why, version: installedVersion(root),
			reader: networkdReader{root: root, access: passwdAccess(root)}}
		if conf, err := readNetworkdConf(networkdReader{root: root}); err == nil {
			in.keeps = conf.keeps
		}
		if in.host {
			in.facts = hostFactsNow()
		} else {
			in.container, in.initPid, in.facts = containerName(ip), ip, containerFacts(root)
		}
		in.taken, in.fwd = namespaceState(ip, in.reader)
		out = append(out, in)
	}
	return out, nil
}

// managesItsNamespace reports whether the networkd pid could configure the links of its own network namespace: its
// user namespace is the one that owns that network namespace. A process named systemd-networkd that runs in a user
// namespace of its own, beside the host's network namespace (any user can start one, with a harmless configuration
// mounted over the real one), configures nothing there, so it neither counts nor stands in for the networkd that
// would start. One that cannot be read counts.
func managesItsNamespace(pid int) bool {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	var user unix.Stat_t
	if unix.Stat(filepath.Join(dir, "ns", "user"), &user) != nil {
		return true
	}
	fd, err := unix.Open(filepath.Join(dir, "ns", "net"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true
	}
	defer unix.Close(fd)
	owner, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), nsGetUserns, 0)
	if errno != 0 {
		return true
	}
	defer unix.Close(int(owner))
	var ost unix.Stat_t
	if unix.Fstat(int(owner), &ost) != nil {
		return true
	}
	return ost.Dev == user.Dev && ost.Ino == user.Ino
}

// isInit reports whether pid is pid 1 of a pid namespace of its own.
func isInit(pid int) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "NSpid:"); ok {
			f := strings.Fields(v)
			return len(f) > 1 && f[len(f)-1] == "1"
		}
	}
	return false
}

// isNetworkd reports whether pid runs systemd-networkd, by the program it runs ("... (deleted)" after an upgrade it
// has not been restarted for); its command name, which any process can set, only narrows the search.
func isNetworkd(pid int) bool {
	comm, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil || strings.TrimSpace(string(comm)) != "systemd-network" { // the kernel cuts names to 15 bytes
		return false
	}
	exe, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return true // a networkd whose program cannot be read is taken to be one
	}
	return filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == "systemd-networkd"
}

// unitDirs are where systemd keeps the enablement of units, highest priority first.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

// networkdWouldStart says why a networkd that does not run would start and manage a device placed in the namespace of
// init (PID 1, or a container's init), or "": init holds a routing socket there (systemd-networkd.socket listens, and
// a new link starts networkd), or networkd is installed under root, enabled and not masked (its D-Bus alias lets any
// process start it).
func networkdWouldStart(root string, init int) string {
	for _, d := range unitDirs {
		if b, fi, _ := readUnder(root, filepath.Join(d, "systemd-networkd.service")); fi != nil && (len(b) == 0 || !fi.Mode().IsRegular()) {
			return "" // masked: a link to /dev/null, or empty
		}
	}
	if initHoldsRouteSocket(init) {
		return "where it does not run, but any new device starts it (init holds its routing socket)"
	}
	installed := false
	for _, p := range []string{"/usr/lib/systemd/systemd-networkd", "/lib/systemd/systemd-networkd"} {
		if _, fi, _ := readUnder(root, p); fi != nil {
			installed = true
		}
	}
	if !installed {
		return ""
	}
	for _, d := range unitDirs {
		for _, link := range []string{"dbus-org.freedesktop.network1.service", "multi-user.target.wants/systemd-networkd.service",
			"sockets.target.wants/systemd-networkd.socket", "sockets.target.wants/systemd-networkd-varlink.socket",
			"network-online.target.wants/systemd-networkd-wait-online.service"} {
			if fd, err := openUnder(root, filepath.Join(d, link), unix.O_PATH|unix.O_NOFOLLOW); err == nil {
				unix.Close(fd)
				return "where it does not run, but it is enabled, so any process can start it over D-Bus"
			}
		}
	}
	return ""
}

// initHoldsRouteSocket reports whether init holds a NETLINK_ROUTE socket of its own namespace, which only a socket unit
// listening on rtnetlink (systemd-networkd.socket) makes it do. One that cannot be read is taken to be held.
func initHoldsRouteSocket(init int) bool {
	route := map[string]bool{}
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(init), "net", "netlink"))
	if err != nil {
		return true
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		c := strings.Fields(sc.Text())
		if len(c) >= 10 && c[1] == "0" { // Eth, the protocol: NETLINK_ROUTE
			route[c[9]] = true
		}
	}
	dir := filepath.Join(procRoot, strconv.Itoa(init), "fd")
	fds, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, d := range fds {
		l, err := os.Readlink(filepath.Join(dir, d.Name()))
		if err == nil && strings.HasPrefix(l, "socket:[") && route[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] {
			return true
		}
	}
	return false
}

// credsAccess says whether a running process may read (4) or search (1) a file or directory, by the owner and mode
// bits against its filesystem uid, gid and groups as /proc shows them. A process whose credentials cannot be read
// may do everything.
func credsAccess(pid int) func(fs.FileInfo, uint32) bool {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return nil
	}
	uid, gid := -1, -1
	groups := map[uint32]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch {
		case k == "Uid" && len(f) == 4:
			uid, _ = strconv.Atoi(f[3])
		case k == "Gid" && len(f) == 4:
			gid, _ = strconv.Atoi(f[3])
		case k == "Groups":
			for _, g := range f {
				if n, err := strconv.ParseUint(g, 10, 32); err == nil {
					groups[uint32(n)] = true
				}
			}
		}
	}
	if uid < 0 || gid < 0 {
		return nil
	}
	groups[uint32(gid)] = true
	return modeAccess(uint32(uid), groups)
}

// passwdAccess is credsAccess for networkd's own user, systemd-network, as root's /etc/passwd and /etc/group name it,
// for a networkd that does not run yet. Without that user, everything counts as allowed.
func passwdAccess(root string) func(fs.FileInfo, uint32) bool {
	b, _, err := readUnder(root, "/etc/passwd")
	if err != nil || b == nil {
		return nil
	}
	var uid, gid uint64
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == "systemd-network" {
			u, err1 := strconv.ParseUint(f[2], 10, 32)
			g, err2 := strconv.ParseUint(f[3], 10, 32)
			if err1 == nil && err2 == nil {
				uid, gid, found = u, g, true
			}
		}
	}
	if !found {
		return nil
	}
	groups := map[uint32]bool{uint32(gid): true}
	if b, _, err := readUnder(root, "/etc/group"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) == 4 && contains(strings.Split(f[3], ","), "systemd-network") {
				if n, err := strconv.ParseUint(f[2], 10, 32); err == nil {
					groups[uint32(n)] = true
				}
			}
		}
	}
	return modeAccess(uint32(uid), groups)
}

// modeAccess is the classic permission check: root may do everything, the owner by the owner's bits, a member of the
// file's group by the group's, everyone else by the rest. ACLs are not read.
func modeAccess(uid uint32, groups map[uint32]bool) func(fs.FileInfo, uint32) bool {
	return func(fi fs.FileInfo, want uint32) bool {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || uid == 0 {
			return true
		}
		m := uint32(fi.Mode().Perm())
		switch {
		case st.Uid == uid:
			m >>= 6
		case groups[st.Gid]:
			m >>= 3
		}
		return m&want == want
	}
}

// hostFactsNow reads what host conditions are judged against on this host.
func hostFactsNow() hostFacts {
	var h hostFacts
	if b, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "hostname")); err == nil {
		h.hostname = strings.TrimSpace(string(b))
	}
	if b, _, err := readUnder(filepath.Join(procRoot, "1", "root"), "/etc/machine-id"); err == nil {
		h.machineID = strings.TrimSpace(string(b))
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.arch = unix.ByteSliceToString(u.Machine[:])
		h.kernel = unix.ByteSliceToString(u.Release[:])
	}
	if b, err := os.ReadFile(filepath.Join(procRoot, "cmdline")); err == nil {
		h.cmdline = splitWords(strings.TrimSpace(string(b)), true)
		if h.cmdline == nil {
			h.cmdline = []string{}
		}
	}
	return h
}

// containerFacts is hostFacts as a networkd running in a container judges them: its machine id and the kind of
// container systemd recorded there, read under its root; the host's kernel. Its hostname is its UTS namespace's,
// which is not read, so Host= by name is unknown there, and so is its command line.
func containerFacts(root string) hostFacts {
	h := hostFactsNow()
	h.hostname, h.machineID, h.cmdline = "", "", nil
	if b, _, err := readUnder(root, "/etc/machine-id"); err == nil {
		h.machineID = strings.TrimSpace(string(b))
	}
	h.container = "container-other"
	if b, _, err := readUnder(root, "/run/systemd/container"); err == nil && strings.TrimSpace(string(b)) != "" {
		h.container = strings.TrimSpace(string(b))
	}
	return h
}

// containerName names the container pid runs in for the refusal, from its cgroup: an LXD or Incus container's name,
// a systemd-nspawn machine's, or else the cgroup itself.
func containerName(pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	path := ""
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if p, ok := strings.CutPrefix(line, "0::"); ok {
				path = p
			}
		}
	}
	for _, part := range strings.Split(path, "/") {
		if n, ok := strings.CutPrefix(part, "lxc.payload."); ok {
			return n
		}
		if n, ok := strings.CutPrefix(part, "machine-"); ok && strings.HasSuffix(n, ".scope") {
			return unescapeUnit(strings.TrimSuffix(n, ".scope"))
		}
	}
	if path == "" {
		return "of pid " + strconv.Itoa(pid)
	}
	return "in the cgroup " + path
}

// unescapeUnit undoes systemd's \xNN escaping of a unit name.
func unescapeUnit(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// namespaceState reads, in the network namespace of pid, the names a placed device cannot take there (every link's
// name and alternative names: a process cannot remove a link it did not make, and one it did make it may as well
// keep) and whether that namespace forwards what a new device receives, adding what networkd.conf under r turns on
// when networkd starts. Forwarding that cannot be read counts as on; a family the kernel does not have cannot forward.
func namespaceState(pid int, r networkdReader) (map[string]bool, hostForwarding) {
	taken := map[string]bool{"lo": true}
	fwd := hostForwarding{v4: true, v6: true}
	if fd, err := unix.Open(filepath.Join(procRoot, strconv.Itoa(pid), "ns", "net"), unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		_ = onThreadIn(fd, func() error {
			for n := range linkNames() {
				taken[n] = true
			}
			fwd = hostForwarding{
				v4: sysctlOn("/proc/sys/net/ipv4/conf/default/forwarding"),
				v6: sysctlOn("/proc/sys/net/ipv6/conf/all/forwarding"),
			}
			return nil
		})
		unix.Close(fd)
	}
	if conf, err := readNetworkdConf(networkdReader{root: r.root}); err == nil {
		fwd.v4, fwd.v6 = fwd.v4 || conf.fwd.v4, fwd.v6 || conf.fwd.v6
	}
	return taken, fwd
}

// linkNames are the names and alternative names of every link in the calling thread's namespace.
func linkNames() map[string]bool {
	names := map[string]bool{}
	r, err := openRTNL()
	if err != nil {
		return names
	}
	defer r.close()
	_, _ = r.dumpAll(unix.RTM_GETLINK, make([]byte, unix.SizeofIfInfomsg), func(data []byte) error {
		if len(data) < unix.SizeofIfInfomsg {
			return nil
		}
		eachAttr(data[unix.SizeofIfInfomsg:], func(typ uint16, val []byte) {
			switch typ {
			case unix.IFLA_IFNAME:
				names[unix.ByteSliceToString(val)] = true
			case unix.IFLA_PROP_LIST:
				eachAttr(val, func(t uint16, v []byte) {
					if t == unix.IFLA_ALT_IFNAME {
						names[unix.ByteSliceToString(v)] = true
					}
				})
			}
		})
		return nil
	})
	return names
}

func sysctlOn(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return strings.TrimSpace(string(b)) != "0"
}

// linksConfiguredBy maps each .network file a running networkd of this namespace applies now to the links it applies
// it to, from networkd's own state files, so the refusal can say what a fix takes away.
func linksConfiguredBy(in networkdInstance) map[string][]string {
	out := map[string][]string{}
	if !in.ownNS || in.pid == 0 {
		return out
	}
	const dir = "/run/systemd/netif/links"
	ents, _, err := listUnder(in.reader.root, dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		idx, err := strconv.Atoi(e)
		if err != nil {
			continue
		}
		b, _, err := readUnder(in.reader.root, filepath.Join(dir, e))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if file, ok := strings.CutPrefix(line, "NETWORK_FILE="); ok {
				if ifc, err := net.InterfaceByIndex(idx); err == nil {
					out[file] = append(out[file], quoteText(ifc.Name))
				}
			}
		}
	}
	return out
}

// runningVersion reads the release of the networkd pid runs from the shared library it has mapped
// (libsystemd-shared-<release>.so), or 0.
func runningVersion(pid int) int {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return 0
	}
	return sharedVersion(strings.Split(string(b), "\n"))
}

// installedVersion reads the release of the networkd installed under root from the name of its shared library, or 0
// when there is not exactly one.
func installedVersion(root string) int {
	var names []string
	for _, d := range []string{"/usr/lib/systemd", "/lib/systemd", "/usr/lib64/systemd", "/usr/lib/x86_64-linux-gnu/systemd",
		"/usr/lib/aarch64-linux-gnu/systemd"} {
		ents, _, err := listUnder(root, d)
		if err != nil {
			continue
		}
		names = append(names, ents...)
	}
	return sharedVersion(names)
}

// containerInit is pid 1 of the container networkd pid runs in, found up its parents (the one whose pid in its own
// namespace is 1), or 0 when none is found: networkd's own mount namespace is read-only, so a fix enters through the
// container's init, and with none found the refusal prints no command.
func containerInit(pid int) int {
	p := pid
	for i := 0; i < 64 && p > 1; i++ {
		if isInit(p) {
			return p
		}
		b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(p), "status"))
		if err != nil {
			break
		}
		ppid := 0
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PPid:"); ok {
				ppid, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		p = ppid
	}
	return 0
}

// The present. A process may have placed a device before the containment, while nothing refused it: a far end that
// networkd brought up, with the process (or a child it left in its own namespace) on the near end. A containment then
// starts with the way out already open, and masking a file or stopping networkd later does not take a device down. So
// a veth or netkit device that is up, in this namespace or one a networkd manages, with its far end in a network
// namespace whose user namespace a uid of the process owns, refuses; one whose far end cannot be traced refuses too.

const (
	nsGetUserns   = 0xb701 // NS_GET_USERNS, _IO(0xb7, 0x1)
	nsGetParent   = 0xb702 // NS_GET_PARENT
	nsGetOwnerUID = 0xb704 // NS_GET_OWNER_UID
	initUsernsIno = 0xEFFFFFFD
)

// placedLinkUpIn is placedLinkUp in the namespace of nsPid (0: this one), on a thread that goes there and back.
func placedLinkUpIn(nsPid int, st procStatus) (string, string, error) {
	if nsPid == 0 {
		return placedLinkUp(st)
	}
	fd, err := unix.Open(filepath.Join(procRoot, strconv.Itoa(nsPid), "ns", "net"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", "", nil // gone
	}
	defer unix.Close(fd)
	var link, why string
	err = onThreadIn(fd, func() error {
		var e error
		link, why, e = placedLinkUp(st)
		return e
	})
	return link, why, err
}

// placedLinkUp names a device of the calling thread's namespace a process with the uids of st may already hold a way
// out through, and says why, or answers "" for both.
func placedLinkUp(st procStatus) (string, string, error) {
	links, err := peeredLinksUp()
	if err != nil || len(links) == 0 {
		return "", "", err
	}
	owners := netnsOwnersByID()
	// Read again after the walk: a device whose far end went meanwhile (a container that stopped) is not one to name.
	again, err := peeredLinksUp()
	if err != nil {
		return "", "", err
	}
	still := map[peeredLink]bool{}
	for _, l := range again {
		still[l] = true
	}
	for _, l := range links {
		if !still[l] {
			continue
		}
		owner, ok := owners[l.nsid]
		switch {
		case !ok || owner == -2:
			return l.name, fmt.Sprintf("the %s %s is up with its far end in a network namespace this command cannot trace "+
				"to its owner, so it cannot tell who holds the other end", l.kind, quoteText(l.name)), nil
		case owner >= 0:
			for _, u := range st.Uids {
				if u == owner {
					return l.name, fmt.Sprintf("the %s %s is up, and its far end is in a network namespace of a user "+
						"namespace that the process's user (uid %d) owns, so the process can reach the network through it",
						l.kind, quoteText(l.name), owner), nil
				}
			}
		}
	}
	return "", "", nil
}

type peeredLink struct {
	name, kind string
	nsid       int32
}

// peeredLinksUp lists the veth and netkit devices of the calling thread's namespace that are up with their far end in
// another one. A dump the kernel marks interrupted is read again; one that stays so, or fails, is an error.
func peeredLinksUp() ([]peeredLink, error) {
	for attempt := 0; attempt < 3; attempt++ {
		r, err := openRTNL()
		if err != nil {
			return nil, err
		}
		var out []peeredLink
		intr, err := r.dumpAll(unix.RTM_GETLINK, make([]byte, unix.SizeofIfInfomsg), func(data []byte) error {
			if len(data) < unix.SizeofIfInfomsg {
				return nil
			}
			flags := binary.NativeEndian.Uint32(data[8:12])
			l := peeredLink{nsid: -1}
			eachAttr(data[unix.SizeofIfInfomsg:], func(typ uint16, val []byte) {
				switch typ {
				case unix.IFLA_IFNAME:
					l.name = unix.ByteSliceToString(val)
				case unix.IFLA_LINK_NETNSID:
					if len(val) >= 4 {
						l.nsid = int32(binary.NativeEndian.Uint32(val))
					}
				case unix.IFLA_LINKINFO:
					eachAttr(val, func(t uint16, v []byte) {
						if t == unix.IFLA_INFO_KIND {
							l.kind = unix.ByteSliceToString(v)
						}
					})
				}
			})
			if flags&unix.IFF_UP != 0 && l.nsid >= 0 && (l.kind == "veth" || l.kind == "netkit") {
				out = append(out, l)
			}
			return nil
		})
		r.close()
		if err != nil {
			return nil, err
		}
		if !intr {
			return out, nil
		}
	}
	return nil, errors.New("the link dump was interrupted three times")
}

// netnsOwnersByID maps the id the calling thread's namespace gives each other network namespace it can find (every
// process's, every one a process holds by a descriptor, every one mounted somewhere, each mount namespace read once)
// to the uid that owns the first user namespace below the initial one on its way up, -1 for one of the initial user
// namespace, -2 for one that cannot be read.
func netnsOwnersByID() map[int32]int {
	out := map[int32]int{}
	seen := map[uint64]bool{}
	try := func(root, path string) {
		fd, ok := openNamespace(root, path)
		if !ok {
			return
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || seen[st.Ino] {
			return
		}
		seen[st.Ino] = true
		if id, ok := netnsID(fd); ok {
			out[id] = netnsOwner(fd)
		}
	}
	mounts := map[uint64]bool{}
	ents, _ := os.ReadDir(procRoot)
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		try("", filepath.Join(dir, "ns", "net"))
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		for _, f := range fds {
			if l, err := os.Readlink(filepath.Join(dir, "fd", f.Name())); err == nil && strings.HasPrefix(l, "net:[") {
				try("", filepath.Join(dir, "fd", f.Name()))
			}
		}
		var mnt unix.Stat_t
		if unix.Stat(filepath.Join(dir, "ns", "mnt"), &mnt) != nil || mounts[mnt.Ino] {
			continue
		}
		mounts[mnt.Ino] = true
		mi, err := os.ReadFile(filepath.Join(dir, "mountinfo"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(mi), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && strings.HasPrefix(f[3], "net:[") {
				try(filepath.Join(dir, "root"), unescapeMount(f[4]))
			}
		}
	}
	return out
}

// netnsID asks this namespace for the id it gives the network namespace fd holds (RTM_GETNSID), or reports that it
// gives it none.
func netnsID(fd int) (int32, bool) {
	r, err := openRTNL()
	if err != nil {
		return 0, false
	}
	defer r.close()
	body := append(make([]byte, 4), nlAttr(unix.NETNSA_FD, u32(uint32(fd)))...) // struct rtgenmsg, aligned
	msg := make([]byte, unix.SizeofNlMsghdr+len(body))
	seq := nlSeq.Add(1)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], unix.RTM_GETNSID)
	binary.NativeEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	copy(msg[unix.SizeofNlMsghdr:], body)
	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, false
	}
	_ = unix.SetsockoptTimeval(r.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	buf := make([]byte, 4096)
	for {
		n, from, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, false
		}
		if !fromKernel(from) {
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return 0, false
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Type != unix.RTM_NEWNSID || len(m.Data) < 4 {
				return 0, false // an error, or an answer of another kind
			}
			id, ok := int32(-1), false
			eachAttr(m.Data[4:], func(typ uint16, val []byte) {
				if typ == unix.NETNSA_NSID && len(val) >= 4 {
					id, ok = int32(binary.NativeEndian.Uint32(val)), true
				}
			})
			return id, ok && id >= 0
		}
	}
}

// netnsOwner is the uid owning the first user namespace below the initial one above the network namespace fd holds,
// or -1 when it belongs to the initial user namespace. One that cannot be read is owned by an unknown uid (-2).
func netnsOwner(fd int) int {
	cur, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), nsGetUserns, 0)
	if errno != 0 {
		return -2
	}
	user := int(cur)
	for depth := 0; depth < 64; depth++ {
		var st unix.Stat_t
		if unix.Fstat(user, &st) != nil {
			unix.Close(user)
			return -2
		}
		if st.Ino == initUsernsIno {
			unix.Close(user)
			return -1
		}
		parent, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(user), nsGetParent, 0)
		if errno != 0 {
			unix.Close(user)
			return -2
		}
		var pst unix.Stat_t
		if unix.Fstat(int(parent), &pst) == nil && pst.Ino == initUsernsIno {
			unix.Close(int(parent))
			var uid uint32
			_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(user), nsGetOwnerUID, uintptr(unsafe.Pointer(&uid)))
			unix.Close(user)
			if errno != 0 {
				return -2
			}
			return int(uid)
		}
		unix.Close(user)
		user = int(parent)
	}
	unix.Close(user)
	return -2
}

// The placement probe. This binary is started as the holder, in a new network namespace of its own (the scratch),
// and the holder starts it again as the child, root of a new user namespace and in a new network namespace of that
// user namespace, holding the scratch by a descriptor. The child holds no capability over the scratch, exactly as a
// process that made a user namespace of its own holds none over the host's. It first makes a pair with the far end
// in its own namespace, named by a descriptor (the control: the same request, to a namespace it does hold the
// capability over, which must work for any refusal to mean anything), then asks for a pair of each kind with the far
// end in the scratch, by a descriptor, and for a veth by the holder's pid. The holder looks for each far end in the
// scratch itself, says what it saw, and lets the child go only when this command closes its input or is gone; the
// child's namespace, and every pair with it, ends with the child. Neither ever touches this command's own namespace:
// the holder checks it is not in it, and the child that the scratch it holds is the holder's.

// probeAsks are the requests the child makes: a kind, how the scratch is named, and the far end's name there.
var probeAsks = []struct{ key, kind, by, peer string }{
	{"veth", "veth", "fd", "wsprobe1"},
	{"veth-pid", "veth", "pid", "wsprobe2"},
	{"netkit", "netkit", "fd", "wsprobe3"},
}

// placeAnswer is what the kernel did with one kind.
type placeAnswer int

const (
	placedUnknown placeAnswer = iota // the probe could not tell: counted as placed
	placedSeen                       // placed, and the holder saw the far end in the scratch
	placedRefused                    // refused with EPERM while the control in the child's own namespace worked
	placedAbsent                     // this kernel has no such kind
)

type probeResult struct {
	kinds         map[string]placeAnswer // by placeKind.kind
	why           string                 // why it could not tell, for the refusal
	holder, child int                    // the probe's processes, for the tests that follow them to their end
	loaded        []string               // modules that were not loaded before the test and are now
}

// placeable are the kinds a process could place, as far as the probe tells.
func (p probeResult) placeable() []placeKind {
	var out []placeKind
	for _, k := range placeKinds {
		if a, ok := p.kinds[k.kind]; !ok || a == placedSeen || a == placedUnknown {
			out = append(out, k)
		}
	}
	return out
}

// sentence says what the probe found, for the refusal.
func (p probeResult) sentence(kinds []placeKind) string {
	var seen []string
	all := true
	for _, k := range kinds {
		if p.kinds[k.kind] != placedSeen {
			all = false
		} else if !contains(seen, k.kind) {
			seen = append(seen, k.kind)
		}
	}
	loaded := ""
	if len(p.loaded) > 0 {
		loaded = "; that test loaded the " + strings.Join(p.loaded, " and ") + " module, as any process's request would"
	}
	if all && p.why == "" {
		return "this kernel allowed exactly that for a " + strings.Join(seen, " and a ") + " in a test just now, in a " +
			"namespace this command made and has removed" + loaded
	}
	why := p.why
	if why == "" {
		why = "it gave no clear answer"
	}
	return "this command could not test whether this kernel allows that (" + why + "), so it takes it that it does"
}

var (
	probeMu    sync.Mutex
	probeKept  *probeResult // an answer with nothing unknown, kept for the life of the process
	probeCount int          // how many probes ran, for the tests
	probeWait  = 5 * time.Second
)

// placeProbeCommand starts the holder; a variable so a test can start one that does not answer.
var placeProbeCommand = func(hostIno uint64) *exec.Cmd {
	return exec.Command("/proc/self/exe", PlaceProbeArg, "holder", strconv.FormatUint(hostIno, 10))
}

// probePlacement runs the probe once per process, or answers what an earlier run found. An answer that is not
// clear is never kept.
func probePlacement() probeResult {
	probeMu.Lock()
	defer probeMu.Unlock()
	if probeKept != nil {
		return *probeKept
	}
	probeCount++
	var before [2]error
	for i, m := range []string{"veth", "netkit"} {
		_, before[i] = os.Stat("/sys/module/" + m)
	}
	r := runPlacementProbe()
	for i, m := range []string{"veth", "netkit"} {
		if _, after := os.Stat("/sys/module/" + m); before[i] != nil && after == nil {
			r.loaded = append(r.loaded, m)
		}
	}
	if r.why == "" {
		probeKept = &r
	}
	return r
}

func runPlacementProbe() probeResult {
	unknown := func(why string) probeResult { return probeResult{kinds: map[string]placeAnswer{}, why: why} }
	host, err := nsInode()
	if err != nil {
		return unknown("cannot read this command's network namespace")
	}
	deadline := time.Now().Add(probeWait)
	cmd := placeProbeCommand(host)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	in, err := cmd.StdinPipe()
	if err != nil {
		return unknown(err.Error())
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return unknown(err.Error())
	}
	if err := cmd.Start(); err != nil {
		return unknown("the test process did not start: " + err.Error())
	}
	holder, wait := cmd.Process.Pid, probeWait
	// However this ends, the holder is let go and reaped without this command waiting on it: a process killed while
	// it waits for the kernel's routing lock dies only when it gets the lock.
	defer func() {
		in.Close()
		go func() {
			t := time.AfterFunc(wait, func() { _ = cmd.Process.Kill() })
			_ = cmd.Wait()
			t.Stop()
		}()
	}()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case s := <-line:
		r := parseProbeLine(s)
		r.holder = holder
		return r
	case <-time.After(time.Until(deadline)):
		_ = cmd.Process.Kill()
		r := unknown(fmt.Sprintf("the test did not answer within %s", wait))
		r.holder = holder
		return r
	}
}

// parseProbeLine reads the holder's answer: "own=<result> <ask>=<result>[,seen|,unseen] ...", or "error <why>".
func parseProbeLine(s string) probeResult {
	r := probeResult{kinds: map[string]placeAnswer{}}
	if s == "" {
		r.why = "the test said nothing"
		return r
	}
	if why, ok := strings.CutPrefix(s, "error "); ok {
		r.why = "the test failed: " + why
		return r
	}
	if errno, ok := strings.CutPrefix(s, "nouserns "); ok {
		// The kernel's own limit at zero (ENOSPC with user.max_user_namespaces 0) stops every process making one, and
		// with none but the initial one anywhere, none can enter one either: nothing is placeable. Any other refusal
		// (a seccomp filter, an LSM, this command's own bounding set) is this command's alone.
		if errno == "ENOSPC" && userNamespacesShut() {
			for _, k := range placeKinds {
				r.kinds[k.kind] = placedRefused
			}
			return r
		}
		r.why = "the test could not make a user namespace (" + errno + "), which says nothing about another process"
		return r
	}
	got := map[string]string{}
	for _, kv := range strings.Fields(s) {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	r.child, _ = strconv.Atoi(got["child"])
	// Each kind has its own control: the same request with the far end in the child's own namespace, which it holds
	// the capability over. EOPNOTSUPP there means this kernel has no such kind; any other failure means the test tells
	// nothing about that kind.
	controls := map[string]string{}
	for _, k := range []string{"veth", "netkit"} {
		controls[k] = got["own-"+k]
		if c := controls[k]; c != "ok" && c != "EOPNOTSUPP" && r.why == "" {
			r.why = fmt.Sprintf("the test could not make a %s even with both ends in a namespace of its own: %s", k, c)
		}
	}
	worst := map[string]placeAnswer{}
	for _, a := range probeAsks {
		v := got[a.key]
		var ans placeAnswer
		switch {
		case controls[a.kind] == "EOPNOTSUPP":
			ans = placedAbsent
		case v == "ok,seen":
			ans = placedSeen
		case v == "EPERM" && controls[a.kind] == "ok":
			ans = placedRefused
		case v == "EOPNOTSUPP":
			ans = placedAbsent
		default:
			ans = placedUnknown
			if r.why == "" {
				r.why = fmt.Sprintf("a %s by %s answered %q", a.kind, a.by, v)
			}
		}
		// A kind counts as placeable when any way of naming the scratch placed it, unknown when any could not tell.
		prev, had := worst[a.kind]
		switch {
		case !had, ans == placedSeen, ans == placedUnknown && prev != placedSeen:
			worst[a.kind] = ans
		case ans == placedRefused && prev == placedAbsent:
			worst[a.kind] = ans
		}
	}
	r.kinds = worst
	return r
}

// userNamespacesShut reports whether no process can make or enter a user namespace: user.max_user_namespaces is 0,
// and no user namespace but the initial one exists, held by a process, a descriptor or a mount. A variable so the
// probe's reading can be tested.
var userNamespacesShut = func() bool {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys", "user", "max_user_namespaces"))
	if err != nil || strings.TrimSpace(string(b)) != "0" {
		return false
	}
	return !otherUserNamespaces()
}

// ownerOther reports whether the namespace at path is owned by a user namespace other than the initial one.
func ownerOther(path string) bool { return ownerOtherUnder("", path) }

func ownerOtherUnder(root, path string) bool {
	fd, ok := openNamespace(root, path)
	if !ok {
		return false
	}
	defer unix.Close(fd)
	u, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), nsGetUserns, 0)
	if errno != 0 {
		return false
	}
	defer unix.Close(int(u))
	var st unix.Stat_t
	return unix.Fstat(int(u), &st) == nil && st.Ino != initUsernsIno
}

// otherUserNamespaces reports whether any user namespace other than the initial one exists: a process's, one a
// process holds by a descriptor, or one mounted somewhere. One that cannot be read counts as such.
func otherUserNamespaces() bool {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return true
	}
	other := func(root, path string) bool {
		fd, ok := openNamespace(root, path)
		if !ok {
			return false
		}
		defer unix.Close(fd)
		var st unix.Stat_t
		return unix.Fstat(fd, &st) == nil && st.Ino != initUsernsIno
	}
	mounts := map[uint64]bool{}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		if other("", filepath.Join(dir, "ns", "user")) {
			return true
		}
		// A user namespace kept alive only by a namespace it owns (a network or mount namespace held open).
		for _, kind := range []string{"net", "mnt"} {
			if ownerOther(filepath.Join(dir, "ns", kind)) {
				return true
			}
		}
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		for _, f := range fds {
			if l, err := os.Readlink(filepath.Join(dir, "fd", f.Name())); err == nil && strings.HasPrefix(l, "user:[") &&
				other("", filepath.Join(dir, "fd", f.Name())) {
				return true
			}
		}
		var mnt unix.Stat_t
		if unix.Stat(filepath.Join(dir, "ns", "mnt"), &mnt) != nil || mounts[mnt.Ino] {
			continue
		}
		mounts[mnt.Ino] = true
		mi, err := os.ReadFile(filepath.Join(dir, "mountinfo"))
		if err != nil {
			return true
		}
		for _, line := range strings.Split(string(mi), "\n") {
			f := strings.Fields(line)
			// A user namespace mounted somewhere exists, whether or not its mount can be opened from here.
			if len(f) >= 5 && strings.HasPrefix(f[3], "user:[") && f[3] != fmt.Sprintf("user:[%d]", uint64(initUsernsIno)) {
				return true
			}
			if len(f) >= 5 && strings.HasPrefix(f[3], "net:[") && ownerOtherUnder(filepath.Join(dir, "root"), unescapeMount(f[4])) {
				return true
			}
		}
	}
	return false
}

// RunPlaceProbe is the probe's two processes, chosen by os.Args[2].
func RunPlaceProbe() {
	say := func(s string) {
		fmt.Println(s)
		os.Exit(0)
	}
	if len(os.Args) < 4 {
		say("error the probe was started without its arguments")
	}
	host, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		say("error the probe was started with a bad namespace")
	}
	switch os.Args[2] {
	case "holder":
		probeHolder(host)
	case "child":
		if len(os.Args) < 6 {
			say("error the child was started without the scratch namespace")
		}
		scratch, err1 := strconv.ParseUint(os.Args[4], 10, 64)
		holder, err2 := strconv.Atoi(os.Args[5])
		if err1 != nil || err2 != nil {
			say("error the child was started with a bad scratch namespace")
		}
		probeChild(host, scratch, holder)
	default:
		say("error unknown probe role")
	}
	os.Exit(0)
}

// probeHolder runs in the scratch namespace.
func probeHolder(host uint64) {
	fail := func(why string) {
		fmt.Println("error " + why)
		os.Exit(0)
	}
	ino, err := nsInode()
	if err != nil || ino == host {
		fail("the scratch namespace is this command's own")
	}
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fail("cannot hold the scratch namespace: " + err.Error())
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Ino != ino {
		fail("the scratch namespace changed under the holder")
	}
	child := exec.Command("/proc/self/exe", PlaceProbeArg, "child", strconv.FormatUint(host, 10), strconv.FormatUint(ino, 10),
		strconv.Itoa(os.Getpid()))
	child.Env = []string{}
	child.ExtraFiles = []*os.File{os.NewFile(uintptr(fd), "the scratch namespace")}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	cin, err := child.StdinPipe()
	if err != nil {
		fail(err.Error())
	}
	cout, err := child.StdoutPipe()
	if err != nil {
		fail(err.Error())
	}
	if err := child.Start(); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && (errno == syscall.ENOSPC || errno == syscall.EPERM || errno == syscall.EUSERS) {
			fmt.Printf("nouserns %s\n", unix.ErrnoName(errno))
			os.Exit(0)
		}
		fail("cannot make a user namespace: " + err.Error())
	}
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(cout).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	var s string
	select {
	case s = <-line:
	case <-time.After(probeWait - time.Second):
		_ = child.Process.Kill()
		fail("the child did not answer")
	}
	if why, ok := strings.CutPrefix(s, "error "); ok {
		_ = child.Process.Kill()
		fail(why)
	}
	fields := strings.Fields(s)
	for i, kv := range fields {
		k, v, _ := strings.Cut(kv, "=")
		for _, a := range probeAsks {
			if a.key == k && v == "ok" {
				if _, err := ifIndex(a.peer); err == nil {
					fields[i] += ",seen"
				} else {
					fields[i] += ",unseen"
				}
			}
		}
	}
	fmt.Printf("child=%d %s\n", child.Process.Pid, strings.Join(fields, " "))
	// Held until this command closes its input (it has read the answer, or it is gone), then the child goes.
	_, _ = io.Copy(io.Discard, os.Stdin)
	cin.Close()
	done := make(chan struct{})
	go func() { _ = child.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = child.Process.Kill()
	}
}

// probeChild runs as root of its own user namespace, in a network namespace of that user namespace, with the scratch
// as fd 3 and the holder (in the scratch) as holder.
func probeChild(host, scratch uint64, holder int) {
	var st unix.Stat_t
	if unix.Fstat(3, &st) != nil || st.Ino != scratch || st.Ino == host {
		fmt.Println("error the namespace handed to the child is not the scratch")
		os.Exit(0)
	}
	own, err := nsInode()
	if err != nil || own == host || own == scratch {
		fmt.Println("error the child is not in a namespace of its own")
		os.Exit(0)
	}
	ownFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Println("error the child cannot hold its own namespace")
		os.Exit(0)
	}
	res := []string{"own-veth=" + resultName(addPair("veth", "wsown0", "wsown1", peerByFD(ownFD))),
		"own-netkit=" + resultName(addPair("netkit", "wsown2", "wsown3", peerByFD(ownFD)))}
	for i, a := range probeAsks {
		target := peerByFD(3)
		if a.by == "pid" {
			target = nlAttr(unix.IFLA_NET_NS_PID, u32(uint32(holder)))
		}
		res = append(res, a.key+"="+resultName(addPair(a.kind, fmt.Sprintf("wsprobe%d", 10+i), a.peer, target)))
	}
	fmt.Println(strings.Join(res, " "))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func peerByFD(fd int) []byte { return nlAttr(unix.IFLA_NET_NS_FD, u32(uint32(fd))) }

func resultName(err error) string {
	if err == nil {
		return "ok"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		if n := unix.ErrnoName(errno); n != "" {
			return n
		}
	}
	return strings.ReplaceAll(err.Error(), " ", "_")
}

// netkitL2 is NETKIT_L2 and ifaNetkitMode IFLA_NETKIT_MODE, from include/uapi/linux/if_link.h; the peer's
// attributes go in attribute 1 for both a veth (VETH_INFO_PEER) and a netkit (IFLA_NETKIT_PEER_INFO).
const (
	netkitL2      = 0
	ifaNetkitMode = 5
	peerInfoAttr  = 1
)

// addPair asks this namespace for a pair of kind: name here, its peer named peer in the namespace target names
// (an IFLA_NET_NS_FD or IFLA_NET_NS_PID attribute).
func addPair(kind, name, peer string, target []byte) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	peerMsg := append(ifinfo(0, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte(peer+"\x00"))...)
	peerMsg = append(peerMsg, target...)
	data := nlAttr(peerInfoAttr, peerMsg)
	if kind == "netkit" {
		data = append(data, nlAttr(ifaNetkitMode, u32(netkitL2))...)
	}
	info := append(nlAttr(unix.IFLA_INFO_KIND, []byte(kind)), nlAttr(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, data)...)
	body := append(ifinfo(0, 0, 0), nlAttr(unix.IFLA_IFNAME, []byte(name+"\x00"))...)
	body = append(body, nlAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	return r.do(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}
