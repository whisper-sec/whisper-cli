// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// networkd_root_linux_test.go runs the placed-device check against this kernel, as root, in the suite's own network
// namespace (the suite runs under `unshare -n`), and never touches a host's networkd: the configurations are the
// fixtures of networkd_test.go, and every device the probe makes lives in namespaces it makes and removes. What the
// probe says is held to what the measurement helper of contain_otherns_root_linux_test.go (otherNSOwner), root of a
// user namespace of its own, sees the kernel do.

const probeHangArg = "__whisper-placement-probe-hang"

// probeHang stands in for a holder that never answers.
func probeHang() {
	time.Sleep(time.Hour)
	os.Exit(0)
}

// freshProbe forgets any probe answer this process kept, and restores the probe's settings when the test ends.
func freshProbe(t *testing.T) {
	t.Helper()
	probeMu.Lock()
	oldKept, oldCount, oldWait, oldCmd := probeKept, probeCount, probeWait, placeProbeCommand
	probeKept, probeCount = nil, 0
	probeMu.Unlock()
	t.Cleanup(func() {
		probeMu.Lock()
		probeKept, probeCount, probeWait, placeProbeCommand = oldKept, oldCount, oldWait, oldCmd
		probeMu.Unlock()
	})
}

// ownerSays runs otherNSOwner, root of a user namespace of its own, with fd 3 this test's namespace, and
// returns what the kernel answered it, the far end it placed (if any) still in place until the test ends.
func ownerSays(t *testing.T) map[string]string {
	t.Helper()
	host, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostSock := os.NewFile(uintptr(sock), "a socket of the test's namespace")
	defer hostSock.Close()
	cmd := exec.Command(agentBinary(t), otherNSOwnerArg, "4000")
	cmd.Env = []string{testsLockedEnv + "=1"}
	cmd.ExtraFiles = []*os.File{host, hostSock}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outp, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the user namespace's root: %v", err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(outp).ReadString('\n')
		line <- strings.TrimSpace(l)
	}()
	got := map[string]string{}
	select {
	case out := <-line:
		t.Logf("the user namespace's root: %s", out)
		for _, kv := range strings.Fields(out) {
			k, v, _ := strings.Cut(kv, "=")
			got[k] = v
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the user namespace's root never answered")
	}
	return got
}

// linkWatch listens for new links in the namespace fd names (-1: this thread's), until stop, which returns the names
// of every link announced meanwhile.
func linkWatch(t *testing.T, nsFD int) (stop func() []string) {
	t.Helper()
	open := func() (int, error) {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if err != nil {
			return -1, err
		}
		if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
			unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	var fd int
	var err error
	if nsFD < 0 {
		fd, err = open()
	} else {
		err = onThreadIn(nsFD, func() error {
			var e error
			fd, e = open()
			return e
		})
	}
	if err != nil {
		t.Fatalf("cannot listen for new links: %v", err)
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000})
	var mu sync.Mutex
	var names []string
	lost := false
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buf := make([]byte, 1<<16)
		for {
			flags := 0
			select {
			case <-done:
				flags = unix.MSG_DONTWAIT // what is queued is still read, then it stops
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, flags)
			if err != nil {
				if errors.Is(err, unix.ENOBUFS) {
					mu.Lock()
					lost = true
					mu.Unlock()
					continue
				}
				if flags != 0 {
					return
				}
				continue
			}
			msgs, err := syscall.ParseNetlinkMessage(buf[:n])
			if err != nil {
				continue
			}
			for _, m := range msgs {
				if m.Header.Type != unix.RTM_NEWLINK || len(m.Data) < unix.SizeofIfInfomsg {
					continue
				}
				eachAttr(m.Data[unix.SizeofIfInfomsg:], func(typ uint16, val []byte) {
					if typ == unix.IFLA_IFNAME {
						mu.Lock()
						names = append(names, unix.ByteSliceToString(val))
						mu.Unlock()
					}
				})
			}
		}
	}()
	return func() []string {
		close(done)
		<-finished
		unix.Close(fd)
		mu.Lock()
		defer mu.Unlock()
		if lost {
			t.Error("the link watch lost announcements (ENOBUFS), so it cannot say none was made")
		}
		return names
	}
}

func probeNames(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "wsprobe") || strings.HasPrefix(n, "wsown") {
			out = append(out, n)
		}
	}
	return out
}

// gone waits for pid to be gone, a zombie being gone too once its parent reaps it.
func gone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// The probe answers what the kernel does, measured the other way by otherNSOwner: on a kernel that lets root of a
// user namespace of its own put a veth's far end in a namespace it holds no capability over, the probe says it saw
// the far end placed; on one that refuses, it says refused. It never puts a device in this test's namespace or in
// pid 1's, it leaves no process behind, and a clear answer is kept, so the second call runs nothing.
func TestTheProbeSaysWhatTheKernelDoes(t *testing.T) {
	needRoot(t)
	freshProbe(t)
	stopHere := linkWatch(t, -1)
	stopInit := linkWatch(t, nsFD(t, 1))
	start := time.Now()
	r := probePlacement()
	took := time.Since(start)
	holder, child := r.holder, r.child
	if here, init := probeNames(stopHere()), probeNames(stopInit()); len(here) > 0 || len(init) > 0 {
		t.Fatalf("the probe announced links in this test's namespace %v or in pid 1's %v", here, init)
	}
	t.Logf("probe answered %v (%q) in %s", r.kinds, r.why, took)
	if r.why != "" {
		t.Fatalf("the probe could not answer on this host: %s", r.why)
	}
	owner := ownerSays(t)
	switch owner["peer"] {
	case "ok":
		if r.kinds["veth"] != placedSeen {
			t.Fatalf("the kernel placed the helper's far end, but the probe says %v for a veth", r.kinds["veth"])
		}
	case "EPERM":
		if r.kinds["veth"] != placedRefused {
			t.Fatalf("the kernel refused the helper, but the probe says %v for a veth", r.kinds["veth"])
		}
	default:
		t.Fatalf("the helper got %q placing a far end", owner["peer"])
	}
	if a := r.kinds["netkit"]; a != placedAbsent && a != r.kinds["veth"] {
		t.Errorf("this kernel answers a netkit (%v) unlike a veth (%v), which takes the same path", a, r.kinds["veth"])
	}
	// Gone well inside the reaper's own deadline (probeWait): closing the holder's input ends it, and its child.
	if !gone(holder, probeWait*7/10) || (child > 0 && !gone(child, probeWait*7/10)) {
		t.Fatalf("the probe left its holder %d or child %d behind", holder, child)
	}
	if probePlacement(); probeCount != 1 {
		t.Fatalf("a clear answer was not kept: %d probes ran", probeCount)
	}
}

// A probe that does not answer is not taken for a refusal: every kind counts as placeable, the answer is not kept,
// and the process that did not answer is killed and reaped, within the probe's wait.
func TestAProbeThatDoesNotAnswerIsNeitherTrustedNorKept(t *testing.T) {
	needRoot(t)
	freshProbe(t)
	probeWait = 500 * time.Millisecond
	var cmd *exec.Cmd
	placeProbeCommand = func(uint64) *exec.Cmd {
		cmd = exec.Command("/proc/self/exe", probeHangArg)
		return cmd
	}
	start := time.Now()
	r := probePlacement()
	if took := time.Since(start); took > probeWait+time.Second {
		t.Fatalf("the probe took %s, past its wait", took)
	}
	if !strings.Contains(r.why, "did not answer") || len(r.placeable()) != len(placeKinds) {
		t.Fatalf("a probe that did not answer said %v (%q), placeable %v", r.kinds, r.why, r.placeable())
	}
	if probeKept != nil {
		t.Fatal("an answer that was not clear was kept")
	}
	if cmd == nil || cmd.Process == nil || !gone(cmd.Process.Pid, 3*time.Second) {
		t.Fatal("the process that did not answer was left running")
	}
	if probePlacement(); probeCount != 2 {
		t.Fatalf("an unclear answer was reused: %d probes ran", probeCount)
	}
}

// The probe's child ends with its holder however the holder ends, so a command killed during the probe leaves
// nothing: its namespace, and every device the child placed, goes with it.
func TestTheProbeChildEndsWithItsHolder(t *testing.T) {
	needRoot(t)
	host, err := nsInode()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/exe", PlaceProbeArg, "holder", strconv.FormatUint(host, 10))
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	line, _ := bufio.NewReader(out).ReadString('\n')
	t.Logf("holder: %s", strings.TrimSpace(line))
	var child int
	if _, err := fmt.Sscanf(line, "child=%d", &child); err != nil || child <= 0 {
		t.Fatalf("the holder said %q", line)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !gone(child, 3*time.Second) {
		t.Fatalf("the child %d outlived its holder", child)
	}
}

// fixtureNetworkd is one host networkd, not running, over a configuration root built from the fixtures.
func fixtureNetworkd(t *testing.T, root string) {
	t.Helper()
	old := findNetworkd
	findNetworkd = func(procStatus) ([]networkdInstance, error) {
		return []networkdInstance{{host: true, ownNS: true, why: "where a test stands one in", reader: networkdReader{root: root},
			facts: stockHost, taken: stockTaken}}, nil
	}
	t.Cleanup(func() { findNetworkd = old })
}

// The check, end to end on this kernel: over the stock configuration it refuses, naming the file, a device it takes
// and the fix, when this kernel places a far end in a namespace its creator holds no capability over; with the fix in
// place it passes. On a kernel that refuses, it passes either way.
func TestTheCheckRefusesWhereAPlacedDeviceWouldBeLetOut(t *testing.T) {
	needRoot(t)
	freshProbe(t)
	placed := ownerSays(t)["peer"] == "ok"
	st := procStatus{Name: "agent", Uids: [4]int{1000, 1000, 1000, 1000}}
	root := netRoot(t, nil)
	fixtureNetworkd(t, root)
	err := checkPlacedDevices(4242, st)
	if !placed {
		if err != nil {
			t.Fatalf("on a kernel that refuses the placement the check refused: %v", err)
		}
		t.Skip("this kernel refuses to place a far end in a namespace its creator holds no capability over")
	}
	if err == nil {
		t.Fatal("the stock configuration passed on a kernel that places far ends")
	}
	msg := err.Error()
	t.Logf("refusal: %s", msg)
	for _, want := range []string{"pid 4242 (agent) was not contained", "/usr/lib/systemd/network/80-container-ve.network",
		`named "ve-x"`, "IPMasquerade=both", "/usr/lib/systemd/network/80-container-vb.network", "allowed exactly that",
		unmanagedFixFile, "Unmanaged=yes", "7b735ef81286", "Nothing was changed", "`sudo whisper contain 4242`"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q", want)
		}
	}
	if strings.Contains(msg, "restart systemd-networkd") {
		t.Error("the refusal restarts a networkd that does not run, which would start it")
	}
	if strings.Contains(msg, "\u2014") {
		t.Error("the refusal has an em dash")
	}
	fixed := netRoot(t, map[string]string{"etc/systemd/network/" + unmanagedFixFile: "[Match]\nDriver=veth netkit\n\n[Link]\nUnmanaged=yes\n"})
	fixtureNetworkd(t, fixed)
	if err := checkPlacedDevices(4242, st); err != nil {
		t.Fatalf("with the fix in place: %v", err)
	}
	if probeCount != 1 {
		t.Fatalf("%d probes ran for one clear answer", probeCount)
	}
}

// A device placed before the containment counts: a veth that is up here with its far end in a network namespace of
// a user namespace a uid of the process owns refuses, for that uid only. One whose far end is in a namespace of the
// initial user namespace (a container a root daemon made) never does.
func TestADevicePlacedBeforeTheContainmentRefusesIt(t *testing.T) {
	needRoot(t)
	owned := exec.Command("/proc/self/exe", probeHangArg)
	owned.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		Pdeathsig:   syscall.SIGKILL,
	}
	plain := exec.Command("/proc/self/exe", probeHangArg)
	plain.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	for _, c := range []*exec.Cmd{owned, plain} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		c := c
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	}
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	for _, l := range []struct {
		name string
		cmd  *exec.Cmd
	}{{"wsplacedu", owned}, {"wsplacedp", plain}} {
		if err := addPair("veth", l.name, l.name+"x", peerByFD(nsFD(t, l.cmd.Process.Pid))); err != nil {
			t.Fatalf("a veth with its far end in pid %d's namespace: %v", l.cmd.Process.Pid, err)
		}
		name := l.name
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
		idx, err := ifIndex(l.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.setUp(idx); err != nil {
			t.Fatal(err)
		}
	}
	// The user namespace was made by root, so root owns it; a process of another user is not refused for it.
	if _, why, err := placedLinkUp(procStatus{Uids: [4]int{1234, 1234, 1234, 1234}}); why != "" || err != nil {
		t.Fatalf("refused for a device another user's namespace holds: %s", why)
	}
	link, why, _ := placedLinkUp(procStatus{Uids: [4]int{1234, 0, 1234, 1234}})
	if link != "wsplacedu" || !strings.Contains(why, "wsplacedu") || !strings.Contains(why, "uid 0") {
		t.Fatalf("a device up here with its far end in a namespace the process's user owns was not named: %q", why)
	}
	if strings.Contains(why, "wsplacedp") {
		t.Fatalf("a device whose far end is in a namespace of the initial user namespace was named: %q", why)
	}
	if err := r.do(unix.RTM_NEWLINK, 0, ifinfo(mustIndex(t, "wsplacedu"), 0, unix.IFF_UP)); err != nil {
		t.Fatal(err)
	}
	if _, why, _ := placedLinkUp(procStatus{Uids: [4]int{0, 0, 0, 0}}); why != "" {
		t.Fatalf("a device that is down was named: %s", why)
	}
}

func mustIndex(t *testing.T, name string) int {
	t.Helper()
	i, err := ifIndex(name)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// The detection, against this host's own networkd if it runs one: from the suite's namespace it is a networkd of the
// host (PID 1's mount namespace), of another network namespace, read through its own root, and a process is not
// taken for it by its command name alone.
func TestTheHostsNetworkdIsFoundFromAnotherNamespace(t *testing.T) {
	needRoot(t)
	out, _ := exec.Command("pgrep", "-x", "systemd-network").Output()
	pid, _ := strconv.Atoi(strings.Fields(string(out) + " 0")[0])
	if pid == 0 {
		t.Skip("no systemd-networkd runs on this host")
	}
	if !isNetworkd(pid) || isNetworkd(os.Getpid()) {
		t.Fatalf("isNetworkd(%d) = %v, isNetworkd(self) = %v", pid, isNetworkd(pid), isNetworkd(os.Getpid()))
	}
	instances, err := networkdInstances(procStatus{Uids: [4]int{1234, 1234, 1234, 1234}})
	if err != nil {
		t.Fatal(err)
	}
	var found *networkdInstance
	for i := range instances {
		if instances[i].pid == pid {
			found = &instances[i]
		}
	}
	if found == nil {
		t.Fatalf("the host's networkd (pid %d) was not found among %d", pid, len(instances))
	}
	if !found.host || found.ownNS || found.reader.root != fmt.Sprintf("%s/%d/root", procRoot, pid) {
		t.Fatalf("the host's networkd was judged as host=%v own=%v root=%q", found.host, found.ownNS, found.reader.root)
	}
	if !strings.Contains(found.where(), "network namespace of pid") {
		t.Fatalf("it is described as %q", found.where())
	}
	if _, err := loadNetworkFiles(found.reader); err != nil {
		t.Fatalf("its files cannot be read through its root: %v", err)
	}
}

var _ = binary.NativeEndian

// A device whose far end is in a namespace nothing can name any more (no process is in it, no descriptor or mount
// names it; a socket made there keeps it alive) cannot be traced to its owner, and refuses.
func TestADeviceWhoseFarEndCannotBeTracedRefuses(t *testing.T) {
	needRoot(t)
	holder := exec.Command("/proc/self/exe", probeHangArg)
	holder.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", holder.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := addPair("veth", "wsplacedt", "wsplacedtx", peerByFD(fd)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "wsplacedt").Run() })
	var sock int
	if err := onThreadIn(fd, func() error {
		var e error
		sock, e = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(sock) })
	unix.Close(fd)
	_ = holder.Process.Kill()
	_ = holder.Wait()
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.setUp(mustIndex(t, "wsplacedt")); err != nil {
		t.Fatal(err)
	}
	link, why, err := placedLinkUp(procStatus{Uids: [4]int{1234, 1234, 1234, 1234}})
	if err != nil || link != "wsplacedt" || !strings.Contains(why, "cannot trace") {
		t.Fatalf("a device whose far end cannot be traced: %q %q %v", link, why, err)
	}
}

const fakeNetworkdArg = "__whisper-fake-networkd"

// fakeNetworkd stands in for a container's networkd: it roots itself at os.Args[2] and waits for its input to close.
func fakeNetworkd() {
	if err := syscall.Chroot(os.Args[2]); err != nil {
		fmt.Println("err " + err.Error())
		os.Exit(1)
	}
	_ = os.Chdir("/")
	fmt.Println("ok")
	b := make([]byte, 1)
	_, _ = os.Stdin.Read(b)
	os.Exit(0)
}

// A networkd in a container of its own (a pid, mount and network namespace, rooted at a configuration holding the
// stock files, marked an LXC container) is found as one, judged as it judges itself (Virtualization= container,
// names taken in its own namespace, its own forwarding), and refused with a fix entered through the container's init.
func TestAContainersNetworkdIsJudgedAndFixedFromItsInit(t *testing.T) {
	needRoot(t)
	freshProbe(t)
	if ownerSays(t)["peer"] != "ok" {
		t.Skip("this kernel refuses to place a far end in a namespace its creator holds no capability over")
	}
	root := netRoot(t, map[string]string{"run/systemd/container": "lxc\n"})
	bin := filepath.Join(t.TempDir(), "systemd-networkd")
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, fakeNetworkdArg, root)
	cmd.Env = []string{testsLockedEnv + "=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		Pdeathsig: syscall.SIGKILL}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	if l, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(l) != "ok" {
		t.Fatalf("the stand-in networkd said %q", l)
	}
	pid := cmd.Process.Pid
	st := procStatus{Name: "agent", Uids: [4]int{1234, 1234, 1234, 1234}}
	instances, err := networkdInstances(st)
	if err != nil {
		t.Fatal(err)
	}
	var found *networkdInstance
	for i := range instances {
		if instances[i].pid == pid {
			found = &instances[i]
		}
	}
	if found == nil {
		t.Fatalf("the container's networkd (pid %d) was not found", pid)
	}
	// A new namespace takes IPv4 forwarding from the initial one, as this test's own namespace did.
	// Its namespace holds loopback and whatever fallback tunnel devices loaded modules put in every new namespace.
	takenOK := found.taken["lo"]
	for n := range found.taken {
		takenOK = takenOK && (n == "lo" || isFallbackName(n))
	}
	if found.host || found.ownNS || found.initPid != pid || found.facts.container != "lxc" || !takenOK ||
		found.fwd.v4 != sysctlOn("/proc/sys/net/ipv4/conf/default/forwarding") {
		t.Fatalf("judged as host=%v own=%v init=%d container=%q taken=%v fwd=%+v", found.host, found.ownNS, found.initPid,
			found.facts.container, found.taken, found.fwd)
	}
	err = checkPlacedDevices(4242, st)
	if err == nil {
		t.Fatal("a container networkd that masquerades a placed ve-* device was not refused")
	}
	msg := err.Error()
	for _, want := range []string{fmt.Sprintf("(networkd pid %d)", pid), "80-container-ve.network",
		fmt.Sprintf("sudo nsenter -t %d -a -- sh -c 'mkdir -p /etc/systemd/network && ", pid),
		"ln -s /dev/null /etc/systemd/network/80-container-ve.network", "&& systemctl restart systemd-networkd'",
		"A container started after this check is not judged"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q\n%s", want, msg)
		}
	}
}

// A process named systemd-networkd in a user namespace of its own, beside this namespace (any user can start one,
// with a harmless configuration mounted over the real one), configures nothing here: it is not taken for this
// namespace's networkd, and so cannot stand in for the one that would start.
func TestANetworkdOfAnotherUserNamespaceIsNotThisNamespaces(t *testing.T) {
	needRoot(t)
	root := netRoot(t, nil)
	bin := filepath.Join(t.TempDir(), "systemd-networkd")
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, fakeNetworkdArg, root)
	cmd.Env = []string{testsLockedEnv + "=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		Pdeathsig:   syscall.SIGKILL}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = cmd.Wait() })
	if l, _ := bufio.NewReader(out).ReadString('\n'); strings.TrimSpace(l) != "ok" {
		t.Fatalf("the stand-in said %q", l)
	}
	if !isNetworkd(cmd.Process.Pid) || managesItsNamespace(cmd.Process.Pid) {
		t.Fatalf("isNetworkd %v, managesItsNamespace %v", isNetworkd(cmd.Process.Pid), managesItsNamespace(cmd.Process.Pid))
	}
	instances, err := networkdInstances(procStatus{Uids: [4]int{1234, 1234, 1234, 1234}})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range instances {
		if in.pid == cmd.Process.Pid {
			t.Fatalf("the stand-in in a user namespace of its own was judged as %s", in.where())
		}
	}
	if !managesItsNamespace(os.Getpid()) {
		t.Fatal("control: this test, in the user namespace that owns its network namespace, does not count")
	}
}
