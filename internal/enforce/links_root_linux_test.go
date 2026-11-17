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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// links_root_linux_test.go runs the place rule as root against real namespaces, on a host whose tunnel modules put
// their fallback devices in every new namespace: the agent starts beside them and cannot touch them, anything that
// configured one refuses the start, and contain counts a sandbox that holds them as reaching nothing. Run it in a
// network namespace of its own (unshare -n) or not, as the other root suites.

// fallbackProbeArg runs this binary as the agent's probe of the fallback devices (fallbackProbe), and
// sandboxHelperArg as a sandboxed child in a user and network namespace of its own (sandboxHelper).
const (
	fallbackProbeArg = "__whisper-fallback-probe"
	sandboxHelperArg = "__whisper-sandbox-helper"
)

// testModules is what this run loaded, so that it unloads exactly that when it ends: a tunnel module left loaded
// puts its devices in every namespace made afterwards on the host. testModulesFile, beside the host-wide test lock,
// holds the same list while it is loaded, so the next run that takes the lock unloads what a run that was killed or
// timed out could not.
var testModules struct {
	sync.Mutex
	before map[string]bool
	loaded []string
}

const testModulesFile = "/run/whisper-enforce-tests.modules"

// testTunnelModules are what WHISPER_TEST_LOAD_TUNNELS=1 loads.
var testTunnelModules = []string{"ip6_tunnel", "sit"}

func procModules() map[string]bool {
	out := map[string]bool{}
	b, _ := os.ReadFile("/proc/modules")
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

// moduleDeps is every module modprobe would load for mods, by the name /proc/modules gives it.
func moduleDeps(mods ...string) map[string]bool {
	out := map[string]bool{}
	for _, m := range mods {
		out[strings.ReplaceAll(m, "-", "_")] = true
		b, _ := exec.Command("modprobe", "--show-depends", m).Output()
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "insmod" {
				continue
			}
			name := filepath.Base(f[1])
			if i := strings.Index(name, ".ko"); i > 0 {
				out[strings.ReplaceAll(name[:i], "-", "_")] = true
			}
		}
	}
	return out
}

func loadTestModules(t *testing.T, mods ...string) {
	t.Helper()
	testModules.Lock()
	defer testModules.Unlock()
	if testModules.before == nil {
		testModules.before = procModules()
	}
	for _, m := range mods {
		if out, err := exec.Command("modprobe", m).CombinedOutput(); err != nil {
			t.Fatalf("WHISPER_TEST_LOAD_TUNNELS=1, and modprobe %s failed: %v %s", m, err, out)
		}
	}
	// Only what these modules pull in: a module another process loaded meanwhile is not this run's to unload.
	deps := moduleDeps(mods...)
	for m := range procModules() {
		if deps[m] && !testModules.before[m] && !contains(testModules.loaded, m) {
			testModules.loaded = append(testModules.loaded, m)
		}
	}
	_ = os.WriteFile(testModulesFile, []byte(strings.Join(testModules.loaded, "\n")+"\n"), 0o600)
}

// unloadModules unloads mods, in passes, since a module goes only once nothing uses it, and returns what it could
// not.
func unloadModules(mods []string) []string {
	left := mods
	for pass := 0; pass < 6 && len(left) > 0; pass++ {
		var still []string
		for _, m := range left {
			if exec.Command("rmmod", m).Run() != nil && procModules()[m] {
				still = append(still, m)
			}
		}
		left = still
	}
	return left
}

// unloadTestModules unloads what the run loaded and says what it could not, which stays in testModulesFile.
func unloadTestModules() {
	testModules.Lock()
	defer testModules.Unlock()
	if len(testModules.loaded) == 0 {
		return
	}
	if left := unloadModules(testModules.loaded); len(left) > 0 {
		_ = os.WriteFile(testModulesFile, []byte(strings.Join(left, "\n")+"\n"), 0o600)
		fmt.Fprintf(os.Stderr, "the run loaded and could not unload: %s (listed in %s for the next run)\n", strings.Join(left, " "), testModulesFile)
		return
	}
	_ = os.Remove(testModulesFile)
}

// unloadLeftModules unloads what an earlier run listed in testModulesFile and never unloaded, of the modules this
// suite loads and theirs only.
func unloadLeftModules() {
	b, err := os.ReadFile(testModulesFile)
	if err != nil {
		return
	}
	deps := moduleDeps(testTunnelModules...)
	var mods []string
	for _, m := range strings.Fields(string(b)) {
		if deps[m] && procModules()[m] {
			mods = append(mods, m)
		}
	}
	if left := unloadModules(mods); len(left) > 0 {
		fmt.Fprintf(os.Stderr, "an earlier run loaded and this one could not unload: %s\n", strings.Join(left, " "))
		return
	}
	_ = os.Remove(testModulesFile)
}

// newNamespaceFD is a descriptor for a new network namespace, held by a process made in it for the purpose and
// ended at the end of the test.
func newNamespaceFD(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start a process in a namespace of its own: %v", err)
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// inFreshNamespace runs fn on a thread in a new network namespace, which ends once the thread is back.
func inFreshNamespace(t *testing.T, fn func() error) {
	t.Helper()
	if err := onThreadIn(newNamespaceFD(t), fn); err != nil {
		t.Fatal(err)
	}
}

// freshNames lists, sorted, the links a new namespace starts with on this host.
func freshNames(t *testing.T) []string {
	t.Helper()
	var names []string
	inFreshNamespace(t, func() error {
		v, err := readLinkView()
		for _, l := range v.links {
			names = append(names, l.name)
		}
		return err
	})
	sort.Strings(names)
	return names
}

func fallbackLinks(v linkView) []nlLink {
	var out []nlLink
	for _, l := range v.links {
		if d, ok := fallbackDevices[l.kind]; ok && d.name == l.name {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].index < out[j].index })
	return out
}

// needFallbackDevices skips unless a new namespace on this host starts with a fallback device. With
// WHISPER_TEST_LOAD_TUNNELS=1 the run loads ip6_tunnel and sit to make it so, unloads them when it ends, and fails
// rather than skips if that does not.
func needFallbackDevices(t *testing.T) {
	t.Helper()
	has := func() bool {
		for _, n := range freshNames(t) {
			if isFallbackName(n) {
				return true
			}
		}
		return false
	}
	if has() {
		return
	}
	if b, err := os.ReadFile("/proc/sys/net/core/fb_tunnels_only_for_init_net"); err == nil && strings.TrimSpace(string(b)) != "0" {
		t.Skipf("this host keeps fallback devices out of new namespaces (net.core.fb_tunnels_only_for_init_net=%s)", strings.TrimSpace(string(b)))
	}
	if os.Getenv("WHISPER_TEST_LOAD_TUNNELS") != "1" {
		t.Skip("needs a tunnel module loaded (WHISPER_TEST_LOAD_TUNNELS=1 lets the run load ip6_tunnel and sit, and unload them when it ends)")
	}
	loadTestModules(t, testTunnelModules...)
	if !has() {
		t.Fatal("ip6_tunnel and sit are loaded and a new namespace still holds no fallback device")
	}
}

// agentBinary is a copy of this test binary that the agent's user can run: go test builds into a directory only
// root can enter.
func agentBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "whisper-enforce-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "enforce.test")
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// captureFile runs fn with *which (os.Stdout or os.Stderr) pointed into a pipe, and returns what was written.
func captureFile(t *testing.T, which **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	saved := *which
	*which = w
	fn()
	*which = saved
	w.Close()
	out := <-done
	r.Close()
	return string(out)
}

func errName(err error) string {
	var en unix.Errno
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &en):
		return unix.ErrnoName(en)
	}
	return strings.ReplaceAll(err.Error(), " ", "_")
}

// txPackets is a link's IFLA_STATS64 tx_packets, read in the calling thread's namespace.
func txPackets(index int32) uint64 {
	r, err := openRTNL()
	if err != nil {
		return ^uint64(0)
	}
	defer r.close()
	n := ^uint64(0)
	_ = r.dump(unix.RTM_GETLINK, ifinfo(0, 0, 0), func(data []byte) {
		if len(data) < unix.SizeofIfInfomsg || int32(binary.NativeEndian.Uint32(data[4:8])) != index {
			return
		}
		eachAttr(data[unix.SizeofIfInfomsg:], func(typ uint16, val []byte) {
			if typ == unix.IFLA_STATS64 && len(val) >= 16 {
				n = binary.NativeEndian.Uint64(val[8:16])
			}
		})
	})
	return n
}

// probeFallbackDevice tries, as the calling process, every way to make a fallback device carry a packet: bring it up,
// address it, route through it (rtnetlink); bring it up (ioctl); reconfigure it as a tunnel (SIOCCHGTUNNEL); and
// send from a UDP socket bound to it, of each family, counting what it transmitted.
func probeFallbackDevice(l nlLink) string {
	var parts []string
	try := func(name string, err error) { parts = append(parts, name+"="+errName(err)) }
	r, err := openRTNL()
	if err != nil {
		return "rtnl=" + errName(err)
	}
	defer r.close()
	try("up", r.setUp(int(l.index)))
	try("addr", r.addAddr(int(l.index), netip.MustParseAddr("2001:db8::99")))
	var m unix.RtMsg
	m.Family, m.Dst_len, m.Table, m.Protocol, m.Type = unix.AF_INET6, 48, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RTN_UNICAST
	body := append([]byte(nil), (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.RTA_DST, netip.MustParseAddr("2001:db8:99::").AsSlice())...)
	body = append(body, nlAttr(unix.RTA_OIF, u32(uint32(l.index)))...)
	try("route", r.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body))
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		ifr, _ := unix.NewIfreq(l.name)
		ifr.SetUint16(unix.IFF_UP | unix.IFF_NOARP)
		try("ifflags", unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr))
		parm := make([]byte, 256) // larger than any tunnel's parameter block, zero but its name
		copy(parm, l.name)
		var req struct {
			name [unix.IFNAMSIZ]byte
			data unsafe.Pointer
			_    [16]byte
		}
		copy(req.name[:], l.name)
		req.data = unsafe.Pointer(&parm[0])
		_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCDEVPRIVATE+3, uintptr(unsafe.Pointer(&req))) // SIOCCHGTUNNEL
		runtime.KeepAlive(parm)
		var terr error
		if e != 0 {
			terr = e
		}
		try("tunnel", terr)
		unix.Close(fd)
	}
	before := txPackets(l.index)
	send := func(family int, sa unix.Sockaddr) error {
		s, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(s)
		if err := unix.SetsockoptString(s, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, l.name); err != nil {
			return fmt.Errorf("bind %w", err)
		}
		return unix.Sendto(s, []byte("probe"), 0, sa)
	}
	try("udp4", send(unix.AF_INET, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{192, 0, 2, 1}}))
	try("udp6", send(unix.AF_INET6, &unix.SockaddrInet6{Port: 9, Addr: netip.MustParseAddr("2001:db8::1").As16()}))
	time.Sleep(50 * time.Millisecond)
	parts = append(parts, fmt.Sprintf("tx=%d->%d", before, txPackets(l.index)))
	return strings.Join(parts, " ")
}

// ownNamespaceControl proves this process holds a usable CAP_NET_ADMIN in its own user namespace: it makes a
// network namespace there and brings its loopback up. Without that, a refusal elsewhere proves nothing about why.
func ownNamespaceControl() error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the probe process ends right after
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- err
			return
		}
		r, err := openRTNL()
		if err != nil {
			ch <- err
			return
		}
		defer r.close()
		idx, err := ifIndex("lo")
		if err != nil {
			ch <- err
			return
		}
		ch <- r.setUp(idx)
	}()
	return <-ch
}

// fallbackProbe runs as the agent. It prints "inside=" and InsideEnforced, then "dev <name> <results>" for each
// fallback device of its namespace, then runs itself again as root of a user namespace of its own (which the
// default seccomp mode allows) and passes that leg's lines on after "nested ", with "control=" saying whether that
// leg could use its capabilities at all.
func fallbackProbe() {
	nested := len(os.Args) > 2 && os.Args[2] == "nested"
	v, err := readLinkView()
	if err != nil {
		fmt.Printf("view-error %s\n", errName(err))
		os.Exit(3)
	}
	if nested {
		fmt.Printf("control=%s\n", errName(ownNamespaceControl()))
	} else {
		fmt.Printf("inside=%v\n", InsideEnforced())
	}
	for _, l := range fallbackLinks(v) {
		fmt.Printf("dev %s %s\n", l.name, probeFallbackDevice(l))
	}
	if !nested {
		self, _ := os.Executable()
		cmd := exec.Command(self, fallbackProbeArg, "nested")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("nested-error %s\n", errName(err))
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				fmt.Println("nested " + line)
			}
		}
	}
	os.Exit(0)
}

// sandboxHelper is a sandboxed child: root of a user namespace of its own, which owns its network namespace, as a
// browser's renderer is. With "up" it brings its first fallback device up; with "tun:<name>" it makes a TUN of that
// name; then it prints "ready" and waits for its stdin to close.
func sandboxHelper() {
	mode := ""
	if len(os.Args) > 2 {
		mode = os.Args[2]
	}
	var keep tun.Device
	switch {
	case mode == "up":
		v, err := readLinkView()
		fl := fallbackLinks(v)
		if err != nil || len(fl) == 0 {
			fmt.Printf("no fallback device to bring up: %v\n", err)
			os.Exit(3)
		}
		r, err := openRTNL()
		if err == nil {
			err = r.setUp(int(fl[0].index))
		}
		if err != nil {
			fmt.Printf("cannot bring %s up: %v\n", fl[0].name, err)
			os.Exit(3)
		}
	case strings.HasPrefix(mode, "tun:"):
		dev, err := openTUN(strings.TrimPrefix(mode, "tun:"), 0)
		if err != nil {
			fmt.Printf("cannot make the TUN: %v\n", err)
			os.Exit(3)
		}
		keep = dev
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	if keep != nil {
		keep.Close()
	}
	os.Exit(0)
}

// startSandbox starts sandboxHelper in mode, mapped to the nobody user, and returns its pid and how to end it.
func startSandbox(t *testing.T, bin, mode string) (int, func()) {
	t.Helper()
	cmd := exec.Command(bin, sandboxHelperArg, mode)
	// Root of its own user namespace, mapped to root: a host that keeps capabilities out of user namespaces made by
	// unprivileged users (Ubuntu's AppArmor restriction) still lets this one use them. No parent-death signal: the
	// kernel ties it to the thread that started the child, and a Go thread can end while the child should live.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start the sandbox: %v", err)
	}
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	var once sync.Once
	stop := func() { once.Do(func() { in.Close(); _ = cmd.Wait() }) }
	t.Cleanup(func() { _ = cmd.Process.Kill(); stop() })
	select {
	case l := <-line:
		if l != "ready" {
			stop()
			t.Fatalf("the sandbox (%s) said %q", mode, l)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		stop()
		t.Fatalf("the sandbox (%s) never got ready", mode)
	}
	return cmd.Process.Pid, stop
}

// A routing socket takes unicast from the kernel alone: another socket's datagram, which an unconnected socket
// takes (the control), is refused.
func TestARoutingSocketTakesUnicastOnlyFromTheKernel(t *testing.T) {
	needRoot(t)
	sender, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sender)
	if err := unix.Bind(sender, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	portOf := func(fd int) uint32 {
		sa, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		return sa.(*unix.SockaddrNetlink).Pid
	}
	forged := nlMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, 1, nlStatus(0))
	plain, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(plain)
	if err := unix.Bind(plain, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(sender, forged, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: portOf(plain)}); err != nil {
		t.Fatalf("control: an unconnected routing socket must take another socket's datagram, got %v", err)
	}
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := unix.Sendto(sender, forged, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: portOf(r.fd)}); !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("a forged answer sent to the routing socket: %v, want ECONNREFUSED", err)
	}
}

// The issue itself: on a host whose tunnel modules put their fallback devices in every namespace, the agent
// starts, which it never did. Running as the agent, with the default seccomp mode and with none, it cannot bring a
// fallback device up, address it, route through it, reconfigure it or send a packet through it; neither can it as
// root of a user namespace of its own, where the host lets that leg use its capabilities. And `whisper ip`, inside,
// knows where it is.
func TestAnIdleFallbackDeviceDoesNotStopTheAgent(t *testing.T) {
	needRoot(t)
	needFallbackDevices(t)
	l := startNS(t)
	var v linkView
	if err := l.ns.run(func() (err error) { v, err = readLinkView("lo", IfName); return }); err != nil {
		t.Fatal(err)
	}
	fl := fallbackLinks(v)
	if len(fl) == 0 {
		t.Fatalf("the agent's namespace holds no fallback device: %+v", v.links)
	}
	if err := agentPlaceError(v); err != nil {
		t.Fatalf("the agent's own namespace is refused: %v", err)
	}
	bin := agentBinary(t)
	for _, mode := range []string{SeccompDefault, SeccompOff} {
		var code int
		var serr error
		out := captureFile(t, &os.Stdout, func() {
			code, serr = l.ns.Spawn(Spec{Path: bin, Args: []string{bin, fallbackProbeArg}, Env: []string{"PATH=/usr/bin:/bin"},
				Dir: "/", UID: 65534, GID: 65534, Groups: []uint32{65534}, Resolvers: []string{tResolver.String()}, Seccomp: mode}, nil)
		})
		t.Logf("seccomp %s, the agent saw:\n%s", mode, out)
		if serr != nil || code != 0 {
			t.Fatalf("seccomp %s: the agent did not start and finish (code %d, %v)", mode, code, serr)
		}
		if !strings.Contains(out, "inside=true\n") {
			t.Errorf("seccomp %s: InsideEnforced is not true inside the agent", mode)
		}
		lines := map[string]string{}
		control := ""
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) >= 3 && f[0] == "dev":
				lines[f[1]] = line
			case len(f) >= 4 && f[0] == "nested" && f[1] == "dev":
				lines["nested "+f[2]] = line
			case strings.HasPrefix(line, "nested control="):
				control = strings.TrimPrefix(line, "nested control=")
			}
		}
		check := func(key, line string) {
			for _, want := range []string{" up=EPERM", " addr=EPERM", " route=EPERM", " ifflags=EPERM"} {
				if !strings.Contains(line, want) {
					t.Errorf("seccomp %s, %s: want%s in %q", mode, key, want, line)
				}
			}
			if !strings.Contains(line, " tunnel=EPERM") && !strings.Contains(line, " tunnel=EOPNOTSUPP") {
				t.Errorf("seccomp %s, %s: the tunnel ioctl was not refused: %q", mode, key, line)
			}
			if i := strings.Index(line, " tx="); i < 0 {
				t.Errorf("seccomp %s, %s: no count of what it sent: %q", mode, key, line)
			} else if a, b, _ := strings.Cut(line[i+4:], "->"); a != b {
				t.Errorf("seccomp %s, %s: the device transmitted (%s): %q", mode, key, line[i+4:], line)
			}
		}
		for _, d := range fl {
			line, ok := lines[d.name]
			if !ok {
				t.Errorf("seccomp %s: the agent did not probe %s", mode, d.name)
				continue
			}
			check(d.name, line)
			if control == "ok" {
				check("nested "+d.name, lines["nested "+d.name])
			}
		}
		if control != "ok" {
			if os.Getenv("WHISPER_TEST_REQUIRE_NESTED") == "1" {
				t.Fatalf("seccomp %s: WHISPER_TEST_REQUIRE_NESTED=1, and the nested user namespace could not use its capabilities (control=%q)", mode, control)
			}
			t.Logf("seccomp %s: the nested user namespace could not use its capabilities here (control=%q), so that leg proves nothing on this host", mode, control)
		}
	}
}

// A fallback device that something has configured refuses the start, naming the device, its kind and what was
// done to it, with the advice that goes with a fallback device.
func TestAFallbackDeviceSomethingConfiguredStopsTheAgent(t *testing.T) {
	needRoot(t)
	needFallbackDevices(t)
	l := startNS(t)
	var up, addressed nlLink
	err := l.ns.run(func() error {
		v, err := readLinkView("lo", IfName)
		if err != nil {
			return err
		}
		fl := fallbackLinks(v)
		if len(fl) == 0 {
			return errors.New("no fallback device in the agent's namespace")
		}
		up, addressed = fl[0], fl[len(fl)-1]
		r, err := openRTNL()
		if err != nil {
			return err
		}
		defer r.close()
		if err := r.setUp(int(up.index)); err != nil {
			return err
		}
		if addressed.index != up.index {
			return r.addAddr(int(addressed.index), netip.MustParseAddr("2001:db8::7"))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var code int
	var serr error
	errOut := captureFile(t, &os.Stderr, func() {
		code, serr = l.ns.Spawn(Spec{Path: "/bin/true", Args: []string{"true"}, Dir: "/", UID: 65534, GID: 65534}, nil)
	})
	t.Logf("init said: %s", errOut)
	if serr != nil || code != ExitSetup {
		t.Fatalf("a configured fallback device must refuse the start with %d: code %d, %v", ExitSetup, code, serr)
	}
	wants := []string{up.name + " (" + up.kind, "is up", "something else on this host did", "fb_tunnels_only_for_init_net=1", "sudo modprobe -r", "the agent was not started"}
	if addressed.index != up.index {
		wants = append(wants, addressed.name+" ("+addressed.kind)
	}
	for _, want := range wants {
		if !strings.Contains(errOut, want) {
			t.Errorf("the refusal does not say %q", want)
		}
	}
}

// An interface the kernel did not make, here a second TUN, refuses the start by name, with no advice about the
// kernel's tunnel devices. It needs no tunnel module.
func TestAnInterfaceTheKernelDidNotMakeStopsTheAgent(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	var dev tun.Device
	if err := l.ns.run(func() (err error) { dev, err = openTUN("stray0", 0); return }); err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	var code int
	var serr error
	errOut := captureFile(t, &os.Stderr, func() {
		code, serr = l.ns.Spawn(Spec{Path: "/bin/true", Args: []string{"true"}, Dir: "/", UID: 65534, GID: 65534}, nil)
	})
	t.Logf("init said: %s", errOut)
	if serr != nil || code != ExitSetup {
		t.Fatalf("a second TUN must refuse the start with %d: code %d, %v", ExitSetup, code, serr)
	}
	if !strings.Contains(errOut, "stray0 (tun) is not a device the kernel makes in every namespace") || strings.Contains(errOut, "fb_tunnels_only_for_init_net") {
		t.Fatalf("the refusal: %s", errOut)
	}
}

// contain counts a sandbox (root of a user namespace that owns its network namespace) as reaching nothing past
// loopback when its namespace holds loopback and idle fallback devices, and not once it has brought one up or
// holds anything else, a TUN named with a '|' included.
func TestASandboxHoldingOnlyIdleFallbackDevicesReachesNothing(t *testing.T) {
	needRoot(t)
	needFallbackDevices(t)
	bin := agentBinary(t)
	for _, c := range []struct {
		mode string
		want bool
	}{{"", true}, {"up", false}, {"tun:v|0", false}, {"tun:stray0", false}} {
		pid, stop := startSandbox(t, bin, c.mode)
		got := loopbackOnly(pid)
		stop()
		if got != c.want {
			t.Errorf("a sandbox (%q): loopbackOnly %v, want %v", c.mode, got, c.want)
		}
	}
}

// Reading a sandbox's namespace, a hundred times at once, leaves no thread of this process in it, and ends none.
func TestReadingAnotherNamespaceLeavesNoThreadInIt(t *testing.T) {
	needRoot(t)
	pid, stop := startSandbox(t, agentBinary(t), "")
	defer stop()
	// Each thread's namespace before the reads. A thread an earlier test left somewhere (the main thread, parked) is
	// not this test's business; one the reads moved, or a new one that is not in this test's namespace, is.
	var host unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &host); err != nil {
		t.Fatal(err)
	}
	threadNS := func() map[string]unix.Stat_t {
		out := map[string]unix.Stat_t{}
		tasks, _ := os.ReadDir("/proc/self/task")
		for _, task := range tasks {
			var st unix.Stat_t
			if unix.Stat(filepath.Join("/proc/self/task", task.Name(), "ns", "net"), &st) == nil {
				out[task.Name()] = st
			}
		}
		return out
	}
	before := threadNS()
	// A child with a parent-death signal, as the attribution probe has, started from whatever thread this goroutine
	// is on: the kernel kills it when that thread ends. Before the reads went home, they ended theirs, and this died
	// in most runs.
	sleeper := exec.Command("sleep", "60")
	sleeper.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := sleeper.Start(); err != nil {
		t.Skipf("needs sleep(1): %v", err)
	}
	defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	var wg sync.WaitGroup
	var read atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if loopbackOnly(pid) {
				read.Add(1)
			}
		}()
	}
	wg.Wait()
	// Every read entered the namespace and read it: a sandbox that holds loopback and nothing else but idle
	// fallback devices reaches nothing. A read that failed before it entered would make the rest of this vacuous.
	if read.Load() != 100 {
		t.Fatalf("%d of 100 reads of the sandbox's namespace counted it as reaching nothing", read.Load())
	}
	if err := sleeper.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("a child with a parent-death signal died during the reads: %v", err)
	}
	// Every thread is back at once: none is left to end, and none, the main thread above all, is parked there.
	var strays []string
	for tid, st := range threadNS() {
		was, ok := before[tid]
		if ok && (st.Dev != was.Dev || st.Ino != was.Ino) || !ok && (st.Dev != host.Dev || st.Ino != host.Ino) {
			strays = append(strays, tid)
		}
	}
	if len(strays) > 0 {
		t.Fatalf("threads %v of this process were moved into another namespace and left there", strays)
	}
}

// The thread a read of another namespace runs on is handed back: after onThreadIn returns, that very thread is
// alive and in the namespace it started in. A thread left locked would end (or, the main thread, stay parked inside
// the other namespace), which this sees every time, where the test above sees it only when the timing falls so.
func TestTheThreadThatEnteredAnotherNamespaceComesBack(t *testing.T) {
	needRoot(t)
	var home unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &home); err != nil {
		t.Fatal(err)
	}
	fd := newNamespaceFD(t)
	for i := 0; i < 20; i++ {
		tid := 0
		var inside unix.Stat_t
		err := onThreadIn(fd, func() error {
			tid = unix.Gettid()
			return unix.Stat("/proc/thread-self/ns/net", &inside)
		})
		if err != nil {
			t.Fatal(err)
		}
		if inside.Ino == home.Ino {
			t.Fatal("control: fn did not run in another namespace")
		}
		path := filepath.Join("/proc/self/task", strconv.Itoa(tid), "ns", "net")
		var st unix.Stat_t
		ok := false
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if unix.Stat(path, &st) == nil && st.Dev == home.Dev && st.Ino == home.Ino {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("thread %d is gone or not back in its namespace after onThreadIn (now %v)", tid, st.Ino)
		}
	}
}

// A routing socket drops a datagram that is not the kernel's even when it was queued before the socket was
// connected: one sent in the window between bind and connect, a forged end of the next dump, does not end it.
func TestAnAnswerQueuedBeforeTheConnectIsNotTakenForTheKernels(t *testing.T) {
	needRoot(t)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	r := &rtnl{fd: fd}
	defer r.close()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sender)
	if err := unix.Bind(sender, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	forged := nlMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, nlSeq.Load()+1, nlStatus(0))
	if err := unix.Sendto(sender, forged, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: sa.(*unix.SockaddrNetlink).Pid}); err != nil {
		t.Fatalf("control: the forged end could not be queued before the connect: %v", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	links := 0
	if _, err := r.dumpAll(unix.RTM_GETLINK, make([]byte, unix.SizeofIfInfomsg), func([]byte) error { links++; return nil }); err != nil {
		t.Fatal(err)
	}
	if links == 0 {
		t.Fatal("a forged end queued before the connect ended the dump: no link was read")
	}
}
