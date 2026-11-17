// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// netns_linux_test.go runs the real namespace, TUN and filter as root, with no WireGuard:
// the test reads what the namespace sends straight off the TUN, which is exactly what
// WireGuard would encrypt. Unprivileged it skips, and says why.

// TestMain lets the test binary be the agent's init, the way the CLI binary is: Spawn
// re-executes /proc/self/exe with InitArg.
func TestMain(m *testing.M) {
	// The helpers the CLI's main starts, through the same dispatch it uses, so a helper missing there fails here.
	if run := ReexecEntry(os.Args); run != nil {
		run()
	}
	if len(os.Args) > 1 && os.Args[1] == containHelperArg {
		containHelper()
	}
	if len(os.Args) > 1 && os.Args[1] == sealProbeArg {
		sealProbe()
	}
	if len(os.Args) > 2 && os.Args[1] == deviceHelperArg {
		deviceHelper()
	}
	if len(os.Args) > 1 && os.Args[1] == fallbackProbeArg {
		fallbackProbe()
	}
	if len(os.Args) > 1 && os.Args[1] == sandboxHelperArg {
		sandboxHelper()
	}
	if len(os.Args) > 1 && os.Args[1] == otherNSSpawnerArg {
		otherNSSpawner()
	}
	if len(os.Args) > 1 && os.Args[1] == otherNSChildArg {
		otherNSChild()
	}
	if len(os.Args) > 2 && os.Args[1] == otherNSOwnerArg {
		otherNSOwner()
	}
	if len(os.Args) > 1 && os.Args[1] == probeHangArg {
		probeHang()
	}
	if len(os.Args) > 2 && os.Args[1] == fakeNetworkdArg {
		fakeNetworkd()
	}
	// As root, one run of this package at a time on a host: each test may run in a network namespace
	// of its own, but the cgroup hierarchy, /run/whisper and the agents' locks are the host's, and two
	// runs containing the same test agents would see each other's containments. Only the run itself
	// takes the lock: a test that starts this binary again as a helper (-test.run=...Helper) passes it
	// the environment, and must not wait for the lock its own parent holds.
	// The root suite contains test processes in namespaces of its own on a host whose own networkd may well take a
	// placed device (any Ubuntu with systemd-networkd does), so the placed-device check would refuse every one of
	// them; its own tests (networkd_root_linux_test.go) give it the configuration they mean.
	placedDeviceCheckAtStart = placedDeviceCheck
	placedDeviceCheck = func(int, procStatus) error { return nil }
	if os.Geteuid() == 0 && os.Getenv(testsLockedEnv) == "" {
		if f, err := os.OpenFile("/run/whisper-enforce-tests.lock", os.O_RDWR|os.O_CREATE|syscall.O_CLOEXEC, 0o600); err == nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
			// Held until the run exits, which takes a reference that lives as long: an *os.File nothing refers
			// to is closed by its finalizer at the next collection, and the lock goes with its descriptor (two
			// runs overlapped that way, and one unloaded the tunnel modules under the other's test).
			testsLock = f
			_ = os.Setenv(testsLockedEnv, "1")
			unloadLeftModules() // what a run killed before its end left loaded
		}
	}
	code := m.Run()
	unloadTestModules() // under the lock still: what this run loaded, and nothing else
	os.Exit(code)
}

// testsLockedEnv tells a helper this binary starts that the run already holds the host-wide lock.
const testsLockedEnv = "WHISPER_ENFORCE_TESTS_LOCKED"

// placedDeviceCheckAtStart is what Preflight's placed-device check was before TestMain stubbed it.
var placedDeviceCheckAtStart func(int, procStatus) error

// testsLock is the host-wide lock's file, kept referenced for the whole run.
var testsLock *os.File

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: this test creates a network namespace and a TUN device (run it with sudo)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("needs /dev/net/tun, which this host does not have")
	}
}

type liveNS struct {
	ns *Namespace
	f  *Filter
	ft *filteredTUN
	// sent receives every packet the filter let through toward the tunnel.
	sent chan []byte
}

func startNS(t *testing.T) *liveNS {
	t.Helper()
	ns, err := CreateNamespace(tSelf)
	if err != nil {
		t.Fatalf("CreateNamespace: %v", err)
	}
	f := NewFilter(Policy{Self: tSelf, Resolvers: []netip.Addr{tResolver}, NAT64: tPrefix})
	f.SetLive(true)
	l := &liveNS{ns: ns, f: f, ft: FilterTUN(ns.Dev, f).(*filteredTUN), sent: make(chan []byte, 64)}
	go func() {
		bufs := [][]byte{make([]byte, 4096)}
		sizes := []int{0}
		for {
			n, err := l.ft.Read(bufs, sizes, replyHeadroom)
			if err != nil {
				close(l.sent)
				return
			}
			if n == 1 && sizes[0] > 0 {
				l.sent <- append([]byte(nil), bufs[0][replyHeadroom:replyHeadroom+sizes[0]]...)
			}
		}
	}()
	t.Cleanup(ns.Close)
	return l
}

// nextTCP returns the next TCP packet the namespace sent, skipping anything else.
func (l *liveNS) nextTCP(t *testing.T) []byte {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case p, ok := <-l.sent:
			if !ok {
				t.Fatal("the TUN closed")
			}
			if p[0]>>4 == 6 && p[6] == protoTCP {
				return p
			}
		case <-deadline:
			t.Fatal("no TCP packet reached the tunnel")
		}
	}
}

// dialAsync dials from inside the namespace on a goroutine of its own. The dial is cancelled and
// waited for when the test ends, before the namespace is closed, so no test leaves one running
// into the next.
func dialAsync(t *testing.T, l *liveNS, addr string) chan error {
	ch := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		c, err := l.ns.DialContext(ctx, "tcp", addr)
		if c != nil {
			c.Close()
		}
		ch <- err
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ch
}

// The namespace holds loopback, the tunnel interface and whatever a new namespace starts with on this host (on a
// host with tunnel modules loaded, their idle fallback devices; elsewhere nothing): it adds nothing the kernel did
// not, and passes the rule init holds it to.
func TestNamespaceHoldsOnlyLoopbackAndTheTunnel(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	var v linkView
	if err := l.ns.run(func() (err error) { v, err = readLinkView("lo", IfName); return }); err != nil {
		t.Fatal(err)
	}
	if err := agentPlaceError(v); err != nil {
		t.Fatalf("the agent's namespace: %v", err)
	}
	var names []string
	for _, k := range v.links {
		if k.name != IfName {
			names = append(names, k.name)
		}
	}
	sort.Strings(names)
	if fresh := freshNames(t); strings.Join(names, ",") != strings.Join(fresh, ",") {
		t.Fatalf("the agent's namespace holds %v besides %s; a new namespace here starts with %v", names, IfName, fresh)
	}
	if l.ns.Inode == l.ns.HostInode {
		t.Fatal("the agent's namespace must not be the host's")
	}
	if ino, _ := nsInode(); ino != l.ns.HostInode {
		t.Fatal("the test goroutine's thread must still be in the host's namespace")
	}
}

func TestDirectV6DialLeavesFromTheSlash128(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	dialAsync(t, l, "[2606:4700:4700::1111]:443")
	p := l.nextTCP(t)
	if addr16(p[8:24]) != tSelf || addr16(p[24:40]) != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("SYN %s -> %s", addr16(p[8:24]), addr16(p[24:40]))
	}
}

func TestDirectV4DialIsTranslatedIntoTheTunnel(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	dialAsync(t, l, "1.1.1.1:443")
	p := l.nextTCP(t)
	if addr16(p[8:24]) != tSelf || addr16(p[24:40]) != netip.MustParseAddr("64:ff9b::101:101") {
		t.Fatalf("translated SYN %s -> %s", addr16(p[8:24]), addr16(p[24:40]))
	}
	verify6(t, p)
}

func TestRefusalsFailTheDialAtOnce(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	for addr, want := range map[string]syscall.Errno{
		"10.0.0.1:80":                syscall.EHOSTUNREACH,
		"[2001:4860:4860::8888]:53":  syscall.EACCES,
		"[2001:4860:4860::8888]:853": syscall.EACCES,
	} {
		start := time.Now()
		err := <-dialAsync(t, l, addr)
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", addr, err, want)
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("%s: refusal took %s, want immediate", addr, el)
		}
	}
}

func TestKillSwitchRefusesAndAClosedTUNLeavesNoRoute(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	l.f.SetLive(false)
	if err := <-dialAsync(t, l, "[2606:4700:4700::1111]:443"); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("dead tunnel, v6: got %v", err)
	}
	if err := <-dialAsync(t, l, "1.1.1.1:443"); !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("dead tunnel, v4: got %v", err)
	}
	l.ns.Dev.Close()
	time.Sleep(100 * time.Millisecond)
	for _, a := range []string{"[2606:4700:4700::1111]:443", "1.1.1.1:443"} {
		if err := <-dialAsync(t, l, a); !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("TUN gone, %s: got %v, want network unreachable", a, err)
		}
	}
}

func TestInitRunsTheAgentUnprivilegedInItsOwnWorld(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	// A descriptor inherited WITHOUT close-on-exec, which init must not let through.
	leak, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(leak)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	script := `grep -E '^(NoNewPrivs|CapEff|CapPrm):' /proc/self/status; echo uid=$(id -u); echo init=$(tr '\0' ' ' < /proc/1/cmdline);` +
		` echo procs=$(ls /proc | grep -c '^[0-9]'); echo fds=$(ls /proc/self/fd | tr '\n' ' ');` +
		` grep -h nameserver /etc/resolv.conf; grep '^hosts:' /etc/nsswitch.conf; exit 7`
	code, serr := l.ns.Spawn(Spec{
		Path: "/bin/sh", Args: []string{"sh", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"},
		Dir: "/", UID: 65534, GID: 65534, Groups: []uint32{65534}, Resolvers: []string{tResolver.String()},
	}, nil)
	os.Stdout = saved
	w.Close()
	out, _ := io.ReadAll(r)
	if serr != nil {
		t.Fatalf("Spawn: %v", serr)
	}
	got := string(out)
	t.Logf("agent saw:\n%s", got)
	if code != 7 {
		t.Fatalf("exit status %d, want the agent's own 7", code)
	}
	for _, want := range []string{"NoNewPrivs:\t1", "CapEff:\t0000000000000000", "CapPrm:\t0000000000000000",
		"uid=65534", "init=whisper-enforce-init " + InitArg, "nameserver " + tResolver.String(), "hosts:          files dns"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(got, "nameserver") && strings.Count(got, "nameserver") != 1 {
		t.Fatal("resolv.conf must name only the tunnel's resolver")
	}
	for _, line := range strings.Split(got, "\n") {
		// init, the shell, and the commands of this one pipeline: never the host's processes.
		if n, ok := strings.CutPrefix(line, "procs="); ok && len(n) > 1 {
			t.Fatalf("the agent must see only its own PID namespace, got %s", line)
		}
		if strings.HasPrefix(line, "fds=") {
			for _, fd := range strings.Fields(strings.TrimPrefix(line, "fds=")) {
				if fd != "0" && fd != "1" && fd != "2" && fd != "3" {
					t.Fatalf("descriptor %s reached the agent (%s)", fd, line)
				}
			}
		}
	}
}

func TestInitRefusesARootAgent(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	code, err := l.ns.Spawn(Spec{Path: "/bin/true", Args: []string{"true"}, Dir: "/", UID: 0, GID: 0}, nil)
	if err != nil || code != ExitSetup {
		t.Fatalf("a uid 0 agent must be refused by init with %d: code=%d err=%v", ExitSetup, code, err)
	}
}

// hereNamespace is a handle on the calling thread's own network namespace, which any user can
// open, so the handle's locking is tested without root. Unprivileged, setns into it is refused
// with EPERM, and that still proves the descriptor setns was given named a live namespace: a
// freed descriptor is EBADF, and a number the process has since reused for another file is EINVAL.
// As root (or with CAP_SYS_ADMIN over the namespace) the thread enters it and fn runs.
func hereNamespace(t *testing.T) *Namespace {
	t.Helper()
	fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("cannot open this thread's network namespace: %v", err)
	}
	ino, err := nsInode()
	if err != nil {
		unix.Close(fd)
		t.Fatalf("cannot read this thread's network namespace: %v", err)
	}
	n := &Namespace{fd: fd, Inode: ino, HostInode: ino}
	t.Cleanup(n.Close)
	return n
}

// enteredOrRefused fails unless err is one of the two honest outcomes of entering a live
// namespace: in (nil, and fn ran) or not permitted (EPERM, and fn did not run).
func enteredOrRefused(t *testing.T, err error, ran bool) {
	t.Helper()
	switch {
	case err == nil && ran:
	case errors.Is(err, unix.EPERM) && !ran:
	default:
		t.Fatalf("setns was not given a live namespace descriptor: err=%v, fn ran=%v", err, ran)
	}
}

func TestCloseWhileEnteringNeverHandsSetnsAFreedDescriptor(t *testing.T) {
	n := hereNamespace(t)
	freed, reused := n.fd, -1
	n.beforeEnter = func() {
		n.Close()
		// The lowest free number is handed out next, so this open is given the one Close freed.
		reused, _ = unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	t.Cleanup(func() {
		if reused >= 0 {
			unix.Close(reused)
		}
	})
	ran := false
	err := n.run(func() error { ran = true; return nil })
	t.Logf("Close freed descriptor %d; the next open was handed %d; run: err=%v ran=%v", freed, reused, err, ran)
	enteredOrRefused(t, err, ran)
}

func TestRunAfterCloseIsRefusedAndNeverRuns(t *testing.T) {
	n := hereNamespace(t)
	n.Close()
	n.Close() // a second Close is a no-op
	ran := false
	if err := n.run(func() error { ran = true; return nil }); !errors.Is(err, errNamespaceClosed) || ran {
		t.Fatalf("run after Close: err=%v ran=%v, want %v and nothing run", err, ran, errNamespaceClosed)
	}
	if _, err := n.DialContext(context.Background(), "tcp", "[2606:4700:4700::1111]:443"); !errors.Is(err, errNamespaceClosed) {
		t.Fatalf("a dial after Close must be refused, got %v", err)
	}
	if _, err := n.Interfaces(); !errors.Is(err, errNamespaceClosed) {
		t.Fatalf("Interfaces after Close must be refused, got %v", err)
	}
	if _, err := n.Spawn(Spec{Path: "/bin/true"}, nil); !errors.Is(err, errNamespaceClosed) {
		t.Fatalf("Spawn after Close must be refused, got %v", err)
	}
}

func TestAHostDeviceHasNoNamespaceToEnter(t *testing.T) {
	n := &Namespace{fd: -1}
	ran := false
	err := n.run(func() error { ran = true; return nil })
	if err == nil || ran || !strings.Contains(err.Error(), "host namespace") {
		t.Fatalf("run on a host device: err=%v ran=%v, want a refusal naming the host namespace", err, ran)
	}
}

// nsHandles counts this process's descriptors of the namespace with inode ino. Only those are
// counted: the root tests leave nothing running now, but the whole table is not a measure of one
// handle's duplicates.
func nsHandles(t *testing.T, ino uint64) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, e := range ents {
		if target, _ := os.Readlink("/proc/self/fd/" + e.Name()); target == fmt.Sprintf("net:[%d]", ino) {
			held++
		}
	}
	return held
}

// TestRunsRacingCloseShareNoDescriptor is the race itself: threads entering the namespace while
// Close runs, more than once and from more than one goroutine. Under -race an unsynchronised read
// of the descriptor fails it; without -race the outcomes and the descriptor count do. Every worker
// runs until it is refused, so each round proves Close landed among runs in flight.
func TestRunsRacingCloseShareNoDescriptor(t *testing.T) {
	ino, err := nsInode()
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 20; round++ {
		before := nsHandles(t, ino)
		n := hereNamespace(t)
		if nsHandles(t, ino) != before+1 {
			t.Fatalf("round %d: the handle's own descriptor is not counted, so the leak check would see nothing", round)
		}
		const workers, warm, most = 8, 3, 100000
		var started, wg sync.WaitGroup
		started.Add(workers)
		errs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var once sync.Once
				defer once.Do(started.Done)
				for i := 0; i < most; i++ {
					if i == warm {
						once.Do(started.Done)
					}
					ran := false
					err := n.run(func() error { ran = true; return nil })
					switch {
					case errors.Is(err, errNamespaceClosed) && !ran:
						if i < warm {
							errs <- fmt.Errorf("run %d refused before Close was called", i)
						}
						return
					case err == nil && ran, errors.Is(err, unix.EPERM) && !ran:
					default:
						errs <- fmt.Errorf("run %d: err=%v ran=%v", i, err, ran)
						return
					}
				}
				errs <- fmt.Errorf("never refused in %d runs", most)
			}()
		}
		started.Wait() // every worker is mid-stream, so Close lands among runs in flight
		var closers sync.WaitGroup
		for c := 0; c < 3; c++ {
			closers.Add(1)
			go func() { defer closers.Done(); n.Close() }()
		}
		closers.Wait()
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: %v", round, err)
		}
		if after := nsHandles(t, ino); after != before {
			t.Fatalf("round %d: %d descriptors of the namespace open before, %d after: a thread's own descriptor leaked", round, before, after)
		}
	}
}

// A thread that ends without answering (runtime.Goexit, which t.Fatal in a callback is) neither
// leaves run waiting forever nor keeps its descriptor.
func TestAThreadThatEndsWithoutAnAnswerFreesRunAndItsDescriptor(t *testing.T) {
	n := hereNamespace(t)
	before := nsHandles(t, n.Inode)
	for name, set := range map[string]func(){
		"before setns": func() { n.beforeEnter = runtime.Goexit },
		"inside":       func() { n.beforeEnter = nil },
	} {
		set()
		done := make(chan error, 1)
		go func() {
			done <- n.run(func() error { runtime.Goexit(); return nil })
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "ended without an answer") {
				// Unprivileged, the inside case is refused at setns before fn runs: also an answer.
				if !(name == "inside" && errors.Is(err, unix.EPERM)) {
					t.Fatalf("%s: run answered %v, want the thread's ending reported", name, err)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: run is still waiting for a thread that ended", name)
		}
		if got := nsHandles(t, n.Inode); got != before {
			t.Fatalf("%s: %d descriptors of the namespace before, %d after: the thread's own leaked", name, before, got)
		}
	}
}

// seal refuses every way in at once and leaves releasing to Close; Close seals before it lets the
// device go, so whoever closes the TUN has always sealed first.
func TestSealRefusesAtOnceAndCloseSealsBeforeTheDeviceGoes(t *testing.T) {
	n := hereNamespace(t)
	n.seal()
	ran := false
	if err := n.run(func() error { ran = true; return nil }); !errors.Is(err, errNamespaceClosed) || ran {
		t.Fatalf("run after seal: err=%v ran=%v, want %v", err, ran, errNamespaceClosed)
	}
	if n.fd < 0 {
		t.Fatal("seal must leave the descriptor to Close")
	}
	n.Close()
	if n.fd >= 0 {
		t.Fatal("Close after seal must still release the descriptor")
	}

	m := hereNamespace(t)
	dev := &sealCheckTUN{n: m}
	m.Dev = dev
	m.Close()
	m.Close()
	if dev.closes != 1 || !dev.sealedFirst {
		t.Fatalf("the device was closed %d time(s), sealed first=%v; want once, after the seal", dev.closes, dev.sealedFirst)
	}
}

// sealCheckTUN records whether its namespace was already sealed when it was closed.
type sealCheckTUN struct {
	tun.Device
	n           *Namespace
	closes      int
	sealedFirst bool
}

func (d *sealCheckTUN) Close() error {
	d.closes++
	d.sealedFirst = d.n.closed // read on the goroutine that holds n.mu inside Close
	return nil
}

// A host device's DialContext passes the handle's own guard to the dial, so once the handle is
// sealed the dial is refused before any socket option is set.
func TestAHostDeviceDialAfterTheSealIsRefused(t *testing.T) {
	hr := routeFor("wsc255", 0, 255, 1)
	hr.CarryV4 = true
	n := &Namespace{fd: -1, host: &hr, closed: true} // sealed by hand: removeRules never runs here
	if _, err := n.DialContext(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, errNamespaceClosed) {
		t.Fatalf("a dial through a sealed host device: got %v, want %v", err, errNamespaceClosed)
	}
}

// teardownTUN is a TUN whose reader blocks until it is closed, and which records, at its first
// Close, whether its handle was already sealed. Stop and a failed start close the TUN through the
// wireguard device, outside the handle's lock; only Namespace.Close closes it under the lock, and
// that seals first (TestSealRefusesAtOnceAndCloseSealsBeforeTheDeviceGoes).
type teardownTUN struct {
	n           *Namespace
	once        sync.Once
	gone        chan struct{}
	events      chan tun.Event
	sealedFirst bool
}

func newTeardownTUN(n *Namespace) *teardownTUN {
	return &teardownTUN{n: n, gone: make(chan struct{}), events: make(chan tun.Event)}
}

func (d *teardownTUN) File() *os.File { return nil }
func (d *teardownTUN) Read([][]byte, []int, int) (int, error) {
	<-d.gone
	return 0, os.ErrClosed
}
func (d *teardownTUN) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (d *teardownTUN) MTU() (int, error)                       { return minMTU, nil }
func (d *teardownTUN) Name() (string, error)                   { return "td0", nil }
func (d *teardownTUN) Events() <-chan tun.Event                { return d.events }
func (d *teardownTUN) BatchSize() int                          { return 1 }
func (d *teardownTUN) Close() error {
	d.once.Do(func() {
		if d.n.mu.TryLock() {
			d.sealedFirst = d.n.closed
			d.n.mu.Unlock()
		} else {
			d.sealedFirst = true // under the handle's lock: Namespace.Close, which seals first
		}
		close(d.gone)
		close(d.events)
	})
	return nil
}

func (d *teardownTUN) closed() bool {
	select {
	case <-d.gone:
		return true
	default:
		return false
	}
}

func TestStopSealsTheHandleBeforeTheTUNCloses(t *testing.T) {
	n := hereNamespace(t)
	td := newTeardownTUN(n)
	f := NewFilter(Policy{Self: tSelf, Resolvers: []netip.Addr{tResolver}, NAT64: tPrefix})
	dev := device.NewDevice(FilterTUN(td, f), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	tn := &Tunnel{NS: n, Filter: f, dev: dev, stop: make(chan struct{}), done: make(chan struct{})}
	close(tn.done) // no watch goroutine to wait for
	tn.Stop()
	if !td.closed() || !td.sealedFirst {
		t.Fatalf("Stop: the TUN was closed=%v with the handle sealed first=%v; want closed, after the seal", td.closed(), td.sealedFirst)
	}
}

func TestAFailedStartSealsTheHandleBeforeTheTUNCloses(t *testing.T) {
	n := hereNamespace(t)
	td := newTeardownTUN(n)
	n.Dev = td
	cfg := wgtun.Config{
		Address:            tSelf,
		PrivateKeyHex:      "not-a-key", // the device refuses it, which takes the failure path
		ServerPublicKeyHex: strings.Repeat("ab", 32),
		Endpoint:           "[2001:db8::1]:51820", // a literal: nothing is resolved
	}
	place := func(netip.Addr) (*Namespace, error) { return n, nil }
	if _, err := startTunnel(cfg, Policy{Resolvers: []netip.Addr{tResolver}, NAT64: tPrefix}, Options{}, place); err == nil {
		t.Fatal("a start with a key the device refuses must fail")
	}
	if !td.closed() || !td.sealedFirst {
		t.Fatalf("failed start: the TUN was closed=%v with the handle sealed first=%v; want closed, after the seal", td.closed(), td.sealedFirst)
	}
}

// threadNS maps every thread of this process to its network namespace.
func threadNS(t *testing.T) map[string]unix.Stat_t {
	t.Helper()
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

// homeNS is this thread's own network namespace, the host's.
func homeNS(t *testing.T) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// atHome reports whether the thread tid is alive and in the home namespace, read once, as awayAndBack promises it is
// when it returns. What that catches is a thread ended inside (gone) or left inside (read there). It does not pin
// the order of the answer and the way home: the woken caller usually runs only after the thread is back, so a version
// that answered first would mostly read home as well.
func atHome(t *testing.T, tid int, home unix.Stat_t) (unix.Stat_t, bool) {
	t.Helper()
	var st unix.Stat_t
	if unix.Stat(filepath.Join("/proc/self/task", strconv.Itoa(tid), "ns", "net"), &st) != nil {
		return st, false // gone: a version that ended the thread inside
	}
	return st, st.Dev == home.Dev && st.Ino == home.Ino
}

// strayThreads names the threads that are away from home and are new, or were moved there since before: a thread an
// earlier test left somewhere is not this one's business, and one that came home is no stray.
func strayThreads(t *testing.T, before map[string]unix.Stat_t, home unix.Stat_t) []string {
	t.Helper()
	var out []string
	for tid, st := range threadNS(t) {
		if st.Dev == home.Dev && st.Ino == home.Ino {
			continue
		}
		if was, ok := before[tid]; !ok || st.Dev != was.Dev || st.Ino != was.Ino {
			out = append(out, tid)
		}
	}
	return out
}

// run hands its thread back even when it cannot enter: a version that never unlocks ends the thread whatever
// happens (its tid is gone), so this catches it without root. As root run enters this thread's own namespace and
// runs fn; unprivileged setns refuses before fn, which is also an answer. Either way the thread is home after.
func TestRunHandsItsThreadBackEvenWhenItCannotEnter(t *testing.T) {
	n := hereNamespace(t)
	home := homeNS(t)
	for i := 0; i < 20; i++ {
		tid := 0
		n.beforeEnter = func() { tid = unix.Gettid() }
		ran := false
		err := n.run(func() error { ran = true; return nil })
		enteredOrRefused(t, err, ran)
		if st, ok := atHome(t, tid, home); !ok {
			t.Fatalf("run %d: thread %d is not home after run (now %d)", i, tid, st.Ino)
		}
	}
}

// awayAndBack reports work that ends its goroutine (a t.Fatal in a callback) and still hands its thread back home.
// It needs no root: enter does not move the thread, so fn runs and then calls Goexit.
func TestAwayAndBackReportsWorkThatEndsItsGoroutine(t *testing.T) {
	home := homeNS(t)
	for i := 0; i < 20; i++ {
		tid := 0
		err := awayAndBack(func() error { return nil }, func() error {
			tid = unix.Gettid()
			runtime.Goexit()
			return nil
		})
		if !errors.Is(err, errNoAnswer) {
			t.Fatalf("round %d: awayAndBack must report the goroutine that ended: got %v", i, err)
		}
		if st, ok := atHome(t, tid, home); !ok {
			t.Fatalf("round %d: thread %d is not home after the work ended its goroutine (now %d)", i, tid, st.Ino)
		}
	}
}

// CreateNamespace refused for want of root gives back the thread it took, every time: a version that never unlocks
// ends it, and its tid is gone. Unprivileged, the build after a failed unshare never runs, and the refusal says root
// is needed. The root suite builds instead (TestTheThreadThatBuiltTheNamespaceComesBack).
func TestCreateNamespaceRefusedGivesItsThreadBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this pins the refusal path; the root suite builds a namespace instead")
	}
	home := homeNS(t)
	for i := 0; i < 20; i++ {
		tid := 0
		ns, err := createNamespace(tSelf, func() { tid = unix.Gettid() })
		if err == nil || !strings.Contains(err.Error(), "needs root") || ns != nil {
			t.Fatalf("round %d: unprivileged createNamespace must refuse with the needs-root message, got %v", i, err)
		}
		if st, ok := atHome(t, tid, home); !ok {
			t.Fatalf("round %d: thread %d is not home after a refused build (now %d)", i, tid, st.Ino)
		}
	}
}
