// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// netns_linux_test.go runs the real namespace, TUN and filter as root, with no WireGuard:
// the test reads what the namespace sends straight off the TUN, which is exactly what
// WireGuard would encrypt. Unprivileged it skips, and says why.

// TestMain lets the test binary be the agent's init, the way the CLI binary is: Spawn
// re-executes /proc/self/exe with InitArg.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == InitArg {
		RunInit()
	}
	os.Exit(m.Run())
}

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

func dialAsync(l *liveNS, addr string) chan error {
	ch := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := l.ns.DialContext(ctx, "tcp", addr)
		if c != nil {
			c.Close()
		}
		ch <- err
	}()
	return ch
}

func TestNamespaceHoldsOnlyLoopbackAndTheTunnel(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	names, err := l.ns.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "lo,"+IfName && strings.Join(names, ",") != IfName+",lo" {
		t.Fatalf("interfaces %v", names)
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
	dialAsync(l, "[2606:4700:4700::1111]:443")
	p := l.nextTCP(t)
	if addr16(p[8:24]) != tSelf || addr16(p[24:40]) != netip.MustParseAddr("2606:4700:4700::1111") {
		t.Fatalf("SYN %s -> %s", addr16(p[8:24]), addr16(p[24:40]))
	}
}

func TestDirectV4DialIsTranslatedIntoTheTunnel(t *testing.T) {
	needRoot(t)
	l := startNS(t)
	dialAsync(l, "1.1.1.1:443")
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
		err := <-dialAsync(l, addr)
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
	if err := <-dialAsync(l, "[2606:4700:4700::1111]:443"); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("dead tunnel, v6: got %v", err)
	}
	if err := <-dialAsync(l, "1.1.1.1:443"); !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("dead tunnel, v4: got %v", err)
	}
	l.ns.Dev.Close()
	time.Sleep(100 * time.Millisecond)
	for _, a := range []string{"[2606:4700:4700::1111]:443", "1.1.1.1:443"} {
		if err := <-dialAsync(l, a); !errors.Is(err, syscall.ENETUNREACH) {
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
