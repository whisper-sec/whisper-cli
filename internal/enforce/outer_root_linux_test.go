// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// outer_root_linux_test.go runs, as root, what a kernel tunnel of the host's own does while the host has no
// usable global IPv6 address of its own: its outer packets belong to no socket, so no cgroup program
// sees them, and the kernel picks their source after routing, which leaves the agent's /128 the only candidate.

// srcCount counts the datagrams a listener got, by source address.
type srcCount struct {
	mu sync.Mutex
	by map[netip.Addr]int
}

func (c *srcCount) of(a netip.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.by[a]
}

func (c *srcCount) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	for a, n := range c.by {
		parts = append(parts, fmt.Sprintf("%s: %d", a, n))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// listen counts every UDP datagram that reaches [u.dst]:port inside the uplink namespace, by its source.
func (u *uplink6) listen(t *testing.T, port int) *srcCount {
	t.Helper()
	c := &srcCount{by: map[netip.Addr]int{}}
	pcCh := make(chan net.PacketConn, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies inside the namespace
		fd, err := unix.Open("/run/netns/"+u.ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			pcCh <- nil
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			pcCh <- nil
			return
		}
		pc, err := net.ListenPacket("udp6", fmt.Sprintf("[%s]:%d", u.dst, port))
		if err != nil {
			pc = nil
		}
		pcCh <- pc
	}()
	pc := <-pcCh
	if pc == nil {
		t.Fatalf("could not listen on port %d in the uplink namespace", port)
	}
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		b := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if ua, ok := from.(*net.UDPAddr); ok {
				a, _ := netip.AddrFromSlice(ua.IP)
				c.mu.Lock()
				c.by[a.Unmap()]++
				c.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); reader.Wait() })
	return c
}

func ipOK(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v %s", args, err, out)
	}
}

// kernelVXLAN makes a VXLAN device to [remote]:4789 with no local address, carrying IPv4 only (so it adds no
// IPv6 source of its own), and returns a function that sends n inner datagrams through it, one every interval.
// Each inner datagram leaves as an outer UDP packet the kernel makes itself, with no socket of its own.
func kernelVXLAN(t *testing.T, remote netip.Addr) func(n int, every time.Duration) {
	t.Helper()
	dev := fmt.Sprintf("wcx%d", os.Getpid()%10000)
	ipOK(t, "link", "add", dev, "type", "vxlan", "id", "2651", "remote", remote.String(), "dstport", "4789")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", dev).Run() })
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+dev+"/disable_ipv6", []byte("1"), 0o644); err != nil {
		t.Fatalf("turn IPv6 off on %s: %v", dev, err)
	}
	ipOK(t, "addr", "add", "10.65.1.1/24", "dev", dev)
	ipOK(t, "link", "set", dev, "up")
	ipOK(t, "neigh", "replace", "10.65.1.2", "lladdr", "02:00:00:26:51:02", "dev", dev)
	return func(n int, every time.Duration) {
		t.Helper()
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 65, 1, 1)}, &net.UDPAddr{IP: net.IPv4(10, 65, 1, 2), Port: 9})
		if err != nil {
			t.Fatalf("dial through the VXLAN: %v", err)
		}
		defer c.Close()
		for i := 0; i < n; i++ {
			_, _ = c.Write([]byte("inner"))
			time.Sleep(every)
		}
	}
}

// dropHostAddress takes the host's own address off the uplink and keeps its route, as on a host whose only
// global address is being re-added (systemd-networkd's restart, DAD), and reports the source the kernel
// would now give a packet to the uplink's far end.
func dropHostAddress(t *testing.T, up *uplink6) netip.Addr {
	t.Helper()
	ipOK(t, "-6", "addr", "del", "fd00:2620::1/64", "dev", up.hostIf)
	ipOK(t, "-6", "route", "replace", "fd00:2620::/64", "dev", up.hostIf)
	out, err := exec.Command("ip", "-6", "route", "get", up.dst.String()).CombinedOutput()
	if err != nil {
		t.Fatalf("ip -6 route get %s: %v %s", up.dst, err, out)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "src" {
			if a, err := netip.ParseAddr(f[i+1]); err == nil {
				return a
			}
		}
	}
	return netip.Addr{}
}

// wgKey makes a WireGuard private key in a file of the test's own, and returns the file and the public key.
func wgKey(t *testing.T) (file, pub string) {
	t.Helper()
	priv, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		t.Fatalf("wg genkey: %v", err)
	}
	file = t.TempDir() + "/key"
	if err := os.WriteFile(file, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(string(priv))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wg pubkey: %v", err)
	}
	return file, strings.TrimSpace(string(out))
}

// peerEndpoint is the endpoint the uplink's WireGuard peer last took for the host: WireGuard roams to the source
// of every packet it authenticates, so it names the address the host's last packet came from.
func peerEndpoint(u *uplink6, dev string) string {
	out, _ := exec.Command("ip", "netns", "exec", u.ns, "wg", "show", dev, "endpoints").Output()
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// kernelWireGuard makes a kernel WireGuard on the host to a peer in the uplink namespace at [u.dst]:51820, with a
// keepalive every second, carrying IPv4 only, and waits for the peer to take the host's own address as its
// endpoint. It returns the peer's device and a function that sends one inner datagram through the tunnel.
func kernelWireGuard(t *testing.T, u *uplink6) (peerDev string, send func()) {
	t.Helper()
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("needs wireguard-tools (wg) to configure a kernel WireGuard")
	}
	keyA, pubA := wgKey(t)
	keyB, pubB := wgKey(t)
	a, b := fmt.Sprintf("wcwA%d", os.Getpid()%1000), fmt.Sprintf("wcwB%d", os.Getpid()%1000)
	if out, err := exec.Command("ip", "link", "add", a, "type", "wireguard").CombinedOutput(); err != nil {
		t.Skipf("this kernel has no WireGuard: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", a).Run() })
	ipOK(t, "-n", u.ns, "link", "add", b, "type", "wireguard")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("ip", "netns", "exec", u.ns, "wg", "set", b, "listen-port", "51820", "private-key", keyB,
		"peer", pubA, "allowed-ips", "10.66.1.1/32")
	run("ip", "netns", "exec", u.ns, "sh", "-c", "echo 1 > /proc/sys/net/ipv6/conf/"+b+"/disable_ipv6")
	ipOK(t, "-n", u.ns, "addr", "add", "10.66.1.2/24", "dev", b)
	ipOK(t, "-n", u.ns, "link", "set", b, "up")
	run("wg", "set", a, "private-key", keyA, "peer", pubB, "endpoint", "["+u.dst.String()+"]:51820",
		"allowed-ips", "10.66.1.2/32", "persistent-keepalive", "1")
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+a+"/disable_ipv6", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ipOK(t, "addr", "add", "10.66.1.1/24", "dev", a)
	ipOK(t, "link", "set", a, "up")
	send = func() {
		if c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 66, 1, 1)}, &net.UDPAddr{IP: net.IPv4(10, 66, 1, 2), Port: 9}); err == nil {
			_, _ = c.Write([]byte("inner"))
			c.Close()
		}
	}
	for deadline := time.Now().Add(5 * time.Second); !strings.HasPrefix(peerEndpoint(u, b), "[fd00:2620::1]:"); {
		if time.Now().After(deadline) {
			t.Fatalf("control: the peer never took the host's own address as its endpoint (it has %q)", peerEndpoint(u, b))
		}
		send()
		time.Sleep(50 * time.Millisecond)
	}
	return b, send
}

// watchEndpoint sends through the tunnel and reads the peer's endpoint every 50 ms for d, and returns every
// endpoint it saw, in order, once each.
func watchEndpoint(u *uplink6, peerDev string, send func(), d time.Duration) []string {
	var seen []string
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		send()
		if e := peerEndpoint(u, peerDev); e != "" && (len(seen) == 0 || seen[len(seen)-1] != e) {
			seen = append(seen, e)
		}
	}
	return seen
}

// readd gives the uplink the host's address back the way a SLAAC or DHCPv6 client does: without a prefix route
// of its own, so the main table is not touched (the route dropHostAddress kept stays), and with DAD unless nodad.
// Nothing about it can invalidate a tunnel's cached route but the address coming back itself.
func readd(t *testing.T, up *uplink6, nodad bool) {
	t.Helper()
	args := []string{"-6", "addr", "add", "fd00:2620::1/64", "dev", up.hostIf, "noprefixroute"}
	if nodad {
		args = append(args, "nodad")
	}
	ipOK(t, args...)
}

var hostAddr = netip.MustParseAddr("fd00:2620::1")

// needNFCheck returns the device's gate with its netfilter check, or skips on a kernel that cannot have one. A
// kernel that has netfilter BPF programs and BTF, and is not locked down for confidentiality, must have it: a
// check that quietly went missing is the bug, so that fails.
func needNFCheck(t *testing.T, ns *Namespace) *rootGate {
	t.Helper()
	g := ns.HostRoute().gate
	if g.nf != nil {
		if g.nf.unproven != "" && g.nf.unproven != nfNoDevice && !allowUnproven {
			t.Fatalf("the check is linked but not proved: %s", g.nf.unproven)
		}
		return g
	}
	_, btfErr := os.Stat(kernelBTFPath)
	lockdown, _ := os.ReadFile("/sys/kernel/security/lockdown")
	if features.HaveProgramType(ebpf.Netfilter) == nil && btfErr == nil && !strings.Contains(string(lockdown), "[confidentiality]") {
		t.Fatalf("Linux %s has netfilter BPF programs and BTF, and the containment has no netfilter check: %v",
			kernelRelease(), g.nfWhy)
	}
	t.Skipf("this kernel cannot have the netfilter check: %v", g.nfWhy)
	return nil
}

// allowUnproven lets a test that stops the proof on purpose take an unproven check.
var allowUnproven bool

// withoutNF stands in for a kernel that cannot have the netfilter check, for the rest of the test.
func withoutNF(t *testing.T, why string) {
	t.Helper()
	attachNF = func(nfFor) (*nfCheck, error) { return nil, &nfUnavailable{why: why, remedy: "a kernel that has them"} }
	t.Cleanup(func() { attachNF = attachNFSource })
}

// dropCheck closes the device's netfilter check, as a control: what it held then leaves.
func dropCheck(g *rootGate) {
	g.nf.close()
	g.nf = nil
}

// heldBy is what the check has held so far.
func heldBy(g *rootGate) uint64 {
	n, _ := g.nf.held()
	return n
}

// agentIsTheSource fails unless the kernel now gives a packet to the uplink's far end the agent's address: with
// the /128 deprecated and the host's own address gone, that is deterministic, so anything else is a regression.
func agentIsTheSource(t *testing.T, src netip.Addr) {
	t.Helper()
	if src != tSelf5 {
		t.Fatalf("with the host's address gone the kernel picks %v, not the agent's address, as the source", src)
	}
}

// waitFrom waits up to d for got to count a datagram from a, sending more meanwhile, and says how long it took.
func waitFrom(t *testing.T, got *srcCount, a netip.Addr, d time.Duration, more func()) time.Duration {
	t.Helper()
	start := time.Now()
	for got.of(a) == 0 {
		if time.Since(start) > d {
			t.Fatalf("nothing from %s reached the uplink within %s (by source: %s)", a, d, got)
		}
		more()
	}
	return time.Since(start)
}

// While the host has no usable global IPv6 address of its own, a kernel tunnel's outer packets, which belong to
// no socket, never leave by the uplink from the agent's address, and the check counts each it holds. Once the
// host's address is back (with DAD, nothing in the main table touched) the tunnel speaks from it again on its own.
// Without the check (the control) the packets do leave from the agent's address, so the check is the reason.
func TestAKernelTunnelsOwnPacketsNeverLeaveFromTheAgentsAddress(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	got := up.listen(t, 4789)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	send := kernelVXLAN(t, up.dst)
	agentIsTheSource(t, dropHostAddress(t, up))
	held := heldBy(g)
	send(150, 2*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if n := got.of(tSelf5); n > 0 {
		t.Fatalf("%d of the tunnel's 150 outer packets left by the uplink from the agent's address (by source: %s)", n, got)
	}
	if h := heldBy(g) - held; h < 140 {
		t.Fatalf("the check held %d of the tunnel's 150 packets: they were not made, or not held by it", h)
	}

	readd(t, up, false)
	took := waitFrom(t, got, hostAddr, 6*time.Second, func() { send(5, 10*time.Millisecond) })
	if got.of(tSelf5) > 0 {
		t.Fatalf("with the host's address back the tunnel spoke from the agent's address (by source: %s)", got)
	}
	held = heldBy(g)
	send(20, 2*time.Millisecond)
	if h := heldBy(g) - held; h != 0 {
		t.Fatalf("with the host's address back the check still held %d packets", h)
	}

	agentIsTheSource(t, dropHostAddress(t, up))
	dropCheck(g)
	waitFrom(t, got, tSelf5, 3*time.Second, func() { send(5, 10*time.Millisecond) })
	t.Logf("the tunnel spoke from the host's address %s after it came back through DAD; by source: %s (the "+
		"agent's address only once the check was closed)", took.Round(10*time.Millisecond), got)
}

// peerReceived is how many bytes the uplink's WireGuard peer has received from the host.
func peerReceived(u *uplink6, dev string) int64 {
	out, _ := exec.Command("ip", "netns", "exec", u.ns, "wg", "show", dev, "transfer").Output()
	var key string
	var rx, tx int64
	fmt.Sscan(string(out), &key, &rx, &tx)
	return rx
}

// A kernel WireGuard of the host's own never reaches its peer from the agent's address while the host's own
// address is gone: the peer would roam to the agent's address, and every reply would then come back through the
// agent's tunnel. Once the host's address is back through DAD the tunnel carries on from it on its own; and
// without the check (the control) the peer does roam to the agent's address.
func TestAKernelWireGuardNeverReachesItsPeerFromTheAgentsAddress(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	peerDev, send := kernelWireGuard(t, up)
	agentIsTheSource(t, dropHostAddress(t, up))
	held := heldBy(g)
	agent := "[" + tSelf5.String() + "]:"
	seen := watchEndpoint(up, peerDev, send, 3500*time.Millisecond)
	for _, e := range seen {
		if strings.HasPrefix(e, agent) {
			t.Fatalf("the peer took the agent's address as the host's endpoint: it saw %v", seen)
		}
	}
	if heldBy(g) == held {
		t.Fatal("the check held none of the WireGuard's packets: they were not made, or not held by it")
	}

	readd(t, up, false)
	rx := peerReceived(up, peerDev)
	for deadline := time.Now().Add(8 * time.Second); peerReceived(up, peerDev) <= rx; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("with the host's address back the peer received nothing more (endpoint %q)", peerEndpoint(up, peerDev))
		}
		send()
	}
	if e := peerEndpoint(up, peerDev); !strings.HasPrefix(e, "[fd00:2620::1]:") {
		t.Fatalf("with the host's address back the peer has %q as the host's endpoint", e)
	}

	agentIsTheSource(t, dropHostAddress(t, up))
	dropCheck(g)
	roamed := false
	for deadline := time.Now().Add(5 * time.Second); !roamed && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		send()
		roamed = strings.HasPrefix(peerEndpoint(up, peerDev), agent)
	}
	if !roamed {
		t.Fatalf("control: without the check the peer never roamed to the agent's address (it has %q)", peerEndpoint(up, peerDev))
	}
	t.Logf("the peer's endpoint while the check held: %v; without it: %s", seen, peerEndpoint(up, peerDev))
}

// However the host's address comes back (through DAD, or at once with nodad), and with nothing in the main table
// changed, a tunnel's cached route and the agent's address it picked with it do not keep the tunnel off the
// host's own address: the check would then hold its packets for the rest of the containment.
func TestAKernelTunnelSpeaksFromTheHostsAddressOnceItIsBack(t *testing.T) {
	needRoot(t)
	for _, nodad := range []bool{false, true} {
		t.Run(map[bool]string{false: "after DAD", true: "nodad"}[nodad], func(t *testing.T) {
			up := startUplink6(t)
			got := up.listen(t, 4789)
			ns, _ := hostTUNAs(t, tSelf5)
			needNFCheck(t, ns)
			send := kernelVXLAN(t, up.dst)
			agentIsTheSource(t, dropHostAddress(t, up))
			send(50, 2*time.Millisecond) // the tunnel caches its route with the agent's address
			readd(t, up, nodad)
			took := waitFrom(t, got, hostAddr, 6*time.Second, func() { send(5, 10*time.Millisecond) })
			if got.of(tSelf5) > 0 {
				t.Fatalf("by source: %s", got)
			}
			t.Logf("the tunnel spoke from the host's address %s after it came back", took.Round(10*time.Millisecond))
		})
	}
}

// With no route at all (networkd deletes the routes with the address), the kernel gives a tunnel's packet the
// agent's address and looks the route up again with it, and the containment's own rule sends it into the tunnel,
// where admission refuses it: nothing reaches the uplink, and the check, which passes what goes into the tunnel,
// holds nothing.
func TestWithNoRouteATunnelsPacketsGoNoFurtherThanTheContainmentsTunnel(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	got := up.listen(t, 4789)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	send := kernelVXLAN(t, up.dst)
	dropHostAddress(t, up)
	ipOK(t, "-6", "route", "del", "fd00:2620::/64", "dev", up.hostIf)
	held := heldBy(g)
	send(50, 2*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if n := got.of(tSelf5) + got.of(hostAddr); n > 0 {
		t.Fatalf("with no route %d of the tunnel's packets reached the uplink (by source: %s)", n, got)
	}
	if h := heldBy(g) - held; h != 0 {
		t.Fatalf("the check held %d packets that were going into the containment's tunnel", h)
	}
}

// inNamespace runs fn on a thread that has joined the named namespace and dies there.
func inNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies inside the namespace
		fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- false
			return
		}
		err = unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
		if err != nil {
			done <- false
			return
		}
		fn()
		done <- true
	}()
	if !<-done {
		t.Fatalf("could not join namespace %s", name)
	}
}

// A packet the host forwards and masquerades takes its source after routing too: with the host's own address
// gone, source NAT gives it the agent's address. The check, after source NAT, holds it; without the check it
// leaves from the agent's address. No socket of the host's and no rule sees it.
func TestAMasqueradedPacketNeverLeavesFromTheAgentsAddress(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("needs nftables (nft) to masquerade")
	}
	init1, err := os.Stat("/proc/1/ns/net")
	self, err2 := os.Stat("/proc/self/ns/net")
	if err != nil || err2 != nil || os.SameFile(init1, self) {
		t.Skip("turns on IPv6 forwarding: run the suite in a network namespace of its own (unshare -n)")
	}
	up := startUplink6(t)
	got := up.listen(t, 7)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	// A container behind the host: fd00:2656::2, routed out through the host, masqueraded on the uplink.
	cname := fmt.Sprintf("wcc%d", os.Getpid())
	hostIf, peerIf := fmt.Sprintf("wccA%d", os.Getpid()%1000), fmt.Sprintf("wccB%d", os.Getpid()%1000)
	ipOK(t, "netns", "add", cname)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", cname).Run() })
	ipOK(t, "link", "add", hostIf, "type", "veth", "peer", "name", peerIf)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", hostIf).Run() })
	ipOK(t, "link", "set", peerIf, "netns", cname)
	// The host's side holds only a link-local address, as a routed container network's often does: a global
	// one there would itself be the source NAT picks.
	ipOK(t, "-6", "addr", "add", "fe80::2656:1/64", "dev", hostIf, "nodad")
	ipOK(t, "link", "set", hostIf, "up")
	ipOK(t, "-6", "route", "add", "fd00:2656::/64", "dev", hostIf)
	ipOK(t, "-n", cname, "-6", "addr", "add", "fd00:2656::2/64", "dev", peerIf, "nodad")
	ipOK(t, "-n", cname, "-6", "addr", "add", "fe80::2656:2/64", "dev", peerIf, "nodad")
	ipOK(t, "-n", cname, "link", "set", peerIf, "up")
	ipOK(t, "-n", cname, "-6", "route", "add", "default", "via", "fe80::2656:1", "dev", peerIf)
	fwd := "/proc/sys/net/ipv6/conf/all/forwarding"
	was, _ := os.ReadFile(fwd)
	if err := os.WriteFile(fwd, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(fwd, was, 0o644) })
	nft := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %v: %v %s", args, err, out)
		}
	}
	nft("add", "table", "ip6", "outmasq")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip6", "outmasq").Run() })
	nft("add", "chain", "ip6", "outmasq", "post", "{ type nat hook postrouting priority 100 ; }")
	nft("add", "rule", "ip6", "outmasq", "post", "oifname", up.hostIf, "masquerade")
	send := func(n int) {
		inNamespace(t, cname, func() {
			c, err := net.Dial("udp6", "[fd00:2620::2]:7")
			if err != nil {
				return
			}
			defer c.Close()
			for i := 0; i < n; i++ {
				_, _ = c.Write([]byte("forwarded"))
				time.Sleep(2 * time.Millisecond)
			}
		})
	}
	// Control: with its address the host masquerades the container as itself.
	waitFrom(t, got, hostAddr, 3*time.Second, func() { send(5) })
	agentIsTheSource(t, dropHostAddress(t, up))
	held := heldBy(g)
	send(100)
	time.Sleep(200 * time.Millisecond)
	if n := got.of(tSelf5); n > 0 {
		t.Fatalf("%d masqueraded packets left by the uplink from the agent's address (by source: %s)", n, got)
	}
	if heldBy(g) == held {
		t.Fatal("the check held none of the masqueraded packets: they were not made, or not held by it")
	}
	dropCheck(g)
	waitFrom(t, got, tSelf5, 3*time.Second, func() { send(5) })
	t.Logf("by source: %s (the agent's address only once the check was closed)", got)
}

// The check passes what the agent's address sends over loopback, to itself or to the host's own address: a
// contained process talking to a service on this host is not a leak.
func TestTheAgentsAddressStillSpeaksOverLoopback(t *testing.T) {
	needRoot(t)
	startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	held := heldBy(g)
	for _, to := range []netip.Addr{tSelf5, hostAddr} {
		ln, err := net.ListenUDP("udp6", &net.UDPAddr{IP: to.AsSlice()})
		if err != nil {
			t.Fatalf("listen on %s: %v", to, err)
		}
		c, err := net.DialUDP("udp6", &net.UDPAddr{IP: tSelf5.AsSlice()}, ln.LocalAddr().(*net.UDPAddr))
		if err != nil {
			ln.Close()
			t.Fatalf("dial %s from the agent's address: %v", to, err)
		}
		_, werr := c.Write([]byte("loopback"))
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 16)
		n, from, rerr := ln.ReadFromUDP(b)
		c.Close()
		ln.Close()
		if werr != nil || rerr != nil || string(b[:n]) != "loopback" || !from.IP.Equal(tSelf5.AsSlice()) {
			t.Fatalf("from the agent's address to %s over loopback: write %v, read %v %q from %v", to, werr, rerr, b[:n], from)
		}
	}
	if h := heldBy(g) - held; h != 0 {
		t.Fatalf("the check held %d packets over loopback", h)
	}
}

// probeHeld sends one packet the check must hold (nfCheck.prove's: from self to ff02::1 by dev, hop limit 0) and
// reports whether the check counted it.
func probeHeld(t *testing.T, g *rootGate, self netip.Addr, dev string) bool {
	t.Helper()
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	before := heldBy(g)
	_ = sendFrom(self, &unix.SockaddrInet6{Addr: [16]byte{0: 0xff, 1: 0x02, 15: 1}, Port: 9}, func(fd int) error {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifc.Index); err != nil {
			return err
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 0)
	})
	return heldBy(g) > before
}

// The check is linked in the host's namespace and nowhere else: from a thread in another namespace it refuses to
// link at all, rather than hold nothing of the host's.
func TestTheNetfilterCheckGoesInTheHostsNamespaceOnly(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	needNFCheck(t, ns)
	var err error
	inNamespace(t, up.ns, func() {
		var c *nfCheck
		c, err = attachNFSource(nfFor{self: tSelf4, tun: 1, gen: 0xfffe, slot: 9, host: ns.HostInode})
		c.close()
	})
	if err == nil || !strings.Contains(err.Error(), "host's network namespace") {
		t.Fatalf("linking the check from another namespace: %v", err)
	}
	if n := nfLinks(t, nfSourceName(0xfffe)); n != 0 {
		t.Fatalf("%d checks were linked from another namespace", n)
	}
}

// nfLinks counts the netfilter links whose program carries name.
func nfLinks(t *testing.T, name string) int {
	t.Helper()
	n := 0
	var it link.Iterator
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil || info.Type != link.NetfilterType {
			continue
		}
		p, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			continue
		}
		if pi, err := p.Info(); err == nil && pi.Name == name {
			n++
		}
		p.Close()
	}
	if err := it.Err(); err != nil {
		t.Fatalf("listing the kernel's links: %v", err)
	}
	return n
}

// The check lives exactly as long as its device: the garbage collector never takes its link from a device that
// still holds it, it holds what it must while the device lives, and a stop takes it away.
func TestTheNetfilterCheckLivesExactlyAsLongAsItsDevice(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	name := nfSourceName(ns.HostRoute().Gen)
	// Collect until a sentinel's cleanup has run, so every cleanup queued before it has too.
	for i := 0; i < 3; i++ {
		ran := make(chan struct{})
		sentinel := new([64]byte) // not a tiny allocation, whose cleanup may never run
		runtime.AddCleanup(sentinel, func(ch chan struct{}) { close(ch) }, ran)
		sentinel = nil
		runtime.GC()
		select {
		case <-ran:
		case <-time.After(5 * time.Second):
			t.Fatal("a sentinel's cleanup never ran")
		}
	}
	if n := nfLinks(t, name); n != 1 {
		t.Fatalf("%d netfilter checks named %s while the device lives, after collections, not 1", n, name)
	}
	if !probeHeld(t, g, tSelf5, up.hostIf) {
		t.Fatal("after collections the check no longer holds a packet it must hold")
	}
	ns.Close()
	if n := nfLinks(t, name); n != 0 {
		t.Fatalf("%d netfilter checks named %s outlived the device", n, name)
	}
}

// One containment's check is its own: closing it leaves another containment's linked and holding.
func TestOneContainmentsCheckLeavesAnothersAlone(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	nsA, _ := hostTUNAs(t, tSelf4)
	gA := needNFCheck(t, nsA)
	nsB, _ := hostTUNAs(t, tSelf5)
	gB := needNFCheck(t, nsB)
	if gA.nf.prio == gB.nf.prio || nfLinks(t, nfSourceName(nsA.HostRoute().Gen)) != 1 {
		t.Fatalf("two containments' checks at priorities %d and %d", gA.nf.prio, gB.nf.prio)
	}
	dropCheck(gA)
	if n := nfLinks(t, nfSourceName(nsB.HostRoute().Gen)); n != 1 {
		t.Fatalf("B's check is linked %d times after A's closed", n)
	}
	if !probeHeld(t, gB, tSelf5, up.hostIf) {
		t.Fatal("B's check no longer holds B's address after A's closed")
	}
}

// deviceHelperArg makes this test binary a command that holds a host device for the agent address in argv[2],
// says "gen <generation> nf <0|1>", and waits to be killed.
const deviceHelperArg = "__whisper-device-helper"

func deviceHelper() {
	a, err := netip.ParseAddr(os.Args[2])
	if err != nil {
		os.Stdout.WriteString("bad address\n")
		os.Exit(2)
	}
	ns, err := CreateHostDevice(a)
	if err != nil {
		os.Stdout.WriteString("refused: " + err.Error() + "\n")
		os.Exit(1)
	}
	nf := 0
	if ns.HostRoute().gate.nf != nil {
		nf = 1
	}
	fmt.Printf("gen %d nf %d\n", ns.HostRoute().Gen, nf)
	select {}
}

// A killed command's netfilter check goes with it, as its address check does: nothing it left refuses the
// agent's traffic through the agent's next device, which has a device index of its own.
func TestAKilledContainmentsNetfilterCheckGoesWithItsCommand(t *testing.T) {
	needRoot(t)
	ns, _ := hostTUNAs(t, tSelf4) // proves this kernel can have the check, and leaves the agent's lock made
	needNFCheck(t, ns)
	ns.Close()
	cmd := exec.Command("/proc/self/exe", deviceHelperArg, tSelf4.String())
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the device helper: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	type said struct {
		gen uint32
		nf  int
		err error
	}
	ch := make(chan said, 1)
	go func() {
		var s said
		_, s.err = fmt.Fscanf(out, "gen %d nf %d\n", &s.gen, &s.nf)
		ch <- s
	}()
	var s said
	select {
	case s = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatal("the device helper said nothing in 15 s")
	}
	if s.err != nil || s.nf != 1 {
		t.Fatalf("the helper's device: gen %d nf %d (%v)", s.gen, s.nf, s.err)
	}
	if n := nfLinks(t, nfSourceName(s.gen)); n != 1 {
		t.Fatalf("control: the live command holds %d netfilter checks named %s, not 1", n, nfSourceName(s.gen))
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_ = cmd.Wait()
	for deadline := time.Now().Add(2 * time.Second); nfLinks(t, nfSourceName(s.gen)) > 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the killed command's netfilter check %s is still linked", nfSourceName(s.gen))
		}
	}
	nsB, sentB := hostTUNAs(t, tSelf4) // the agent's next device: it reaps what the killed one left
	far := netip.MustParseAddr("2606:4700:4700::1001")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := nsB.DialContext(ctx, "tcp", "["+far.String()+"]:443"); err == nil {
			c.Close()
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	if syn := waitTCP6(t, sentB, far); addr16(syn[8:24]) != tSelf4 {
		t.Fatalf("the next device's dial left from %s", addr16(syn[8:24]))
	}
}

// The kernel lets only a program with a GPL-compatible licence read the structures a netfilter program is handed,
// which is why the check, alone among the containment's programs, declares nfSourceLicense: measured, so the
// comment that says so stays true.
func TestTheNetfilterCheckNeedsAGPLCompatibleLicence(t *testing.T) {
	needRoot(t)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	o, err := kernelNFOffsets()
	if err != nil {
		t.Fatal(err)
	}
	spec := nfSourceSpec(tSelf5, ns.HostRoute().Index, loIndex(), 0, o, g.nf.counts.FD())
	spec.License = "MIT"
	p, err := ebpf.NewProgram(spec)
	if err == nil {
		p.Close()
		t.Fatal("this kernel loads the check under the MIT licence alone; nfSourceLicense is no longer needed")
	}
	t.Logf("declared MIT, the kernel refuses it: %v", err)
}

// The check alone holds a socket's packet from the agent's address too: with wsc_src's link closed, a host socket
// the kernel gives the agent's address reaches nothing, and the check counts what it held.
func TestTheNetfilterCheckAloneHoldsASocketsPackets(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns)
	g.src.Close()
	g.src = nil
	agentIsTheSource(t, dropHostAddress(t, up))
	c, err := net.Dial("udp6", "["+up.dst.String()+"]:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	held := heldBy(g)
	for i := 0; i < 20; i++ {
		_, _ = c.Write([]byte("host"))
	}
	time.Sleep(200 * time.Millisecond)
	if n := up.datagrams.Load(); n > 0 {
		t.Fatalf("%d of the host's datagrams from the agent's address reached the uplink with only the check", n)
	}
	if h := heldBy(g) - held; h < 20 {
		t.Fatalf("the check held %d of the host's 20 datagrams", h)
	}
}

// On a kernel that cannot have the netfilter check (before 6.4, no BTF, a refusal), the containment still comes
// up with every other protection (its rules, the deprecated address, wsc_src) and says, in one line, what stays
// open, naming the kernel and the host's tunnels that are up; it never refuses for it.
func TestAKernelWithoutTheCheckStillContainsAndSaysSo(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	withoutNF(t, "netfilter BPF links need Linux 6.4")
	ns, _ := hostTUNAs(t, tSelf5)
	hr := ns.HostRoute()
	// The note names the host's tunnels that are up, and only those: a device that is down sends nothing.
	up1, down1 := fmt.Sprintf("wcxu%d", os.Getpid()%10000), fmt.Sprintf("wcxd%d", os.Getpid()%10000)
	for i, d := range []string{up1, down1} {
		ipOK(t, "link", "add", d, "type", "vxlan", "id", fmt.Sprint(2652+i), "remote", up.dst.String(), "dstport", "4789")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", d).Run() })
	}
	ipOK(t, "link", "set", up1, "up")
	if hr.gate.nf != nil || hr.gate.src == nil {
		t.Fatalf("the check is %v and wsc_src is %v; want no check and wsc_src in place", hr.gate.nf, hr.gate.src)
	}
	note := hr.OuterNote()
	for _, want := range []string{"Linux " + kernelRelease(), "netfilter BPF links need Linux 6.4", "agent's address",
		"DAD", up1 + " (vxlan)"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note %q does not say %q", note, want)
		}
	}
	if strings.Contains(note, down1) {
		t.Fatalf("the note names %s, which is down and sends nothing: %q", down1, note)
	}
	v6, v4 := listRules(t)
	if w := keepPlan(hr.rules(tSelf5), tSelf5, v6, v4); w.broken() {
		t.Fatalf("the containment's rules are not whole without the check: missing %v", describeRules(w.missing))
	}
	if out, err := exec.Command("ip", "-6", "addr", "show", "dev", hr.Name).CombinedOutput(); err != nil ||
		!strings.Contains(string(out), "deprecated") {
		t.Fatalf("the agent's address is not deprecated without the check (%v):\n%s", err, out)
	}
	if n := hr.OuterHeld(); n != 0 {
		t.Fatalf("without a check it reports %d held", n)
	}
	// With its address gone the note says the exposure lasts as long as the containment.
	agentIsTheSource(t, dropHostAddress(t, up))
	if n := hr.OuterNote(); !strings.Contains(n, "(it has none now)") {
		t.Fatalf("with no global address of the host's own the note says %q", n)
	}
	// wsc_src still refuses a host socket the kernel gives the agent's address.
	c, err := net.Dial("udp6", "["+up.dst.String()+"]:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 20; i++ {
		_, _ = c.Write([]byte("host"))
	}
	time.Sleep(200 * time.Millisecond)
	if n := up.datagrams.Load(); n > 0 {
		t.Fatalf("%d of the host's datagrams from the agent's address reached the uplink without the check", n)
	}
	t.Logf("note: %s", note)
}

// The proofs of wsc_src and of the rule keeper, run again on a kernel without the netfilter check: there they are all
// that holds the agent's address in, and on a kernel with it the check would pass them for wsc_src (it runs first).
func TestAHostSocketGivenTheAgentsAddressNeverLeavesByTheUplinkWithoutTheNetfilterCheck(t *testing.T) {
	withoutNF(t, "left out: wsc_src alone")
	TestAHostSocketGivenTheAgentsAddressNeverLeavesByTheUplink(t)
}

func TestTheKeeperHoldsTheAddressRefusedWhileDeletionsGoOnWithoutTheNetfilterCheck(t *testing.T) {
	withoutNF(t, "left out: wsc_src alone")
	TestTheKeeperHoldsTheAddressRefusedWhileDeletionsGoOn(t)
}

func TestNetworkdsSweepLeavesALiveContainmentsRulesWithoutTheNetfilterCheck(t *testing.T) {
	withoutNF(t, "left out: wsc_src alone")
	TestNetworkdsSweepLeavesALiveContainmentsRules(t)
}

func TestNetworkdsSweepTakesRulesOfAnyOtherProtocolWithoutTheNetfilterCheck(t *testing.T) {
	withoutNF(t, "left out: wsc_src alone")
	TestNetworkdsSweepTakesRulesOfAnyOtherProtocol(t)
}

// nextSlot is the slot the next tunnel device in this namespace will take: the lowest wsc%d that is free.
func nextSlot(t *testing.T) int {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	taken := map[string]bool{}
	for _, i := range ifs {
		taken[i.Name] = true
	}
	for n := 0; ; n++ {
		if !taken[fmt.Sprintf("wsc%d", n)] {
			return n
		}
	}
}

// A check whose priority another hook holds (another BPF program, or an nftables base chain) never goes without:
// a kernel that links a BPF program only at a priority no other hook holds (6.8, measured) has it step on past
// them; one that lets them share a priority (RHEL 9.8's backport, measured) links it at its own.
func TestACheckStepsPastAnotherHookAtItsPriority(t *testing.T) {
	needRoot(t)
	if features.HaveProgramType(ebpf.Netfilter) != nil {
		t.Skip("this kernel has no netfilter BPF programs")
	}
	other, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "other_hook", Type: ebpf.Netfilter,
		AttachType: ebpf.AttachNetfilter, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, nfAccept), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	slot := nextSlot(t)
	at := int32(nfSourcePriority + slot)
	l, err := link.AttachNetfilter(link.NetfilterOptions{Program: other, ProtocolFamily: link.NetfilterProtoIPv6,
		Hook: link.NetfilterInetPostRouting, Priority: at})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := exec.LookPath("nft"); err == nil {
		// And an nftables base chain at the next step.
		nft := func(args ...string) {
			t.Helper()
			if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
				t.Fatalf("nft %v: %v %s", args, err, out)
			}
		}
		nft("add", "table", "ip6", "outslots")
		t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip6", "outslots").Run() })
		nft("add", "chain", "ip6", "outslots", "post", fmt.Sprintf("{ type filter hook postrouting priority %d ; }", at+maxHostSlots))
		at += maxHostSlots
	}
	ns, _ := hostTUNAs(t, tSelf5)
	if ns.HostRoute().Slot != slot {
		t.Fatalf("the device took slot %d, not the %d this test read", ns.HostRoute().Slot, slot)
	}
	g := needNFCheck(t, ns) // linked and proved, wherever it sits
	switch g.nf.prio {
	case at + maxHostSlots:
	case int32(nfSourcePriority + slot):
		t.Logf("this kernel let the check share priority %d with another program", g.nf.prio)
	default:
		t.Fatalf("the check sits at priority %d, neither its own %d nor %d past the hooks at %d", g.nf.prio,
			nfSourcePriority+slot, at+maxHostSlots, at)
	}
}

// The proof is honest both ways: a check asked about an address it does not hold says it is not proved, and its
// own address proves.
func TestTheProofSaysWhenACheckHoldsNothing(t *testing.T) {
	needRoot(t)
	startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf4)
	g := needNFCheck(t, ns)
	if why, err := g.nf.prove(tSelf5); err != nil || !strings.Contains(why, "reached it with its nonce") {
		t.Fatalf("a check for %s proving itself on %s: %q %v", tSelf4, tSelf5, why, err)
	}
	if why, err := g.nf.prove(tSelf4); why != "" || err != nil {
		t.Fatalf("the check failed its own proof: %q %v", why, err)
	}
}

// Any local process may bind the agent's address and send by the uplink, which the check holds and counts; doing
// so all through the proof switches nothing off: arrival over loopback, not the count, proves the pass.
func TestAProcessMovingTheCountCannotSwitchTheCheckOff(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ifc, err := net.InterfaceByName(up.hostIf)
	if err != nil {
		t.Fatal(err)
	}
	// Four senders, as fast as they go, on one socket each: the count moves all through the proof.
	var quit atomic.Bool
	done := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func() {
			n := 0
			fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
				_ = unix.Bind(fd, &unix.SockaddrInet6{Addr: tSelf5.As16()})
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifc.Index)
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 0)
				to := &unix.SockaddrInet6{Addr: [16]byte{0: 0xff, 1: 0x02, 15: 1}, Port: 7}
				for !quit.Load() {
					_ = unix.Sendto(fd, []byte("tick"), 0, to)
					n++
				}
				unix.Close(fd)
			}
			done <- n
		}()
	}
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns) // fails if the check is missing or unproven
	held := heldBy(g)
	time.Sleep(50 * time.Millisecond)
	quit.Store(true)
	sent := 0
	for i := 0; i < 4; i++ {
		sent += <-done
	}
	if heldBy(g) == held {
		t.Fatalf("control: the check counted none of the %d packets sent from the agent's address by the uplink", sent)
	}
}

// A host whose output rules stop the probe the check must hold keeps the check, proved over ICMPv6 when only UDP
// to ff02::1 is stopped, and linked but said to be unproven when both are: closing it could only take protection
// away.
func TestAnOutputRuleThatStopsTheProbeLeavesTheCheckLinked(t *testing.T) {
	needRoot(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("needs nftables (nft) for the host's output rule")
	}
	up := startUplink6(t)
	nft := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft %v: %v %s", args, err, out)
		}
	}
	nft("add", "table", "ip6", "outdrop")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "ip6", "outdrop").Run() })
	nft("add", "chain", "ip6", "outdrop", "out", "{ type filter hook output priority 0 ; }")
	nft("add", "rule", "ip6", "outdrop", "out", "ip6", "daddr", "ff02::1", "meta", "l4proto", "udp", "drop")
	ns, _ := hostTUNAs(t, tSelf5)
	g := needNFCheck(t, ns) // proved over ICMPv6
	held := heldBy(g)
	hit, err := g.nf.holdProbeEcho(tSelf5, ifIndexOf(t, up.hostIf))
	g.nf.disarm()
	if !hit || err == nil || heldBy(g) == held {
		t.Fatalf("the check does not hold an echo from the agent's address (held with its nonce %v, %v)", hit, err)
	}
	ns.Close()

	nft("add", "rule", "ip6", "outdrop", "out", "ip6", "daddr", "ff02::1", "meta", "l4proto", "ipv6-icmp", "drop")
	allowUnproven = true
	t.Cleanup(func() { allowUnproven = false })
	ns2, _ := hostTUNAs(t, tSelf5)
	g2 := needNFCheck(t, ns2)
	if g2.nf.unproven == "" || !strings.Contains(g2.nf.unproven, "output rule") {
		t.Fatalf("with both probes stopped the check says %q", g2.nf.unproven)
	}
	note := ns2.HostRoute().OuterNote()
	if !strings.Contains(note, "linked but could not prove itself here") || !strings.Contains(note, nfSourceName(ns2.HostRoute().Gen)) {
		t.Fatalf("the note for an unproven check: %q", note)
	}
	// Still linked, and still holding what the rule lets reach it.
	got := up.listen(t, 4789)
	send := kernelVXLAN(t, up.dst)
	agentIsTheSource(t, dropHostAddress(t, up))
	held = heldBy(g2)
	send(50, 2*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if got.of(tSelf5) > 0 || heldBy(g2) == held {
		t.Fatalf("the unproven check held %d; by source at the uplink: %s", heldBy(g2)-held, got)
	}
}

// A kernel locked down for confidentiality forbids the read the check needs: it is said as that, with what would
// close it, never as a fault of this release.
func TestALockedDownKernelIsSaidAsSuch(t *testing.T) {
	needRoot(t)
	startUplink6(t)
	f := t.TempDir() + "/lockdown"
	if err := os.WriteFile(f, []byte("none integrity [confidentiality]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	was := lockdownPath
	lockdownPath = f
	t.Cleanup(func() { lockdownPath = was })
	ns, _ := hostTUNAs(t, tSelf5)
	hr := ns.HostRoute()
	if hr.gate.nf != nil {
		t.Fatal("the check was linked under a confidentiality lockdown")
	}
	note := hr.OuterNote()
	for _, want := range []string{"locked down for confidentiality", "lockdown set to integrity or none"} {
		if !strings.Contains(note, want) {
			t.Fatalf("the note %q does not say %q", note, want)
		}
	}
	if strings.Contains(note, "fault of this release") {
		t.Fatalf("the note blames the release: %q", note)
	}
}

func ifIndexOf(t *testing.T, name string) int {
	t.Helper()
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return ifc.Index
}

// A check that came back empty, neither linked nor refused, is said like one the kernel refused, never silently.
func TestAnEmptyCheckIsSaid(t *testing.T) {
	needRoot(t)
	attachNF = func(nfFor) (*nfCheck, error) { return nil, nil }
	t.Cleanup(func() { attachNF = attachNFSource })
	ns, _ := hostTUNAs(t, tSelf5)
	if n := ns.HostRoute().OuterNote(); !strings.Contains(n, "came back empty") {
		t.Fatalf("an empty check is said as %q", n)
	}
}

// sendFrom sends one datagram from self (bound with IPV6_FREEBIND, so it need not be on a device yet) to to,
// after set, if any, has adjusted the socket.
func sendFrom(self netip.Addr, to *unix.SockaddrInet6, set func(fd int) error) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: self.As16()}); err != nil {
		return err
	}
	if set != nil {
		if err := set(fd); err != nil {
			return err
		}
	}
	return unix.Sendto(fd, []byte("wsc_nf"), 0, to)
}

// No local process can prove a check that holds nothing of the probe's address: packets it gets held from the
// address the check does hold carry no probe's nonce. A check for tSelf4 asked about tSelf5 stays unproven
// through a flood from tSelf4 by the uplink.
func TestAFloodCannotProveACheckThatHoldsNothing(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf4)
	g := needNFCheck(t, ns)
	var quit atomic.Bool
	done := make(chan struct{}, 4)
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			fd, _, err := boundSocket(tSelf4, unix.SOCK_DGRAM, 0)
			if err != nil {
				return
			}
			defer unix.Close(fd)
			if toMulticast(fd, ifIndexOf(t, up.hostIf)) != nil {
				return
			}
			for p := 1024; !quit.Load(); p = 1024 + (p+1)%64512 {
				_ = unix.Sendto(fd, []byte("flood"), 0, &unix.SockaddrInet6{Addr: allNodes, Port: p})
			}
		}()
	}
	stop := func() {
		quit.Store(true)
		for i := 0; i < 4; i++ {
			<-done
		}
	}
	// Control: the flood is being held before the proof starts, and still is after it.
	held := heldBy(g)
	for deadline := time.Now().Add(3 * time.Second); heldBy(g) == held; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			stop()
			t.Fatal("control: the flood was not held, so it would prove nothing")
		}
	}
	why, err := g.nf.prove(tSelf5)
	during := heldBy(g)
	time.Sleep(10 * time.Millisecond)
	after := heldBy(g)
	stop()
	if err != nil || why == "" {
		t.Fatalf("a check for %s asked about %s through a flood: %q %v", tSelf4, tSelf5, why, err)
	}
	if after == during {
		t.Fatal("control: the flood had stopped being held by the end of the proof")
	}
}

// The verifier refusing the program (here, a read at a negative offset from struct net_device, as a misread layout
// could give) is said as a fault of this release, though the kernel answers EACCES, which a security module's
// refusal gives too. The control is a read BEFORE the struct because every kernel refuses that one ("invalid
// negative access"). A read past its end is no refusal on a newer kernel: struct net_device ends in a flexible
// u8 priv[] array, and once the verifier lets a program read a flexible array of integers (7.0 does) a read at
// any offset past the struct is read from priv as a scalar. Measured: offset 30000 refused on 6.8 and loaded on 7.0.
func TestAVerifierRefusalIsAFaultOfThisRelease(t *testing.T) {
	needRoot(t)
	if features.HaveProgramType(ebpf.Netfilter) != nil {
		t.Skip("this kernel has no netfilter BPF programs")
	}
	o, err := kernelNFOffsets()
	if err != nil {
		t.Skip(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: nfSlots})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	o.ifindex = -8
	p, err := ebpf.NewProgram(nfSourceSpec(tSelf5, 7, 1, 0, o, m.FD()))
	if err == nil {
		p.Close()
		t.Fatal("control: the kernel took a read at a negative offset from struct net_device")
	}
	if u := refusedLoad(err); !strings.Contains(u.why, "a fault of this release") || u.remedy != "a report of it, please" {
		t.Fatalf("the verifier's refusal (%v) said as %+v", firstLine(err), u)
	}
}
