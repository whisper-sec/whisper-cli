// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rulekeep_root_linux_test.go runs, as root, what systemd-networkd does to a live containment's rules,
// what the keeper does when anything else deletes them, and what a prune may take. "The uplink" is a
// second namespace on a veth pair with an IPv6 prefix of its own: a packet from the agent's /128 that
// takes the host's main table arrives there, which is the leak.

// touchLock makes the agent's lock file, as every command that makes a device does before it does: a
// prune leaves an address that has none alone.
func touchLock(t *testing.T, a netip.Addr) {
	t.Helper()
	l, err := LockExclusive(a)
	if err != nil {
		t.Fatalf("the agent lock for %s: %v", a, err)
	}
	l.Release()
}

// uplink6 is the outside world over IPv6: a namespace on a veth pair, counting the datagrams that reach
// [fd00:2620::2]:9.
type uplink6 struct {
	dst       netip.Addr
	hostIf    string // the host's end of the veth pair, holding fd00:2620::1/64
	ns        string // the uplink namespace's name, under /run/netns
	datagrams atomic.Int32
}

func startUplink6(t *testing.T) *uplink6 {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2 (ip) to build the uplink namespace")
	}
	name := fmt.Sprintf("wcu%d", os.Getpid())
	hostIf, peerIf := fmt.Sprintf("wcuA%d", os.Getpid()%1000), fmt.Sprintf("wcuB%d", os.Getpid()%1000)
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	run("netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	run("link", "add", hostIf, "type", "veth", "peer", "name", peerIf)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", hostIf).Run() })
	run("link", "set", peerIf, "netns", name)
	run("-6", "addr", "add", "fd00:2620::1/64", "dev", hostIf, "nodad")
	run("link", "set", hostIf, "up")
	run("-n", name, "-6", "addr", "add", "fd00:2620::2/64", "dev", peerIf, "nodad")
	run("-n", name, "link", "set", peerIf, "up")
	u := &uplink6{dst: netip.MustParseAddr("fd00:2620::2"), hostIf: hostIf, ns: name}
	pcCh := make(chan net.PacketConn, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies inside the namespace
		fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
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
		pc, err := net.ListenPacket("udp6", "[fd00:2620::2]:9")
		if err != nil {
			pc = nil
		}
		pcCh <- pc
	}()
	pc := <-pcCh
	if pc == nil {
		t.Fatal("could not listen in the uplink namespace")
	}
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		b := make([]byte, 64)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
			u.datagrams.Add(1)
		}
	}()
	t.Cleanup(func() { pc.Close(); reader.Wait() })
	// Control: the host's own address reaches it.
	c, err := net.Dial("udp6", "[fd00:2620::2]:9")
	if err != nil {
		t.Fatalf("control: dial the uplink: %v", err)
	}
	defer c.Close()
	for deadline := time.Now().Add(3 * time.Second); u.datagrams.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("control: the host's own datagrams never reached the uplink")
		}
		_, _ = c.Write([]byte("control"))
		time.Sleep(20 * time.Millisecond)
	}
	u.datagrams.Store(0)
	return u
}

// freebindSender is what any unprivileged process may do: bind the agent's /128 with IPV6_FREEBIND and
// send from it, unmarked, outside the containment. It sends one datagram to [dst]:9 every interval
// until the returned function is called, which says how many the kernel took.
func freebindSender(t *testing.T, self, dst netip.Addr, every time.Duration) (stop func() (sent, refused int)) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: self.As16()}); err != nil {
		unix.Close(fd)
		t.Fatalf("bind %s: %v", self, err)
	}
	var quit atomic.Bool
	var sent, refused atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		to := &unix.SockaddrInet6{Addr: dst.As16(), Port: 9}
		for !quit.Load() {
			if unix.Sendto(fd, []byte("leak"), 0, to) == nil {
				sent.Add(1)
			} else {
				refused.Add(1)
			}
			time.Sleep(every)
		}
	}()
	var once sync.Once
	stop = func() (int, int) {
		once.Do(func() { quit.Store(true); <-done; unix.Close(fd) })
		return int(sent.Load()), int(refused.Load())
	}
	t.Cleanup(func() { stop() })
	return stop
}

// rawRules lists every rule of one family as the kernel's own message payloads.
func rawRules(t *testing.T, fam uint8) [][]byte {
	t.Helper()
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	h := fibRuleHdr{Family: fam}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	var out [][]byte
	if err := r.dump(unix.RTM_GETRULE, body, func(data []byte) { out = append(out, append([]byte(nil), data...)) }); err != nil {
		t.Fatal(err)
	}
	return out
}

// networkdSweep does what systemd-networkd does to foreign rules whenever it configures a link it
// manages (ManageForeignRoutingPolicyRules=yes, the default): it deletes every rule whose protocol is
// not kernel, each named by everything the kernel listed for it. It returns how many it deleted.
func networkdSweep(t *testing.T) int {
	t.Helper()
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	n := 0
	for _, fam := range []uint8{unix.AF_INET6, unix.AF_INET} {
		for _, msg := range rawRules(t, fam) {
			if ri, ok := parseRule(msg); ok && ri.proto != unix.RTPROT_KERNEL {
				if err := r.do(unix.RTM_DELRULE, 0, msg); err == nil {
					n++
				}
			}
		}
	}
	return n
}

// listRules reads both families.
func listRules(t *testing.T) (v6, v4 []ruleInfo) {
	t.Helper()
	v6, err := dumpRulesErr(unix.AF_INET6)
	if err != nil {
		t.Fatal(err)
	}
	if v4, err = dumpRulesErr(unix.AF_INET); err != nil {
		t.Fatal(err)
	}
	return v6, v4
}

func addRaw(t *testing.T, body []byte) {
	t.Helper()
	r, err := openRTNL()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil && !errors.Is(err, unix.EEXIST) {
		t.Fatalf("add a rule: %v", err)
	}
}

func delRaw(body []byte) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	return r.do(unix.RTM_DELRULE, 0, body)
}

// keptRoute brings up a host device for self with its keeper running, and collects what the keeper says.
func keptRoute(t *testing.T, self netip.Addr) (*Namespace, *HostRoute, func() string) {
	t.Helper()
	ns, _ := hostTUNAs(t, self)
	var mu sync.Mutex
	var said []string
	ns.keepRules(func(f string, a ...any) {
		mu.Lock()
		said = append(said, fmt.Sprintf(f, a...))
		mu.Unlock()
		t.Logf("keeper: "+f, a...)
	})
	if ns.keeper == nil {
		t.Fatal("no keeper started")
	}
	select {
	case <-ns.keeper.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper never started following the rules")
	}
	return ns, ns.HostRoute(), func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(said, "\n") }
}

// waitSaid waits for the keeper to say something containing each of want: its notes reach logf through a
// writer of their own, a moment after what they describe.
func waitSaid(said func() string, want ...string) bool {
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		ok := true
		for _, w := range want {
			ok = ok && strings.Contains(said(), w)
		}
		if ok || time.Now().After(deadline) {
			return ok
		}
	}
}

// waitWhole waits until the containment's rules are listed whole, in an order that works, and no guard
// is up, and says how long it took.
func waitWhole(t *testing.T, hr *HostRoute, self netip.Addr, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		v6, v4 := listRules(t)
		w := keepPlan(hr.rules(self), self, v6, v4)
		if !w.broken() && !w.guard {
			return time.Since(start)
		}
		if time.Since(start) > within {
			t.Fatalf("the rules are not whole after %s (missing %v, reorder %v, guard %v):\n%s", within,
				describeRules(w.missing), w.reorder, w.guard, ipRules(t))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// What networkd does to a host's rules leaves a live containment's alone, so nothing from the agent's
// address reaches the uplink. The same sweep takes a rule tagged as the release before tagged them, and
// a rule of the host's own written with `ip rule add`: what it does is real.
func TestNetworkdsSweepLeavesALiveContainmentsRules(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5) // no keeper: the protocol alone has to hold
	hr := ns.HostRoute()
	hostsOwn := ruleBodyProhibit(unix.AF_INET6, 4250, netip.MustParseAddr("2001:db8:2620::7"))
	addRaw(t, hostsOwn)
	t.Cleanup(func() { _ = delRaw(hostsOwn) })
	earlier := withProto(ruleBodyProhibit(unix.AF_INET6, hostRulePrio+11, tSelf6), legacyRuleProto)
	addRaw(t, earlier)
	t.Cleanup(func() { _ = delRaw(earlier) })
	stop := freebindSender(t, tSelf5, up.dst, 200*time.Microsecond)
	time.Sleep(100 * time.Millisecond)
	swept := networkdSweep(t)
	time.Sleep(300 * time.Millisecond)
	sent, _ := stop()
	if swept < 2 {
		t.Fatalf("control: the sweep deleted %d rules; the host's own and the earlier release's were there", swept)
	}
	v6, v4 := listRules(t)
	for _, r := range v6 {
		if r.prio == 4250 || r.prio == hostRulePrio+11 {
			t.Fatalf("control: the sweep left a rule networkd deletes:\n%s", ipRules(t))
		}
	}
	if w := keepPlan(hr.rules(tSelf5), tSelf5, v6, v4); w.broken() {
		t.Fatalf("the sweep took the containment's %s:\n%s", describeRules(w.missing), ipRules(t))
	}
	if sent == 0 {
		t.Fatal("control: the sender sent nothing")
	}
	if n := up.datagrams.Load(); n > 0 {
		t.Fatalf("%d of %d datagrams from the agent's address reached the uplink", n, sent)
	}
	t.Logf("swept %d rules; %d datagrams from the agent's address sent, 0 reached the uplink", swept, sent)
}

// Control for the one above: rules in the containment's shape that carry another protocol (as this
// release's did) are swept. From then on only the gate on the root cgroup keeps the agent's address in:
// a sender bound to it is refused at the send. With the gate off as well, which is what the release
// before had in this case, the address reaches the uplink. That is the defect.
func TestNetworkdsSweepTakesRulesOfAnyOtherProtocol(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	hr := ns.HostRoute()
	// Install the same rules again with the earlier protocol, and take away this release's: the host as
	// it was before the fix.
	for _, s := range hr.rules(tSelf5) {
		addRaw(t, withProto(s.body(), legacyRuleProto))
	}
	for _, s := range hr.rules(tSelf5) {
		_ = delRaw(tagged(s.body()))
	}
	stop := freebindSender(t, tSelf5, up.dst, 200*time.Microsecond)
	time.Sleep(100 * time.Millisecond)
	if n := up.datagrams.Load(); n > 0 {
		t.Fatalf("control: %d datagrams reached the uplink while the rules were all there", n)
	}
	if swept := networkdSweep(t); swept < 4 {
		t.Fatalf("control: the sweep took %d rules", swept)
	}
	v6, _ := listRules(t)
	for _, r := range v6 {
		if r.src == tSelf5 && r.proto == legacyRuleProto {
			t.Fatalf("control: the sweep left a rule tagged 87:\n%s", ipRules(t))
		}
	}
	time.Sleep(300 * time.Millisecond)
	_, refused := stop()
	if n := up.datagrams.Load(); n > 0 || refused == 0 {
		t.Fatalf("with the rules swept and the gate on, %d datagrams reached the uplink and %d were refused", n, refused)
	}
	stop = freebindSender(t, tSelf5, up.dst, 200*time.Microsecond)
	hr.gate.detach()
	deadline := time.Now().Add(2 * time.Second)
	for up.datagrams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	sent, _ := stop()
	if up.datagrams.Load() == 0 {
		route, _ := exec.Command("ip", "-6", "route", "get", up.dst.String(), "from", tSelf5.String()).CombinedOutput()
		t.Fatalf("with the rules swept and the gate off, nothing from the agent's address reached the uplink (%d "+
			"sent; %s): the test proves nothing\n%s", sent, route, ipRules(t))
	}
	t.Logf("rules swept: the gate refused %d sends; with it off, %d datagrams from the agent's address reached the uplink",
		refused, up.datagrams.Load())
}

// Whatever another program deletes of a live containment's rules, the keeper puts back, in an order that
// works, and takes its guard away again once nothing more is deleted; it says so.
func TestTheKeeperPutsBackWhatAnotherProgramDeletes(t *testing.T) {
	needRoot(t)
	ns, hr, said := keptRoute(t, tSelf5)
	all := hr.rules(tSelf5)
	byIdx := func(idx ...int) []ruleSpec {
		var out []ruleSpec
		for _, i := range idx {
			if i < len(all) {
				out = append(out, all[i])
			}
		}
		return out
	}
	cases := map[string][]ruleSpec{
		"the IPv6 mark lookup":   byIdx(0),
		"the address lookup":     byIdx(1),
		"the refusal":            byIdx(2),
		"both address rules":     byIdx(1, 2),
		"both lookups":           byIdx(0, 1),
		"every IPv6 rule":        byIdx(0, 1, 2),
		"the IPv4 rules":         byIdx(3, 4),
		"every rule, as a sweep": all,
	}
	waitWhole(t, hr, tSelf5, 2*time.Second)
	for name, gone := range cases {
		if len(gone) == 0 {
			continue // IPv4 not carried here
		}
		before := ns.keeper.repaired()
		for _, s := range gone {
			if err := delRaw(tagged(s.body())); err != nil {
				t.Fatalf("%s: delete %s: %v", name, s, err)
			}
		}
		took := waitWhole(t, hr, tSelf5, 3*time.Second)
		if ns.keeper.repaired() == before {
			t.Fatalf("%s: whole again without the keeper writing anything", name)
		}
		t.Logf("%s: whole again, guard down, after %s", name, took)
	}
	// Reordered by hand: the lookups put back after the refusal, as a program that deleted and re-added
	// them would leave them. The refusal ahead of every lookup would refuse the containment's own traffic.
	for _, s := range all[:2] {
		_ = delRaw(tagged(s.body()))
	}
	for _, s := range all[:2] {
		addRaw(t, tagged(s.body()))
	}
	waitWhole(t, hr, tSelf5, 3*time.Second)
	if !waitSaid(said, "deleted the containment's routing rules", "back in place") {
		t.Fatalf("the keeper did not say what it did:\n%s", said())
	}
}

// The first deletion is answered with the guard: from then on nothing leaves with the agent's address,
// and the guard stays up while deletions go on, coming down only once they stop. A program that keeps
// deleting meets a refusal, not a gap. One that deletes the guard too gets it back at once, each time,
// and what leaves is the reaction to each of its rounds.
func TestTheKeeperHoldsTheAddressRefusedWhileDeletionsGoOn(t *testing.T) {
	needRoot(t)
	for _, guardToo := range []bool{false, true} {
		t.Run(fmt.Sprintf("guard deleted too %v", guardToo), func(t *testing.T) {
			up := startUplink6(t)
			ns, hr, said := keptRoute(t, tSelf5)
			waitWhole(t, hr, tSelf5, 2*time.Second)
			all := hr.rules(tSelf5)
			guard := tagged(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, tSelf5))
			stop := freebindSender(t, tSelf5, up.dst, 100*time.Microsecond)
			var deletes, rounds atomic.Int32
			deleter := make(chan struct{})
			go func() { // as `while ip rule del ...; do :; done` would, every 20 ms for a second
				defer close(deleter)
				for end := time.Now().Add(time.Second); time.Now().Before(end); {
					rounds.Add(1)
					if guardToo && delRaw(guard) == nil {
						deletes.Add(1)
					}
					for _, s := range all[1:3] {
						if delRaw(tagged(s.body())) == nil {
							deletes.Add(1)
						}
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
			time.Sleep(100 * time.Millisecond)
			held := 0
			for i := 0; i < 15; i++ { // sampled while the deletions go on
				v6, _ := listRules(t)
				if keepPlan(all, tSelf5, v6, nil).guard {
					held++
				}
				time.Sleep(50 * time.Millisecond)
			}
			<-deleter
			took := waitWhole(t, hr, tSelf5, 3*time.Second)
			sent, refused := stop()
			leaked := up.datagrams.Load()
			t.Logf("%d rounds, %d deletions; the guard was up in %d of 15 samples; whole %s after they stopped; %d "+
				"datagrams sent, %d refused, %d reached the uplink", rounds.Load(), deletes.Load(), held, took, sent, refused, leaked)
			if deletes.Load() < 10 {
				t.Fatalf("control: only %d deletions", deletes.Load())
			}
			if took < keepQuiet/2 {
				t.Fatalf("the guard came down %s after the last deletion, before the quiet period", took)
			}
			if ns.keeper.repaired() == 0 || !waitSaid(said, "was refused for") {
				t.Fatalf("the keeper did not say it held and released the address:\n%s", said())
			}
			if !guardToo {
				// What can leave is the time from the very first deletion to the guard: one notification and
				// one dump. Every later deletion meets the guard.
				if held < 15 {
					t.Fatalf("the guard came down while deletions went on (%d of 15 samples)", held)
				}
				// About a datagram here, a few on a loaded box; a guard that came down between rounds would
				// let hundreds through.
				if leaked > 20 {
					t.Fatalf("%d datagrams from the agent's address reached the uplink", leaked)
				}
				return
			}
			// The guard deleted every round is back each time within the reaction (a few milliseconds on a
			// loaded box), so it is up most of the time, and what leaves is the reaction to each round, not
			// the rest of the second: a keeper that let the guard stay down would show it in no sample and
			// leak nearly every datagram after the first round.
			if held < 5 {
				t.Fatalf("the guard, deleted every round, was up in only %d of 15 samples", held)
			}
			if int(leaked) > 3*int(rounds.Load()) || 2*int(leaked) > sent+refused {
				t.Fatalf("%d of %d datagrams reached the uplink in %d rounds of deletion", leaked, sent+refused, rounds.Load())
			}
		})
	}
}

// Once the handle is sealed the keeper writes nothing: a teardown that lands while it repairs, or while
// it holds its guard, waits for it and then removes the rules, and nothing puts one back after that.
// The teardown never waits on it for long.
func TestTheKeeperWritesNothingOnceSealed(t *testing.T) {
	needRoot(t)
	for i := 0; i < 30; i++ {
		ns, hr, _ := keptRoute(t, tSelf6)
		all := hr.rules(tSelf6)
		// Something deletes the containment's rules for a few milliseconds, so the teardown lands while
		// the keeper puts them back or holds its guard.
		for end := time.Now().Add(time.Duration(i%7) * time.Millisecond); ; {
			for _, s := range all {
				_ = delRaw(tagged(s.body()))
			}
			if time.Now().After(end) {
				break
			}
		}
		start := time.Now()
		ns.Close()
		closed := time.Since(start)
		select {
		case <-ns.keeper.done:
		default:
			t.Fatal("the keeper still runs after Close")
		}
		if closed > 2*time.Second {
			t.Fatalf("round %d: Close took %s", i, closed)
		}
		time.Sleep(50 * time.Millisecond)
		v6, v4 := listRules(t)
		for _, r := range append(v6, v4...) {
			if r.mark == hr.Mark || r.src == tSelf6 && r.action == frActToTbl {
				t.Fatalf("round %d: a rule of the sealed containment is back: %+v\n%s", i, r, ipRules(t))
			}
		}
		if hasAddrRules(tSelf6) {
			t.Fatalf("round %d: the sealed containment left its refusal or a guard, with nothing that needs it:\n%s%s", i,
				ipRules(t), pruneWhy(tSelf6))
		}
	}
}

// A keeper acts on its own containment's rules only: deleting another containment's, or pruning another
// agent's refusal at its priority, makes it write nothing.
func TestAKeeperLeavesOtherContainmentsAlone(t *testing.T) {
	needRoot(t)
	nsA, hrA, _ := keptRoute(t, tSelf5)
	nsB, hrB, _ := keptRoute(t, tSelf6)
	waitWhole(t, hrA, tSelf5, 2*time.Second)
	waitWhole(t, hrB, tSelf6, 2*time.Second)
	for _, s := range hrB.rules(tSelf6) {
		_ = delRaw(tagged(s.body()))
	}
	waitWhole(t, hrB, tSelf6, 3*time.Second)
	touchLock(t, tSelf3)
	addRaw(t, tagged(ruleBodyProhibit(unix.AF_INET6, hrA.Prio, tSelf3)))
	t.Cleanup(func() { removeAgentAddrRules(tSelf3) })
	pruneAgentRefusals(netip.Addr{}, 0)
	time.Sleep(keepEvery / 5)
	if n := nsA.keeper.repaired(); n != 0 {
		t.Fatalf("A's keeper wrote %d times for B's rules and C's refusal", n)
	}
	if nsB.keeper.repaired() == 0 {
		t.Fatal("control: B's keeper did not put B's rules back")
	}
	if hasAddrRules(tSelf3) {
		t.Fatalf("control: C's refusal was not pruned:\n%s", ipRules(t))
	}
}

// A refusal or a guard a release before left, tagged with that release's protocol, is still a
// containment's: the prune takes it once nothing needs it, and the guard's removal takes it too.
func TestAnEarlierReleasesRefusalAndGuardStillGo(t *testing.T) {
	needRoot(t)
	touchLock(t, tSelf3)
	addRaw(t, withProto(ruleBodyProhibit(unix.AF_INET6, hostRulePrio+7, tSelf3), legacyRuleProto))
	addRaw(t, withProto(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, tSelf3), legacyRuleProto))
	t.Cleanup(func() { removeAgentAddrRules(tSelf3); _ = removeGuard(tSelf3) })
	pruneAgentRefusals(netip.Addr{}, 0)
	if hasAddrRules(tSelf3) {
		t.Fatalf("an earlier release's refusal or guard survived a prune:\n%s%s", ipRules(t), pruneWhy(tSelf3))
	}
	addRaw(t, withProto(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, tSelf4), legacyRuleProto))
	addRaw(t, tagged(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, tSelf4)))
	if err := removeGuard(tSelf4); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ipRules(t), fmt.Sprintf("%d:\tfrom %s prohibit", hostGuardPrio, tSelf4)) {
		t.Fatalf("a guard survived its removal:\n%s", ipRules(t))
	}
}

// Kernel is also the protocol a host's own rule carries when it is written to survive networkd, so a
// prune takes only an exact shape, for an agent this host has served, and only when the delete takes
// that very rule. A host's refusal written without a priority while a containment is live lands at the
// guard's priority, in the guard's shape: it survives the containment's teardown.
func TestAPruneLeavesTheHostsOwnRulesThatLookLikeAContainments(t *testing.T) {
	needRoot(t)
	useTempLockDir(t) // this host's real lock directory may name anything an earlier run made
	ns, _ := hostTUNAs(t, tSelf5)
	x := netip.MustParseAddr("2001:db8:2620::9")
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("-6", "rule", "add", "from", x.String(), "prohibit", "protocol", "kernel")
	t.Cleanup(func() {
		_ = exec.Command("ip", "-6", "rule", "del", "from", x.String(), "prohibit", "protocol", "kernel").Run()
	})
	if !strings.Contains(ipRules(t), fmt.Sprintf("%d:\tfrom %s prohibit", hostGuardPrio, x)) {
		t.Fatalf("control: the host's rule did not land at the guard's priority:\n%s", ipRules(t))
	}
	// Rules naming an agent this host has served, selecting on something more, inside the band.
	touchLock(t, tSelf3)
	y := tSelf3.String()
	richer := [][]string{
		{"-6", "rule", "add", "pref", "4310", "from", y, "iif", "lo", "prohibit", "protocol", "kernel"},
		{"-6", "rule", "add", "pref", "4310", "from", y, "to", "2001:db8::1", "prohibit", "protocol", "kernel"},
		{"-6", "rule", "add", "pref", "4310", "from", y, "ipproto", "udp", "prohibit", "protocol", "kernel"},
		{"-6", "rule", "add", "pref", "4312", "not", "from", y, "prohibit", "protocol", "kernel"},
		{"-6", "rule", "add", "pref", "4311", "from", y, "iif", "lo", "prohibit", "protocol", "kernel"},
	}
	for _, a := range richer {
		ip(a...)
	}
	t.Cleanup(func() {
		for i := 0; i < 8; i++ {
			_ = exec.Command("ip", "-6", "rule", "del", "pref", "4310").Run()
			_ = exec.Command("ip", "-6", "rule", "del", "pref", "4311").Run()
			_ = exec.Command("ip", "-6", "rule", "del", "pref", "4312").Run()
		}
	})
	// And a containment's exact leftover at 4311, behind the host's richer rule there: deleting it would
	// take the host's rule first.
	addRaw(t, tagged(ruleBodyProhibit(unix.AF_INET6, 4311, tSelf3)))
	before := ipRules(t)
	ns.Close() // the teardown prunes
	pruneAgentRefusals(netip.Addr{}, 0)
	after := ipRules(t)
	for _, want := range []string{
		fmt.Sprintf("%d:\tfrom %s prohibit", hostGuardPrio, x),
		"4310:\tfrom " + y + " iif lo prohibit",
		"4310:\tfrom " + y + " to 2001:db8::1 prohibit",
		"4310:\tfrom " + y + " ipproto udp prohibit",
		"4312:\tnot from " + y + " prohibit",
		"4311:\tfrom " + y + " iif lo prohibit",
	} {
		if strings.Contains(before, want) && !strings.Contains(after, want) {
			t.Errorf("a prune took the host's own %q:\n%s", want, after)
		}
	}
	if _, err := os.Stat(filepath.Join(LockDir, lockName(x))); err == nil {
		t.Errorf("the prune made a lock file for %s, an address this host never served", x)
	}
}

// A forged notification from a process (root here, since no one else may send to the keeper's socket)
// makes the keeper write nothing: only the kernel's own messages are read.
func TestAForgedNotificationMakesTheKeeperWriteNothing(t *testing.T) {
	needRoot(t)
	ns, hr, _ := keptRoute(t, tSelf5)
	waitWhole(t, hr, tSelf5, 2*time.Second)
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	// A DELRULE naming the containment's refusal, sent to every listener of the IPv6 rule group.
	body := tagged(hr.rules(tSelf5)[2].body())
	msg := make([]byte, unix.SizeofNlMsghdr+len(body))
	*(*uint32)(unsafe.Pointer(&msg[0])) = uint32(len(msg))
	*(*uint16)(unsafe.Pointer(&msg[4])) = unix.RTM_DELRULE
	copy(msg[unix.SizeofNlMsghdr:], body)
	for i := 0; i < 20; i++ {
		if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.RTNLGRP_IPV6_RULE - 1)}); err != nil &&
			!errors.Is(err, syscall.EPERM) {
			t.Fatalf("send: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := ns.keeper.repaired(); n != 0 {
		t.Fatalf("the keeper wrote %d times for a forged notification", n)
	}
	v6, _ := listRules(t)
	if keepPlan(hr.rules(tSelf5), tSelf5, v6, nil).guard {
		t.Fatal("the keeper put up its guard for a forged notification")
	}
}

// The refusal a stop leaves is there after the stop even when something deleted it in the moment
// between the keeper stopping and the rules coming out: a connection still ending never takes the
// host's routes.
func TestTheRefusalIsThereAfterTheStopWhateverWasDeleted(t *testing.T) {
	needRoot(t)
	withoutDestroy(t)
	ns, _ := hostTUNAs(t, tSelf4) // no keeper: as after it stopped
	hr := ns.HostRoute()
	end := tcpFrom(t, tSelf4)
	if err := delRaw(tagged(hr.rules(tSelf4)[2].body())); err != nil {
		t.Fatalf("delete the refusal: %v", err)
	}
	ns.Close()
	if !refused(t, tSelf4) {
		t.Fatalf("with a connection still open from the agent's address and its refusal deleted before the stop, the "+
			"address takes the host's routes:\n%s", ipRules(t))
	}
	end()
}

// A containment an earlier release runs, whose rules carry 87, is live: a prune of this release, run by
// another agent's device, never takes its rules.
func TestAPruneNeverTakesTheRulesOfALiveContainmentOfAnEarlierRelease(t *testing.T) {
	needRoot(t)
	old, _ := hostTUNAs(t, tSelf6)
	hr := old.HostRoute()
	for _, s := range hr.rules(tSelf6) { // as that release installed them
		addRaw(t, withProto(s.body(), legacyRuleProto))
		_ = delRaw(tagged(s.body()))
	}
	other, _ := hostTUNAs(t, tSelf5) // makes a device, and prunes
	other.Close()                    // stops one, and prunes
	pruneAgentRefusals(netip.Addr{}, 0)
	v6, _ := listRules(t)
	n := 0
	for _, r := range v6 {
		if r.src == tSelf6 && r.prio == hr.Prio && r.proto == legacyRuleProto {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("a prune took the address rules of a live containment tagged 87 (%d of 2 left):\n%s", n, ipRules(t))
	}
}

// A deletion whose dump fails is still answered: the guard goes up at once, and the keeper reads again
// when the hold ends, however busy the host's rules are with changes of nobody's concern to it.
func TestADeletionTheKeeperCannotReadIsRefusedAndRetried(t *testing.T) {
	needRoot(t)
	ns, hr, said := keptRoute(t, tSelf5)
	waitWhole(t, hr, tSelf5, 2*time.Second)
	var fails atomic.Int32
	fails.Store(4) // the next looks' dumps fail, four of them
	standIn := func(fam uint8) ([]ruleInfo, error) {
		if fails.Add(-1) >= 0 {
			return nil, errors.New("dump interrupted")
		}
		return dumpRulesErr(fam)
	}
	keepDumpHook.Store(&standIn)
	t.Cleanup(func() { keepDumpHook.Store(nil) })
	var quit atomic.Bool
	churned := make(chan struct{})
	go func() { // somebody else's rule, added and deleted every 50 ms
		defer close(churned)
		other := ruleBodyProhibit(unix.AF_INET6, 4250, netip.MustParseAddr("2001:db8:2620::5"))
		for !quit.Load() {
			addRaw(t, other)
			_ = delRaw(other)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer func() { quit.Store(true); <-churned }()
	if err := delRaw(tagged(hr.rules(tSelf5)[2].body())); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		v6, _ := listRules(t)
		if keepPlan(hr.rules(tSelf5), tSelf5, v6, nil).guard {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a deletion the keeper could not read was not answered with the guard (dumps left to fail %d):\n%s\n%s",
				fails.Load(), said(), ipRules(t))
		}
		time.Sleep(2 * time.Millisecond)
	}
	took := waitWhole(t, hr, tSelf5, 4*time.Second)
	if ns.keeper.repaired() == 0 {
		t.Fatal("whole again without the keeper writing")
	}
	t.Logf("guard up at once, whole again %s later, through rule changes every 50 ms", took)
}

// A rule of the same shape that also selects on a destination makes the kernel take the containment's add
// as a duplicate: the keeper says it could not put the rule back, and keeps the address refused.
func TestAKeeperBlockedByALookAlikeSaysSoAndStaysClosed(t *testing.T) {
	needRoot(t)
	ns, hr, said := keptRoute(t, tSelf5)
	waitWhole(t, hr, tSelf5, 2*time.Second)
	lookup := hr.rules(tSelf5)[1]
	alike := tagged(lookup.body())
	alike[1] = 64 // dst_len: to 2001:db8::/64
	alike = append(alike, nlAttr(unix.FRA_DST, netip.MustParseAddr("2001:db8::").AsSlice())...)
	addRaw(t, alike)
	t.Cleanup(func() { _ = delRaw(alike) })
	if err := delRaw(tagged(lookup.body())); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !waitSaid(said, "could not put the containment's routing rules back") {
		if time.Now().After(deadline) {
			v6, v4 := listRules(t)
			w := keepPlan(hr.rules(tSelf5), tSelf5, v6, v4)
			if !w.broken() {
				t.Skipf("this kernel added the exact rule beside the look-alike, so nothing blocks the keeper:\n%s", ipRules(t))
			}
			t.Fatalf("the keeper never said it could not put the lookup back:\n%s\n%s", said(), ipRules(t))
		}
		time.Sleep(20 * time.Millisecond)
	}
	v6, _ := listRules(t)
	if !keepPlan(hr.rules(tSelf5), tSelf5, v6, nil).guard {
		t.Fatalf("the keeper let the guard down with the lookup still missing:\n%s", ipRules(t))
	}
	_ = ns
}

// A host's own rule at the guard's priority that names the agent's address and selects on more stays
// whatever the containment does: its device refuses to start rather than take it with its guard.
func TestAHostsRuleAtTheGuardsPriorityIsNeverTaken(t *testing.T) {
	needRoot(t)
	touchLock(t, tSelf6)
	ip := []string{"-6", "rule", "add", "pref", fmt.Sprint(hostGuardPrio), "from", tSelf6.String(), "iif", "lo", "prohibit",
		"protocol", "kernel"}
	if out, err := exec.Command("ip", ip...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v %s", ip, err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "-6", "rule", "del", "pref", fmt.Sprint(hostGuardPrio), "from", tSelf6.String(), "iif", "lo",
			"prohibit").Run()
	})
	ns, err := CreateHostDevice(tSelf6)
	if err == nil {
		ns.Close()
	}
	want := fmt.Sprintf("%d:\tfrom %s iif lo prohibit", hostGuardPrio, tSelf6)
	if !strings.Contains(ipRules(t), want) {
		t.Fatalf("the host's rule at the guard's priority was taken (device made: %v):\n%s", err == nil, ipRules(t))
	}
	if err == nil {
		t.Fatal("the device was made though its guard could not be told from the host's rule")
	}
	t.Logf("refused, as it should be: %v", err)
	removeAgentAddrRules(tSelf6)
	_ = removeGuard(tSelf6)
}

// A rule missing when the keeper first looks, with that look's dump failing, is put back at the keeper's
// next period, however often other rules on the host change in between: the period is a deadline, not a
// wait that every notification starts again.
func TestTheKeepersPeriodIsADeadlineThatChurnNeverPutsOff(t *testing.T) {
	needRoot(t)
	oldEvery := keepEvery
	keepEvery = 500 * time.Millisecond
	t.Cleanup(func() { keepEvery = oldEvery })
	ns, _ := hostTUNAs(t, tSelf5)
	hr := ns.HostRoute()
	if err := delRaw(tagged(hr.rules(tSelf5)[2].body())); err != nil { // gone before the keeper starts
		t.Fatal(err)
	}
	var fails atomic.Int32
	fails.Store(1) // its first look's dump fails, so it knows nothing yet
	standIn := func(fam uint8) ([]ruleInfo, error) {
		if fails.Add(-1) >= 0 {
			return nil, errors.New("dump interrupted")
		}
		return dumpRulesErr(fam)
	}
	keepDumpHook.Store(&standIn)
	t.Cleanup(func() { keepDumpHook.Store(nil) })
	var quit atomic.Bool
	churned := make(chan struct{})
	go func() { // somebody else's rule, added and deleted every 50 ms
		defer close(churned)
		other := ruleBodyProhibit(unix.AF_INET6, 4250, netip.MustParseAddr("2001:db8:2620::5"))
		for !quit.Load() {
			addRaw(t, other)
			_ = delRaw(other)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer func() { quit.Store(true); <-churned }()
	ns.keepRules(t.Logf)
	took := waitWhole(t, hr, tSelf5, 3*time.Second)
	t.Logf("whole %s after the keeper started, through rule changes every 50 ms", took)
}

// While the host has no other usable global IPv6 address (systemd-networkd re-adding its SLAAC address,
// tentative until DAD ends), the kernel gives an unbound socket of the host's own the agent's address as
// its source, after it has routed the packet: the rules never see it. The gate on the root cgroup keeps
// it in: nothing from the agent's address leaves by anything but the tunnel or loopback.
func TestAHostSocketGivenTheAgentsAddressNeverLeavesByTheUplink(t *testing.T) {
	needRoot(t)
	up := startUplink6(t) // reachable from the host's own fd00:2620::1, proved inside
	hostTUNAs(t, tSelf5)
	// The host's own address goes, its route stays: as on a host whose SLAAC address is being re-added.
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("-6", "addr", "del", "fd00:2620::1/64", "dev", up.hostIf)
	ip("-6", "route", "replace", "fd00:2620::/64", "dev", up.hostIf)
	c, err := net.Dial("udp6", "[fd00:2620::2]:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if src := c.LocalAddr().(*net.UDPAddr).IP; !src.Equal(tSelf5.AsSlice()) {
		t.Skipf("control: the kernel gave the host's socket %s, not the agent's address, as its source", src)
	}
	refused := 0
	for i := 0; i < 50; i++ {
		if _, err := c.Write([]byte("host")); err != nil {
			refused++
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := up.datagrams.Load(); n > 0 {
		t.Fatalf("%d datagrams the host sent from the agent's address (%d of 50 refused) reached the uplink", n, refused)
	}
	t.Logf("the host's socket was given %s; 0 of 50 datagrams reached the uplink, %d refused at the send", tSelf5, refused)
}

// A killed containment's gate stays on the root cgroup, but its check on the agent's address goes with
// the command: the agent's next device carries the agent's traffic through its own tunnel at once.
func TestAKilledContainmentsAddressCheckGoesWithItsCommand(t *testing.T) {
	needRoot(t)
	needCgroup2(t)
	peer := startPeer(t)
	nsA, _ := hostTUNAs(t, tSelf4)
	ha := *nsA.HostRoute()
	h1 := startHelper(t, peer.addr)
	if _, err := Contain(h1.cmd.Process.Pid, tSelf4, ha, t.Logf); err != nil {
		t.Fatalf("Contain: %v", err)
	}
	t.Cleanup(func() {
		if _, notes, err := ReleaseStale(h1.cmd.Process.Pid, netip.Addr{}); err != nil || len(notes) > 0 {
			t.Errorf("releasing the killed containment: %v %v", err, notes)
		}
	})
	killDevice(nsA) // its gate stays: its containment record names it
	if gens := rootGateGenerations(needCgroup2(t)); !slicesContain(gens, ha.Gen) {
		t.Fatalf("control: the killed containment's gate (generation %d) is not on the root cgroup: %v", ha.Gen, gens)
	}
	nsB, sentB := hostTUNAs(t, tSelf4) // the agent's next device
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

func slicesContain(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The agent's address is deprecated on the host, so the host's own sockets never prefer it to an address
// of the host's that is only deprecated itself (RFC 6724 rule 3 ranks above rule 5): a host whose
// uplink address has merely aged keeps speaking as itself, rather than as the agent and refused.
func TestTheHostPrefersItsOwnDeprecatedAddressToTheAgents(t *testing.T) {
	needRoot(t)
	up := startUplink6(t)
	ns, _ := hostTUNAs(t, tSelf5)
	out, err := exec.Command("ip", "-6", "addr", "show", "dev", ns.HostRoute().Name).CombinedOutput()
	if err != nil || !strings.Contains(string(out), tSelf5.String()) || !strings.Contains(string(out), "deprecated") {
		t.Fatalf("the agent's address on the device is not deprecated (%v):\n%s", err, out)
	}
	if out, err := exec.Command("ip", "-6", "addr", "change", "fd00:2620::1/64", "dev", up.hostIf, "preferred_lft", "0",
		"nodad").CombinedOutput(); err != nil {
		t.Fatalf("deprecate the host's own address: %v %s", err, out)
	}
	c, err := net.Dial("udp6", "[fd00:2620::2]:9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if src := c.LocalAddr().(*net.UDPAddr).IP; !src.Equal(net.ParseIP("fd00:2620::1")) {
		t.Fatalf("with both addresses deprecated the host's socket was given %s, not its own address", src)
	}
	if _, err := c.Write([]byte("host")); err != nil {
		t.Fatalf("the host's own send was refused: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for up.datagrams.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if up.datagrams.Load() == 0 {
		t.Fatal("the host's own datagram never reached the uplink")
	}
}

// A dial through the device still leaves from the agent's address though it is deprecated: the tunnel's
// table names it as the preferred source.
func TestTheContainmentStillSpeaksFromItsDeprecatedAddress(t *testing.T) {
	needRoot(t)
	ns, sent := hostTUNAs(t, tSelf5)
	far := netip.MustParseAddr("2606:4700:4700::1001")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := ns.DialContext(ctx, "tcp", "["+far.String()+"]:443"); err == nil {
			c.Close()
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	if syn := waitTCP6(t, sent, far); addr16(syn[8:24]) != tSelf5 {
		t.Fatalf("the dial left from %s", addr16(syn[8:24]))
	}
}
