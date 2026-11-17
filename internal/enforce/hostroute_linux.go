// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// hostroute_linux.go is the tunnel's other home: a TUN device in the HOST's network namespace,
// for a process that is already running there and so cannot be put in a namespace of its own
// (contain_linux.go). The device carries the agent's /128 and, when it can, 192.0.0.2, exactly
// like the namespace's wsp0, and it is reached only through a routing table of its own that a
// rule selects by socket mark. Nothing in the host's main table points at it, so the host's own
// traffic never sees it; only a socket carrying the mark is routed in.
//
// Each containment gets a slot n, the number the kernel gives the device when it is created as
// "wsc%d". The slot names the table and the rule priority, so two live containments on one host
// never share either, and a slot is free exactly when no device holds its name. The kernel hands
// out the lowest free name, so a slot is used again as soon as its device is gone.
//
// The MARK is not the slot's. It is the containment's own, taken from a counter that is never
// reset while the host runs (markFor, nextGeneration), and it is what makes a socket the
// containment's: a packet enters the device only if it carries the mark (the device's admission
// program), and a packet carrying it leaves the host only through the device or loopback (the
// gate on the root cgroup, contain_linux.go). A socket keeps its mark after the containment is
// gone, so a mark used twice would let a socket of the first containment speak as the second.

const (
	hostIfPattern = "wsc%d"
	// hostRulePrio sits after the local table (0) and before main (32766). It also sits before
	// the 5210-5270 block a Tailscale client installs, so its own rules never see a contained
	// socket's traffic first.
	hostRulePrio  = 4300
	hostTableBase = 4300
	maxHostSlots  = 256
	// hostGuardPrio is the guard's, just above every slot: while a device swaps its agent's rules from an
	// earlier containment's to its own, "from <the /128> prohibit" there keeps the address refused.
	hostGuardPrio = hostRulePrio - 1
	// hostRuleProto is the protocol every rule a containment installs carries (FRA_PROTOCOL): kernel.
	// systemd-networkd, at its default ManageForeignRoutingPolicyRules=yes, deletes every policy rule it
	// did not configure except those with protocol kernel, whenever it configures a link it manages (its
	// start, `networkctl reconfigure`, `netplan apply`, a reload after a .network change). Deleting the
	// address rules of a live containment lets an unmarked packet from the /128 leave by the host's own
	// uplink (measured on Ubuntu 24.04), so the rules carry the one protocol networkd leaves alone. The
	// kernel gives it only to its own default rules, which name no source and sit at 0, 32766 and 32767,
	// and `ip rule add` writes none (unspec), so a rule in a containment's exact shape, at a slot's or the
	// guard's priority, carrying it, is a containment's: that is how a prune tells its own rules from a
	// host's, since a rule added without a priority lands just above the lowest slot's.
	hostRuleProto = unix.RTPROT_KERNEL
	// legacyRuleProto is what releases from before tagged their rules with: a refusal or a guard one of
	// them left is still a containment's, and goes the same way.
	legacyRuleProto = 0x57
	// legacyMarkBase | slot is the mark an earlier release gave every containment on a slot. It
	// is only ever deleted again, for a killed containment whose record predates the counter.
	legacyMarkBase = 0x77630000
	// A containment's mark is hostMarkSig with its generation spread over hostMarkFree. The bits
	// left out are the ones other software on a host reads or rewrites with a mask: kube-proxy's
	// 0x4000 and 0x8000, Cilium's 0xf00 nibble, the AWS VPC CNI's 0x80, and 0xf0000, which Calico's
	// iptables dataplane clears on every packet the host sends. Bit 23 keeps the third byte away
	// from Tailscale's 0x04 and 0x08 and from the legacy 0x63, and the top bit stays clear so the
	// mark is a positive 32-bit immediate in a BPF comparison.
	hostMarkSig   = 0x70800000
	hostMarkFree  = 0x0f70307f
	maxGeneration = 1<<16 - 1 // one per set bit of hostMarkFree
	// hostMarkMask is every bit a containment's mark is made of. The rule, the device's admission
	// program and the root gate all compare a mark under it, so a tool that sets one of the bits
	// left out (kube-proxy ORs 0x4000 into a packet it will masquerade) changes nothing here.
	hostMarkMask = hostMarkSig | hostMarkFree
)

// HostRoute is the routing a containment's tunnel device holds in the host namespace.
type HostRoute struct {
	Name    string // the device, wsc<n>
	Index   int    // its ifindex, which the cgroup's egress gate allows
	Slot    int
	Gen     uint32 // the containment's generation, which its mark encodes
	Mark    uint32 // the socket mark that selects the table and admits a packet to the device
	Table   uint32
	Prio    uint32
	CarryV4 bool   // whether IPv4 is routed in (see v4Reason)
	V4Note  string // why not, when it is not

	self netip.Addr // the agent's /128
	gate *rootGate  // the gate on the root cgroup, for the life of the device
}

// slotOf reads n back from the device's name.
func slotOf(name string) (int, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(name, "wsc"))
	if err != nil || !strings.HasPrefix(name, "wsc") || n < 0 || n >= maxHostSlots {
		return 0, fmt.Errorf("enforce: unexpected tunnel device name %q", name)
	}
	return n, nil
}

func routeFor(name string, idx, n int, gen uint32) HostRoute {
	return HostRoute{Name: name, Index: idx, Slot: n, Gen: gen, Mark: markFor(gen),
		Table: hostTableBase + uint32(n), Prio: hostRulePrio + uint32(n)}
}

// markFor spreads gen over hostMarkFree, low bit to low bit. It is one to one for every
// generation up to maxGeneration.
func markFor(gen uint32) uint32 {
	m := uint32(hostMarkSig)
	next := uint32(1)
	for b := uint32(0); b < 32; b++ {
		if hostMarkFree&(1<<b) == 0 {
			continue
		}
		if gen&next != 0 {
			m |= 1 << b
		}
		next <<= 1
	}
	return m
}

// genOf reads the generation back from a mark, or reports that the mark is not a containment's.
func genOf(mark uint32) (uint32, bool) {
	if mark&^hostMarkMask != 0 || mark&hostMarkSig != hostMarkSig {
		return 0, false
	}
	g, next := uint32(0), uint32(1)
	for b := uint32(0); b < 32; b++ {
		if hostMarkFree&(1<<b) == 0 {
			continue
		}
		if mark&(1<<b) != 0 {
			g |= next
		}
		next <<= 1
	}
	return g, g != 0
}

// generationFile holds the last generation handed out on this host since it booted. It lives on
// /run, a tmpfs, so it starts over exactly when every socket that could still carry an old mark
// is gone with the boot that made it.
const generationFile = "generation"

// nextGeneration takes the next generation, never one handed out before in this boot.
func nextGeneration() (uint32, error) {
	if err := secureDir(containState); err != nil {
		return 0, fmt.Errorf("enforce: the containment state directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(containState, generationFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("enforce: the containment counter: %w", err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Uid != 0 || st.Mode&0o077 != 0 {
		return 0, errors.New("enforce: the containment counter is not root's own")
	}
	return bumpGeneration(f, highestLiveGeneration())
}

// bootIDPath names this boot; the counter is good for one boot only.
var bootIDPath = "/proc/sys/kernel/random/boot_id"

// counterWait bounds how long a containment waits for another one that holds the counter: the
// lock is held for one read and one write, so a holder that keeps it longer is stopped or stuck.
var counterWait = 10 * time.Second

// bumpGeneration reads the counter in f, under an exclusive lock, and writes the next value back
// in one fixed-width write at the start of the file: a process killed at any point leaves either
// the old value or the new one, never an empty or a torn file. The value is handed out only once
// it is written.
//
// floor is the highest generation any containment state on the host still names (rules, records,
// root gates). A counter that is missing or empty while such state exists was removed under live
// containments, and starting over at 1 would hand out their marks again, so it starts above floor.
// A counter that is behind floor is not the one those containments took their marks from (a second
// /run), and is refused rather than trusted.
func bumpGeneration(f *os.File, floor uint32) (uint32, error) {
	fd := int(f.Fd())
	deadline := time.Now().Add(counterWait)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return 0, fmt.Errorf("enforce: cannot lock the containment counter: %w", err)
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("enforce: another containment has held the containment counter for %s (a stopped "+
				"`whisper contain`?); nothing was changed", counterWait)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	buf := make([]byte, 64)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("enforce: cannot read the containment counter: %w", err)
	}
	boot := readTrim(bootIDPath)
	last := uint64(0)
	if fs := strings.Fields(string(buf[:n])); len(fs) > 0 {
		if last, err = strconv.ParseUint(fs[0], 16, 32); err != nil {
			return 0, fmt.Errorf("enforce: the containment counter %s holds %q, not a number; removing the file is safe "+
				"(the next containment starts above every generation still in use)", f.Name(), fs[0])
		}
		// Written in an earlier boot (a /run that is not a tmpfs): no socket of that boot is left.
		if len(fs) > 1 && boot != "" && fs[1] != boot {
			last = 0
		}
	}
	switch {
	case last == 0 && floor > 0:
		last = uint64(floor)
	case last < uint64(floor):
		return 0, fmt.Errorf("enforce: a containment on this host carries generation %d, past this counter's %d, so "+
			"another counter is handing out marks (a second /run?); nothing was changed", floor, last)
	}
	if last >= maxGeneration {
		return 0, fmt.Errorf("enforce: this host has started %d containments since it booted, which is every mark a "+
			"containment can carry without sharing one; it takes a reboot to start over", maxGeneration)
	}
	next := uint32(last + 1)
	if boot == "" {
		boot = "-"
	}
	// Fixed width: the boot id is always 36 characters, so a write never leaves a tail of an older one.
	if _, err := f.WriteAt([]byte(fmt.Sprintf("%08x %-36s\n", next, boot)), 0); err != nil {
		return 0, fmt.Errorf("enforce: cannot write the containment counter: %w", err)
	}
	return next, nil
}

// v4Reason says why IPv4 cannot be carried on this host, or "" when it can.
//
//   - 192.0.0.2 already on an interface (a CLAT of the host's own) cannot be claimed twice.
//   - Strict reverse-path filtering (net.ipv4.conf.all.rp_filter = 1) checks a reply arriving
//     on the device against the MAIN table, where its source routes out of the host's own
//     uplink, and drops it. The effective setting is the larger of "all" and the device's, so
//     the device's own 0 cannot lift it.
//
// Not carried means not routed in: a v4 packet then takes the host's route and the cgroup's
// egress gate refuses it, so the socket sees EPERM. Refused, never leaked.
func v4Reason(clatInUse bool, rpAll string) string {
	switch {
	case clatInUse:
		return "192.0.0.2 is already in use on this host"
	case strings.TrimSpace(rpAll) == "1":
		return "strict reverse-path filtering (net.ipv4.conf.all.rp_filter=1) would drop the replies"
	}
	return ""
}

func clatInUse() bool {
	ifs, err := hostAddrs()
	if err != nil {
		return true // cannot tell: do not claim it
	}
	for _, a := range ifs {
		if a == CLATv4 {
			return true
		}
	}
	return false
}

// CreateHostDevice makes the containment's TUN device in the host namespace, gives it the
// /128 (and 192.0.0.2 when IPv4 can be carried), and installs its table, its rules and its gate on
// the root cgroup. On any error everything it made is gone again.
//
// The device admits a packet only if it carries the containment's mark (admitSpec), from the
// moment it exists: binding a socket to it, or naming it in IP_PKTINFO, is open to any process
// on the host, and over IPv4 the kernel then sends without a route, from the device's own
// 192.0.0.2, which the translator would turn into the agent's /128.
func CreateHostDevice(self netip.Addr) (*Namespace, error) {
	if !self.Is6() || self.Is4In6() {
		return nil, errors.New("enforce: the agent address must be an IPv6 /128")
	}
	host, err := nsInode()
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot read this host's network namespace: %w", err)
	}
	gen, err := nextGeneration()
	if err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("enforce: could not lift the locked-memory limit for BPF: %w", err)
	}
	v4why := v4Reason(clatInUse(), readTrim("/proc/sys/net/ipv4/conf/all/rp_filter"))
	dev, err := openTUN(hostIfPattern, markFor(gen))
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("enforce: the tunnel device has no name: %w", err)
	}
	n, err := slotOf(name)
	if err != nil {
		dev.Close()
		return nil, err
	}
	idx, err := ifIndex(name)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("enforce: the tunnel interface is missing: %w", err)
	}
	hr := routeFor(name, idx, n, gen)
	hr.CarryV4 = v4why == ""
	hr.V4Note = v4why
	hr.self = self
	// A device a killed command left is found by its record, which nobody holds any more, and its
	// gate and rules go before this one's are made.
	reapDeadDevices()
	// The guard keeps the agent's address refused while its rules from an earlier containment (whose
	// connections may still be ending) give way to this one's: make before break. A guard a killed
	// command left is this one's now, and goes with it.
	if err := addGuard(self); err != nil {
		dev.Close()
		return nil, fmt.Errorf("enforce: could not keep the agent's address refused while its rules are replaced: %w", err)
	}
	// The record goes down, held, before the gate goes on, so no gate is ever on the root cgroup
	// without a record that names it. The gate goes on before any rule routes the mark into the
	// device, so no packet carrying the mark ever reaches the device unchecked.
	rec, err := holdDeviceRecord(devRecord{Gen: gen, Slot: n, Mark: hr.Mark, Index: idx, Self: self.String()})
	if err != nil {
		_ = removeGuard(self) // nothing was swapped yet
		dev.Close()
		return nil, err
	}
	if hr.gate, err = attachRootGate(hr.Mark, idx, gen, self); err != nil {
		_ = removeGuard(self)
		dev.Close()
		releaseDeviceRecord(rec)
		return nil, err
	}
	hr.gate.rec = rec
	// Whatever a killed holder of this slot left at its priority and table goes before this one's
	// rules go in. The slot is this device's while it holds the name. So do the address rules a
	// killed containment of this same agent left on any slot: one on a lower slot would catch this
	// one's packets from the /128 first, look up an empty table and refuse them. The caller holds
	// the agent's lock, so no live containment of the agent owns them.
	removeSlotRules(hr.Prio, hr.Table)
	removeAgentAddrRules(self)
	if err := hr.install(self); err != nil {
		hr.removeRules()
		// The earlier containment's refusal went with the swap; one stays for whatever of it still ends,
		// or else the guard does.
		if addRuleBody(tagged(ruleBodyProhibit(unix.AF_INET6, hr.Prio, self))) == nil {
			_ = removeGuard(self)
		}
		dev.Close()
		hr.gate.detach() // last, once nothing can enter the device
		return nil, err
	}
	// The guard sits above every slot and would refuse this containment's own traffic from the address.
	if err := removeGuard(self); err != nil {
		hr.removeRules()
		dev.Close()
		hr.gate.detach()
		hint := fmt.Sprintf("`ip -6 rule del from %s prohibit pref %d` removes it", self, hostGuardPrio)
		if errors.Is(err, errGuardShadowed) {
			hint = fmt.Sprintf("`ip -6 -d rule show pref %d` shows both; the containment's guard is the one that "+
				"selects on nothing else, and it goes once the other rule is moved or removed", hostGuardPrio)
		}
		return nil, fmt.Errorf("enforce: could not take away the guard that kept the agent's address refused while its "+
			"rules were replaced (%v), and it would refuse the containment's own traffic: %s", err, hint)
	}
	// Other agents' refusals that nothing needs any more go now (refusals_linux.go), so a host that
	// contains many agents does not gather one per agent per boot. This one's agent is live, and kept.
	pruneAgentRefusals(self, host)
	return &Namespace{fd: -1, Inode: host, HostInode: host, Dev: dev, host: &hr}, nil
}

// addGuard puts "from self prohibit" at the guard's priority; one already there (a killed command's)
// is taken as this one's.
func addGuard(self netip.Addr) error {
	return addRuleBody(tagged(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, self)))
}

// removeGuard takes the guard away again, and reports whether one is still there. A guard an earlier
// release left carries that release's protocol, and goes too.
func removeGuard(self netip.Addr) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	return removeGuardOn(r, self)
}

// removeGuardOn takes every guard for self away over r, each only when the delete takes that very rule
// (deletesFirst): a delete names the priority, the action, the address and the protocol, and the kernel
// would take any rule matching those that selects on more, if it came first.
func removeGuardOn(r *rtnl, self netip.Addr) error {
	for i := 0; i < 64; i++ {
		list, err := dumpRulesErr(unix.AF_INET6)
		if err != nil {
			return err
		}
		var g *ruleInfo
		for j := range list {
			if isGuard(list[j], self) {
				g = &list[j]
				break
			}
		}
		if g == nil {
			return nil
		}
		if !deletesFirst(list, *g) {
			return fmt.Errorf("%w: another rule at priority %d names %s the same way ahead of it", errGuardShadowed,
				hostGuardPrio, self)
		}
		if err := r.do(unix.RTM_DELRULE, 0, withProto(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, self), g.proto)); err != nil &&
			!errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return errors.New("the guard would not go")
}

// errGuardShadowed is a guard no delete can take without taking a host's own rule first.
var errGuardShadowed = errors.New("the guard cannot be deleted on its own")

// isGuard reports whether a rule is the guard for self: exactly "from self prohibit" at hostGuardPrio,
// carrying a containment's protocol.
func isGuard(r ruleInfo, self netip.Addr) bool {
	return r.fam == unix.AF_INET6 && r.prio == hostGuardPrio && r.action == frActProhibit && r.table == 0 &&
		r.src == self && r.mark == 0 && r.mask == 0 && !r.extra && (r.proto == hostRuleProto || r.proto == legacyRuleProto)
}

// addRuleBody adds one rule; an identical rule already there is not an error.
func addRuleBody(body []byte) error {
	r, err := openRTNL()
	if err != nil {
		return err
	}
	defer r.close()
	if err := r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

// afterStop runs once the tunnel is gone (its rules removed, its TUN closed, its gate detached): it
// ends the TCP sockets that could still send from the agent's address and removes the agent's refusal
// once nothing needs it, and any other agent's that nothing needs either. The caller holds the agent's
// lock, as every command that makes a host device does. While a containment record names the agent (a
// killed containment this command failed to take over, or a release that could not give everything
// back), its connections are that containment's, held as they are, and nothing of them is ended.
func (hr *HostRoute) afterStop(hostNS uint64) {
	if !hr.self.Is6() {
		return
	}
	if !containedAgents()[hr.self] {
		endAgentSockets(hr.self)
	}
	pruneAgentRefusals(hr.self, hostNS)
}

// devRecord names a tunnel device's gate and rules, for as long as the device lives: its file is
// held under an exclusive lock by the command that made the device, and the kernel lets the lock go
// when that command dies, however it dies. A record nobody holds is a device that is gone.
type devRecord struct {
	Gen   uint32 `json:"gen"`
	Slot  int    `json:"slot"`
	Mark  uint32 `json:"mark"`
	Index int    `json:"index"`
	Self  string `json:"self"`
}

func devRecordPath(gen uint32) string {
	return filepath.Join(containState, fmt.Sprintf("dev-%04x.json", gen))
}

// heldRecord is a device record and the open, locked file that holds it.
type heldRecord struct {
	f    *os.File
	path string
}

// holdDeviceRecord writes the record to a new file, locks it, and only then puts it in place by
// rename, so a reaper never sees it unlocked. The lock follows the file through the rename.
func holdDeviceRecord(r devRecord) (*heldRecord, error) {
	fail := func(err error) (*heldRecord, error) {
		return nil, fmt.Errorf("enforce: could not write the tunnel device's record under %s: %w", containState, err)
	}
	if err := secureDir(containState); err != nil {
		return fail(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fail(err)
	}
	f, err := os.CreateTemp(containState, ".dev-*")
	if err != nil {
		return fail(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		os.Remove(f.Name())
		return fail(err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return fail(err)
	}
	if err := os.Rename(f.Name(), devRecordPath(r.Gen)); err != nil {
		f.Close()
		os.Remove(f.Name())
		return fail(err)
	}
	return &heldRecord{f: f, path: devRecordPath(r.Gen)}, nil
}

// releaseDeviceRecord removes the record and lets its lock go: the device and its gate are gone.
// The file is removed while still locked, so no reaper ever finds it unheld.
func releaseDeviceRecord(h *heldRecord) {
	if h == nil {
		return
	}
	_ = os.Remove(h.path)
	h.f.Close()
}

// drop lets the record's lock go and leaves the file, for the next device to reap.
func (h *heldRecord) drop() {
	if h != nil {
		h.f.Close()
	}
}

// reapDeadDevices clears what each device a killed command left still holds: its gate on the root
// cgroup and its mark's rule. Both are named by the dead device's generation, which no live device
// shares, so a reap that comes late, or twice, touches nothing alive. Its agent's address rules are
// not touched here: this runs under another agent's lock, and that agent's next containment may
// already hold the same slot with rules of the same shape. The slot's next holder takes the lookup,
// and the prohibit goes with the agent's next device, which clears it under its own lock, or with
// the first prune once nothing needs it (refusals_linux.go); until then it refuses the old /128. A
// device whose record is still held is alive and is left alone.
// A gate a containment record names is left too: a containment that was killed while it held a
// process keeps it, fail closed, until `whisper contain --release` or the agent's next containment
// takes it over.
func reapDeadDevices() {
	ents, err := os.ReadDir(containState)
	if err != nil {
		return
	}
	kept := containedGenerations()
	root := cgroupRoot()
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "dev-") || !strings.HasSuffix(name, ".json") {
			if strings.HasPrefix(name, ".dev-") || strings.HasPrefix(name, ".record-") {
				if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
					_ = os.Remove(filepath.Join(containState, name)) // a write a killed command never finished
				}
			}
			continue
		}
		path := filepath.Join(containState, name)
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			f.Close() // held: the device is alive
			continue
		}
		// Another reaper may have removed the file between the open and the lock: then it is done.
		var st, now syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &st) != nil || syscall.Stat(path, &now) != nil || now.Ino != st.Ino || now.Dev != st.Dev {
			f.Close()
			continue
		}
		// A record that cannot be read, or whose gate will not come off, stays: it is the only thing
		// that names that gate.
		var r devRecord
		if st.Uid != 0 || st.Mode&0o022 != 0 || json.NewDecoder(f).Decode(&r) != nil || r.Gen == 0 {
			f.Close()
			continue
		}
		if !kept[r.Gen] && !detachRootGatesOf(root, r.Gen) {
			f.Close()
			continue
		}
		if r.Slot >= 0 && r.Slot < maxHostSlots {
			deleteRules(hostRulePrio+uint32(r.Slot), hostTableBase+uint32(r.Slot), r.Mark, hostMarkMask)
		}
		_ = os.Remove(path)
		f.Close()
	}
}

// containedGenerations is every generation a containment record names: its own and the ones it
// took over.
func containedGenerations() map[uint32]bool {
	out := map[uint32]bool{}
	ents, err := os.ReadDir(containState)
	if err != nil {
		return out
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, "dev-") {
			if rec, err := readRecord(filepath.Join(containState, n)); err == nil {
				out[rec.Gen] = true
				for _, a := range rec.Adopt {
					out[a] = true
				}
			}
		}
	}
	return out
}

func cgroupRoot() string {
	mi, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return ""
	}
	root, _ := cgroup2Mount(string(mi))
	return root
}

// rootGate is the program a containment keeps on the root of the v2 hierarchy, for the life of its
// tunnel device, beside whatever else is there (BPF_F_ALLOW_MULTI), so it sees every socket on the
// host. A packet that carries the containment's mark leaves only through the tunnel or loopback,
// and enters the tunnel only from a socket that is the containment's: one in its cgroup, or one it
// adopted (a socket the sweep found from before the move, or this command's own), which carries a
// tag in tags that the kernel copies to every connection such a listener accepts.
//
// The mark alone is not enough: since Linux 5.17 CAP_NET_RAW may set any mark, and on a stock
// distribution a program such as mtr-packet holds it for every user, so anybody could put the
// mark on a socket bound to the device. The cgroup and the tag cannot be given to a socket that
// way. It is attached with the classic BPF_PROG_ATTACH, so a killed command leaves it in place and
// the containment fails closed; `whisper contain --release` finds it by its name.
type rootGate struct {
	prog *ebpf.Program
	// src keeps the agent's address in (sourceGateSpec), attached by a link this command holds: it goes
	// when the command does, with the device, however the command ends, while the gate itself stays.
	src     link.Link
	srcProg *ebpf.Program
	tags    *ebpf.Map // sockets the containment adopted
	cfg     *ebpf.Map // [0]: the containment's cgroup id, 0 until Contain sets it
	root    string    // the v2 hierarchy's mount point
	gen     uint32
	rec     *heldRecord // the device's record, held for the gate's life
}

// bpfFNoPrealloc and bpfFClone are BPF_F_NO_PREALLOC and BPF_F_CLONE from linux/bpf.h: socket storage
// is allocated per socket, and copied to a socket accepted from one that has it.
const (
	bpfFNoPrealloc = 0x1
	bpfFClone      = 0x200
	skbSkOff       = 168 // __sk_buff.sk
)

// rootGateName names a containment's program on the root cgroup after its generation, which is how
// a release finds it again, the containment's own or a killed one's.
func rootGateName(gen uint32) string { return fmt.Sprintf("wsc_gate_%04x", gen) }

// rootGateGenerations reads the generations of the gates on the root cgroup's egress.
func rootGateGenerations(root string) []uint32 {
	var out []uint32
	forRootGates(root, func(_ int, _ *ebpf.Program, name string) {
		if hex, ok := strings.CutPrefix(name, "wsc_gate_"); ok {
			if g, err := strconv.ParseUint(hex, 16, 32); err == nil {
				out = append(out, uint32(g))
			}
		}
	})
	return out
}

// forRootGates calls fn for every program attached to the root cgroup's egress, with its name, and
// reports whether it could look at all.
func forRootGates(root string, fn func(fd int, p *ebpf.Program, name string)) bool {
	if root == "" {
		return false
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	res, err := link.QueryPrograms(link.QueryOptions{Target: fd, Attach: ebpf.AttachCGroupInetEgress})
	if err != nil {
		return false
	}
	for _, ap := range res.Programs {
		p, err := ebpf.NewProgramFromID(ap.ID)
		if err != nil {
			continue
		}
		if info, err := p.Info(); err == nil {
			fn(fd, p, info.Name)
		}
		p.Close()
	}
	return true
}

// detachRootGatesOf removes every program on the root cgroup's egress that carries generation gen's
// name, and nothing else, and reports whether none is left; a root it could not look at counts as
// one that may still hold it. Gen 0 is a containment from before marks, which put nothing there.
func detachRootGatesOf(root string, gen uint32) bool {
	if gen == 0 {
		return true
	}
	want := rootGateName(gen)
	left := false
	looked := forRootGates(root, func(fd int, p *ebpf.Program, name string) {
		if name == want && link.RawDetachProgram(link.RawDetachProgramOptions{Target: fd, Program: p, Attach: ebpf.AttachCGroupInetEgress}) != nil {
			left = true
		}
	})
	return looked && !left
}

func attachRootGate(mark uint32, tunIdx int, gen uint32, self netip.Addr) (*rootGate, error) {
	mi, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot read %s: %w", mountinfoPath, err)
	}
	root, err := cgroup2Mount(string(mi))
	if err != nil {
		return nil, errors.New("enforce: this kernel has no cgroup v2 hierarchy, where the containment's gate goes")
	}
	g := &rootGate{root: root, gen: gen}
	ok := false
	defer func() {
		if !ok {
			g.close()
		}
	}()
	if g.tags, err = ebpf.NewMap(&ebpf.MapSpec{Name: "wsc_tags", Type: ebpf.SkStorage, KeySize: 4, ValueSize: 4,
		Flags: bpfFNoPrealloc | bpfFClone,
		Key:   &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Value: &btf.Int{Name: "u32", Size: 4}}); err != nil {
		return nil, fmt.Errorf("enforce: this kernel refused the containment's socket tags (socket storage, Linux 5.3+): %w", err)
	}
	if g.cfg, err = ebpf.NewMap(&ebpf.MapSpec{Name: "wsc_cfg", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}); err != nil {
		return nil, fmt.Errorf("enforce: this kernel refused the containment's gate settings: %w", err)
	}
	if g.prog, err = ebpf.NewProgram(rootGateSpec(mark, tunIdx, loIndex(), gen, g.tags, g.cfg)); err != nil {
		return nil, fmt.Errorf("enforce: this kernel refused the containment's gate on the root cgroup (cgroup_skb): %w", err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("enforce: could not open the cgroup hierarchy's root: %w", err)
	}
	defer unix.Close(fd)
	// The address check first: if the gate cannot go on after it, closing its link takes it off again.
	if self.IsValid() {
		if g.srcProg, err = ebpf.NewProgram(sourceGateSpec(self, tunIdx, loIndex(), gen)); err != nil {
			return nil, fmt.Errorf("enforce: this kernel refused the check that keeps the agent's address in (cgroup_skb): %w", err)
		}
		l, err := link.AttachRawLink(link.RawLinkOptions{Target: fd, Program: g.srcProg, Attach: ebpf.AttachCGroupInetEgress})
		if err != nil {
			switch {
			case errors.Is(err, unix.E2BIG):
				return nil, fmt.Errorf("enforce: could not attach the check that keeps the agent's address in to the root "+
					"cgroup (%v): %s", err, rootFull(root))
			case errors.Is(err, unix.EPERM), errors.Is(err, unix.EEXIST):
				return nil, fmt.Errorf("enforce: could not attach the check that keeps the agent's address in to the root "+
					"cgroup (%v): something else holds that attachment point alone", err)
			}
			return nil, fmt.Errorf("enforce: this kernel cannot tie the check that keeps the agent's address in to this "+
				"command (a cgroup link, Linux 5.7+): %w", err)
		}
		g.src = l // only once it is one: a failed attach returns a nil link, which the cleanup must not close
	}
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: fd, Program: g.prog,
		Attach: ebpf.AttachCGroupInetEgress, Flags: unix.BPF_F_ALLOW_MULTI}); err != nil {
		why := "something else holds that attachment point alone"
		if errors.Is(err, unix.E2BIG) {
			why = rootFull(root)
		}
		return nil, fmt.Errorf("enforce: could not attach the containment's gate to the root cgroup (%v): %s", err, why)
	}
	ok = true
	return g, nil
}

// dialTag is the tag this command's own dials carry. A socket the sweep adopts carries the
// generation instead, which never reaches this value, and counts only while the containment's cgroup
// is named to the gate: the release unnames it (setCgroup(0)), and with that every socket the sweep
// adopted stops being the containment's at once, wherever it is (in flight on a unix socket, passed
// out of the tree, waiting in an adopted listener's queue), while the command's own dials go on.
// Positive, so it compares as a 32-bit immediate unchanged.
const dialTag = 0x7fff0000

// adopt tags a socket the sweep found as the containment's own, for as long as the containment holds.
func (g *rootGate) adopt(fd int) error {
	if g == nil {
		return errors.New("enforce: the containment has no gate")
	}
	return g.tags.Update(int32(fd), g.gen, ebpf.UpdateAny)
}

// adoptDial tags one of this command's own dials, for the life of the device.
func (g *rootGate) adoptDial(fd int) error {
	if g == nil {
		return errors.New("enforce: the containment has no gate")
	}
	return g.tags.Update(int32(fd), uint32(dialTag), ebpf.UpdateAny)
}

// forget removes a socket's tag: it is given back to the program, no longer the containment's.
func (g *rootGate) forget(fd int) {
	if g != nil && g.tags != nil {
		_ = g.tags.Delete(int32(fd))
	}
}

// setCgroup tells the gate which cgroup's sockets are the containment's.
func (g *rootGate) setCgroup(id uint64) error {
	if g == nil {
		return errors.New("enforce: the containment has no gate")
	}
	return g.cfg.Update(uint32(0), id, ebpf.UpdateAny)
}

// detach removes the gate from the root cgroup and lets its maps go.
func (g *rootGate) detach() {
	if g == nil {
		return
	}
	detached := g.prog == nil
	if g.prog != nil {
		if fd, err := unix.Open(g.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
			detached = link.RawDetachProgram(link.RawDetachProgramOptions{Target: fd, Program: g.prog, Attach: ebpf.AttachCGroupInetEgress}) == nil
			unix.Close(fd)
		}
	}
	g.close()
	// A gate that would not come off keeps its record, unlocked once this command ends, for the
	// next device to reap.
	if detached {
		releaseDeviceRecord(g.rec)
	} else {
		g.rec.drop()
	}
	g.rec = nil
}

func (g *rootGate) close() {
	for _, c := range []interface{ Close() error }{g.src, g.srcProg, g.prog, g.tags, g.cfg} {
		if c != nil && !isNilCloser(c) {
			c.Close()
		}
	}
}

func isNilCloser(c interface{ Close() error }) bool {
	switch v := c.(type) {
	case *ebpf.Program:
		return v == nil
	case *ebpf.Map:
		return v == nil
	case *link.RawLink:
		return v == nil
	}
	return false
}

// rootFull says why the root cgroup takes no more egress programs, and what to do about it.
func rootFull(root string) string {
	return fmt.Sprintf("it already carries as many egress programs as the kernel allows (64; each containment "+
		"puts two there); `bpftool cgroup show %s` lists them, and `sudo whisper contain --release <pid>` removes a "+
		"killed containment's", root)
}

// sourceGateSpec keeps the agent's address in: an IPv6 packet whose source is self leaves only through the
// tunnel or loopback, whatever socket sent it. The kernel picks an unbound socket's source after it has
// routed the packet, so the rule "from <the /128> lookup" never sees it: while the host has no other
// usable global IPv6 address (systemd-networkd re-adding its SLAAC address, tentative until DAD ends;
// measured for about 2.4 s), its own sockets take the /128 and would leave by its uplink with it. The
// rules keep what knows its source before routing (a reply, a bound socket); this keeps what is given
// one after. It is a program of its own, attached by a link the command holds, because it must end with
// the device: once the TUN has closed the /128 is no longer the host's to give, and a check left behind
// with a killed command's gate would refuse the agent's next containment, or its connect.
func sourceGateSpec(self netip.Addr, tunIdx, loIdx int, gen uint32) *ebpf.ProgramSpec {
	ipv6 := binary.NativeEndian.Uint16([]byte{0x86, 0xdd}) // __sk_buff.protocol holds ETH_P_IPV6 in network order
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, skbProtocolOff, asm.Word),
		asm.JNE.Imm(asm.R2, int32(ipv6), "allow"), // IPv4 never reaches the helper
	}
	insns = append(insns, gateSourceCheck(self, tunIdx, loIdx)...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return &ebpf.ProgramSpec{
		Name: fmt.Sprintf("wsc_src_%04x", gen),
		Type: ebpf.CGroupSKB, AttachType: ebpf.AttachCGroupInetEgress, License: "MIT",
		Instructions: insns,
	}
}

// gateSourceCheck is sourceGateSpec's body, the context in R6 (symbol "speaks"): an IPv6 packet from self
// leaving by neither the tunnel nor loopback is dropped, anything else passes. The tunnel's and
// loopback's indexes are the host namespace's; a packet of another namespace that leaves by a device of
// the same number passes, and meets the rules if it is forwarded into the host. The
// source compares as four words read off the packet in host order, each against the same bytes of self
// read the same way, with 32-bit jumps (an immediate with its top bit set would otherwise be
// sign-extended). Without an address to compare there is no check: an unspecified one would refuse
// every packet sent from ::.
func gateSourceCheck(self netip.Addr, tunIdx, loIdx int) asm.Instructions {
	if !self.Is6() || self.Is4In6() || self.IsUnspecified() {
		return asm.Instructions{asm.Ja.Label("allow").WithSymbol("speaks")}
	}
	a := self.As16()
	out := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R6, skbIfindexOff, asm.Word).WithSymbol("speaks"),
		asm.JEq.Imm(asm.R2, int32(loIdx), "allow"),
		asm.JEq.Imm(asm.R2, int32(tunIdx), "allow"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -32),
		asm.Mov.Imm(asm.R4, 24), // the IPv6 header up to the end of its source
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "allow"), // shorter than that: not an IPv6 packet with a source
		asm.LoadMem(asm.R2, asm.RFP, -32, asm.Byte),
		asm.RSh.Imm(asm.R2, 4),
		asm.JNE.Imm(asm.R2, 6, "allow"),
	}
	for i := 0; i < 4; i++ {
		out = append(out,
			asm.LoadMem(asm.R2, asm.RFP, int16(-24+4*i), asm.Word),
			asm.JNE.Imm32(asm.R2, int32(binary.NativeEndian.Uint32(a[4*i:])), "allow"))
	}
	return append(out, asm.Ja.Label("drop"))
}

// rootGateSpec judges a packet that is the containment's: one that carries mark (under
// hostMarkMask), or whose socket is adopted (tagged in tags; a request socket by its listener; a tag
// the sweep gave counts only while cfg names the containment's cgroup, dialTag always). Such a
// packet passes through loopback; through the tunnel only if it is adopted or comes from the cgroup
// cfg names; anywhere else never. Being adopted is checked whatever the mark: a connection a pinned
// listener completes after the sweep takes its binding and mark from the request, made before the
// pin, so it carries neither, but the kernel copies the listener's tag to it. Every other packet passes; keeping the agent's address in is sourceGateSpec's.
func rootGateSpec(mark uint32, tunIdx, loIdx int, gen uint32, tags, cfg *ebpf.Map) *ebpf.ProgramSpec {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		// R7 = 1 when the packet's socket (or a request's listener) is adopted.
		asm.Mov.Imm(asm.R7, 0),
		asm.LoadMem(asm.R1, asm.R6, skbSkOff, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, "checked"),
		asm.FnSkFullsock.Call(),
		asm.JNE.Imm(asm.R0, 0, "lookup"),
		asm.LoadMem(asm.R1, asm.R6, skbSkOff, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, "checked"),
		asm.FnGetListenerSock.Call(),
		asm.JEq.Imm(asm.R0, 0, "checked"),
		asm.Mov.Reg(asm.R2, asm.R0).WithSymbol("lookup"),
		asm.LoadMapPtr(asm.R1, tags.FD()),
		asm.Mov.Imm(asm.R3, 0),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnSkStorageGet.Call(),
		asm.JEq.Imm(asm.R0, 0, "checked"),
		// The command's own dial is adopted for the device's life; a socket the sweep adopted only
		// while the containment's cgroup is named to the gate, which the release undoes.
		asm.LoadMem(asm.R2, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R2, dialTag, "adopted"),
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, cfg.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "checked"),
		asm.LoadMem(asm.R2, asm.R0, 0, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, "checked"),
		asm.Mov.Imm(asm.R7, 1).WithSymbol("adopted"),
		// Neither marked nor adopted: not the containment's.
		asm.LoadMem(asm.R2, asm.R6, skbMarkOff, asm.Word).WithSymbol("checked"),
		asm.And.Imm32(asm.R2, hostMarkMask),
		asm.JEq.Imm(asm.R2, int32(mark), "ours"),
		asm.JEq.Imm(asm.R7, 0, "allow"),
		asm.LoadMem(asm.R2, asm.R6, skbIfindexOff, asm.Word).WithSymbol("ours"),
		asm.JEq.Imm(asm.R2, int32(loIdx), "allow"),
		asm.JNE.Imm(asm.R2, int32(tunIdx), "drop"),
		asm.JEq.Imm(asm.R7, 1, "allow"),
		// Into the tunnel unadopted: only from the containment's cgroup, once Contain has named it.
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, cfg.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.LoadMem(asm.R8, asm.R0, 0, asm.DWord),
		asm.JEq.Imm(asm.R8, 0, "drop"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnSkbCgroupId.Call(),
		asm.JEq.Reg(asm.R0, asm.R8, "allow"),
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return &ebpf.ProgramSpec{
		Name: rootGateName(gen),
		Type: ebpf.CGroupSKB, AttachType: ebpf.AttachCGroupInetEgress, License: "MIT",
		Instructions: insns,
	}
}

// __sk_buff.len and __sk_buff.mark, from include/uapi/linux/bpf.h.
const (
	skbLenOff      = 0
	skbMarkOff     = 8
	skbProtocolOff = 16 // __sk_buff.protocol
)

// admitSpec passes a packet into the device whole when it carries mark (under hostMarkMask), and
// drops it otherwise.
// It runs in the device's transmit path (TUNSETFILTEREBPF), on every packet the host routes into
// it, whoever sent it and however it was routed.
func admitSpec(mark uint32) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name: "wsc_admit", Type: ebpf.SocketFilter, License: "MIT",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, skbMarkOff, asm.Word),
			asm.And.Imm32(asm.R2, hostMarkMask),
			asm.LoadMem(asm.R0, asm.R1, skbLenOff, asm.Word),
			asm.JEq.Imm(asm.R2, int32(mark), "admit"),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return().WithSymbol("admit"),
		},
	}
}

// attachAdmission loads admitSpec and attaches it to the TUN behind fd. The device keeps its own
// reference, so the program lives exactly as long as the device.
func attachAdmission(fd int, mark uint32) error {
	prog, err := ebpf.NewProgram(admitSpec(mark))
	if err != nil {
		return fmt.Errorf("enforce: this kernel refused the tunnel's admission program (socket filter): %w", err)
	}
	defer prog.Close()
	if err := unix.IoctlSetPointerInt(fd, unix.TUNSETFILTEREBPF, prog.FD()); err != nil {
		return fmt.Errorf("enforce: this kernel cannot filter what enters the tunnel device (TUNSETFILTEREBPF, Linux 4.16+): %w", err)
	}
	return nil
}

func (hr *HostRoute) install(self netip.Addr) error {
	r, err := openRTNL()
	if err != nil {
		return fmt.Errorf("enforce: %w", err)
	}
	defer r.close()
	type step struct {
		what string
		do   func() error
	}
	steps := []step{
		{"turn off link-local addressing", func() error { return r.noLinkLocal(hr.Index) }},
		// Deprecated (preferred lifetime 0), so the host's own sockets never prefer it as their source
		// over an address of the host's that is itself only deprecated; the table's routes still give
		// it to the containment's sockets as their preferred source.
		{"assign the agent address", func() error { return r.addAddrDeprecated(hr.Index, self) }},
	}
	if hr.CarryV4 {
		steps = append(steps, step{"assign the IPv4 translator address", func() error { return r.addAddr(hr.Index, CLATv4) }})
	}
	steps = append(steps,
		step{"bring the tunnel interface up", func() error { return r.setUp(hr.Index) }},
		step{"route IPv6 into the tunnel", func() error { return r.addTableDefault(hr.Index, hr.Table, self, minMTU) }},
	)
	rules := hr.rules(self)
	addRules := func(fam uint8) {
		for _, s := range rules {
			if s.fam == fam {
				body := tagged(s.body())
				steps = append(steps, step{s.what, func() error { return r.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body) }})
			}
		}
	}
	addRules(unix.AF_INET6)
	if hr.CarryV4 {
		steps = append(steps, step{"route IPv4 into the translator", func() error { return r.addTableDefault(hr.Index, hr.Table, CLATv4, v4MTU) }})
		addRules(unix.AF_INET)
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("enforce: could not %s: %w", s.what, err)
		}
	}
	if hr.CarryV4 {
		// The reply to a translated packet arrives on the device. Its own setting is made 0, and
		// v4Reason already established that "all" does not make the effective value strict.
		_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+hr.Name+"/rp_filter", []byte("0"), 0)
	}
	return nil
}

// removeRules deletes this containment's rules: the ones carrying its own mark, and the ones for
// its own addresses. The routes and addresses go with the device. A rule that is already gone is
// not an error.
func (hr *HostRoute) removeRules() {
	deleteRules(hr.Prio, hr.Table, hr.Mark, hostMarkMask)
	if hr.self.Is6() {
		// The prohibit is there before the lookup goes: something may have deleted it after the keeper
		// stopped.
		_ = addRuleBody(tagged(ruleBodyProhibit(unix.AF_INET6, hr.Prio, hr.self)))
	}
	// The lookup for the agent's address goes; its prohibit stays for now: a connection of the
	// containment still ending (FIN_WAIT1, LAST_ACK, TIME_WAIT) after the tunnel is gone would
	// otherwise retransmit from the /128 by the host's main table. afterStop removes it once no socket
	// could still send from the /128, and so does any later prune (refusals_linux.go).
	if hr.self.Is6() {
		for _, r := range dumpRules(unix.AF_INET6) {
			if r.prio == hr.Prio && r.src == hr.self && r.action == frActToTbl && r.table == hr.Table {
				deleteRuleBodies(func(fam uint8) []byte {
					if fam != unix.AF_INET6 {
						return nil
					}
					return ruleBodyFrom(fam, hr.Prio, hr.self, r.table)
				})
			}
		}
	}
	if hr.CarryV4 {
		// The translator's address is not the agent's: whichever containment carries IPv4 holds this
		// rule, so only its own removal (and the next holder of its slot) ever deletes it.
		deleteRuleBodies(func(fam uint8) []byte {
			if fam == unix.AF_INET {
				return ruleBodyFrom(fam, hr.Prio, CLATv4, hr.Table)
			}
			return nil
		})
	}
}

// removeAgentAddrRulesAt deletes self's own rules at prio: "from self lookup" (any table) and
// "from self prohibit". It never touches the translator's 192.0.0.2, which another agent's
// containment may hold.
func removeAgentAddrRulesAt(self netip.Addr, prio uint32) { removeAgentRulesAt(self, prio, true) }

// removeAgentRulesAt is removeAgentAddrRulesAt, leaving the prohibit when prohibitToo is false.
func removeAgentRulesAt(self netip.Addr, prio uint32, prohibitToo bool) {
	if !self.Is6() {
		return
	}
	for _, r := range dumpRules(unix.AF_INET6) {
		lookup := r.action == frActToTbl && r.table == hostTableBase+(prio-hostRulePrio)
		if r.prio == prio && r.src == self && (lookup || prohibitToo && r.action == frActProhibit) {
			deleteRuleBodies(func(fam uint8) []byte {
				if fam != unix.AF_INET6 {
					return nil
				}
				if r.action == frActProhibit {
					return ruleBodyProhibit(fam, prio, self)
				}
				return ruleBodyFrom(fam, prio, self, r.table)
			})
		}
	}
}

// removeAgentAddrRules deletes self's own rules at every slot's priority, read from one dump of the
// rules rather than asked for slot by slot.
func removeAgentAddrRules(self netip.Addr) {
	if !self.Is6() {
		return
	}
	seen := map[uint32]bool{}
	for _, r := range dumpRules(unix.AF_INET6) {
		if r.src == self && r.prio >= hostRulePrio && r.prio < hostRulePrio+maxHostSlots && !seen[r.prio] {
			seen[r.prio] = true
			removeAgentAddrRulesAt(self, r.prio)
		}
	}
}

// removeSlotRules deletes every rule at prio that looks up table, whatever its mark. Only a device
// that holds the slot's name calls it: a rule at the slot's priority and table is installed only
// by that holder, and removed by it before its TUN closes (Namespace.seal), so what is left there
// is a killed holder's.
//
// A prohibit left there is not deleted: it names only its own agent's /128, so it is harmless to the
// new holder, and it may still be refusing that address to a connection of the old containment that
// is ending. That agent's next device clears it, or the first prune once nothing needs it.
//
// Only what a containment installs is taken, a release that did not tag its rules included: a mark
// rule with a containment's mark, and a lookup of the slot's table from the translator's 192.0.0.2 or
// from a single IPv6 address. A host's own rule that happens to sit at the priority goes untouched.
func removeSlotRules(prio, table uint32) {
	r, err := openRTNL()
	if err != nil {
		return
	}
	defer r.close()
	slot := prio - hostRulePrio
	for _, fam := range []uint8{unix.AF_INET6, unix.AF_INET} {
		for _, ri := range dumpRules(fam) {
			if ri.prio != prio || ri.table != table || ri.action != frActToTbl {
				continue
			}
			var body []byte
			_, ours := genOf(ri.mark)
			switch {
			case ri.mark != 0 && (ours || ri.mark == legacyMarkBase|slot):
				body = ruleBody(fam, prio, ri.mark, ri.mask, table)
			case ri.mark == 0 && fam == unix.AF_INET && ri.src == CLATv4:
				body = ruleBodyFrom(fam, prio, ri.src, table)
			case ri.mark == 0 && fam == unix.AF_INET6 && ri.src.Is6() && !ri.src.Is4In6():
				body = ruleBodyFrom(fam, prio, ri.src, table)
			}
			if body != nil {
				_ = r.do(unix.RTM_DELRULE, 0, body)
			}
		}
	}
}

// deleteRules deletes, in both families, the rules at prio that look up table and carry exactly
// mark under mask. Mark 0 is refused: a delete that names no mark matches every mark.
func deleteRules(prio, table, mark, mask uint32) {
	if mark == 0 {
		return
	}
	deleteRuleBodies(func(fam uint8) []byte { return ruleBody(fam, prio, mark, mask, table) })
}

func deleteRuleBodies(body func(fam uint8) []byte) {
	r, err := openRTNL()
	if err != nil {
		return
	}
	defer r.close()
	for _, fam := range []uint8{unix.AF_INET6, unix.AF_INET} {
		b := body(fam)
		if b == nil {
			continue
		}
		for i := 0; i < 64 && r.do(unix.RTM_DELRULE, 0, b) == nil; i++ {
		}
	}
}

// RemoveStaleRules clears the rules a killed containment left: the ones at its slot carrying its
// own mark, and (given its agent) the agent's lookup there. Its prohibit is left to the prune
// (pruneAgentRefusals), which removes it only once no socket could still send from the /128. The
// translator's rule is left: it may be a live containment's now, and the slot's next holder clears it
// otherwise. A mark belongs to one containment for the whole boot, so this can never take the rule
// of a live containment that holds the slot now. They are harmless while they stay (their table
// is empty, or another containment's that does not admit their mark); this only tidies. A record
// from before the counter has no mark; its slot's shared mark is removed only while no device
// holds the slot, as that release did.
func RemoveStaleRules(slot int, mark uint32, self netip.Addr) {
	if slot < 0 || slot >= maxHostSlots {
		return
	}
	prio, table := hostRulePrio+uint32(slot), hostTableBase+uint32(slot)
	if mark != 0 {
		deleteRules(prio, table, mark, hostMarkMask)
		removeAgentRulesAt(self, prio, false)
		return
	}
	if _, err := ifIndex(fmt.Sprintf("wsc%d", slot)); err == nil {
		return
	}
	deleteRules(prio, table, legacyMarkBase|uint32(slot), 0xffffffff)
}

// highestLiveGeneration is the highest generation any containment state on this host still
// names: a rule at a slot's priority, a record, or a gate on the root cgroup.
func highestLiveGeneration() uint32 {
	high := uint32(0)
	note := func(g uint32) {
		if g > high {
			high = g
		}
	}
	for _, m := range slotRuleMarks() {
		if g, ok := genOf(m); ok {
			note(g)
		}
	}
	if ents, err := os.ReadDir(containState); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".json") {
				if rec, err := readRecord(filepath.Join(containState, e.Name())); err == nil {
					note(rec.Gen)
					for _, a := range rec.Adopt {
						note(a)
					}
				}
			}
		}
	}
	if mi, err := os.ReadFile(mountinfoPath); err == nil {
		if root, err := cgroup2Mount(string(mi)); err == nil {
			for _, g := range rootGateGenerations(root) {
				note(g)
			}
		}
	}
	return high
}

// slotRuleMarks returns the marks of the policy rules, of both families, at a slot's priority.
func slotRuleMarks() []uint32 {
	var out []uint32
	for _, fam := range []uint8{unix.AF_INET6, unix.AF_INET} {
		for _, r := range dumpRules(fam) {
			if r.prio >= hostRulePrio && r.prio < hostRulePrio+maxHostSlots && r.mark != 0 {
				out = append(out, r.mark)
			}
		}
	}
	return out
}

// ruleInfo is what a dump says about one policy rule.
type ruleInfo struct {
	prio, table, mark, mask uint32
	fam, action, proto      uint8
	src                     netip.Addr // the full-length source a rule names, or invalid
	// extra is set when the rule also selects on something no containment's rule does (a destination,
	// a TOS, "not", an interface, a uid or port range, an IP protocol, a suppressor, a goto, a tunnel
	// id, a realm, l3mdev), and unknown when it carries an attribute this code does not know. Either
	// makes it a rule in a containment's shape that is not a containment's.
	extra, unknown bool
}

// dumpRules reads every policy rule of one family, or as many as a dump that fails returned.
func dumpRules(fam uint8) []ruleInfo {
	out, _ := dumpRulesErr(fam)
	return out
}

// dumpRulesErr reads every policy rule of one family, in the kernel's order (by priority, and at one
// priority in the order they were added), and says whether the dump was complete.
func dumpRulesErr(fam uint8) ([]ruleInfo, error) {
	r, err := openRTNL()
	if err != nil {
		return nil, err
	}
	defer r.close()
	var out []ruleInfo
	h := fibRuleHdr{Family: fam}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	err = r.dump(unix.RTM_GETRULE, body, func(data []byte) {
		if ri, ok := parseRule(data); ok {
			out = append(out, ri)
		}
	})
	return out, err
}

// parseRule reads one rule message's payload (struct fib_rule_hdr and its attributes), from a dump or
// from a notification.
func parseRule(data []byte) (ruleInfo, bool) {
	const hdr = int(unsafe.Sizeof(fibRuleHdr{}))
	if len(data) < hdr {
		return ruleInfo{}, false
	}
	var ri ruleInfo
	srcLen, action := data[2], data[7]
	ri.fam = data[0]
	ri.action = action
	ri.table = uint32(data[4])
	ri.extra = data[1] != 0 || data[3] != 0 || binary.NativeEndian.Uint32(data[8:12]) != 0 // dst_len, tos, flags
	off := hdr
	for off+4 <= len(data) {
		l := int(binary.NativeEndian.Uint16(data[off:]))
		if l < 4 || off+l > len(data) {
			ri.unknown = true // a broken attribute: whatever follows cannot be read
			break
		}
		raw := binary.NativeEndian.Uint16(data[off+2:])
		typ := raw &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)
		if raw != typ {
			ri.unknown = true // no rule attribute the kernel lists is nested
		}
		val := data[off+4 : off+l]
		switch {
		case typ == fraPriority && len(val) >= 4:
			ri.prio = binary.NativeEndian.Uint32(val)
		case typ == fraFwmark && len(val) >= 4:
			ri.mark = binary.NativeEndian.Uint32(val)
		case typ == fraFwmask && len(val) >= 4:
			ri.mask = binary.NativeEndian.Uint32(val)
		case typ == fraTable && len(val) >= 4:
			ri.table = binary.NativeEndian.Uint32(val)
		case typ == fraProtocol && len(val) >= 1:
			ri.proto = val[0]
		case typ == fraSrc:
			if a, ok := netip.AddrFromSlice(val); ok && int(srcLen) == a.BitLen() {
				ri.src = a
			} else {
				ri.extra = true // a source shorter than an address
			}
		case typ == unix.FRA_SUPPRESS_PREFIXLEN || typ == unix.FRA_SUPPRESS_IFGROUP:
			// The kernel always lists the prefix length; -1 is "not set".
			if len(val) < 4 || binary.NativeEndian.Uint32(val) != 0xffffffff {
				ri.extra = true
			}
		case typ == unix.FRA_PAD:
		case typ == unix.FRA_DST, typ == unix.FRA_IIFNAME, typ == unix.FRA_GOTO, typ == unix.FRA_FLOW,
			typ == unix.FRA_TUN_ID, typ == unix.FRA_OIFNAME, typ == unix.FRA_L3MDEV, typ == unix.FRA_UID_RANGE,
			typ == unix.FRA_IP_PROTO, typ == unix.FRA_SPORT_RANGE, typ == unix.FRA_DPORT_RANGE,
			typ >= fraDSCP && typ <= fraDSCPMask:
			ri.extra = true
		default:
			ri.unknown = true
		}
		off += (l + 3) &^ 3
	}
	if off < len(data) {
		ri.unknown = true // bytes no attribute accounts for
	}
	return ri, true
}

// deletesFirst says whether a delete of rule c, named by its priority, action, table (for a lookup),
// protocol and full-length source, takes c itself. The kernel deletes the first rule, in its order,
// that matches every field a delete names, and takes any value for every field it leaves out (a
// destination, an interface, a mark, "not"), so a rule of anybody else's that matches those fields and
// selects on something more, sitting ahead of c, would go instead.
func deletesFirst(list []ruleInfo, c ruleInfo) bool {
	for _, r := range list {
		if r.prio == c.prio && r.action == c.action && (c.action != frActToTbl || r.table == c.table) &&
			r.proto == c.proto && r.src == c.src {
			return r == c
		}
	}
	return false
}

// dial opens a connection the way a contained socket's leaves: with the route's mark, which
// selects the tunnel's table (whose preferred source is the /128), and also bound to the device,
// so that this process, which is not in the containment's cgroup and so not under its gate, can
// still never leave another way. IPv4 is refused outright when the device does not carry it.
//
// The device's name is free for the next containment on the host the moment its TUN closes, and
// the slot it names carries the same mark and table. Two things keep a late dial of this one off
// that one's tunnel. The socket is bound to the device's INDEX, which the kernel hands out in a
// cycle over 2^31 values and so not to the next device it makes (only root, naming an index or
// moving a device in from another namespace, can place one on a given index), so a dial that
// outlives the device is bound to an index nothing holds and reaches nothing, whoever holds the
// name by then. And it is
// marked and bound inside whileOpen, the namespace's guard, which every teardown Whisper drives
// seals before the TUN closes (Namespace.seal), so a dial that starts later is refused before it
// touches the socket.
func (hr *HostRoute) dial(ctx context.Context, network, addr, host string, whileOpen func(func() error) error) (net.Conn, error) {
	if a, err := netip.ParseAddr(host); err == nil && a.Unmap().Is4() && !hr.CarryV4 {
		return nil, fmt.Errorf("enforce: IPv4 is not carried here (%s)", hr.V4Note)
	}
	mark, index, name, gate := int(hr.Mark), hr.Index, hr.Name, hr.gate
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if cerr := rc.Control(func(fd uintptr) {
			serr = whileOpen(func() error {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
					return err
				}
				if err := gate.adoptDial(int(fd)); err != nil {
					return err
				}
				return bindToDevice(int(fd), index, name)
			})
		}); cerr != nil {
			return cerr
		}
		return serr
	}}
	return d.DialContext(ctx, network, addr)
}

// bindToDevice binds a socket to the device with this index. A kernel older than 5.0 has no
// SO_BINDTOIFINDEX and gets the device's name instead, which the seal keeps safe on every
// teardown Whisper drives. Index 0 would mean "unbind", so it is refused, never sent.
func bindToDevice(fd, index int, name string) error {
	if index <= 0 {
		return fmt.Errorf("enforce: the tunnel device %s has no interface index", name)
	}
	err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, index)
	if errors.Is(err, unix.ENOPROTOOPT) {
		return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
	}
	return err
}

// addTableDefault installs a default route of src's family through the interface, in table,
// with src as the preferred source: a socket that has not bound an address gets the agent's
// at connect() from the route itself, so no packet ever needs its source rewritten.
func (r *rtnl) addTableDefault(index int, table uint32, src netip.Addr, mtu uint32) error {
	var m unix.RtMsg
	m.Table = unix.RT_TABLE_UNSPEC
	m.Protocol = unix.RTPROT_BOOT
	m.Type = unix.RTN_UNICAST
	if src.Is6() {
		m.Family = unix.AF_INET6
		m.Scope = unix.RT_SCOPE_UNIVERSE
	} else {
		m.Family = unix.AF_INET
		m.Scope = unix.RT_SCOPE_LINK
	}
	body := append([]byte(nil), (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.RTA_TABLE, u32(table))...)
	body = append(body, nlAttr(unix.RTA_OIF, u32(uint32(index)))...)
	body = append(body, nlAttr(unix.RTA_PREFSRC, src.AsSlice())...)
	body = append(body, nlAttr(unix.RTA_METRICS|unix.NLA_F_NESTED, nlAttr(unix.RTAX_MTU, u32(mtu)))...)
	return r.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// fibRuleHdr is struct fib_rule_hdr from linux/fib_rules.h.
type fibRuleHdr struct {
	Family, DstLen, SrcLen, Tos uint8
	Table                       uint8
	Res1, Res2                  uint8
	Action                      uint8
	Flags                       uint32
}

const (
	fraSrc      = 2  // FRA_SRC
	fraPriority = 6  // FRA_PRIORITY
	fraFwmark   = 10 // FRA_FWMARK
	fraTable    = 15 // FRA_TABLE
	fraFwmask   = 16 // FRA_FWMASK
	fraProtocol = 21 // FRA_PROTOCOL (Linux 4.17)
	// FRA_DSCP, FRA_FLOWLABEL, FRA_FLOWLABEL_MASK, FRA_SPORT_MASK, FRA_DPORT_MASK and FRA_DSCP_MASK (Linux
	// 6.13 to 6.15): selectors, listed only when set, which a delete that does not name them ignores.
	fraDSCP       = 25
	fraDSCPMask   = 30
	frActToTbl    = 1 // FR_ACT_TO_TBL
	frActProhibit = 8 // FR_ACT_PROHIBIT
)

// ruleBody encodes "priority prio fwmark mark/mask lookup table" for one family.
func ruleBody(fam uint8, prio, mark, mask, table uint32) []byte {
	h := fibRuleHdr{Family: fam, Table: unix.RT_TABLE_UNSPEC, Action: frActToTbl}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	body = append(body, nlAttr(fraPriority, u32(prio))...)
	body = append(body, nlAttr(fraFwmark, u32(mark))...)
	body = append(body, nlAttr(fraFwmask, u32(mask))...)
	body = append(body, nlAttr(fraTable, u32(table))...)
	return body
}

// ruleBodyFrom encodes "priority prio from src lookup table": a packet from the agent's address
// that carries no mark (a reply the kernel makes, or a socket outside the containment bound to the
// address) is routed into the tunnel, where the device's admission program refuses it, instead of
// out of the host's own uplink with the agent's address as its source.
func ruleBodyFrom(fam uint8, prio uint32, src netip.Addr, table uint32) []byte {
	h := fibRuleHdr{Family: fam, SrcLen: uint8(src.BitLen()), Table: unix.RT_TABLE_UNSPEC, Action: frActToTbl}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	body = append(body, nlAttr(fraPriority, u32(prio))...)
	body = append(body, nlAttr(fraSrc, src.AsSlice())...)
	body = append(body, nlAttr(fraTable, u32(table))...)
	return body
}

// ruleBodyProhibit encodes "priority prio from src prohibit", after the lookup: when the tunnel's
// table is empty (its device gone with a killed command), the agent's address is refused rather
// than routed by main.
func ruleBodyProhibit(fam uint8, prio uint32, src netip.Addr) []byte {
	h := fibRuleHdr{Family: fam, SrcLen: uint8(src.BitLen()), Action: frActProhibit}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	body = append(body, nlAttr(fraPriority, u32(prio))...)
	body = append(body, nlAttr(fraSrc, src.AsSlice())...)
	return body
}

func (r *rtnl) rule(typ uint16, fam uint8, prio, mark, table uint32) error {
	flags := uint16(0)
	body := ruleBody(fam, prio, mark, hostMarkMask, table)
	if typ == unix.RTM_NEWRULE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
		body = tagged(body)
	}
	return r.do(typ, flags, body)
}

// tagged adds hostRuleProto to a rule body. A rule a containment installs carries it, and a delete
// that names it matches only a rule carrying it; a prune and a guard's removal also check, from a dump,
// that the delete takes the very rule they mean (deletesFirst). The other deletes name the
// exact shapes a containment installs (a containment's mark, a lookup of the slot's own table from a
// single address, the agent's own address under its lock), so they also take the rules of a release
// that tagged them otherwise or not at all, which last until the next boot at most; a host's own rule
// in such a shape (table 4300+n at priority 4300+n, or the agent's own /128) is the only one they
// could take.
func tagged(body []byte) []byte { return withProto(body, hostRuleProto) }

// withProto adds a protocol to a rule body: a rule added with it carries it, and a delete that names
// it matches only a rule carrying it.
func withProto(body []byte, proto uint8) []byte {
	return append(body, nlAttr(fraProtocol, []byte{proto})...)
}

// hostAddrs lists every address on every interface of the calling thread's namespace.
func hostAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if p, perr := netip.ParsePrefix(a.String()); perr == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
