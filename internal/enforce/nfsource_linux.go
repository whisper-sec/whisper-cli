// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// nfsource_linux.go keeps the agent's address in for the packets that belong to no socket. While the
// host has no usable global IPv6 address of its own (systemd-networkd re-adding its SLAAC address, tentative
// until DAD ends; a host whose only route is an RA default with no address of its own), the kernel picks the
// agent's /128 as the source of anything that picks its source after routing. wsc_src, a cgroup program, refuses
// a socket's packet from it; but a kernel tunnel's outer packet (a WireGuard keepalive or handshake, a VXLAN or
// Geneve frame) passes no cgroup program: a keepalive has no socket at all, and an outer packet carries the inner
// sender's socket, not the tunnel's, which the cgroup hook compares. Nor does a packet the host forwards and
// masquerades, whose source NAT picks the same way. All of them reach netfilter's IPv6 postrouting, which every
// packet the host sends or forwards passes once its source is final. So the containment adds a netfilter program
// of its own there, wsc_nf_<generation>, attached by a link the command holds, so it ends with the command exactly
// as wsc_src does.
//
// Its context is two kernel pointers (struct bpf_nf_ctx), read through the running kernel's BTF: the hook's state,
// for the device the packet leaves by, and the packet, whose source is read with bpf_probe_read_kernel. The kernel
// lets only a program that declares a GPL-compatible licence read either, so this program, and only this one,
// declares nfSourceLicense: the Go that writes it stays MIT, and the program may be used under MIT. It counts what
// it holds, which is both the proof that it works (a probe it must hold, when it is linked) and what the command
// tells the operator. Without the hook (Linux before 6.4, no BTF, a kernel that refuses the program) the
// containment goes ahead without it, with every other protection, and says so in one line.

const (
	// nfSourcePriority places the check after source NAT, which runs at 100 whatever priority an nftables nat
	// chain declares, so it judges the source a packet actually leaves with, and before conntrack's confirm,
	// which stays last (a BPF link may not take NF_IP_PRI_LAST, INT_MAX). Linux 6.8 links a BPF program only at
	// a priority no other hook holds at that hook (a second check at the same one got EBUSY, measured; an
	// nftables base chain or SELinux's postrouting hook at 225 counts too; RHEL 9.8's backport lets them share,
	// measured), so each check sits at
	// nfSourcePriority plus its device's slot, which no other live containment holds, and steps on by
	// maxHostSlots past another hook's. The base is high and odd, INT_MAX - 0xffff, so that neither do the
	// round numbers other software reaches for (0, 100, 200, 300) meet one of these, nor would a later program
	// at one of them be refused for it.
	nfSourcePriority = 1<<31 - 1 - 0xffff
	nfPriorityTries  = 4
	// nfSourceLicense is the licence this one program declares to the kernel. A netfilter program is handed
	// kernel structures (struct nf_hook_state, struct sk_buff), and reading a packet takes bpf_probe_read_kernel
	// or the dynptr kfuncs; the kernel allows none of that to a program whose licence is not GPL-compatible. The
	// same program declared "MIT" is refused on Linux 6.8 ("Cannot access kernel 'struct nf_hook_state' from
	// non-GPL compatible program"; measured, and kept true by TestTheNetfilterCheckNeedsAGPLCompatibleLicence).
	// "Dual MIT/GPL" is the kernel's standard string for that: the program may be used under MIT, and the Go that
	// writes it is MIT like the rest of the CLI.
	nfSourceLicense = "Dual MIT/GPL"
	// The check's counts map: [nfHeld] packets it held, [nfLastOut] the index of the device the last one was
	// leaving by.
	nfHeld    = 0
	nfLastOut = 1
	// The proof's slots: [nfProbeHit] is set to 1 when a held packet carries the probe's own nonce, which
	// [nfProbeWant] holds under the mask in [nfProbeMask]; the nonce is the 8 bytes after the IPv6 header (a UDP
	// probe's ports, an echo's type, id and sequence), random, so no other process can supply it. A mask of 0
	// means no probe is out.
	nfProbeHit  = 2
	nfProbeWant = 3
	nfProbeMask = 4
	nfSlots     = 5
)

// nfSourceName names a containment's netfilter check after its generation, as its other programs are, and
// nfHeldName its count of what it held.
func nfSourceName(gen uint32) string { return fmt.Sprintf("wsc_nf_%04x", gen) }
func nfHeldName(gen uint32) string   { return fmt.Sprintf("wsc_nfh_%04x", gen) }

// nfOffsets are the byte offsets the check reads, in the running kernel's own layout.
type nfOffsets struct {
	out           int16 // struct nf_hook_state.out, a struct net_device *
	ifindex       int16 // struct net_device.ifindex, an int
	head          int16 // struct sk_buff.head, an unsigned char *
	networkHeader int16 // struct sk_buff.network_header, a __u16
}

var kernelNF struct {
	mu  sync.Mutex
	off *nfOffsets // only a success is kept: a failure is read again by the next device
}

// kernelBTFPath is the running kernel's own BTF. Nothing else is read: a vmlinux on disk may be another build.
const kernelBTFPath = "/sys/kernel/btf/vmlinux"

// errNoBTF is a kernel without BTF; any other reason the offsets could not be read is a fault of this release.
var errNoBTF = fmt.Errorf("it publishes no BTF (%s)", kernelBTFPath)

// layoutUnavailable says why the offsets could not be read: a kernel without BTF wants one built with it; a
// kernel whose BTF this release cannot read, or that lacks or lays out a member otherwise, is this release's fault.
func layoutUnavailable(err error) *nfUnavailable {
	if errors.Is(err, errNoBTF) {
		return &nfUnavailable{why: err.Error(), remedy: "a kernel built with BTF"}
	}
	return &nfUnavailable{why: "this release could not read the kernel's layout: " + err.Error(),
		remedy: "a report of it, please"}
}

// kernelNFOffsets reads the offsets from the running kernel's BTF, and keeps them once it has.
func kernelNFOffsets() (nfOffsets, error) {
	kernelNF.mu.Lock()
	defer kernelNF.mu.Unlock()
	if kernelNF.off != nil {
		return *kernelNF.off, nil
	}
	f, err := os.Open(kernelBTFPath)
	if err != nil {
		return nfOffsets{}, errNoBTF
	}
	defer f.Close()
	spec, err := btf.LoadSpecFromReader(f)
	if err != nil {
		return nfOffsets{}, fmt.Errorf("this kernel's BTF could not be read: %w", err)
	}
	o, err := nfOffsetsFrom(func(name string) (btf.Type, error) {
		var s *btf.Struct
		err := spec.TypeByName(name, &s)
		return s, err
	})
	if err != nil {
		return nfOffsets{}, err
	}
	kernelNF.off = &o
	return o, nil
}

// nfOffsetsFrom finds the offsets through lookup, and checks that each member is what the program reads: a pointer
// to a struct net_device, an int of 4 bytes, a pointer, and a 2-byte integer that is not a bitfield. A layout it
// would misread is refused, never guessed at.
func nfOffsetsFrom(lookup func(name string) (btf.Type, error)) (nfOffsets, error) {
	var o nfOffsets
	type want struct {
		typ, member string
		dst         *int16
		check       func(btf.Type) bool
	}
	isPtr := func(t btf.Type) bool { _, ok := btf.UnderlyingType(t).(*btf.Pointer); return ok }
	isInt := func(size uint32) func(btf.Type) bool {
		return func(t btf.Type) bool { i, ok := btf.UnderlyingType(t).(*btf.Int); return ok && i.Size == size }
	}
	toNetDevice := func(t btf.Type) bool {
		p, ok := btf.UnderlyingType(t).(*btf.Pointer)
		if !ok {
			return false
		}
		s, ok := btf.UnderlyingType(p.Target).(*btf.Struct)
		return ok && s.Name == "net_device"
	}
	for _, w := range []want{
		{"nf_hook_state", "out", &o.out, toNetDevice},
		{"net_device", "ifindex", &o.ifindex, isInt(4)},
		{"sk_buff", "head", &o.head, isPtr},
		{"sk_buff", "network_header", &o.networkHeader, isInt(2)},
	} {
		t, err := lookup(w.typ)
		if err != nil {
			return nfOffsets{}, fmt.Errorf("the kernel's BTF has no struct %s: %w", w.typ, err)
		}
		m, off, ok := memberAt(t, w.member)
		if !ok {
			return nfOffsets{}, fmt.Errorf("the kernel's struct %s has no member %s", w.typ, w.member)
		}
		if m.BitfieldSize != 0 || off%8 != 0 || !w.check(m.Type) || off/8 > 1<<15-8 {
			return nfOffsets{}, fmt.Errorf("the kernel's %s.%s is not laid out as this check reads it", w.typ, w.member)
		}
		*w.dst = int16(off / 8)
	}
	return o, nil
}

// memberAt finds a named member of a struct or union, looking through anonymous members (the kernel groups
// sk_buff's headers in an anonymous union, struct_group), and returns it with its offset in bits from the start.
func memberAt(t btf.Type, name string) (btf.Member, uint32, bool) {
	var members []btf.Member
	switch v := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = v.Members
	case *btf.Union:
		members = v.Members
	default:
		return btf.Member{}, 0, false
	}
	for _, m := range members {
		if m.Name == name {
			return m, uint32(m.Offset), true
		}
	}
	for _, m := range members {
		if m.Name != "" {
			continue
		}
		if inner, off, ok := memberAt(m.Type, name); ok {
			return inner, uint32(m.Offset) + off, true
		}
	}
	return btf.Member{}, 0, false
}

// nfSourceSpec drops an IPv6 packet whose source is self and that leaves by a device other than the tunnel or
// loopback, counting it in the map behind countsFD, and accepts every other packet. Its context (R1) is struct
// bpf_nf_ctx { state; skb; }. Anything it cannot read is accepted: every postrouting caller names a device and sets the network
// header, so an unreadable field means a kernel this check does not understand, and a check that failed on every
// packet must never become the host's outage (the probe in attachNFSource catches one that holds nothing). The
// source compares as four words read in host order, each against the same bytes of self, with 32-bit jumps.
func nfSourceSpec(self netip.Addr, tunIdx, loIdx int, gen uint32, o nfOffsets, countsFD int) *ebpf.ProgramSpec {
	a := self.As16()
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, 0, asm.DWord), // ctx->state
		asm.JEq.Imm(asm.R2, 0, "accept"),
		asm.LoadMem(asm.R3, asm.R2, o.out, asm.DWord), // state->out
		asm.JEq.Imm(asm.R3, 0, "accept"),
		asm.LoadMem(asm.R7, asm.R3, o.ifindex, asm.Word), // out->ifindex, kept for the count
		asm.JEq.Imm(asm.R7, int32(loIdx), "accept"),
		asm.JEq.Imm(asm.R7, int32(tunIdx), "accept"),
		asm.LoadMem(asm.R2, asm.R6, 8, asm.DWord), // ctx->skb
		asm.JEq.Imm(asm.R2, 0, "accept"),
		asm.LoadMem(asm.R3, asm.R2, o.head, asm.DWord),
		asm.LoadMem(asm.R4, asm.R2, o.networkHeader, asm.Half),
		asm.Add.Reg(asm.R3, asm.R4),
		asm.Mov.Reg(asm.R8, asm.R3), // the IPv6 header, kept for the probe's nonce
		asm.Add.Imm(asm.R3, 8),      // the IPv6 source
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "accept"),
	}
	for i := 0; i < 4; i++ {
		insns = append(insns,
			asm.LoadMem(asm.R2, asm.RFP, int16(-16+4*i), asm.Word),
			asm.JNE.Imm32(asm.R2, int32(binary.NativeEndian.Uint32(a[4*i:])), "accept"))
	}
	// Held. If a probe is out (its mask is not 0) and this packet carries its nonce, say so in nfProbeHit.
	lookup := func(slot int32, miss string) asm.Instructions {
		return asm.Instructions{
			asm.Mov.Imm(asm.R2, slot),
			asm.StoreMem(asm.RFP, -20, asm.R2, asm.Word),
			asm.LoadMapPtr(asm.R1, countsFD),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -20),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, miss),
		}
	}
	insns = append(insns, lookup(nfProbeMask, "count")...)
	insns = append(insns,
		asm.LoadMem(asm.R9, asm.R0, 0, asm.DWord),
		asm.JEq.Imm(asm.R9, 0, "count"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -32),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.Add.Imm(asm.R3, 40), // the 8 bytes after the IPv6 header
		asm.FnProbeReadKernel.Call(),
		asm.JNE.Imm(asm.R0, 0, "count"),
	)
	insns = append(insns, lookup(nfProbeWant, "count")...)
	insns = append(insns,
		asm.LoadMem(asm.R2, asm.R0, 0, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, -32, asm.DWord),
		asm.And.Reg(asm.R1, asm.R9),
		asm.JNE.Reg(asm.R1, asm.R2, "count"),
	)
	insns = append(insns, lookup(nfProbeHit, "count")...)
	insns = append(insns,
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
	)
	// Count it, and name the device it was leaving by.
	insns = append(insns,
		asm.Mov.Imm(asm.R2, nfHeld).WithSymbol("count"),
		asm.StoreMem(asm.RFP, -20, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, countsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -20),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 0),
		asm.Mov.Imm(asm.R2, nfLastOut),
		asm.StoreMem(asm.RFP, -20, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, countsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -20),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.StoreMem(asm.R0, 0, asm.R7, asm.DWord),
		asm.Mov.Imm(asm.R0, nfDrop).WithSymbol("drop"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, nfAccept).WithSymbol("accept"),
		asm.Return(),
	)
	return &ebpf.ProgramSpec{
		Name: nfSourceName(gen), Type: ebpf.Netfilter, AttachType: ebpf.AttachNetfilter, License: nfSourceLicense,
		Instructions: insns,
	}
}

// NF_DROP and NF_ACCEPT, the only verdicts a netfilter program may return.
const (
	nfDrop   = 0
	nfAccept = 1
)

// nfCheck is a containment's netfilter check: the link that holds it at IPv6 postrouting, its program, and what
// it has held. The hook is there exactly as long as the link is open. Only a check that was linked and proved is
// ever handed out, so its fields are never nil.
type nfCheck struct {
	link     link.Link
	prog     *ebpf.Program
	counts   *ebpf.Map
	prio     int32  // where it sits at postrouting
	base     uint64 // what it held of its own probe, which is not the operator's
	unproven string // why it could not prove itself on this host, when it could not; it stays linked
}

// nfUnavailable is why a host has no check, and what would give it one.
type nfUnavailable struct {
	why, remedy string
}

func (u *nfUnavailable) Error() string { return u.why }

// lockdownPath is where the kernel says how it is locked down.
var lockdownPath = "/sys/kernel/security/lockdown"

// confidential reports whether the kernel's lockdown, as lockdownPath reads, is confidentiality: it forbids
// bpf_probe_read_kernel, which the check needs.
func confidential(lockdown string) bool { return strings.Contains(lockdown, "[confidentiality]") }

// refusedLoad says why the kernel refused the program, and what would let it load. The verifier refusing it (it
// answers with a log, and with EACCES for any access it will not allow: a kernel whose layout this release
// misread) is a fault of this release; a security module's refusal (EPERM or EACCES before any verification, so
// with no log) is the host's policy; anything else, on a kernel that has netfilter BPF programs and BTF and is not
// locked down for confidentiality, is a fault of this release too.
func refusedLoad(err error) *nfUnavailable {
	var ve *ebpf.VerifierError
	verified := errors.As(err, &ve) && len(ve.Log) > 0
	if !verified && (errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
		return &nfUnavailable{why: "a security module refused the program (" + firstLine(err) + ")",
			remedy: "allowing it there"}
	}
	return &nfUnavailable{why: "this kernel refused the program, a fault of this release: " + firstLine(err),
		remedy: "a report of it, please"}
}

// nfFor is what a check is built for: the agent's address, the tunnel's index, the containment's generation and
// slot, and the host namespace's inode.
type nfFor struct {
	self netip.Addr
	tun  int
	gen  uint32
	slot int
	host uint64
}

func (c *nfCheck) close() {
	if c == nil {
		return
	}
	if c.link != nil {
		c.link.Close()
	}
	if c.prog != nil {
		c.prog.Close()
	}
	if c.counts != nil {
		c.counts.Close()
	}
}

// held reads what the check has held (its own probe left out) and the index of the device the last packet was
// leaving by.
func (c *nfCheck) held() (uint64, int) {
	if c == nil || c.counts == nil {
		return 0, 0
	}
	var n, dev uint64
	if c.counts.Lookup(uint32(nfHeld), &n) != nil || c.counts.Lookup(uint32(nfLastOut), &dev) != nil {
		return 0, 0
	}
	if n < c.base {
		return 0, int(dev)
	}
	return n - c.base, int(dev)
}

// attachNF is attachNFSource, a variable so that a test can stand in for a kernel that cannot.
var attachNF = attachNFSource

// attachNFSource links the check for f.self at IPv6 postrouting in the host namespace, reads the link back, and
// proves it holds a packet it must hold and passes one it must pass, before it is relied on.
func attachNFSource(f nfFor) (*nfCheck, error) {
	self, tunIdx, gen, host := f.self, f.tun, f.gen, f.host
	if !self.Is6() || self.Is4In6() || self.IsUnspecified() {
		return nil, errors.New("there is no IPv6 address to keep in")
	}
	if err := features.HaveProgramType(ebpf.Netfilter); err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return nil, &nfUnavailable{why: "it has no netfilter BPF programs",
				remedy: "a kernel that has them (Linux 6.4 or later, or a backport such as RHEL 9.8's)"}
		}
		return nil, &nfUnavailable{why: "it could not be asked whether it has netfilter BPF programs (" +
			firstLine(err) + ")", remedy: "a report of it, please"}
	}
	o, err := kernelNFOffsets()
	if err != nil {
		return nil, layoutUnavailable(err)
	}
	if b, err := os.ReadFile(lockdownPath); err == nil && confidential(string(b)) {
		return nil, &nfUnavailable{why: "it is locked down for confidentiality, which forbids a netfilter program to " +
			"read a packet", remedy: "lockdown set to integrity or none"}
	}
	// The hook is registered in the calling thread's own namespace, unlike a cgroup program, so the thread is
	// held and checked: a thread left in another namespace would put the check where nothing of the host passes.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ino, err := nsInode(); err != nil || ino != host {
		return nil, &nfUnavailable{why: "this thread is not in the host's network namespace, where the check has to go",
			remedy: "a report of it, please"}
	}
	c := &nfCheck{}
	ok := false
	defer func() {
		if !ok {
			c.close()
		}
	}()
	if c.counts, err = ebpf.NewMap(&ebpf.MapSpec{Name: nfHeldName(gen), Type: ebpf.Array, KeySize: 4, ValueSize: 8,
		MaxEntries: nfSlots}); err != nil {
		return nil, refusedLoad(fmt.Errorf("the check's counter: %w", err))
	}
	if c.prog, err = ebpf.NewProgram(nfSourceSpec(self, tunIdx, loIndex(), gen, o, c.counts.FD())); err != nil {
		return nil, refusedLoad(err)
	}
	for try := 0; ; try++ {
		c.prio = int32(nfSourcePriority + f.slot + try*maxHostSlots)
		c.link, err = link.AttachNetfilter(link.NetfilterOptions{Program: c.prog, ProtocolFamily: link.NetfilterProtoIPv6,
			Hook: link.NetfilterInetPostRouting, Priority: c.prio})
		if err == nil {
			break
		}
		if errors.Is(err, unix.EBUSY) && try == nfPriorityTries-1 {
			return nil, &nfUnavailable{why: fmt.Sprintf("another hook holds every priority it tried at IPv6 "+
				"postrouting (%d, and on by %d up to %d)", nfSourcePriority+f.slot, maxHostSlots, c.prio),
				remedy: "one of those priorities left free"}
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, refusedLoad(fmt.Errorf("linking it at priority %d: %w", c.prio, err))
		}
	}
	if err := c.readBack(); err != nil {
		return nil, &nfUnavailable{why: err.Error(), remedy: "a report of it, please"}
	}
	held, err := c.prove(self)
	if err != nil {
		return nil, &nfUnavailable{why: err.Error(), remedy: "a report of it, please"}
	}
	c.unproven = held
	ok = true
	return c, nil
}

// readBack checks the link is where it was asked to be: IPv6, postrouting, its priority, no flags (no
// defragmentation pulled into the host). Installed is not armed.
func (c *nfCheck) readBack() error {
	info, err := c.link.Info()
	if err != nil {
		return fmt.Errorf("the check's link could not be read back: %w", err)
	}
	nf := info.Netfilter()
	if nf == nil || nf.ProtocolFamily != link.NetfilterProtoIPv6 || nf.Hook != link.NetfilterInetPostRouting ||
		nf.Priority != c.prio || nf.Flags != 0 {
		return fmt.Errorf("the kernel reports the check's link as %+v, not at IPv6 postrouting, priority %d", nf, c.prio)
	}
	return nil
}

// prove sends the check a packet it must pass and one it must hold, none of which can reach a wire, each carrying
// a random nonce in the 8 bytes after its IPv6 header that the check matches only while that probe is out: its
// count would not do, since any local process can bind the /128 and send by the uplink, which the check rightly
// holds and counts. The one it must pass goes from self to ::1 over loopback, and its arrival is the proof; a
// check that held it (its nonce matched) is closed. The one it must hold is a datagram from self to ff02::1 by a
// device that is up and speaks IPv6, with a hop limit of 0, which the kernel frees after postrouting whatever the
// check does, sent as UDP and then, if that was not held, as an ICMPv6 echo; held with its nonce is the proof. A
// probe the host stops before postrouting (an output rule, a rule ahead of the local table) proves nothing either
// way, and the check stays linked: closing it could only take protection away. prove returns why the check is
// not proved on this host ("" when it is), or an error when it must be closed.
func (c *nfCheck) prove(self netip.Addr) (string, error) {
	defer c.disarm()
	got, held, sendErr := c.passProbe(self)
	if held {
		return "", errors.New("it held a packet leaving by loopback, which it must pass")
	}
	if !got {
		if errors.Is(sendErr, unix.EACCES) {
			return "a rule ahead of the local table refused its loopback probe", nil
		}
		return fmt.Sprintf("its loopback probe did not arrive (%v; a host rule on loopback?)", sendErr), nil
	}
	dev := probeDevice()
	if dev == 0 {
		return nfNoDevice, nil
	}
	held, sendErr = c.holdProbeUDP(self, dev)
	if !held {
		var echoErr error
		if held, echoErr = c.holdProbeEcho(self, dev); !errors.Is(sendErr, unix.EACCES) {
			sendErr = echoErr
		}
	}
	if !held {
		if errors.Is(sendErr, unix.EACCES) {
			return "a rule ahead of the local table refused the probe it must hold", nil
		}
		return "neither probe it must hold reached it with its nonce (an output rule on this host?)", nil
	}
	n, _ := c.held()
	c.base += n
	return "", nil
}

// arm puts a probe out: the check now marks a held packet whose 8 bytes after the IPv6 header, under mask, are
// want. It takes the last probe back first (mask 0) and puts the new mask in last, so no packet is ever matched
// against a mix of the two: the loopback probe's nonce is readable in /proc/net/udp6, and must not count for the
// next. disarm takes it back.
func (c *nfCheck) arm(want, mask [8]byte) error {
	if err := c.counts.Update(uint32(nfProbeMask), uint64(0), ebpf.UpdateAny); err != nil {
		return err
	}
	if err := c.counts.Update(uint32(nfProbeHit), uint64(0), ebpf.UpdateAny); err != nil {
		return err
	}
	if err := c.counts.Update(uint32(nfProbeWant), want, ebpf.UpdateAny); err != nil {
		return err
	}
	return c.counts.Update(uint32(nfProbeMask), mask, ebpf.UpdateAny)
}

func (c *nfCheck) disarm() { _ = c.counts.Update(uint32(nfProbeMask), uint64(0), ebpf.UpdateAny) }

// hit reports whether the check held a packet carrying the probe's nonce since arm.
func (c *nfCheck) hit() bool {
	var v uint64
	return c.counts.Lookup(uint32(nfProbeHit), &v) == nil && v == 1
}

// portsNonce is what a UDP datagram from sport to dport carries in the 8 bytes after its IPv6 header, under its
// mask: the two ports.
func portsNonce(sport, dport uint16) (want, mask [8]byte) {
	binary.BigEndian.PutUint16(want[0:], sport)
	binary.BigEndian.PutUint16(want[2:], dport)
	return want, [8]byte{0xff, 0xff, 0xff, 0xff}
}

// echoNonce is what an echo request with id and seq carries there, under its mask: its type, id and sequence.
func echoNonce(id, seq uint16) (want, mask [8]byte) {
	want[0] = 128
	binary.BigEndian.PutUint16(want[4:], id)
	binary.BigEndian.PutUint16(want[6:], seq)
	return want, [8]byte{0xff, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
}

// boundSocket is a socket of typ and proto bound to self with IPV6_FREEBIND (so the address need not be on a
// device yet), with its source port when it has one.
func boundSocket(self netip.Addr, typ, proto int) (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET6, typ|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, 0, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{Addr: self.As16()}); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	var port uint16
	if sa, err := unix.Getsockname(fd); err == nil {
		if a6, ok := sa.(*unix.SockaddrInet6); ok {
			port = uint16(a6.Port)
		}
	}
	return fd, port, nil
}

// toMulticast sets fd to send to ff02::1 by dev with a hop limit of 0, looped back, so the kernel frees what it
// sends after postrouting.
func toMulticast(fd, dev int) error {
	for _, o := range [][2]int{{unix.IPV6_MULTICAST_IF, dev}, {unix.IPV6_MULTICAST_HOPS, 0}, {unix.IPV6_MULTICAST_LOOP, 1}} {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, o[0], o[1]); err != nil {
			return err
		}
	}
	return nil
}

var allNodes = [16]byte{0: 0xff, 1: 0x02, 15: 1}

// passProbe sends self to ::1 over loopback, and reports whether it arrived, whether the check held it (its
// nonce matched), and the send's own error.
func (c *nfCheck) passProbe(self netip.Addr) (got, held bool, err error) {
	ln, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return false, false, err
	}
	defer ln.Close()
	dport := uint16(ln.LocalAddr().(*net.UDPAddr).Port)
	fd, sport, err := boundSocket(self, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false, false, err
	}
	defer unix.Close(fd)
	if err := c.arm(portsNonce(sport, dport)); err != nil {
		return false, false, err
	}
	err = unix.Sendto(fd, []byte("wsc_nf"), 0, &unix.SockaddrInet6{Addr: [16]byte{15: 1}, Port: int(dport)})
	if err == nil {
		_ = ln.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 16)
		_, _, rerr := ln.ReadFrom(b)
		got, err = rerr == nil, rerr
	}
	return got, c.hit(), err
}

// holdProbeUDP sends a datagram from self to ff02::1 by dev, to a random port, and reports whether the check held
// it with its nonce.
func (c *nfCheck) holdProbeUDP(self netip.Addr, dev int) (bool, error) {
	fd, sport, err := boundSocket(self, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := toMulticast(fd, dev); err != nil {
		return false, err
	}
	dport := uint16(1024 + randUint16()%64512)
	if err := c.arm(portsNonce(sport, dport)); err != nil {
		return false, err
	}
	err = unix.Sendto(fd, []byte("wsc_nf"), 0, &unix.SockaddrInet6{Addr: allNodes, Port: int(dport)})
	return c.hit(), err
}

// holdProbeEcho sends an ICMPv6 echo request from self to ff02::1 by dev, with a random id and sequence, and
// reports whether the check held it with its nonce. Output rules that stop UDP rarely stop ICMPv6 (RFC 4890). The
// kernel fills in the checksum.
func (c *nfCheck) holdProbeEcho(self netip.Addr, dev int) (bool, error) {
	fd, _, err := boundSocket(self, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := toMulticast(fd, dev); err != nil {
		return false, err
	}
	id, seq := randUint16(), randUint16()
	if err := c.arm(echoNonce(id, seq)); err != nil {
		return false, err
	}
	echo := []byte{128, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq)}
	err = unix.Sendto(fd, echo, 0, &unix.SockaddrInet6{Addr: allNodes})
	return c.hit(), err
}

func randUint16() uint16 {
	var b [2]byte
	_, _ = cryptorand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// nfNoDevice is why a check is not proved on a host with no device a packet could leave by but loopback and the
// tunnels.
const nfNoDevice = "there is no IPv6 device here, other than loopback and the tunnels, to prove it on"

// probeDevice is a device the check must hold a packet from the agent's address on: up, multicast, speaking IPv6,
// neither loopback nor a containment's tunnel. 0 when there is none.
func probeDevice() int {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagLoopback != 0 ||
			strings.HasPrefix(i.Name, "wsc") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil {
				return i.Index
			}
		}
	}
	return 0
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// tunnelKinds are the kernel devices whose own packets take a source after routing over IPv6 when nothing fixes
// it: WireGuard (it has no local address to fix), and a VXLAN, Geneve or bareudp with no local address. An ip6tnl
// or ip6gre with no fixed local address sends nothing at all (measured), and one in external mode is rare enough
// that it is left out of the list; the check holds its packets all the same.
var tunnelKinds = map[string]bool{"wireguard": true, "vxlan": true, "geneve": true, "bareudp": true}

// hostTunnels names the host's devices of a tunnelKinds kind that are up, sorted, or says why it could not look.
// A device that is down sends nothing, which leaves out the fallback devices the kernel makes in every namespace.
func hostTunnels() ([]string, error) {
	r, err := openRTNL()
	if err != nil {
		return nil, err
	}
	defer r.close()
	var out []string
	err = r.dump(unix.RTM_GETLINK, ifinfo(0, 0, 0), func(data []byte) {
		if name, kind, up := linkInfo(data); up && tunnelKinds[kind] {
			out = append(out, fmt.Sprintf("%s (%s)", name, kind))
		}
	})
	sort.Strings(out)
	return out, err
}

// linkInfo reads a link's name (IFLA_IFNAME), kind (IFLA_LINKINFO > IFLA_INFO_KIND) and whether it is up from one
// RTM_NEWLINK payload; what it cannot read comes back empty.
func linkInfo(data []byte) (name, kind string, up bool) {
	l, _ := parseLink(data, binary.NativeEndian)
	return l.name, l.kind, l.up
}

// hostHasOwnGlobalV6 reports whether the host holds a global IPv6 address of its own, on a device that is not a
// containment's tunnel, that is not tentative: without one, the agent's address is the only global source the
// kernel can pick for the host's own traffic.
func hostHasOwnGlobalV6() (bool, error) {
	r, err := openRTNL()
	if err != nil {
		return false, err
	}
	defer r.close()
	names := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names[i.Index] = i.Name
		}
	}
	found := false
	err = r.dump(unix.RTM_GETADDR, []byte{unix.AF_INET6, 0, 0, 0, 0, 0, 0, 0}, func(data []byte) {
		if len(data) < unix.SizeofIfAddrmsg {
			return
		}
		m := (*unix.IfAddrmsg)(unsafe.Pointer(&data[0]))
		if m.Family != unix.AF_INET6 || m.Scope != unix.RT_SCOPE_UNIVERSE || strings.HasPrefix(names[int(m.Index)], "wsc") {
			return
		}
		flags := uint32(m.Flags)
		eachAttr(data[unix.SizeofIfAddrmsg:], func(typ uint16, val []byte) {
			if typ == unix.IFA_FLAGS && len(val) >= 4 {
				flags = binary.NativeEndian.Uint32(val)
			}
		})
		if flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) == 0 {
			found = true
		}
	})
	return found, err
}

func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// outerState is what the note says about the host: its own tunnels that are up (or why they could not be
// listed), and whether it has a usable global IPv6 address of its own now (or why that could not be read).
type outerState struct {
	tunnels []string
	listErr error
	own     bool
	ownErr  error
}

// outerNote is the one line the containment says when its netfilter check (name) is not in place (u) or is linked
// but not proved (unproven): the kernel (release), why, what stays open, how to get out of it, and what would
// close it. "" when the check is linked and proved.
func outerNote(name string, u *nfUnavailable, unproven, release string, st outerState) string {
	when := "while the host has no usable global IPv6 address of its own (systemd-networkd re-adding its " +
		"address, DAD)"
	if st.ownErr == nil && !st.own {
		when = "while this host has no usable global IPv6 address of its own (it has none now)"
	}
	var n string
	switch {
	case u != nil:
		n = fmt.Sprintf("the netfilter check that keeps the agent's address off packets that belong to no socket "+
			"(%s) is unavailable on this kernel (Linux %s), since %s, so a kernel tunnel's own packets (WireGuard, "+
			"VXLAN, Geneve) and IPv6 the host masquerades can leave from the agent's address %s, and a WireGuard "+
			"peer that sees one moves to it (`wg set <dev> peer <key> endpoint <peer-addr:port>` on this host, once "+
			"its own address is back, moves it back); what would close that: %s", name, release, u.why, when, u.remedy)
	case unproven != "":
		n = fmt.Sprintf("the netfilter check that keeps the agent's address off packets that belong to no socket "+
			"(%s) is linked but could not prove itself here (Linux %s): %s; if it does not hold, a kernel tunnel's "+
			"own packets and IPv6 the host masquerades can leave from the agent's address %s", name, release,
			unproven, when)
	default:
		return ""
	}
	switch {
	case st.listErr != nil:
		n += fmt.Sprintf("; this host's devices could not be listed (%v)", st.listErr)
	case len(st.tunnels) > 0:
		n += "; this host runs " + strings.Join(st.tunnels, ", ") + ", which may send such packets"
	default:
		n += "; no such tunnel is up in this namespace now"
	}
	return n
}

// OuterNote is outerNote for this device: "" when its check is linked and proved.
func (hr *HostRoute) OuterNote() string {
	if hr == nil || hr.gate == nil {
		return ""
	}
	g := hr.gate
	var u *nfUnavailable
	unproven := ""
	switch {
	case g.nf == nil && g.nfWhy == nil:
		return ""
	case g.nf == nil:
		u = g.nfWhy
	default:
		unproven = g.nf.unproven
	}
	if u == nil && unproven == "" {
		return ""
	}
	var st outerState
	st.tunnels, st.listErr = hostTunnels()
	st.own, st.ownErr = hostHasOwnGlobalV6()
	return outerNote(nfSourceName(g.gen), u, unproven, kernelRelease(), st)
}

// OuterHeld is how many packets the netfilter check has held since it was proved; 0 without a check.
func (hr *HostRoute) OuterHeld() uint64 {
	if hr == nil || hr.gate == nil {
		return 0
	}
	n, _ := hr.gate.nf.held()
	return n
}

// OuterHeldBy names the device the last packet the check held was leaving by: a link dump, so only when it is
// about to be said.
func (hr *HostRoute) OuterHeldBy() string {
	if hr == nil || hr.gate == nil {
		return ""
	}
	_, idx := hr.gate.nf.held()
	if ifc, err := net.InterfaceByIndex(idx); err == nil {
		return ifc.Name
	}
	return fmt.Sprintf("device %d", idx)
}

// HeldReport paces what the command says about the check: the first packets held are said at once, then at most
// once a minute, and whatever is left when it is told to (force), at the end.
type HeldReport struct {
	said uint64
	at   time.Time
}

// Due is how many packets to say now, of n held so far, or 0; saying them is the caller's.
func (r *HeldReport) Due(n uint64, now time.Time, force bool) uint64 {
	if n <= r.said || !(force || r.said == 0 || now.Sub(r.at) >= time.Minute) {
		return 0
	}
	d := n - r.said
	r.said, r.at = n, now
	return d
}

// HeldNote is the line the command says about what the check held: n more since it last spoke, the last leaving
// by dev. What sent them it cannot know: the host's own traffic given the agent's address while the host had none
// of its own (a kernel tunnel, a masqueraded container, a socket), or a process bound to the address.
func HeldNote(n uint64, dev string) string {
	return fmt.Sprintf("held %d packet%s from the agent's address that this host sent or forwarded, the last by %s, "+
		"rather than through the tunnel (traffic of the host's given the agent's address while it had no usable IPv6 "+
		"address of its own, or a process bound to it); they were dropped before they left the host",
		n, plural(int(min(n, 2))), dev)
}

// kernelRelease is uname -r, or "unknown".
func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// unavailable is err as an nfUnavailable, keeping its remedy when it has one.
func unavailable(err error) *nfUnavailable {
	var u *nfUnavailable
	if errors.As(err, &u) {
		return u
	}
	return &nfUnavailable{why: err.Error(), remedy: "a report of it, please"}
}
