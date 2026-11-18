// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// fakeKernel is a BTF as the check reads it, laid out like Linux 6.8's: sk_buff's network_header sits in an
// anonymous struct inside the anonymous union struct_group makes.
func fakeKernel() map[string]btf.Type {
	u16 := &btf.Typedef{Name: "__u16", Type: &btf.Int{Name: "unsigned short", Size: 2}}
	netDevice := &btf.Struct{Name: "net_device", Size: 2048, Members: []btf.Member{
		{Name: "name", Type: &btf.Array{Type: &btf.Int{Name: "char", Size: 1}, Nelems: 16}, Offset: 0},
		{Name: "ifindex", Type: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Offset: 224 * 8},
	}}
	state := &btf.Struct{Name: "nf_hook_state", Size: 48, Members: []btf.Member{
		{Name: "hook", Type: &btf.Int{Name: "u8", Size: 1}, Offset: 0},
		{Name: "in", Type: &btf.Pointer{Target: netDevice}, Offset: 8 * 8},
		{Name: "out", Type: &btf.Pointer{Target: netDevice}, Offset: 16 * 8},
	}}
	inner := &btf.Struct{Size: 8, Members: []btf.Member{
		{Name: "transport_header", Type: u16, Offset: 0},
		{Name: "network_header", Type: u16, Offset: 16},
		{Name: "mac_header", Type: u16, Offset: 32},
	}}
	headers := &btf.Struct{Name: "", Size: 8, Members: inner.Members}
	group := &btf.Union{Size: 8, Members: []btf.Member{
		{Name: "", Type: inner, Offset: 0},
		{Name: "headers", Type: headers, Offset: 0},
	}}
	skb := &btf.Struct{Name: "sk_buff", Size: 232, Members: []btf.Member{
		{Name: "dev", Type: &btf.Pointer{Target: netDevice}, Offset: 16 * 8},
		{Name: "", Type: group, Offset: 180 * 8},
		{Name: "head", Type: &btf.Pointer{Target: &btf.Int{Name: "unsigned char", Size: 1}}, Offset: 200 * 8},
	}}
	return map[string]btf.Type{"net_device": netDevice, "nf_hook_state": state, "sk_buff": skb}
}

func lookupIn(types map[string]btf.Type) func(string) (btf.Type, error) {
	return func(name string) (btf.Type, error) {
		if t, ok := types[name]; ok {
			return t, nil
		}
		return nil, btf.ErrNotFound
	}
}

func TestTheCheckFindsItsOffsetsThroughAnonymousMembers(t *testing.T) {
	o, err := nfOffsetsFrom(lookupIn(fakeKernel()))
	if err != nil {
		t.Fatal(err)
	}
	if want := (nfOffsets{out: 16, ifindex: 224, head: 200, networkHeader: 182}); o != want {
		t.Fatalf("offsets %+v, want %+v (network_header is 2 bytes into the group at 180)", o, want)
	}
}

// A layout the check would misread is refused, never guessed at: the program would read another field.
func TestTheCheckRefusesALayoutItCannotRead(t *testing.T) {
	for name, spoil := range map[string]func(map[string]btf.Type){
		"no sk_buff": func(k map[string]btf.Type) { delete(k, "sk_buff") },
		"no ifindex": func(k map[string]btf.Type) {
			nd := k["net_device"].(*btf.Struct)
			nd.Members = nd.Members[:1]
		},
		"a 64-bit ifindex": func(k map[string]btf.Type) {
			k["net_device"].(*btf.Struct).Members[1].Type = &btf.Int{Name: "long", Size: 8}
		},
		"network_header a bitfield": func(k map[string]btf.Type) {
			grp := k["sk_buff"].(*btf.Struct).Members[1].Type.(*btf.Union)
			grp.Members[0].Type.(*btf.Struct).Members[1].BitfieldSize = 16
		},
		"out to another struct": func(k map[string]btf.Type) {
			k["nf_hook_state"].(*btf.Struct).Members[2].Type = &btf.Pointer{Target: &btf.Struct{Name: "sock"}}
		},
		"head not a pointer": func(k map[string]btf.Type) {
			k["sk_buff"].(*btf.Struct).Members[2].Type = &btf.Int{Name: "unsigned long", Size: 8}
		},
		"an offset past what a load can name": func(k map[string]btf.Type) {
			k["sk_buff"].(*btf.Struct).Members[2].Offset = 40000 * 8
		},
		"an offset inside a byte": func(k map[string]btf.Type) {
			k["net_device"].(*btf.Struct).Members[1].Offset = 224*8 + 4
		},
	} {
		k := fakeKernel()
		spoil(k)
		if o, err := nfOffsetsFrom(lookupIn(k)); err == nil {
			t.Errorf("%s: accepted, offsets %+v", name, o)
		}
	}
}

// The running kernel's own BTF, when it has one, gives offsets the program can use.
func TestThisKernelsBTFGivesTheCheckItsOffsets(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("this kernel publishes no BTF")
	}
	o, err := kernelNFOffsets()
	if err != nil {
		t.Fatal(err)
	}
	if o.out <= 0 || o.ifindex <= 0 || o.head <= 0 || o.networkHeader <= 0 {
		t.Fatalf("offsets %+v", o)
	}
}

// The program reads what it was built for and nothing else: the tunnel's and loopback's indexes, self as four
// words, and the offsets it was given; it returns only NF_DROP or NF_ACCEPT, and declares the licence the kernel
// asks of a program that reads kernel memory.
func TestTheCheckIsBuiltForItsDeviceAndAddress(t *testing.T) {
	self := netip.MustParseAddr("2001:db8:46::46")
	o := nfOffsets{out: 16, ifindex: 224, head: 200, networkHeader: 182}
	spec := nfSourceSpec(self, 77, 1, 0x2a, o, 99)
	if spec.Name != "wsc_nf_002a" || spec.Type != ebpf.Netfilter || spec.AttachType != ebpf.AttachNetfilter ||
		spec.License != nfSourceLicense {
		t.Fatalf("spec %s %v %v %q", spec.Name, spec.Type, spec.AttachType, spec.License)
	}
	var imms []int64
	var offs []int16
	returns := map[int64]bool{}
	for i, ins := range spec.Instructions {
		if ins.OpCode.JumpOp() == asm.JEq || ins.OpCode.JumpOp() == asm.JNE {
			imms = append(imms, ins.Constant)
		}
		if ins.OpCode.Class().IsLoad() {
			offs = append(offs, ins.Offset)
		}
		if ins.OpCode.JumpOp() == asm.Exit {
			returns[spec.Instructions[i-1].Constant] = true
		}
	}
	a := self.As16()
	for _, want := range []int64{77, 1, int64(int32(binary.NativeEndian.Uint32(a[0:]))),
		int64(int32(binary.NativeEndian.Uint32(a[12:])))} {
		found := false
		for _, c := range imms {
			found = found || c == want
		}
		if !found {
			t.Errorf("no comparison with %#x in %v", want, imms)
		}
	}
	for _, want := range []int16{0, 8, 16, 224, 200, 182} {
		found := false
		for _, off := range offs {
			found = found || off == want
		}
		if !found {
			t.Errorf("no load at offset %d in %v", want, offs)
		}
	}
	if len(returns) != 2 || !returns[nfDrop] || !returns[nfAccept] {
		t.Errorf("returns %v, want only NF_DROP and NF_ACCEPT", returns)
	}
	if nfSourcePriority <= 100 || nfSourcePriority+maxHostSlots*nfPriorityTries >= 1<<31-1 {
		t.Errorf("priority %d runs before source NAT (100), so it would judge a source that is not the one leaving", nfSourcePriority)
	}
}

// rtmLink is an RTM_NEWLINK payload for a link that is up, with a name and, when kind is not "", a nested
// IFLA_LINKINFO kind.
func rtmLink(name, kind string) []byte {
	b := append([]byte(nil), ifinfo(7, unix.IFF_UP, 0)...)
	b = append(b, nlAttr(unix.IFLA_IFNAME, append([]byte(name), 0))...)
	if kind != "" {
		info := nlAttr(unix.IFLA_INFO_KIND, append([]byte(kind), 0))
		b = append(b, nlAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	}
	return b
}

func TestALinksKindIsReadFromItsNestedInfo(t *testing.T) {
	for _, c := range []struct{ name, kind string }{{"wg0", "wireguard"}, {"vx0", "vxlan"}, {"enp1s0", ""}} {
		if n, k, up := linkInfo(rtmLink(c.name, c.kind)); n != c.name || k != c.kind || !up {
			t.Errorf("%s/%s read as %q/%q up %v", c.name, c.kind, n, k, up)
		}
	}
	down := rtmLink("ip6tnl0", "ip6tnl")
	copy(down, ifinfo(7, 0, 0))
	if _, k, up := linkInfo(down); k != "ip6tnl" || up {
		t.Errorf("a fallback device that is down read as %q up %v", k, up)
	}
	// A broken attribute stops the read; what came before it stands, nothing after it is guessed.
	b := rtmLink("wg0", "wireguard")
	broken := append(append([]byte(nil), b[:unix.SizeofIfInfomsg+12]...), 0xff, 0x00, 0x12, 0x00)
	if n, k, _ := linkInfo(broken); n != "wg0" || k != "" {
		t.Errorf("a broken attribute read as %q/%q", n, k)
	}
	if n, k, up := linkInfo(b[:4]); n != "" || k != "" || up {
		t.Errorf("a short message read as %q/%q up %v", n, k, up)
	}
	for _, kind := range []string{"wireguard", "vxlan", "geneve"} {
		if !tunnelKinds[kind] {
			t.Errorf("%s is not a kind whose own packets the note covers", kind)
		}
	}
	for _, kind := range []string{"veth", "bridge", "tun", "dummy", "sit", "gre", "ipip"} {
		if tunnelKinds[kind] {
			t.Errorf("%s sends nothing of its own over IPv6 with a source picked after routing", kind)
		}
	}
}

func TestTheNoteSaysWhatStaysOpenWhenTheCheckIsMissing(t *testing.T) {
	if n := outerNote("wsc_nf_002a", nil, "", "6.8.0", outerState{tunnels: []string{"wg0 (wireguard)"}}); n != "" {
		t.Errorf("the check is there and proved, yet: %q", n)
	}
	noProgs := &nfUnavailable{why: "it has no netfilter BPF programs", remedy: "a kernel that has them (Linux 6.4 or later, or a backport such as RHEL 9.8's)"}
	for _, c := range []struct {
		u        *nfUnavailable
		unproven string
		st       outerState
		want     []string
		not      []string
	}{
		{noProgs, "", outerState{own: true}, []string{"netfilter check", "(wsc_nf_002a)", "(Linux 6.1.0-27-amd64), since it has no netfilter BPF programs",
			"agent's address", "DAD", "masquerades", "wg set <dev> peer <key> endpoint <peer-addr:port>` on this host, once its own address is back",
			"what would close that: a kernel that has them", "RHEL 9.8", "no such tunnel is up in this namespace now"},
			[]string{"the guard", "(it has none now)", "fault"}},
		{noProgs, "", outerState{own: true, tunnels: []string{"vx0 (vxlan)", "wg0 (wireguard)"}},
			[]string{"runs vx0 (vxlan), wg0 (wireguard), which may send such packets"}, nil},
		{noProgs, "", outerState{own: true, listErr: errors.New("EPERM")}, []string{"could not be listed (EPERM)"}, nil},
		// A host with no global address of its own gives its own traffic the agent's address now.
		{noProgs, "", outerState{own: false}, []string{"(it has none now)"}, []string{"DAD"}},
		// When that could not be read, the note does not claim it.
		{noProgs, "", outerState{own: false, ownErr: errors.New("EPERM")}, []string{"DAD"}, []string{"has none now"}},
		{nil, "neither probe it must hold reached postrouting (an output rule on this host?)", outerState{own: true},
			[]string{"(wsc_nf_002a) is linked but could not prove itself here", "an output rule on this host?", "if it does not hold"},
			[]string{"unavailable"}},
	} {
		n := outerNote("wsc_nf_002a", c.u, c.unproven, "6.1.0-27-amd64", c.st)
		for _, w := range c.want {
			if !strings.Contains(n, w) {
				t.Errorf("the note %q does not say %q", n, w)
			}
		}
		for _, w := range c.not {
			if strings.Contains(n, w) {
				t.Errorf("the note %q says %q", n, w)
			}
		}
		if strings.ContainsAny(n, "\n\r") {
			t.Errorf("the note is more than one line: %q", n)
		}
	}
	if n := (*HostRoute)(nil).OuterNote(); n != "" {
		t.Errorf("a missing route says %q", n)
	}
	if n := (*HostRoute)(nil).OuterHeld(); n != 0 {
		t.Errorf("a missing route held %d", n)
	}
}

// A refusal is said as what it is: a security module's (EPERM, EACCES) as the host's policy, anything else on a
// kernel that should take the program as this release's fault; a confidentiality lockdown is read from the file.
func TestARefusalIsSaidAsWhatItIs(t *testing.T) {
	for _, c := range []struct {
		err         error
		why, remedy string
		notWhy      string
	}{
		{unix.EPERM, "a security module refused the program", "allowing it there", "fault"},
		{fmt.Errorf("load program: %w", unix.EACCES), "a security module refused the program", "allowing it there", "fault"},
		// A security module refuses before any verification: an EPERM with no log is its.
		{&ebpf.VerifierError{Cause: unix.EPERM}, "a security module refused the program", "allowing it there", "fault"},
		// The verifier answers EACCES, with a log, for an access it will not allow: a layout this release misread.
		{fmt.Errorf("load program: %w", &ebpf.VerifierError{Cause: unix.EACCES,
			Log: []string{"0: (bf) r6 = r1", "access beyond struct net_device at off 30000 size 4"}}),
			"a fault of this release", "a report of it, please", "security module"},
		{fmt.Errorf("load program: %w\nverifier log", unix.EINVAL), "a fault of this release: load program: invalid argument", "a report of it, please", "verifier log"},
	} {
		u := refusedLoad(c.err)
		if !strings.Contains(u.why, c.why) || u.remedy != c.remedy || strings.Contains(u.why, c.notWhy) {
			t.Errorf("%v said as %q, remedy %q", c.err, u.why, u.remedy)
		}
	}
	for content, want := range map[string]bool{"none integrity [confidentiality]\n": true, "none [integrity] confidentiality\n": false,
		"[none] integrity confidentiality\n": false, "": false} {
		if confidential(content) != want {
			t.Errorf("lockdown %q read as confidential=%v", content, !want)
		}
	}
	if u := layoutUnavailable(errNoBTF); u.remedy != "a kernel built with BTF" {
		t.Errorf("no BTF said as %+v", u)
	}
	if _, err := nfOffsetsFrom(lookupIn(map[string]btf.Type{})); err == nil {
		t.Fatal("control: a BTF with no structs gave offsets")
	} else if u := layoutUnavailable(err); u.remedy != "a report of it, please" || !strings.Contains(u.why, "could not read the kernel's layout") {
		t.Errorf("a BTF that lacks a struct said as %+v", u)
	}
	if u := unavailable(errors.New("plain")); u.why != "plain" || u.remedy == "" {
		t.Errorf("a plain error became %+v", u)
	}
	held := &nfUnavailable{why: "w", remedy: "r"}
	if u := unavailable(fmt.Errorf("wrapped: %w", held)); u != held {
		t.Errorf("a wrapped reason lost its remedy: %+v", u)
	}
}

func TestTheHeldNoteCountsAndNamesTheLastDevice(t *testing.T) {
	n := HeldNote(1, "enp1s0")
	for _, want := range []string{"held 1 packet from the agent's address that this host sent or forwarded, the last by enp1s0",
		"or a process bound to it", "dropped before they left the host"} {
		if !strings.Contains(n, want) {
			t.Errorf("%q does not say %q", n, want)
		}
	}
	if n := HeldNote(73, "enp1s0"); !strings.Contains(n, "held 73 packets") {
		t.Errorf("%q", n)
	}
}

// The command says the first packets held at once, then at most once a minute, and what is left at the end.
func TestTheHeldReportIsPaced(t *testing.T) {
	var r HeldReport
	t0 := time.Unix(1_800_000_000, 0)
	if d := r.Due(0, t0, false); d != 0 {
		t.Fatalf("nothing held, yet %d due", d)
	}
	if d := r.Due(16, t0, false); d != 16 {
		t.Fatalf("the first held are not said at once: %d", d)
	}
	if d := r.Due(40, t0.Add(30*time.Second), false); d != 0 {
		t.Fatalf("said again within the minute: %d", d)
	}
	if d := r.Due(52, t0.Add(61*time.Second), false); d != 36 {
		t.Fatalf("after a minute %d due, want 36", d)
	}
	if d := r.Due(60, t0.Add(70*time.Second), true); d != 8 {
		t.Fatalf("the end says %d, want the 8 left", d)
	}
	if d := r.Due(60, t0.Add(80*time.Second), true); d != 0 {
		t.Fatalf("nothing new, yet %d due at the end", d)
	}
}

// The host's own addresses are read without privilege; on this host the answer is whatever it is, but the read
// must work.
func TestTheHostsOwnAddressesCanBeRead(t *testing.T) {
	if _, err := hostHasOwnGlobalV6(); err != nil {
		t.Fatalf("reading the host's addresses: %v", err)
	}
}
