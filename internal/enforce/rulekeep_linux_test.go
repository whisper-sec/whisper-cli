// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// rulekeep_linux_test.go proves, without privilege, the protocol a containment's rules carry, the shape
// a prune takes as a containment's, and what the keeper decides from a list of rules.

var (
	kSelf  = netip.MustParseAddr("2a04:2a01:0:1::42")
	kOther = netip.MustParseAddr("2a04:2a01:0:1::99")
)

func keepRoute(carryV4 bool) *HostRoute {
	hr := routeFor("wsc3", 9, 3, 7)
	hr.CarryV4 = carryV4
	hr.self = kSelf
	return &hr
}

// asListed is a rule as the kernel lists one a containment installed.
func asListed(s ruleSpec) ruleInfo {
	return ruleInfo{fam: s.fam, prio: s.prio, action: s.action, table: s.table, mark: s.mark, mask: s.mask, src: s.src,
		proto: hostRuleProto}
}

// systemd-networkd deletes every policy rule it did not configure except those with protocol kernel
// (networkd.conf(5); manager_mark_routing_policy_rules / link_drop_routing_policy_rules from v249 on),
// so that is the protocol every rule a containment installs carries, and it is what a delete names.
func TestTheRulesCarryTheOneProtocolNetworkdLeavesAlone(t *testing.T) {
	if hostRuleProto != unix.RTPROT_KERNEL {
		t.Fatalf("a containment's rules carry protocol %d; systemd-networkd deletes any but kernel (%d)", hostRuleProto,
			unix.RTPROT_KERNEL)
	}
	if legacyRuleProto == hostRuleProto {
		t.Fatal("the earlier release's protocol must be told apart from the current one")
	}
	for _, s := range keepRoute(true).rules(kSelf) {
		b := tagged(s.body())
		ri, ok := parseRule(b)
		if !ok || ri.proto != unix.RTPROT_KERNEL || ri.extra || ri.unknown || !s.is(ri) {
			t.Fatalf("%s as installed reads back as %+v", s, ri)
		}
	}
}

// The rules go in, and come back, in the one order that works at a single priority: both lookups
// before the refusal of the agent's address, IPv4 only when it is carried.
func TestTheRulesAreListedInTheOrderTheyMustBeInstalled(t *testing.T) {
	for _, v4 := range []bool{false, true} {
		rs := keepRoute(v4).rules(kSelf)
		want := 3
		if v4 {
			want = 5
		}
		if len(rs) != want {
			t.Fatalf("carryV4 %v: %d rules, want %d", v4, len(rs), want)
		}
		if rs[0].mark == 0 || rs[1].src != kSelf || rs[1].action != frActToTbl || rs[2].action != frActProhibit {
			t.Fatalf("the IPv6 rules are not mark lookup, address lookup, refusal: %v", rs)
		}
		for _, s := range rs {
			if s.prio != 4303 || s.action == frActToTbl && s.table != 4303 {
				t.Fatalf("%s is not at the slot's priority and table", s)
			}
		}
		if v4 && (rs[3].fam != unix.AF_INET || rs[4].src != CLATv4) {
			t.Fatalf("the IPv4 rules: %v", rs[3:])
		}
	}
}

// ruleMsg builds a rule message's payload the way the kernel lists one: header fields, then attributes.
func ruleMsg(fam, dstLen, srcLen, tos, action uint8, flags uint32, attrs ...[]byte) []byte {
	h := fibRuleHdr{Family: fam, DstLen: dstLen, SrcLen: srcLen, Tos: tos, Action: action, Flags: flags}
	b := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// What a containment's rule never selects on makes a rule in its shape somebody else's; the kernel's
// "suppress_prefixlength -1", which it lists on every rule, does not.
func TestParseRuleMarksEverySelectorAContainmentNeverSets(t *testing.T) {
	base := func(extra ...[]byte) []byte {
		attrs := [][]byte{nlAttr(fraPriority, u32(4299)), nlAttr(fraSrc, kOther.AsSlice()),
			nlAttr(unix.FRA_SUPPRESS_PREFIXLEN, u32(0xffffffff)), nlAttr(fraProtocol, []byte{unix.RTPROT_KERNEL})}
		return ruleMsg(unix.AF_INET6, 0, 128, 0, frActProhibit, 0, append(attrs, extra...)...)
	}
	plain, ok := parseRule(base())
	if !ok || plain.extra || plain.unknown || plain.src != kOther || plain.prio != 4299 || plain.proto != unix.RTPROT_KERNEL {
		t.Fatalf("a plain refusal reads as %+v", plain)
	}
	if _, owned := agentRuleOf(plain); !owned {
		t.Fatal("control: an exact refusal at the guard's priority is a containment's shape")
	}
	be16 := func(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
	cases := map[string][]byte{
		"to a destination": ruleMsg(unix.AF_INET6, 64, 128, 0, frActProhibit, 0, nlAttr(fraPriority, u32(4299)),
			nlAttr(fraSrc, kOther.AsSlice()), nlAttr(unix.FRA_DST, kSelf.AsSlice()), nlAttr(fraProtocol, []byte{2})),
		"a tos":   ruleMsg(unix.AF_INET6, 0, 128, 8, frActProhibit, 0, nlAttr(fraPriority, u32(4299)), nlAttr(fraSrc, kOther.AsSlice()), nlAttr(fraProtocol, []byte{2})),
		"not":     ruleMsg(unix.AF_INET6, 0, 128, 0, frActProhibit, 2, nlAttr(fraPriority, u32(4299)), nlAttr(fraSrc, kOther.AsSlice()), nlAttr(fraProtocol, []byte{2})),
		"iif":     base(nlAttr(unix.FRA_IIFNAME, []byte("lo\x00"))),
		"oif":     base(nlAttr(unix.FRA_OIFNAME, []byte("eth9\x00"))),
		"ipproto": base(nlAttr(unix.FRA_IP_PROTO, []byte{17})),
		"sport":   base(nlAttr(unix.FRA_SPORT_RANGE, append(be16(53), be16(53)...))),
		"dport":   base(nlAttr(unix.FRA_DPORT_RANGE, append(be16(53), be16(53)...))),
		"uid":     base(nlAttr(unix.FRA_UID_RANGE, append(u32(1000), u32(1000)...))),
		"l3mdev":  base(nlAttr(unix.FRA_L3MDEV, []byte{1})),
		"goto":    base(nlAttr(unix.FRA_GOTO, u32(32766))),
		"tun id":  base(nlAttr(unix.FRA_TUN_ID, make([]byte, 8))),
		"realm":   base(nlAttr(unix.FRA_FLOW, u32(7))),
		"suppressed prefix": ruleMsg(unix.AF_INET6, 0, 128, 0, frActProhibit, 0, nlAttr(fraPriority, u32(4299)),
			nlAttr(fraSrc, kOther.AsSlice()), nlAttr(unix.FRA_SUPPRESS_PREFIXLEN, u32(0)), nlAttr(fraProtocol, []byte{2})),
		"suppressed group": base(nlAttr(unix.FRA_SUPPRESS_IFGROUP, u32(3))),
		"a /64 source": ruleMsg(unix.AF_INET6, 0, 64, 0, frActProhibit, 0, nlAttr(fraPriority, u32(4299)),
			nlAttr(fraSrc, kOther.AsSlice()), nlAttr(fraProtocol, []byte{2})),
		"dscp (6.13)":       base(nlAttr(25, []byte{10})),
		"flow label (6.13)": base(nlAttr(26, u32(7))),
		"flow label mask":   base(nlAttr(27, u32(0xfffff))),
		"sport mask (6.15)": base(nlAttr(28, be16(0xff00))),
		"dport mask (6.15)": base(nlAttr(29, be16(0xff00))),
		"dscp mask (6.15)":  base(nlAttr(30, []byte{0x3f})),
	}
	for name, msg := range cases {
		ri, ok := parseRule(msg)
		if !ok || !ri.extra {
			t.Errorf("%s: not seen as a selector a containment never sets: %+v", name, ri)
		}
		if _, owned := agentRuleOf(ri); owned {
			t.Errorf("%s: a prune would take it as a containment's", name)
		}
	}
	// A message no kernel sends is read as one this code cannot vouch for: a broken attribute, one
	// flagged nested, or bytes no attribute accounts for.
	broken := base(nlAttr(unix.FRA_DST, kSelf.AsSlice()))
	binary.NativeEndian.PutUint16(broken[len(broken)-20:], 64) // its length now runs past the message
	nested := base(nlAttr(unix.FRA_DST|unix.NLA_F_NESTED, kSelf.AsSlice()))
	nestedKnown := base(nlAttr(fraPriority|unix.NLA_F_NESTED, u32(4300)))
	trailing := append(base(), 1, 2)
	for name, msg := range map[string][]byte{"a broken attribute": broken, "a nested destination": nested,
		"a nested priority": nestedKnown, "trailing bytes": trailing} {
		if ri, _ := parseRule(msg); !ri.unknown {
			t.Errorf("%s reads as one this code can vouch for: %+v", name, ri)
		} else if _, owned := agentRuleOf(ri); owned {
			t.Errorf("%s: a prune would take it", name)
		}
	}
	unknown, _ := parseRule(base(nlAttr(200, u32(1))))
	if !unknown.unknown || unknown.extra {
		t.Fatalf("an attribute this code does not know: %+v", unknown)
	}
	if _, owned := agentRuleOf(unknown); owned {
		t.Fatal("a prune would take a rule carrying an attribute it does not know")
	}
	// The keeper still recognises its own rule when the kernel lists an attribute this code does not know,
	// so a newer kernel never makes it think every rule is gone.
	s := keepRoute(false).rules(kSelf)[2]
	own, _ := parseRule(append(tagged(s.body()), nlAttr(200, u32(1))...))
	if !s.is(own) {
		t.Fatal("the keeper lost its own refusal to an attribute it does not know")
	}
}

// A prune takes a rule only in a containment's exact shape, at a slot's priority or the guard's, with a
// containment's protocol: kernel now, or 87 from the release before.
func TestAPruneTakesOnlyAContainmentsExactShape(t *testing.T) {
	r := func(prio uint32, action uint8, table uint32, proto uint8, src netip.Addr) ruleInfo {
		return ruleInfo{fam: unix.AF_INET6, prio: prio, action: action, table: table, proto: proto, src: src}
	}
	type c struct {
		r    ruleInfo
		want bool
	}
	cases := map[string]c{
		"refusal at a slot, kernel":          {r(4305, frActProhibit, 0, unix.RTPROT_KERNEL, kOther), true},
		"refusal at a slot, 87":              {r(4305, frActProhibit, 0, legacyRuleProto, kOther), true},
		"guard, kernel":                      {r(4299, frActProhibit, 0, unix.RTPROT_KERNEL, kOther), true},
		"lookup of the slot's table":         {r(4305, frActToTbl, 4305, unix.RTPROT_KERNEL, kOther), true},
		"lookup at the guard's priority":     {r(4299, frActToTbl, 4299, unix.RTPROT_KERNEL, kOther), false},
		"lookup of another table":            {r(4305, frActToTbl, 4306, unix.RTPROT_KERNEL, kOther), false},
		"refusal, no protocol (ip rule add)": {r(4305, frActProhibit, 0, unix.RTPROT_UNSPEC, kOther), false},
		"refusal, boot":                      {r(4305, frActProhibit, 0, unix.RTPROT_BOOT, kOther), false},
		"refusal, static (networkd's own)":   {r(4305, frActProhibit, 0, unix.RTPROT_STATIC, kOther), false},
		"refusal naming table main":          {r(4305, frActProhibit, 254, unix.RTPROT_KERNEL, kOther), false},
		"guard naming table main":            {r(4299, frActProhibit, 254, unix.RTPROT_KERNEL, kOther), false},
		"refusal below the band":             {r(4298, frActProhibit, 0, unix.RTPROT_KERNEL, kOther), false},
		"refusal above the band":             {r(4300+maxHostSlots, frActProhibit, 0, unix.RTPROT_KERNEL, kOther), false},
		"refusal of an IPv4 address":         {r(4305, frActProhibit, 0, unix.RTPROT_KERNEL, netip.MustParseAddr("192.0.2.1")), false},
		"refusal of a mapped address":        {r(4305, frActProhibit, 0, unix.RTPROT_KERNEL, netip.MustParseAddr("::ffff:192.0.2.1")), false},
		"the kernel's main rule":             {r(32766, frActToTbl, 254, unix.RTPROT_KERNEL, netip.Addr{}), false},
		"the kernel's local rule":            {r(0, frActToTbl, 255, unix.RTPROT_KERNEL, netip.Addr{}), false},
	}
	marked := r(4305, frActToTbl, 4305, unix.RTPROT_KERNEL, kOther)
	marked.mark, marked.mask = markFor(3), hostMarkMask
	cases["a marked lookup from the address"] = c{marked, false}
	for name, tc := range cases {
		if _, got := agentRuleOf(tc.r); got != tc.want {
			t.Errorf("%s: taken %v, want %v", name, got, tc.want)
		}
	}
}

// A delete names a rule by priority, action, table, protocol and source, and the kernel takes the first
// rule that matches those, whatever else it selects on: so the containment's rule is deleted only when
// it is that first one.
func TestADeleteGoesAheadOnlyWhenItTakesTheContainmentsOwnRule(t *testing.T) {
	ours := ruleInfo{fam: unix.AF_INET6, prio: 4305, action: frActProhibit, proto: unix.RTPROT_KERNEL, src: kOther}
	richer := ours
	richer.extra = true
	marked := ours
	marked.mark = 5
	lookup := ours
	lookup.action, lookup.table = frActToTbl, 4305
	otherProto := ours
	otherProto.proto = legacyRuleProto
	cases := map[string]struct {
		list []ruleInfo
		want bool
	}{
		"alone":                         {[]ruleInfo{ours}, true},
		"a richer twin ahead":           {[]ruleInfo{richer, ours}, false},
		"a richer twin behind":          {[]ruleInfo{ours, richer}, true},
		"a marked twin ahead":           {[]ruleInfo{marked, ours}, false},
		"a lookup ahead":                {[]ruleInfo{lookup, ours}, true},
		"another protocol's twin ahead": {[]ruleInfo{otherProto, ours}, true},
		"gone":                          {[]ruleInfo{richer}, false},
	}
	for name, tc := range cases {
		if got := deletesFirst(tc.list, ours); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// What the keeper decides from a list: nothing when the rules are whole and in an order that works; the
// missing ones, in install order, otherwise; the refusal moved last when no lookup is ahead of it; a
// guard noticed whenever one for the agent is up.
func TestTheKeeperPlansFromWhatTheKernelLists(t *testing.T) {
	hr := keepRoute(true)
	want := hr.rules(kSelf)
	m6, a6, p6, m4, a4 := asListed(want[0]), asListed(want[1]), asListed(want[2]), asListed(want[3]), asListed(want[4])
	guard := ruleInfo{fam: unix.AF_INET6, prio: hostGuardPrio, action: frActProhibit, proto: unix.RTPROT_KERNEL, src: kSelf}
	otherRefusal := ruleInfo{fam: unix.AF_INET6, prio: want[0].prio, action: frActProhibit, proto: unix.RTPROT_KERNEL, src: kOther}
	v4 := []ruleInfo{m4, a4}
	names := func(rs []ruleSpec) string {
		var out []string
		for _, s := range rs {
			out = append(out, s.String())
		}
		return strings.Join(out, "; ")
	}
	type c struct {
		v6, v4         []ruleInfo
		missing        []ruleSpec
		reorder, guard bool
	}
	cases := map[string]c{
		"whole":                                 {[]ruleInfo{m6, a6, p6}, v4, nil, false, false},
		"whole, another agent's refusal ahead":  {[]ruleInfo{otherRefusal, m6, a6, p6}, v4, nil, false, false},
		"mark lookup put back last":             {[]ruleInfo{a6, p6, m6}, v4, nil, false, false},
		"address lookup put back last":          {[]ruleInfo{m6, p6, a6}, v4, nil, false, false},
		"mark lookup gone":                      {[]ruleInfo{a6, p6}, v4, want[0:1], false, false},
		"address lookup gone":                   {[]ruleInfo{m6, p6}, v4, want[1:2], false, false},
		"refusal gone":                          {[]ruleInfo{m6, a6}, v4, want[2:3], false, false},
		"both address rules gone":               {[]ruleInfo{m6}, v4, want[1:3], false, false},
		"both lookups gone":                     {[]ruleInfo{p6}, v4, want[0:2], true, false},
		"refusal ahead of the only lookup":      {[]ruleInfo{p6, a6}, v4, want[0:1], true, false},
		"refusal ahead of both":                 {[]ruleInfo{p6, m6, a6}, v4, nil, true, false},
		"everything gone":                       {nil, nil, want, false, false},
		"IPv4 only gone":                        {[]ruleInfo{m6, a6, p6}, nil, want[3:5], false, false},
		"a guard up, rules whole":               {[]ruleInfo{guard, m6, a6, p6}, v4, nil, false, true},
		"another agent's guard":                 {[]ruleInfo{func() ruleInfo { g := guard; g.src = kOther; return g }(), m6, a6, p6}, v4, nil, false, false},
		"an earlier release's guard":            {[]ruleInfo{func() ruleInfo { g := guard; g.proto = legacyRuleProto; return g }(), m6, a6, p6}, v4, nil, false, true},
		"a refusal at 4299 naming table main":   {[]ruleInfo{func() ruleInfo { g := guard; g.table = 254; return g }(), m6, a6, p6}, v4, nil, false, false},
		"a look-alike refusal is not the rule":  {[]ruleInfo{m6, a6, func() ruleInfo { r := p6; r.extra = true; return r }()}, v4, want[2:3], false, false},
		"the refusal tagged 87 is not the rule": {[]ruleInfo{m6, a6, func() ruleInfo { r := p6; r.proto = legacyRuleProto; return r }()}, v4, want[2:3], false, false},
	}
	for name, tc := range cases {
		w := keepPlan(want, kSelf, tc.v6, tc.v4)
		if names(w.missing) != names(tc.missing) || w.reorder != tc.reorder || w.guard != tc.guard {
			t.Errorf("%s: missing [%s] reorder %v guard %v; want [%s] reorder %v guard %v", name, names(w.missing),
				w.reorder, w.guard, names(tc.missing), tc.reorder, tc.guard)
		}
		if w.broken() != (len(tc.missing) > 0 || tc.reorder) {
			t.Errorf("%s: broken %v", name, w.broken())
		}
	}
}

// The keeper says what it did without flooding: the first time at once, then at most once a minute with
// a count, and a failure once until a repair succeeds.
func TestTheKeeperSaysWhatItDidWithoutFlooding(t *testing.T) {
	k := &ruleKeeper{self: kSelf, want: keepRoute(false).rules(kSelf)}
	w := keepWork{missing: k.want[1:3]}
	first := k.noteHold(w, nil)
	if !strings.Contains(first, "deleted the containment's routing rules (IPv6 4303: from "+kSelf.String()+" lookup 4303") ||
		!strings.Contains(first, "refused while they are put back") {
		t.Fatalf("the first note: %q", first)
	}
	if again := k.noteHold(w, nil); again != "" {
		t.Fatalf("a second hold within the minute was said: %q", again)
	}
	k.notedAt = time.Now().Add(-2 * keepNoteEvery)
	if later := k.noteHold(w, nil); !strings.Contains(later, "(2 times since the last note)") {
		t.Fatalf("the note after the minute does not count what it did not say: %q", later)
	}
	k.held, k.heldSince, k.holdSeen = true, time.Now().Add(-1500*time.Millisecond), 4
	if rel := k.noteRelease(time.Now()); !strings.Contains(rel, "was refused for 1.5s") ||
		!strings.Contains(rel, "through 4 more deletions") {
		t.Fatalf("the release note: %q", rel)
	}
	if f := k.noteFail(w, true, fmt.Errorf("boom")); !strings.Contains(f, "stays refused") ||
		!strings.Contains(f, "`ip -6 -d rule show pref 4299` shows `from "+kSelf.String()+" prohibit`") {
		t.Fatalf("a guarded failure: %q", f)
	}
	if f := k.noteFail(w, true, fmt.Errorf("boom")); f != "" {
		t.Fatalf("a failure was said twice: %q", f)
	}
	k.failing = false
	if f := k.noteFail(w, false, fmt.Errorf("boom")); !strings.Contains(f, "can leave by this host's own routes") {
		t.Fatalf("an unguarded failure does not say what it leaves open: %q", f)
	}
	for i := 1; i <= 4; i++ {
		if m := k.noteDump(fmt.Errorf("x")); (m != "") != (i == 3) {
			t.Fatalf("dump failure %d said %q", i, m)
		}
	}
}

// A keeper whose notes nobody reads (a paused pager, a stalled journal) still stops at once: its writer
// is one nothing waits for. Here its device does not exist, so its first look says so, into a logf that
// never returns, and from then on it only waits to be stopped.
func TestAKeeperStopsWhileItsNotesAreStuck(t *testing.T) {
	host, err := nsInode()
	if err != nil {
		t.Skip("no network namespace to read")
	}
	hr := routeFor("wsc255", 1<<30, 255, 9)
	hr.self = kSelf
	n := &Namespace{fd: -1, HostInode: host, host: &hr}
	stuck, said := make(chan struct{}), make(chan string, 4)
	defer close(stuck)
	n.keepRules(func(f string, a ...any) {
		said <- fmt.Sprintf(f, a...)
		<-stuck
	})
	if n.keeper == nil {
		t.Fatal("no keeper started")
	}
	select {
	case m := <-said:
		if !strings.Contains(m, "wsc255 is gone") {
			t.Fatalf("the keeper said %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper said nothing about a device that does not exist")
	}
	done := make(chan struct{})
	go func() { n.keeper.stop(); close(done) }() // what seal does first; the rest of seal needs root
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopping the keeper waited on its stuck notes")
	}
}

// The gate compares the source a word at a time with 32-bit jumps: an address word with its top bit set
// would be sign-extended against a 64-bit register by a 64-bit jump, and never match. No address, no
// check: an unspecified one would refuse every packet sent from ::.
func TestTheGatesSourceCheckComparesEveryWordWith32BitJumps(t *testing.T) {
	self := netip.MustParseAddr("2001:db8:ff80:ff80:aaaa:bbbb:cccc:dd99") // every word's top bit set, read little-endian
	words := map[int32]bool{}
	a := self.As16()
	for i := 0; i < 4; i++ {
		words[int32(binary.NativeEndian.Uint32(a[4*i:]))] = true
	}
	found := 0
	for _, ins := range gateSourceCheck(self, 7, 1) {
		if ins.OpCode.Class() == asm.Jump32Class && words[int32(ins.Constant)] {
			found++
		}
		if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.JNE && words[int32(ins.Constant)] && ins.Constant > 7 {
			t.Fatalf("an address word is compared with a 64-bit jump: %v", ins)
		}
	}
	if found != 4 {
		t.Fatalf("%d of the 4 address words are compared with 32-bit jumps", found)
	}
	// IPv4 never reaches the helper: the protocol is read first.
	proto, helper := -1, -1
	for i, ins := range sourceGateSpec(self, 7, 1, 3).Instructions {
		if ins.OpCode.Class().IsLoad() && ins.Offset == skbProtocolOff && proto < 0 {
			proto = i
		}
		if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnSkbLoadBytes) {
			helper = i
		}
	}
	if proto < 0 || helper < 0 || proto > helper {
		t.Fatalf("the protocol is read at %d and the packet at %d: IPv4 would pay for the read", proto, helper)
	}
	for _, none := range []netip.Addr{{}, netip.IPv6Unspecified(), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1")} {
		for _, ins := range gateSourceCheck(none, 7, 1) {
			if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnSkbLoadBytes) {
				t.Fatalf("a gate for %v reads packet bytes: it has no address to compare", none)
			}
		}
	}
}

// A gate whose address check could not be attached is cleaned up without closing a link it never had: a
// failed attach hands back a nil link in an interface, which is not a nil interface.
func TestAGateCleanupNeverClosesALinkItNeverGot(t *testing.T) {
	var nilLink *link.RawLink
	g := &rootGate{}
	g.src = nilLink
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("closing a gate whose link attach failed panicked: %v", r)
		}
	}()
	g.close()
}
