// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// refusals_linux.go removes what a containment leaves behind on purpose, once nothing needs it.
//
// When a tunnel stops, its agent's "from <the /128> prohibit" stays at the slot's priority, so a
// connection of the containment that is still ending (FIN_WAIT1, LAST_ACK, a request socket's
// SYN-ACK) never retransmits from the /128 by the host's own routes. A command that was killed leaves
// its "from <the /128> lookup <table>" beside it. Neither is needed once the kernel drives no TCP
// socket from the /128 any more, and every uncached IPv6 route lookup on the host passes both before
// it reaches main, so they go then: when any device is made, when a tunnel stops, and on
// `whisper contain --release`.
//
// The refusal protects the containment's own connections, not the address against the host: any
// unprivileged process can bind the /128 with IPV6_FREEBIND and send from it by main once nothing
// refuses it. So "nothing needs it" means what the kernel can list (sockdiag_linux.go): no TCP socket
// it could still send from the /128 for, other than one bound to a device that is gone, and no SCTP
// association with the /128 among its local addresses.
//
// A prune only ever deletes a rule a containment made: one carrying a containment's protocol (kernel, or
// 87 from a release before), in one of the exact shapes it installs. A rule written without a priority
// lands just above the lowest slot's (the kernel picks "the first rule's priority minus one"), so a
// priority alone proves nothing.

// prunePerPass bounds how many agents one prune takes up: their locks are held for its length, and a
// containment of one of them waits that out (LockExclusive). The rest go with the next prune.
const prunePerPass = 64

// pruneHeld runs once a prune holds its agents' locks. Tests use it to start a containment then.
var pruneHeld = func() {}

// agentRule is one rule a containment made for its agent's address.
type agentRule struct {
	prio, table uint32
	prohibit    bool
	proto       uint8    // the protocol it carries, which the delete names
	ri          ruleInfo // as the dump read it
}

// agentRuleOf says whether one IPv6 rule is one a containment made for an agent's address: exactly a
// "from <the /128> lookup <table>" at a slot's priority whose table is that slot's, or a
// "from <the /128> prohibit" at a slot's priority or at the guard's (CreateHostDevice), carrying a
// containment's protocol (hostRuleProto, or legacyRuleProto from a release before) and selecting on
// nothing else. The protocol alone proves little: kernel is also what a host's own rule carries when
// it is written to survive systemd-networkd, so the shape has to be exact too.
func agentRuleOf(r ruleInfo) (agentRule, bool) {
	if r.proto != hostRuleProto && r.proto != legacyRuleProto || r.mark != 0 || r.mask != 0 || r.extra || r.unknown ||
		!r.src.Is6() || r.src.Is4In6() {
		return agentRule{}, false
	}
	slot := r.prio >= hostRulePrio && r.prio < hostRulePrio+maxHostSlots
	switch {
	case r.action == frActProhibit && r.table == 0 && (slot || r.prio == hostGuardPrio):
		return agentRule{prio: r.prio, prohibit: true, proto: r.proto, ri: r}, true
	case r.action == frActToTbl && slot && r.table == hostTableBase+(r.prio-hostRulePrio):
		return agentRule{prio: r.prio, table: r.table, proto: r.proto, ri: r}, true
	}
	return agentRule{}, false
}

// agentRulesOnHost reads, from one dump, every rule a containment made for an agent's address
// (agentRuleOf). A dump that fails reads none, and so prunes nothing.
func agentRulesOnHost() map[netip.Addr][]agentRule {
	out := map[netip.Addr][]agentRule{}
	rules, err := dumpRulesErr(unix.AF_INET6)
	if err != nil {
		return out
	}
	for _, r := range rules {
		if ar, ok := agentRuleOf(r); ok {
			out[r.src] = append(out[r.src], ar)
		}
	}
	return out
}

// liveDeviceAgents names the agent of every tunnel device alive on this host: one whose record its
// command still holds. ok is false when a held record cannot be read, so some live device's agent
// is unknown and nothing may be pruned.
func liveDeviceAgents() (live map[netip.Addr]bool, ok bool) {
	live = map[netip.Addr]bool{}
	ents, err := os.ReadDir(containState)
	if err != nil {
		return live, errors.Is(err, os.ErrNotExist)
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "dev-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		f, err := os.OpenFile(filepath.Join(containState, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue // removed since the listing: that device is gone
		}
		if unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) == nil {
			_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
			f.Close() // nobody holds it: a device a killed command left, which the reaper takes
			continue
		}
		var r devRecord
		derr := json.NewDecoder(f).Decode(&r)
		f.Close()
		a, perr := netip.ParseAddr(r.Self)
		if derr != nil || perr != nil {
			return live, false
		}
		live[a] = true
	}
	return live, true
}

// containedAgents names every agent a containment record names: a containment that is live, or one
// whose command was killed, whose rules `whisper contain --release` or the agent's next containment
// clears. A record is named for its agent whether or not it can be read.
func containedAgents() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	ents, err := os.ReadDir(containState)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if name, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if a := addrOfCgroupName(name); a.IsValid() {
				out[a] = true
			}
		}
	}
	return out
}

// tunnelDeviceAddrs is every address a containment's tunnel device (wsc<n>) of this namespace holds. A
// device made under another /run is still one of these; an interface of the host's own carrying the
// address (a WireGuard set up by hand) is not, and does not keep a refusal that would refuse its traffic.
func tunnelDeviceAddrs() (map[netip.Addr]bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]bool{}
	for _, ifc := range ifs {
		if !strings.HasPrefix(ifc.Name, "wsc") {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			if p, perr := netip.ParsePrefix(a.String()); perr == nil {
				out[p.Addr().Unmap()] = true
			}
		}
	}
	return out, nil
}

// pruneAgentRefusals deletes the rules a containment made for each agent no containment needs any
// more, and returns the agents whose rules it deleted. An agent's rules go only when its lock can be
// held for the prune, no live device and no containment record names it, its address is on no tunnel
// device of this namespace, and the kernel drives no TCP socket and no SCTP association from it.
// Anything it cannot read prunes nothing.
//
// held is an agent whose lock the caller already holds (its own device's, or the containment it
// releases). Every other agent's lock is taken shared for the length of the prune: no device of an
// agent is made except under its exclusive lock, so the agent's next containment cannot put rules of
// the same shape on the same slot while they are deleted. The records live under /run, so the
// address on a tunnel device is checked too, from the kernel itself: a device holds its agent's address
// from before its rules go in until after they come out (install, seal), whoever's /run it uses.
//
// hostNS, when not 0, is the network namespace the rules belong to; a prune that finds itself on a
// thread of another one prunes nothing. The whole prune runs on one thread, so the rules, the
// sockets and the interfaces it reads are all that namespace's.
func pruneAgentRefusals(held netip.Addr, hostNS uint64) []netip.Addr {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if hostNS != 0 {
		if ino, err := nsInode(); err != nil || ino != hostNS {
			return nil
		}
	}
	rules := agentRulesOnHost()
	if len(rules) == 0 {
		return nil
	}
	var locks []*AgentLock
	defer func() {
		for _, l := range locks {
			l.Release()
		}
	}()
	var mine []netip.Addr
	for a := range rules {
		if len(mine) >= prunePerPass {
			break
		}
		if a == held {
			mine = append(mine, a)
			continue
		}
		if l := lockSharedQuiet(a); l != nil {
			locks = append(locks, l)
			mine = append(mine, a)
		}
	}
	pruneHeld()
	// Read under the locks, so a device or a containment of one of these agents is either seen here or
	// cannot start before the prune is done.
	live, ok := liveDeviceAgents()
	if !ok {
		return nil
	}
	contained := containedAgents()
	onHost, err := tunnelDeviceAddrs()
	if err != nil {
		return nil
	}
	var check []netip.Addr
	for _, a := range mine {
		if !live[a] && !contained[a] && !onHost[a] {
			check = append(check, a)
		}
	}
	if len(check) == 0 {
		return nil
	}
	socks, complete, _ := agentSockets(check)
	if !complete {
		return nil
	}
	ifs, err := liveIfindexes() // after the dump: a device that went in between leaves its sockets inert
	if err != nil {
		return nil
	}
	busy := map[netip.Addr]bool{}
	for _, s := range socks {
		if !s.inert(ifs) {
			busy[s.src] = true
		}
	}
	// Read again, now, for what each delete would take: a host's rule that names the same address at the
	// same priority, with the same protocol, and selects on something more, would go first if it sits
	// ahead of the containment's (deletesFirst), so then the containment's is left where it is.
	now, err := dumpRulesErr(unix.AF_INET6)
	if err != nil {
		return nil
	}
	r, err := openRTNL()
	if err != nil {
		return nil
	}
	defer r.close()
	var pruned []netip.Addr
	for _, a := range check {
		if busy[a] {
			continue
		}
		for _, ar := range rules[a] {
			if !deletesFirst(now, ar.ri) {
				continue
			}
			body := ruleBodyFrom(unix.AF_INET6, ar.prio, a, ar.table)
			if ar.prohibit {
				body = ruleBodyProhibit(unix.AF_INET6, ar.prio, a)
			}
			_ = r.do(unix.RTM_DELRULE, 0, withProto(body, ar.proto))
		}
		pruned = append(pruned, a)
	}
	return pruned
}

// endAgentSockets ends, with SOCK_DESTROY where the kernel has it, every TCP socket the kernel could
// still send from self for: a connection of the containment still ending, its TIME_WAIT, a request
// socket, or one held outside the containment. It runs once the tunnel is gone, so what is ended
// sends nothing. A full socket bound to a device that is gone is left: it can never send. It reports
// how many it ended.
func endAgentSockets(self netip.Addr) int {
	if !self.Is6() {
		return 0
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	socks, _, _ := agentSockets([]netip.Addr{self})
	if len(socks) == 0 {
		return 0
	}
	ifs, err := liveIfindexes()
	if err != nil {
		return 0
	}
	d, err := openSockDiag()
	if err != nil {
		return 0
	}
	defer d.close()
	n := 0
	for _, s := range socks {
		if !s.sctp && !s.inert(ifs) && endSocket(d, s) == nil { // an SCTP association is not TCP's to end
			n++
		}
	}
	return n
}

// endSocket ends one socket. A variable so a test can stand in for a kernel built without
// CONFIG_INET_DIAG_DESTROY, which answers EOPNOTSUPP.
var endSocket = func(d *sockDiag, s diagSock) error { return d.destroy(s) }
