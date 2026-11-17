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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// rulekeep_linux.go keeps a live containment's policy rules in place.
//
// The rules are the containment: the mark's lookup routes its sockets into the tunnel, and the
// agent's address rules keep anything else from leaving with the /128 as its source. They are
// ordinary rules in the host's table, and anything with CAP_NET_ADMIN can delete them.
// systemd-networkd used to, on every restart or reconfigure; the protocol they carry now
// (hostRuleProto) is the one it leaves alone. Nothing makes every other program on a host do the
// same, so while the tunnel lives a keeper watches the kernel's rule notifications, puts back what
// goes, and says so. Without it a deleted rule would lapse silently: the contained process would lose
// its traffic, or an unmarked packet from the /128 would leave by the host's own uplink.
//
// When it finds any of its rules gone, it first puts up the guard, "from <the /128> prohibit" at
// hostGuardPrio above every slot, which refuses the address outright, marked or not. Then it puts the
// rules back, and it takes the guard away only once nothing has deleted any of them for keepQuiet. A
// program that deletes rules one by one from a list it read earlier, or that keeps deleting them, so
// meets the guard and not a gap: the containment is closed for as long as that goes on, and it
// says so. What is left open is the time from the first deletion to the guard, one notification and
// one dump.
//
// A notification is only ever a reason to look. What the keeper does comes from a dump of the rules,
// read from the kernel and compared with the rules this containment installed, and only the kernel's
// own messages are read: a message it should not have received can at most cost one more look.

// keepEvery is how often the keeper looks even when nothing told it to: it is what still finds a
// deletion when the notifications cannot be read, and what retries a repair that failed.
var keepEvery = 5 * time.Second

// keepQuiet is how long nothing may delete one of the containment's rules before the keeper takes its
// guard away again.
var keepQuiet = 300 * time.Millisecond

// keepNoteEvery bounds how often the keeper says it put rules back, when something keeps deleting
// them: the first time at once, then at most once in this long, with how many times since.
const keepNoteEvery = time.Minute

// ruleSpec is one policy rule a containment installs, exactly as it installs it.
type ruleSpec struct {
	fam        uint8
	prio       uint32
	action     uint8 // frActToTbl or frActProhibit
	table      uint32
	mark, mask uint32     // a mark rule's; zero for a source rule
	src        netip.Addr // a source rule's full-length source; invalid for a mark rule
	what       string     // what it does, for a message that it could not be added
}

// rules lists the rules a containment installs for self, in the order it installs them. The order
// matters at one priority: the kernel tries rules of equal priority in the order they were added,
// and the refusal of the agent's address has to come after a lookup that takes the containment's
// own marked traffic from the /128.
func (hr *HostRoute) rules(self netip.Addr) []ruleSpec {
	out := []ruleSpec{
		{fam: unix.AF_INET6, prio: hr.Prio, action: frActToTbl, table: hr.Table, mark: hr.Mark, mask: hostMarkMask,
			what: "select the tunnel's table by socket mark (IPv6)"},
		{fam: unix.AF_INET6, prio: hr.Prio, action: frActToTbl, table: hr.Table, src: self,
			what: "select the tunnel's table for the agent's address"},
		{fam: unix.AF_INET6, prio: hr.Prio, action: frActProhibit, src: self,
			what: "refuse the agent's address any other way"},
	}
	if hr.CarryV4 {
		out = append(out,
			ruleSpec{fam: unix.AF_INET, prio: hr.Prio, action: frActToTbl, table: hr.Table, mark: hr.Mark, mask: hostMarkMask,
				what: "select the tunnel's table by socket mark (IPv4)"},
			ruleSpec{fam: unix.AF_INET, prio: hr.Prio, action: frActToTbl, table: hr.Table, src: CLATv4,
				what: "select the tunnel's table for the translator's address"})
	}
	return out
}

// body encodes the rule, without its protocol.
func (s ruleSpec) body() []byte {
	switch {
	case s.mark != 0:
		return ruleBody(s.fam, s.prio, s.mark, s.mask, s.table)
	case s.action == frActProhibit:
		return ruleBodyProhibit(s.fam, s.prio, s.src)
	default:
		return ruleBodyFrom(s.fam, s.prio, s.src, s.table)
	}
}

// is reports whether a rule the kernel listed is this one, carrying the protocol a containment
// installs it with and selecting on nothing more. An attribute this code does not know does not stop
// it being this one: a kernel that lists a new attribute on every rule must not make the keeper think
// every rule is gone.
func (s ruleSpec) is(r ruleInfo) bool {
	return r.fam == s.fam && r.prio == s.prio && r.action == s.action && r.table == s.table &&
		r.mark == s.mark && r.mask == s.mask && r.src == s.src && r.proto == hostRuleProto && !r.extra
}

// String names the rule the way `ip rule` shows it.
func (s ruleSpec) String() string {
	fam := "IPv6"
	if s.fam == unix.AF_INET {
		fam = "IPv4"
	}
	switch {
	case s.mark != 0:
		return fmt.Sprintf("%s %d: fwmark %#x/%#x lookup %d", fam, s.prio, s.mark, s.mask, s.table)
	case s.action == frActProhibit:
		return fmt.Sprintf("%s %d: from %s prohibit", fam, s.prio, s.src)
	default:
		return fmt.Sprintf("%s %d: from %s lookup %d", fam, s.prio, s.src, s.table)
	}
}

// keepWork is what one look found.
type keepWork struct {
	missing []ruleSpec // this containment's rules the kernel no longer lists, in install order
	// reorder is set when the refusal is listed with no lookup ahead of it: a rule added again lands
	// after every other rule at its priority, so putting back only the lookups would leave the refusal
	// first, refusing the containment's own traffic. The refusal then goes and comes back last.
	reorder bool
	refusal ruleInfo // the refusal as listed, when reorder is set
	// guard is set when a guard for the agent's address is up.
	guard bool
}

func (w keepWork) broken() bool { return len(w.missing) > 0 || w.reorder }

// keepPlan compares the rules a containment installs (want, in order) with what the kernel lists.
func keepPlan(want []ruleSpec, self netip.Addr, v6, v4 []ruleInfo) keepWork {
	var w keepWork
	firstLookup, refusalAt := -1, -1
	for _, s := range want {
		list := v6
		if s.fam == unix.AF_INET {
			list = v4
		}
		at := -1
		for i, r := range list {
			if s.is(r) {
				at = i
				break
			}
		}
		switch {
		case at < 0:
			w.missing = append(w.missing, s)
		case s.fam != unix.AF_INET6:
		case s.action == frActProhibit:
			refusalAt, w.refusal = at, list[at]
		case firstLookup < 0 || at < firstLookup:
			firstLookup = at
		}
	}
	w.reorder = refusalAt >= 0 && (firstLookup < 0 || refusalAt < firstLookup)
	for _, r := range v6 {
		w.guard = w.guard || isGuard(r, self)
	}
	return w
}

// ruleKeeper puts a live containment's rules back when something else on the host deletes them.
type ruleKeeper struct {
	want  []ruleSpec
	self  netip.Addr
	dev   string // the tunnel device, wsc<n>, and the index it had when it was made: the slot's rules
	index int    // are this containment's only while that device still holds the name
	host  uint64 // the host namespace's inode: a keeper on a thread of any other one does nothing
	logf  func(string, ...any)
	// notes carries what the keeper says to a writer of its own, which nothing waits for: a stderr that
	// blocks (a paused pager, a stalled journal) never holds up a look or stop. A note that finds it full
	// is dropped and counted.
	notes   chan string
	dropped int

	mu        sync.Mutex // held for a whole look and by stop, so no look writes anything after stop returns
	stopped   bool
	wake      int // an eventfd that stop writes to
	done      chan struct{}
	ready     chan struct{} // closed once it follows the notifications and has looked once, or has given up
	readyOnce sync.Once

	w    *rtnl  // the keeper's own writes; a notification of one carries its port id
	wpid uint32 // that port id

	held         bool      // the guard is up
	heldSince    time.Time //
	holdUntil    time.Time // when it comes down, unless another deletion is seen first
	holdSeen     int       // deletions seen while it was up
	repairs      int       // looks that put a rule back
	repairedLast bool      // the last look put rules back
	subscribed   bool      // it follows the kernel's notifications, so a deletion it was not told of is none
	deleter      uint32    // the netlink port the last notified deletion came from: a hint at who
	nextLook     time.Time // when the keeper looks next with nothing told: its period, or the hold's end
	buf          []byte    // for the notifications

	// What it has said, so a fight with something that keeps deleting is not a flood.
	notedAt   time.Time
	unnoted   int
	holdNoted bool
	failing   bool
	dumpFails int
	gone      bool
	watchNote bool
}

// keepRules starts the keeper for a host device's rules, for as long as the handle is open: seal stops
// it before it removes them. It does nothing for an agent namespace, whose rules no host program sees.
func (n *Namespace) keepRules(logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := n.startKeeper(logf); err != nil {
		logf("whisper: cannot keep the containment's routing rules (%v): if another program on this host deletes "+
			"them, nothing puts them back", err)
	}
}

func (n *Namespace) startKeeper(logf func(string, ...any)) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.closed || n.keeper != nil {
		return nil
	}
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return err
	}
	k := &ruleKeeper{want: n.host.rules(n.host.self), self: n.host.self, dev: n.host.Name, index: n.host.Index,
		host: n.HostInode, logf: logf, wake: wake, done: make(chan struct{}), ready: make(chan struct{}),
		notes: make(chan string, 16),
		buf:   make([]byte, 1<<16)}
	n.keeper = k
	go func() {
		for m := range k.notes {
			logf("%s", m)
		}
	}()
	go k.run()
	return nil
}

// stop ends the keeper and waits for it. Once it returns, the keeper writes nothing more: a look in
// progress finishes first, and none starts after.
func (k *ruleKeeper) stop() {
	k.mu.Lock()
	k.stopped = true
	k.mu.Unlock()
	var one [8]byte
	binary.NativeEndian.PutUint64(one[:], 1)
	_, _ = unix.Write(k.wake, one[:])
	<-k.done
	unix.Close(k.wake) // the keeper is gone, so nothing can still be polling it
	close(k.notes)     // its writer says what is left and ends; nothing waits for it
}

// repaired is how many looks put a rule back.
func (k *ruleKeeper) repaired() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.repairs
}

func (k *ruleKeeper) run() {
	defer close(k.done)
	isReady := func() { k.readyOnce.Do(func() { close(k.ready) }) }
	defer isReady()
	// One thread for the keeper's whole life, checked to be in the host's namespace: every socket it
	// opens, the subscription, its writes and each dump, belongs to the namespace of the thread that
	// opens it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ino, err := nsInode(); err != nil || ino != k.host {
		k.say("whisper: the containment's rule keeper is not in the host's network namespace, so it does not run: " +
			"if another program on this host deletes the containment's routing rules, nothing puts them back")
		return
	}
	w, err := openRTNL()
	if err != nil {
		k.say(fmt.Sprintf("whisper: cannot keep the containment's routing rules (%v): if another program on this host "+
			"deletes them, nothing puts them back", err))
		return
	}
	defer w.close()
	k.w = w
	if sa, err := unix.Getsockname(w.fd); err == nil {
		if nl, ok := sa.(*unix.SockaddrNetlink); ok {
			k.wpid = nl.Pid
		}
	}
	sub, err := subscribeRules()
	if err != nil {
		sub = -1
		k.say(k.noteWatch(err))
	}
	k.subscribed = sub >= 0
	defer func() {
		if sub >= 0 {
			unix.Close(sub)
		}
	}()
	k.look(false) // after subscribing: a deletion from here on is either seen by this look or notified
	isReady()
	for {
		fds := []unix.PollFd{{Fd: int32(k.wake), Events: unix.POLLIN}}
		timeout := -1 // a keeper whose device is gone only waits to be stopped
		if !k.gone {
			if sub >= 0 {
				fds = append(fds, unix.PollFd{Fd: int32(sub), Events: unix.POLLIN})
			}
			timeout = int((max(time.Until(k.nextLook), 0) + time.Millisecond - 1) / time.Millisecond)
		}
		_, err := unix.Poll(fds, timeout)
		if err != nil {
			if !errors.Is(err, unix.EINTR) {
				time.Sleep(100 * time.Millisecond) // a poll the kernel refused (ENOMEM) is asked again, not spun on
			}
			continue
		}
		if fds[0].Revents != 0 {
			return
		}
		if k.gone {
			continue
		}
		told := false
		if sub >= 0 && fds[1].Revents != 0 {
			// Every waiting notification is read before the dump, so one that arrives during the dump is
			// still waiting for the next round. An overflow (POLLERR) is read as ENOBUFS, which also clears
			// it. Notifications of other rules are read and set aside; they never put off the next look.
			hit, port, rerr := drainRuleEvents(sub, k.buf, k.ours, k.wpid)
			if port != 0 {
				k.deleter = port
			}
			if rerr != nil {
				unix.Close(sub)
				sub = -1
				k.subscribed = false
				k.say(k.noteWatch(rerr))
				hit = true
			}
			told = hit
		}
		due := !time.Now().Before(k.nextLook)
		if sub < 0 && due {
			if s, err := subscribeRules(); err == nil { // tried again at every period
				sub, k.subscribed = s, true
			}
		}
		if told || due {
			k.look(told)
		}
	}
}

// ours reports whether a deleted rule is one of this containment's, or its guard.
func (k *ruleKeeper) ours(r ruleInfo) bool {
	for _, s := range k.want {
		if s.is(r) {
			return true
		}
	}
	return isGuard(r, k.self)
}

// look reads the rules and puts back what is missing; told says a deletion of one of them was notified.
// It writes its messages after letting go of the lock, so a stuck stderr never holds up stop.
func (k *ruleKeeper) look(told bool) {
	k.mu.Lock()
	msgs := k.lookLocked(told)
	// The next look with nothing told: the period, or sooner while the guard is held, never in the past,
	// so a look that returned early never makes the keeper spin.
	now := time.Now()
	k.nextLook = now.Add(keepEvery)
	if k.held {
		end := k.holdUntil
		if end.Before(now.Add(keepQuiet)) && !end.After(now) {
			end = now.Add(keepQuiet)
		}
		if end.Before(k.nextLook) {
			k.nextLook = end
		}
	}
	k.mu.Unlock()
	for _, m := range msgs {
		k.say(m)
	}
}

func (k *ruleKeeper) say(m string) {
	if m == "" {
		return
	}
	if k.dropped > 0 {
		m += fmt.Sprintf(" (%d earlier notes were dropped: nothing was reading them)", k.dropped)
	}
	select {
	case k.notes <- m:
		k.dropped = 0
	default:
		k.dropped++
	}
}

func (k *ruleKeeper) lookLocked(told bool) (msgs []string) {
	if k.stopped {
		return nil
	}
	// The slot's rules are this containment's only while its device holds the slot's name: a device that
	// went (its TUN closed on an error) frees the slot for the next containment on the host.
	if !k.ownsSlot() {
		k.gone = true
		return append(msgs, fmt.Sprintf("whisper: the containment's tunnel device %s is gone, so its routing rules "+
			"are no longer kept", k.dev))
	}
	now := time.Now()
	if told && k.held {
		k.holdSeen++
		k.holdUntil = now.Add(keepQuiet)
	}
	w, v6, err := k.read()
	if err != nil {
		if told && !k.held && k.addGuard() == nil {
			// A deletion was notified and the rules cannot be read: refused until they can.
			k.held, k.heldSince, k.holdSeen, k.holdUntil = true, now, 0, now.Add(keepQuiet)
		}
		return append(msgs, k.noteDump(err))
	}
	if w.broken() {
		// Confirmed by a second read before the address is refused: a dump that ran while another
		// containment's rules changed can skip a rule.
		if w, v6, err = k.read(); err != nil {
			return append(msgs, k.noteDump(err))
		}
	}
	k.dumpFails = 0
	broken := w.broken()
	if broken && !told && k.repairedLast && k.subscribed {
		// Put back last time, and listed as missing again with no deletion notified: the kernel took the adds
		// (EEXIST) but does not list the rules as this containment's. Said once; the guard stays meanwhile.
		msgs = append(msgs, k.noteFail(w, true, fmt.Errorf("they were put back but the kernel does not list them "+
			"(`ip -6 -d rule show pref %d`): a rule of the same shape that also selects on something (a destination, "+
			"`not`, a tos) is in the way", k.want[0].prio)))
	}
	k.repairedLast = false
	if broken || k.held && now.Before(k.holdUntil) {
		// The guard is up for as long as the hold lasts, whatever deleted it meanwhile.
		if !w.guard {
			if gerr := k.addGuard(); gerr != nil {
				if !broken {
					return append(msgs, k.noteFail(w, false, fmt.Errorf("could not put the guard back: %w", gerr)))
				}
				// No guard, but the rules go back all the same: that alone closes the gap.
				if rerr := k.repair(w, v6); rerr != nil {
					return append(msgs, k.noteFail(w, false, fmt.Errorf("%w; and could not refuse the agent's address "+
						"meanwhile: %v", rerr, gerr)))
				}
				k.repairs++
				k.repairedLast = true
				return append(msgs, k.noteHold(w, gerr))
			}
		}
		if !k.held {
			k.held, k.heldSince, k.holdSeen = true, now, 0
			msgs = append(msgs, k.noteHold(w, nil))
		}
		if broken {
			k.holdUntil = now.Add(keepQuiet)
			if err := k.repair(w, v6); err != nil {
				return append(msgs, k.noteFail(w, true, err))
			}
			k.repairs++
			k.repairedLast = true
		}
		return msgs // the guard stays until nothing has deleted any for keepQuiet
	}
	released := ""
	if (k.held && !now.Before(k.holdUntil)) || (!k.held && w.guard) {
		if err := k.removeGuard(); err != nil {
			return append(msgs, k.noteFail(w, true, fmt.Errorf("could not take away the guard: %w", err)))
		}
		released = k.noteRelease(now)
		k.held = false
		msgs = append(msgs, released)
	}
	if k.failing && !k.held {
		k.failing = false
		if released == "" {
			msgs = append(msgs, "whisper: the containment's routing rules are back in place")
		}
	}
	return msgs
}

// keepDump is how the keeper reads the rules; a test stands in a dump the kernel did not finish.
var keepDump = dumpRulesErr

// read dumps both families and compares them with the containment's rules.
func (k *ruleKeeper) read() (keepWork, []ruleInfo, error) {
	v6, err := keepDump(unix.AF_INET6)
	if err != nil {
		return keepWork{}, nil, err
	}
	v4, err := keepDump(unix.AF_INET)
	if err != nil {
		return keepWork{}, nil, err
	}
	return keepPlan(k.want, k.self, v6, v4), v6, nil
}

// repair puts the missing rules back in install order. A refusal listed ahead of every lookup is moved
// after them once they are back: it goes and comes back last, while a lookup already takes unmarked
// traffic from the /128 into the tunnel, so the address is never left unrefused meanwhile, guard or not.
// If the device lost the slot's name while it wrote, what it wrote is taken back: the slot's rules would
// be the next holder's.
func (k *ruleKeeper) repair(w keepWork, v6 []ruleInfo) error {
	var added []ruleSpec
	add := func(s ruleSpec) error {
		if err := k.w.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, tagged(s.body())); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil
			}
			return fmt.Errorf("could not %s: %w", s.what, err)
		}
		added = append(added, s)
		return nil
	}
	defer func() {
		if len(added) > 0 && !k.ownsSlot() {
			for _, s := range added {
				if s.action != frActProhibit { // the refusal is the address's, not the slot's: it stays
					_ = k.w.do(unix.RTM_DELRULE, 0, tagged(s.body()))
				}
			}
			k.gone = true
		}
	}()
	for _, s := range k.want {
		for _, m := range w.missing {
			if m == s {
				if err := add(s); err != nil {
					return err
				}
			}
		}
	}
	if w.reorder {
		// Only if this delete takes the containment's own refusal, and not a rule of anybody else's that
		// names the address the same way and selects on more.
		if !deletesFirst(v6, w.refusal) {
			return fmt.Errorf("another rule at priority %d names %s the same way ahead of the containment's refusal, "+
				"so the refusal is left where it is", w.refusal.prio, k.self)
		}
		var refusal ruleSpec
		for _, s := range k.want {
			if s.fam == unix.AF_INET6 && s.action == frActProhibit {
				refusal = s
			}
		}
		if err := k.w.do(unix.RTM_DELRULE, 0, tagged(refusal.body())); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("could not move the refusal after the lookups: %w", err)
		}
		if err := add(refusal); err != nil {
			return err
		}
	}
	return nil
}

// ownsSlot reports whether the containment's device still holds the slot's name: the slot's rules are its
// own only while it does. A device that went (its TUN closed on an error) frees the slot for the next
// containment on the host.
func (k *ruleKeeper) ownsSlot() bool {
	idx, err := ifIndex(k.dev)
	return err == nil && idx == k.index
}

func (k *ruleKeeper) addGuard() error {
	err := k.w.do(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, tagged(ruleBodyProhibit(unix.AF_INET6, hostGuardPrio, k.self)))
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// removeGuard takes away every guard for the agent's address, of either protocol, over the keeper's own
// socket (removeGuardOn).
func (k *ruleKeeper) removeGuard() error { return removeGuardOn(k.w, k.self) }

// noteHold says the guard went up (or, with guardErr, that it could not, and the rules went back
// without it), at once the first time and then at most once every keepNoteEvery.
func (k *ruleKeeper) noteHold(w keepWork, guardErr error) string {
	k.unnoted++
	if !k.notedAt.IsZero() && time.Since(k.notedAt) < keepNoteEvery {
		k.holdNoted = false
		return ""
	}
	times := ""
	if k.unnoted > 1 {
		times = fmt.Sprintf(" (%d times since the last note)", k.unnoted)
	}
	what := describeRules(w.missing)
	if what == "" {
		what = fmt.Sprintf("the order of its rules at %d", w.refusal.prio)
	}
	if by := deleterHint(k.deleter); by != "" {
		what += "; " + by
	}
	k.notedAt, k.unnoted, k.holdNoted = time.Now(), 0, guardErr == nil
	if guardErr != nil {
		return fmt.Sprintf("whisper: something on this host deleted the containment's routing rules (%s)%s. They are "+
			"back in place; the agent's address could not be refused while they went back (%v)", what, times, guardErr)
	}
	return fmt.Sprintf("whisper: something on this host deleted the containment's routing rules (%s)%s. The agent's "+
		"address is refused while they are put back, until nothing has deleted any for %s", what, times, keepQuiet)
}

// noteRelease says the guard came down, when its going up was said.
func (k *ruleKeeper) noteRelease(now time.Time) string {
	if !k.held || !k.holdNoted {
		return ""
	}
	k.holdNoted = false
	more := ""
	if k.holdSeen > 0 {
		more = fmt.Sprintf(", through %d more deletions", k.holdSeen)
	}
	return fmt.Sprintf("whisper: the containment's routing rules are back in place; the agent's address was refused "+
		"for %s%s", now.Sub(k.heldSince).Round(time.Millisecond), more)
}

// noteFail says a repair failed, once until one succeeds.
func (k *ruleKeeper) noteFail(w keepWork, guarded bool, err error) string {
	if k.failing {
		return ""
	}
	k.failing = true
	what := describeRules(w.missing)
	if what == "" {
		what = "their order"
	}
	if guarded {
		return fmt.Sprintf("whisper: could not put the containment's routing rules back (%s): %v. The agent's address "+
			"stays refused (`ip -6 -d rule show pref %d` shows `from %s prohibit`), so its traffic stops until they "+
			"are back; retrying", what, err, hostGuardPrio, k.self)
	}
	return fmt.Sprintf("whisper: could not put the containment's routing rules back (%s): %v. Until they are, a "+
		"packet from %s can leave by this host's own routes; retrying", what, err, k.self)
}

// noteDump says, once in a run of them, that the rules could not be read.
func (k *ruleKeeper) noteDump(err error) string {
	k.dumpFails++
	if k.dumpFails != 3 {
		return ""
	}
	return fmt.Sprintf("whisper: this host's routing rules could not be read %d times in a row (%v); the "+
		"containment's are checked again every %s", k.dumpFails, err, keepEvery)
}

// noteWatch says, once, that the keeper is down to looking every keepEvery.
func (k *ruleKeeper) noteWatch(err error) string {
	if k.watchNote {
		return ""
	}
	k.watchNote = true
	return fmt.Sprintf("whisper: cannot follow changes to this host's routing rules (%v); the containment's are checked "+
		"every %s instead, so one another program deletes is back within that", err, keepEvery)
}

// deleterHint names the program a deletion came from, as far as its netlink port tells: a socket bound
// by the kernel's choice takes its process's id as its port, so the process that port names is
// probably the one (a hint, not a proof; a process that has exited names nothing).
func deleterHint(port uint32) string {
	if port == 0 {
		return ""
	}
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", port)); err == nil {
		return fmt.Sprintf("deleted over netlink port %d, and process %d is %q", port, port, strings.TrimSpace(string(comm)))
	}
	return fmt.Sprintf("deleted over netlink port %d", port)
}

func describeRules(rs []ruleSpec) string {
	parts := make([]string, len(rs))
	for i, s := range rs {
		parts[i] = s.String()
	}
	return strings.Join(parts, ", ")
}

// subscribeRules opens a socket on the kernel's IPv4 and IPv6 rule notifications. It is only ever read:
// a request sent on it would have its answer mixed with the notifications.
func subscribeRules() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("netlink bind: %w", err)
	}
	for _, g := range []int{unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_IPV6_RULE} {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("joining the rule notifications: %w", err)
		}
	}
	// Room for a burst; one that still overflows is ENOBUFS, which is a look of its own.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 1<<20) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	}
	return fd, nil
}

// drainRuleEvents reads every notification waiting on fd and reports whether any is a reason to look:
// one of this containment's rules deleted (ours) by anyone but the keeper itself (wpid), notifications
// lost to an overflow, or one that cannot be read. Only the kernel's own messages count. port is the
// netlink port the last such deletion was asked for on, when one was. An error is one that ends the
// subscription.
func drainRuleEvents(fd int, buf []byte, ours func(ruleInfo) bool, wpid uint32) (hit bool, port uint32, err error) {
	for {
		n, from, rerr := unix.Recvfrom(fd, buf, 0)
		switch {
		case errors.Is(rerr, unix.EAGAIN):
			return hit, port, nil
		case errors.Is(rerr, unix.EINTR):
			continue
		case errors.Is(rerr, unix.ENOBUFS):
			hit = true
			continue
		case rerr != nil:
			return hit, port, rerr
		}
		if sa, ok := from.(*unix.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue
		}
		msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
		if perr != nil {
			hit = true
			continue
		}
		for _, m := range msgs {
			if m.Header.Type != unix.RTM_DELRULE || wpid != 0 && m.Header.Pid == wpid {
				continue
			}
			if r, ok := parseRule(m.Data); !ok || ours(r) {
				hit, port = true, m.Header.Pid
			}
		}
	}
}
