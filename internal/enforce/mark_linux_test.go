// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// mark_linux_test.go covers what needs no root: a containment's mark, the counter it comes from,
// and the readers the sweep decides with.

// Every generation has a mark of its own, and no mark sets a bit another common mark user reads.
func TestEveryGenerationHasAMarkOfItsOwnThatNoOtherMarkUserReads(t *testing.T) {
	seen := make(map[uint32]uint32, maxGeneration)
	for g := uint32(1); g <= maxGeneration; g++ {
		m := markFor(g)
		if o, dup := seen[m]; dup {
			t.Fatalf("generations %d and %d share the mark %#x", o, g, m)
		}
		seen[m] = g
		switch {
		case m&0xc000 != 0:
			t.Fatalf("mark %#x (generation %d) sets kube-proxy's 0x4000 or 0x8000", m, g)
		case m&0x0f00 != 0:
			t.Fatalf("mark %#x (generation %d) sets Cilium's 0xf00 nibble", m, g)
		case m&0x80 != 0:
			t.Fatalf("mark %#x (generation %d) sets the AWS VPC CNI's 0x80", m, g)
		case (m>>16)&0xff == 0x04 || (m>>16)&0xff == 0x08:
			t.Fatalf("mark %#x (generation %d) has one of Tailscale's bytes as its third", m, g)
		case m>>16 == legacyMarkBase>>16:
			t.Fatalf("mark %#x (generation %d) could be a slot mark of the earlier release", m, g)
		case m&0x80000000 != 0:
			t.Fatalf("mark %#x (generation %d) is not a positive 32-bit immediate", m, g)
		}
	}
	if markFor(0) == markFor(1) || markFor(maxGeneration) == markFor(maxGeneration-1) {
		t.Fatal("neighbouring generations must differ")
	}
}

func counterFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), generationFile)
}

func bump(t *testing.T, path string) (uint32, error) {
	t.Helper()
	return bumpFloor(t, path, 0)
}

func bumpFloor(t *testing.T, path string, floor uint32) (uint32, error) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return bumpGeneration(f, floor)
}

func TestTheCounterHandsOutEachGenerationOnce(t *testing.T) {
	path := counterFile(t)
	for want := uint32(1); want <= 3; want++ {
		if got, err := bump(t, path); err != nil || got != want {
			t.Fatalf("bump %d: got %d, %v", want, got, err)
		}
	}
	// Concurrent containments, each with its own open file, never share a generation.
	var mu sync.Mutex
	got := map[uint32]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := bump(t, path)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if got[g] {
				t.Errorf("generation %d handed out twice", g)
			}
			got[g] = true
		}()
	}
	wg.Wait()
	if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), "00000023") {
		t.Fatalf("after 35 containments the counter holds %q", b)
	}
}

// A counter removed under live containments starts above the highest generation they still name;
// one behind it is not the counter they took their marks from, and refuses.
func TestTheCounterNeverGoesBelowWhatTheHostStillNames(t *testing.T) {
	path := counterFile(t)
	if g, err := bumpFloor(t, path, 40); err != nil || g != 41 {
		t.Fatalf("a missing counter with generation 40 alive: got %d, %v; want 41", g, err)
	}
	if g, err := bumpFloor(t, path, 41); err != nil || g != 42 {
		t.Fatalf("the next: %d, %v", g, err)
	}
	if _, err := bumpFloor(t, path, 99); err == nil || !strings.Contains(err.Error(), "another counter") {
		t.Fatalf("a live generation past the counter must refuse, got %v", err)
	}
}

// A holder that keeps the counter's lock (a stopped command) is waited for, then refused.
func TestTheCounterRefusesAHolderThatNeverLetsGo(t *testing.T) {
	path := counterFile(t)
	held, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	old := counterWait
	counterWait = 200 * time.Millisecond
	defer func() { counterWait = old }()
	if _, err := bump(t, path); err == nil || !strings.Contains(err.Error(), "held the containment counter") {
		t.Fatalf("a held counter must refuse after the wait, got %v", err)
	}
}

func TestTheCounterRefusesWhenEveryMarkIsTaken(t *testing.T) {
	path := counterFile(t)
	if err := os.WriteFile(path, []byte("0000fffe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := bump(t, path); err != nil || g != maxGeneration {
		t.Fatalf("the last generation: %d, %v", g, err)
	}
	if _, err := bump(t, path); err == nil || !strings.Contains(err.Error(), "reboot") {
		t.Fatalf("past the last generation the counter must refuse and say how to start over, got %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bump(t, path); err == nil {
		t.Fatal("a counter that is not a number must refuse, never start over at 1")
	}
}

// A marked rule names the mark under the containment's mask; a source rule names the address and
// its length; a tagged one carries the containment's route protocol, which a delete then matches.
func TestRuleBodiesNameWhatTheyMatch(t *testing.T) {
	attrs := func(b []byte) map[uint16][]byte {
		out := map[uint16][]byte{}
		for off := 12; off+4 <= len(b); {
			l := int(binary.NativeEndian.Uint16(b[off:]))
			out[binary.NativeEndian.Uint16(b[off+2:])] = b[off+4 : off+l]
			off += (l + 3) &^ 3
		}
		return out
	}
	u := func(b []byte) uint32 { return binary.NativeEndian.Uint32(b) }
	if tag := attrs(tagged(ruleBodyProhibit(unix.AF_INET6, 4300, netip.MustParseAddr("2a04:2a01:0:1::42")))); len(tag[fraProtocol]) != 1 ||
		tag[fraProtocol][0] != hostRuleProto {
		t.Fatalf("a tagged body %v", tag)
	}
	one := attrs(ruleBody(unix.AF_INET, 4301, markFor(9), hostMarkMask, 4301))
	if u(one[fraFwmark]) != markFor(9) || u(one[fraFwmask]) != hostMarkMask {
		t.Fatalf("a marked body %v", one)
	}
	self := netip.MustParseAddr("2a04:2a01:0:1::42")
	b := ruleBodyFrom(unix.AF_INET6, 4302, self, 4302)
	if b[1] != 0 || b[2] != 128 || b[7] != frActToTbl {
		t.Fatalf("a source rule's header % x", b[:12])
	}
	if from := attrs(b); netip.AddrFrom16([16]byte(from[fraSrc])) != self || u(from[fraTable]) != 4302 {
		t.Fatalf("a source rule %v", from)
	}
	p := ruleBodyProhibit(unix.AF_INET6, 4302, self)
	if p[2] != 128 || p[7] != frActProhibit {
		t.Fatalf("a prohibit rule's header % x", p[:12])
	}
	if _, has := attrs(p)[fraTable]; has {
		t.Fatal("a prohibit rule names no table")
	}
}

// genOf reads back every mark markFor makes, and nothing else.
func TestGenOfReadsBackEveryMark(t *testing.T) {
	for g := uint32(1); g <= maxGeneration; g++ {
		if got, ok := genOf(markFor(g)); !ok || got != g {
			t.Fatalf("genOf(markFor(%d)) = %d, %v", g, got, ok)
		}
	}
	for _, m := range []uint32{0, legacyMarkBase | 3, 0x80000, markFor(5) | 0x4000, hostMarkSig} {
		if g, ok := genOf(m); ok {
			t.Fatalf("mark %#x read as generation %d", m, g)
		}
	}
}

func TestScmInFlightReadsTheFdinfoLine(t *testing.T) {
	for in, want := range map[string][2]int{
		"pos:\t0\nflags:\t02\nmnt_id:\t9\nino:\t12\nscm_fds: 0\n": {0, 1},
		"pos:\t0\nscm_fds: 3\n":                                   {3, 1},
		"pos:\t0\nflags:\t02\n":                                   {0, 0},
		"scm_fds: x\n":                                            {0, 0},
	} {
		n, ok := scmInFlight(in)
		if n != want[0] || ok != (want[1] == 1) {
			t.Errorf("%q: %d %v, want %v", in, n, ok, want)
		}
	}
}

// A ring's fdinfo lists each registered-file slot by the file's bare name or "<none>", which cannot
// tell a socket from a file, so every occupied slot counts; and a table the kernel did not list (it
// could not take the ring's lock at once) is not read as empty. The first sample is a 6.8 kernel's
// for a ring holding a file named hostname and a UDP socket in a sparse table of four.
func TestRingHeldFilesCountsWhatTheRingHolds(t *testing.T) {
	for _, c := range []struct {
		info string
		held int
		ok   bool
	}{
		{"pos:\t0\nSqMask:\t0x3\nUserFiles:\t4\n    0: hostname\n    1: <none>\n    2: UDPv6\n    3: <none>\nUserBufs:\t0\n", 2, true},
		{"UserFiles:\t2\n    0: <none>\n    1: <none>\nUserBufs:\t0\n", 0, true},
		{"UserFiles:\t0\nUserBufs:\t0\n", 0, true},
		{"UserFiles:\t3\nUserBufs:\t0\n", 0, false}, // slots not listed
		{"pos:\t0\nSqMask:\t0x3\n", 0, true},        // no table
	} {
		held, ok := ringHeldFiles(c.info)
		if held != c.held || ok != c.ok {
			t.Errorf("%q: %d %v, want %d %v", c.info, held, ok, c.held, c.ok)
		}
	}
}

// On a kernel before 5.15 a mounted cgroup v1 net_cls or net_prio controller can turn off the cgroup
// v2 attribution of every socket, at any moment, so it refuses; from 5.15 the kernel keeps both.
func TestOldKernelsWithV1SocketClassifiersRefuse(t *testing.T) {
	v1 := "#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t0\t1\t1\nnet_cls\t5\t1\t1\nnet_prio\t5\t1\t1\n"
	unified := "#subsys_name\thierarchy\tnum_cgroups\tenabled\nnet_cls\t0\t1\t1\nnet_prio\t0\t1\t1\n"
	if got := v1SocketClassifier("5.10.0-23-amd64", v1); got != "net_cls" {
		t.Fatalf("5.10 with net_cls on a v1 hierarchy: %q", got)
	}
	for _, c := range [][2]string{{"5.10.0", unified}, {"5.15.0-91-generic", v1}, {"6.8.0-147-generic", v1}, {"6.12.116-fly", v1}} {
		if got := v1SocketClassifier(c[0], c[1]); got != "" {
			t.Fatalf("%s: %q", c[0], got)
		}
	}
}

// Scope 0 and no Yama at all are said; any other scope leaves nothing to say.
func TestPtraceNoteSaysWhatScopeZeroLeavesOpen(t *testing.T) {
	if n := ptraceNoteFor("0", nil); !strings.Contains(n, "ptrace_scope is 0") || !strings.Contains(n, "ptrace_scope=1") ||
		!strings.Contains(n, "run --enforce") {
		t.Fatalf("scope 0: %q", n)
	}
	if n := ptraceNoteFor("", &fs.PathError{Op: "open", Err: fs.ErrNotExist}); !strings.Contains(n, "no Yama") {
		t.Fatalf("no Yama: %q", n)
	}
	for _, scope := range []string{"1", "2", "3"} {
		if n := ptraceNoteFor(scope, nil); n != "" {
			t.Fatalf("scope %s must say nothing, said %q", scope, n)
		}
	}
	if n := ptraceNoteFor("", errors.New("permission denied")); n != "" {
		t.Fatalf("an unreadable scope is not a claim either way: %q", n)
	}
}

func TestACgroupNameGivesTheAgentBack(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:0:1::42")
	if got := addrOfCgroupName(containCgroupName(a)); got != a {
		t.Fatalf("got %s", got)
	}
	for _, bad := range []string{"", "2a042a01", strings.Repeat("g", 32)} {
		if addrOfCgroupName(bad).IsValid() {
			t.Fatalf("%q read as an address", bad)
		}
	}
	if n := rootGateName(maxGeneration); len(n) > 15 {
		t.Fatalf("a BPF program name has at most 15 characters, %q has %d", n, len(n))
	}
}

// The release leaves a socket alone only when its namespace could be read and is one the sweep found isolated.
// Every other case is cut, which is the fail-closed side: a namespace that could not be read, the host's, and any
// namespace at all when the release has no record of the isolated ones (a killed command's).
func TestTheReleaseKeepsOnlySocketsOfNamespacesTheSweepFoundIsolated(t *testing.T) {
	sealed := map[uint64]bool{4026532607: true}
	for _, c := range []struct {
		name   string
		netns  uint64
		known  bool
		sealed map[uint64]bool
		kept   bool
	}{
		{"isolated", 4026532607, true, sealed, true},
		{"the host's", 4026531840, true, sealed, false},
		{"another, not isolated", 4026532999, true, sealed, false},
		{"unreadable", 4026532607, false, sealed, false},
		{"no record of the isolated", 4026532607, true, nil, false},
		{"no record, unreadable", 0, false, nil, false},
	} {
		if got := keptAtRelease(c.netns, c.known, c.sealed); got != c.kept {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.kept)
		}
	}
}
