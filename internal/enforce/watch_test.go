// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The enforced run's ending, driven step by step: every ordering below is forced through
// channels, so none of these tests depends on how fast anything runs. The deadline in wait only
// turns a hang into a failure.

// fakeAgent is the agent's main process as the watch sees it: it exits once, with its own code
// or with the code of a kill that reached it first.
type fakeAgent struct {
	mu     sync.Mutex
	exited bool
	code   uint32
	kills  []uint32
	killed chan struct{}
	fail   int // how many kills fail before one works
}

func newFakeAgent() *fakeAgent { return &fakeAgent{killed: make(chan struct{}, 8)} }

func (a *fakeAgent) exit(code uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.exited {
		a.exited, a.code = true, code
	}
}

// kill is what ending the job does: every process still running ends with code, and one that
// has already exited keeps the code it exited with.
func (a *fakeAgent) kill(code uint32) error {
	a.mu.Lock()
	if a.fail > 0 {
		a.fail--
		a.mu.Unlock()
		return errors.New("access denied")
	}
	a.mu.Unlock()
	a.exit(code)
	a.mu.Lock()
	a.kills = append(a.kills, code)
	a.mu.Unlock()
	a.killed <- struct{}{}
	return nil
}

func (a *fakeAgent) exitCode() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.exited {
		panic("the run read the exit code of an agent that is still running")
	}
	return a.code
}

func (a *fakeAgent) killCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.kills)
}

func (a *fakeAgent) killCodes() []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint32(nil), a.kills...)
}

type logCount struct{ n atomic.Int32 }

func (l *logCount) logf(string, ...any) { l.n.Add(1) }

func wait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	var zero T
	return zero
}

const lost = "one of the agent's filters is gone"

// A filter really lost just as the agent exits on its own: the check is in flight when the agent
// exits 7 and then reports the loss. The tree is still ended and the loss is said, but the
// agent's own exit is what comes back.
func TestAnAgentsOwnExitWinsOverACheckThatRacesIt(t *testing.T) {
	agent := newFakeAgent()
	tick := make(chan time.Time)
	inCheck, release := make(chan struct{}), make(chan struct{})
	var logs logCount
	w := startWatch(tick, nil, func() string {
		inCheck <- struct{}{}
		<-release
		return lost
	}, agent.kill, logs.logf)

	tick <- time.Time{}
	wait(t, inCheck, "the check to start")
	agent.exit(7) // the agent ends on its own while the check is in flight
	close(release)
	wait(t, agent.killed, "the kill") // the tree is still ended: the agent may have left children

	if why := w.finish(agent.exitCode()); why != "" {
		t.Fatalf("an agent that exited 7 on its own reads as killed: %q", why)
	}
	if logs.n.Load() != 1 { // read after finish, which has waited for the watch
		t.Fatalf("the loss was logged %d times, want once", logs.n.Load())
	}
	if got := agent.exitCode(); got != 7 {
		t.Fatalf("exit code %d, want the agent's own 7", got)
	}
}

// The safety property: a filter that disappears while the agent is still running ends it, and
// the run says why.
func TestAFilterLostWhileTheAgentRunsStillKillsIt(t *testing.T) {
	agent := newFakeAgent()
	tick := make(chan time.Time)
	var logs logCount
	w := startWatch(tick, nil, func() string { return lost }, agent.kill, logs.logf)

	tick <- time.Time{}
	wait(t, agent.killed, "the kill")
	code := agent.exitCode()
	if code != exitFilterLost {
		t.Fatalf("exit code %#x, want %#x", code, exitFilterLost)
	}
	if why := w.finish(code); why != lost {
		t.Fatalf("finish = %q, want %q", why, lost)
	}
	if logs.n.Load() != 1 {
		t.Fatalf("logged %d times, want once", logs.n.Load())
	}
}

// The failure seen on a real host: the agent exited 7 while the watch was still checking, the
// run removed its own filters, and the late check read that as a lost filter. finish waits for a
// check in flight, and once it returns no check runs again, so the teardown that follows can never
// be read as a lost filter and no kill can reach a job the run has let go of.
func TestFinishWaitsForTheCheckInFlightAndNoCheckFollowsIt(t *testing.T) {
	agent := newFakeAgent()
	tick := make(chan time.Time, 1)
	var filtersPresent atomic.Bool
	filtersPresent.Store(true)
	var checks atomic.Int32
	var checkReturned atomic.Bool
	inCheck := make(chan struct{})
	var w *agentWatch // set before the first tick is sent, which the check waits on
	check := func() string {
		checks.Add(1)
		inCheck <- struct{}{}
		<-w.stop // hold the check until finish has begun
		defer checkReturned.Store(true)
		if !filtersPresent.Load() {
			return lost
		}
		return ""
	}
	var logs logCount
	w = startWatch(tick, nil, check, agent.kill, logs.logf)

	tick <- time.Time{}
	wait(t, inCheck, "the check to start")
	agent.exit(7)
	if why := w.finish(agent.exitCode()); why != "" {
		t.Fatalf("finish = %q, want the agent's own exit", why)
	}
	if !checkReturned.Load() {
		t.Fatal("finish returned while a check was still in flight")
	}
	select {
	case <-w.stopped:
	default:
		t.Fatal("the watch is still running after finish")
	}

	// The run's teardown: the filters go, and time keeps passing. Nothing takes the tick.
	filtersPresent.Store(false)
	tick <- time.Time{}
	if len(tick) != 1 || checks.Load() != 1 {
		t.Fatalf("the watch took a tick after finish (%d checks)", checks.Load())
	}
	if agent.killCount() != 0 {
		t.Fatalf("the watch killed after finish: %v", agent.killCodes())
	}
}

func TestCtrlCEndsTheAgentAndSaysSo(t *testing.T) {
	agent := newFakeAgent()
	intr := make(chan os.Signal, 1)
	var logs logCount
	w := startWatch(nil, intr, func() string { return "" }, agent.kill, logs.logf)

	intr <- os.Interrupt
	wait(t, agent.killed, "the kill")
	if why := w.finish(agent.exitCode()); why != "interrupted" {
		t.Fatalf("finish = %q, want interrupted", why)
	}
	if got := agent.exitCode(); got != exitInterrupted {
		t.Fatalf("exit code %#x, want %#x", got, uint32(exitInterrupted))
	}
}

// An agent that handles Ctrl-C itself and exits before the CLI's kill lands reports its own
// exit.
func TestAnAgentThatExitsBeforeTheCtrlCKillKeepsItsOwnExit(t *testing.T) {
	agent := newFakeAgent()
	intr := make(chan os.Signal, 1)
	var logs logCount
	w := startWatch(nil, intr, func() string { return "" }, agent.kill, logs.logf)

	agent.exit(1)
	intr <- os.Interrupt
	wait(t, agent.killed, "the kill")
	if why := w.finish(agent.exitCode()); why != "" {
		t.Fatalf("finish = %q, want the agent's own exit", why)
	}
}

// A filter that stays missing for several ticks ends the agent once and says so once.
func TestTheAgentIsEndedOnceHoweverManyChecksFail(t *testing.T) {
	agent := newFakeAgent()
	tick := make(chan time.Time)
	var logs logCount
	w := startWatch(tick, nil, func() string { return lost }, agent.kill, logs.logf)

	for i := 0; i < 3; i++ {
		tick <- time.Time{}
	}
	wait(t, agent.killed, "the kill")
	if why := w.finish(agent.exitCode()); why != lost {
		t.Fatalf("finish = %q", why)
	}
	if n := agent.killCount(); n != 1 {
		t.Fatalf("killed %d times, want once", n)
	}
	if n := logs.n.Load(); n != 1 {
		t.Fatalf("logged %d times, want once", n)
	}
}

// An agent that exits with no check failing and no Ctrl-C reports its own exit.
func TestACleanExitIsReportedAsTheAgentsOwn(t *testing.T) {
	agent := newFakeAgent()
	tick := make(chan time.Time)
	var logs logCount
	w := startWatch(tick, nil, func() string { return "" }, agent.kill, logs.logf)
	tick <- time.Time{}
	agent.exit(0)
	if why := w.finish(agent.exitCode()); why != "" || agent.killCount() != 0 || logs.n.Load() != 0 {
		t.Fatalf("finish = %q, kills %d, logs %d", why, agent.killCount(), logs.n.Load())
	}
}

// A kill that fails is not taken as done: the next tick that still finds the filter gone kills
// again, and only a kill that worked becomes the verdict.
func TestAKillThatFailsIsTriedAgainOnTheNextTick(t *testing.T) {
	agent := newFakeAgent()
	agent.fail = 1
	tick := make(chan time.Time)
	var logs logCount
	w := startWatch(tick, nil, func() string { return lost }, agent.kill, logs.logf)

	tick <- time.Time{} // the first kill fails
	tick <- time.Time{} // taken only once the first check and its failed kill are done
	wait(t, agent.killed, "the second kill")
	code := agent.exitCode()
	if why := w.finish(code); why != lost || code != exitFilterLost {
		t.Fatalf("finish = %q, code %#x", why, code)
	}
	if n := agent.killCount(); n != 1 {
		t.Fatalf("%d kills worked, want 1", n)
	}
	if n := logs.n.Load(); n != 2 {
		t.Fatalf("logged %d times, want 2 (the failure, then the kill)", n)
	}
}

// A Ctrl-C whose kill fails is not dropped: the next tick kills again.
func TestACtrlCWhoseKillFailsIsTriedAgainOnTheNextTick(t *testing.T) {
	agent := newFakeAgent()
	agent.fail = 1
	intr := make(chan os.Signal) // unbuffered: the send returns once the watch has taken it
	tick := make(chan time.Time)
	var checks atomic.Int32
	var logs logCount
	w := startWatch(tick, intr, func() string { checks.Add(1); return "" }, agent.kill, logs.logf)

	intr <- os.Interrupt
	tick <- time.Time{} // taken only once the Ctrl-C and its failed kill are done
	wait(t, agent.killed, "the second kill")
	if why := w.finish(agent.exitCode()); why != "interrupted" {
		t.Fatalf("finish = %q, want interrupted", why)
	}
	if checks.Load() != 0 {
		t.Fatalf("the watch checked filters (%d) instead of ending an interrupted agent", checks.Load())
	}
}

// A kill that keeps failing is said once, not on every tick.
func TestAKillThatKeepsFailingIsSaidOnce(t *testing.T) {
	agent := newFakeAgent()
	agent.fail = 5
	tick := make(chan time.Time)
	var logs logCount
	w := startWatch(tick, nil, func() string { return lost }, agent.kill, logs.logf)
	for i := 0; i < 5; i++ {
		tick <- time.Time{}
	}
	agent.exit(7)
	if why := w.finish(agent.exitCode()); why != "" {
		t.Fatalf("finish = %q: no kill went through", why)
	}
	if n := logs.n.Load(); n != 1 {
		t.Fatalf("logged %d times, want once", n)
	}
}
