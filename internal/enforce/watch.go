// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"os"
	"time"
)

// watchInterval is how often the watch asks the engine for every filter the run depends on.
const watchInterval = 500 * time.Millisecond

// exitFilterLost is the agent's exit code when the watch ended it for a lost filter;
// exitInterrupted is STATUS_CONTROL_C_EXIT, what Windows reports for a program ended by Ctrl-C.
const (
	exitFilterLost  = 0xE0F1
	exitInterrupted = 0xC000013A
)

// agentWatch ends an enforced agent when a filter it depends on is gone, or on Ctrl-C. It owns
// the ordering of an enforced run's ending and nothing platform-specific, so that ordering is
// tested on every platform.
//
// Two rules hold the result honest:
//
//   - finish stops the watch and waits for it. The run removes its filters only after finish
//     returns, so a check can never see the run's own teardown and call it a lost filter, and
//     kill is never called once the run has started to let go of the agent's job.
//   - The agent's exit code decides whether the CLI ended it. A kill that reaches an agent that
//     has already exited leaves the agent's own code in place, and then the run reports the
//     agent's own exit, not a kill. (The kill still goes to the whole tree, so anything the agent
//     left running is stopped all the same.)
type agentWatch struct {
	tick  <-chan time.Time
	intr  <-chan os.Signal
	check func() string           // why the run must stop, "" while every filter is in place
	kill  func(code uint32) error // ends the agent's whole tree with code
	logf  func(string, ...any)

	stop    chan struct{}
	stopped chan struct{}

	// Written only by the watch goroutine, read by finish after the goroutine has ended.
	why  string
	code uint32
	// A Ctrl-C whose kill failed, retried on every tick; and whether a failed kill was said.
	interrupted, killFailed bool
}

// startWatch runs the watch until finish is called.
func startWatch(tick <-chan time.Time, intr <-chan os.Signal, check func() string, kill func(uint32) error,
	logf func(string, ...any)) *agentWatch {
	w := &agentWatch{tick: tick, intr: intr, check: check, kill: kill, logf: logf,
		stop: make(chan struct{}), stopped: make(chan struct{})}
	go w.loop()
	return w
}

func (w *agentWatch) loop() {
	defer close(w.stopped)
	for {
		// A stop that is already due is taken before a tick that is also due. This only saves a
		// needless check: finish waits for any check that does slip in, before anything is torn
		// down, so such a check still finds every filter in place.
		select {
		case <-w.stop:
			return
		default:
		}
		select {
		case <-w.stop:
			return
		case <-w.intr:
			w.interrupted = true
			w.end("interrupted", exitInterrupted)
		case <-w.tick:
			if w.interrupted {
				w.end("interrupted", exitInterrupted)
			} else if why := w.check(); why != "" {
				w.end(why, exitFilterLost)
			}
		}
	}
}

// end kills the agent's tree once and remembers why. A kill that fails is said once and not
// remembered, so the next tick kills again: after a Ctrl-C, or while a filter is still gone.
func (w *agentWatch) end(why string, code uint32) {
	if w.why != "" {
		return
	}
	if err := w.kill(code); err != nil {
		if !w.killFailed {
			w.killFailed = true
			w.logf("whisper: %s, and stopping the agent failed (%v); trying again every %v", why, err, watchInterval)
		}
		return
	}
	if why != "interrupted" {
		// Said here, whatever the verdict: if the agent had already exited, the loss is still
		// worth knowing, and anything the agent left running was stopped with the tree.
		w.logf("whisper: %s, so the agent's tree was stopped (it is never left running unfiltered)", why)
	}
	w.why, w.code = why, code
}

// finish is called once the agent's process has exited with exitCode. It stops the watch, waits
// until no check is in flight, and returns why the CLI ended the agent: empty when the agent's own
// exit came first. A check in flight is a call to the local filter engine, so the wait is as long
// as that call; the agent cannot outlive the CLI meanwhile, because its job dies with the CLI.
func (w *agentWatch) finish(exitCode uint32) string {
	close(w.stop)
	<-w.stopped
	if w.why == "" || exitCode != w.code {
		return ""
	}
	return w.why
}
