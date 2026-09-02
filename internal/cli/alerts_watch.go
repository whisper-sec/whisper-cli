// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/alerts"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// alerts_watch.go is the live tail. Almost no security product has one, and a terminal is
// where an operator already lives, so this is modelled on the two tails they already
// trust: journalctl -f and kubectl get -w.
//
// Three decisions carry it.
//
// The first poll is a BASELINE, not news. A tail that opened by printing the whole
// standing book as if it had just happened would be the one thing a tail must not do.
//
// It emits on a STATE change and never on a severity change. Severity is derived and will
// move as the graph improves; a feed that emitted on it would get noisier every time our
// intelligence got better. The single exception is a promotion, which is the one raise the
// design lets cross a lane boundary on its own.
//
// And it proves it is alive on a quiet hour, because most hours are quiet. Every heartbeat
// interval, whether or not anything happened, it writes one line to stderr carrying the
// denominators: how many endpoints reported, what is standing, and whether any stream
// failed to answer. A tail that prints nothing for an hour and a tail whose process died
// forty minutes ago look identical, and that is the same comfortable lie as a blank feed.

const (
	// defaultWatchInterval is how often the standing queue is re-read. The read is an
	// in-memory fold on the plane, so this is cheap; it is not set lower because a change
	// that matters is not measured in seconds and a tighter loop would only add noise.
	defaultWatchInterval = 20 * time.Second
	// defaultWatchHeartbeat is how often a quiet watch proves it is alive.
	defaultWatchHeartbeat = 15 * time.Minute
	// minWatchInterval is the floor. Anything faster is a poll loop against a shared
	// control plane, not a watch.
	minWatchInterval = 5 * time.Second
)

func newAlertsWatchCmd(f *alertFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch [target]",
		Short: "Tail the queue live, and prove it is still alive when it is quiet",
		Long: "Follow the standing queue. One line per change, as it happens.\n\n" +
			"The first read is a baseline, not news, so opening a watch never replays what was\n" +
			"already true. After that you see a condition opening, being taken by somebody,\n" +
			"being released, being severed, moving UP a lane, or no longer standing. You never\n" +
			"see a score move: severity is derived and shifts as the graph learns, and a tail\n" +
			"that emitted on that would get louder every time we got better.\n\n" +
			"Most hours nothing happens, so every heartbeat interval this writes one line to\n" +
			"stderr with the denominators - endpoints reporting, conditions standing, streams\n" +
			"that did not answer. A silent tail and a dead tail must not look the same.\n\n" +
			"Piped, it writes NDJSON: one compact JSON object per change, on stdout, with the\n" +
			"heartbeats and the commentary on stderr where they will not pollute it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			return runAlertsWatch(cmd.Context(), f, target)
		},
	}
	cmd.Flags().DurationVar(&f.interval, "interval", defaultWatchInterval, "how often to re-read the queue")
	cmd.Flags().DurationVar(&f.heartbeat, "heartbeat", defaultWatchHeartbeat,
		"how often a quiet watch proves it is alive (0 disables it)")
	return cmd
}

func runAlertsWatch(ctx context.Context, f *alertFlags, target string) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	interval := f.interval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	if interval < minWatchInterval {
		return usageErr("--interval %s is faster than the %s floor - a tighter loop is a poll, not a watch",
			interval, minWatchInterval)
	}
	sel := alerts.ParseSelector(target)
	ndjson := g.jsonOut || !stdoutIsTTY()

	cx, cancel := context.WithCancel(ctx)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		cancel()
	}()

	w := &watcher{
		client:   c,
		flags:    f,
		sel:      sel,
		ndjson:   ndjson,
		out:      os.Stdout,
		err:      os.Stderr,
		interval: interval,
		beat:     f.heartbeat,
	}
	return w.run(cx)
}

// watcher holds the loop's state: the previous snapshot, whether the last read failed, and
// when we last told the operator we were alive.
type watcher struct {
	client   *client.Client
	flags    *alertFlags
	sel      alerts.Selector
	ndjson   bool
	out      io.Writer
	err      io.Writer
	interval time.Duration
	beat     time.Duration

	prev     alerts.Snapshot
	failing  bool
	lastBeat time.Time
	changes  int
}

func (w *watcher) run(ctx context.Context) error {
	w.poll(ctx, true)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// A clean stop is a success. Say how long we watched and what we saw, so a
			// terminal that has scrolled still ends with the summary.
			fmt.Fprintf(w.err, "\nwhisper: stopped watching after %d change(s)\n", w.changes)
			return nil
		case <-ticker.C:
			w.poll(ctx, false)
		}
	}
}

// poll performs one read and emits whatever moved. It NEVER returns an error: a watch that
// exited on a transport blip would be a watch nobody could leave running, which is the same
// as not having one. A failure is announced once, on the transition into failing, and the
// recovery is announced too - because "it went quiet" and "it stopped being able to look"
// have to be different lines on the screen.
func (w *watcher) poll(ctx context.Context, first bool) {
	need := wanted{standing: true, endpoints: true, trail: true}
	if first || w.dueForBeat() {
		need.coverage = true
	}
	b := readBook(ctx, w.client, need, w.flags.limit)
	if ctx.Err() != nil {
		return
	}
	opt := renderOptions(w.flags, false)

	if bad := b.Incomplete(); len(bad) > 0 {
		if !w.failing {
			w.failing = true
			fmt.Fprintf(w.err, "whisper: %s did not answer at %s - still watching, and NOT reporting quiet\n",
				streamNames(bad), time.Now().UTC().Format("15:04:05Z"))
		}
		// A failed read must never become a diff. Treating "we could not look" as "nothing
		// is there" would emit a resolve for every standing condition.
		return
	}
	if w.failing {
		w.failing = false
		fmt.Fprintf(w.err, "whisper: reads recovered at %s\n", time.Now().UTC().Format("15:04:05Z"))
	}

	if !w.sel.Empty() {
		var kept []alerts.Row
		for _, r := range b.Rows {
			if w.sel.Matches(r, b.EndpointFor(r)) {
				kept = append(kept, r)
			}
		}
		b.Rows = kept
	}

	next := alerts.Snap(b, opt)
	if first {
		w.prev = next
		w.baseline(b, opt)
		w.lastBeat = time.Now()
		return
	}
	for _, ch := range alerts.Diff(w.prev, next, time.Now()) {
		w.emit(ch)
		w.changes++
	}
	w.prev = next
	if w.dueForBeat() {
		w.heartbeat(b, opt)
		w.lastBeat = time.Now()
	}
}

func (w *watcher) dueForBeat() bool {
	if w.beat <= 0 {
		return false
	}
	return time.Since(w.lastBeat) >= w.beat
}

// baseline is what a watch says when it opens: what is true right now, so the operator
// knows what the tail is measured against.
func (w *watcher) baseline(b *alerts.Book, opt alerts.Options) {
	fmt.Fprintf(w.err, "whisper: watching %s, re-reading every %s\n", controlHost(), w.interval)
	fmt.Fprintf(w.err, "whisper: baseline is %d standing condition(s); nothing below this line was already true\n",
		len(b.Rows))
	alerts.RenderQuiet(w.err, b, opt)
}

// heartbeat is the line that makes a quiet watch trustworthy. It carries the denominators,
// never a bare reassurance: a tick with no numbers behind it is exactly the sentence a
// breach review quotes back.
func (w *watcher) heartbeat(b *alerts.Book, opt alerts.Options) {
	c := b.Coverage
	stamp := time.Now().UTC().Format("15:04:05Z")
	if !c.Present {
		fmt.Fprintf(w.err, "-- %s still watching; %d standing, and the coverage read did not answer\n",
			stamp, len(b.Rows))
		return
	}
	fmt.Fprintf(w.err, "-- %s still watching; %d standing, heard from %d of %d endpoints, %d change(s) so far\n",
		stamp, len(b.Rows), c.HeardFrom(), c.Endpoints, w.changes)
}

// emit writes one change: NDJSON on a pipe, one aligned line on a terminal.
func (w *watcher) emit(ch alerts.Change) {
	if w.ndjson {
		enc := json.NewEncoder(w.out)
		_ = enc.Encode(ch)
		return
	}
	fmt.Fprintf(w.out, "%s  %-9s %-28s %s\n",
		ch.At.UTC().Format("15:04:05Z"), ch.Kind, ch.Ref, ch.Line)
}
