// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// startStream launches the long-lived SSE reader goroutine and returns a Cmd that waits
// for its first message. The goroutine decodes each live event, normalises it to a
// model.Event, and pushes it on a buffered channel; Update drains the channel via
// waitStream (one message → one fold → re-arm). On a drop/503 it reconnects with
// backoff (the hybrid §6.4 robustness pattern; the op:logs poll fallback is layered in
// step C). ctx-cancel on quit tears the goroutine down cleanly.
//
// This wires the ALWAYS-ON live panel for Step B; step C extends it with the op:logs
// backfill, the per-agent narrow, and the poll fallback.
func (a *App) startStream() tea.Cmd {
	if a.client == nil {
		return nil
	}
	// Guard: only one stream goroutine at a time (the 1-token channel). If the previous
	// goroutine hasn't released yet (a slow teardown after a narrow change), don't bind to
	// its soon-to-close channel — retry the re-arm shortly so the restart always lands.
	select {
	case a.streamMu <- struct{}{}:
	default:
		return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return streamRestartMsg{} })
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.streamCancel = cancel
	a.streamCh = make(chan tea.Msg, 256)
	ch := a.streamCh
	cl := a.client
	// Narrow to the focused /128 when set (server-side pin, §6.1); else the launch hint.
	if a.streamAddr == "" {
		a.streamAddr = a.opts.StartAgent
	}
	narrow := a.streamAddr

	go func() {
		// On exit: release the single-stream token AND close this goroutine's own channel.
		// Each goroutine is the sole sender on its `ch` (created fresh above, captured by
		// value), so closing it here is safe — and it unblocks any pending waitStream still
		// reading the OLD channel after a restart (it gets ok=false → streamIdle), which
		// prevents a leaked, forever-blocked tea.Cmd per focus change. `send` already guards
		// on ctx.Done, so no send races the close.
		defer func() { close(ch); <-a.streamMu }()
		backoff := time.Second
		lastStatus := 0 // last surfaced non-503 problem status (toast once, not per retry)
		for {
			if ctx.Err() != nil {
				return
			}
			send(ch, ctx, streamStateMsg{state: streamRetry})
			err := cl.StreamMonitor(ctx, narrow, func(ev client.MonitorEvent) {
				send(ch, ctx, streamEventMsg{event: model.FromStream(ev)})
			})
			if ctx.Err() != nil {
				return
			}
			// The stream ended (EOF, a 503 subscriber-cap, a 404/401, a transport
			// error). ALWAYS drop to the op:logs poll fallback so the picture keeps
			// updating — fail OPEN, never a hard stop — and surface a non-503 error
			// once (not every retry) so a deterministic failure is never silent.
			st := streamStateMsg{state: streamPoll}
			if pe, ok := client.AsProblem(err); ok && pe.Status != 503 && pe.Status != lastStatus {
				st.err, lastStatus = pe, pe.Status
			}
			send(ch, ctx, st)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
	}()

	return a.waitStream()
}

// waitStream returns a Cmd that blocks on the next stream message (event or state) and
// delivers it to Update. It re-arms itself after each message so the stream keeps
// flowing without busy-looping the UI thread.
func (a *App) waitStream() tea.Cmd {
	ch := a.streamCh
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return streamStateMsg{state: streamIdle}
		}
		return msg
	}
}

// stopStream cancels the stream goroutine (called on quit).
func (a *App) stopStream() {
	if a.streamCancel != nil {
		a.streamCancel()
		a.streamCancel = nil
	}
}

// restartStreamNarrowed re-points the live SSE stream at a new /128 narrow ("" =
// tenant-wide). It cancels the running goroutine and re-arms a fresh one after a short
// delay (giving the old goroutine's `defer <-streamMu` time to release the single-stream
// token, so the guard in startStream lets the new one through). A no-op when the narrow is
// unchanged, so a redundant focus doesn't churn the connection.
func (a *App) restartStreamNarrowed(addr string) tea.Cmd {
	if addr == a.streamAddr {
		return nil
	}
	a.streamAddr = addr
	a.stopStream()
	a.source = srcNone
	// Brief delay so the cancelled goroutine releases the streamMu token before we re-arm.
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return streamRestartMsg{} })
}

// send pushes a message on the buffered channel, dropping it if the channel is full or
// the context is done (drop-on-full: the UI never blocks the reader, the reader never
// blocks on a slow UI).
func send(ch chan tea.Msg, ctx context.Context, msg tea.Msg) {
	select {
	case ch <- msg:
	case <-ctx.Done():
	default:
		// full — drop (the ring buffer in the UI already bounds memory)
	}
}
