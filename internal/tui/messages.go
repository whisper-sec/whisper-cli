// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package tui is the full-screen Bubble Tea front-end of whisper-cli v2: a btop/k9s-
// grade dashboard to manage AND watch agents. It reuses internal/client for every
// control-plane call and internal/model for the view data, so the TUI and the
// scriptable Cobra surface share ONE implementation (DRY).
package tui

import (
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// --- async result messages (delivered to Update from tea.Cmds / the stream goroutine) ---

// fleetMsg carries the result of an op:list (+ logs/stream union) fleet refresh.
type fleetMsg struct {
	agents []model.Agent
	err    error
}

// agentDetailMsg carries an op:agent detail for the selected agent.
type agentDetailMsg struct {
	key   string // the agent Key() this detail is for (guards against a stale select)
	agent model.Agent
	err   error
}

// logsMsg carries the result of an op:logs query (the LOGS view + monitor backfill).
type logsMsg struct {
	events []model.Event
	token  int // the request token, so a stale reply is dropped
	err    error
}

// policyMsg carries the current op:policy (read-back) result.
type policyMsg struct {
	rows []policyRow
	err  error
}

// writeResultMsg is the generic result of a write op (create/kill/connect/policy-set).
type writeResultMsg struct {
	op      string
	env     *client.Envelope
	summary map[string]any // the first result row, column-keyed (for the result card)
	err     error
}

// toastMsg shows a transient status line (an error detail or a success note).
type toastMsg struct {
	text  string
	isErr bool
}

// tickMsg drives the 4Hz sample-and-render cadence (sparklines, clocks, the live feed).
type tickMsg time.Time

// streamEventMsg is one decoded live event from the SSE goroutine (step C wires the
// goroutine; the type lives here so the always-on monitor panel can already fold it).
type streamEventMsg struct {
	event model.Event
}

// streamStateMsg reports the monitor connection state (connected / reconnecting / poll).
type streamStateMsg struct {
	state monitorState
	err   error
}

// monitorBackfillMsg seeds the live feed from an op:logs query on MONITOR enter (the
// hybrid §6.4: paint history, then tail the stream on top). token drops a stale reply.
type monitorBackfillMsg struct {
	events []model.Event
	token  int
	err    error
}

// monitorPollMsg carries an op:logs poll result used as the SSE fallback while the
// stream is down (drop/503). Only rows newer than the last-seen ts are folded.
type monitorPollMsg struct {
	events []model.Event
	err    error
}

// pollFireMsg is the re-arm tick for the poll fallback: it asks Update to issue a fresh
// op:logs poll (only while the stream is still down). addr narrows to the focused /128.
type pollFireMsg struct {
	addr string
}

// streamRestartMsg re-arms the SSE goroutine after a narrow change (restartStreamNarrowed
// cancels the old one, waits briefly for the token to free, then this re-starts it).
type streamRestartMsg struct{}
