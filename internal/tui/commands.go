// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// callTimeout bounds every non-streaming control call from the TUI (never block the UI).
const callTimeout = 20 * time.Second

// tickInterval is the 4Hz sample-and-render cadence (the design's monitor tick).
const tickInterval = 250 * time.Millisecond

// tick schedules the next render tick.
func tick() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// loadFleet runs op:list and maps rows to Agents (newest first). Per the caveat
// the list may miss connect-created agents; the app unions these with agents seen in
// the live stream, so a fail-open empty list is fine here (never an error to the user).
func loadFleet(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		env, err := c.Agents(ctx, "list", map[string]any{"kind": "agents"})
		if err != nil {
			return fleetMsg{err: err}
		}
		if !env.Ok {
			return fleetMsg{err: envErr(env)}
		}
		var agents []model.Agent
		for _, rec := range env.Result.Records() {
			a := model.AgentFromListItem(rec)
			if a.Key() == "" {
				continue
			}
			agents = append(agents, a)
		}
		sort.SliceStable(agents, func(i, j int) bool { return agents[i].Created > agents[j].Created })
		return fleetMsg{agents: agents}
	}
}

// loadAgentDetail runs op:agent for the selected agent (by address when known, else id).
// Reads fail OPEN per the contract: a storage hiccup yields zeroed counters, not a 500.
func loadAgentDetail(c *client.Client, a model.Agent) tea.Cmd {
	key := a.Key()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		args := map[string]any{}
		if a.Address != "" {
			args["address"] = a.Address
		} else {
			args["agent"] = a.ID
		}
		env, err := c.Agents(ctx, "agent", args)
		if err != nil {
			return agentDetailMsg{key: key, err: err}
		}
		if !env.Ok {
			return agentDetailMsg{key: key, err: envErr(env)}
		}
		recs := env.Result.Records()
		out := a
		if len(recs) > 0 {
			out.MergeDetail(recs[0])
		}
		return agentDetailMsg{key: key, agent: out}
	}
}

// loadLogs runs op:logs with the given filters and maps rows to unified Events. token
// lets the caller drop a stale reply after the filter changed.
func loadLogs(c *client.Client, args map[string]any, token int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		env, err := c.Agents(ctx, "logs", args)
		if err != nil {
			return logsMsg{token: token, err: err}
		}
		if !env.Ok {
			return logsMsg{token: token, err: envErr(env)}
		}
		var evs []model.Event
		for _, rec := range env.Result.Records() {
			evs = append(evs, model.FromLogRecord(rec))
		}
		return logsMsg{events: evs, token: token}
	}
}

// loadMonitorBackfill seeds the live monitor from op:logs on enter (the hybrid §6.4:
// paint the recent history, then tail the SSE on top). agent narrows to one /128 when
// focused; from is the window (e.g. "-15m"). Reads fail OPEN — an empty backfill is fine,
// never an error to the operator.
func loadMonitorBackfill(c *client.Client, agent, from string, token int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		args := map[string]any{"limit": 500, "from": from}
		if agent != "" {
			args["agent"] = agent
		}
		env, err := c.Agents(ctx, "logs", args)
		if err != nil {
			return monitorBackfillMsg{token: token, err: err}
		}
		if !env.Ok {
			return monitorBackfillMsg{token: token, err: envErr(env)}
		}
		var evs []model.Event
		for _, rec := range env.Result.Records() {
			evs = append(evs, model.FromLogRecord(rec))
		}
		return monitorBackfillMsg{events: evs, token: token}
	}
}

// loadMonitorPoll runs the op:logs fallback while the SSE stream is down. It asks for a
// short recent window; Update folds only rows newer than the last-seen ts (dedup). agent
// narrows when focused. Fail-open: an error just leaves the feed as-is.
func loadMonitorPoll(c *client.Client, agent, from string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		args := map[string]any{"limit": 200, "from": from}
		if agent != "" {
			args["agent"] = agent
		}
		env, err := c.Agents(ctx, "logs", args)
		if err != nil {
			return monitorPollMsg{err: err}
		}
		if !env.Ok {
			return monitorPollMsg{err: envErr(env)}
		}
		var evs []model.Event
		for _, rec := range env.Result.Records() {
			evs = append(evs, model.FromLogRecord(rec))
		}
		return monitorPollMsg{events: evs}
	}
}

// loadPolicy reads the current policy back (op:policy with no args).
func loadPolicy(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		env, err := c.Agents(ctx, "policy", map[string]any{})
		if err != nil {
			return policyMsg{err: err}
		}
		if !env.Ok {
			return policyMsg{err: envErr(env)}
		}
		var rows []policyRow
		for _, rec := range env.Result.Records() {
			rows = append(rows, policyRow{
				Key:   asStr(rec["key"]),
				Value: asStr(rec["value"]),
			})
		}
		return policyMsg{rows: rows}
	}
}

// runWrite executes any write op (create/kill/connect/policy-set/token) and returns the
// generic write result. The summary is the first result row, column-keyed, for the
// result card.
func runWrite(c *client.Client, op string, args map[string]any) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		env, err := c.Agents(ctx, op, args)
		if err != nil {
			return writeResultMsg{op: op, err: err}
		}
		if !env.Ok {
			return writeResultMsg{op: op, env: env, err: envErr(env)}
		}
		var summary map[string]any
		if recs := env.Result.Records(); len(recs) > 0 {
			summary = recs[0]
		}
		return writeResultMsg{op: op, env: env, summary: summary}
	}
}

// envErr surfaces the envelope's RFC-7807 problem as an error (helpful detail, never
// opaque). A nil/ok envelope yields nil.
func envErr(env *client.Envelope) error {
	if env == nil {
		return &client.ProblemError{Status: 502, Detail: "empty control-plane reply"}
	}
	if env.Ok {
		return nil
	}
	if env.Err != nil {
		return env.Err
	}
	return &client.ProblemError{Status: env.Status, Detail: "control plane reported failure"}
}

// asStr renders a decoded JSON value as a display string (mirrors model.asString).
func asStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case json.Number:
		return x.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}
