// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// mode is one of the five top-level views (the tab bar).
type mode int

const (
	modeAgents mode = iota
	modeMonitor
	modeLogs
	modePolicy
	modeConfig
)

var modeNames = []string{"AGENTS", "MONITOR", "LOGS", "POLICY", "CONFIG"}

// overlay is a modal/palette state stacked above the active view.
type overlay int

const (
	overlayNone overlay = iota
	overlayPalette
	overlayHelp
	overlayCreate
	overlayKill
	overlayConnect
	overlayDrill
	overlayResult
)

// Options configures a TUI run (resolved once in cmd/whisper).
type Options struct {
	Client     *client.Client
	Tenant     string // best-effort tenant handle for the header (opaque t<sha256>)
	Node       string // emitting node hint (e.g. "ns1"); cosmetic
	ThemeName  theme.Name
	NoColor    bool
	Light      bool
	StartAgent string // optional /128 to focus the monitor on at launch
	StartOnMon bool   // open straight on the MONITOR tab (whisper monitor <addr>)
	Version    string
}

// App is the root Bubble Tea model. It holds the whole TUI state and folds every
// message — key, resize, async result, stream event, tick — into a re-render.
type App struct {
	opts   Options
	client *client.Client
	th     *theme.Theme

	width, height int
	ready         bool

	mode    mode
	overlay overlay

	// fleet + selection
	agents   []model.Agent
	selected int // index into agents
	loading  bool
	lastErr  string

	// per-view models
	agentsView *agentsView
	logsView   *logsView
	policyView *policyView
	configView *configView
	monitorVw  *monitorView

	// overlays
	palette *palette
	create  *createForm
	kill    *killForm
	connect *connectForm
	drill   string // pretty-JSON for the drill / result card
	result  string

	// always-on live monitor (the bottom panel + the MONITOR view share this state)
	feed       *feedRing
	join       *joinCache
	stream     monitorState
	source     feedSource // the data path currently filling the feed (backfill/live/poll)
	paused     bool
	hbSeen     bool
	streamMu   chan struct{} // a 1-buffered token guarding a single stream goroutine
	streamAddr string        // the /128 the stream is currently narrowed to ("" = tenant-wide)

	// hybrid backfill/poll bookkeeping (the §6.4 pattern)
	backfillToken int   // drops a stale backfill reply after a focus change
	lastEventUS   int64 // newest folded event ts (µs) — dedup for the poll fallback
	bufferedPause int   // events dropped while paused (the "⏸ N buffered" counter)
	hbPulse       int   // heartbeat animation phase (●→◉→●), advanced on the tick

	// toast (transient status)
	toast      string
	toastErr   bool
	toastTicks int

	// tickCount drives the per-second ring advance from the 4Hz render tick.
	tickCount int

	// stream plumbing (step C fully wires the goroutine; the channel + cancel live here)
	streamCancel context.CancelFunc
	streamCh     chan tea.Msg

	quitting bool
}

// New builds the root App from resolved options.
func New(opts Options) *App {
	th := theme.New(opts.ThemeName, opts.NoColor, opts.Light)
	a := &App{
		opts:     opts,
		client:   opts.Client,
		th:       th,
		mode:     modeAgents,
		feed:     newFeedRing(2000),
		join:     newJoinCache(512),
		stream:   streamIdle,
		streamMu: make(chan struct{}, 1),
		loading:  true,
	}
	a.agentsView = newAgentsView(a)
	a.logsView = newLogsView(a)
	a.policyView = newPolicyView(a)
	a.configView = newConfigView(a)
	a.monitorVw = newMonitorView(a)
	a.palette = newPalette(a)
	if opts.StartOnMon {
		a.mode = modeMonitor
		if opts.StartAgent != "" {
			a.monitorVw.focused = opts.StartAgent
		}
	}
	return a
}

// Init kicks off the first fleet load, the render tick, and (deferred to step C) the
// live stream. Returning a batch keeps the UI responsive from frame one.
func (a *App) Init() tea.Cmd {
	return tea.Batch(
		loadFleet(a.client),
		loadPolicy(a.client),
		tick(),
		a.startStream(),
	)
}

// Update is the Elm reducer: it folds each message and returns the next command.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		a.ready = true
		a.layout()
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(m)

	case tea.MouseMsg:
		return a.handleMouse(m)

	case tickMsg:
		a.onTick()
		return a, tick()

	case fleetMsg:
		a.loading = false
		if m.err != nil {
			a.setToast(friendlyErr(m.err), true)
			return a, nil
		}
		a.mergeFleet(m.agents)
		// Refresh the selected agent's detail.
		if cmd := a.refreshSelectedDetail(); cmd != nil {
			return a, cmd
		}
		return a, nil

	case agentDetailMsg:
		if m.err == nil {
			a.applyDetail(m)
		}
		return a, nil

	case logsMsg:
		a.logsView.onLogs(m)
		return a, nil

	case policyMsg:
		a.policyView.onPolicy(m)
		return a, nil

	case writeResultMsg:
		return a.onWriteResult(m)

	case streamEventMsg:
		a.onStreamEvent(m.event)
		return a, a.waitStream()

	case streamStateMsg:
		prev := a.stream
		a.stream = m.state
		if m.err != nil {
			a.setToast(friendlyErr(m.err), true)
		}
		// Hybrid §6.4: when the live tail drops to poll (503/EOF), kick the op:logs poll
		// fallback so the picture keeps updating until the SSE reconnects. Only fire on the
		// transition (not every state message) to avoid a poll storm.
		var extra tea.Cmd
		if m.state == streamPoll && prev != streamPoll {
			a.source = srcPoll
			extra = loadMonitorPoll(a.client, a.streamAddr, "-2m")
		}
		return a, tea.Batch(a.waitStream(), extra)

	case monitorBackfillMsg:
		a.onMonitorBackfill(m)
		return a, nil

	case monitorPollMsg:
		return a, a.onMonitorPoll(m)

	case pollFireMsg:
		// Re-arm tick: issue a fresh op:logs poll only while the stream is still down.
		if a.stream == streamConn {
			return a, nil
		}
		return a, loadMonitorPoll(a.client, m.addr, "-2m")

	case streamRestartMsg:
		// Re-arm the SSE goroutine after a narrow change (focus/unfocus).
		return a, a.startStream()

	case toastMsg:
		a.setToast(m.text, m.isErr)
		return a, nil
	}
	return a, nil
}

// View renders the whole frame: header, tab bar, the active view, the always-on
// monitor panel, the footer — with any overlay (palette/modal/help) drawn on top.
func (a *App) View() string {
	if !a.ready || a.width == 0 {
		return "starting whisper…"
	}
	if a.quitting {
		return ""
	}
	// Hard floor: a terminal too small for a usable dashboard gets a clean message,
	// never a broken layout or a crash (Postel: degrade gracefully).
	if a.width < 60 || a.height < 18 {
		msg := fmt.Sprintf("terminal too small\nneed at least 60×18 (have %d×%d)\n\npress q to quit", a.width, a.height)
		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, a.th.Dim.Render(msg))
	}

	body := a.renderBody()
	frame := lipgloss.JoinVertical(lipgloss.Left,
		a.renderHeader(),
		a.renderTabs(),
		body,
		a.renderFooter(),
	)
	if a.overlay != overlayNone {
		return a.renderOverlay(frame)
	}
	return a.th.App.Render(frame)
}

// --- selection + fleet -----------------------------------------------------------

// SelectedAgent returns the currently-selected agent (zero value when the fleet empty).
func (a *App) SelectedAgent() (model.Agent, bool) {
	if a.selected < 0 || a.selected >= len(a.agents) {
		return model.Agent{}, false
	}
	return a.agents[a.selected], true
}

// mergeFleet replaces the fleet from op:list, preserving any stream-discovered agents
// (#112: op:list may miss connect-created agents) and any already-fetched detail.
func (a *App) mergeFleet(fresh []model.Agent) {
	byKey := make(map[string]model.Agent, len(a.agents))
	for _, ex := range a.agents {
		byKey[ex.Key()] = ex
	}
	out := make([]model.Agent, 0, len(fresh))
	seen := make(map[string]bool, len(fresh))
	for _, f := range fresh {
		if ex, ok := byKey[f.Key()]; ok && ex.Detailed {
			// keep enriched counters but refresh summary fields
			ex.Label, ex.State, ex.Created = f.Label, f.State, f.Created
			if f.Contact != "" {
				ex.Contact = f.Contact
			}
			out = append(out, ex)
		} else {
			out = append(out, f)
		}
		seen[f.Key()] = true
	}
	// Retain stream-only agents not present in op:list.
	for _, ex := range a.agents {
		if ex.SeenInStream && !seen[ex.Key()] {
			out = append(out, ex)
		}
	}
	a.agents = out
	if a.selected >= len(a.agents) {
		a.selected = len(a.agents) - 1
	}
	if a.selected < 0 {
		a.selected = 0
	}
	a.agentsView.syncRows()
}

// applyDetail folds an op:agent reply into the matching fleet entry.
func (a *App) applyDetail(m agentDetailMsg) {
	for i := range a.agents {
		if a.agents[i].Key() == m.key {
			a.agents[i] = m.agent
			break
		}
	}
	a.agentsView.syncRows()
}

// refreshSelectedDetail asks for the selected agent's op:agent detail when not yet
// enriched (so the right-hand panel fills in without an extra round-trip per move).
func (a *App) refreshSelectedDetail() tea.Cmd {
	sel, ok := a.SelectedAgent()
	if !ok || sel.Detailed {
		return nil
	}
	return loadAgentDetail(a.client, sel)
}

// upsertStreamAgent records an agent first seen on the live stream / logs so the fleet
// reflects ALL activity, not just the op:list roster (the #112 union).
func (a *App) upsertStreamAgent(addr128, agentID string) {
	if addr128 == "" && agentID == "" {
		return
	}
	key := addr128
	if key == "" {
		key = agentID
	}
	for i := range a.agents {
		if a.agents[i].Key() == key || (addr128 != "" && a.agents[i].Address == addr128) {
			return // already known
		}
	}
	a.agents = append(a.agents, model.Agent{
		ID: agentID, Address: addr128, State: "active", SeenInStream: true,
	})
	a.agentsView.syncRows()
}

// --- toast -----------------------------------------------------------------------

func (a *App) setToast(text string, isErr bool) {
	a.toast, a.toastErr, a.toastTicks = text, isErr, 16 // ~4s at 4Hz
	if isErr {
		a.lastErr = text
	}
}

func (a *App) onTick() {
	if a.toastTicks > 0 {
		a.toastTicks--
		if a.toastTicks == 0 {
			a.toast = ""
		}
	}
	// The render tick fires at 4Hz; advance the per-second sparkline rings once a second
	// (every 4th tick). The always-on feed re-renders each frame from the ring.
	a.tickCount++
	if a.tickCount%4 == 0 {
		a.monitorVw.advance()
		// Heartbeat pulse phase ●→◉→● advances once a second (only when alive).
		if a.stream == streamConn {
			a.hbPulse = (a.hbPulse + 1) % 3
		}
	}
}

// flashTicks is how many 4Hz ticks a freshly-arrived row stays highlighted (~400ms).
const flashTicks = 2

// isFlashing reports whether an event arrived recently enough to still flash-in. A
// backfill/poll row (flashTick 0) never flashes; only the live tail does (motion only for
// genuinely-new activity, never a re-render artefact).
func (a *App) isFlashing(e model.Event) bool {
	ft := e.FlashTick()
	if ft <= 0 {
		return false
	}
	return a.tickCount-ft >= 0 && a.tickCount-ft <= flashTicks
}

// friendlyErr renders an error as its most helpful single line.
func friendlyErr(err error) string {
	if pe, ok := client.AsProblem(err); ok {
		return pe.Error()
	}
	return err.Error()
}
