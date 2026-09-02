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

// mode is one of the six top-level views (the tab bar). EXPLORE leads the order as tab 1
// the graph explorer is the showpiece; it opens on whisper.security); AGENTS is
// the merged operational view (fleet + the selected agent's live monitor in one panel)
// and remains the LAUNCH view (bare `whisper` lands on your agents; `whisper explore`
// lands on tab 1). GRAPH is the live, self-expanding agent-activity graph fed by the
// monitor stream. CONFIG stays last. Every dispatch site references modes BY NAME, so
// this const block is the single place the order lives.
type mode int

const (
	modeExplore mode = iota
	modeAgents
	modeGraph
	modeLogs
	modePolicy
	modeConfig
)

var modeNames = []string{"EXPLORE", "AGENTS", "GRAPH", "LOGS", "POLICY", "CONFIG"}

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
	StartOnMon bool   // launch with the merged dashboard focused on StartAgent (whisper monitor <addr>)

	StartOnExplore bool   // open straight on the EXPLORE tab (whisper explore [node])
	StartNode      string // optional node to land the explorer on (the fetch is not wired yet)

	Version string
}

// App is the root Bubble Tea model. It holds the whole TUI state and folds every
// message - key, resize, async result, stream event, tick - into a re-render.
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
	exploreVw  *exploreView
	graphVw    *graphView

	// overlays
	palette *palette
	create  *createForm
	kill    *killForm
	connect *connectForm
	drill   string // pretty-JSON for the drill / result card
	result  string

	// always-on live monitor (the merged AGENTS panel + the GRAPH view share this state)
	feed       *feedRing
	join       *joinCache
	lgraph     *liveGraph // the self-expanding agent-activity graph, fed from the same fold
	stream     monitorState
	source     feedSource // the data path currently filling the feed (backfill/live/poll)
	paused     bool
	hbSeen     bool
	streamMu   chan struct{} // a 1-buffered token guarding a single stream goroutine
	streamAddr string        // the /128 the stream is currently narrowed to ("" = tenant-wide)

	// hybrid backfill/poll bookkeeping (the pattern)
	backfillToken int   // drops a stale backfill reply after a focus change
	lastEventUS   int64 // newest folded event ts (µs) - dedup for the poll fallback

	// lastActiveUS is each agent's newest folded-event timestamp (µs), keyed exactly
	// like the monitor rings (Addr128, falling back to the agent id - Agent.Key()).
	// It drives the fleet's last-active sort: fresh traffic moves an agent up.
	// Derived from data we already fold - never fetched (self-contained by design).
	// fleetDirty coalesces the re-sort to the 4Hz tick (never a rebuild per event).
	lastActiveUS  map[string]int64
	fleetDirty    bool
	bufferedPause int  // events dropped while paused (the "⏸ N buffered" counter)
	hbPulse       int  // heartbeat animation phase (●→◉→●), advanced on the tick
	pollArmed     bool // ONE poll chain at a time - N failed reconnects must not stack N pollers

	// toast (transient status)
	toast      string
	toastErr   bool
	toastTicks int

	// tickCount drives the per-second ring advance from the 4Hz render tick.
	tickCount int

	// live-session counters: events folded from the LIVE tail this run (backfill and
	// poll replays excluded, so a focus-change re-seed can never double-count them).
	liveDNS, liveConn, liveBlocked int64

	// stream plumbing (step C fully wires the goroutine; the channel + cancel live here)
	streamCancel context.CancelFunc
	streamCh     chan tea.Msg

	quitting bool
}

// New builds the root App from resolved options.
func New(opts Options) *App {
	th := theme.New(opts.ThemeName, opts.NoColor, opts.Light)
	a := &App{
		opts:         opts,
		client:       opts.Client,
		th:           th,
		mode:         modeAgents,
		feed:         newFeedRing(2000),
		join:         newJoinCache(512),
		lgraph:       newLiveGraph(),
		stream:       streamIdle,
		streamMu:     make(chan struct{}, 1),
		lastActiveUS: map[string]int64{},
		loading:      true,
	}
	a.agentsView = newAgentsView(a)
	a.logsView = newLogsView(a)
	a.policyView = newPolicyView(a)
	a.configView = newConfigView(a)
	a.monitorVw = newMonitorView(a)
	a.exploreVw = newExploreView(a)
	a.graphVw = newGraphView(a)
	a.palette = newPalette(a)
	if opts.StartOnMon && opts.StartAgent != "" {
		// `whisper monitor <addr>` lands on the merged dashboard already watching that
		// agent (the SSE narrows to it via streamAddr; the backfill narrows via focused).
		a.monitorVw.focused = opts.StartAgent
	}
	if opts.StartOnExplore {
		a.mode = modeExplore
	}
	return a
}

// Init kicks off the first fleet load, the render tick, the live stream, and the
// monitor's op:logs backfill (the merged AGENTS dashboard shows the live monitor from
// frame one, so its history seed belongs at launch, not behind a tab switch). A launch
// straight onto EXPLORE (whisper explore [node]) also fires its first live land here,
// since onEnterMode only runs on a tab SWITCH.
func (a *App) Init() tea.Cmd {
	cmds := []tea.Cmd{
		loadFleet(a.client),
		loadPolicy(a.client),
		tick(),
		a.startStream(),
		a.monitorVw.onEnter(),
	}
	if a.mode == modeExplore {
		cmds = append(cmds, a.exploreVw.onEnter())
	}
	return tea.Batch(cmds...)
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
		return a, tea.Batch(a.waitStream(), a.graphEnrichCmd())

	case streamStateMsg:
		prev := a.stream
		a.stream = m.state
		if m.err != nil {
			a.setToast(friendlyErr(m.err), true)
		}
		// The hybrid feed: when the live tail drops to poll (503/EOF/404), kick the op:logs
		// poll fallback so the picture keeps updating until the SSE reconnects. pollArmed
		// keeps it to ONE chain - the reconnect loop oscillates retry→poll, and firing on
		// every oscillation would stack N concurrent pollers.
		_ = prev
		var extra tea.Cmd
		if m.state == streamPoll && !a.pollArmed {
			a.pollArmed = true
			a.source = srcPoll
			extra = loadMonitorPoll(a.client, a.streamAddr, "-2m")
		}
		return a, tea.Batch(a.waitStream(), extra)

	case monitorBackfillMsg:
		a.onMonitorBackfill(m)
		return a, a.graphEnrichCmd()

	case monitorPollMsg:
		return a, tea.Batch(a.onMonitorPoll(m), a.graphEnrichCmd())

	case lgAsnMsg:
		// One IP's ASN enrichment landed (or honestly missed): fold it into the live
		// graph and drain the next queued lookup (bounded in-flight, keyed only).
		a.lgraph.onASN(m)
		return a, a.graphEnrichCmd()

	case pollFireMsg:
		// Re-arm tick: issue a fresh op:logs poll only while the stream is still down.
		if a.stream == streamConn {
			a.pollArmed = false
			return a, nil
		}
		return a, loadMonitorPoll(a.client, m.addr, "-2m")

	case streamRestartMsg:
		// Re-arm the SSE goroutine after a narrow change (focus/unfocus).
		return a, a.startStream()

	case toastMsg:
		a.setToast(m.text, m.isErr)
		return a, nil

	// EXPLORE async replies: each folds into exploreVw, which drops any reply whose
	// focusToken is stale (the fast-walk-flurry discipline: never paint a node you
	// already left).
	case focusMsg:
		return a, a.exploreVw.onFocus(m)
	case edgesMsg:
		return a, a.exploreVw.onEdges(m)
	case neighborsMsg:
		return a, a.exploreVw.onNeighbors(m)
	case enrichMsg:
		return a, a.exploreVw.onEnrich(m)
	case verbResultMsg:
		return a, a.exploreVw.onVerbResult(m)
	case searchMsg:
		_ = m // reserved for the JUMP match list
		return a, nil
	}
	// Anything else while a form overlay is open belongs to the form: huh drives its
	// field focus, validation, and group advance through its OWN messages (returned as
	// commands from form.Update/Init) - swallowing them here freezes the form with a
	// dead Enter/Tab. Forward them, and the form comes alive.
	switch a.overlay {
	case overlayCreate:
		return a.updateCreate(msg)
	case overlayKill:
		return a.updateKill(msg)
	case overlayConnect:
		return a.updateConnect(msg)
	case overlayPalette:
		// The palette's textinput needs its cursor-blink messages too.
		var cmd tea.Cmd
		a.palette.input, cmd = a.palette.input.Update(msg)
		return a, cmd
	}
	return a, nil
}

// View renders the whole frame: header, tab bar, the active view, the always-on
// monitor panel, the footer - with any overlay (palette/modal/help) drawn on top.
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
	// Belt-and-braces: clamp the frame to the terminal so a width-math slip in any one
	// view degrades to a clipped edge, never a scrolled/wrapped full-screen collapse
	// Conservative in what we emit.
	return a.th.App.MaxWidth(a.width).MaxHeight(a.height).Render(frame)
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
// (op:list may miss connect-created agents) and any already-fetched detail.
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
	a.deriveTenant()
	a.agentsView.syncRows()
}

// deriveTenant backfills the header's tenant handle from an agent fqdn
// (<agent>.<t-handle>.agents.<zone>) when the launch-time best-effort lookup came
// back empty - the fleet we already hold IS the answer (derive, don't fetch).
func (a *App) deriveTenant() {
	if a.opts.Tenant != "" {
		return
	}
	for _, ag := range a.agents {
		if t := model.TenantFromFQDN(ag.FQDN); t != "" {
			a.opts.Tenant = t
			return
		}
	}
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
// reflects ALL activity, not just the op:list roster (the union).
func (a *App) upsertStreamAgent(addr128, agentID string) {
	if addr128 == "" && agentID == "" {
		return
	}
	key := addr128
	if key == "" {
		key = agentID
	}
	for i := range a.agents {
		// Match on EITHER handle: an event that carries only the agent id must still
		// collapse onto a roster entry keyed by its /128 (else every id-only event
		// minted a phantom "(no /128)" duplicate row).
		if a.agents[i].Key() == key ||
			(addr128 != "" && a.agents[i].Address == addr128) ||
			(agentID != "" && a.agents[i].ID == agentID) {
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
	// A fresh last-active watermark re-sorts the fleet at tick cadence: the list
	// follows live activity without a per-event table rebuild. syncRows itself honors
	// the freeze toggle, so a frozen list stays put even while watermarks advance.
	if a.fleetDirty {
		a.fleetDirty = false
		a.agentsView.syncRows()
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
