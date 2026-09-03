// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// panel_test.go guards the one property that makes `whisper panel status` worth having: it is
// polled by something nobody is watching closely, so a leg we could not READ must never reach
// the screen as a leg we read and found negative. "Could not ask the service manager" is not
// "stopped". "The echo timed out" is not "your traffic is leaking". A panel that draws the same
// grey dot for both teaches the person to stop believing the green one, and then the whole
// surface is decoration.
//
// The tests below therefore care much less about the happy path than about the three unhappy
// ones, plus the two rules that keep the document honest at rest: no measurement appears unless
// something measured it, and no key value appears at all.

// panelDeadURL refuses instantly on every platform we build for, which is what makes a failed
// leg fast and deterministic here rather than a timeout the test has to wait out.
const panelDeadURL = "http://127.0.0.1:1"

// panelTestKey is deliberately distinctive so the leak assertion can find it anywhere in the
// emitted bytes, at any nesting depth, however it were to be spelled.
const panelTestKey = "whisper_live_paneltestkey_must_never_be_printed"

// panelIsolation points HOME, the key ladder, the session registry and the published path-state
// records at empty temp state, so a developer's real key, real sessions and real tunnels can
// never change what these tests see.
func panelIsolation(t *testing.T) string {
	t.Helper()
	dir := testenv.HermeticHome(t)
	t.Setenv("WHISPER_BEARER", "")
	prevSessions := sessionsDirFn
	sessionsDirFn = func() string { return filepath.Join(dir, "sessions") }
	prevG := g
	// The system-proxy seams are reset here rather than per-test so no test can reach the real
	// network settings of the machine running the suite, and - the one that matters - so the
	// pre-flight's live legs can never make a real HTTP request from a unit test. The default
	// fake refuses at leg 1, which is the cheapest honest answer and touches nothing.
	prevLegs, prevDrive := newSysProxyLegs, systemProxyDrivable
	prevWrite, prevRestore := writeSystemProxyFn, restoreSystemProxyFn
	newSysProxyLegs = func() sysProxyLegs { return &fakeSysProxyLegs{} }
	// The egress reachability probe is reset here for the same reason: it makes two real HTTPS
	// requests to a host that is deliberately NOT ours, and a unit test must never make one. The
	// default answers "nothing was measured", which is the cheapest honest answer and touches
	// nothing; a test that cares installs its own with panelStubReach.
	prevReach := panelReachLeg
	panelReachLeg = func(context.Context, statusSession) panelReach { return panelReach{} }
	t.Cleanup(func() {
		sessionsDirFn = prevSessions
		g = prevG
		newSysProxyLegs, systemProxyDrivable = prevLegs, prevDrive
		writeSystemProxyFn, restoreSystemProxyFn = prevWrite, prevRestore
		panelReachLeg = prevReach
	})
	return dir
}

// panelStubReach installs one scripted pair of reachability observations, and records the
// session it was asked about so a test can prove the leg was actually consulted.
func panelStubReach(t *testing.T, r panelReach) *[]statusSession {
	t.Helper()
	var asked []statusSession
	saved := panelReachLeg
	panelReachLeg = func(_ context.Context, sess statusSession) panelReach {
		asked = append(asked, sess)
		return r
	}
	t.Cleanup(func() { panelReachLeg = saved })
	return &asked
}

// fakeSysProxyLegs is the pre-flight's three measurements, scripted. Every verdict below is
// reached through the REAL sysProxyPreflight against this, so what the tests pin is the decision
// logic and the words it produces, not a re-implementation of them.
type fakeSysProxyLegs struct {
	mu      sync.Mutex
	answers bool
	// egress is consulted per call, so a test can let the pre-flight pass and the dead man fail,
	// which is the exact shape of the failure the dead man exists for.
	egress func(call int) (string, error)
	v4     func() sysProxyV4Leg
	calls  int
}

func (f *fakeSysProxyLegs) ProxyAnswers(int) bool { return f.answers }

func (f *fakeSysProxyLegs) WhisperEgress(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if f.egress == nil {
		return "", errors.New("no egress scripted")
	}
	return f.egress(n)
}

func (f *fakeSysProxyLegs) IPv4Leg(context.Context, string) sysProxyV4Leg {
	if f.v4 == nil {
		return sysProxyV4Leg{}
	}
	return f.v4()
}

// panelStubSysProxyLegs installs one scripted set of measurements for a test.
func panelStubSysProxyLegs(t *testing.T, legs *fakeSysProxyLegs) *fakeSysProxyLegs {
	t.Helper()
	newSysProxyLegs = func() sysProxyLegs { return legs }
	return legs
}

// panelSysProxyMac is a fake Mac's SOCKS setting: what it currently says, and a record of every
// write and restore made against it. It is what turns "restores the EXACT previous state" from a
// claim into an assertion.
type panelSysProxyMac struct {
	mu         sync.Mutex
	current    systemProxyState
	wrote      []int
	restored   []sysProxyPrevious
	writeErr   error
	restoreErr error
}

// install wires the fake Mac into all three platform seams and switches the flow on, so the
// enable path (pre-flight, record, dead man, revert) runs end to end on whatever OS the suite is
// running on. Without this every one of these tests would be a skip on Linux and CI would be
// asserting nothing about the code that took a machine down.
func (m *panelSysProxyMac) install(t *testing.T) *panelSysProxyMac {
	t.Helper()
	systemProxyDrivable = true
	readSaved := readSystemProxyState
	readSystemProxyState = func(livePorts []int) (systemProxyState, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		st := m.current
		st.Supported = true
		st.PointsAtWhisper = systemProxyPointsAtWhisper(st.Host, st.Port, livePorts)
		return st, nil
	}
	writeSystemProxyFn = func(on bool, port int) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.writeErr != nil {
			return m.writeErr
		}
		m.wrote = append(m.wrote, port)
		if on {
			m.current.Enabled, m.current.Host, m.current.Port = true, "127.0.0.1", port
		} else {
			m.current.Enabled = false
		}
		return nil
	}
	restoreSystemProxyFn = func(prev sysProxyPrevious) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.restoreErr != nil {
			return m.restoreErr
		}
		m.restored = append(m.restored, prev)
		m.current.Enabled, m.current.Host, m.current.Port = prev.Enabled, prev.Host, prev.Port
		return nil
	}
	t.Cleanup(func() { readSystemProxyState = readSaved })
	return m
}

func (m *panelSysProxyMac) writes() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int(nil), m.wrote...)
}

func (m *panelSysProxyMac) restores() []sysProxyPrevious {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sysProxyPrevious(nil), m.restored...)
}

// carriesIPv6ButNotIPv4 is the measured failure this whole surface was built for: the egress
// answers on a dual-stack host as the agent's own /128, and an IPv4-only host fails through it
// while the identical request straight from the machine succeeds.
func carriesIPv6ButNotIPv4(addr string) *fakeSysProxyLegs {
	return &fakeSysProxyLegs{
		answers: true,
		egress:  func(int) (string, error) { return addr, nil },
		v4: func() sysProxyV4Leg {
			return sysProxyV4Leg{Host: "api.ipify.org", Tried: true,
				Proxied: errors.New("dial tcp: i/o timeout"), Direct: nil}
		},
	}
}

// panelStubSensor drives the hostSensorStatus seam.
//
// It returns an anonymous struct rather than the endpoint half's own type on purpose. The sensor
// half of this CLI is not part of the source we publish, so this file must not name it - and the
// contract the panel actually depends on is the JSON shape, not the Go type, which is exactly
// what this stub pins.
func panelStubSensor(t *testing.T, state, detail string) {
	t.Helper()
	saved := hostSensorStatus
	hostSensorStatus = func() (any, string) {
		return struct {
			State  string `json:"state"`
			Detail string `json:"detail,omitempty"`
		}{State: state, Detail: detail}, state
	}
	t.Cleanup(func() { hostSensorStatus = saved })
}

// panelStubSystemProxy drives the platform system-proxy reader, so the sentence the panel builds
// from it can be checked on any OS rather than only on a Mac.
func panelStubSystemProxy(t *testing.T, read func(livePorts []int) (systemProxyState, error)) {
	t.Helper()
	saved := readSystemProxyState
	readSystemProxyState = read
	t.Cleanup(func() { readSystemProxyState = saved })
}

// panelStatusJSON runs the REAL command through the REAL root - the argv a person types - and
// returns the decoded document plus the raw bytes. Every remote endpoint is pointed at a refusing
// port, which is the hermetic half; the wiring it proves is the real one.
func panelStatusJSON(t *testing.T, dir string, extra ...string) (map[string]any, string) {
	t.Helper()
	args := append([]string{
		"panel", "status", "--json",
		"--control-url", panelDeadURL + "/api/query",
		"--verify-url", panelDeadURL,
		"--echo-url", panelDeadURL + "/egress-ip",
		"--key-file", filepath.Join(dir, "no-such-key"),
		"--agent-file", filepath.Join(dir, "no-such-agent"),
		"--timeout", "5s",
	}, extra...)

	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetArgs(args)
	var err error
	stdout, _ := captureStd(t, func() { err = root.Execute() })
	if err != nil {
		t.Fatalf("`whisper panel status` must never fail - a panel that errors renders nothing at "+
			"all, which is worse than rendering what it did read: %v", err)
	}
	var doc map[string]any
	if uerr := json.Unmarshal([]byte(stdout), &doc); uerr != nil {
		t.Fatalf("panel status --json must be valid JSON: %v (%q)", uerr, stdout)
	}
	return doc, stdout
}

// panelSub walks into a nested object, failing with a useful message rather than a panic.
func panelSub(t *testing.T, doc map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := doc
	for i, key := range path {
		next, ok := cur[key].(map[string]any)
		if !ok {
			t.Fatalf("%s is missing or is not an object (got %v)", strings.Join(path[:i+1], "."), cur[key])
		}
		cur = next
	}
	return cur
}

// --- 1. the command is reachable, and a typo is not a success --------------------------------

// TestPanel_IsRegisteredAndRefusesAnUnknownSubcommand is the wiring proof. A finished feature
// that can never be reached is the most frequent defect in this tree, so the registration is
// asserted rather than assumed - and so is asParent, without which `whisper panel typo` would
// print help and hand a script exit 0.
func TestPanel_IsRegisteredAndRefusesAnUnknownSubcommand(t *testing.T) {
	var panelCmd *cobra.Command
	for _, c := range NewRootCommand().Commands() {
		if c.Name() == "panel" {
			panelCmd = c
		}
	}
	if panelCmd == nil {
		t.Fatal("`whisper panel` is not registered on the root command; the surface ships unreachable")
	}
	if panelCmd.Annotations[parentAnnotation] != "true" {
		t.Fatal("`whisper panel` is not wired through asParent, so an unknown subcommand would print " +
			"help and exit 0 - a script would carry on as though the command had run")
	}
	have := map[string]bool{}
	for _, c := range panelCmd.Commands() {
		have[c.Name()] = true
	}
	for _, want := range []string{"status", "system-proxy"} {
		if !have[want] {
			t.Fatalf("`whisper panel %s` is not registered", want)
		}
	}

	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	root.SetArgs([]string{"panel", "zzznotacommand"})
	err := root.Execute()
	if err == nil {
		t.Fatal("`whisper panel zzznotacommand` returned no error, so the shell sees exit 0")
	}
	if !strings.Contains(err.Error(), "zzznotacommand") {
		t.Errorf("the error does not name the verb that was not understood: %v", err)
	}
}

// --- 2. the document itself ------------------------------------------------------------------

// TestPanelStatus_EmitsTheWholeDocument pins the contract the panel app is coded against: one
// JSON object, schema 1, with every top-level key and every nested object the app decodes. It is
// the test that fails if a field is renamed or quietly given an omitempty it cannot carry.
func TestPanelStatus_EmitsTheWholeDocument(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, false, nil)

	doc, raw := panelStatusJSON(t, dir)

	if doc["schema"] != float64(panelSchema) {
		t.Fatalf("schema must be %d, got %v", panelSchema, doc["schema"])
	}
	for _, key := range []string{
		"schema", "generated_at", "cli_version", "key", "identity",
		"connection", "egress", "sensor", "whalenet", "errors",
	} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("the top-level key %q is missing from the document:\n%s", key, raw)
		}
	}
	if s, _ := doc["generated_at"].(string); s == "" {
		t.Fatal("generated_at is empty; the panel cannot tell a fresh read from a stuck one")
	}
	if s, _ := doc["cli_version"].(string); s == "" {
		t.Fatal("cli_version is empty")
	}

	// The nested objects the app decodes, each asserted for presence rather than value.
	panelSub(t, doc, "key")
	panelSub(t, doc, "identity", "verify")
	panelSub(t, doc, "connection", "tunnel")
	panelSub(t, doc, "egress", "proxy_apps")
	panelSub(t, doc, "egress", "system_apps", "system_proxy")
	panelSub(t, doc, "whalenet")

	if _, ok := doc["errors"].([]any); !ok {
		t.Fatalf("errors must be an array, never null - an absent array and an empty one are "+
			"different claims: %v", doc["errors"])
	}
	whalenet := panelSub(t, doc, "whalenet")
	if _, ok := whalenet["peers"].([]any); !ok {
		t.Fatalf("whalenet.peers must be an array, never null: %v", whalenet["peers"])
	}
	if _, ok := whalenet["notes"].([]any); !ok {
		t.Fatalf("whalenet.notes must be an array, never null: %v", whalenet["notes"])
	}

	// Nothing is connected in this hermetic run, and that is a read, not a failure.
	conn := panelSub(t, doc, "connection")
	if conn["state"] != panelNotConnected {
		t.Fatalf("with an empty session registry the connection state must be %q, got %v",
			panelNotConnected, conn["state"])
	}
	tunnel := panelSub(t, doc, "connection", "tunnel")
	if tunnel["known"] != false {
		t.Fatalf("nothing published a path-state record, so tunnel.known must be false, got %v", tunnel["known"])
	}
}

// --- 3. the unknown-versus-negative invariant -------------------------------------------------

// TestPanelStatus_AFailedSensorReadIsUnknownNeverStopped is the defect this file exists for, in
// its most expensive form: a service manager that did not answer must not render as a sensor
// that is not running. The remedy for the two is different, and only one of them is alarming.
func TestPanelStatus_AFailedSensorReadIsUnknownNeverStopped(t *testing.T) {
	dir := panelIsolation(t)
	stubProbe(t, false, nil)
	panelStubSensor(t, "unknown", "the service manager did not answer within 3s")

	doc, raw := panelStatusJSON(t, dir)

	sensor := panelSub(t, doc, "sensor")
	if sensor["state"] != panelUnknown {
		t.Fatalf("a sensor read that failed must say %q, got %v", panelUnknown, sensor["state"])
	}
	if sensor["state"] == "stopped" {
		t.Fatal("a failed sensor read was rendered as a stopped sensor")
	}
	if !strings.Contains(raw, "the service manager did not answer") {
		t.Fatalf("the reason the sensor could not be read was dropped:\n%s", raw)
	}
	if !panelErrorsMention(t, doc, "host sensor") {
		t.Fatalf("a failed sensor read must appear in errors, or a panel that renders only the "+
			"error banner shows nothing at all:\n%s", raw)
	}
}

// TestPanelStatus_AFailedSensorReadIsNotProducedByASensorThatIsSimplyStopped is the control for
// the test above. Without it, an implementation that reported "unknown" for everything would
// pass, and the assertion would be worth nothing.
func TestPanelStatus_AStoppedSensorStillReadsAsStopped(t *testing.T) {
	dir := panelIsolation(t)
	stubProbe(t, false, nil)
	panelStubSensor(t, "stopped", "")

	doc, raw := panelStatusJSON(t, dir)

	sensor := panelSub(t, doc, "sensor")
	if sensor["state"] != "stopped" {
		t.Fatalf("a sensor the service manager called stopped must read as stopped, got %v", sensor["state"])
	}
	if panelErrorsMention(t, doc, "host sensor") {
		t.Fatalf("a sensor that was read successfully must not appear in errors:\n%s", raw)
	}
}

// TestPanelStatus_AFailedVerifyIsUnknownNeverUnverified: an unreachable verify endpoint says
// nothing about the identity. Rendering it as `unverified` would turn our own network problem
// into an accusation about the user's agent.
func TestPanelStatus_AFailedVerifyIsUnknownNeverUnverified(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "wireguard"))

	doc, raw := panelStatusJSON(t, dir)

	verify := panelSub(t, doc, "identity", "verify")
	if verify["state"] != panelUnknown {
		t.Fatalf("verify against a refusing endpoint must be %q, got %v (%s)", panelUnknown, verify["state"], raw)
	}
	if verify["state"] == panelUnverified {
		t.Fatal("an unreachable verify endpoint was rendered as an unverified identity")
	}
	if !panelErrorsMention(t, doc, "could not verify") {
		t.Fatalf("the failed verify must be named in errors:\n%s", raw)
	}
}

// TestPanelStatus_AFailedEgressReadIsUnknownNeverNotInForce: the egress echo failing tells us
// nothing about where traffic is leaving from. `not-in-force` is a finding, and it must be
// reserved for the case where we actually saw the wrong address come back.
func TestPanelStatus_AFailedEgressReadIsUnknownNeverNotInForce(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	// A live record whose local proxy answers the registry probe, but which nothing is really
	// serving: the echo through it cannot complete, which is the failed read we want.
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5"))

	doc, raw := panelStatusJSON(t, dir)

	if conn := panelSub(t, doc, "connection"); conn["state"] != panelConnected {
		t.Fatalf("a probe-confirmed session must read as connected, got %v", conn["state"])
	}
	proxyApps := panelSub(t, doc, "egress", "proxy_apps")
	if proxyApps["state"] != panelUnknown {
		t.Fatalf("an egress read that failed must be %q, got %v (%s)", panelUnknown, proxyApps["state"], raw)
	}
	if !panelErrorsMention(t, doc, "egress") {
		t.Fatalf("the failed egress read must be named in errors:\n%s", raw)
	}
}

// TestPanelStatus_NothingConnectedIsNotInForceNotUnknown is the other control: with no session
// at all, nothing can be riding the Whisper egress, and that IS a finding rather than a failed
// read. Without this the previous test could be satisfied by an implementation that answered
// "unknown" to every egress question it was ever asked.
func TestPanelStatus_NothingConnectedIsNotInForceNotUnknown(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, false, nil)

	doc, _ := panelStatusJSON(t, dir)

	proxyApps := panelSub(t, doc, "egress", "proxy_apps")
	if proxyApps["state"] != panelNotInForce {
		t.Fatalf("with nothing connected, proxy_apps must be %q, got %v", panelNotInForce, proxyApps["state"])
	}
	if detail, _ := proxyApps["detail"].(string); !strings.Contains(detail, "whisper connect") {
		t.Fatalf("the not-connected detail must end in the command that fixes it, got %q", detail)
	}
}

// panelErrorsMention reports whether any line in the document's errors array contains substr.
func panelErrorsMention(t *testing.T, doc map[string]any, substr string) bool {
	t.Helper()
	lines, ok := doc["errors"].([]any)
	if !ok {
		t.Fatalf("errors is not an array: %v", doc["errors"])
	}
	for _, l := range lines {
		if s, ok := l.(string); ok && strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// --- 4. rtt_ms is a measurement, never a default ----------------------------------------------

// TestPanelWhalenet_RTTIsAbsentUnlessSomethingMeasuredIt. A zero here would render as "0.0 ms",
// which is a round trip nobody made and a claim the panel is not entitled to. The key must be
// absent entirely until a probe fills it in.
func TestPanelWhalenet_RTTIsAbsentUnlessSomethingMeasuredIt(t *testing.T) {
	cases := []struct {
		name    string
		rtt     float64
		present bool
	}{
		{name: "nothing measured it", rtt: 0, present: false},
		{name: "a probe measured it", rtt: 12.5, present: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := whaleStatusView{
				PathNote: "note",
				Peers: []whaleStatusPeer{{
					whalePeer: whalePeer{
						Name: "scout", Address: "2a04:2a01:9::abcd",
						FQDN: "scout.t9999.agents.whisper.online.", State: "active",
					},
					Path:  "relayed",
					RTTMs: tc.rtt,
				}},
			}
			raw, err := json.Marshal(panelWhalenetFrom(view))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got struct {
				Peers []map[string]any `json:"peers"`
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(got.Peers) != 1 {
				t.Fatalf("want one peer, got %d", len(got.Peers))
			}
			_, present := got.Peers[0]["rtt_ms"]
			if present != tc.present {
				t.Fatalf("rtt_ms present = %v, want %v (%s)", present, tc.present, raw)
			}
			// The tenant is derived from the fqdn, which is the one field the panel cannot get
			// anywhere else and the reason this flattening exists at all.
			if got.Peers[0]["tenant"] != "t9999" {
				t.Fatalf("the peer's tenant was not derived from its fqdn: %v", got.Peers[0]["tenant"])
			}
		})
	}
}

// --- 5. a stale system proxy is not egress ----------------------------------------------------

// TestPanel_ASystemProxyPointingAtADeadPortIsNotEgress is the honesty fix, asserted.
//
// A connection ends. The macOS SOCKS setting stays behind, still switched on, still pointed at
// 127.0.0.1:54209, and nothing is serving that port any more. Every GUI app on the machine now
// fails to reach the internet while the settings pane reads "on". That is the wrong answer
// wearing the clothes of a working one, and the panel must call it not-in-force and say why.
func TestPanel_ASystemProxyPointingAtADeadPortIsNotEgress(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, false, nil) // no live session, so nothing is serving 54209
	panelStubSystemProxy(t, func(livePorts []int) (systemProxyState, error) {
		host, port := "127.0.0.1", 54209
		return systemProxyState{
			Supported: true, Enabled: true, Host: host, Port: port, Service: "Wi-Fi",
			PointsAtWhisper: systemProxyPointsAtWhisper(host, port, livePorts),
		}, nil
	})

	doc, raw := panelStatusJSON(t, dir)

	sysProxy := panelSub(t, doc, "egress", "system_apps", "system_proxy")
	if sysProxy["points_at_whisper"] != false {
		t.Fatalf("a system proxy aimed at a port no live session is serving must not claim to "+
			"point at Whisper: %s", raw)
	}
	sysApps := panelSub(t, doc, "egress", "system_apps")
	if sysApps["state"] != panelNotInForce {
		t.Fatalf("a stale system proxy must read as %q, got %v", panelNotInForce, sysApps["state"])
	}
	detail, _ := sysApps["detail"].(string)
	for _, want := range []string{"no live Whisper session is serving that port", "NOT using the Whisper egress"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("the detail must say the egress is not in force and why; %q is missing from %q", want, detail)
		}
	}
}

// TestPanel_ASystemProxyOnTheLiveSessionIsEgress is the control. Without it, an implementation
// that always answered `false` would pass the test above.
func TestPanel_ASystemProxyOnTheLiveSessionIsEgress(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:54209", "socks5"))
	panelStubSystemProxy(t, func(livePorts []int) (systemProxyState, error) {
		host, port := "127.0.0.1", 54209
		return systemProxyState{
			Supported: true, Enabled: true, Host: host, Port: port, Service: "Wi-Fi",
			PointsAtWhisper: systemProxyPointsAtWhisper(host, port, livePorts),
		}, nil
	})

	doc, raw := panelStatusJSON(t, dir)

	sysProxy := panelSub(t, doc, "egress", "system_apps", "system_proxy")
	if sysProxy["points_at_whisper"] != true {
		t.Fatalf("a system proxy aimed at the live session's port must point at Whisper: %s", raw)
	}
	sysApps := panelSub(t, doc, "egress", "system_apps")
	if sysApps["state"] != panelInForce {
		t.Fatalf("want %q, got %v", panelInForce, sysApps["state"])
	}
	if detail, _ := sysApps["detail"].(string); !strings.Contains(detail, "2a04:2a01:9::abcd") {
		t.Fatalf("the in-force detail must name the address system apps leave from, got %q", detail)
	}
}

// TestPanel_AnUnsupportedPlatformIsUnknownNotOff: on a platform whose system network settings
// this build does not read, the answer is "not known", not "off". Reporting a confident negative
// about a setting we never looked at is the same defect in a different costume.
func TestPanel_AnUnsupportedPlatformIsUnknownNotOff(t *testing.T) {
	leg := panelSystemAppsFrom(systemProxyState{}, "2a04:2a01:9::abcd", sysProxyVerdict{})
	if leg.State != panelUnknown {
		t.Fatalf("an unsupported platform must be %q, got %q", panelUnknown, leg.State)
	}
	if leg.Detail == "" {
		t.Fatal("the unsupported state must still say why")
	}
}

// --- 6. the key never leaves this process -----------------------------------------------------

// TestPanelStatus_NeverEmitsTheKeyValue. The panel is a document that gets copied into bug
// reports, logs and screenshots. It carries presence and provenance; it never carries the key.
func TestPanelStatus_NeverEmitsTheKeyValue(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	stubProbe(t, false, nil)

	doc, raw := panelStatusJSON(t, dir, "--key", panelTestKey)

	key := panelSub(t, doc, "key")
	if key["present"] != true {
		t.Fatalf("the key passed on the command line was not seen: %v", key)
	}
	if key["source"] != "flag" {
		t.Fatalf("the key source must name where it came from, got %v", key["source"])
	}
	if strings.Contains(raw, panelTestKey) {
		t.Fatalf("the key VALUE appears in the emitted document:\n%s", raw)
	}
	// Not just the literal: no field anywhere may carry a whisper_live_ prefix either.
	if strings.Contains(raw, "whisper_live_") {
		t.Fatalf("something that looks like a key appears in the emitted document:\n%s", raw)
	}
}

// TestPanelSystemProxy_RefusesAtTheFirstStep pins the ORDER of the two refusals, which is a real
// usability property rather than a cosmetic one: on a platform this build cannot drive, being
// told to go and connect first, and only THEN that the switch does not exist here, is a dead end
// reached the slow way. The assertion adapts to the platform so it is a real check on both, not
// a skip on one.
func TestPanelSystemProxy_RefusesAtTheFirstStep(t *testing.T) {
	panelIsolation(t)
	stubProbe(t, false, nil) // nothing connected, on every platform

	deepencli_globals(t, globalFlags{})
	err := runPanelSystemProxySet(true, sysProxyEnableOptions{})
	if err == nil {
		t.Fatal("`whisper panel system-proxy on` succeeded with nothing connected and nothing to point at")
	}
	if systemProxySupported {
		if !strings.Contains(err.Error(), "no live Whisper connection") {
			t.Fatalf("on a platform we can drive, the missing connection is the first thing to say: %v", err)
		}
		return
	}
	if !strings.Contains(err.Error(), "macOS-only") {
		t.Fatalf("on a platform we cannot drive, say so first rather than sending the user off to "+
			"connect and hit the same wall a step later: %v", err)
	}
}

// --- 7. the pre-flight: refuse rather than brick -----------------------------------------------
//
// `whisper panel system-proxy on` points every application on a Mac at the Whisper egress.
// Measured on a live Tier-1 session, that egress reached IPv6 destinations and did not reach IPv4
// ones, so the toggle took the machine off most of the web while reporting success. The tests
// below are the four halves of not doing that again: refuse on real evidence, do NOT refuse on
// evidence that is really about the user's own network, let an operator override with their eyes
// open, and put the machine back exactly as it was if the change turns out badly.

// panelSysProxySession registers one live session and points the probe at it, which is the state
// every enable test starts from.
func panelSysProxySession(t *testing.T, addr string, port int) statusSession {
	t.Helper()
	endpoint := "socks5h://127.0.0.1:" + strconv.Itoa(port)
	stubProbe(t, true, nil)
	writeSessionRecord(ownedSession(addr, endpoint, "wireguard"))
	return statusSession{Endpoint: endpoint, Address: addr, Tier: "wireguard", Port: port}
}

// TestPanelSystemProxy_RefusesWhenTheEgressCannotCarryIPv4 is the outage, asserted.
//
// The refusal has to do two things, and the second is the one that is usually skipped: change
// nothing, and say the true reason in words a person can act on. "Pre-flight failed" would be a
// worse outcome than the outage in one respect, because the person would go looking in the wrong
// place.
func TestPanelSystemProxy_RefusesWhenTheEgressCannotCarryIPv4(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	mac := (&panelSysProxyMac{}).install(t)
	panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	panelStubSysProxyLegs(t, carriesIPv6ButNotIPv4("2a04:2a01:9::abcd"))

	err := runPanelSystemProxySet(true, sysProxyEnableOptions{})
	if err == nil {
		t.Fatal("`system-proxy on` succeeded against an egress that cannot reach IPv4 - that is the " +
			"outage this check exists to prevent")
	}
	if got := mac.writes(); len(got) != 0 {
		t.Fatalf("the system setting was changed despite the refusal (%v). A refusal that has already "+
			"broken the machine is not a refusal", got)
	}
	msg := err.Error()
	for _, want := range []string{
		"IPv6 destinations but not IPv4",   // what is actually wrong
		"straight from this Mac succeeded", // how we know it is not their network
		"Safari, Chrome, Mail",             // what would have happened, in their terms
		"Nothing has been changed",         // the state they are in now
		"ALL_PROXY",                        // the way to use it in the meantime
		"--force",                          // the way past this, for somebody who means it
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal does not say %q, so it is not the reason a person can act on:\n%s", want, msg)
		}
	}
}

// TestPanelSystemProxy_DoesNotRefuseWhenTheMachinesOwnNetworkIsDown is the control, and without
// it the test above is worth nothing: an implementation that refused whenever the v4 fetch failed
// would pass it and would then refuse on every train, plane and flaky cafe wifi in the world.
//
// Both legs failing is a statement about the machine, not about the egress.
func TestPanelSystemProxy_DoesNotRefuseWhenTheMachinesOwnNetworkIsDown(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	mac := (&panelSysProxyMac{}).install(t)
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	legs := carriesIPv6ButNotIPv4(sess.Address)
	legs.v4 = func() sysProxyV4Leg {
		return sysProxyV4Leg{Host: "api.ipify.org", Tried: true,
			Proxied: errors.New("dial tcp: i/o timeout"),
			Direct:  errors.New("dial tcp: i/o timeout")}
	}
	panelStubSysProxyLegs(t, legs)

	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: 2 * time.Second}); err != nil {
		t.Fatalf("`system-proxy on` refused because the USER's network is down, which is not evidence "+
			"about the Whisper egress: %v", err)
	}
	if got := mac.writes(); len(got) != 1 || got[0] != sess.Port {
		t.Fatalf("the setting was not pointed at the live session: %v", got)
	}
}

// TestPanelSystemProxy_ForceOverridesAndSaysWhatItOverrode. An override that goes quiet is how
// somebody ends up debugging a dead browser having never learned we warned them.
func TestPanelSystemProxy_ForceOverridesAndSaysWhatItOverrode(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	mac := (&panelSysProxyMac{}).install(t)
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	panelStubSysProxyLegs(t, carriesIPv6ButNotIPv4(sess.Address))

	var err error
	_, stderr := captureStd(t, func() {
		err = runPanelSystemProxySet(true, sysProxyEnableOptions{force: true, verifyTimeout: 2 * time.Second})
	})
	if err != nil {
		t.Fatalf("--force did not override the refusal: %v", err)
	}
	if got := mac.writes(); len(got) != 1 || got[0] != sess.Port {
		t.Fatalf("--force did not actually apply the setting: %v", got)
	}
	if !strings.Contains(stderr, "--force") || !strings.Contains(stderr, "IPv6 destinations but not IPv4") {
		t.Fatalf("--force must print what it is overriding, in the same words as the refusal:\n%s", stderr)
	}
}

// TestPanelSystemProxy_DeadManRestoresTheExactPreviousState.
//
// The previous state here is a corporate SOCKS proxy that was already switched on. "Revert" for
// that machine means putting THAT back, not turning the proxy off: a person who ends up off their
// company network because our toggle failed has been broken in a second, quieter way.
func TestPanelSystemProxy_DeadManRestoresTheExactPreviousState(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	prev := systemProxyState{Supported: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi"}
	mac := (&panelSysProxyMac{current: prev}).install(t)
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)

	// The pre-flight passes; the fetch AFTER the setting is applied never comes back. That is the
	// dead man's whole reason for existing: a pre-flight can only prove the past.
	legs := &fakeSysProxyLegs{answers: true}
	legs.egress = func(call int) (string, error) {
		if call == 1 {
			return sess.Address, nil
		}
		return "", errors.New("the local Whisper proxy is not answering")
	}
	legs.v4 = func() sysProxyV4Leg {
		return sysProxyV4Leg{Host: "api.ipify.org", Tried: true}
	}
	panelStubSysProxyLegs(t, legs)
	sysProxyVerifyPoll = 10 * time.Millisecond
	t.Cleanup(func() { sysProxyVerifyPoll = 1500 * time.Millisecond })

	err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: 150 * time.Millisecond})
	if err == nil {
		t.Fatal("the setting was applied, nothing could be fetched through it, and the command still " +
			"reported success")
	}
	restores := mac.restores()
	if len(restores) != 1 {
		t.Fatalf("the dead man did not put the previous settings back: %d restores", len(restores))
	}
	got := restores[0]
	if !got.Known || !got.Enabled || got.Host != "proxy.corp.example" || got.Port != 1080 || got.Service != "Wi-Fi" {
		t.Fatalf("the previous state was not restored EXACTLY - a machine behind a corporate proxy must "+
			"end up behind it again, not with the proxy switched off: %+v", got)
	}
	for _, want := range []string{"put back exactly as they were", "nothing is routed through Whisper"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must say it was reverted and why; %q is missing from:\n%s", want, err.Error())
		}
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("a reverted change left its record behind, so the reaper would later 'restore' over a " +
			"setting Whisper no longer owns")
	}
	// And the panel must not be handed the passing pre-flight it started from: it would draw the
	// same button on its next poll and offer the user the identical trap once a minute.
	if v, ok := readSysProxyVerdictCache(sess); !ok || v.CanEnable {
		t.Fatalf("the verdict behind the enable button survived a revert that disproved it: %+v", v)
	}
}

// --- 8. the reaper: undo our own change once it has become an outage --------------------------

// TestPanelSystemProxyReap_RevertsAWhisperSetProxyWhosePortIsDead is the failure that does not
// need a failed toggle: the session ends, the setting stays behind, and every app on the machine
// quietly stops reaching the internet while the settings pane still reads "on".
func TestPanelSystemProxyReap_RevertsAWhisperSetProxyWhosePortIsDead(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	stubProbe(t, false, nil) // nothing is serving anything
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSysProxyRecord(sysProxyRecord{
		Service:  "Wi-Fi",
		Host:     "127.0.0.1",
		Port:     55312,
		Previous: sysProxyPrevious{Known: true, Enabled: false, Service: "Wi-Fi"},
	})

	res, err := runSysProxyReap()
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if !res.Reverted {
		t.Fatalf("the reaper left a Whisper-set proxy pointing at a dead port, which is a machine with "+
			"no internet: %+v", res)
	}
	if len(mac.restores()) != 1 {
		t.Fatalf("nothing was restored: %v", mac.restores())
	}
	if !strings.Contains(res.Detail, "no live Whisper session is serving") {
		t.Fatalf("the reaper must say what it found and why it acted: %q", res.Detail)
	}
	if _, ok := readSysProxyRecord(); ok {
		t.Fatal("the record survived the revert, so a second reap would act on a setting we no longer own")
	}
}

// TestPanelSystemProxyReap_LeavesAProxyWhisperDidNotSetAlone is the constraint that makes the
// watchdog defensible at all. An application that silently reverts system settings it did not
// make is malware with good intentions; this one only ever undoes its own change.
func TestPanelSystemProxyReap_LeavesAProxyWhisperDidNotSetAlone(t *testing.T) {
	cases := map[string]struct {
		record *sysProxyRecord
		want   string
	}{
		"whisper never set anything": {
			record: nil,
			want:   "no record of setting it",
		},
		"whisper set a different port": {
			record: &sysProxyRecord{Service: "Wi-Fi", Host: "127.0.0.1", Port: 41080,
				Previous: sysProxyPrevious{Known: true}},
			want: "not what Whisper wrote",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			panelIsolation(t)
			deepencli_globals(t, globalFlags{})
			stubProbe(t, false, nil)
			// Somebody else's local proxy: on, on loopback, and serving nothing we know about.
			mac := (&panelSysProxyMac{current: systemProxyState{
				Supported: true, Enabled: true, Host: "127.0.0.1", Port: 8888, Service: "Wi-Fi",
			}}).install(t)
			if tc.record != nil {
				writeSysProxyRecord(*tc.record)
			}

			res, err := runSysProxyReap()
			if err != nil {
				t.Fatalf("reap: %v", err)
			}
			if res.Reverted {
				t.Fatal("the reaper changed a system setting Whisper did not make")
			}
			if len(mac.restores()) != 0 || len(mac.writes()) != 0 {
				t.Fatalf("the reaper touched the settings: writes=%v restores=%v", mac.writes(), mac.restores())
			}
			if !strings.Contains(res.Detail, tc.want) {
				t.Fatalf("the reaper must say why it declined; %q is missing from %q", tc.want, res.Detail)
			}
		})
	}
}

// TestPanelSystemProxyReap_LeavesTheLiveSessionAlone is the other control: the reaper must not
// tear down a system proxy that is working. Without this, an implementation that reverted
// everything would pass both tests above.
func TestPanelSystemProxyReap_LeavesTheLiveSessionAlone(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "127.0.0.1", Port: 55312, Service: "Wi-Fi",
	}}).install(t)
	writeSysProxyRecord(sysProxyRecord{Service: "Wi-Fi", Host: "127.0.0.1", Port: 55312,
		Previous: sysProxyPrevious{Known: true}})

	res, err := runSysProxyReap()
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if res.Reverted || len(mac.restores()) != 0 {
		t.Fatalf("the reaper reverted a system proxy that points at the LIVE session: %+v", res)
	}
}

// --- 9. the panel must not offer a button that bricks the Mac ----------------------------------

// TestPanelStatus_CanEnableIsFalseWithAReasonWhenThePreflightFails.
//
// The panel drew the enable button whenever a connection was up. The document now carries the
// verdict, and the reason has to travel with it: a control that just disappears reads as a broken
// app, and the person is left with no idea why the thing they were told to press is gone.
func TestPanelStatus_CanEnableIsFalseWithAReasonWhenThePreflightFails(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	panelStubSysProxyLegs(t, carriesIPv6ButNotIPv4(sess.Address))
	panelStubSystemProxy(t, func(livePorts []int) (systemProxyState, error) {
		return systemProxyState{Supported: true, Service: "Wi-Fi"}, nil
	})

	doc, raw := panelStatusJSON(t, dir)

	sysApps := panelSub(t, doc, "egress", "system_apps")
	if sysApps["can_enable"] != false {
		t.Fatalf("can_enable must be false when the pre-flight refuses, got %v:\n%s", sysApps["can_enable"], raw)
	}
	reason, _ := sysApps["cannot_enable_reason"].(string)
	if strings.TrimSpace(reason) == "" {
		t.Fatalf("can_enable is false with no reason, so the panel has a missing button and nothing to "+
			"put in its place:\n%s", raw)
	}
	if !strings.Contains(reason, "IPv6 destinations but not IPv4") {
		t.Fatalf("the reason must be the real one, not a generic failure: %q", reason)
	}
	if _, ok := sysApps["preflight_age_seconds"]; !ok {
		t.Fatalf("a verdict must carry its age, so a cached one is never read as this second's "+
			"measurement:\n%s", raw)
	}
}

// TestPanelStatus_CanEnableIsTrueWhenTheEgressCarriesBoth is the control. Without it an
// implementation that answered can_enable:false always would pass, and the button would never be
// offered to anybody.
func TestPanelStatus_CanEnableIsTrueWhenTheEgressCarriesBoth(t *testing.T) {
	dir := panelIsolation(t)
	panelStubSensor(t, "running", "")
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	legs := carriesIPv6ButNotIPv4(sess.Address)
	legs.v4 = func() sysProxyV4Leg { return sysProxyV4Leg{Host: "api.ipify.org", Tried: true} }
	panelStubSysProxyLegs(t, legs)
	panelStubSystemProxy(t, func(livePorts []int) (systemProxyState, error) {
		return systemProxyState{Supported: true, Service: "Wi-Fi"}, nil
	})

	doc, raw := panelStatusJSON(t, dir)

	sysApps := panelSub(t, doc, "egress", "system_apps")
	if sysApps["can_enable"] != true {
		t.Fatalf("can_enable must be true when the egress carries both families:\n%s", raw)
	}
	if r, _ := sysApps["cannot_enable_reason"].(string); r != "" {
		t.Fatalf("a passing pre-flight must carry no refusal reason, got %q", r)
	}
}

// TestPanelSystemProxy_PreflightVerdictIsCachedWithItsAge pins the cheap-polling property AND the
// honesty rule that comes with it. A resident panel polls this document every few seconds; three
// real HTTP requests each time is not a thing to do to somebody's laptop. The verdict may
// therefore be reused - but it must never be reported as a measurement made just now.
func TestPanelSystemProxy_PreflightVerdictIsCachedWithItsAge(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	sess := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	legs := panelStubSysProxyLegs(t, carriesIPv6ButNotIPv4(sess.Address))

	cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := sysProxyPreflightCached(cx, sess)
	if first.AgeSecs != 0 {
		t.Fatalf("a verdict measured during this read must report age 0, got %d", first.AgeSecs)
	}
	before := legs.calls
	second := sysProxyPreflightCached(cx, sess)
	if legs.calls != before {
		t.Fatalf("the second read re-measured instead of reusing the verdict (%d -> %d calls)", before, legs.calls)
	}
	if second.CanEnable != first.CanEnable || second.Reason != first.Reason {
		t.Fatal("the cached verdict is not the one that was measured")
	}

	// A different session is a different machine state, and its verdict is not transferable.
	other := statusSession{Endpoint: "socks5h://127.0.0.1:41080", Address: sess.Address, Port: 41080}
	if _ = sysProxyPreflightCached(cx, other); legs.calls == before {
		t.Fatal("a verdict reached against one session was reused for another")
	}
}

// TestPanelSystemProxy_ReEnablingKeepsTheORIGINALPreviousState.
//
// Switch it on for one session, then on again for the next: the naive answer records Whisper's own
// first setting as "what this Mac had before", and a later revert restores a Whisper proxy aimed
// at a port that is long gone. That is the exact broken state this whole surface exists to undo,
// reinstated by the repair itself, and it is only visible on the second enable.
func TestPanelSystemProxy_ReEnablingKeepsTheORIGINALPreviousState(t *testing.T) {
	panelIsolation(t)
	deepencli_globals(t, globalFlags{})
	mac := (&panelSysProxyMac{current: systemProxyState{
		Supported: true, Enabled: true, Host: "proxy.corp.example", Port: 1080, Service: "Wi-Fi",
	}}).install(t)
	sysProxyVerifyPoll = 10 * time.Millisecond
	t.Cleanup(func() { sysProxyVerifyPoll = 1500 * time.Millisecond })

	first := panelSysProxySession(t, "2a04:2a01:9::abcd", 55312)
	legs := carriesIPv6ButNotIPv4(first.Address)
	legs.v4 = func() sysProxyV4Leg { return sysProxyV4Leg{Host: "api.ipify.org", Tried: true} }
	panelStubSysProxyLegs(t, legs)
	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: time.Second}); err != nil {
		t.Fatalf("first enable: %v", err)
	}

	// A second session on a new port, with the first setting still in place. The first record is
	// removed by ITS OWN path: the registry is keyed on the /128 AND the port, so the
	// two sessions below are two rows and the second no longer overwrites the first.
	removeSessionRecordAt(sessionRecordPath(first.Address, first.Port))
	second := panelSysProxySession(t, "2a04:2a01:9::abcd", 41080)
	if err := runPanelSystemProxySet(true, sysProxyEnableOptions{verifyTimeout: time.Second}); err != nil {
		t.Fatalf("second enable: %v", err)
	}

	rec, ok := readSysProxyRecord()
	if !ok {
		t.Fatal("the second enable left no record")
	}
	if rec.Port != second.Port {
		t.Fatalf("the record does not name the setting we just wrote: %+v", rec)
	}
	if rec.Previous.Host != "proxy.corp.example" || rec.Previous.Port != 1080 || !rec.Previous.Enabled {
		t.Fatalf("the second enable recorded Whisper's OWN first setting as the previous state, so a "+
			"revert would restore a proxy pointing at a dead port: %+v", rec.Previous)
	}
	if len(mac.writes()) != 2 {
		t.Fatalf("want two writes, got %v", mac.writes())
	}
}
